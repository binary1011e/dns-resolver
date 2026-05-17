#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import os
import random
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional


class Runner:
    def __init__(
        self,
        port: int,
        attach: bool,
        build: bool,
        stress_overload: bool,
        stress_requests: int,
        stress_concurrency: int,
        upstream_timeout_ms: int,
    ) -> None:
        self.port = port
        self.attach = attach
        self.build = build
        self.stress_overload = stress_overload
        self.stress_requests = stress_requests
        self.stress_concurrency = stress_concurrency
        self.upstream_timeout_ms = upstream_timeout_ms
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.procs: List[subprocess.Popen[str]] = []

    def log(self, msg: str) -> None:
        print(f"[e2e-dig] {msg}")

    def pass_(self, msg: str) -> None:
        self.passed += 1
        self.total += 1
        print(f"PASS: {msg}")

    def fail(self, msg: str, extra: Optional[str] = None) -> None:
        self.failed += 1
        self.total += 1
        print(f"FAIL: {msg}")
        if extra:
            print(extra)

    def cleanup(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)

    def dig(self, name: str, qtype: str) -> subprocess.CompletedProcess[str]:
        cmd = [
            "dig",
            "@127.0.0.1",
            "-p",
            str(self.port),
            "+time=2",
            "+tries=1",
            "+nocmd",
            "+comments",
            "+answer",
            "+authority",
            "+additional",
            name,
            qtype,
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    @staticmethod
    def read_rcode(dig_output: str) -> str:
        match = re.search(r"status:\s*([A-Z]+)", dig_output)
        return match.group(1) if match else ""

    @staticmethod
    def answer_lines(dig_output: str) -> List[str]:
        lines = dig_output.splitlines()
        inside = False
        out: List[str] = []
        for line in lines:
            if line.startswith(";; ANSWER SECTION:"):
                inside = True
                continue
            if inside and line.startswith(";;"):
                break
            if inside and line.strip():
                out.append(line)
        return out

    def assert_rcode(self, name: str, qtype: str, expected: str) -> None:
        proc = self.dig(name, qtype)
        out = proc.stdout + proc.stderr
        if proc.returncode != 0:
            self.fail(f"dig failed for {name} {qtype}", out)
            return
        got = self.read_rcode(out)
        if got == expected:
            self.pass_(f"{name} {qtype} rcode={expected}")
        else:
            self.fail(f"{name} {qtype} expected rcode={expected} got={got or '<none>'}", out)

    def assert_answer_nonempty(self, name: str, qtype: str) -> None:
        proc = self.dig(name, qtype)
        out = proc.stdout + proc.stderr
        if proc.returncode != 0:
            self.fail(f"dig failed for {name} {qtype}", out)
            return
        rcode = self.read_rcode(out)
        answers = self.answer_lines(out)
        if rcode == "NOERROR" and len(answers) > 0:
            self.pass_(f"{name} {qtype} has NOERROR with non-empty answer")
        else:
            self.fail(
                f"{name} {qtype} expected NOERROR + answer, got rcode={rcode or '<none>'} answers={len(answers)}",
                out,
            )

    def assert_answer_contains(self, name: str, qtype: str, expected: str) -> None:
        proc = self.dig(name, qtype)
        out = proc.stdout + proc.stderr
        if proc.returncode != 0:
            self.fail(f"dig failed for {name} {qtype}", out)
            return
        rcode = self.read_rcode(out)
        answers = "\n".join(self.answer_lines(out))
        if rcode == "NOERROR" and expected in answers:
            self.pass_(f"{name} {qtype} contains '{expected}'")
        else:
            self.fail(
                f"{name} {qtype} expected answer containing '{expected}' (rcode={rcode or '<none>'})",
                out,
            )

    def wait_for_resolver(self) -> bool:
        cmd = [
            "dig",
            "@127.0.0.1",
            "-p",
            str(self.port),
            "+time=1",
            "+tries=1",
            "+short",
            "example.com",
            "A",
        ]
        for _ in range(40):
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                return True
            time.sleep(0.25)
        return False

    def start_resolver(self, mode: str) -> bool:
        if self.build:
            self.log("Building binary")
            build = subprocess.run(["cargo", "build"], text=True)
            if build.returncode != 0:
                self.fail("cargo build failed")
                return False

        self.log(f"Starting resolver on port {self.port} mode={mode}")
        log_path = Path(f"/tmp/dns-resolver-e2e-{self.port}-{mode}.log")
        log_file = log_path.open("w")
        child_env = dict(os.environ)
        child_env["DNS_UPSTREAM_TIMEOUT_MS"] = str(self.upstream_timeout_ms)
        if self.stress_overload:
            child_env["DNS_MAX_INFLIGHT"] = "8"
            child_env["DNS_QUEUE_TIMEOUT_MS"] = "5"
        proc = subprocess.Popen(
            ["cargo", "run", "--quiet", "--bin", "main", "--", str(self.port), mode],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=child_env,
        )
        self.procs.append(proc)

        if not self.wait_for_resolver():
            self.fail(f"resolver did not become ready on port {self.port} (mode {mode})")
            if log_path.exists():
                print("--- resolver log ---")
                print(log_path.read_text())
                print("--- end resolver log ---")
            return False

        self.pass_(f"resolver ready on port {self.port} mode={mode}")
        return True

    def run_overload_stress(self, mode: str) -> None:
        self.log(
            f"Running overload stress mode={mode} requests={self.stress_requests} concurrency={self.stress_concurrency}"
        )

        def one_query(i: int) -> str:
            host = f"overload-{i}-{random.randint(1000,999999)}.invalid"
            out = self.dig(host, "A")
            if out.returncode != 0:
                return "ERR"
            return self.read_rcode(out.stdout + out.stderr) or "UNKNOWN"

        counts: Dict[str, int] = {}
        with ThreadPoolExecutor(max_workers=self.stress_concurrency) as pool:
            futures = [pool.submit(one_query, i) for i in range(self.stress_requests)]
            for fut in as_completed(futures):
                rcode = fut.result()
                counts[rcode] = counts.get(rcode, 0) + 1

        servfail = counts.get("SERVFAIL", 0)
        noerror = counts.get("NOERROR", 0)
        nxdomain = counts.get("NXDOMAIN", 0)

        if servfail > 0 and (noerror + nxdomain) > 0:
            self.pass_(f"overload stress produced controlled SERVFAIL (counts={counts})")
        else:
            self.fail(f"overload stress expected mixed outcomes with SERVFAIL; counts={counts}")

    def run_suite(self, mode: str) -> None:
        self.log(f"Running suite for mode={mode} on port {self.port}")

        self.assert_rcode("example.com", "A", "NOERROR")
        self.assert_answer_nonempty("example.com", "A")

        self.assert_rcode("example.com", "AAAA", "NOERROR")
        self.assert_answer_nonempty("example.com", "AAAA")

        self.assert_rcode("www.wikipedia.org", "A", "NOERROR")
        self.assert_answer_nonempty("www.wikipedia.org", "A")

        miss = f"does-not-exist-{random.randint(1000, 99999)}-{random.randint(1000, 99999)}.invalid"
        self.assert_rcode(miss, "A", "NXDOMAIN")

        self.assert_rcode("0.fls.doubleclick.net", "A", "NOERROR")
        self.assert_answer_contains("0.fls.doubleclick.net", "A", "0.0.0.0")

        self.assert_rcode("0.fls.doubleclick.net", "AAAA", "NOERROR")
        self.assert_answer_contains("0.fls.doubleclick.net", "AAAA", "::")

        if self.stress_overload:
            self.run_overload_stress(mode)

    def run_mode(self, mode: str) -> None:
        if self.attach:
            self.log(f"Attach mode: expecting resolver already running on port {self.port} for mode={mode}")
        else:
            if not self.start_resolver(mode):
                return

        self.run_suite(mode)

        if not self.attach and self.procs:
            proc = self.procs[-1]
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="E2E dig harness for dns resolver")
    parser.add_argument("--port", type=int, default=2053, help="Resolver port (default: 2053)")
    parser.add_argument("--mode", choices=["0", "1", "both"], default="both", help="Resolver mode")
    parser.add_argument("--attach", action="store_true", help="Do not start resolver process")
    parser.add_argument("--no-build", action="store_true", help="Skip cargo build")
    parser.add_argument("--stress-overload", action="store_true", help="Run opt-in overload stress checks")
    parser.add_argument("--stress-requests", type=int, default=200, help="Overload stress query count")
    parser.add_argument("--stress-concurrency", type=int, default=64, help="Overload stress concurrency")
    parser.add_argument(
        "--upstream-timeout-ms",
        type=int,
        default=600,
        help="Set DNS_UPSTREAM_TIMEOUT_MS for self-managed resolver runs (default: 600)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if subprocess.run(["which", "dig"], capture_output=True, text=True).returncode != 0:
        print("dig not found in PATH", file=sys.stderr)
        return 2

    if args.attach and args.mode == "both":
        print("--attach with --mode both is ambiguous; use --mode 0 or --mode 1", file=sys.stderr)
        return 2

    runner = Runner(
        port=args.port,
        attach=args.attach,
        build=not args.no_build,
        stress_overload=args.stress_overload,
        stress_requests=args.stress_requests,
        stress_concurrency=args.stress_concurrency,
        upstream_timeout_ms=args.upstream_timeout_ms,
    )
    atexit.register(runner.cleanup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(130))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))

    if args.mode == "both":
        runner.run_mode("0")
        runner.run_mode("1")
    else:
        runner.run_mode(args.mode)

    print(f"\nSummary: total={runner.total} passed={runner.passed} failed={runner.failed}")
    return 1 if runner.failed > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
