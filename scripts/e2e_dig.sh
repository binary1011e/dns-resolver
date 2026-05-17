#!/usr/bin/env bash
set -euo pipefail

PORT="2053"
MODE="both"
ATTACH=0
BUILD=1

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

PIDS=()

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--port <port>] [--mode <0|1|both>] [--attach] [--no-build]

Options:
  --port <port>   DNS resolver port to query (default: 2053)
  --mode <mode>   Resolver mode: 0 (iterative), 1 (recursive), both (default)
  --attach        Do not start resolver process; use an already-running resolver
  --no-build      Skip cargo build before starting resolver
  -h, --help      Show this help
USAGE
}

log() {
  printf '[e2e-dig] %s\n' "$*"
}

pass() {
  local msg="$1"
  PASS_COUNT=$((PASS_COUNT + 1))
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  printf 'PASS: %s\n' "$msg"
}

fail() {
  local msg="$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  printf 'FAIL: %s\n' "$msg"
}

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}

trap cleanup EXIT INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      PORT="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --attach)
      ATTACH=1
      shift
      ;;
    --no-build)
      BUILD=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if ! command -v dig >/dev/null 2>&1; then
  echo "dig not found in PATH" >&2
  exit 2
fi

if [[ "$MODE" != "0" && "$MODE" != "1" && "$MODE" != "both" ]]; then
  echo "Invalid mode: $MODE (expected 0, 1, or both)" >&2
  exit 2
fi

read_rcode() {
  local out="$1"
  printf '%s\n' "$out" | awk -F'[, ]+' '/status:/{for(i=1;i<=NF;i++){if($i=="status:"){print $(i+1); exit}}}'
}

run_dig() {
  local qname="$1"
  local qtype="$2"
  dig @127.0.0.1 -p "$PORT" +time=2 +tries=1 +nocmd +comments +answer +authority +additional "$qname" "$qtype"
}

assert_rcode() {
  local qname="$1"
  local qtype="$2"
  local expected="$3"

  local out
  if ! out="$(run_dig "$qname" "$qtype" 2>&1)"; then
    fail "dig failed for $qname $qtype; command: dig @127.0.0.1 -p $PORT $qname $qtype"
    printf '%s\n' "$out"
    return
  fi

  local got
  got="$(read_rcode "$out")"

  if [[ "$got" == "$expected" ]]; then
    pass "$qname $qtype rcode=$expected"
  else
    fail "$qname $qtype expected rcode=$expected got=${got:-<none>}"
    printf '%s\n' "$out"
  fi
}

assert_answer_nonempty() {
  local qname="$1"
  local qtype="$2"

  local out
  if ! out="$(run_dig "$qname" "$qtype" 2>&1)"; then
    fail "dig failed for $qname $qtype; command: dig @127.0.0.1 -p $PORT $qname $qtype"
    printf '%s\n' "$out"
    return
  fi

  local rcode
  rcode="$(read_rcode "$out")"

  local answer_count
  answer_count="$(printf '%s\n' "$out" | awk '/^;; ANSWER SECTION:/{in_ans=1;next}/^;;/{if(in_ans){in_ans=0}} in_ans && NF{c++} END{print c+0}')"

  if [[ "$rcode" == "NOERROR" && "$answer_count" -gt 0 ]]; then
    pass "$qname $qtype has NOERROR with non-empty answer"
  else
    fail "$qname $qtype expected NOERROR + answer, got rcode=${rcode:-<none>} answers=$answer_count"
    printf '%s\n' "$out"
  fi
}

assert_answer_contains() {
  local qname="$1"
  local qtype="$2"
  local expected_substring="$3"

  local out
  if ! out="$(run_dig "$qname" "$qtype" 2>&1)"; then
    fail "dig failed for $qname $qtype; command: dig @127.0.0.1 -p $PORT $qname $qtype"
    printf '%s\n' "$out"
    return
  fi

  local rcode
  rcode="$(read_rcode "$out")"

  local answer_text
  answer_text="$(printf '%s\n' "$out" | awk '/^;; ANSWER SECTION:/{in_ans=1;next}/^;;/{if(in_ans){in_ans=0}} in_ans {print}')"

  if [[ "$rcode" == "NOERROR" ]] && printf '%s\n' "$answer_text" | grep -Fq "$expected_substring"; then
    pass "$qname $qtype contains '$expected_substring'"
  else
    fail "$qname $qtype expected answer containing '$expected_substring' (rcode=${rcode:-<none>})"
    printf '%s\n' "$out"
  fi
}

wait_for_resolver() {
  local tries=40
  local qname="example.com"

  while [[ $tries -gt 0 ]]; do
    if dig @127.0.0.1 -p "$PORT" +time=1 +tries=1 +short "$qname" A >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
    tries=$((tries - 1))
  done

  return 1
}

start_resolver() {
  local mode="$1"

  if [[ "$BUILD" -eq 1 ]]; then
    log "Building binary"
    cargo build >/dev/null
  fi

  log "Starting resolver on port $PORT mode=$mode"
  cargo run --quiet --bin main -- "$PORT" "$mode" >/tmp/dns-resolver-e2e-${PORT}-${mode}.log 2>&1 &
  local pid=$!
  PIDS+=("$pid")

  if ! wait_for_resolver; then
    fail "resolver did not become ready on port $PORT (mode $mode)"
    if [[ -f /tmp/dns-resolver-e2e-${PORT}-${mode}.log ]]; then
      printf '%s\n' '--- resolver log ---'
      cat "/tmp/dns-resolver-e2e-${PORT}-${mode}.log"
      printf '%s\n' '--- end resolver log ---'
    fi
    return 1
  fi

  pass "resolver ready on port $PORT mode=$mode"
  return 0
}

run_suite() {
  local label="$1"
  log "Running suite for mode=$label on port $PORT"

  assert_rcode "example.com" "A" "NOERROR"
  assert_answer_nonempty "example.com" "A"

  assert_rcode "example.com" "AAAA" "NOERROR"
  assert_answer_nonempty "example.com" "AAAA"

  assert_rcode "www.wikipedia.org" "A" "NOERROR"
  assert_answer_nonempty "www.wikipedia.org" "A"

  local miss="does-not-exist-$RANDOM-$RANDOM.invalid"
  assert_rcode "$miss" "A" "NXDOMAIN"

  assert_rcode "0.fls.doubleclick.net" "A" "NOERROR"
  assert_answer_contains "0.fls.doubleclick.net" "A" "0.0.0.0"

  assert_rcode "0.fls.doubleclick.net" "AAAA" "NOERROR"
  assert_answer_contains "0.fls.doubleclick.net" "AAAA" "::"
}

run_mode() {
  local mode="$1"
  local attach_label="$2"

  if [[ "$ATTACH" -eq 1 ]]; then
    log "Attach mode: expecting resolver already running on port $PORT for mode=$mode"
  else
    if ! start_resolver "$mode"; then
      return
    fi
  fi

  run_suite "$mode"

  if [[ "$ATTACH" -eq 0 ]]; then
    local pid="${PIDS[-1]}"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  fi
}

if [[ "$MODE" == "both" ]]; then
  if [[ "$ATTACH" -eq 1 ]]; then
    echo "--attach with --mode both is ambiguous; use --mode 0 or --mode 1 in attach mode" >&2
    exit 2
  fi
  run_mode "0" "iterative"
  run_mode "1" "recursive"
else
  run_mode "$MODE" "$MODE"
fi

printf '\nSummary: total=%d passed=%d failed=%d\n' "$TOTAL_COUNT" "$PASS_COUNT" "$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
