use dns::{handle_packet, servfail_response_for_packet, CachedValue, ResolverRuntimeConfig};
use moka::sync::Cache;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Wrong # args. 3 not {}", args.len());
        return;
    }

    let max_inflight = env::var("DNS_MAX_INFLIGHT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1024);
    let queue_timeout_ms = env::var("DNS_QUEUE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(50);
    let upstream_timeout_ms = env::var("DNS_UPSTREAM_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(150);
    let max_pending_upstreams = env::var("DNS_MAX_PENDING_UPSTREAMS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2048);

    let file = File::open("ads-nl.txt").unwrap();
    let reader = io::BufReader::new(file);
    let mut blocklist = HashSet::new();

    for line in reader.lines() {
        let line = line.unwrap();
        if !line.starts_with('r') {
            blocklist.insert(line);
        }
    }

    let port = args[1].parse::<u16>().expect("Expect port as u16");

    let iterative = match args[2].as_str() {
        "0" => true,
        "1" => false,
        _ => {
            println!("iterative must be 0 or 1");
            return;
        }
    };

    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", port)).await.expect("failed to bind UDP socket"));

    println!("Listening on {}, iterative={}", socket.local_addr().unwrap(), iterative);
    let public_dns_servers: Arc<Mutex<(Vec<SocketAddr>, usize)>> = Arc::new(Mutex::new((
        vec![
            SocketAddr::from_str("8.8.8.8:53").unwrap(),
            SocketAddr::from_str("8.8.4.4:53").unwrap(),
            SocketAddr::from_str("1.1.1.1:53").unwrap(),
            SocketAddr::from_str("1.0.0.1:53").unwrap(),
            SocketAddr::from_str("9.9.9.9:53").unwrap(),
        ],
        0,
    )));

    let dns_cache: Arc<Cache<String, CachedValue>> = Arc::new(Cache::new(1000));
    let blocklist = Arc::new(blocklist);
    let limiter = Arc::new(Semaphore::new(max_inflight));
    let runtime = ResolverRuntimeConfig {
        upstream_timeout: Duration::from_millis(upstream_timeout_ms),
        max_pending_upstreams,
    };

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("shutdown signal received");
    };

    tokio::pin!(shutdown);

    loop {
        let mut buf = [0u8; 4096];
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            recv = socket.recv_from(&mut buf) => {
                let (len, src) = match recv {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("recv_from failed: {e}");
                        continue;
                    }
                };

                let packet = buf[..len].to_vec();
                let acquired = timeout(
                    Duration::from_millis(queue_timeout_ms),
                    limiter.clone().acquire_owned(),
                ).await;

                let permit = match acquired {
                    Ok(Ok(p)) => p,
                    _ => {
                        if let Some(reply) = servfail_response_for_packet(&packet) {
                            let _ = socket.send_to(&reply, src).await;
                        }
                        continue;
                    }
                };

                let worker_socket = Arc::clone(&socket);
                let dns_servers = Arc::clone(&public_dns_servers);
                let blocklist = Arc::clone(&blocklist);
                let cache = Arc::clone(&dns_cache);

                tokio::spawn(async move {
                    let _permit = permit;
                    handle_packet(
                        worker_socket,
                        packet,
                        src,
                        iterative,
                        dns_servers,
                        blocklist,
                        cache,
                        runtime,
                    ).await;
                });
            }
        }
    }

    // Graceful drain window.
    tokio::time::sleep(Duration::from_secs(2)).await;
}
