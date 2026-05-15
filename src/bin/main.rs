use dns::{handle_packet, CachedValue};
use std::net::{SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{env, thread};
use std::fs::File;
use std::io::{self, BufRead};
use std::collections::HashSet;
use moka::sync::Cache;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Wrong # args. 3 not {}", args.len());
        return;
    }
    let file = File::open("ads-nl.txt").unwrap();
    
    let reader = io::BufReader::new(file);
    let mut blocklist = HashSet::new();

    for line in reader.lines() {
        let line = line.unwrap();
        if !line.starts_with("r") {
            blocklist.insert(line);
        }
    }
    
    let port = args[1].parse::<u16>().expect("Expect port as u16");

    // 0 for iterative, 1 for recursive
    let iterative = match args[2].as_str() {
        "0" => true,
        "1" => false,
        _ => {
            println!("iterative must be 0 or 1");
            return;
        }
    };

    let socket = UdpSocket::bind(("0.0.0.0", port))
        .expect("failed to bind UDP socket");

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
    loop {
        let mut buf = [0u8; 4096];

        let (len, src) = socket
            .recv_from(&mut buf)
            .expect("recv_from failed");

        // Copy packet data out of the stack buffer so the thread owns it.
        let packet = buf[..len].to_vec();

        // Clone the socket if the worker thread may need to send a response.
        let worker_socket = socket.try_clone().expect("failed to clone socket");
        let dns_servers = Arc::clone(&public_dns_servers);
        let blocklist = blocklist.clone();
        let cache = Arc::clone(&dns_cache);
        thread::spawn(move || {
            handle_packet(worker_socket, packet, src, iterative, dns_servers, &blocklist, cache);
        });
    }
}
