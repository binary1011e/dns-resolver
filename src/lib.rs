mod cache_util;

use hickory_proto::op::{Message, ResponseCode, OpCode, Query, MessageType};
use hickory_proto::rr::{Name, RData, Record, RecordType, DNSClass};
use std::io::Error;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use moka::sync::Cache;
use rand::Rng;
use crate::cache_util::make_cache_key;

const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4:53", "199.9.14.201:53", "192.33.4.12:53",
    "199.7.91.13:53", "192.203.230.10:53", "192.5.5.241:53",
    "192.112.36.4:53", "198.97.190.53:53", "192.36.148.17:53",
    "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53",
    "202.12.27.33:53",
];

#[derive(Clone)]
pub enum CachedValue {
    Answers {records: Vec<Record>, expires_at: Instant},
    // Negative caching: NXDomain is held in cache for longer than ServFail
    NXDomain {expires_at: Instant},
    ServFail {expires_at: Instant},
}

pub fn handle_packet(socket: UdpSocket, packet: Vec<u8>, src: SocketAddr,
                     iterative: bool, dns_servers: Arc<Mutex<(Vec<SocketAddr>, usize)>>,
                     blocklist: &HashSet<String>,
                     dns_cache: Arc<Cache<String, CachedValue>>) {
    println!("got {} bytes from {}", packet.len(), src);
    let send_socket = UdpSocket::bind("0.0.0.0:0")
        .expect("failed to bind UDP socket");
    send_socket.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    if iterative {
        match iterative_resolve(&packet, &send_socket, blocklist, dns_cache.as_ref()) {
            Ok(reply) => {
                let _ = socket.send_to(&reply, src);
            }
            Err(msg) => {
                eprintln!("iterative resolve error: {}", msg);
            }
        }
    } else { // In recursive case, just ask a public DNS server and return its result
        let ip = {
            let mut guard = dns_servers.lock().unwrap();
            let index = guard.1;
            let ip = guard.0[index];
            guard.1 = (guard.1 + 1) % guard.0.len();
            ip
        };
        send_socket.send_to(packet.as_slice(), ip).expect("");
        let mut buf = [0u8; 4096];
        let (len, _) = send_socket
            .recv_from(&mut buf)
            .expect("recv_from failed");
        let _ = socket.send_to(&buf[..len], src);
    }
}

fn iterative_resolve(query: &[u8], send_socket: &UdpSocket, blocklist: &HashSet<String>, dns_cache: &Cache<String, CachedValue>) -> Result<Vec<u8>, Error> {
    let request = Message::from_vec(query).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    let question = request.queries.first().ok_or_else(|| Error::new(ErrorKind::InvalidData, "no query exists"))?.clone();
    if blocked_packet(&question.name().clone(), blocklist) {
        return build_blocked_response(&request, &question);
    }
    let records = iterative_lookup_records(
        question.name().clone(),
        question.query_type(),
        send_socket,
        0,
        dns_cache
    );
    match records {
        Ok(records) => {
            let mut response = Message::new(request.metadata.id, MessageType::Response, request.metadata.op_code);
            response.metadata.response_code = ResponseCode::NoError;
            response.metadata.recursion_desired = request.metadata.recursion_desired;
            response.metadata.recursion_available = false;
            response.metadata.authoritative = false;
            response.metadata.truncation = false;
            response.add_query(question.clone());
            for record in records {
                if record.record_type() == RecordType::SOA {
                    response.add_authority(record);
                } else {
                    response.add_answer(record);
                }
            }
            response
                .to_vec()
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))
        } Err (e) => {
            let mut response = Message::new(
                request.metadata.id,
                MessageType::Response,
                request.metadata.op_code,
            );
            println!("iterative lookup failed: {}", e);
            response.metadata.response_code = ResponseCode::ServFail;
            if e.to_string().contains("NXDomain") {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            response.metadata.recursion_desired = request.metadata.recursion_desired;
            response.metadata.authoritative = false;
            response.metadata.truncation = false;

            response.add_query(question.clone());

            response
                .to_vec()
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))
        }
    }
}

fn resolve_names(names : &[Name], socket: &UdpSocket, depth: usize, dns_cache: &Cache<String, CachedValue>) -> Result<Vec<SocketAddr>, Error> {
    if depth > 16 {
    return Err(Error::new(ErrorKind::Other, "max recursion depth"));
    }
    let mut addrs = Vec::new();
    for name in names {
        let a_records = iterative_lookup_records(
            name.clone(),
            RecordType::A,
            socket,
            depth,
            dns_cache
        );
        match a_records {
            Ok(records) => {
                 for record in records {
                    if let RData::A(ip) = record.data {
                        addrs.push(SocketAddr::new((*ip).into(), 53));
                    }
                }
            } Err(_) => {
                continue;
            }
        }
        let aaaa_records = iterative_lookup_records(
            name.clone(),
            RecordType::AAAA,
            socket,
            depth,
            dns_cache
        );
        match aaaa_records {
            Ok(records) => {
                 for record in records {
                    if let RData::AAAA(ip) = record.data {
                        addrs.push(SocketAddr::new((*ip).into(), 53));
                    }
                }
            } Err(_) => {
                continue;
            }
        }           
       
    }

    Ok(addrs)
}

fn iterative_lookup_records(name: Name, qtype: RecordType,
                            send_socket: &UdpSocket, depth: usize, cache: &Cache<String, CachedValue>) -> Result<Vec<Record>, Error> {
    if depth > 16 {
        return Err(Error::new(ErrorKind::Other, "max recursion depth reached"));
    }
    let key = make_cache_key(&name, qtype);
    if let Some(entry) = cache.get(&key) {
        let now = Instant::now();
        match entry {
            CachedValue::Answers {records, expires_at} if expires_at > now => {
                let remaining = expires_at.duration_since(now).as_secs() as u32;
                let adjusted = records.into_iter().map(|mut r| {
                    r.ttl = remaining.min(r.ttl);
                    r
                }).collect();
                return Ok(adjusted);
            }
            CachedValue::NXDomain {expires_at} if expires_at > now => {
                return Err(Error::new(ErrorKind::Other, "DNS error: NXDomain"))
            }
            _ => { cache.invalidate(&key); }
        }
    }

    let mut root_servers: Vec<SocketAddr> = ROOT_SERVERS.iter()
        .map(|s| s.parse().unwrap())
        .collect();

    let mut current_name = name.clone();
    let mut collected: Vec<Record> = Vec::new();
    for _ in 0..16 {
        for _ in 0..16 { // Cap # referral hops at 16 before giving up, only 2-4 hops needed usually
            let mut response_bytes: Option<Vec<u8>> = None;

            // Try each server until one responds
            for serv in &root_servers {
                let mut rng = rand::thread_rng();
                let id: u16 = rng.r#gen();
                let query_bytes = build_query(current_name.clone(), qtype, id)?;
                let _ = send_socket.send_to(&query_bytes, serv);
                let mut buf = [0u8; 4096];
                if let Ok((len, src)) = send_socket.recv_from(&mut buf) {
                    // Sanity checks
                    if src != *serv {
                        continue;
                    }
                    let resp = match Message::from_vec(&buf[..len]) {
                        Ok(resp) => resp,
                        Err(e) => {
                            println!("bad DNS response from {}: {}", serv, e);
                            continue;
                        }
                    };
                    
                    if resp.metadata.id != id {
                        continue;
                    }
                    response_bytes = Some(buf[..len].to_vec());
                    break;
                }
            }

            let bytes = response_bytes.ok_or_else(
                || Error::new(ErrorKind::TimedOut, "no response from servers"))?;
            let resp = Message::from_vec(&bytes)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

            // If response contains an answer we are done
            let final_records: Vec<Record> = resp
                .answers
                .iter()
                .filter(|r| r.name == current_name && r.record_type() == qtype)
                .cloned()
                .collect();

            if !final_records.is_empty() {
                collected.extend(final_records);
                let min_ttl = collected.iter().map(|r| r.ttl).min().unwrap_or(60).max(30);
                cache.insert(make_cache_key(&name, qtype),
                CachedValue::Answers {
                    records: collected.clone(),
                    expires_at: Instant::now() + Duration::from_secs(min_ttl as u64),
                });
                return Ok(collected);
            }

            let cname_record = resp
                .answers
                .iter()
                .find(|r| r.name == current_name && r.record_type() == RecordType::CNAME)
                .cloned();

            if let Some(cname_record) = cname_record {
                let target = match &cname_record.data {
                    RData::CNAME(name) => name.0.clone(),
                    _ => unreachable!(),
                };

                collected.push(cname_record);
                current_name = target;
                root_servers = ROOT_SERVERS
                .iter()
                .map(|s| s.parse().unwrap())
                .collect();
                break;
            }

            // forward NXDOMAIN and SERVFAIL errors as-is
            if resp.metadata.response_code == ResponseCode::NXDomain {
                // by REF 2308: TTL is min of SOA minimum field and SOA TTL
                let neg_ttl = resp.authorities.iter()
                    .filter_map(|r| match &r.data {
                        RData::SOA(soa) => Some(soa.minimum.min(r.ttl)),
                        _ => None,
                    })
                    .min()
                    .unwrap_or(60)
                    .max(30);
                let key = make_cache_key(&name, qtype);
                cache.insert(key,
                             CachedValue::NXDomain {
                                 expires_at: Instant::now() + Duration::from_secs(neg_ttl as u64)
                             });
                return Err(Error::new(
                        ErrorKind::Other,
                        "DNS Error: NXDomain",
                ));
            }
            if resp.metadata.response_code == ResponseCode::ServFail {
                // Put into cache with a small TTL like 5 secs, per RFC
                let key = make_cache_key(&name, qtype);
                cache.insert(key, CachedValue::ServFail {
                    expires_at: Instant::now() + Duration::from_secs(5)
                });

                return Err(Error::new(
                    ErrorKind::Other,
                    "DNS Error: ServFail",
                ));
            }

            let soa_records: Vec<Record> = resp
                .authorities
                .iter()
                .filter(|r| r.record_type() == RecordType::SOA)
                .cloned()
                .collect();

            if !soa_records.is_empty() {
                collected.extend(soa_records);
                let min_ttl = collected.iter().map(|r| r.ttl).min().unwrap_or(60).max(30);
                cache.insert(make_cache_key(&name, qtype),
                             CachedValue::Answers {
                                 records: collected.clone(),
                                 expires_at: Instant::now() + Duration::from_secs(min_ttl as u64),
                             });
                return Ok(collected);
            }

            // Continue iterating along the chain of servers
            // Create next server list from AUTHORITY + gluing in ADDITIONAL
            let ns_names: Vec<Name> = resp.authorities.iter()
                .filter_map(|r| match &r.data {
                    RData::NS(n) => { // n.0 is the name
                        Some(n.0.clone())
                    }
                    _ => None
                }).collect();

            // Additionals gives us the IP of the names from AUTHORITY
            let mut next: Vec<SocketAddr> = resp.additionals.iter()
                .filter_map(|r| {
                    if !ns_names.contains(&r.name) { return None; }
                    match r.data {
                        RData::A(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                        RData::AAAA(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                        _ => None
                    }
                }).collect();

            if next.is_empty() {
                next = resolve_names(&ns_names, send_socket, depth + 1, cache)?;
            }
            if next.is_empty() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "referral had NS names but no usable A/AAAA addresses",
                ));
            }
            root_servers = next;
        }
    }
    Err(Error::new(ErrorKind::Other, "max CNAME/referral iterations reached"))
}

fn build_blocked_response(request: &Message, question: &Query) -> Result<Vec<u8>, Error> {
    let mut response = Message::new(request.metadata.id, MessageType::Response, request.metadata.op_code);
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = false;
    response.metadata.authoritative = false;
    response.metadata.truncation = false;
    response.add_query(question.clone());

    // Send back bad ip for A and AAAA.
    match question.query_type().clone() {
        RecordType::A => {
            let record = Record::from_rdata(
                question.name.clone(), 60, RData::A(Ipv4Addr::new(0, 0, 0, 0).into()),
            );
            response.add_answer(record);
        }

        RecordType::AAAA => {
            let record = Record::from_rdata(question.name.clone(), 60, RData::AAAA(Ipv6Addr::UNSPECIFIED.into()),
            );
            response.add_answer(record);
        }
        _ => {
        }
    }
    response.to_vec().map_err(|e| Error::new(ErrorKind::InvalidData, e))

}

fn build_query(name: Name, qtype: RecordType, id: u16) -> Result<Vec<u8>, Error> {

    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = false;
    let mut query = Query::query(name, qtype);

    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    msg.to_vec().map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

fn blocked_packet(name: &Name, blocklist: &HashSet<String>) -> bool {
    let q = name.to_ascii().trim_end_matches('.').to_lowercase();

    for blocked in blocklist {
        if q == *blocked || q.ends_with(&format!(".{}", blocked)) {
            return true;
        }
    }
    false
}