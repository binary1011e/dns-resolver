mod cache_util;
mod resolver;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use moka::sync::Cache;
use resolver::{
    IterativeResolver, RecursiveForwardResolver, ResolutionOutcome, ResolutionStatus, Resolver,
    UdpTransportAdapter,
};
use std::collections::HashSet;
use std::future::Future;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone)]
pub enum CachedValue {
    Answers { records: Vec<Record>, expires_at: Instant },
    NXDomain { expires_at: Instant },
    ServFail { expires_at: Instant },
}

#[derive(Clone, Copy)]
pub struct ResolverRuntimeConfig {
    pub upstream_timeout: Duration,
    pub max_pending_upstreams: usize,
}

pub async fn handle_packet(
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    src: SocketAddr,
    iterative: bool,
    dns_servers: Arc<Mutex<(Vec<SocketAddr>, usize)>>,
    blocklist: Arc<HashSet<String>>,
    dns_cache: Arc<Cache<String, CachedValue>>,
    runtime: ResolverRuntimeConfig,
) {
    println!("got {} bytes from {}", packet.len(), src);
    let request = match Message::from_vec(&packet) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to parse request: {e}");
            return;
        }
    };

    let question = match request.queries.first() {
        Some(q) => q,
        None => {
            eprintln!("request had no question");
            return;
        }
    };

    let outcome = if blocked_packet(question.name(), &blocklist) {
        blocked_outcome(question)
    } else {
        let send_socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to bind UDP socket: {e}");
                return;
            }
        };

        let transport = match UdpTransportAdapter::new(
            send_socket,
            runtime.upstream_timeout,
            runtime.max_pending_upstreams,
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                eprintln!("failed to initialize transport: {e}");
                return;
            }
        };

        if iterative {
            IterativeResolver::new(&transport, dns_cache.as_ref())
                .resolve(&request, question)
                .await
        } else {
            let dns_servers_ref = Arc::clone(&dns_servers);
            let picker = move || {
                let dns_servers_ref = Arc::clone(&dns_servers_ref);
                let fut: Pin<Box<dyn Future<Output = SocketAddr> + Send>> = Box::pin(async move {
                    let mut guard = dns_servers_ref.lock().await;
                    let index = guard.1;
                    let ip = guard.0[index];
                    guard.1 = (guard.1 + 1) % guard.0.len();
                    ip
                });
                fut
            };
            RecursiveForwardResolver::new(&transport, Box::new(picker))
                .resolve(&request, question)
                .await
        }
    };

    match build_response(&request, question, outcome) {
        Ok(reply) => {
            let _ = socket.send_to(&reply, src).await;
        }
        Err(e) => {
            eprintln!("failed to build response: {e}");
        }
    }
}

fn build_response(request: &Message, question: &Query, outcome: ResolutionOutcome) -> Result<Vec<u8>, Error> {
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata.response_code = map_status(outcome.status);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = false;
    response.metadata.authoritative = false;
    response.metadata.truncation = false;
    response.add_query(question.clone());

    for record in outcome.answers {
        response.add_answer(record);
    }
    for record in outcome.authorities {
        response.add_authority(record);
    }

    response
        .to_vec()
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

pub fn servfail_response_for_packet(packet: &[u8]) -> Option<Vec<u8>> {
    let request = Message::from_vec(packet).ok()?;
    let question = request.queries.first()?.clone();
    build_response(
        &request,
        &question,
        ResolutionOutcome::with_status(ResolutionStatus::ServFail, Vec::new()),
    )
    .ok()
}

fn map_status(status: ResolutionStatus) -> ResponseCode {
    match status {
        ResolutionStatus::NoError => ResponseCode::NoError,
        ResolutionStatus::NxDomain => ResponseCode::NXDomain,
        ResolutionStatus::ServFail | ResolutionStatus::Timeout | ResolutionStatus::Malformed => {
            ResponseCode::ServFail
        }
    }
}

fn blocked_outcome(question: &Query) -> ResolutionOutcome {
    let mut answers = Vec::new();
    match question.query_type() {
        RecordType::A => answers.push(Record::from_rdata(
            question.name().clone(),
            60,
            RData::A(Ipv4Addr::new(0, 0, 0, 0).into()),
        )),
        RecordType::AAAA => answers.push(Record::from_rdata(
            question.name().clone(),
            60,
            RData::AAAA(Ipv6Addr::UNSPECIFIED.into()),
        )),
        _ => {}
    }

    ResolutionOutcome {
        status: ResolutionStatus::NoError,
        answers,
        authorities: Vec::new(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::OpCode;

    #[test]
    fn packet_assembly_maps_nxdomain() {
        let mut request = Message::new(10, MessageType::Query, OpCode::Query);
        let q = Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A);
        request.add_query(q.clone());

        let reply = build_response(
            &request,
            &q,
            ResolutionOutcome {
                status: ResolutionStatus::NxDomain,
                answers: Vec::new(),
                authorities: Vec::new(),
            },
        )
        .unwrap();

        let parsed = Message::from_vec(&reply).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(parsed.queries.len(), 1);
    }
}
