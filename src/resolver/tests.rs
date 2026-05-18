use super::iterative::ROOT_SERVERS;
use super::transport::DnsTransport;
use async_trait::async_trait;
use super::*;
use crate::cache_util::make_cache_key;
use crate::CachedValue;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{CNAME, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use moka::sync::Cache;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct ScriptedTransportAdapter {
    scripts: Mutex<HashMap<SocketAddr, VecDeque<Result<Vec<u8>, Error>>>>,
}

impl ScriptedTransportAdapter {
    fn new() -> Self {
        Self {
            scripts: Mutex::new(HashMap::new()),
        }
    }

    fn push_response(&self, server: SocketAddr, response: Result<Vec<u8>, Error>) {
        let mut scripts = self.scripts.lock().unwrap();
        scripts.entry(server).or_default().push_back(response);
    }
}

#[async_trait]
impl DnsTransport for ScriptedTransportAdapter {
    async fn exchange(&self, request: &[u8], server: SocketAddr) -> Result<Vec<u8>, Error> {
        let mut scripts = self.scripts.lock().unwrap();
        let queue = scripts
            .get_mut(&server)
            .ok_or_else(|| Error::new(ErrorKind::TimedOut, "no scripted server response"))?;
        match queue.pop_front() {
            Some(Ok(bytes)) => {
                let req = Message::from_vec(request).ok();
                let mut resp = Message::from_vec(&bytes).ok();
                if let (Some(req), Some(ref mut resp)) = (req, resp.as_mut()) {
                    resp.metadata.id = req.metadata.id;
                    return resp
                        .to_vec()
                        .map_err(|e| Error::new(ErrorKind::InvalidData, e));
                }
                Ok(bytes)
            }
            Some(Err(err)) => Err(err),
            None => Err(Error::new(ErrorKind::TimedOut, "scripted response depleted")),
        }
    }
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn query(name: &str, qtype: RecordType) -> Query {
    Query::query(Name::from_ascii(name).unwrap(), qtype)
}

fn req(name: &str, qtype: RecordType) -> Message {
    let mut m = Message::new(7, MessageType::Query, OpCode::Query);
    m.add_query(query(name, qtype));
    m
}

fn response_with(
    id: u16,
    code: ResponseCode,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
) -> Vec<u8> {
    let mut m = Message::new(id, MessageType::Response, OpCode::Query);
    m.metadata.response_code = code;
    for a in answers {
        m.add_answer(a);
    }
    for a in authorities {
        m.add_authority(a);
    }
    for a in additionals {
        m.add_additional(a);
    }
    m.to_vec().unwrap()
}

fn scripted_with_single(response: Vec<u8>) -> ScriptedTransportAdapter {
    let transport = ScriptedTransportAdapter::new();
    let root: SocketAddr = ROOT_SERVERS[0].parse().unwrap();
    transport.push_response(root, Ok(response));
    transport
}

#[tokio::test]
async fn direct_answer_path() {
    let qn = name("example.com.");
    let answer = Record::from_rdata(qn.clone(), 120, RData::A(Ipv4Addr::new(1, 2, 3, 4).into()));
    let r = response_with(0, ResponseCode::NoError, vec![answer], vec![], vec![]);
    let transport = scripted_with_single(r);
    let cache = Cache::new(100);
    let resolver = IterativeResolver::new(&transport, &cache);
    let request = req("example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::NoError);
    assert_eq!(out.answers.len(), 1);
}

#[tokio::test]
async fn cname_chain_resolution() {
    let qn = name("www.example.com.");
    let target = name("example.com.");
    let cname = Record::from_rdata(qn.clone(), 120, RData::CNAME(CNAME(target.clone().into())));
    let a = Record::from_rdata(target.clone(), 120, RData::A(Ipv4Addr::new(2, 2, 2, 2).into()));
    let t = ScriptedTransportAdapter::new();
    let root: SocketAddr = ROOT_SERVERS[0].parse().unwrap();
    t.push_response(root, Ok(response_with(0, ResponseCode::NoError, vec![cname], vec![], vec![])));
    t.push_response(root, Ok(response_with(0, ResponseCode::NoError, vec![a], vec![], vec![])));
    let cache = Cache::new(100);
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("www.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::NoError);
    assert_eq!(out.answers.len(), 2);
}

#[tokio::test]
async fn nxdomain_and_negative_cache() {
    let soa = Record::from_rdata(
        name("example.com."),
        300,
        RData::SOA(SOA::new(name("ns1.example.com."), name("hostmaster.example.com."), 1, 2, 3, 4, 60)),
    );
    let mut m = Message::new(0, MessageType::Response, OpCode::Query);
    m.metadata.response_code = ResponseCode::NXDomain;
    m.add_authority(soa);
    let root: SocketAddr = ROOT_SERVERS[0].parse().unwrap();
    let t = ScriptedTransportAdapter::new();
    t.push_response(root, Ok(m.to_vec().unwrap()));
    let cache = Cache::new(100);
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("missing.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::NxDomain);
    let key = make_cache_key(&name("missing.example.com."), RecordType::A);
    assert!(matches!(cache.get(&key), Some(CachedValue::NXDomain { .. })));
}

#[tokio::test]
async fn servfail_short_term_cache() {
    let mut m = Message::new(0, MessageType::Response, OpCode::Query);
    m.metadata.response_code = ResponseCode::ServFail;
    let root: SocketAddr = ROOT_SERVERS[0].parse().unwrap();
    let t = ScriptedTransportAdapter::new();
    t.push_response(root, Ok(m.to_vec().unwrap()));
    let cache = Cache::new(100);
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("broken.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::ServFail);
    let key = make_cache_key(&name("broken.example.com."), RecordType::A);
    assert!(matches!(cache.get(&key), Some(CachedValue::ServFail { .. })));
}

#[tokio::test]
async fn timeout_handling() {
    let cache = Cache::new(100);
    let t = ScriptedTransportAdapter::new();
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("timeout.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::Timeout);
}

#[tokio::test]
async fn referral_with_glue_records() {
    let qn = name("x.example.com.");
    let nsn = name("ns1.example.net.");
    let referral = Record::from_rdata(name("example.com."), 300, RData::NS(NS(nsn.clone().into())));
    let glue = Record::from_rdata(nsn, 300, RData::A(Ipv4Addr::new(4, 4, 4, 4).into()));
    let answer = Record::from_rdata(qn, 300, RData::A(Ipv4Addr::new(9, 9, 9, 9).into()));
    let root: SocketAddr = ROOT_SERVERS[0].parse().unwrap();
    let child = SocketAddr::new(Ipv4Addr::new(4, 4, 4, 4).into(), 53);
    let t = ScriptedTransportAdapter::new();
    t.push_response(root, Ok(response_with(0, ResponseCode::NoError, vec![], vec![referral], vec![glue])));
    t.push_response(child, Ok(response_with(0, ResponseCode::NoError, vec![answer], vec![], vec![])));
    let cache = Cache::new(100);
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("x.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::NoError);
    assert_eq!(out.answers.len(), 1);
}

#[tokio::test]
async fn referral_requires_ns_name_resolution() {
    let qn = name("x.example.com.");
    let nsn = name("ns1.example.net.");
    let referral = Record::from_rdata(name("example.com."), 300, RData::NS(NS(nsn.clone().into())));
    let ns_a = Record::from_rdata(nsn.clone(), 300, RData::A(Ipv4Addr::new(5, 5, 5, 5).into()));
    let answer = Record::from_rdata(qn, 300, RData::A(Ipv4Addr::new(6, 6, 6, 6).into()));
    let root: SocketAddr = ROOT_SERVERS[0].parse().unwrap();
    let child = SocketAddr::new(Ipv4Addr::new(5, 5, 5, 5).into(), 53);
    let t = ScriptedTransportAdapter::new();
    t.push_response(root, Ok(response_with(0, ResponseCode::NoError, vec![], vec![referral], vec![])));
    t.push_response(root, Ok(response_with(0, ResponseCode::NoError, vec![ns_a], vec![], vec![])));
    t.push_response(child, Ok(response_with(0, ResponseCode::NoError, vec![answer], vec![], vec![])));
    let cache = Cache::new(100);
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("x.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::NoError);
    assert_eq!(out.answers.len(), 1);
}

#[tokio::test]
async fn cache_hit_ttl_adjustment() {
    let cache = Cache::new(100);
    let qn = name("cached.example.com.");
    let rec = Record::from_rdata(qn.clone(), 300, RData::AAAA(Ipv6Addr::LOCALHOST.into()));
    cache.insert(
        make_cache_key(&qn, RecordType::AAAA),
        CachedValue::Answers {
            records: vec![rec],
            expires_at: Instant::now() + Duration::from_secs(2),
        },
    );

    let t = ScriptedTransportAdapter::new();
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("cached.example.com.", RecordType::AAAA);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::NoError);
    assert_eq!(out.answers.len(), 1);
    assert!(out.answers[0].ttl <= 2);
}

#[tokio::test]
async fn recursive_servfail_propagation() {
    let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = ScriptedTransportAdapter::new();
    transport.push_response(server, Ok(response_with(0, ResponseCode::ServFail, vec![], vec![], vec![])));
    let resolver = RecursiveForwardResolver::new(&transport, Box::new(move || Box::pin(async move { server })));
    let request = req("recursive.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::ServFail);
}

#[tokio::test]
async fn transport_error_with_nxdomain_text_still_times_out_after_retries() {
    let root: SocketAddr = ROOT_SERVERS[0].parse().unwrap();
    let t = ScriptedTransportAdapter::new();
    t.push_response(root, Err(Error::new(ErrorKind::Other, "nxdomain text from transport")));
    let cache = Cache::new(100);
    let resolver = IterativeResolver::new(&t, &cache);
    let request = req("message.example.com.", RecordType::A);
    let out = resolver.resolve(&request, request.queries.first().unwrap()).await;
    assert_eq!(out.status, ResolutionStatus::Timeout);
}
