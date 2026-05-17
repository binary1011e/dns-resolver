use crate::cache_util::make_cache_key;
use crate::resolver::transport::DnsTransport;
use crate::resolver::types::{ResolutionOutcome, ResolutionStatus, Resolver};
use crate::CachedValue;
use async_recursion::async_recursion;
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use moka::sync::Cache;
use rand::Rng;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub(crate) const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4:53",
    "199.9.14.201:53",
    "192.33.4.12:53",
    "199.7.91.13:53",
    "192.203.230.10:53",
    "192.5.5.241:53",
    "192.112.36.4:53",
    "198.97.190.53:53",
    "192.36.148.17:53",
    "192.58.128.30:53",
    "193.0.14.129:53",
    "199.7.83.42:53",
    "202.12.27.33:53",
];

pub struct IterativeResolver<'a> {
    transport: &'a dyn DnsTransport,
    cache: &'a Cache<String, CachedValue>,
}

impl<'a> IterativeResolver<'a> {
    pub fn new(transport: &'a dyn DnsTransport, cache: &'a Cache<String, CachedValue>) -> Self {
        Self { transport, cache }
    }

    #[async_recursion]
    async fn resolve_names(&self, names: &[Name], depth: usize) -> Result<Vec<SocketAddr>, Error> {
        if depth > 16 {
            return Err(Error::new(ErrorKind::Other, "max recursion depth"));
        }

        let mut addrs = Vec::new();
        for name in names {
            if let Ok(records) = self.lookup_records(name.clone(), RecordType::A, depth).await {
                for record in records {
                    if let RData::A(ip) = record.data {
                        addrs.push(SocketAddr::new((*ip).into(), 53));
                    }
                }
            }
            if let Ok(records) = self.lookup_records(name.clone(), RecordType::AAAA, depth).await {
                for record in records {
                    if let RData::AAAA(ip) = record.data {
                        addrs.push(SocketAddr::new((*ip).into(), 53));
                    }
                }
            }
        }

        Ok(addrs)
    }

    #[async_recursion]
    async fn lookup_records(&self, name: Name, qtype: RecordType, depth: usize) -> Result<Vec<Record>, Error> {
        if depth > 16 {
            return Err(Error::new(ErrorKind::Other, "max recursion depth reached"));
        }

        let key = make_cache_key(&name, qtype);
        if let Some(entry) = self.cache.get(&key) {
            let now = Instant::now();
            match entry {
                CachedValue::Answers { records, expires_at } if expires_at > now => {
                    let remaining = expires_at.duration_since(now).as_secs() as u32;
                    let adjusted = records
                        .into_iter()
                        .map(|mut r| {
                            r.ttl = remaining.min(r.ttl);
                            r
                        })
                        .collect();
                    return Ok(adjusted);
                }
                CachedValue::NXDomain { expires_at } if expires_at > now => {
                    return Err(Error::new(ErrorKind::Other, "DNS error: NXDomain"));
                }
                CachedValue::ServFail { expires_at } if expires_at > now => {
                    return Err(Error::new(ErrorKind::Other, "DNS error: ServFail"));
                }
                _ => self.cache.invalidate(&key),
            }
        }

        let mut root_servers: Vec<SocketAddr> = ROOT_SERVERS.iter().map(|s| s.parse().unwrap()).collect();

        let mut current_name = name.clone();
        let mut collected: Vec<Record> = Vec::new();
        for _ in 0..16 {
            for _ in 0..16 {
                let mut response_bytes: Option<Vec<u8>> = None;

                for server in &root_servers {
                    let id: u16 = rand::thread_rng().r#gen();
                    let query_bytes = build_query(current_name.clone(), qtype, id)?;
                    let resp_bytes = match self.transport.exchange(&query_bytes, *server).await {
                        Ok(b) => b,
                        Err(_) => continue,
                    };

                    let resp = match Message::from_vec(&resp_bytes) {
                        Ok(resp) => resp,
                        Err(_) => continue,
                    };

                    if resp.metadata.id != id {
                        continue;
                    }
                    response_bytes = Some(resp_bytes);
                    break;
                }

                let bytes = response_bytes.ok_or_else(|| Error::new(ErrorKind::TimedOut, "no response from servers"))?;
                let resp = Message::from_vec(&bytes).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

                let final_records: Vec<Record> = resp
                    .answers
                    .iter()
                    .filter(|r| r.name == current_name && r.record_type() == qtype)
                    .cloned()
                    .collect();

                if !final_records.is_empty() {
                    collected.extend(final_records);
                    let min_ttl = collected.iter().map(|r| r.ttl).min().unwrap_or(60).max(30);
                    self.cache.insert(
                        make_cache_key(&name, qtype),
                        CachedValue::Answers {
                            records: collected.clone(),
                            expires_at: Instant::now() + Duration::from_secs(min_ttl as u64),
                        },
                    );
                    return Ok(collected);
                }

                if let Some(cname_record) = resp
                    .answers
                    .iter()
                    .find(|r| r.name == current_name && r.record_type() == RecordType::CNAME)
                    .cloned()
                {
                    let target = match &cname_record.data {
                        RData::CNAME(name) => name.0.clone(),
                        _ => unreachable!(),
                    };

                    collected.push(cname_record);
                    current_name = target;
                    root_servers = ROOT_SERVERS.iter().map(|s| s.parse().unwrap()).collect();
                    break;
                }

                if resp.metadata.response_code == ResponseCode::NXDomain {
                    let neg_ttl = resp
                        .authorities
                        .iter()
                        .filter_map(|r| match &r.data {
                            RData::SOA(soa) => Some(soa.minimum.min(r.ttl)),
                            _ => None,
                        })
                        .min()
                        .unwrap_or(60)
                        .max(30);
                    self.cache.insert(
                        make_cache_key(&name, qtype),
                        CachedValue::NXDomain {
                            expires_at: Instant::now() + Duration::from_secs(neg_ttl as u64),
                        },
                    );
                    return Err(Error::new(ErrorKind::Other, "DNS Error: NXDomain"));
                }
                if resp.metadata.response_code == ResponseCode::ServFail {
                    self.cache.insert(
                        make_cache_key(&name, qtype),
                        CachedValue::ServFail {
                            expires_at: Instant::now() + Duration::from_secs(5),
                        },
                    );
                    return Err(Error::new(ErrorKind::Other, "DNS Error: ServFail"));
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
                    self.cache.insert(
                        make_cache_key(&name, qtype),
                        CachedValue::Answers {
                            records: collected.clone(),
                            expires_at: Instant::now() + Duration::from_secs(min_ttl as u64),
                        },
                    );
                    return Ok(collected);
                }

                let ns_names: Vec<Name> = resp
                    .authorities
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::NS(n) => Some(n.0.clone()),
                        _ => None,
                    })
                    .collect();

                let mut next: Vec<SocketAddr> = resp
                    .additionals
                    .iter()
                    .filter_map(|r| {
                        if !ns_names.contains(&r.name) {
                            return None;
                        }
                        match r.data {
                            RData::A(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                            RData::AAAA(ip) => Some(SocketAddr::new((*ip).into(), 53)),
                            _ => None,
                        }
                    })
                    .collect();

                if next.is_empty() {
                    next = self.resolve_names(&ns_names, depth + 1).await?;
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

        Err(Error::new(
            ErrorKind::Other,
            "max CNAME/referral iterations reached",
        ))
    }
}

#[async_trait]
impl Resolver for IterativeResolver<'_> {
    async fn resolve(&self, _request: &Message, question: &Query) -> ResolutionOutcome {
        match self.lookup_records(question.name().clone(), question.query_type(), 0).await {
            Ok(records) => {
                let (authorities, answers): (Vec<Record>, Vec<Record>) = records
                    .into_iter()
                    .partition(|r| r.record_type() == RecordType::SOA);
                ResolutionOutcome::noerror(answers, authorities)
            }
            Err(e) => {
                let status = if e.kind() == ErrorKind::TimedOut {
                    ResolutionStatus::Timeout
                } else if e.kind() == ErrorKind::InvalidData {
                    ResolutionStatus::Malformed
                } else {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("nxdomain") {
                        ResolutionStatus::NxDomain
                    } else if msg.contains("servfail") {
                        ResolutionStatus::ServFail
                    } else {
                        ResolutionStatus::ServFail
                    }
                };
                ResolutionOutcome::with_status(status, Vec::new())
            }
        }
    }
}

pub(crate) fn build_query(name: Name, qtype: RecordType, id: u16) -> Result<Vec<u8>, Error> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = false;
    let mut query = Query::query(name, qtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);
    msg.to_vec().map_err(|e| Error::new(ErrorKind::InvalidData, e))
}
