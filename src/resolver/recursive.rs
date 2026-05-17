use crate::resolver::transport::DnsTransport;
use crate::resolver::types::{ResolutionOutcome, ResolutionStatus, Resolver};
use async_trait::async_trait;
use hickory_proto::op::{Message, Query, ResponseCode};
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;

pub struct RecursiveForwardResolver<'a> {
    transport: &'a dyn DnsTransport,
    next_server:
        Box<dyn Fn() -> Pin<Box<dyn Future<Output = SocketAddr> + Send + 'a>> + Send + Sync + 'a>,
}

impl<'a> RecursiveForwardResolver<'a> {
    pub fn new(
        transport: &'a dyn DnsTransport,
        next_server: Box<
            dyn Fn() -> Pin<Box<dyn Future<Output = SocketAddr> + Send + 'a>> + Send + Sync + 'a,
        >,
    ) -> Self {
        Self {
            transport,
            next_server,
        }
    }
}

#[async_trait]
impl Resolver for RecursiveForwardResolver<'_> {
    async fn resolve(&self, request: &Message, _question: &Query) -> ResolutionOutcome {
        let bytes = match request.to_vec() {
            Ok(v) => v,
            Err(_) => return ResolutionOutcome::with_status(ResolutionStatus::Malformed, Vec::new()),
        };
        let server = (self.next_server)().await;
        let response_bytes = match self.transport.exchange(&bytes, server).await {
            Ok(v) => v,
            Err(e) => {
                return if e.kind() == ErrorKind::TimedOut {
                    ResolutionOutcome::with_status(ResolutionStatus::Timeout, Vec::new())
                } else {
                    ResolutionOutcome::with_status(ResolutionStatus::ServFail, Vec::new())
                }
            }
        };
        let response = match Message::from_vec(&response_bytes) {
            Ok(v) => v,
            Err(_) => return ResolutionOutcome::with_status(ResolutionStatus::Malformed, Vec::new()),
        };

        let status = match response.metadata.response_code {
            ResponseCode::NoError => ResolutionStatus::NoError,
            ResponseCode::NXDomain => ResolutionStatus::NxDomain,
            ResponseCode::ServFail => ResolutionStatus::ServFail,
            _ => ResolutionStatus::ServFail,
        };

        ResolutionOutcome {
            status,
            answers: response.answers,
            authorities: response.authorities,
        }
    }
}
