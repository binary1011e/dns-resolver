use async_trait::async_trait;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::Record;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStatus {
    NoError,
    NxDomain,
    ServFail,
    Timeout,
    Malformed,
}

#[derive(Debug, Clone)]
pub struct ResolutionOutcome {
    pub status: ResolutionStatus,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
}

impl ResolutionOutcome {
    pub(crate) fn noerror(answers: Vec<Record>, authorities: Vec<Record>) -> Self {
        Self {
            status: ResolutionStatus::NoError,
            answers,
            authorities,
        }
    }

    pub(crate) fn with_status(status: ResolutionStatus, authorities: Vec<Record>) -> Self {
        Self {
            status,
            answers: Vec::new(),
            authorities,
        }
    }
}

#[async_trait]
pub trait Resolver {
    async fn resolve(&self, request: &Message, question: &Query) -> ResolutionOutcome;
}
