mod iterative;
mod recursive;
mod transport;
mod types;

pub use iterative::IterativeResolver;
pub use recursive::RecursiveForwardResolver;
pub use transport::UdpTransportAdapter;
pub use types::{ResolutionOutcome, ResolutionStatus, Resolver};

#[cfg(test)]
mod tests;
