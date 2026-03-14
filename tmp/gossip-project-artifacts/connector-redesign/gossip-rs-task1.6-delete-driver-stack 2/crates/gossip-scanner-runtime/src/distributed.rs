//! Distributed runtime placeholders for the new family-oriented execution model.
//!
//! Task 1.5 removed the previous driver-based distributed path from the
//! runtime compile surface. Concrete leased worker loops land in later tasks.

use crate::{ScanBudgets, ScanRuntimeError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributedFamily {
    OrderedContent,
    GitRepo,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedRunConfig {
    pub family: DistributedFamily,
    pub budgets: ScanBudgets,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DistributedRunReport {
    pub leases_seen: u64,
    pub shards_scanned: u64,
    pub shards_skipped_done: u64,
}

#[derive(Debug)]
pub enum DistributedRuntimeError {
    Runtime(ScanRuntimeError),
}

impl std::fmt::Display for DistributedRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DistributedRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
        }
    }
}

impl From<ScanRuntimeError> for DistributedRuntimeError {
    fn from(value: ScanRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

pub fn run_distributed(_config: &DistributedRunConfig) -> Result<DistributedRunReport, DistributedRuntimeError> {
    Err(ScanRuntimeError::FamilyRuntimeNotImplemented {
        family: "distributed-runtime",
        source: "worker-loop",
    }
    .into())
}
