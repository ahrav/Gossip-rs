//! Distributed runtime placeholders for family-oriented execution.
//!
//! This module exposes the high-level distributed runtime nouns without the
//! removed driver-based lease execution surface.

use anyhow::anyhow;

use crate::{ScanBudgets, ScanRuntimeError};

/// Family selected for distributed execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributedFamily {
    /// Ordered-content family worker loop.
    OrderedContent,
    /// Git repository family worker loop.
    GitRepo,
}

/// Runtime config for distributed scans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributedRunConfig {
    /// Source family to execute.
    pub family: DistributedFamily,
    /// Budget controls applied to the run.
    pub budgets: ScanBudgets,
}

impl Default for DistributedRunConfig {
    fn default() -> Self {
        Self {
            family: DistributedFamily::OrderedContent,
            budgets: ScanBudgets::default(),
        }
    }
}

/// Summary report from one distributed runtime invocation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DistributedRunReport {
    /// Total number of leases dequeued from the coordinator.
    pub leases_seen: u64,
    /// Number of shards that were scanned.
    pub shards_scanned: u64,
    /// Number of shards skipped because they were already done.
    pub shards_skipped_done: u64,
}

/// Error returned by distributed runtime entry points.
#[derive(Debug)]
pub enum DistributedRuntimeError {
    /// Underlying runtime error.
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

/// Run the distributed worker loop for the selected family.
pub fn run_distributed(
    config: &DistributedRunConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError> {
    config.budgets.validate()?;
    let family = match config.family {
        DistributedFamily::OrderedContent => "ordered-content",
        DistributedFamily::GitRepo => "git-repo",
    };
    Err(ScanRuntimeError::Driver(anyhow!(
        "{family} distributed runtime path is not implemented yet"
    ))
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributed_runtime_validates_budgets_before_placeholder_error() {
        let error = run_distributed(&DistributedRunConfig {
            family: DistributedFamily::OrderedContent,
            budgets: ScanBudgets {
                max_items: 0,
                max_bytes: 1,
            },
        })
        .expect_err("zero budget should fail");

        assert!(matches!(
            error,
            DistributedRuntimeError::Runtime(ScanRuntimeError::ConnectorInput(_))
        ));
    }

    #[test]
    fn distributed_runtime_returns_placeholder_error() {
        let error = run_distributed(&DistributedRunConfig::default()).expect_err("placeholder");
        assert!(matches!(
            error,
            DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(_))
        ));
    }
}
