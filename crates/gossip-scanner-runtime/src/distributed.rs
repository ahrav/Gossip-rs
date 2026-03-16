//! Distributed runtime placeholders for family-oriented execution.
//!
//! This module exposes the high-level distributed runtime nouns without the
//! removed driver-based lease execution surface.

use std::fmt;
use std::sync::Arc;

use anyhow::anyhow;
use gossip_contracts::{
    identity::{PolicyHash, TenantSecretKey},
    persistence::WriteContext,
};

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

/// Assignment payload that can report its policy scope for lease validation.
pub trait ShardLeaseAssignment {
    /// Detection-policy hash carried by the assignment payload.
    fn policy_hash(&self) -> PolicyHash;
}

/// Lease payload consumed by the future distributed runtime.
///
/// One lease corresponds to one shard from the coordination layer. The string
/// shard label routes runtime telemetry, while [`WriteContext`] carries the
/// numeric shard identity used for fenced writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardLease<A> {
    shard_id: Arc<str>,
    assignment: A,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
}

/// Policy-hash mismatch between a shard assignment and its write context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMismatchError {
    assignment: PolicyHash,
    context: PolicyHash,
}

impl fmt::Display for PolicyMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "assignment policy_hash ({:?}) does not match write_context policy_hash ({:?})",
            self.assignment, self.context
        )
    }
}

impl std::error::Error for PolicyMismatchError {}

impl PolicyMismatchError {
    /// Policy hash carried by the assignment payload.
    #[must_use]
    pub fn assignment(&self) -> PolicyHash {
        self.assignment
    }

    /// Policy hash carried by the write context.
    #[must_use]
    pub fn context(&self) -> PolicyHash {
        self.context
    }
}

impl<A: ShardLeaseAssignment> ShardLease<A> {
    /// Construct a lease payload, verifying that assignment and write context
    /// agree on policy scope.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyMismatchError`] if the assignment's policy hash differs
    /// from the write context's policy hash.
    pub fn new(
        shard_id: Arc<str>,
        assignment: A,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
    ) -> Result<Self, PolicyMismatchError> {
        if assignment.policy_hash() != write_context.policy_hash() {
            return Err(PolicyMismatchError {
                assignment: assignment.policy_hash(),
                context: write_context.policy_hash(),
            });
        }

        Ok(Self {
            shard_id,
            assignment,
            write_context,
            tenant_secret_key,
        })
    }

    /// String shard label used for routing recorder events.
    #[inline]
    #[must_use]
    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    /// Scan assignment payload associated with this lease.
    #[inline]
    #[must_use]
    pub fn assignment(&self) -> &A {
        &self.assignment
    }

    /// Shared routing and fencing metadata for all writes emitted under the lease.
    #[inline]
    #[must_use]
    pub fn write_context(&self) -> WriteContext {
        self.write_context
    }

    /// Tenant secret key used for secret-hash derivation.
    #[inline]
    #[must_use]
    pub fn tenant_secret_key(&self) -> TenantSecretKey {
        self.tenant_secret_key
    }
}

/// Summary report from one distributed runtime invocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    use gossip_contracts::identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StubAssignment {
        policy_hash: PolicyHash,
    }

    impl ShardLeaseAssignment for StubAssignment {
        fn policy_hash(&self) -> PolicyHash {
            self.policy_hash
        }
    }

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

    #[test]
    fn shard_lease_preserves_assignment_and_write_context() {
        let write_context = WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(3),
            ShardId::from_raw(4),
            FenceEpoch::from_raw(5),
        );
        let assignment = StubAssignment {
            policy_hash: write_context.policy_hash(),
        };
        let lease = ShardLease::new(
            Arc::from("shard-a"),
            assignment.clone(),
            write_context,
            TenantSecretKey::from_bytes([0x33; 32]),
        )
        .unwrap();

        assert_eq!(lease.shard_id(), "shard-a");
        assert_eq!(lease.assignment(), &assignment);
        assert_eq!(lease.write_context(), write_context);
    }

    #[test]
    fn shard_lease_rejects_mismatched_policy_hash() {
        let write_context = WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(3),
            ShardId::from_raw(4),
            FenceEpoch::from_raw(5),
        );
        let assignment_hash = PolicyHash::from_bytes([0xFF; 32]);
        let assignment = StubAssignment {
            policy_hash: assignment_hash,
        };
        let err = ShardLease::new(
            Arc::from("shard-x"),
            assignment,
            write_context,
            TenantSecretKey::from_bytes([0x33; 32]),
        )
        .unwrap_err();

        assert_eq!(err.assignment(), assignment_hash);
        assert_eq!(err.context(), write_context.policy_hash());
    }
}
