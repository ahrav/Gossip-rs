//! Foundational distributed runtime types for receipt-driven worker execution.
//!
//! This module defines the shared nouns consumed by the distributed worker
//! loop: lease payloads ([`ShardLease`]), coordinator callbacks
//! ([`DistributedCoordinator`]), cloned persistence handles
//! ([`DistributedPersistence`]), runtime configuration
//! ([`DistributedRuntimeConfig`]), run reports ([`DistributedRunReport`]),
//! and error layering ([`DistributedRuntimeError`]).

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::{Error as AnyError, Result};
use gossip_contracts::{
    connector::Cursor,
    identity::{PolicyHash, TenantSecretKey},
    persistence::WriteContext,
};

/// Error returned when a [`ShardLease`] construction detects that the
/// assignment's policy hash does not match the write context's policy hash.
///
/// This is a boundary-validation failure: the coordinator adapter produced
/// inconsistent shard data, typically during rolling policy updates or
/// coordinator bugs. Surfacing this as a recoverable error lets the worker
/// loop skip the shard and continue draining the queue instead of crashing.
#[derive(Debug, Clone)]
pub struct PolicyMismatchError {
    /// Shard label that triggered the mismatch.
    pub shard_id: Arc<str>,
    /// Policy hash carried by the assignment payload.
    pub assignment_hash: PolicyHash,
    /// Policy hash carried by the write context.
    pub write_context_hash: PolicyHash,
}

impl fmt::Display for PolicyMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shard {:?}: assignment policy_hash ({:?}) != write_context policy_hash ({:?})",
            self.shard_id, self.assignment_hash, self.write_context_hash,
        )
    }
}

impl std::error::Error for PolicyMismatchError {}

use crate::{
    ScanBudgets, ScanReport, ScanRuntimeError, coordination_sink::CoordinationEventRecorder,
};

/// Assignment payloads expose their policy scope so leases can assert that the
/// payload agrees with the shared write context.
pub trait ShardLeaseAssignment {
    /// Detection-policy hash carried by the assignment payload.
    fn policy_hash(&self) -> PolicyHash;
}

/// Lease payload consumed by the distributed runtime.
///
/// One lease corresponds to one shard from the coordination layer. The string
/// shard label routes telemetry, while [`WriteContext`] carries the numeric
/// shard identity used for fenced writes.
#[derive(Clone, Debug)]
pub struct ShardLease<A> {
    /// String shard label used for routing recorder events.
    shard_id: Arc<str>,
    /// Scan assignment payload associated with this lease.
    assignment: A,
    /// Shared routing and fencing metadata for all writes emitted under the
    /// lease.
    write_context: WriteContext,
    /// Tenant secret key used for secret-hash derivation.
    tenant_secret_key: TenantSecretKey,
}

impl<A: ShardLeaseAssignment> ShardLease<A> {
    /// Construct a lease payload, validating that the assignment and write
    /// context agree on policy scope.
    ///
    /// Returns [`PolicyMismatchError`] when the hashes diverge. This is a
    /// boundary-validation check: the coordinator adapter is responsible for
    /// producing consistent shard data, but a mismatch must be surfaced as a
    /// recoverable error so the worker loop can skip the shard instead of
    /// crashing.
    pub fn new(
        shard_id: Arc<str>,
        assignment: A,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
    ) -> std::result::Result<Self, PolicyMismatchError> {
        let assignment_hash = assignment.policy_hash();
        let write_context_hash = write_context.policy_hash();

        if assignment_hash != write_context_hash {
            return Err(PolicyMismatchError {
                shard_id,
                assignment_hash,
                write_context_hash,
            });
        }

        Ok(Self {
            shard_id,
            assignment,
            write_context,
            tenant_secret_key,
        })
    }
}

impl<A> ShardLease<A> {
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

    /// Shared routing and fencing metadata for all writes emitted under the
    /// lease.
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

/// Coordinator surface required by the distributed runtime.
///
/// Implementors must guarantee:
///
/// - `acquire_shard` returns `None` when no more work is available.
/// - Production coordinators make `complete_shard` idempotent or
///   at-least-once tolerant because crash recovery may replay the call.
/// - `mark_shard_done` is called only after `complete_shard` succeeds.
/// - `release_shard` validates lease ownership.
/// - `event_recorder` is safe to share across event and commit telemetry for
///   one shard.
///
/// # Design note
///
/// This trait intentionally bundles shard lifecycle, done-ledger, and
/// recorder access into one surface. The worker loop calls all six methods
/// on the same coordinator instance. Split into focused traits when a
/// second implementation or test double needs a subset.
///
/// Methods are synchronous so the trait can be used in deterministic
/// simulation tests without an async runtime. Implementations that wrap
/// remote I/O should run on a dedicated OS thread or use interior
/// `block_on`; the worker loop must not call these methods from a Tokio
/// reactor thread.
pub trait DistributedCoordinator<A>: Send + Sync
where
    A: ShardLeaseAssignment,
{
    /// Acquire the next lease to process, or `None` when no work remains.
    fn acquire_shard(&self) -> Result<Option<ShardLease<A>>>;

    /// Release a lease without marking it complete.
    fn release_shard(&self, lease: &ShardLease<A>) -> Result<()>;

    /// Mark one lease complete with optional receipt-derived checkpoint
    /// metadata. The [`Cursor`] is the connector-layer owned cursor; the
    /// coordinator adapter bridges it to `CursorUpdate` for the coordination
    /// backend.
    fn complete_shard(
        &self,
        lease: &ShardLease<A>,
        checkpoint: Option<Cursor>,
        report: ScanReport,
    ) -> Result<()>;

    /// Query done-ledger status before scanning a shard.
    fn is_shard_done(&self, lease: &ShardLease<A>) -> Result<bool>;

    /// Persist done-ledger completion after successful scan.
    fn mark_shard_done(&self, lease: &ShardLease<A>) -> Result<()>;

    /// Shared recorder used by event and progress telemetry.
    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder>;
}

/// Shared persistence backends used by the distributed runtime.
///
/// The runtime clones these handles per shard. Production backends should make
/// that cheap, for example by cloning an `Arc` or a pool handle.
#[derive(Clone, Debug)]
pub struct DistributedPersistence<F, D>
where
    F: Clone + Send + Sync,
    D: Clone + Send + Sync,
{
    /// Findings sink handle cloned by the worker loop.
    pub findings_sink: F,
    /// Done-ledger handle cloned by the worker loop.
    pub done_ledger: D,
}

impl<F, D> DistributedPersistence<F, D>
where
    F: Clone + Send + Sync,
    D: Clone + Send + Sync,
{
    /// Construct one runtime durability bundle.
    #[must_use]
    pub fn new(findings_sink: F, done_ledger: D) -> Self {
        Self {
            findings_sink,
            done_ledger,
        }
    }
}

/// Runtime config for distributed scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DistributedRuntimeConfig {
    /// Scan execution budget controls applied to every shard assignment.
    pub budgets: ScanBudgets,
    /// Capacity of the bounded execution-to-commit queue. Matches the
    /// [`CommitPipelineConfig`](crate::commit_pipeline::CommitPipelineConfig)
    /// default.
    pub commit_queue_capacity: NonZeroUsize,
}

impl Default for DistributedRuntimeConfig {
    fn default() -> Self {
        Self {
            budgets: ScanBudgets::default(),
            commit_queue_capacity: NonZeroUsize::new(64).unwrap(),
        }
    }
}

/// Summary report from one distributed runtime invocation.
///
/// Invariant: `shards_scanned + shards_skipped_done <= leases_seen`.
/// The difference (`leases_seen - shards_scanned - shards_skipped_done`)
/// represents leases that were acquired but released without completion,
/// for example due to a per-shard runtime error or a coordinator-level skip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DistributedRunReport {
    /// Total number of leases dequeued from the coordinator.
    pub leases_seen: u64,
    /// Number of shards that were scanned.
    pub shards_scanned: u64,
    /// Number of shards skipped because they were already done.
    pub shards_skipped_done: u64,
}

/// Distributed runtime error.
#[derive(Debug)]
pub enum DistributedRuntimeError {
    /// The coordinator returned an error.
    Coordinator(AnyError),
    /// The scan runtime failed while executing an assignment.
    Runtime(ScanRuntimeError),
    /// The local durability pipeline failed.
    Durability(AnyError),
}

impl fmt::Display for DistributedRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinator(error) => write!(f, "coordinator error: {error}"),
            Self::Runtime(error) => write!(f, "runtime error: {error}"),
            Self::Durability(error) => write!(f, "durability pipeline error: {error}"),
        }
    }
}

impl std::error::Error for DistributedRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coordinator(error) => Some(error.as_ref()),
            Self::Runtime(error) => Some(error),
            Self::Durability(error) => Some(error.as_ref()),
        }
    }
}

impl From<ScanRuntimeError> for DistributedRuntimeError {
    fn from(value: ScanRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossip_contracts::identity::{FenceEpoch, RunId, ShardId, TenantId};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StubAssignment {
        policy_hash: PolicyHash,
    }

    impl ShardLeaseAssignment for StubAssignment {
        fn policy_hash(&self) -> PolicyHash {
            self.policy_hash
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StubFindings(u8);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StubDoneLedger(u8);

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
        .expect("matching hashes should succeed");

        assert_eq!(lease.shard_id(), "shard-a");
        assert_eq!(lease.assignment(), &assignment);
        assert_eq!(lease.write_context(), write_context);
        assert_eq!(
            lease.tenant_secret_key(),
            TenantSecretKey::from_bytes([0x33; 32])
        );
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
        let assignment = StubAssignment {
            policy_hash: PolicyHash::from_bytes([0xFF; 32]),
        };

        let err = ShardLease::new(
            Arc::from("shard-x"),
            assignment,
            write_context,
            TenantSecretKey::from_bytes([0x33; 32]),
        )
        .expect_err("mismatched hashes should fail");

        assert_eq!(&*err.shard_id, "shard-x");
        assert_eq!(err.assignment_hash, PolicyHash::from_bytes([0xFF; 32]));
        assert_eq!(err.write_context_hash, PolicyHash::from_bytes([0x22; 32]));
    }

    #[test]
    fn distributed_persistence_clones_backend_handles() {
        let persistence = DistributedPersistence::new(StubFindings(1), StubDoneLedger(2));
        let cloned = persistence.clone();

        assert_eq!(persistence.findings_sink, StubFindings(1));
        assert_eq!(persistence.done_ledger, StubDoneLedger(2));
        assert_eq!(cloned.findings_sink, StubFindings(1));
        assert_eq!(cloned.done_ledger, StubDoneLedger(2));
    }

    #[test]
    fn distributed_runtime_config_defaults_commit_queue_capacity() {
        let config = DistributedRuntimeConfig::default();

        assert_eq!(config.budgets, ScanBudgets::default());
        assert_eq!(config.commit_queue_capacity, NonZeroUsize::new(64).unwrap());
    }

    #[test]
    fn distributed_runtime_error_exposes_variant_sources() {
        let coordinator = DistributedRuntimeError::Coordinator(AnyError::msg("coord boom"));
        assert_eq!(coordinator.to_string(), "coordinator error: coord boom");
        assert!(std::error::Error::source(&coordinator).is_some());

        let runtime =
            DistributedRuntimeError::from(ScanRuntimeError::Driver(AnyError::msg("scan")));
        assert_eq!(
            runtime.to_string(),
            "runtime error: runtime execution failed: scan"
        );
        assert!(std::error::Error::source(&runtime).is_some());

        let durability = DistributedRuntimeError::Durability(AnyError::msg("commit boom"));
        assert_eq!(
            durability.to_string(),
            "durability pipeline error: commit boom"
        );
        assert!(std::error::Error::source(&durability).is_some());
    }
}
