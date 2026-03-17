//! Foundational distributed runtime types for receipt-driven worker execution.
//!
//! This module defines the shared nouns consumed by the distributed worker
//! loop: lease payloads ([`ShardLease`]), coordinator callbacks
//! ([`DistributedCoordinator`]), cloned persistence handles
//! ([`DistributedPersistence`]), runtime configuration
//! ([`DistributedRuntimeConfig`]), run reports ([`DistributedRunReport`]),
//! and error layering ([`DistributedRuntimeError`]).
//!
//! It also provides `ReceiptCommitSink`, the compatibility adapter that
//! translates scan-driver `CommitSink` callbacks into receipt-driven commit
//! pipeline work.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Error as AnyError, Result};
use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{LogicalTime, ObjectVersionId, PolicyHash, RuleFingerprint, TenantSecretKey},
    persistence::WriteContext,
};
use scanner_scheduler::store::FsFindingRecord;

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
    ScanBudgets, ScanReport, ScanRuntimeError,
    commit_model::CompletedUnit,
    commit_pipeline::{CommitPipelineSender, QueuedCommit},
    commit_sink::{CommitSink, FindingsBatch, ItemMeta},
    coordination_sink::{CommitProgressRecord, CoordinationEventRecorder},
    result_translation::{ItemResult, ScanTiming, translate_item_result},
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

/// One item that has begun scanning but has not yet been submitted to commit.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct InFlightItem {
    sequence_no: u64,
    item_key: ItemKey,
    meta: ItemMeta,
    findings: Vec<FsFindingRecord>,
}

/// Ordered record of one item successfully handed to the commit pipeline.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SubmittedCommit {
    sequence_no: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SubmittedCommit {
    #[inline]
    #[must_use]
    fn sequence_no(&self) -> u64 {
        self.sequence_no
    }
}

/// Scan-driver commit sink that bridges begin/upsert/finish callbacks into the
/// receipt-driven commit pipeline.
///
/// The existing scan-driver seam still emits compact `ItemMeta` and
/// `FindingRecord` batches rather than the richer runtime commit inputs.
/// `ReceiptCommitSink` reconstructs the deterministic translation inputs
/// expected by the shared commit pipeline so ordered-content execution can
/// produce durable receipts without changing the scheduler callback surface.
#[cfg_attr(not(test), allow(dead_code))]
struct ReceiptCommitSink {
    shard_id: Arc<str>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
    rule_fingerprint: Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>,
    submitter: CommitPipelineSender,
    next_sequence_no: AtomicU64,
    in_flight: Mutex<BTreeMap<Vec<u8>, InFlightItem>>,
    submitted: Mutex<Vec<SubmittedCommit>>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ReceiptCommitSink {
    fn new(
        recorder: Arc<dyn CoordinationEventRecorder>,
        shard_id: Arc<str>,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
        rule_fingerprint: Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>,
        submitter: CommitPipelineSender,
    ) -> Self {
        Self {
            shard_id,
            recorder,
            write_context,
            tenant_secret_key,
            rule_fingerprint,
            submitter,
            next_sequence_no: AtomicU64::new(0),
            in_flight: Mutex::new(BTreeMap::new()),
            submitted: Mutex::new(Vec::new()),
        }
    }

    fn finish(self) -> Result<Vec<SubmittedCommit>> {
        let in_flight = self
            .in_flight
            .into_inner()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;
        if !in_flight.is_empty() {
            return Err(anyhow::anyhow!(
                "receipt commit sink finished with {} item(s) still in flight",
                in_flight.len()
            ));
        }

        self.submitted
            .into_inner()
            .map_err(|_| anyhow::anyhow!("receipt commit sink submitted state lock poisoned"))
    }

    fn next_sequence_no(&self) -> u64 {
        self.next_sequence_no.fetch_add(1, Ordering::Relaxed)
    }

    fn logical_timing_for(sequence_no: u64) -> Result<ScanTiming> {
        let started = sequence_no.checked_mul(2).ok_or_else(|| {
            anyhow::anyhow!("sequence number overflow while deriving scan timing")
        })?;
        let finished = started.checked_add(1).ok_or_else(|| {
            anyhow::anyhow!("sequence number overflow while deriving scan timing")
        })?;

        Ok(ScanTiming::new(
            LogicalTime::from_raw(started),
            LogicalTime::from_raw(finished),
        ))
    }

    fn record_begin(&self, item_key: &ItemKey, meta: &ItemMeta) {
        let _ = self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Begin {
                write_context: self.write_context,
                item_key: item_key.as_bytes().to_vec(),
                size_hint: meta.size_hint,
            },
        );
    }

    fn record_finish(&self, item_key: &ItemKey) {
        let _ = self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Finish {
                write_context: self.write_context,
                item_key: item_key.as_bytes().to_vec(),
            },
        );
    }

    fn translate_in_flight(&self, item: InFlightItem) -> Result<QueuedCommit> {
        let timing = Self::logical_timing_for(item.sequence_no)?;
        let bytes_scanned = item.meta.size_hint.unwrap_or(0);
        let version = item.meta.version.unwrap_or_else(|| {
            VersionId::Weak(ObjectVersionId::from_version_bytes(
                item.item_key.as_bytes(),
            ))
        });
        let checkpoint_cursor = Cursor::with_last_key(item.item_key.clone());
        let item_ref = ItemRef::try_from_slice(item.item_key.as_bytes())?;
        let mut scan_item =
            ScanItem::new(item.item_key, item_ref, item.meta.stable_item_id, version);

        if let Some(size_hint) = item.meta.size_hint {
            scan_item = scan_item.with_size_hint(size_hint);
        }

        if let Ok(display) = std::str::from_utf8(scan_item.item_key().as_bytes())
            && let Ok(location) = Location::try_new(display.to_owned(), None)
        {
            scan_item = scan_item.with_location(location);
        }

        let translation = translate_item_result(
            self.write_context,
            &self.tenant_secret_key,
            &scan_item,
            bytes_scanned,
            timing,
            ItemResult::Scanned {
                findings: &item.findings,
            },
            &*self.rule_fingerprint,
        )?;

        Ok(QueuedCommit::new(
            self.write_context,
            CompletedUnit::ordered_content(item.sequence_no, checkpoint_cursor),
            translation,
        ))
    }
}

impl CommitSink for ReceiptCommitSink {
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
        let sequence_no = self.next_sequence_no();
        let key_bytes = item_key.as_bytes().to_vec();
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;

        if guard.contains_key(&key_bytes) {
            return Err(anyhow::anyhow!(
                "begin_item called twice without finish_item for the same item"
            ));
        }

        guard.insert(
            key_bytes,
            InFlightItem {
                sequence_no,
                item_key: item_key.clone(),
                meta: meta.clone(),
                findings: Vec::new(),
            },
        );
        drop(guard);

        self.record_begin(item_key, meta);
        Ok(())
    }

    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()> {
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;
        let item = guard
            .get_mut(item_key.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("upsert_findings called before begin_item for item"))?;

        item.findings
            .extend(batch.findings.iter().map(|finding| FsFindingRecord {
                rule_id: finding.rule_id,
                root_hint_start: finding.start,
                root_hint_end: finding.end,
                span_start: finding.start,
                span_end: finding.end,
                norm_hash: finding.norm_hash,
                confidence_score: finding.confidence_score,
            }));

        Ok(())
    }

    fn finish_item(&self, item_key: &ItemKey) -> Result<()> {
        let item = self
            .in_flight
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?
            .remove(item_key.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("finish_item called before begin_item for item"))?;

        let sequence_no = item.sequence_no;
        let work = self.translate_in_flight(item)?;
        self.submitter
            .submit(work)
            .map_err(|error| anyhow::anyhow!("execution to commit submission failed: {error}"))?;

        self.submitted
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink submitted state lock poisoned"))?
            .push(SubmittedCommit { sequence_no });

        self.record_finish(item_key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use gossip_contracts::{
        connector::ItemKey,
        identity::{
            FenceEpoch, PolicyHash, RuleFingerprint, RunId, ShardId, StableItemId, TenantId,
            TenantSecretKey, derive_rule_fingerprint,
        },
        persistence::WriteContext,
    };
    use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};

    use crate::{
        CancellationToken, OwnedCoreEvent,
        commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput},
        commit_sink::{FindingRecord, FindingsBatch, ItemMeta},
        coordination_sink::{CommitProgressRecord, StoredGitEvent},
    };

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

    #[derive(Default)]
    struct Recorder {
        progress: Mutex<Vec<CommitProgressRecord>>,
    }

    impl CoordinationEventRecorder for Recorder {
        fn record_core_event(&self, _shard_id: &str, _event: OwnedCoreEvent) -> Result<()> {
            Ok(())
        }

        fn record_git_event(&self, _shard_id: &str, _event: StoredGitEvent) -> Result<()> {
            Ok(())
        }

        fn record_commit_progress(
            &self,
            _shard_id: &str,
            event: CommitProgressRecord,
        ) -> Result<()> {
            self.progress.lock().expect("progress lock").push(event);
            Ok(())
        }

        fn record_identity_chain(
            &self,
            _shard_id: &str,
            _record: crate::coordination_sink::IdentityChainRecord,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn test_rule_fingerprint(rule_id: u32) -> RuleFingerprint {
        let name = format!("test-rule-{rule_id}");
        derive_rule_fingerprint(&name)
    }

    fn write_context() -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(3),
            ShardId::from_raw(4),
            FenceEpoch::from_raw(5),
        )
    }

    fn tenant_secret_key() -> TenantSecretKey {
        TenantSecretKey::from_bytes([0x33; 32])
    }

    fn item_key(path: &str) -> ItemKey {
        ItemKey::try_from_slice(path.as_bytes()).expect("item key")
    }

    fn item_meta() -> ItemMeta {
        ItemMeta {
            stable_item_id: StableItemId::from_bytes([0x44; 32]),
            version: None,
            size_hint: Some(128),
        }
    }

    fn finding() -> FindingRecord {
        FindingRecord {
            rule_id: 7,
            start: 10,
            end: 20,
            norm_hash: [0x55; 32],
            confidence_score: 6,
        }
    }

    fn make_receipt_sink() -> (
        CommitPipeline<InMemoryFindingsSink, InMemoryDoneLedger>,
        ReceiptCommitSink,
        Arc<Recorder>,
    ) {
        let recorder = Arc::new(Recorder::default());
        let pipeline = CommitPipeline::start(
            InMemoryFindingsSink::new(),
            InMemoryDoneLedger::new(),
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            CancellationToken::new(),
        )
        .expect("pipeline should start");
        let sink = ReceiptCommitSink::new(
            recorder.clone(),
            Arc::from("shard-a"),
            write_context(),
            tenant_secret_key(),
            Arc::new(test_rule_fingerprint),
            pipeline.sender(),
        );

        (pipeline, sink, recorder)
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

    #[test]
    fn begin_item_assigns_monotonic_sequence_numbers() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let first = item_key("tenant/repo/first.txt");
        let second = item_key("tenant/repo/second.txt");
        let meta = item_meta();

        sink.begin_item(&first, &meta).expect("begin first item");
        sink.begin_item(&second, &meta).expect("begin second item");

        let guard = sink.in_flight.lock().expect("in flight lock");
        assert_eq!(
            guard.get(first.as_bytes()).expect("first item").sequence_no,
            0
        );
        assert_eq!(
            guard
                .get(second.as_bytes())
                .expect("second item")
                .sequence_no,
            1
        );
        drop(guard);

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn receipt_commit_sink_translates_and_submits_item() {
        let (pipeline, sink, recorder) = make_receipt_sink();
        let item_key = item_key("tenant/repo/file.txt");
        let meta = item_meta();

        sink.begin_item(&item_key, &meta).expect("begin item");
        sink.upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![finding()],
            },
        )
        .expect("upsert findings");
        sink.finish_item(&item_key).expect("finish item");

        let submitted = sink.finish().expect("sink finish");
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].sequence_no(), 0);

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("commit outcome")
        {
            CommitStageOutput::Committed {
                write_context: got,
                checkpoint_input,
            } => {
                assert_eq!(got, write_context());
                let receipt = checkpoint_input.into_receipt();
                assert_eq!(receipt.completed_unit().sequence_no(), 0);
                assert_eq!(
                    receipt.completed_unit().checkpoint_cursor(),
                    &Cursor::with_last_key(item_key.clone())
                );
                assert_eq!(receipt.durable().findings().finding_count(), 1);
                assert_eq!(receipt.durable().done_ledger().record_count(), 1);
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}");
            }
        }

        let progress = recorder.progress.lock().expect("progress lock");
        assert_eq!(progress.len(), 2);
        match &progress[0] {
            CommitProgressRecord::Begin {
                write_context: got,
                item_key: got_key,
                size_hint,
            } => {
                assert_eq!(*got, write_context());
                assert_eq!(got_key, item_key.as_bytes());
                assert_eq!(*size_hint, meta.size_hint);
            }
            other => panic!("expected begin progress record, got {other:?}"),
        }
        match &progress[1] {
            CommitProgressRecord::Finish {
                write_context: got,
                item_key: got_key,
            } => {
                assert_eq!(*got, write_context());
                assert_eq!(got_key, item_key.as_bytes());
            }
            other => panic!("expected finish progress record, got {other:?}"),
        }

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn upsert_findings_maps_runtime_records_into_fs_findings() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let item_key = item_key("tenant/repo/file.txt");

        sink.begin_item(&item_key, &item_meta())
            .expect("begin item");
        sink.upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![finding()],
            },
        )
        .expect("upsert findings");

        let guard = sink.in_flight.lock().expect("in flight lock");
        let item = guard
            .get(item_key.as_bytes())
            .expect("item should remain in flight");
        assert_eq!(
            item.findings,
            vec![FsFindingRecord {
                rule_id: 7,
                root_hint_start: 10,
                root_hint_end: 20,
                span_start: 10,
                span_end: 20,
                norm_hash: [0x55; 32],
                confidence_score: 6,
            }]
        );
        drop(guard);

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn begin_item_rejects_double_begin_for_same_key() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let item_key = item_key("tenant/repo/file.txt");
        let meta = item_meta();

        sink.begin_item(&item_key, &meta).expect("first begin item");
        let err = sink
            .begin_item(&item_key, &meta)
            .expect_err("duplicate begin should fail");

        assert!(
            err.to_string()
                .contains("begin_item called twice without finish_item"),
            "unexpected error: {err}"
        );

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn upsert_findings_rejects_unknown_item() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let item_key = item_key("tenant/repo/missing.txt");
        let err = sink
            .upsert_findings(
                &item_key,
                &FindingsBatch {
                    findings: vec![finding()],
                },
            )
            .expect_err("upsert without begin should fail");

        assert!(
            err.to_string()
                .contains("upsert_findings called before begin_item"),
            "unexpected error: {err}"
        );

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn finish_item_rejects_unknown_item() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let item_key = item_key("tenant/repo/missing.txt");
        let err = sink
            .finish_item(&item_key)
            .expect_err("finish without begin should fail");

        assert!(
            err.to_string()
                .contains("finish_item called before begin_item"),
            "unexpected error: {err}"
        );

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn finish_rejects_remaining_in_flight_items() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let item_key = item_key("tenant/repo/file.txt");

        sink.begin_item(&item_key, &item_meta())
            .expect("begin item");
        let err = sink
            .finish()
            .expect_err("finish should reject remaining in-flight items");

        assert!(
            err.to_string().contains("still in flight"),
            "unexpected error: {err}"
        );

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn logical_timing_rejects_sequence_overflow() {
        let err = ReceiptCommitSink::logical_timing_for(u64::MAX)
            .expect_err("overflowing timing should fail");

        assert!(
            err.to_string()
                .contains("sequence number overflow while deriving scan timing"),
            "unexpected error: {err}"
        );
    }
}
