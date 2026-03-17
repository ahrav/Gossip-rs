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
//! translates scan-loop `CommitSink` callbacks into receipt-driven commit
//! pipeline work.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Error as AnyError, Result, anyhow};
use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{LogicalTime, ObjectVersionId, PolicyHash, RuleFingerprint, TenantSecretKey},
    persistence::{CheckpointCommitReceipt, DoneLedger, FindingsSink, WriteContext},
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
    CancellationToken, FsScanConfig, ScanBudgets, ScanReport, ScanRuntimeError,
    build_runtime_engine,
    checkpoint_aggregator::PrefixCheckpointAggregator,
    commit_model::CompletedUnit,
    commit_pipeline::{
        CommitPipeline, CommitPipelineConfig, CommitPipelineDrainer, CommitPipelineSender,
        CommitStageOutput, QueuedCommit,
    },
    commit_sink::{CommitSink, FindingsBatch, ItemMeta},
    coordination_sink::{CommitProgressRecord, CoordinationEventRecorder, CoordinationEventSink},
    join_scoped,
    result_translation::{ItemResult, ScanTiming, translate_item_result},
    scan_fs_with_prebuilt_engine,
};

#[cfg(any(test, feature = "test-support"))]
use crate::OwnedCoreEvent;
#[cfg(any(test, feature = "test-support"))]
use crate::coordination_sink::StoredGitEvent;
#[cfg(any(test, feature = "test-support"))]
use std::collections::{HashSet, VecDeque};

/// Assignment payloads expose their policy scope so leases can assert that the
/// payload agrees with the shared write context.
pub trait ShardLeaseAssignment {
    /// Detection-policy hash carried by the assignment payload.
    ///
    /// Implementations must return the same value for the lifetime of `self`.
    fn policy_hash(&self) -> PolicyHash;

    /// Filesystem scan config carried by the assignment payload, if any.
    ///
    /// Distributed receipt-driven execution currently supports only filesystem
    /// leases. Assignment types that do not represent a filesystem shard should
    /// use the default `None` implementation.
    #[must_use]
    fn filesystem_scan_config(&self) -> Option<FsScanConfig> {
        None
    }
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

    /// Arc-wrapped shard label for zero-allocation sharing.
    #[inline]
    #[must_use]
    pub fn shard_id_arc(&self) -> &Arc<str> {
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
/// recorder access into one surface. The worker loop calls all methods
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
    ///
    /// `None` is terminal — the worker loop will shut down. Implementations that
    /// need to express temporary unavailability must block or retry internally.
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
///
/// Both backends must tolerate duplicate writes for the same
/// `(write_context, item_key)` pair because the worker loop provides
/// at-least-once delivery (see `run_filesystem_lease` for details).
#[derive(Clone, Debug)]
pub struct DistributedPersistence<F, D> {
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
    /// Capacity used for both the bounded execution-to-commit queue and the
    /// commit-to-checkpoint outcome queue. Matches the
    /// [`CommitPipelineConfig`] default.
    pub commit_queue_capacity: NonZeroUsize,
}

impl Default for DistributedRuntimeConfig {
    fn default() -> Self {
        Self {
            budgets: ScanBudgets::default(),
            commit_queue_capacity: NonZeroUsize::new(64).expect("hardcoded non-zero constant"),
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
///
/// Accumulates findings through [`ReceiptCommitSink::upsert_findings`] until
/// [`finish_item`](ReceiptCommitSink::finish_item) translates the accumulated
/// state into a [`QueuedCommit`] and submits it to the pipeline. On
/// translation or submission failure, the item is re-inserted into the
/// in-flight map so the caller can retry.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct InFlightItem {
    sequence_no: u64,
    meta: ItemMeta,
    findings: Vec<FsFindingRecord>,
}

/// Scan-driver commit sink that bridges begin/upsert/finish callbacks into the
/// receipt-driven commit pipeline.
///
/// The existing scan-loop seam still emits compact `ItemMeta` and
/// `FindingRecord` batches rather than the richer runtime commit inputs.
/// `ReceiptCommitSink` reconstructs the deterministic translation inputs
/// expected by the shared commit pipeline so ordered-content execution can
/// produce durable receipts without changing the scheduler callback surface.
///
/// # Threading model
///
/// This sink is driven by a single-threaded drain loop. The interior `Mutex`
/// fields satisfy the `Send + Sync` bound required by [`CommitSink`] without
/// introducing real contention. Sequence numbers assigned by
/// [`next_sequence_no`](Self::next_sequence_no) are therefore monotonically
/// ordered with respect to submission; `Ordering::Relaxed` is sufficient
/// because there is no concurrent caller to race against.
#[cfg_attr(not(test), allow(dead_code))]
struct ReceiptCommitSink {
    shard_id: Arc<str>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
    rule_fingerprint: Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>,
    submitter: CommitPipelineSender,
    next_sequence_no: AtomicU64,
    in_flight: Mutex<BTreeMap<ItemKey, InFlightItem>>,
    submitted: Mutex<Vec<u64>>,
    /// First-failure-only flag for progress telemetry. Mirrors
    /// `CoordinationEventSink`'s suppression to avoid flooding logs during
    /// sustained recorder outages.
    progress_error_logged: AtomicBool,
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
            progress_error_logged: AtomicBool::new(false),
        }
    }

    /// Consume the sink and return the sequence numbers of successfully
    /// submitted commits. Returns an error if any items remain in-flight
    /// (indicating a protocol violation by the caller) or if a mutex is
    /// poisoned.
    fn finish(self) -> Result<Vec<u64>> {
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

    /// Derive a pair of non-overlapping logical timestamps from a sequence number.
    ///
    /// Maps sequence `n` to `(2n, 2n+1)`, giving each item a unique
    /// `[started, finished)` interval that never collides with another item's
    /// interval. This is sufficient for the done-ledger provenance columns,
    /// which only require monotonicity within a single shard.
    ///
    /// Returns `Err` when `2 * sequence_no` would overflow `u64`.
    fn logical_timing_for(sequence_no: u64) -> Result<ScanTiming> {
        let started = sequence_no.checked_mul(2).ok_or_else(|| {
            anyhow::anyhow!("sequence number overflow while deriving scan timing")
        })?;
        // When checked_mul(2) succeeds, started is even and <= u64::MAX - 1
        // (u64::MAX is odd), so started + 1 fits without overflow.
        let finished = started + 1;

        Ok(ScanTiming::new(
            LogicalTime::from_raw(started),
            LogicalTime::from_raw(finished),
        ))
    }

    /// Records a begin-progress event for telemetry.
    ///
    /// Recorder errors are intentionally non-fatal: durability flows through
    /// the commit pipeline, not the recorder.
    fn record_begin(&self, item_key: &ItemKey, meta: &ItemMeta) {
        if let Err(error) = self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Begin {
                write_context: self.write_context,
                item_key: item_key.clone(),
                size_hint: meta.size_hint,
            },
        ) && !self.progress_error_logged.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                shard_id = %self.shard_id,
                %error,
                "recorder failed to persist progress event; subsequent failures suppressed",
            );
        }
    }

    /// Records a finish-progress event for telemetry.
    ///
    /// This records that the item's scan completed and was submitted to the
    /// commit pipeline — not that the commit landed durably. Durability
    /// confirmation flows through the receipt/checkpoint path, not through
    /// telemetry. See [`record_begin`](Self::record_begin) for the non-fatal
    /// error rationale.
    fn record_finish(&self, item_key: &ItemKey) {
        if let Err(error) = self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Finish {
                write_context: self.write_context,
                item_key: item_key.clone(),
            },
        ) && !self.progress_error_logged.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                shard_id = %self.shard_id,
                %error,
                "recorder failed to persist progress event; subsequent failures suppressed",
            );
        }
    }

    /// Reconstruct the deterministic translation inputs from an in-flight
    /// item's accumulated state and produce a [`QueuedCommit`] ready for the
    /// commit pipeline.
    ///
    /// When the item has no explicit `version`, a weak version derived from
    /// the item key bytes is used. When the item key is valid UTF-8, a
    /// display-only [`Location`] is attached for diagnostics.
    fn translate_in_flight(&self, item_key: &ItemKey, item: &InFlightItem) -> Result<QueuedCommit> {
        let timing = Self::logical_timing_for(item.sequence_no)?;
        let bytes_scanned = item.meta.size_hint.unwrap_or(0);
        let version = item.meta.version.unwrap_or_else(|| {
            VersionId::Weak(ObjectVersionId::from_version_bytes(item_key.as_bytes()))
        });
        let checkpoint_cursor = Cursor::with_last_key(item_key.clone());
        let item_ref = ItemRef::try_from_slice(item_key.as_bytes())?;
        let mut scan_item = ScanItem::new(
            item_key.clone(),
            item_ref,
            item.meta.stable_item_id,
            version,
        );

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

    /// Re-insert a removed item into the in-flight map on translation or
    /// submission failure.
    ///
    /// Uses `unwrap_or_else` to recover through a poisoned mutex because the
    /// rollback is not on the durability path — see the struct-level threading
    /// model documentation.
    fn rollback_in_flight(&self, key: ItemKey, item: InFlightItem) {
        let overwritten = self
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, item);
        debug_assert!(
            overwritten.is_none(),
            "rollback re-insert overwrote a concurrent begin_item entry; \
             ReceiptCommitSink must be driven by a single-threaded drain loop"
        );
    }
}

impl CommitSink for ReceiptCommitSink {
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;

        use std::collections::btree_map::Entry;
        match guard.entry(item_key.clone()) {
            Entry::Occupied(_) => {
                return Err(anyhow::anyhow!(
                    "begin_item called twice without finish_item for the same item"
                ));
            }
            Entry::Vacant(slot) => {
                let sequence_no = self.next_sequence_no();
                slot.insert(InFlightItem {
                    sequence_no,
                    meta: meta.clone(),
                    findings: Vec::new(),
                });
            }
        }
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
            .get_mut(item_key)
            .ok_or_else(|| anyhow::anyhow!("upsert_findings called before begin_item for item"))?;

        batch.validate()?;

        // The CommitSink surface provides only start/end offsets.
        // Root-hint fields are unavailable through this bridge, so both
        // root_hint_start/end mirror span_start/end. This is safe because
        // root-hint fields never participate in persistence identity
        // derivation (see the `Identity derivation` section in
        // result_translation.rs).
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
        // Remove the item under a short-lived lock. Translation and
        // submission happen outside the critical section to minimize lock
        // hold duration. The interior mutex satisfies `Send + Sync` bounds
        // but the sink is driven by a single-threaded drain loop.
        let (removed_key, item) = {
            let mut guard = self.in_flight.lock().map_err(|_| {
                anyhow::anyhow!("receipt commit sink in-flight state lock poisoned")
            })?;
            guard
                .remove_entry(item_key)
                .ok_or_else(|| anyhow::anyhow!("finish_item called before begin_item for item"))?
        };

        let sequence_no = item.sequence_no;
        let work = match self.translate_in_flight(&removed_key, &item) {
            Ok(work) => work,
            Err(err) => {
                self.rollback_in_flight(removed_key, item);
                return Err(err);
            }
        };

        if let Err(error) = self.submitter.submit(work) {
            self.rollback_in_flight(removed_key, item);
            return Err(anyhow::anyhow!(
                "execution to commit submission failed: {error}"
            ));
        }

        // The commit is in the pipeline. The submitted vec is bookkeeping
        // for ordering assertions, not the durability path — recover
        // through a poisoned mutex rather than returning an error that
        // would mislead the caller into thinking the commit was lost.
        self.submitted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(sequence_no);

        self.record_finish(item_key);
        Ok(())
    }
}

impl From<PolicyMismatchError> for DistributedRuntimeError {
    fn from(value: PolicyMismatchError) -> Self {
        Self::Coordinator(value.into())
    }
}

/// Accumulated state from draining the commit-stage outcome stream.
///
/// Produced by [`drain_commit_stage`] and consumed by
/// [`run_filesystem_lease`] to build the checkpoint and verify that every
/// submitted commit produced a durable outcome.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct CommitStageDrainResult {
    /// Receipt aggregator that tracks the contiguous committed prefix.
    aggregator: PrefixCheckpointAggregator,
    /// Sequence numbers of committed items, in drain order (not necessarily
    /// sorted). Compared against the submitted list by
    /// [`wait_for_submitted_commits`].
    committed_sequence_nos: Vec<u64>,
}

/// Drain commit-stage outcomes to completion while building the receipt-driven
/// checkpoint prefix.
///
/// Any durable commit failure, receipt aggregation violation, or worker panic
/// aborts the shard. The drainer cancels the worker before joining when the
/// first such failure is observed so scan execution does not keep queuing work
/// behind a broken durability path.
///
/// # Cancellation and outcome delivery
///
/// After `drainer.cancel()`, the commit worker uses `try_send` for any
/// in-progress or post-commit outcomes. If the outcome queue is full or
/// disconnected at that moment, the outcome is silently dropped. This is safe
/// because `drain_error` is always set before `drainer.cancel()` is called,
/// so the function returns the original error without reaching the downstream
/// sequence-number cross-check. If external cancellation were introduced,
/// callers would need to distinguish cancellation-induced outcome gaps from
/// genuine durability failures.
#[cfg_attr(not(test), allow(dead_code))]
fn drain_commit_stage<F, D>(
    drainer: CommitPipelineDrainer<F, D>,
    write_context: WriteContext,
    max_buffered: usize,
) -> Result<CommitStageDrainResult>
where
    F: FindingsSink,
    D: DoneLedger,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    // The aggregator's receipt buffer must not share the channel-backpressure
    // limit: the drain model buffers ALL committed receipts before a single
    // checkpoint is prepared (no intermediate `acknowledge_checkpoint` calls).
    // Use an uncapped limit; actual memory is bounded by the number of items
    // the shard produces, which is always finite.
    let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0, usize::MAX);
    let mut committed_sequence_nos = Vec::with_capacity(max_buffered);
    let mut drain_error = None;

    loop {
        match drainer.recv() {
            Ok(CommitStageOutput::Committed {
                checkpoint_input, ..
            }) => {
                if drain_error.is_none() {
                    let sequence_no = checkpoint_input.receipt().completed_unit().sequence_no();
                    match aggregator.record_receipt(checkpoint_input) {
                        Ok(_) => committed_sequence_nos.push(sequence_no),
                        Err(error) => {
                            drain_error = Some(anyhow!("receipt aggregation failed: {error}"));
                            drainer.cancel();
                        }
                    }
                }
            }
            Ok(CommitStageOutput::Failed {
                completed_unit,
                error,
                ..
            }) => {
                if drain_error.is_none() {
                    drain_error = Some(anyhow!(
                        "durable commit failed for sequence {}: {error}",
                        completed_unit.sequence_no()
                    ));
                    drainer.cancel();
                }
            }
            Err(_) => break,
        }
    }

    drainer
        .join()
        .map_err(|_| anyhow!("receipt commit worker thread panicked"))?;

    if let Some(error) = drain_error {
        return Err(error);
    }

    Ok(CommitStageDrainResult {
        aggregator,
        committed_sequence_nos,
    })
}

/// Verify that every submitted commit sequence produced one durable outcome.
///
/// The local commit pipeline exposes an outcome stream rather than per-item
/// completion handles, so this helper matches submitted sequence numbers
/// against the committed sequence numbers drained from that stream.
#[cfg_attr(not(test), allow(dead_code))]
fn wait_for_submitted_commits(
    mut submitted: Vec<u64>,
    mut committed_sequence_nos: Vec<u64>,
) -> Result<()> {
    // Items can finish out of sequence-number order (the atomic counter
    // assigns sequence numbers at begin_item, but finish_item order depends
    // on scan duration per item). Sort both sides so the pairwise comparison
    // below can detect mismatches by value, not by arrival order.
    submitted.sort_unstable();
    committed_sequence_nos.sort_unstable();

    // Reject duplicate sequence numbers — structurally impossible today
    // (atomic counter + aggregator rejection), but a cheap defense-in-depth
    // guard against future regressions.
    if let Some(dup) = submitted
        .windows(2)
        .find_map(|w| (w[0] == w[1]).then_some(w[0]))
    {
        return Err(anyhow!("duplicate submitted sequence number {dup}"));
    }
    if let Some(dup) = committed_sequence_nos
        .windows(2)
        .find_map(|w| (w[0] == w[1]).then_some(w[0]))
    {
        return Err(anyhow!("duplicate committed sequence number {dup}"));
    }

    if submitted.len() != committed_sequence_nos.len() {
        return Err(anyhow!(
            "submitted {} commit(s) but commit stage produced {} durable outcome(s)",
            submitted.len(),
            committed_sequence_nos.len()
        ));
    }

    for (expected, actual) in submitted.into_iter().zip(committed_sequence_nos) {
        if expected != actual {
            return Err(anyhow!(
                "submitted commit sequence {} did not match durable outcome sequence {}",
                expected,
                actual
            ));
        }
    }

    Ok(())
}

/// Derive the logical time used when acknowledging a prepared checkpoint.
///
/// Returns `last_sequence_no + 1`, placing the checkpoint acknowledgment
/// strictly after the last committed item's sequence number. The raw value
/// passed to `LogicalTime::from_raw` is derived from the sequence-number
/// domain, intentionally distinct from the `(2n, 2n+1)` logical-time
/// mapping used by `ReceiptCommitSink`.
///
/// # Errors
///
/// Returns an error if `last_sequence_no` is `u64::MAX` (no room for +1).
#[cfg_attr(not(test), allow(dead_code))]
#[inline]
fn checkpoint_logical_time(last_sequence_no: u64) -> Result<LogicalTime> {
    last_sequence_no
        .checked_add(1)
        .map(LogicalTime::from_raw)
        .ok_or_else(|| anyhow!("checkpoint logical time overflow: last_sequence_no is u64::MAX"))
}

/// Execute one filesystem lease under the receipt-driven durability model.
///
/// The scan path runs with finding persistence enabled and a single execution
/// worker so `ReceiptCommitSink` sequence assignment remains deterministic.
/// The shard completes only after every submitted item has produced a durable
/// commit outcome and the resulting committed prefix has been checkpointed.
///
/// # Completion protocol
///
/// 1. Scan execution and commit-stage drain run concurrently on scoped threads.
/// 2. After both finish, the submitted vs committed sequence lists are compared.
/// 3. The aggregator prepares a checkpoint prefix from the committed receipts.
/// 4. `complete_shard` persists the checkpoint cursor with the coordinator.
/// 5. The checkpoint is acknowledged, advancing the aggregator's watermark.
/// 6. `mark_shard_done` records the shard as complete in the done-ledger.
///
/// If any step fails, the shard is not marked done and will be retried.
///
/// # At-least-once delivery
///
/// If `complete_shard` succeeds but `mark_shard_done` fails, the shard will
/// be re-leased on the next worker iteration. The re-execution replays the
/// full scan-and-commit cycle, producing duplicate `FindingsSink` writes and
/// `DoneLedger` upserts. Both persistence backends must therefore be
/// idempotent for the same `(write_context, item_key)` pair.
#[cfg_attr(not(test), allow(dead_code))]
fn run_filesystem_lease<A, F, D>(
    coordinator: &dyn DistributedCoordinator<A>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    persistence: &DistributedPersistence<F, D>,
    lease: &ShardLease<A>,
    config: DistributedRuntimeConfig,
) -> Result<(), DistributedRuntimeError>
where
    A: ShardLeaseAssignment,
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    config.budgets.validate()?;

    let scan_config = lease
        .assignment()
        .filesystem_scan_config()
        .ok_or_else(|| {
            DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(anyhow!(
                "shard '{}' lease assignment does not carry a filesystem scan config",
                lease.shard_id()
            )))
        })?
        .with_workers(1)
        .with_budgets(config.budgets)
        .with_persist_findings(true);

    // Relaxed ordering on ReceiptCommitSink::next_sequence_no is sound only
    // when exactly one scan worker thread exists. Hard assert rather than
    // debug_assert: this is a soundness invariant that must hold in release
    // builds, and the cost (one integer comparison per shard) is negligible.
    assert_eq!(
        scan_config.workers, 1,
        "receipt-driven execution requires single-threaded scanning"
    );

    let engine = build_runtime_engine(
        scan_config.rules_file.as_deref(),
        &scan_config.transform_filter,
        scan_config.decode_depth,
        scan_config.anchor_mode,
    )?;
    let rule_fingerprint = {
        let engine = Arc::clone(&engine);
        Arc::new(move |rule_id| RuleFingerprint::from_bytes(engine.rule_fingerprint_bytes(rule_id)))
            as Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>
    };

    let sink = CoordinationEventSink::new(recorder.clone(), Arc::clone(lease.shard_id_arc()));
    let cancel = CancellationToken::new();
    let pipeline = CommitPipeline::start(
        persistence.findings_sink.clone(),
        persistence.done_ledger.clone(),
        CommitPipelineConfig {
            execution_queue_capacity: config.commit_queue_capacity.get(),
            outcome_queue_capacity: config.commit_queue_capacity.get(),
        },
        cancel.clone(),
    )
    .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;
    let (submitter, drainer) = pipeline.split();
    let commit = ReceiptCommitSink::new(
        recorder,
        Arc::clone(lease.shard_id_arc()),
        lease.write_context(),
        lease.tenant_secret_key(),
        rule_fingerprint,
        submitter,
    );

    let (outcome, submitted, stage_result) = std::thread::scope(|scope| {
        let write_context = lease.write_context();
        let max_buffered = config.commit_queue_capacity.get();
        let stage_handle =
            scope.spawn(move || drain_commit_stage(drainer, write_context, max_buffered));

        let outcome = scan_fs_with_prebuilt_engine(&scan_config, engine, &sink, &commit, &cancel);
        let submitted = commit.finish();
        let stage_result = join_scoped(stage_handle, "receipt checkpoint drain thread");

        (outcome, submitted, stage_result)
    });

    // Prefer durability errors: when the drain stage fails and cancels the
    // pipeline, the scan typically sees a downstream "pipeline cancelled"
    // Runtime error. Evaluating the drain result first exposes the root cause
    // instead of the cancellation symptom.
    //
    // Runtime errors are checked before submitted-commit accounting because a
    // failed `finish_item` rolls the item back into the in-flight map, which
    // makes `commit.finish()` return "items still in flight". Checking
    // `outcome` first preserves the original translation/span error rather
    // than surfacing its consequence.
    let CommitStageDrainResult {
        mut aggregator,
        committed_sequence_nos,
    } = stage_result
        .map_err(DistributedRuntimeError::Durability)?
        .map_err(DistributedRuntimeError::Durability)?;
    let outcome = outcome.map_err(DistributedRuntimeError::Runtime)?;
    let submitted = submitted.map_err(DistributedRuntimeError::Durability)?;

    let committed_units = committed_sequence_nos.len() as u64;

    // Shards with zero durable commit units (empty directories or directories
    // where no file produced findings) complete without a checkpoint cursor
    // because no receipt-derived cursor position exists.
    // Guard early to avoid calling prepare_checkpoint on an empty aggregator.
    if committed_units == 0 {
        coordinator
            .complete_shard(lease, None, outcome.report)
            .map_err(DistributedRuntimeError::Coordinator)?;
        coordinator
            .mark_shard_done(lease)
            .map_err(DistributedRuntimeError::Coordinator)?;
        return Ok(());
    }

    // Files without findings never reach the commit pipeline (the scanner's
    // emit_persistence_batch early-returns), so `submitted.len()` can be less
    // than items_scanned.
    wait_for_submitted_commits(submitted, committed_sequence_nos)
        .map_err(DistributedRuntimeError::Durability)?;

    let pending = aggregator
        .prepare_checkpoint()
        .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

    let pending = pending.ok_or_else(|| {
        DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' committed {} unit(s) but no receipt-driven checkpoint prefix was prepared",
            lease.shard_id(),
            committed_units
        ))
    })?;
    if pending.committed_units() != committed_units {
        return Err(DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' prepared checkpoint for {} unit(s), expected {}",
            lease.shard_id(),
            pending.committed_units(),
            committed_units
        )));
    }

    coordinator
        .complete_shard(
            lease,
            Some(pending.checkpoint_cursor().clone()),
            outcome.report,
        )
        .map_err(DistributedRuntimeError::Coordinator)?;

    let checkpoint_receipt = CheckpointCommitReceipt::new(
        pending.scope().clone(),
        checkpoint_logical_time(pending.last_sequence_no())
            .map_err(DistributedRuntimeError::Durability)?,
    );
    aggregator
        .acknowledge_checkpoint(checkpoint_receipt)
        .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

    coordinator
        .mark_shard_done(lease)
        .map_err(DistributedRuntimeError::Coordinator)?;
    Ok(())
}

/// Run the distributed worker loop until the coordinator has no more leases.
///
/// Each iteration either skips an already-complete shard, executes one
/// filesystem lease through the receipt-driven durability path, or stops with a
/// safe error when the assignment does not expose a filesystem scan config.
///
/// The loop is **fail-fast**: it terminates on the first per-shard error.
/// Progress accumulated before the failure is not returned to the caller —
/// the `Err` variant carries only the error. The caller is responsible for
/// retry or requeue. Lease release on error paths is best-effort: the
/// original error is returned even if the release itself fails (a warning is
/// logged in that case).
pub fn run_worker<A, F, D>(
    coordinator: &dyn DistributedCoordinator<A>,
    persistence: DistributedPersistence<F, D>,
    config: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError>
where
    A: ShardLeaseAssignment,
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let recorder = coordinator.event_recorder();
    let mut report = DistributedRunReport::default();

    loop {
        let lease = match coordinator.acquire_shard() {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                tracing::info!(
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    shards_skipped_done = report.shards_skipped_done,
                    "worker loop terminating with partial progress",
                );
                return Err(DistributedRuntimeError::Coordinator(e));
            }
        };
        report.leases_seen = report.leases_seen.saturating_add(1);

        let is_done = match coordinator.is_shard_done(&lease) {
            Ok(done) => done,
            Err(e) => {
                if let Err(release_err) = coordinator.release_shard(&lease) {
                    tracing::warn!(
                        shard_id = %lease.shard_id(),
                        %release_err,
                        "failed to release shard; may remain acquired until lease TTL expires",
                    );
                }
                tracing::info!(
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    shards_skipped_done = report.shards_skipped_done,
                    "worker loop terminating with partial progress",
                );
                return Err(DistributedRuntimeError::Coordinator(e));
            }
        };

        if is_done {
            if let Err(release_err) = coordinator.release_shard(&lease) {
                tracing::warn!(
                    shard_id = %lease.shard_id(),
                    %release_err,
                    "best-effort lease release failed for done shard; will expire via TTL",
                );
            }
            report.shards_skipped_done = report.shards_skipped_done.saturating_add(1);
            continue;
        }

        if let Err(e) = run_filesystem_lease(
            coordinator,
            Arc::clone(&recorder),
            &persistence,
            &lease,
            config,
        ) {
            if let Err(release_err) = coordinator.release_shard(&lease) {
                tracing::warn!(
                    shard_id = %lease.shard_id(),
                    %release_err,
                    "best-effort lease release failed after scan error",
                );
            }
            tracing::info!(
                leases_seen = report.leases_seen,
                shards_scanned = report.shards_scanned,
                shards_skipped_done = report.shards_skipped_done,
                "worker loop terminating with partial progress",
            );
            return Err(e);
        }
        report.shards_scanned = report.shards_scanned.saturating_add(1);
    }

    Ok(report)
}

/// In-memory coordinator used by tests and local harnesses.
///
/// The coordinator stores leases, shard lifecycle transitions, and recorder
/// output behind one mutex-protected state bundle. `complete_shard` is
/// intentionally non-idempotent so crash-retry tests can observe duplicate
/// completions when a shard is re-leased between completion and done-marking.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Default)]
pub struct InMemoryCoordinator<A> {
    state: Arc<Mutex<InMemoryCoordinatorState<A>>>,
}

#[cfg(any(test, feature = "test-support"))]
struct InMemoryCoordinatorState<A> {
    queue: VecDeque<ShardLease<A>>,
    done: HashSet<String>,
    done_mark_contexts: Vec<WriteContext>,
    released: Vec<String>,
    completed: Vec<CompletedShard>,
    core_events: Vec<(String, OwnedCoreEvent)>,
    git_events: Vec<(String, StoredGitEvent)>,
    commit_progress: Vec<(String, CommitProgressRecord)>,
    acquire_fail_count: usize,
    release_fail_count: usize,
    is_done_fail_count: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl<A> Default for InMemoryCoordinatorState<A> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            done: HashSet::new(),
            done_mark_contexts: Vec::new(),
            released: Vec::new(),
            completed: Vec::new(),
            core_events: Vec::new(),
            git_events: Vec::new(),
            commit_progress: Vec::new(),
            acquire_fail_count: 0,
            release_fail_count: 0,
            is_done_fail_count: 0,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub struct CompletedShard {
    pub shard_id: String,
    pub checkpoint: Option<Cursor>,
    pub report: ScanReport,
}

#[cfg(any(test, feature = "test-support"))]
impl<A> InMemoryCoordinator<A> {
    /// Create a coordinator pre-loaded with the provided lease queue.
    #[must_use]
    pub fn new(leases: Vec<ShardLease<A>>) -> Self {
        let mut queue = VecDeque::new();
        queue.extend(leases);
        Self {
            state: Arc::new(Mutex::new(InMemoryCoordinatorState {
                queue,
                ..InMemoryCoordinatorState::default()
            })),
        }
    }

    /// Pre-mark a shard as done so the worker loop skips it.
    pub fn mark_done(&self, shard_id: impl Into<String>) {
        self.state
            .lock()
            .expect("state lock")
            .done
            .insert(shard_id.into());
    }

    /// Snapshot of the in-memory done set.
    #[must_use]
    pub fn done_set(&self) -> HashSet<String> {
        self.state.lock().expect("state lock").done.clone()
    }

    /// Snapshot of the write contexts used for `mark_shard_done`.
    #[must_use]
    pub fn done_mark_contexts(&self) -> Vec<WriteContext> {
        self.state
            .lock()
            .expect("state lock")
            .done_mark_contexts
            .clone()
    }

    /// Snapshot of shards released without completion.
    #[must_use]
    pub fn released_shards(&self) -> Vec<String> {
        self.state.lock().expect("state lock").released.clone()
    }

    /// Snapshot of completed shard records.
    #[must_use]
    pub fn completed_shards(&self) -> Vec<CompletedShard> {
        self.state.lock().expect("state lock").completed.clone()
    }

    /// Snapshot of recorded core events.
    #[must_use]
    pub fn core_events(&self) -> Vec<(String, OwnedCoreEvent)> {
        self.state.lock().expect("state lock").core_events.clone()
    }

    /// Snapshot of recorded git events.
    #[must_use]
    pub fn git_events(&self) -> Vec<(String, StoredGitEvent)> {
        self.state.lock().expect("state lock").git_events.clone()
    }

    /// Snapshot of recorded commit-progress events.
    #[must_use]
    pub fn commit_progress_events(&self) -> Vec<(String, CommitProgressRecord)> {
        self.state
            .lock()
            .expect("state lock")
            .commit_progress
            .clone()
    }

    /// Cause the next `count` calls to `acquire_shard` to return an error.
    pub fn fail_next_acquires(&self, count: usize) {
        self.state.lock().expect("state lock").acquire_fail_count = count;
    }

    /// Cause the next `count` calls to `release_shard` to return an error.
    pub fn fail_next_releases(&self, count: usize) {
        self.state.lock().expect("state lock").release_fail_count = count;
    }

    /// Cause the next `count` calls to `is_shard_done` to return an error.
    pub fn fail_next_is_done_checks(&self, count: usize) {
        self.state.lock().expect("state lock").is_done_fail_count = count;
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<A> DistributedCoordinator<A> for InMemoryCoordinator<A>
where
    A: ShardLeaseAssignment + Send + Sync + 'static,
{
    fn acquire_shard(&self) -> Result<Option<ShardLease<A>>> {
        let mut guard = self.state.lock().expect("state lock");
        if guard.acquire_fail_count > 0 {
            guard.acquire_fail_count -= 1;
            return Err(anyhow!("injected acquire_shard failure"));
        }
        Ok(guard.queue.pop_front())
    }

    fn release_shard(&self, lease: &ShardLease<A>) -> Result<()> {
        let mut guard = self.state.lock().expect("state lock");
        if guard.release_fail_count > 0 {
            guard.release_fail_count -= 1;
            return Err(anyhow!("injected release_shard failure"));
        }
        guard.released.push(lease.shard_id().to_owned());
        Ok(())
    }

    fn complete_shard(
        &self,
        lease: &ShardLease<A>,
        checkpoint: Option<Cursor>,
        report: ScanReport,
    ) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .completed
            .push(CompletedShard {
                shard_id: lease.shard_id().to_owned(),
                checkpoint,
                report,
            });
        Ok(())
    }

    fn is_shard_done(&self, lease: &ShardLease<A>) -> Result<bool> {
        let mut guard = self.state.lock().expect("state lock");
        if guard.is_done_fail_count > 0 {
            guard.is_done_fail_count -= 1;
            return Err(anyhow!("injected is_shard_done failure"));
        }
        Ok(guard.done.contains(lease.shard_id()))
    }

    fn mark_shard_done(&self, lease: &ShardLease<A>) -> Result<()> {
        let mut guard = self.state.lock().expect("state lock");
        guard.done.insert(lease.shard_id().to_owned());
        guard.done_mark_contexts.push(lease.write_context());
        Ok(())
    }

    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder> {
        Arc::new(Self {
            state: Arc::clone(&self.state),
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<A> CoordinationEventRecorder for InMemoryCoordinator<A>
where
    A: Send + Sync + 'static,
{
    fn record_core_event(&self, shard_id: &str, event: OwnedCoreEvent) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .core_events
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .git_events
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .commit_progress
            .push((shard_id.to_owned(), event));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use gossip_contracts::{
        connector::{Cursor, ItemKey},
        identity::{
            FenceEpoch, PolicyHash, RuleFingerprint, RunId, ShardId, StableItemId, TenantId,
            TenantSecretKey, derive_rule_fingerprint,
        },
        persistence::{DoneLedgerStatus, WriteContext},
    };
    use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
    use tempfile::tempdir;

    use crate::{
        CancellationToken, OwnedCoreEvent,
        commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput},
        commit_sink::{FindingRecord, FindingsBatch, ItemMeta},
        coordination_sink::{CommitProgressRecord, StoredGitEvent},
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StubAssignment {
        policy_hash: PolicyHash,
        filesystem_scan_config: Option<FsScanConfig>,
    }

    impl ShardLeaseAssignment for StubAssignment {
        fn policy_hash(&self) -> PolicyHash {
            self.policy_hash
        }

        fn filesystem_scan_config(&self) -> Option<FsScanConfig> {
            self.filesystem_scan_config.clone()
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

    fn filesystem_assignment(path: &std::path::Path) -> StubAssignment {
        StubAssignment {
            policy_hash: write_context().policy_hash(),
            filesystem_scan_config: Some(FsScanConfig::new(path)),
        }
    }

    /// Build a secret-shaped test fixture from non-secret fragments.
    ///
    /// The assembled string matches gitleaks' generic-api-key rule at scan
    /// time, but keeping the fragments separate avoids committing a literal
    /// that trips secret-detection CI on the source file itself.
    fn secret_fixture() -> String {
        ["password=", "xK9mP2qL7wN4vR8t"].concat()
    }

    fn filesystem_lease(shard_id: &str, path: &std::path::Path) -> ShardLease<StubAssignment> {
        ShardLease::new(
            Arc::from(shard_id),
            filesystem_assignment(path),
            write_context(),
            tenant_secret_key(),
        )
        .expect("filesystem lease")
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
            filesystem_scan_config: None,
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
            filesystem_scan_config: None,
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

        let msg = err.to_string();
        assert!(msg.contains("shard-x"), "error should name the shard");
        assert!(
            std::error::Error::source(&err).is_none(),
            "leaf error has no source"
        );
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
        assert_eq!(
            config.commit_queue_capacity,
            NonZeroUsize::new(64).expect("hardcoded non-zero constant"),
        );
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

        let mismatch = PolicyMismatchError {
            shard_id: Arc::from("shard-z"),
            assignment_hash: PolicyHash::from_bytes([0xAA; 32]),
            write_context_hash: PolicyHash::from_bytes([0xBB; 32]),
        };
        let from_mismatch = DistributedRuntimeError::from(mismatch);
        assert!(
            matches!(from_mismatch, DistributedRuntimeError::Coordinator(_)),
            "PolicyMismatchError should route to Coordinator variant"
        );
        assert!(std::error::Error::source(&from_mismatch).is_some());

        let msg = from_mismatch.to_string();
        assert!(
            msg.starts_with("coordinator error:"),
            "should use Coordinator display prefix"
        );
        assert!(
            msg.contains("shard-z"),
            "should propagate shard id through display chain"
        );
    }

    #[test]
    fn distributed_run_report_default_satisfies_invariant() {
        let report = DistributedRunReport::default();
        assert_eq!(report.leases_seen, 0);
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.shards_skipped_done, 0);
        assert!(report.shards_scanned + report.shards_skipped_done <= report.leases_seen);

        // Non-trivial case: demonstrates the invariant holds for realistic
        // field values and guards against field-ordering mistakes in future
        // construction sites.
        let nonzero = DistributedRunReport {
            leases_seen: 10,
            shards_scanned: 7,
            shards_skipped_done: 3,
        };
        assert!(nonzero.shards_scanned + nonzero.shards_skipped_done <= nonzero.leases_seen);
    }

    #[test]
    fn wait_for_submitted_commits_accepts_matching_sequences_out_of_order() {
        let submitted = vec![2, 0, 1];

        wait_for_submitted_commits(submitted, vec![1, 2, 0]).expect("matching sequences");
    }

    #[test]
    fn wait_for_submitted_commits_rejects_mismatched_sequences() {
        let submitted = vec![0, 1];
        let err = wait_for_submitted_commits(submitted, vec![0, 2])
            .expect_err("mismatched sequences should fail");

        assert!(
            err.to_string()
                .contains("did not match durable outcome sequence"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wait_for_submitted_commits_rejects_duplicate_submitted_sequences() {
        let submitted = vec![0, 1, 1];
        let err = wait_for_submitted_commits(submitted, vec![0, 1, 1])
            .expect_err("duplicate submitted sequences should fail");

        assert!(
            err.to_string()
                .contains("duplicate submitted sequence number"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wait_for_submitted_commits_rejects_duplicate_committed_sequences() {
        let submitted = vec![0, 1, 2];
        let err = wait_for_submitted_commits(submitted, vec![0, 2, 2])
            .expect_err("duplicate committed sequences should fail");

        assert!(
            err.to_string()
                .contains("duplicate committed sequence number"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn checkpoint_logical_time_overflows_at_u64_max() {
        assert!(checkpoint_logical_time(u64::MAX).is_err());
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
        assert_eq!(guard.get(&first).expect("first item").sequence_no, 0);
        assert_eq!(guard.get(&second).expect("second item").sequence_no, 1);
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
        assert_eq!(submitted[0], 0);

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
                assert_eq!(got_key, &item_key);
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
                assert_eq!(got_key, &item_key);
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
        let item = guard.get(&item_key).expect("item should remain in flight");
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

        // A failed duplicate begin must not consume a sequence number.
        let next_key = ItemKey::try_from_slice(b"tenant/repo/next.txt").expect("next key");
        sink.begin_item(&next_key, &meta)
            .expect("begin after failed duplicate");
        let guard = sink.in_flight.lock().expect("in flight lock");
        assert_eq!(
            guard.get(&next_key).expect("next item").sequence_no,
            1,
            "failed begin must not waste a sequence number"
        );
        drop(guard);

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

    #[test]
    fn upsert_findings_accumulates_across_multiple_batches() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/multi.txt");

        sink.begin_item(&key, &item_meta()).expect("begin item");
        sink.upsert_findings(
            &key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 7,
                    start: 10,
                    end: 20,
                    norm_hash: [0x55; 32],
                    confidence_score: 6,
                }],
            },
        )
        .expect("first upsert");
        sink.upsert_findings(
            &key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 8,
                    start: 30,
                    end: 40,
                    norm_hash: [0x66; 32],
                    confidence_score: 9,
                }],
            },
        )
        .expect("second upsert");

        let guard = sink.in_flight.lock().expect("in flight lock");
        let item = guard.get(&key).expect("item in flight");
        assert_eq!(item.findings.len(), 2, "both batches should accumulate");
        assert_eq!(item.findings[0].rule_id, 7);
        assert_eq!(item.findings[1].rule_id, 8);
        assert_eq!(item.findings[1].span_start, 30);
        assert_eq!(item.findings[1].span_end, 40);
        drop(guard);

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn finish_item_succeeds_with_zero_findings() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/clean.txt");

        sink.begin_item(&key, &item_meta()).expect("begin item");
        sink.finish_item(&key)
            .expect("finish item with zero findings");

        let submitted = sink.finish().expect("sink finish");
        assert_eq!(submitted.len(), 1);

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("commit outcome")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => {
                let receipt = checkpoint_input.into_receipt();
                assert_eq!(receipt.durable().findings().finding_count(), 0);
                assert_eq!(receipt.durable().done_ledger().record_count(), 1);
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}");
            }
        }

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn translate_handles_size_hint_none() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/nohint.txt");
        let meta = ItemMeta {
            stable_item_id: StableItemId::from_bytes([0x44; 32]),
            version: None,
            size_hint: None,
        };

        sink.begin_item(&key, &meta).expect("begin item");
        sink.finish_item(&key).expect("finish item");

        let submitted = sink.finish().expect("sink finish");
        assert_eq!(submitted.len(), 1);

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("commit outcome")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => {
                let receipt = checkpoint_input.into_receipt();
                assert_eq!(receipt.durable().done_ledger().record_count(), 1);
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}");
            }
        }

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn translate_uses_explicit_version_when_provided() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/versioned.txt");
        let meta = ItemMeta {
            stable_item_id: StableItemId::from_bytes([0x44; 32]),
            version: Some(VersionId::Strong(ObjectVersionId::from_version_bytes(
                b"explicit-v1",
            ))),
            size_hint: Some(256),
        };

        sink.begin_item(&key, &meta).expect("begin item");
        sink.finish_item(&key).expect("finish item");

        let submitted = sink.finish().expect("sink finish");
        assert_eq!(submitted.len(), 1);

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("commit outcome")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => {
                let receipt = checkpoint_input.into_receipt();
                assert_eq!(receipt.durable().done_ledger().record_count(), 1);
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}");
            }
        }

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn translate_in_flight_uses_item_key_surrogate_version_when_version_is_missing() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/version-compare.txt");
        let meta_without_version = ItemMeta {
            stable_item_id: StableItemId::from_bytes([0x44; 32]),
            version: None,
            size_hint: Some(256),
        };
        let meta_with_explicit_version = ItemMeta {
            stable_item_id: meta_without_version.stable_item_id,
            version: Some(VersionId::Strong(ObjectVersionId::from_version_bytes(
                b"explicit-v1",
            ))),
            size_hint: meta_without_version.size_hint,
        };
        let findings = vec![FsFindingRecord {
            rule_id: 7,
            root_hint_start: 10,
            root_hint_end: 20,
            span_start: 10,
            span_end: 20,
            norm_hash: [0x55; 32],
            confidence_score: 6,
        }];

        let (_, _, implicit_translation) = sink
            .translate_in_flight(
                &key,
                &InFlightItem {
                    sequence_no: 0,
                    meta: meta_without_version,
                    findings: findings.clone(),
                },
            )
            .expect("surrogate-version translation")
            .into_parts();
        let (_, _, explicit_translation) = sink
            .translate_in_flight(
                &key,
                &InFlightItem {
                    sequence_no: 0,
                    meta: meta_with_explicit_version,
                    findings,
                },
            )
            .expect("explicit-version translation")
            .into_parts();

        assert_eq!(
            implicit_translation.findings()[0].finding_id(),
            explicit_translation.findings()[0].finding_id(),
            "finding identity must stay version-independent",
        );
        assert_ne!(
            implicit_translation.occurrences()[0].occurrence_id(),
            explicit_translation.occurrences()[0].occurrence_id(),
            "missing-version translation must derive occurrence identity from the item-key surrogate version",
        );

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn upsert_findings_rejects_empty_span() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/bad-span.txt");

        sink.begin_item(&key, &item_meta()).expect("begin item");
        let err = sink
            .upsert_findings(
                &key,
                &FindingsBatch {
                    findings: vec![
                        finding(),
                        FindingRecord {
                            rule_id: 8,
                            start: 30,
                            end: 30,
                            norm_hash: [0x66; 32],
                            confidence_score: 9,
                        },
                    ],
                },
            )
            .expect_err("empty span must be rejected at upsert time");
        assert!(
            err.to_string()
                .contains("finding at index 1 has invalid span"),
            "unexpected error: {err}"
        );

        // The item is still in-flight — the batch was rejected before any
        // findings were appended, so finish_item can still be called.
        let guard = sink.in_flight.lock().expect("in flight lock");
        assert!(
            guard.contains_key(&key),
            "rejected batch must not remove the in-flight item"
        );
        drop(guard);

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn upsert_findings_rejects_inverted_span() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/inverted-span.txt");

        sink.begin_item(&key, &item_meta()).expect("begin item");
        let err = sink
            .upsert_findings(
                &key,
                &FindingsBatch {
                    findings: vec![FindingRecord {
                        rule_id: 9,
                        start: 40,
                        end: 30,
                        norm_hash: [0x77; 32],
                        confidence_score: 7,
                    }],
                },
            )
            .expect_err("inverted span must be rejected at upsert time");
        assert!(
            err.to_string()
                .contains("finding at index 0 has invalid span"),
            "unexpected error: {err}"
        );

        let guard = sink.in_flight.lock().expect("in flight lock");
        assert!(
            guard.contains_key(&key),
            "rejected batch must not remove the in-flight item"
        );
        drop(guard);

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn finish_item_preserves_in_flight_on_translation_failure() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/overflow.txt");

        // Force sequence counter to u64::MAX so the next begin_item assigns
        // a sequence_no whose logical_timing_for computation overflows.
        sink.next_sequence_no.store(u64::MAX, Ordering::Relaxed);
        sink.begin_item(&key, &item_meta()).expect("begin item");

        let err = sink
            .finish_item(&key)
            .expect_err("translate should fail on timing overflow");
        assert!(
            err.to_string().contains("sequence number overflow"),
            "unexpected error: {err}"
        );

        let guard = sink.in_flight.lock().expect("in flight lock");
        assert!(
            guard.contains_key(&key),
            "item must remain in in_flight after translation failure"
        );
        drop(guard);

        assert!(
            sink.submitted.lock().expect("submitted lock").is_empty(),
            "submitted must be empty after translation failure"
        );

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn finish_item_preserves_in_flight_on_submit_failure() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/disconnected.txt");

        sink.begin_item(&key, &item_meta()).expect("begin item");
        sink.upsert_findings(
            &key,
            &FindingsBatch {
                findings: vec![finding()],
            },
        )
        .expect("upsert findings");

        // Shut down the pipeline so the sender channel is disconnected.
        pipeline.shutdown().expect("pipeline shutdown");

        let err = sink
            .finish_item(&key)
            .expect_err("submit should fail after pipeline shutdown");
        assert!(
            err.to_string().contains("submission failed"),
            "unexpected error: {err}"
        );

        let guard = sink.in_flight.lock().expect("in flight lock");
        assert!(
            guard.contains_key(&key),
            "item must remain in in_flight after submit failure"
        );
        drop(guard);

        assert!(
            sink.submitted.lock().expect("submitted lock").is_empty(),
            "submitted must be empty after submit failure"
        );
    }

    #[test]
    fn upsert_after_finish_is_rejected() {
        let (pipeline, sink, _recorder) = make_receipt_sink();
        let key = item_key("tenant/repo/finished.txt");

        sink.begin_item(&key, &item_meta()).expect("begin item");
        sink.finish_item(&key).expect("finish item");

        let err = sink
            .upsert_findings(
                &key,
                &FindingsBatch {
                    findings: vec![finding()],
                },
            )
            .expect_err("upsert after finish should fail");

        assert!(
            err.to_string()
                .contains("upsert_findings called before begin_item"),
            "unexpected error: {err}"
        );

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn run_worker_skips_done_shards_before_scan() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let coordinator =
            InMemoryCoordinator::new(vec![filesystem_lease("shard-done", dir.path())]);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        coordinator.mark_done("shard-done");

        let report = run_worker(
            &coordinator,
            DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
            DistributedRuntimeConfig::default(),
        )
        .expect("run worker");

        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.shards_skipped_done, 1);
        assert_eq!(
            report.leases_seen,
            report.shards_scanned + report.shards_skipped_done
        );
        assert_eq!(coordinator.released_shards(), vec!["shard-done".to_owned()]);
        assert!(coordinator.completed_shards().is_empty());
        assert!(
            findings_sink
                .observations_snapshot()
                .expect("observations snapshot")
                .is_empty(),
            "skipped shard must not emit findings durability writes"
        );
        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty(),
            "skipped shard must not emit done-ledger writes"
        );
    }

    #[test]
    fn run_worker_persists_findings_done_ledger_checkpoint_and_marks_done() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let coordinator =
            InMemoryCoordinator::new(vec![filesystem_lease("shard-worker", dir.path())]);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();

        let report = run_worker(
            &coordinator,
            DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
            DistributedRuntimeConfig::default(),
        )
        .expect("run worker");

        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.shards_skipped_done, 0);
        assert_eq!(
            report.leases_seen,
            report.shards_scanned + report.shards_skipped_done
        );

        let completed = coordinator.completed_shards();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].shard_id, "shard-worker");
        assert!(
            completed[0].report.items_scanned >= 1,
            "scan report should record the scanned file"
        );
        let checkpoint = completed[0]
            .checkpoint
            .as_ref()
            .expect("non-empty shard should checkpoint");
        assert!(
            checkpoint.last_key().is_some(),
            "receipt-driven checkpoint should carry a progress key"
        );
        assert!(
            checkpoint.token().is_none(),
            "receipt-driven checkpoint should be tokenless"
        );

        assert!(coordinator.done_set().contains("shard-worker"));
        assert_eq!(coordinator.done_mark_contexts(), vec![write_context()]);

        let observations = findings_sink
            .observations_snapshot()
            .expect("observations snapshot");
        assert!(
            !observations.is_empty(),
            "durable findings observations should be present"
        );

        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            1,
            "one scanned file should produce one done row"
        );
        assert_eq!(rows[0].status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(rows[0].write_context(), write_context());
    }

    #[test]
    fn complete_shard_duplicate_call_produces_duplicate_entry() {
        let dir = tempdir().expect("tempdir");
        let lease = filesystem_lease("shard-dup", dir.path());
        let coordinator = InMemoryCoordinator::new(Vec::<ShardLease<StubAssignment>>::new());
        let report = ScanReport::default();

        coordinator
            .complete_shard(&lease, None, report)
            .expect("first complete_shard");
        coordinator
            .complete_shard(&lease, None, report)
            .expect("second complete_shard");

        let completed = coordinator.completed_shards();
        assert_eq!(completed.len(), 2);
        assert_eq!(completed[0].shard_id, "shard-dup");
        assert_eq!(completed[1].shard_id, "shard-dup");
        assert_eq!(completed[0].checkpoint, completed[1].checkpoint);
        assert_eq!(completed[0].report, completed[1].report);
    }

    #[test]
    fn run_worker_rejects_non_filesystem_assignment_without_receipts() {
        let coordinator = InMemoryCoordinator::new(vec![
            ShardLease::new(
                Arc::from("shard-non-fs"),
                StubAssignment {
                    policy_hash: write_context().policy_hash(),
                    filesystem_scan_config: None,
                },
                write_context(),
                tenant_secret_key(),
            )
            .expect("lease"),
        ]);

        let error = run_worker(
            &coordinator,
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("non-filesystem lease should be rejected");

        assert!(
            error
                .to_string()
                .contains("does not carry a filesystem scan config"),
            "unexpected error: {error}"
        );
        assert!(
            matches!(error, DistributedRuntimeError::Runtime(_)),
            "non-filesystem rejection should use Runtime variant, got: {error:?}"
        );
        assert_eq!(
            coordinator.released_shards(),
            vec!["shard-non-fs".to_owned()],
            "non-filesystem rejection must release the lease"
        );
        assert!(coordinator.completed_shards().is_empty());
        assert!(!coordinator.done_set().contains("shard-non-fs"));
    }

    #[test]
    fn run_worker_releases_lease_on_filesystem_scan_failure() {
        // Create then immediately drop a tempdir so the path is guaranteed
        // nonexistent and unique, avoiding CI flakiness from hardcoded paths.
        let dir = tempdir().expect("tempdir");
        let bogus_path = dir.path().to_owned();
        drop(dir);

        let coordinator =
            InMemoryCoordinator::new(vec![filesystem_lease("shard-fail", &bogus_path)]);

        let error = run_worker(
            &coordinator,
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("scan on non-existent path should fail");

        assert!(
            matches!(
                error,
                DistributedRuntimeError::Runtime(_) | DistributedRuntimeError::Durability(_)
            ),
            "filesystem scan failure should produce a Runtime or Durability error, got: {error:?}"
        );

        assert_eq!(
            coordinator.released_shards(),
            vec!["shard-fail".to_owned()],
            "filesystem scan failure must release the lease"
        );
        assert!(coordinator.completed_shards().is_empty());
        assert!(!coordinator.done_set().contains("shard-fail"));
    }

    #[test]
    fn run_filesystem_lease_persists_checkpoint_and_marks_done() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let coordinator = InMemoryCoordinator::<StubAssignment>::new(vec![]);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());
        let lease = filesystem_lease("shard-fs", dir.path());

        run_filesystem_lease(
            &coordinator,
            coordinator.event_recorder(),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("filesystem lease should succeed");

        let completed = coordinator.completed_shards();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].shard_id, "shard-fs");
        assert!(
            completed[0].report.items_scanned >= 1,
            "scan report should record the scanned file"
        );
        let checkpoint = completed[0]
            .checkpoint
            .as_ref()
            .expect("non-empty shard should checkpoint");
        assert!(
            checkpoint.last_key().is_some(),
            "receipt-driven checkpoint should carry a progress key"
        );
        assert!(
            checkpoint.token().is_none(),
            "receipt-driven checkpoint should be tokenless"
        );

        assert!(coordinator.done_set().contains("shard-fs"));
        assert_eq!(coordinator.done_mark_contexts(), vec![write_context()]);

        let observations = findings_sink
            .observations_snapshot()
            .expect("observations snapshot");
        assert!(
            !observations.is_empty(),
            "durable findings observations should be present"
        );

        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            1,
            "one scanned file should produce one done row"
        );
        assert_eq!(rows[0].status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(rows[0].write_context(), write_context());
    }

    #[test]
    fn run_filesystem_lease_zero_item_shard_completes_without_checkpoint() {
        let dir = tempdir().expect("tempdir");
        let coordinator = InMemoryCoordinator::<StubAssignment>::new(vec![]);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink, done_ledger.clone());
        let lease = filesystem_lease("shard-empty", dir.path());

        run_filesystem_lease(
            &coordinator,
            coordinator.event_recorder(),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("empty filesystem shard should succeed");

        let completed = coordinator.completed_shards();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].shard_id, "shard-empty");
        assert_eq!(
            completed[0].report.items_scanned, 0,
            "empty directory should scan zero items"
        );
        assert!(
            completed[0].checkpoint.is_none(),
            "zero-item shard must complete without a checkpoint"
        );
        assert!(coordinator.done_set().contains("shard-empty"));
        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty(),
            "zero-item shard should not emit done-ledger rows"
        );
    }

    #[test]
    fn run_filesystem_lease_commit_failure_prevents_completion_and_done_mark() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let coordinator = InMemoryCoordinator::<StubAssignment>::new(vec![]);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .fail_next_commits(1)
            .expect("inject done-ledger commit failure");
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());
        let lease = filesystem_lease("shard-fail", dir.path());

        let error = run_filesystem_lease(
            &coordinator,
            coordinator.event_recorder(),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect_err("commit failure should abort shard completion");

        assert!(
            error.to_string().contains("durable commit failed")
                || error.to_string().contains("done-ledger durability failed"),
            "unexpected error: {error}"
        );
        assert!(
            coordinator.completed_shards().is_empty(),
            "checkpoint must not be recorded without a durable receipt"
        );
        assert!(
            !coordinator.done_set().contains("shard-fail"),
            "shard must not be marked done after durability failure"
        );
        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty(),
            "done-ledger rows must remain absent after commit failure"
        );
        assert!(
            !findings_sink
                .observations_snapshot()
                .expect("observations snapshot")
                .is_empty(),
            "findings may still be durable before the done-ledger failure"
        );
    }

    #[test]
    fn run_filesystem_lease_rejects_assignment_without_filesystem_config() {
        let coordinator = InMemoryCoordinator::<StubAssignment>::new(vec![]);
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new());
        let lease = ShardLease::new(
            Arc::from("shard-missing-config"),
            StubAssignment {
                policy_hash: write_context().policy_hash(),
                filesystem_scan_config: None,
            },
            write_context(),
            tenant_secret_key(),
        )
        .expect("lease");

        let error = run_filesystem_lease(
            &coordinator,
            coordinator.event_recorder(),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect_err("missing filesystem config should be rejected");

        assert!(
            matches!(error, DistributedRuntimeError::Runtime(_)),
            "missing filesystem config is a runtime execution precondition error"
        );
        assert!(coordinator.completed_shards().is_empty());
        assert!(!coordinator.done_set().contains("shard-missing-config"));
    }

    #[test]
    fn run_filesystem_lease_succeeds_with_mixed_finding_and_clean_files() {
        let dir = tempdir().expect("tempdir");
        // File with a detectable secret — will produce findings and enter the
        // commit pipeline.
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write secret fixture");
        // Clean file — no findings, so the scanner's emit_persistence_batch
        // early-returns and this file never enters the commit pipeline.
        fs::write(dir.path().join("readme.txt"), "This file has no secrets.")
            .expect("write clean fixture");

        let coordinator = InMemoryCoordinator::<StubAssignment>::new(vec![]);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());
        let lease = filesystem_lease("shard-mixed", dir.path());

        run_filesystem_lease(
            &coordinator,
            coordinator.event_recorder(),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("mixed shard with clean files should succeed");

        let completed = coordinator.completed_shards();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].shard_id, "shard-mixed");

        let checkpoint = completed[0]
            .checkpoint
            .as_ref()
            .expect("non-empty shard should checkpoint");
        assert!(
            checkpoint.last_key().is_some(),
            "receipt-driven checkpoint should carry a progress key"
        );

        assert!(coordinator.done_set().contains("shard-mixed"));

        let observations = findings_sink
            .observations_snapshot()
            .expect("observations snapshot");
        assert!(
            !observations.is_empty(),
            "durable findings observations should be present for the secret file"
        );

        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            1,
            "only the file with findings should produce a done-ledger row"
        );
        assert_eq!(rows[0].status(), DoneLedgerStatus::ScannedWithFindings);
    }

    #[test]
    fn run_worker_returns_zero_report_on_empty_queue() {
        let coordinator = InMemoryCoordinator::<StubAssignment>::new(vec![]);
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new());

        let report = run_worker(
            &coordinator,
            persistence,
            DistributedRuntimeConfig::default(),
        )
        .expect("empty queue should succeed");

        assert_eq!(report.leases_seen, 0);
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.shards_skipped_done, 0);
        assert!(coordinator.released_shards().is_empty());
        assert!(coordinator.completed_shards().is_empty());
    }

    #[test]
    fn run_worker_processes_multiple_shards_from_queue() {
        let dir_a = tempdir().expect("tempdir a");
        let dir_b = tempdir().expect("tempdir b");
        fs::write(dir_a.path().join("secret.txt"), secret_fixture()).expect("write fixture a");
        fs::write(dir_b.path().join("secret.txt"), secret_fixture()).expect("write fixture b");

        let coordinator = InMemoryCoordinator::new(vec![
            filesystem_lease("shard-a", dir_a.path()),
            filesystem_lease("shard-b", dir_b.path()),
        ]);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();

        let report = run_worker(
            &coordinator,
            DistributedPersistence::new(findings_sink, done_ledger),
            DistributedRuntimeConfig::default(),
        )
        .expect("multi-shard run should succeed");

        assert_eq!(report.leases_seen, 2);
        assert_eq!(report.shards_scanned, 2);
        assert_eq!(report.shards_skipped_done, 0);

        let completed: Vec<String> = coordinator
            .completed_shards()
            .into_iter()
            .map(|c| c.shard_id)
            .collect();
        assert!(completed.contains(&"shard-a".to_owned()));
        assert!(completed.contains(&"shard-b".to_owned()));
    }

    #[test]
    fn run_worker_mixed_done_and_active_shards() {
        let dir_active = tempdir().expect("tempdir active");
        fs::write(dir_active.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let dir_done = tempdir().expect("tempdir done");
        fs::write(dir_done.path().join("secret.txt"), secret_fixture())
            .expect("write done fixture");

        let coordinator = InMemoryCoordinator::new(vec![
            filesystem_lease("shard-done", dir_done.path()),
            filesystem_lease("shard-active", dir_active.path()),
        ]);
        coordinator.mark_done("shard-done");

        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();

        let report = run_worker(
            &coordinator,
            DistributedPersistence::new(findings_sink, done_ledger),
            DistributedRuntimeConfig::default(),
        )
        .expect("mixed done/active run should succeed");

        assert_eq!(report.leases_seen, 2);
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.shards_skipped_done, 1);

        let completed: Vec<String> = coordinator
            .completed_shards()
            .into_iter()
            .map(|c| c.shard_id)
            .collect();
        assert_eq!(completed, vec!["shard-active".to_owned()]);
        assert_eq!(
            coordinator.released_shards(),
            vec!["shard-done".to_owned()],
            "only the done shard should be released without completion"
        );
    }

    #[test]
    fn run_worker_returns_coordinator_error_on_acquire_failure() {
        let dir = tempdir().expect("tempdir");
        let coordinator = InMemoryCoordinator::new(vec![filesystem_lease("shard-a", dir.path())]);
        coordinator.fail_next_acquires(1);

        let error = run_worker(
            &coordinator,
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("injected acquire failure should propagate");

        assert!(
            matches!(error, DistributedRuntimeError::Coordinator(_)),
            "acquire failure should produce Coordinator variant, got: {error:?}"
        );
        assert!(
            error.to_string().contains("injected acquire_shard failure"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn run_worker_returns_coordinator_error_on_is_done_failure() {
        let dir = tempdir().expect("tempdir");
        let coordinator = InMemoryCoordinator::new(vec![filesystem_lease("shard-a", dir.path())]);
        coordinator.fail_next_is_done_checks(1);

        let error = run_worker(
            &coordinator,
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("injected is_done failure should propagate");

        assert!(
            matches!(error, DistributedRuntimeError::Coordinator(_)),
            "is_done failure should produce Coordinator variant, got: {error:?}"
        );
        assert!(
            error.to_string().contains("injected is_shard_done failure"),
            "unexpected error: {error}"
        );
        // The is_done error handler does a best-effort release.
        assert_eq!(
            coordinator.released_shards(),
            vec!["shard-a".to_owned()],
            "is_done failure must attempt best-effort lease release"
        );
    }

    #[test]
    fn run_worker_preserves_original_error_when_release_fails_after_is_done_error() {
        let dir = tempdir().expect("tempdir");
        let coordinator = InMemoryCoordinator::new(vec![filesystem_lease("shard-a", dir.path())]);
        // Both is_done and release will fail; the original is_done error
        // should be returned, not the release error.
        coordinator.fail_next_is_done_checks(1);
        coordinator.fail_next_releases(1);

        let error = run_worker(
            &coordinator,
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("injected is_done failure should propagate");

        assert!(
            error.to_string().contains("injected is_shard_done failure"),
            "original is_done error should be preserved, got: {error}"
        );
        // Release failed too, so no shard appears in released list.
        assert!(
            coordinator.released_shards().is_empty(),
            "failed release should not record the shard"
        );
    }

    #[test]
    fn run_worker_continues_after_release_failure_on_done_shard() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let coordinator = InMemoryCoordinator::new(vec![
            filesystem_lease("shard-done", dir.path()),
            filesystem_lease("shard-active", dir.path()),
        ]);
        coordinator.mark_done("shard-done");
        // Release will fail for the done shard, but the loop should continue
        // to process the active shard (F-02 made done-shard release best-effort).
        coordinator.fail_next_releases(1);

        let report = run_worker(
            &coordinator,
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect("done-shard release failure should not abort the loop");

        assert_eq!(report.leases_seen, 2);
        assert_eq!(report.shards_skipped_done, 1);
        assert_eq!(report.shards_scanned, 1);
    }
}
