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
    /// Capacity of the bounded execution-to-commit queue. Matches the
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
///
/// # Threading model
///
/// Like [`DurableCommitSink`](crate::commit_sink::DurableCommitSink), this
/// sink is driven by a single-threaded drain loop. The interior `Mutex`
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
    /// the commit pipeline, not the recorder. This diverges from
    /// `DurableCommitSink` where recorder errors are propagated because the
    /// recorder IS the durability path.
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

    /// Records a finish-progress event for telemetry.
    ///
    /// This records that the item's scan completed and was submitted to the
    /// commit pipeline — not that the commit landed durably. Durability
    /// confirmation flows through the receipt/checkpoint path, not through
    /// telemetry. See [`record_begin`](Self::record_begin) for the non-fatal
    /// error rationale.
    fn record_finish(&self, item_key: &ItemKey) {
        let _ = self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Finish {
                write_context: self.write_context,
                item_key: item_key.as_bytes().to_vec(),
            },
        );
    }

    fn translate_in_flight(&self, item: &InFlightItem) -> Result<QueuedCommit> {
        let timing = Self::logical_timing_for(item.sequence_no)?;
        let bytes_scanned = item.meta.size_hint.unwrap_or(0);
        let version = item.meta.version.unwrap_or_else(|| {
            VersionId::Weak(ObjectVersionId::from_version_bytes(
                item.item_key.as_bytes(),
            ))
        });
        let checkpoint_cursor = Cursor::with_last_key(item.item_key.clone());
        let item_ref = ItemRef::try_from_slice(item.item_key.as_bytes())?;
        let mut scan_item = ScanItem::new(
            item.item_key.clone(),
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
}

impl CommitSink for ReceiptCommitSink {
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
        let key_bytes = item_key.as_bytes().to_vec();
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;

        use std::collections::btree_map::Entry;
        match guard.entry(key_bytes) {
            Entry::Occupied(_) => {
                return Err(anyhow::anyhow!(
                    "begin_item called twice without finish_item for the same item"
                ));
            }
            Entry::Vacant(slot) => {
                let sequence_no = self.next_sequence_no();
                slot.insert(InFlightItem {
                    sequence_no,
                    item_key: item_key.clone(),
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
            .get_mut(item_key.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("upsert_findings called before begin_item for item"))?;

        // The CommitSink surface provides only start/end offsets.
        // Root-hint fields are unavailable through this bridge, so both
        // root_hint_start/end mirror span_start/end. This is safe because
        // root-hint fields never participate in persistence identity
        // derivation (see result_translation.rs module docs).
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
        let key_bytes = item_key.as_bytes();

        // Remove the item under a short-lived lock. Translation and
        // submission happen outside the critical section so concurrent
        // begin_item / upsert_findings calls are not blocked by expensive
        // work (crypto derivations, channel send).
        let item = {
            let mut guard = self.in_flight.lock().map_err(|_| {
                anyhow::anyhow!("receipt commit sink in-flight state lock poisoned")
            })?;
            guard
                .remove(key_bytes)
                .ok_or_else(|| anyhow::anyhow!("finish_item called before begin_item for item"))?
        };

        let sequence_no = item.sequence_no;
        let work = match self.translate_in_flight(&item) {
            Ok(work) => work,
            Err(err) => {
                // Rollback: re-insert so the caller can retry. Recover
                // through a poisoned mutex rather than losing the item.
                self.in_flight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(key_bytes.to_vec(), item);
                return Err(err);
            }
        };

        if let Err(error) = self.submitter.submit(work) {
            // Rollback: re-insert so the caller can retry. Recover through
            // a poisoned mutex rather than silently losing the item.
            self.in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key_bytes.to_vec(), item);
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
            .push(SubmittedCommit { sequence_no });

        self.record_finish(item_key);
        Ok(())
    }
}

impl From<PolicyMismatchError> for DistributedRuntimeError {
    fn from(value: PolicyMismatchError) -> Self {
        Self::Coordinator(value.into())
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct CommitStageDrainResult {
    aggregator: PrefixCheckpointAggregator,
    processed: u64,
    committed_sequence_nos: Vec<u64>,
}

/// Drain commit-stage outcomes to completion while building the receipt-driven
/// checkpoint prefix.
///
/// Any durable commit failure, receipt aggregation violation, or worker panic
/// aborts the shard. The drainer cancels the worker before joining when the
/// first such failure is observed so scan execution does not keep queuing work
/// behind a broken durability path.
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
    let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0, max_buffered);
    let mut processed = 0_u64;
    let mut committed_sequence_nos = Vec::new();
    let mut drain_error = None;

    loop {
        match drainer.recv() {
            Ok(CommitStageOutput::Committed {
                checkpoint_input, ..
            }) => {
                if drain_error.is_none() {
                    let sequence_no = checkpoint_input.receipt().completed_unit().sequence_no();
                    match aggregator.record_receipt(checkpoint_input) {
                        Ok(_) => {
                            processed = processed.checked_add(1).ok_or_else(|| {
                                anyhow!("commit-stage processed counter overflow")
                            })?;
                            committed_sequence_nos.push(sequence_no);
                        }
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
        processed,
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
    mut submitted: Vec<SubmittedCommit>,
    mut committed_sequence_nos: Vec<u64>,
) -> Result<()> {
    submitted.sort_by_key(SubmittedCommit::sequence_no);
    committed_sequence_nos.sort_unstable();

    if submitted.len() != committed_sequence_nos.len() {
        return Err(anyhow!(
            "submitted {} commit(s) but commit stage produced {} durable outcome(s)",
            submitted.len(),
            committed_sequence_nos.len()
        ));
    }

    for (expected, actual) in submitted
        .into_iter()
        .map(|entry| entry.sequence_no())
        .zip(committed_sequence_nos.into_iter())
    {
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
#[cfg_attr(not(test), allow(dead_code))]
#[inline]
fn checkpoint_logical_time(last_sequence_no: u64) -> LogicalTime {
    LogicalTime::from_raw(last_sequence_no.saturating_add(1))
}

/// Execute one filesystem lease under the receipt-driven durability model.
///
/// The scan path runs with finding persistence enabled and a single execution
/// worker so `ReceiptCommitSink` sequence assignment remains deterministic.
/// The shard completes only after every submitted item has produced a durable
/// commit outcome and the resulting committed prefix has been checkpointed.
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
            DistributedRuntimeError::Coordinator(anyhow!(
                "shard '{}' lease assignment does not carry a filesystem scan config",
                lease.shard_id()
            ))
        })?
        .with_workers(1)
        .with_budgets(config.budgets)
        .with_persist_findings(true);

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

    let sink = CoordinationEventSink::new(recorder.clone(), Arc::from(lease.shard_id()));
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
        Arc::from(lease.shard_id()),
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
        let stage_result = join_scoped(stage_handle, "receipt checkpoint drain thread")?;

        Ok::<_, AnyError>((outcome, submitted, stage_result))
    })
    .map_err(DistributedRuntimeError::Durability)?;

    let outcome = outcome.map_err(DistributedRuntimeError::Runtime)?;
    let submitted = submitted.map_err(DistributedRuntimeError::Durability)?;
    let mut stage_result = stage_result.map_err(DistributedRuntimeError::Durability)?;

    let committed_sequence_nos = std::mem::take(&mut stage_result.committed_sequence_nos);
    wait_for_submitted_commits(submitted, committed_sequence_nos)
        .map_err(DistributedRuntimeError::Durability)?;

    let submitted_units = stage_result.processed;
    if submitted_units == 0 && outcome.report.items_scanned > 0 {
        return Err(DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' scanned {} item(s) but produced no durable commit receipts",
            lease.shard_id(),
            outcome.report.items_scanned
        )));
    }
    if submitted_units != outcome.report.items_scanned {
        return Err(DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' reported {} scanned item(s) but commit stage produced {} durable unit(s)",
            lease.shard_id(),
            outcome.report.items_scanned,
            submitted_units
        )));
    }

    let pending = stage_result
        .aggregator
        .prepare_checkpoint()
        .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

    if submitted_units == 0 {
        coordinator
            .complete_shard(lease, None, outcome.report)
            .map_err(DistributedRuntimeError::Coordinator)?;
        coordinator
            .mark_shard_done(lease)
            .map_err(DistributedRuntimeError::Coordinator)?;
        return Ok(());
    }

    let pending = pending.ok_or_else(|| {
        DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' committed {} unit(s) but no receipt-driven checkpoint prefix was prepared",
            lease.shard_id(),
            submitted_units
        ))
    })?;
    if pending.committed_units() != submitted_units {
        return Err(DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' prepared checkpoint for {} unit(s), expected {}",
            lease.shard_id(),
            pending.committed_units(),
            submitted_units
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
        checkpoint_logical_time(pending.last_sequence_no()),
    );
    stage_result
        .aggregator
        .acknowledge_checkpoint(checkpoint_receipt)
        .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

    coordinator
        .mark_shard_done(lease)
        .map_err(DistributedRuntimeError::Coordinator)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
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
        coordination_sink::{CommitProgressRecord, IdentityChainRecord, StoredGitEvent},
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
        identity: Mutex<Vec<IdentityChainRecord>>,
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
            record: crate::coordination_sink::IdentityChainRecord,
        ) -> Result<()> {
            self.identity.lock().expect("identity lock").push(record);
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct CompletedShard {
        shard_id: String,
        checkpoint: Option<Cursor>,
        report: ScanReport,
    }

    #[derive(Default)]
    struct TestCoordinatorState {
        completed: Vec<CompletedShard>,
        released: Vec<String>,
        done: HashSet<String>,
        done_mark_contexts: Vec<WriteContext>,
    }

    #[derive(Clone, Default)]
    struct TestCoordinator {
        recorder: Arc<Recorder>,
        state: Arc<Mutex<TestCoordinatorState>>,
    }

    impl TestCoordinator {
        fn completed_shards(&self) -> Vec<CompletedShard> {
            self.state.lock().expect("state lock").completed.clone()
        }

        fn done_set(&self) -> HashSet<String> {
            self.state.lock().expect("state lock").done.clone()
        }

        fn done_mark_contexts(&self) -> Vec<WriteContext> {
            self.state
                .lock()
                .expect("state lock")
                .done_mark_contexts
                .clone()
        }
    }

    impl DistributedCoordinator<StubAssignment> for TestCoordinator {
        fn acquire_shard(&self) -> Result<Option<ShardLease<StubAssignment>>> {
            Ok(None)
        }

        fn release_shard(&self, lease: &ShardLease<StubAssignment>) -> Result<()> {
            self.state
                .lock()
                .expect("state lock")
                .released
                .push(lease.shard_id().to_owned());
            Ok(())
        }

        fn complete_shard(
            &self,
            lease: &ShardLease<StubAssignment>,
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

        fn is_shard_done(&self, lease: &ShardLease<StubAssignment>) -> Result<bool> {
            Ok(self
                .state
                .lock()
                .expect("state lock")
                .done
                .contains(lease.shard_id()))
        }

        fn mark_shard_done(&self, lease: &ShardLease<StubAssignment>) -> Result<()> {
            let mut guard = self.state.lock().expect("state lock");
            guard.done.insert(lease.shard_id().to_owned());
            guard.done_mark_contexts.push(lease.write_context());
            Ok(())
        }

        fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder> {
            self.recorder.clone()
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
        let submitted = vec![
            SubmittedCommit { sequence_no: 2 },
            SubmittedCommit { sequence_no: 0 },
            SubmittedCommit { sequence_no: 1 },
        ];

        wait_for_submitted_commits(submitted, vec![1, 2, 0]).expect("matching sequences");
    }

    #[test]
    fn wait_for_submitted_commits_rejects_mismatched_sequences() {
        let submitted = vec![
            SubmittedCommit { sequence_no: 0 },
            SubmittedCommit { sequence_no: 1 },
        ];
        let err = wait_for_submitted_commits(submitted, vec![0, 2])
            .expect_err("mismatched sequences should fail");

        assert!(
            err.to_string()
                .contains("did not match durable outcome sequence"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn checkpoint_logical_time_saturates_at_u64_max() {
        assert_eq!(
            checkpoint_logical_time(u64::MAX),
            LogicalTime::from_raw(u64::MAX)
        );
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

        // A failed duplicate begin must not consume a sequence number.
        let next_key = ItemKey::try_from_slice(b"tenant/repo/next.txt").expect("next key");
        sink.begin_item(&next_key, &meta)
            .expect("begin after failed duplicate");
        let guard = sink.in_flight.lock().expect("in flight lock");
        assert_eq!(
            guard
                .get(next_key.as_bytes())
                .expect("next item")
                .sequence_no,
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
        let item = guard.get(key.as_bytes()).expect("item in flight");
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
            guard.contains_key(key.as_bytes()),
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
            guard.contains_key(key.as_bytes()),
            "item must remain in in_flight after submit failure"
        );
        drop(guard);

        assert!(
            sink.submitted.lock().expect("submitted lock").is_empty(),
            "submitted must be empty after submit failure"
        );
    }

    #[test]
    fn run_filesystem_lease_persists_checkpoint_and_marks_done() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), "password=xK9mP2qL7wN4vR8t")
            .expect("write fixture");

        let coordinator = TestCoordinator::default();
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
        let coordinator = TestCoordinator::default();
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
        fs::write(dir.path().join("secret.txt"), "password=xK9mP2qL7wN4vR8t")
            .expect("write fixture");

        let coordinator = TestCoordinator::default();
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
        let coordinator = TestCoordinator::default();
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
            matches!(error, DistributedRuntimeError::Coordinator(_)),
            "missing filesystem config is a lease/coordinator contract error"
        );
        assert!(coordinator.completed_shards().is_empty());
        assert!(!coordinator.done_set().contains("shard-missing-config"));
    }
}
