//! Distributed worker runtime for receipt-driven shard execution.
//!
//! This module is the entry point for distributed scanning. It implements a
//! claim-execute-advance loop: the worker claims shards from a
//! [`CoordinationFacade`], executes each shard's filesystem scan, commits
//! findings and done-ledger rows through a bounded commit pipeline, and then
//! advances the shard lease with either a non-terminal checkpoint cursor or a
//! terminal completion cursor derived from the committed prefix.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐    claim        ┌────────────────────┐
//! │ Coordinator  │ ─────────────>  │  run_worker loop   │
//! │ (CoordFacade)│ <───────────── │ (claim/scan/advance)│
//! └──────────────┘ checkpoint/complete └──────┬────────┘
//!                                        │
//!                              ┌─────────▼──────────┐
//!                              │ run_filesystem_lease│
//!                              │  (per shard)        │
//!                              └─────────┬──────────┘
//!                     ┌──────────────────┼──────────────────┐
//!                     ▼                  ▼                  ▼
//!          ┌────────────────┐  ┌──────────────────┐ ┌─────────────┐
//!          │ scan engine    │  │ ReceiptCommitSink │ │ commit      │
//!          │ (scheduler)    │──│ (CommitSink impl) │─│ pipeline    │
//!          └────────────────┘  └──────────────────┘ │ + drainer   │
//!                                                   └──────┬──────┘
//!                                                          ▼
//!                                                 ┌────────────────┐
//!                                                 │ Checkpoint     │
//!                                                 │ Aggregator     │
//!                                                 └────────────────┘
//! ```
//!
//! # Key types
//!
//! | Type                        | Role                                             |
//! |-----------------------------|--------------------------------------------------|
//! | [`WorkerIdentity`]          | Immutable identity threaded through all calls     |
//! | [`ShardLease`]              | Per-shard lease payload with scan config + fencing|
//! | [`DistributedPersistence`]  | Cloneable persistence backend handles             |
//! | [`DistributedRuntimeConfig`]| Budget and queue-sizing knobs                     |
//! | [`DistributedRunReport`]    | Summary counters from one worker invocation       |
//! | [`DistributedRuntimeError`] | Layered error: coordinator / runtime / durability |
//!
//! # Invariants
//!
//! 1. **Receipt-only checkpoint advancement.** Checkpoint progress is derived
//!    exclusively from durable commit receipts, never from raw scan completion.
//! 2. **Single-threaded scan execution.** Each shard runs with `workers = 1` so
//!    the `ReceiptCommitSink` sequence counter remains monotonic without
//!    cross-thread synchronization.
//! 3. **At-least-once delivery.** The commit pipeline tolerates duplicate writes
//!    for the same `(write_context, item_key)` pair. Persistence backends must
//!    be idempotent.
//! 4. **Fail-fast after claim.** Once a shard is claimed, any scan, commit,
//!    shard-advance, or explicit lease-uncertainty stop terminates the worker
//!    loop. Uncompleted leases expire via coordination-layer deadlines.
//!
//! # Internal adapter: `ReceiptCommitSink`
//!
//! The scan scheduler emits compact `CommitSink` callbacks (`begin_item`,
//! `upsert_findings`, `finish_item`). `ReceiptCommitSink` bridges these into
//! the richer [`CommitPipeline`] by reconstructing deterministic
//! [`crate::result_translation::translate_item_result`]
//! inputs and submitting owned [`QueuedCommit`] work items.
//!
//! [`CoordinationFacade`]: gossip_coordination::CoordinationFacade
//! [`CommitPipeline`]: crate::commit_pipeline::CommitPipeline

use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Error as AnyError, Result, anyhow};
use gossip_connectors::FilesystemConnector;
use gossip_contracts::{
    connector::{
        Budgets, Cursor, ItemKey, ItemRef, Location, PageState, ScanItem, VersionId,
        ordered::OrderedContentSource,
    },
    coordination::{CursorBoundsCheck, RestoredShardState, ShardSpec, check_cursor_bounds},
    identity::{
        CanonicalBytes, FenceEpoch, LogicalTime, ObjectVersionId, OpId, PolicyHash,
        RuleFingerprint, RunId, ShardKey, TenantId, TenantSecretKey, WorkerId, domain_hasher,
        finalize_64,
    },
    persistence::{CheckpointCommitReceipt, DoneLedger, FindingsSink, WriteContext},
};
use gossip_coordination::{
    AcquireResultView, AcquireScratch, CheckpointError, ClaimError, CompleteError,
    CoordinationFacade, CursorSemantics, Lease, OpKind,
};
use gossip_frontier::decode_connector_extra;
use gossip_orchestrator::{FilesystemPathKind, FilesystemShardPayload, FilesystemSourceMode};
use scanner_scheduler::store::FsFindingRecord;
use scanner_scheduler::{
    events::{CoreEvent, EventOutput, FindingEvent, SummaryEvent},
    source_kind::SourceKind,
};

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
    ordered_content::{
        OrderedContentExecutionOutcome, OrderedContentItemExecution, OrderedContentItemOutcome,
        OrderedContentReadStop, OrderedContentRuntime, OrderedContentRuntimeInput,
    },
    result_translation::{ItemResult, ScanTiming, translate_item_result},
};

/// Immutable worker identity threaded through shard claiming and completion.
///
/// Bundles all tenant-scoped, run-scoped, and worker-scoped state that
/// [`run_worker`] needs to claim shards and complete them against a
/// [`CoordinationFacade`]. Each field is constant for the lifetime of one
/// worker invocation; per-shard variability (scan path, fencing epoch) lives
/// on [`ShardLease`] instead.
#[derive(Clone)]
pub struct WorkerIdentity {
    /// Tenant boundary for all coordination calls.
    pub tenant: TenantId,
    /// Run whose shards this worker claims.
    pub run: RunId,
    /// Worker identity recorded on claimed leases.
    pub worker: WorkerId,
    /// Detection policy scope for all writes emitted by this worker.
    pub policy_hash: PolicyHash,
    /// Tenant-scoped secret used when deriving stable persistence identity.
    pub tenant_secret_key: TenantSecretKey,
    /// Base filesystem scan configuration cloned per shard and optionally
    /// overridden from shard metadata.
    pub scan_template: FsScanConfig,
    /// Shared recorder used by event and commit telemetry.
    pub recorder: Arc<dyn CoordinationEventRecorder>,
}

impl WorkerIdentity {
    /// Construct one distributed worker identity bundle.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        policy_hash: PolicyHash,
        tenant_secret_key: TenantSecretKey,
        scan_template: FsScanConfig,
        recorder: Arc<dyn CoordinationEventRecorder>,
    ) -> Self {
        Self {
            tenant,
            run,
            worker,
            policy_hash,
            tenant_secret_key,
            scan_template,
            recorder,
        }
    }
}

/// Hydrated filesystem scan config bundled with the explicit source mode decoded from shard metadata.
#[derive(Clone, Debug)]
struct HydratedFilesystemSource {
    scan_config: FsScanConfig,
    source_mode: FilesystemSourceMode,
}

impl HydratedFilesystemSource {
    fn new(scan_config: FsScanConfig, source_mode: FilesystemSourceMode) -> Self {
        Self {
            scan_config,
            source_mode,
        }
    }

    fn scan_config(&self) -> &FsScanConfig {
        &self.scan_config
    }

    fn source_mode(&self) -> FilesystemSourceMode {
        self.source_mode
    }
}

/// Lease payload consumed by the distributed runtime.
///
/// One lease corresponds to one shard from the coordination layer. It carries
/// everything needed to scan and commit that shard without additional lookups:
///
/// - **`shard_id`** — string label for telemetry routing.
/// - **`lease`** — authoritative coordination lease used for terminal completion.
/// - **`state`** — shard bounds, resume cursor, and cursor semantics restored
///   from the acquire/restore coordination payload.
/// - **`filesystem_source`** — filesystem scan configuration for this shard,
///   derived from the worker template and hydrated from typed shard payload
///   bytes, plus the explicit source mode that the control plane registered.
/// - **`write_context`** — numeric shard identity plus fencing epoch for all
///   persistence writes.
/// - **`tenant_secret_key`** — key material for secret-hash derivation.
///
/// # Lifecycle
///
/// 1. **Claim** — the coordination facade's acquire/restore call returns a
///    [`Lease`] and restored state.
/// 2. **Prepare** — `ShardLease::new` bundles the lease, restored state,
///    hydrated filesystem source, and write context together.
/// 3. **Execute** — the distributed worker loop scans the shard and commits
///    findings using the bundled write context.
/// 4. **Complete** — terminal completion uses the bundled [`Lease`] to emit
///    a receipt-driven checkpoint cursor.
///
/// The coordination lease and restored shard state stay together so later
/// runtime helpers can execute ordered-content work without a second acquire
/// payload or side-map.
#[derive(Clone, Debug)]
pub struct ShardLease {
    /// String shard label used for routing recorder events.
    shard_id: Arc<str>,
    /// Authoritative coordination-layer lease used for terminal completion.
    lease: Lease,
    /// Shard bounds, resume cursor, and cursor semantics restored from
    /// the acquire/restore coordination payload.
    state: RestoredShardState,
    /// Hydrated filesystem scan state for this shard.
    filesystem_source: HydratedFilesystemSource,
    /// Shared routing and fencing metadata for all writes emitted under the
    /// lease.
    write_context: WriteContext,
    /// Tenant secret key used for secret-hash derivation.
    tenant_secret_key: TenantSecretKey,
}

impl ShardLease {
    /// Construct one concrete filesystem shard lease.
    fn new(
        shard_id: Arc<str>,
        lease: Lease,
        state: RestoredShardState,
        filesystem_source: HydratedFilesystemSource,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
    ) -> Self {
        Self {
            shard_id,
            lease,
            state,
            filesystem_source,
            write_context,
            tenant_secret_key,
        }
    }

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

    /// Coordination-layer lease used for terminal completion.
    #[inline]
    pub fn lease(&self) -> Lease {
        self.lease
    }

    /// Restored coordination state for this shard.
    #[inline]
    #[must_use]
    pub fn restored_state(&self) -> &RestoredShardState {
        &self.state
    }

    /// Inclusive lower bound of the shard's key range.
    #[inline]
    #[must_use]
    pub fn range_start(&self) -> &[u8] {
        self.state.shard_spec().key_range_start()
    }

    /// Exclusive upper bound of the shard's key range.
    #[inline]
    #[must_use]
    pub fn range_end(&self) -> &[u8] {
        self.state.shard_spec().key_range_end()
    }

    /// Full authoritative shard specification restored from acquire/restore.
    #[inline]
    #[must_use]
    pub fn shard_spec(&self) -> &ShardSpec {
        self.state.shard_spec()
    }

    /// Authoritative resume cursor restored from acquire/restore.
    #[inline]
    #[must_use]
    pub fn resume_cursor(&self) -> &Cursor {
        self.state.resume_cursor()
    }

    /// Coordination cursor semantics for this shard.
    #[inline]
    #[must_use]
    pub fn cursor_semantics(&self) -> CursorSemantics {
        self.state.cursor_semantics()
    }

    /// Filesystem scan configuration for this shard.
    #[inline]
    #[must_use]
    pub fn scan_config(&self) -> &FsScanConfig {
        self.filesystem_source.scan_config()
    }

    /// Explicit filesystem source mode restored from shard metadata.
    #[inline]
    #[must_use]
    pub fn source_mode(&self) -> FilesystemSourceMode {
        self.filesystem_source.source_mode()
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

    /// Build an ordered-content runtime input from this lease's restored state.
    #[must_use]
    pub fn to_runtime_input(
        &self,
        budgets: Budgets,
    ) -> crate::ordered_content::OrderedContentRuntimeInput {
        crate::ordered_content::OrderedContentRuntimeInput::new(self.state.clone(), budgets)
    }
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

/// Runtime configuration for distributed scans.
///
/// Controls scan budgets (item count, byte count, time limits) and the
/// capacity of the bounded channels that connect scan execution to the
/// commit stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DistributedRuntimeConfig {
    /// Scan execution budget controls applied to every shard assignment.
    pub budgets: ScanBudgets,
    /// Capacity used for both the bounded execution-to-commit queue and the
    /// commit-to-checkpoint outcome queue. Defaults to 64.
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
/// Invariant: `shards_scanned <= leases_seen`.
/// The difference (`leases_seen - shards_scanned`) represents leases that were
/// claimed but not completed because the worker terminated on an error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DistributedRunReport {
    /// Total number of leases dequeued from the coordinator.
    pub leases_seen: u64,
    /// Number of shards that were scanned.
    pub shards_scanned: u64,
}

impl DistributedRunReport {
    /// Assert the structural invariant in debug builds.
    fn debug_assert_invariant(&self) {
        debug_assert!(
            self.shards_scanned <= self.leases_seen,
            "report invariant violated: scanned({}) > seen({})",
            self.shards_scanned,
            self.leases_seen,
        );
    }
}

/// Explicit reason the worker can no longer trust a claimed lease.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LeaseUncertainty {
    /// The local worker reached or passed the lease deadline before the shard
    /// finished its scan and commit pipeline.
    #[error(
        "lease deadline elapsed during shard execution (deadline {deadline:?}, observed {observed:?})"
    )]
    DeadlineElapsed {
        deadline: LogicalTime,
        observed: LogicalTime,
    },
    /// The coordinator rejected completion because another worker already owns
    /// a newer fence epoch.
    #[error(
        "shard completion rejected by a stale fence (presented {presented:?}, current {current:?})"
    )]
    CompletionStaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// The coordinator rejected completion because the lease already expired.
    #[error("shard completion rejected after lease expiry (deadline {deadline:?}, now {now:?})")]
    CompletionLeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
}

/// Shared lease-uncertainty signal written by the deadline watcher.
///
/// The signal can be sealed once the receipt drain finishes successfully so a
/// later wall-clock expiry does not retroactively invalidate a completed local
/// durability stage.
#[derive(Clone, Debug, Default)]
enum LeaseUncertaintyState {
    #[default]
    Open,
    Recorded(LeaseUncertainty),
    Closed,
}

/// Shared lease-uncertainty signal written by the deadline watcher and sealed
/// when the local durability stage has finished successfully.
#[derive(Clone, Debug, Default)]
struct LeaseUncertaintySignal {
    state: Arc<Mutex<LeaseUncertaintyState>>,
}

impl LeaseUncertaintySignal {
    fn note(&self, reason: LeaseUncertainty) -> bool {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match &*guard {
            LeaseUncertaintyState::Open => {
                *guard = LeaseUncertaintyState::Recorded(reason);
                true
            }
            LeaseUncertaintyState::Recorded(_) | LeaseUncertaintyState::Closed => false,
        }
    }

    fn close(&self) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*guard, LeaseUncertaintyState::Open) {
            *guard = LeaseUncertaintyState::Closed;
        }
    }

    fn current(&self) -> Option<LeaseUncertainty> {
        match &*self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            LeaseUncertaintyState::Recorded(reason) => Some(reason.clone()),
            LeaseUncertaintyState::Open | LeaseUncertaintyState::Closed => None,
        }
    }
}

/// Layered error from the distributed runtime.
///
/// Classifies failures by origin so callers can distinguish coordinator
/// connectivity issues from local scan crashes from durability pipeline
/// stalls. The variant determines whether the error is retryable (e.g.,
/// coordinator transient failures) or terminal (e.g., scan panics).
#[derive(Debug, thiserror::Error)]
pub enum DistributedRuntimeError {
    /// The coordinator returned an error.
    #[error("coordinator error: {0}")]
    Coordinator(#[source] AnyError),
    /// The worker intentionally stopped because the lease is no longer trusted.
    #[error("lease uncertainty: {0}")]
    LeaseUncertain(#[source] LeaseUncertainty),
    /// The scan runtime failed while executing an assignment.
    #[error("runtime error: {0}")]
    Runtime(#[source] ScanRuntimeError),
    /// The local durability pipeline failed.
    #[error("durability pipeline error: {0}")]
    Durability(#[source] AnyError),
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
/// state into a [`QueuedCommit`] and submits it to the pipeline.
///
/// Rollback on failure: if translation or pipeline submission fails,
/// `finish_item` re-inserts the item into the in-flight map so the caller
/// can retry or so that `ReceiptCommitSink::finish()` can detect the
/// leaked item.
#[derive(Debug)]
struct InFlightItem {
    sequence_no: u64,
    meta: ItemMeta,
    findings: Vec<FsFindingRecord>,
}

/// Compatibility adapter that bridges runtime item execution into the
/// receipt-driven commit pipeline.
///
/// Supports two submission surfaces:
///
/// - The legacy scan-loop `CommitSink` lifecycle (`begin_item` /
///   `upsert_findings` / `finish_item`), and
/// - direct ordered-content item outcomes submitted through
///   [`submit_ordered_item`](Self::submit_ordered_item).
///
/// Both surfaces converge on `QueuedCommit` work items containing full
/// persistence translations (findings, occurrences, observations, and
/// done-ledger rows) so the downstream commit pipeline retains one
/// receipt-driven durability path.
///
/// # Item lifecycle
///
/// ```text
/// begin_item(key, meta)          → inserts InFlightItem with sequence_no
///   upsert_findings(key, batch)  → appends FsFindingRecord to InFlightItem
///   upsert_findings(key, batch)  → (may be called multiple times)
/// finish_item(key)               → removes InFlightItem, translates,
///                                  submits QueuedCommit to pipeline
/// ```
///
/// # Threading model
///
/// This sink is driven by a single-threaded drain loop. The interior `Mutex`
/// fields satisfy the `Send + Sync` bound required by [`CommitSink`] without
/// introducing real contention. Sequence numbers assigned by
/// [`next_sequence_no`](Self::next_sequence_no) are therefore monotonically
/// ordered with respect to submission; `Ordering::Relaxed` is sufficient
/// because there is no concurrent caller to race against.
///
/// # Failure modes
///
/// - **Translation failure** (e.g., sequence-number overflow): the item is
///   rolled back into `in_flight` and `finish()` will detect it.
/// - **Submission failure** (e.g., pipeline disconnected): same rollback.
/// - **Recorder failure** (telemetry): logged once, then suppressed; non-fatal
///   because durability flows through the commit pipeline, not the recorder.
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

impl ReceiptCommitSink {
    /// Construct one adapter for a single shard's scan lifecycle.
    ///
    /// The `rule_fingerprint` closure maps engine rule IDs to stable
    /// persistence-layer fingerprints. It is called during `finish_item`
    /// translation and must be deterministic for the same rule ID.
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
    /// (either because the caller violated the begin/upsert/finish protocol
    /// or because an earlier translation/submission failure rolled the item
    /// back into the in-flight map) or if a mutex is poisoned.
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

    fn record_progress(&self, event: CommitProgressRecord) {
        if let Err(error) = self.recorder.record_commit_progress(&self.shard_id, event)
            && !self.progress_error_logged.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                shard_id = %self.shard_id,
                %error,
                "recorder failed to persist progress event; subsequent failures suppressed",
            );
        }
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
        self.record_progress(CommitProgressRecord::Begin {
            write_context: self.write_context,
            item_key: item_key.clone(),
            size_hint: meta.size_hint,
        });
    }

    /// Records a finish-progress event for telemetry.
    ///
    /// This records that the item's scan completed and was submitted to the
    /// commit pipeline — not that the commit landed durably. Durability
    /// confirmation flows through the receipt/checkpoint path, not through
    /// telemetry. See [`record_begin`](Self::record_begin) for the non-fatal
    /// error rationale.
    fn record_finish(&self, item_key: &ItemKey) {
        self.record_progress(CommitProgressRecord::Finish {
            write_context: self.write_context,
            item_key: item_key.clone(),
        });
    }

    fn submit_queued_commit(
        &self,
        item_key: &ItemKey,
        sequence_no: u64,
        work: QueuedCommit,
    ) -> Result<()> {
        self.submitter
            .submit(work)
            .map_err(|error| anyhow!("execution to commit submission failed: {error}"))?;

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

    fn ordered_item_meta(execution: &OrderedContentItemExecution) -> ItemMeta {
        let item = execution.item();
        ItemMeta {
            stable_item_id: item.stable_item_id(),
            version: Some(item.version()),
            size_hint: item.size_hint(),
        }
    }

    fn translate_ordered_item(
        &self,
        sequence_no: u64,
        execution: &OrderedContentItemExecution,
    ) -> Result<QueuedCommit> {
        let item = execution.item();
        let timing = Self::logical_timing_for(sequence_no)?;
        let checkpoint_cursor = Cursor::with_last_key(item.item_key().clone());
        let result = match execution.outcome() {
            OrderedContentItemOutcome::Scanned { findings } => ItemResult::Scanned { findings },
            OrderedContentItemOutcome::Truncated { .. } => ItemResult::FailedRetryable {
                error_code: OrderedContentReadStop::truncation_code(),
            },
            OrderedContentItemOutcome::Failed(stop) => {
                let error_code = OrderedContentReadStop::failure_code();
                if stop.class().is_retryable() {
                    ItemResult::FailedRetryable { error_code }
                } else {
                    ItemResult::FailedPermanent { error_code }
                }
            }
            OrderedContentItemOutcome::Skipped(reason) => ItemResult::Skipped {
                error_code: reason.done_ledger_code(),
            },
        };
        let translation = translate_item_result(
            self.write_context,
            &self.tenant_secret_key,
            item,
            execution.report().bytes_scanned,
            timing,
            result,
            &*self.rule_fingerprint,
        )?;

        Ok(QueuedCommit::new(
            self.write_context,
            CompletedUnit::ordered_content(sequence_no, checkpoint_cursor),
            translation,
        ))
    }

    fn submit_ordered_item(&self, execution: &OrderedContentItemExecution) -> Result<()> {
        let item_key = execution.item().item_key().clone();
        let meta = Self::ordered_item_meta(execution);
        // Sequence gap on translation failure is tolerated — the shard terminates
        // on error, so the gap never reaches wait_for_submitted_commits.
        let sequence_no = self.next_sequence_no();

        self.record_begin(&item_key, &meta);
        let work = match self.translate_ordered_item(sequence_no, execution) {
            Ok(work) => work,
            Err(error) => {
                self.record_finish(&item_key);
                return Err(error);
            }
        };
        self.submit_queued_commit(&item_key, sequence_no, work)
    }

    /// Reconstruct the deterministic translation inputs from an in-flight
    /// item's accumulated state and produce a [`QueuedCommit`] ready for the
    /// commit pipeline.
    ///
    /// This is the core bridge logic. It:
    /// 1. Derives a non-overlapping `[started, finished)` logical time pair
    ///    from the item's sequence number.
    /// 2. Falls back to a weak version derived from the item key bytes when
    ///    the connector did not supply an explicit version.
    /// 3. Attaches a display-only [`Location`] when the item key is valid
    ///    UTF-8 and `Location::try_new` accepts the resulting string
    ///    (best-effort; non-UTF-8 keys or keys rejected by `Location`
    ///    construction skip the location).
    /// 4. Delegates to [`translate_item_result`] for deterministic
    ///    persistence row derivation.
    ///
    /// [`translate_item_result`]: crate::result_translation::translate_item_result
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

        if let Err(error) = self.submit_queued_commit(&removed_key, sequence_no, work) {
            self.rollback_in_flight(removed_key, item);
            return Err(error);
        }

        Ok(())
    }
}

fn emit_ordered_item_findings(
    out: &dyn EventOutput,
    engine: &scanner_engine::Engine,
    execution: &OrderedContentItemExecution,
) {
    let OrderedContentItemOutcome::Scanned { findings } = execution.outcome() else {
        return;
    };

    for finding in findings {
        out.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: execution.item().item_key().as_bytes(),
            start: finding.root_hint_start,
            end: finding.root_hint_end,
            rule_id: finding.rule_id,
            rule_name: engine.rule_name(finding.rule_id),
            commit_id: None,
            change_kind: None,
            confidence_score: finding.confidence_score,
        }));
    }
}

fn emit_ordered_summary(out: &dyn EventOutput, report: ScanReport) {
    let elapsed_ms = report.scan_ns / 1_000_000;
    let throughput_mib_s = if report.scan_ns == 0 {
        0.0
    } else {
        (report.bytes_scanned as f64 / (1024.0 * 1024.0))
            / (report.scan_ns as f64 / 1_000_000_000.0)
    };
    out.emit_core(CoreEvent::Summary(SummaryEvent {
        source: SourceKind::Fs,
        status: if report.errors == 0 { "ok" } else { "error" },
        elapsed_ms,
        bytes_scanned: report.bytes_scanned,
        findings_emitted: report.findings_emitted,
        errors: report.errors,
        throughput_mib_s,
    }));
    out.flush();
}

/// Accumulated state from draining the commit-stage outcome stream.
///
/// Produced by [`drain_commit_stage`] and consumed by
/// [`run_filesystem_lease`] to build the checkpoint and verify that every
/// submitted commit produced a durable outcome.
#[derive(Debug)]
struct CommitStageDrainResult {
    /// Receipt aggregator that tracks the contiguous committed prefix.
    aggregator: PrefixCheckpointAggregator,
    /// Sequence numbers of committed items, in drain order (not necessarily
    /// sorted). Compared against the submitted list by
    /// [`wait_for_submitted_commits`].
    committed_sequence_nos: Vec<u64>,
}

/// Resolve the concurrent scan, submission, and drain results from one
/// filesystem lease.
///
/// Lease uncertainty takes absolute precedence: if the deadline watchdog fired,
/// the lease is no longer trusted regardless of whether the scan or durability
/// pipeline also produced errors. After that, scan failures are surfaced before
/// durability failures because a broken scan often cascades into downstream
/// drain errors. Returning the runtime error first gives operators the closest
/// cause.
fn resolve_filesystem_lease_results(
    outcome: Result<OrderedSourceAssignmentOutcome, ScanRuntimeError>,
    submitted: Result<Vec<u64>>,
    stage_result: anyhow::Result<anyhow::Result<CommitStageDrainResult>>,
    lease_uncertainty: Option<LeaseUncertainty>,
) -> Result<
    (
        OrderedSourceAssignmentOutcome,
        Vec<u64>,
        CommitStageDrainResult,
    ),
    DistributedRuntimeError,
> {
    if let Some(reason) = lease_uncertainty {
        return Err(DistributedRuntimeError::LeaseUncertain(reason));
    }
    let outcome = outcome.map_err(DistributedRuntimeError::Runtime)?;
    let submitted = submitted.map_err(DistributedRuntimeError::Durability)?;
    let stage_result = stage_result
        .map_err(DistributedRuntimeError::Durability)?
        .map_err(DistributedRuntimeError::Durability)?;
    Ok((outcome, submitted, stage_result))
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
/// sequence-number cross-check. Callers that cancel for lease uncertainty must
/// branch on that signal before treating submission or drain gaps as
/// durability failures.
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
#[inline]
fn checkpoint_logical_time(last_sequence_no: u64) -> Result<LogicalTime> {
    last_sequence_no
        .checked_add(1)
        .map(LogicalTime::from_raw)
        .ok_or_else(|| anyhow!("checkpoint logical time overflow: last_sequence_no is u64::MAX"))
}

/// Fallback delay when no lease deadline is available to guide retry timing.
///
/// Kept short (25 ms) to avoid stalling the worker loop when concurrent
/// workers are completing shards rapidly.
const CLAIM_RACE_RETRY_DELAY: Duration = Duration::from_millis(25);

/// Synthetic cursor key for completing unbounded shards that produced zero
/// items.
///
/// When a shard's `key_range_start` is empty (unbounded lower bound) and no
/// items were committed, we still need a valid `last_key` to satisfy the
/// coordination layer's completion validation. A single null byte is the
/// smallest non-empty byte sequence and passes all bounds checks when the
/// spec start is empty.
const EMPTY_RANGE_SENTINEL_KEY: &[u8] = b"\x00";

/// Explicit shard-advance outcome from the ordered-content path.
///
/// `Complete` means the scan observed the exhausted-empty suffix required for
/// terminal completion and may transition the shard to `Done` using the
/// authoritative receipt-backed checkpoint cursor. `Checkpoint` means the scan
/// stopped early after a checkpointable cursor was available, so the worker
/// must preserve progress without terminally completing the shard.
/// `ExhaustedEmpty` means the scan observed exhausted-empty before any durable
/// committed unit existed, so completion must use a range-safe fallback cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ShardCompletionOutcome {
    ExhaustedEmpty,
    Checkpoint { checkpoint: Cursor },
    Complete { checkpoint: Cursor },
}

/// Build hydrated filesystem source state by decoding shard metadata onto a
/// worker-owned scan template.
///
/// The shard's `connector_extra` bytes must contain a typed filesystem payload.
/// Hydration restores the canonical root path, validates it against the
/// payload's explicit source mode, and then overlays that path onto the worker
/// template.
///
/// # Trust boundary
///
/// The `connector_extra` metadata originates from a trusted coordination backend,
/// so no path-containment check is performed here. If the coordination backend
/// ever accepts untrusted shard metadata, apply
/// [`FilesystemRequest::normalize_within`] at submission time to verify the
/// canonical path falls within allowed roots before registration. Downstream,
/// the filesystem runtime still validates the hydrated path and the connector's
/// `openat`/`O_NOFOLLOW` enforcement prevents symlink traversal during reads.
/// Hydration uses `symlink_metadata` to reject symlinks before they reach the
/// connector layer.
///
/// [`FilesystemRequest::normalize_within`]: gossip_orchestrator::FilesystemRequest::normalize_within
fn hydrate_filesystem_source_from_spec(
    spec: gossip_coordination::ShardSpecRef<'_>,
    scan_template: &FsScanConfig,
) -> Result<HydratedFilesystemSource> {
    fn validate_payload_path_kind(payload: &FilesystemShardPayload) -> Result<()> {
        let metadata = fs::symlink_metadata(payload.canonical_root())
            .context("failed to inspect filesystem shard payload path")?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            anyhow::bail!("filesystem shard payload path is a symlink; expected a canonical path");
        }
        let actual_kind = FilesystemPathKind::from_file_type(&file_type).ok_or_else(|| {
            anyhow!("filesystem shard payload path must be a regular file or directory")
        })?;
        let expected_kind = payload.mode().expected_path_kind();
        if actual_kind != expected_kind {
            return Err(anyhow!(
                "filesystem shard payload mode '{}' requires a {}, but the path is a {}",
                payload.mode(),
                expected_kind,
                actual_kind
            ));
        }
        Ok(())
    }

    let mut scan_config = scan_template.clone();
    let connector_extra = decode_connector_extra(spec)
        .map_err(|err| anyhow!("failed to decode shard metadata envelope: {err}"))?;
    let payload = FilesystemShardPayload::decode(connector_extra)
        .map_err(|err| anyhow!("failed to decode filesystem shard payload: {err}"))?;
    validate_payload_path_kind(&payload)?;
    scan_config.path = payload.canonical_root().to_path_buf();

    Ok(HydratedFilesystemSource::new(scan_config, payload.mode()))
}

/// Convert an acquired coordination lease into the concrete runtime payload.
///
/// Constructs a [`WriteContext`] from the lease's fencing fields and the
/// worker's policy hash, restores an owned [`ShardSpec`] and resume
/// [`Cursor`] from the acquired snapshot, then decodes the shard spec's typed
/// filesystem payload to restore the scan path and source mode.
fn build_lease_from_acquire(
    acquired: AcquireResultView<'_>,
    identity: &WorkerIdentity,
) -> Result<ShardLease> {
    let snapshot = acquired.snapshot;
    let spec = snapshot.spec();
    let shard_spec = ShardSpec::try_from_ref(spec).with_context(|| {
        format!(
            "failed to restore shard spec for shard {}",
            acquired.lease.shard()
        )
    })?;
    let resume_cursor = Cursor::try_from_update(snapshot.cursor()).with_context(|| {
        format!(
            "failed to restore cursor for shard {}",
            acquired.lease.shard()
        )
    })?;
    let state = RestoredShardState::new(shard_spec, resume_cursor, snapshot.cursor_semantics());
    let write_context = WriteContext::new(
        acquired.lease.tenant(),
        identity.policy_hash,
        acquired.lease.run(),
        acquired.lease.shard(),
        acquired.lease.fence(),
    );

    Ok(ShardLease::new(
        Arc::from(acquired.lease.shard().to_string()),
        acquired.lease,
        state,
        hydrate_filesystem_source_from_spec(spec, &identity.scan_template)?,
        write_context,
        identity.tenant_secret_key,
    ))
}

/// Convert the wall clock to [`LogicalTime`] (milliseconds since Unix epoch).
///
/// Falls back to `1` if the system clock is before the epoch or if the
/// millisecond count overflows `u64`. The minimum of `1` avoids zero-valued
/// logical times, which some coordination backends treat as sentinel values.
fn wall_clock_now() -> LogicalTime {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1);
    LogicalTime::from_raw(millis.max(1))
}

/// Compute how long to sleep before retrying a shard claim.
///
/// When the coordinator provides an `earliest_deadline` (the soonest
/// existing lease expiry), the delay equals `deadline - now` (clamped to
/// at least 1 ms). Without a deadline, the fixed [`CLAIM_RACE_RETRY_DELAY`]
/// is used.
fn claim_retry_delay(now: LogicalTime, earliest_deadline: Option<LogicalTime>) -> Duration {
    earliest_deadline
        .map(|deadline| deadline.as_raw().saturating_sub(now.as_raw()).max(1))
        .map(Duration::from_millis)
        .unwrap_or(CLAIM_RACE_RETRY_DELAY)
}

/// Apply full jitter to a base delay to prevent thundering-herd
/// synchronization when multiple workers retry at the same time.
///
/// Returns a duration in `[1 ms, base]` using a BLAKE3 hash of the current
/// nanosecond timestamp as a lightweight, well-distributed source of
/// randomness. Delays of 1 ms or less are returned unchanged because jitter
/// below that threshold adds no desynchronization value.
fn jittered_delay(base: Duration) -> Duration {
    let base_ms = base.as_millis() as u64;
    if base_ms <= 1 {
        return base;
    }
    let mut hasher = domain_hasher("gossip.scanner_runtime.distributed.jitter");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos.write_canonical(&mut hasher);
    let hash = finalize_64(&hasher);
    Duration::from_millis((hash % base_ms).max(1))
}

/// Poll a lease deadline until shard execution finishes or the deadline elapses.
///
/// The watcher uses [`std::thread::park_timeout`] instead of
/// [`std::thread::sleep`] so the caller can wake it immediately via
/// [`std::thread::Thread::unpark`] when shard execution completes before the
/// deadline. The sleep interval is clamped to [`CLAIM_RACE_RETRY_DELAY`] so
/// expiry detection stays responsive without introducing a separate
/// busy-spin interval.
///
/// Deadline comparison uses a monotonic [`Instant`] to avoid false-positive
/// or false-negative detection from `CLOCK_REALTIME` jumps (NTP step
/// corrections, VM live migration, leap seconds). The wall-clock
/// [`LogicalTime`] deadline is retained only for the diagnostic fields in
/// [`LeaseUncertainty::DeadlineElapsed`].
fn watch_lease_deadline(
    deadline: LogicalTime,
    monotonic_deadline: Instant,
    cancel: CancellationToken,
    done: Arc<AtomicBool>,
    signal: LeaseUncertaintySignal,
) {
    loop {
        if done.load(Ordering::Acquire) {
            return;
        }

        if Instant::now() >= monotonic_deadline {
            if signal.note(LeaseUncertainty::DeadlineElapsed {
                deadline,
                observed: wall_clock_now(),
            }) {
                cancel.cancel();
            }
            return;
        }

        let remaining = monotonic_deadline
            .saturating_duration_since(Instant::now())
            .min(CLAIM_RACE_RETRY_DELAY);
        std::thread::park_timeout(remaining);
    }
}

/// Derive a deterministic [`OpId`] from shard identity, fence epoch, and kind.
///
/// Idempotent: the same `(key, fence, op_kind)` triple always produces the
/// same `OpId`. This allows the coordination backend to detect and deduplicate
/// replayed completion calls.
fn deterministic_op_id(key: ShardKey, fence: FenceEpoch, op_kind: OpKind) -> OpId {
    // Domain string is part of the identity contract: changing it breaks OpId
    // continuity for in-flight operations and causes deduplication mismatches.
    let mut hasher = domain_hasher("gossip.scanner_runtime.distributed.op_id");
    key.run().write_canonical(&mut hasher);
    key.shard().write_canonical(&mut hasher);
    fence.write_canonical(&mut hasher);
    op_kind.as_u8().write_canonical(&mut hasher);
    OpId::from_raw(finalize_64(&hasher))
}

/// Claim the next available shard, retrying while the run still has active
/// work or the coordinator is enforcing worker cooldown.
///
/// Returns `Ok(None)` when no shards are available **and** the run has zero
/// active leases (i.e., the run is fully settled). Returns `Ok(Some(lease))`
/// on successful claim. Retries internally on `NoneAvailable` (other
/// workers hold all shards) and `Throttled` (coordinator-imposed cooldown),
/// sleeping until the earliest deadline expires. Terminal errors like
/// `RunNotFound` or `BackendError` propagate immediately.
fn claim_next_lease<C>(
    coordinator: &mut C,
    identity: &WorkerIdentity,
    scratch: &mut AcquireScratch,
) -> Result<Option<ShardLease>, DistributedRuntimeError>
where
    C: CoordinationFacade,
{
    loop {
        let now = wall_clock_now();
        match coordinator.claim_next_available(
            now,
            identity.tenant,
            identity.run,
            identity.worker,
            scratch,
        ) {
            Ok(acquired) => {
                return build_lease_from_acquire(acquired, identity)
                    .map(Some)
                    .map_err(DistributedRuntimeError::Coordinator);
            }
            Err(ClaimError::NoneAvailable { earliest_deadline }) => {
                let progress = coordinator
                    .get_run_progress(now, identity.tenant, identity.run)
                    .map_err(|error| DistributedRuntimeError::Coordinator(AnyError::new(error)))?;
                if progress.active() == 0 {
                    return Ok(None);
                }
                std::thread::sleep(jittered_delay(claim_retry_delay(now, earliest_deadline)));
            }
            Err(ClaimError::Throttled { retry_after }) => {
                std::thread::sleep(jittered_delay(claim_retry_delay(now, Some(retry_after))));
            }
            Err(error) => {
                return Err(DistributedRuntimeError::Coordinator(AnyError::new(error)));
            }
        }
    }
}

/// Advance a claimed shard directly against the coordination backend.
///
/// `outcome` makes the coordination action explicit:
/// - [`ShardCompletionOutcome::Complete`] uses the receipt-driven
///   checkpoint cursor and transitions the shard to `Done`.
/// - [`ShardCompletionOutcome::Checkpoint`] uses the receipt-driven
///   checkpoint cursor but keeps the shard active for a later claim.
/// - [`ShardCompletionOutcome::ExhaustedEmpty`] uses a range-safe
///   exhausted-empty fallback cursor derived from the shard bounds.
///
/// The chosen cursor is validated with [`check_cursor_bounds`] before the
/// coordinator call so checkpoint and completion updates cannot silently
/// escape the shard's key range.
///
/// The operation uses a deterministic [`OpId`] so replayed calls are
/// idempotent. If the coordination backend reports the update was already
/// applied (idempotent replay), the function logs an info message but
/// succeeds. Coordinator-side lease loss (`StaleFence` / `LeaseExpired`)
/// surfaces as [`DistributedRuntimeError::LeaseUncertain`] for both
/// checkpoint and completion paths.
fn advance_shard<C>(
    coordinator: &mut C,
    identity: &WorkerIdentity,
    lease: &ShardLease,
    outcome: &ShardCompletionOutcome,
) -> Result<(), DistributedRuntimeError>
where
    C: CoordinationFacade,
{
    assert_eq!(lease.lease().tenant(), identity.tenant);

    let (cursor, op_kind, operation_name) = match outcome {
        ShardCompletionOutcome::Checkpoint { checkpoint } => {
            (checkpoint.as_update(), OpKind::Checkpoint, "checkpoint")
        }
        ShardCompletionOutcome::Complete { checkpoint } => {
            (checkpoint.as_update(), OpKind::Complete, "completion")
        }
        ShardCompletionOutcome::ExhaustedEmpty if lease.resume_cursor().last_key().is_some() => (
            lease.resume_cursor().as_update(),
            OpKind::Complete,
            "completion",
        ),
        ShardCompletionOutcome::ExhaustedEmpty if lease.range_start().is_empty() => (
            gossip_coordination::CursorUpdate::new(EMPTY_RANGE_SENTINEL_KEY),
            OpKind::Complete,
            "completion",
        ),
        ShardCompletionOutcome::ExhaustedEmpty => (
            gossip_coordination::CursorUpdate::new(lease.range_start()),
            OpKind::Complete,
            "completion",
        ),
    };
    match check_cursor_bounds(cursor, lease.restored_state().shard_spec().as_ref()) {
        CursorBoundsCheck::InBounds => {}
        CursorBoundsCheck::NoKey => {
            return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                anyhow!(
                    "shard '{}' {} cursor is missing last_key for {:?}",
                    lease.shard_id(),
                    operation_name,
                    lease.restored_state().shard_spec(),
                ),
            )));
        }
        bounds => {
            return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                anyhow!(
                    "shard '{}' {} cursor {:?} is not in bounds for {:?}: {:?}",
                    lease.shard_id(),
                    operation_name,
                    cursor.last_key(),
                    lease.restored_state().shard_spec(),
                    bounds,
                ),
            )));
        }
    }

    let op_id = deterministic_op_id(lease.lease().shard_key(), lease.lease().fence(), op_kind);
    let applied = match outcome {
        ShardCompletionOutcome::Checkpoint { .. } => coordinator
            .checkpoint(
                wall_clock_now(),
                identity.tenant,
                &lease.lease(),
                &cursor,
                op_id,
            )
            .map_err(|error| match error {
                CheckpointError::StaleFence { presented, current } => {
                    DistributedRuntimeError::LeaseUncertain(
                        LeaseUncertainty::CompletionStaleFence { presented, current },
                    )
                }
                CheckpointError::LeaseExpired { deadline, now } => {
                    DistributedRuntimeError::LeaseUncertain(
                        LeaseUncertainty::CompletionLeaseExpired { deadline, now },
                    )
                }
                other => DistributedRuntimeError::Coordinator(AnyError::new(other)),
            })?,
        ShardCompletionOutcome::Complete { .. } | ShardCompletionOutcome::ExhaustedEmpty => {
            coordinator
                .complete(
                    wall_clock_now(),
                    identity.tenant,
                    &lease.lease(),
                    &cursor,
                    op_id,
                )
                .map_err(|error| match error {
                    CompleteError::StaleFence { presented, current } => {
                        DistributedRuntimeError::LeaseUncertain(
                            LeaseUncertainty::CompletionStaleFence { presented, current },
                        )
                    }
                    CompleteError::LeaseExpired { deadline, now } => {
                        DistributedRuntimeError::LeaseUncertain(
                            LeaseUncertainty::CompletionLeaseExpired { deadline, now },
                        )
                    }
                    other => DistributedRuntimeError::Coordinator(AnyError::new(other)),
                })?
        }
    };

    if !applied.is_executed() {
        tracing::info!(
            shard_id = %lease.shard_id(),
            operation = operation_name,
            "{operation_name} was an idempotent replay",
        );
    }

    Ok(())
}

/// Phase of the ordered-content page loop.
///
/// After processing a terminal non-empty page (`PageState::Complete`),
/// the loop transitions to `AwaitingExhaustedEmpty` and expects one
/// more `ExhaustedEmpty` outcome before the shard is fully enumerated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PageLoopPhase {
    Paging,
    AwaitingExhaustedEmpty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PageLoopTermination {
    ExhaustedEmptyConfirmed,
    Partial,
}

#[derive(Clone, Debug)]
struct OrderedSourceAssignmentOutcome {
    report: ScanReport,
    termination: PageLoopTermination,
}

fn scan_ordered_filesystem_lease_with_engine<D>(
    lease: &ShardLease,
    config: &FsScanConfig,
    done_ledger: &D,
    engine: Arc<scanner_engine::Engine>,
    out: &dyn EventOutput,
    commit: &ReceiptCommitSink,
    cancel: &CancellationToken,
) -> Result<OrderedSourceAssignmentOutcome, ScanRuntimeError>
where
    D: DoneLedger,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let mut source = FilesystemConnector::new(config.path.clone());
    scan_ordered_source_with_engine(
        &mut source,
        lease,
        config,
        done_ledger,
        engine,
        out,
        commit,
        cancel,
    )
}

/// Source-generic ordered-content page loop.
///
/// Identical to [`scan_ordered_filesystem_lease_with_engine`] but accepts any
/// [`OrderedContentSource`], enabling injection of scripted test doubles for
/// suffix-protocol verification.
#[allow(clippy::too_many_arguments)]
fn scan_ordered_source_with_engine<S, D>(
    source: &mut S,
    lease: &ShardLease,
    config: &FsScanConfig,
    done_ledger: &D,
    engine: Arc<scanner_engine::Engine>,
    out: &dyn EventOutput,
    commit: &ReceiptCommitSink,
    cancel: &CancellationToken,
) -> Result<OrderedSourceAssignmentOutcome, ScanRuntimeError>
where
    S: OrderedContentSource,
    D: DoneLedger,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let budgets = Budgets::try_new(config.budgets.max_items, config.budgets.max_bytes, None)?;
    let shard_spec = lease.restored_state().shard_spec().clone();
    let cursor_semantics = lease.restored_state().cursor_semantics();
    let mut restored_state = lease.restored_state().clone();
    let mut report = ScanReport::default();
    let mut phase = PageLoopPhase::Paging;
    let mut executed_any_page = false;
    let mut termination = PageLoopTermination::Partial;

    loop {
        if cancel.is_cancelled() {
            if phase == PageLoopPhase::AwaitingExhaustedEmpty {
                tracing::debug!(
                    shard_id = %lease.shard_id(),
                    "cancellation during exhausted-empty suffix wait; \
                     partial progress preserved for re-claim",
                );
            }
            break;
        }

        let runtime_input = OrderedContentRuntimeInput::new(restored_state.clone(), budgets);
        let (page, terminal) = match OrderedContentRuntime::execute_source(source, &runtime_input)?
        {
            OrderedContentExecutionOutcome::ExhaustedEmpty => {
                termination = PageLoopTermination::ExhaustedEmptyConfirmed;
                break;
            }
            OrderedContentExecutionOutcome::Stopped(stop) => {
                if phase == PageLoopPhase::AwaitingExhaustedEmpty {
                    if stop.class().is_retryable() {
                        tracing::warn!(
                            message = stop.message(),
                            retry_after_ms = stop.retry_after_ms(),
                            "retryable enumerate stop while waiting for exhausted-empty suffix, preserving receipt-backed progress",
                        );
                        break;
                    }
                    return Err(ScanRuntimeError::Driver(anyhow!(
                        "ordered-content source stopped before confirming \
                         exhausted-empty suffix after a terminal non-empty \
                         page: {stop}"
                    )));
                }
                if stop.class().is_retryable() {
                    if !executed_any_page {
                        // No progress was made — propagate the error so the
                        // shard is not permanently completed as exhausted-empty.
                        // The shard stays active and can be re-claimed.
                        return Err(ScanRuntimeError::Driver(anyhow!(
                            "retryable enumerate failure with no prior progress: {stop}"
                        )));
                    }
                    // Retryable enumerate failure — preserve partial progress
                    // by breaking instead of returning an error. The shard is
                    // completed with a checkpoint at the last committed item,
                    // and the next claim resumes from there.
                    tracing::warn!(
                        message = stop.message(),
                        retry_after_ms = stop.retry_after_ms(),
                        "retryable enumerate stop, preserving partial progress",
                    );
                    break;
                }
                return Err(ScanRuntimeError::Driver(anyhow!("{stop}")));
            }
            OrderedContentExecutionOutcome::Page(page) => {
                if phase == PageLoopPhase::AwaitingExhaustedEmpty {
                    return Err(ScanRuntimeError::Driver(anyhow!(
                        "ordered-content source emitted a non-empty page \
                         after a terminal non-empty page"
                    )));
                }
                let terminal = matches!(page.page().state(), PageState::Complete);
                (page, terminal)
            }
        };

        let page = page.prefilter_done_ledger(lease.write_context(), done_ledger)?;
        let execution = OrderedContentRuntime::execute_scan_misses_with_prebuilt_engine(
            source,
            page,
            config.budgets,
            config.scan_binary,
            Arc::clone(&engine),
        )?;
        executed_any_page = true;

        // Determine the earliest deferred key so we can stop submitting
        // before the checkpoint advances past a budget-deferred item.
        let min_deferred_key = execution
            .deferred()
            .iter()
            .map(|item| item.item_key())
            .min();

        let mut hit_non_terminal = false;
        let mut submitted_report = ScanReport::default();
        let mut items_submitted: u64 = 0;
        for item in execution.outcomes() {
            if cancel.is_cancelled() {
                hit_non_terminal = true;
                break;
            }
            // A deferred item with a key before this outcome means the
            // checkpoint would skip past the deferred item if we commit
            // this outcome. Stop here so the checkpoint stays before the
            // deferred item's key position.
            if let Some(dk) = min_deferred_key
                && dk < item.item().item_key()
            {
                hit_non_terminal = true;
                break;
            }
            // Retryable outcomes (truncated / transient-failure) must not
            // advance the checkpoint — they need to be re-scanned.
            if item.outcome().is_retryable() {
                hit_non_terminal = true;
                break;
            }
            commit
                .submit_ordered_item(item)
                .map_err(ScanRuntimeError::Driver)?;
            emit_ordered_item_findings(out, &engine, item);
            submitted_report += item.report();
            items_submitted += 1;
        }

        // Build the page report from only submitted items so that
        // findings_emitted and other counters reflect what was actually
        // sent to the event stream. Items past the non-terminal break
        // point will be re-scanned on the next claim.
        submitted_report.items_scanned = execution.already_done_len() as u64 + items_submitted;
        submitted_report.items_deferred = execution.deferred().len() as u64;
        report += submitted_report;

        // Non-terminal or deferred items take priority over terminal-page
        // status: if a page was terminal (`PageState::Complete`) but also
        // contained a deferred item, the checkpoint must stop before that
        // item's key. The next claim resumes from the checkpoint and
        // re-discovers the terminal boundary at that time.
        //
        // When neither condition holds, the checkpoint covers all page
        // items committed before the non-terminal boundary. Deferred items
        // may land on a separate page from subsequent outcomes (the page
        // byte budget can split them), so check `deferred()` even when
        // the outcomes loop ran to completion.
        if hit_non_terminal || !execution.deferred().is_empty() {
            break;
        }

        restored_state = RestoredShardState::new(
            shard_spec.clone(),
            execution.resume_cursor().clone(),
            cursor_semantics,
        );
        if terminal {
            phase = PageLoopPhase::AwaitingExhaustedEmpty;
            continue;
        }
    }

    if executed_any_page {
        emit_ordered_summary(out, report);
    }

    Ok(OrderedSourceAssignmentOutcome {
        report,
        termination,
    })
}

/// Execute one filesystem lease under the receipt-driven durability model.
///
/// This is the per-shard work function called by [`run_worker`]. It
/// orchestrates the full scan-commit-checkpoint pipeline for one shard:
///
/// 1. **Setup**: validates budgets, builds the scan engine, creates the
///    commit pipeline and `ReceiptCommitSink`.
/// 2. **Concurrent execution**: spawns a scoped thread to drain the commit
///    pipeline's outcome stream while the main thread executes bounded
///    ordered-content pages through the filesystem connector runtime until
///    the shard is exhausted.
/// 3. **Post-scan verification**: checks that every submitted sequence
///    number produced exactly one durable outcome (via
///    [`wait_for_submitted_commits`]).
/// 4. **Checkpoint**: prepares and acknowledges the receipt-driven
///    checkpoint prefix through [`PrefixCheckpointAggregator`].
///
/// Returns `(ScanReport, ExhaustedEmpty)` only after the scan explicitly
/// observes exhausted-empty before any durable committed unit exists.
/// Returns `(ScanReport, Complete { checkpoint })` when the shard observes
/// exhausted-empty after durably committing at least one unit. Returns
/// `(ScanReport, Checkpoint { checkpoint })` when the scan stops early after
/// durably committing at least one new unit, preserving progress without
/// marking the shard `Done`.
///
/// If the scan stops early before any new receipt-backed progress exists, the
/// function returns an error instead of fabricating exhausted-empty
/// completion or checkpointing the same cursor again.
///
/// The caller owns the coordination-layer advance step (calling
/// [`advance_shard`] with the returned explicit outcome).
///
/// # Design choice: single worker
///
/// The scan runs with `workers = 1` so that `ReceiptCommitSink` sequence
/// assignment remains monotonic without cross-thread synchronization. The
/// commit pipeline provides the parallelism boundary: scan execution and
/// durable commit proceed concurrently on separate threads.
fn run_filesystem_lease<F, D>(
    recorder: Arc<dyn CoordinationEventRecorder>,
    persistence: &DistributedPersistence<F, D>,
    lease: &ShardLease,
    config: DistributedRuntimeConfig,
) -> Result<(ScanReport, ShardCompletionOutcome), DistributedRuntimeError>
where
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    config.budgets.validate()?;

    let scan_config = lease
        .scan_config()
        .clone()
        .with_workers(1)
        .with_budgets(config.budgets)
        .with_persist_findings(true);

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
    let lease_deadline = lease.lease().deadline();
    let start_time = wall_clock_now();
    if start_time.as_raw() >= lease_deadline.as_raw() {
        return Err(DistributedRuntimeError::LeaseUncertain(
            LeaseUncertainty::DeadlineElapsed {
                deadline: lease_deadline,
                observed: start_time,
            },
        ));
    }
    let lease_uncertainty = LeaseUncertaintySignal::default();
    let lease_watch_done = Arc::new(AtomicBool::new(false));
    let monotonic_deadline = Instant::now()
        + Duration::from_millis(lease_deadline.as_raw().saturating_sub(start_time.as_raw()));
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

    // Scan execution and commit draining run concurrently in a scoped thread.
    // The drain thread consumes commit outcomes and feeds the checkpoint
    // aggregator. When the scan completes, `commit.finish()` consumes the
    // sink (verifying no items remain in-flight) and the drain thread exits
    // once the submission channel closes.
    let (outcome, submitted, stage_result, watch_result) = std::thread::scope(|scope| {
        let write_context = lease.write_context();
        let max_buffered = config.commit_queue_capacity.get();
        let stage_handle = scope.spawn({
            let done = Arc::clone(&lease_watch_done);
            let signal = lease_uncertainty.clone();
            move || {
                let result = drain_commit_stage(drainer, write_context, max_buffered);
                if result.is_ok() {
                    signal.close();
                }
                done.store(true, Ordering::Release);
                result
            }
        });
        let deadline_handle = scope.spawn({
            let cancel = cancel.clone();
            let done = Arc::clone(&lease_watch_done);
            let signal = lease_uncertainty.clone();
            move || watch_lease_deadline(lease_deadline, monotonic_deadline, cancel, done, signal)
        });

        let outcome = scan_ordered_filesystem_lease_with_engine(
            lease,
            &scan_config,
            &persistence.done_ledger,
            engine,
            &sink,
            &commit,
            &cancel,
        );
        let submitted = commit.finish();
        let stage_result = join_scoped(stage_handle, "receipt checkpoint drain thread");
        lease_watch_done.store(true, Ordering::Release);
        deadline_handle.thread().unpark();
        let watch_result = join_scoped(deadline_handle, "lease deadline watchdog");

        (outcome, submitted, stage_result, watch_result)
    });
    watch_result
        .map_err(|error| DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(error)))?;

    let (outcome, submitted, stage_result) = resolve_filesystem_lease_results(
        outcome,
        submitted,
        stage_result,
        lease_uncertainty.current(),
    )?;
    let CommitStageDrainResult {
        mut aggregator,
        committed_sequence_nos,
    } = stage_result;
    let committed_units = committed_sequence_nos.len() as u64;
    let checkpoint_cursor = if committed_units == 0 {
        None
    } else {
        wait_for_submitted_commits(submitted, committed_sequence_nos)
            .map_err(DistributedRuntimeError::Durability)?;

        let (checkpoint_scope, checkpoint_time, checkpoint_cursor) = {
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

            (
                pending.scope().clone(),
                checkpoint_logical_time(pending.last_sequence_no())
                    .map_err(DistributedRuntimeError::Durability)?,
                pending.checkpoint_cursor().clone(),
            )
        };
        let checkpoint_receipt = CheckpointCommitReceipt::new(checkpoint_scope, checkpoint_time);
        aggregator
            .acknowledge_checkpoint(checkpoint_receipt)
            .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

        Some(checkpoint_cursor)
    };

    let completion = match (outcome.termination, checkpoint_cursor) {
        (PageLoopTermination::ExhaustedEmptyConfirmed, None) => {
            ShardCompletionOutcome::ExhaustedEmpty
        }
        (PageLoopTermination::ExhaustedEmptyConfirmed, Some(checkpoint)) => {
            ShardCompletionOutcome::Complete { checkpoint }
        }
        (PageLoopTermination::Partial, Some(checkpoint)) => {
            ShardCompletionOutcome::Checkpoint { checkpoint }
        }
        (PageLoopTermination::Partial, None) => {
            return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                anyhow!(
                    "filesystem shard '{}' stopped before confirming exhaustion and produced no receipt-backed progress",
                    lease.shard_id()
                ),
            )));
        }
    };

    Ok((outcome.report, completion))
}

/// Run the distributed worker loop until the coordinator has no more leases.
///
/// This is the top-level entry point for distributed scanning. The loop:
///
/// 1. **Claims** the next available shard from the coordinator, retrying
///    while the run still has active work but every candidate shard is
///    currently leased or the worker is being throttled.
/// 2. **Executes** the shard's filesystem scan through the full
///    scan-commit-checkpoint pipeline.
/// 3. **Advances** the shard lease against the coordinator, either
///    checkpointing partial progress or completing the shard with the
///    receipt-derived cursor.
/// 4. **Repeats** until no shards remain (returns `Ok(report)`) or an error
///    occurs (returns `Err`).
///
/// # Fail-fast semantics
///
/// The loop terminates on the first claim, scan, shard-advance, or
/// lease-uncertainty stop. Uncompleted leases are not explicitly released; the
/// coordination backend reclaims them when their deadlines expire.
///
/// # Errors
///
/// - [`DistributedRuntimeError::Coordinator`] — shard claiming, progress
///   lookup, checkpoint, or completion failed.
/// - [`DistributedRuntimeError::LeaseUncertain`] -- the worker can no longer
///   trust the claimed lease and must stop before terminal completion.
/// - [`DistributedRuntimeError::Runtime`] — scan execution failed.
/// - [`DistributedRuntimeError::Durability`] — the receipt-driven commit
///   pipeline could not confirm durable progress.
pub fn run_worker<C, F, D>(
    coordinator: &mut C,
    identity: WorkerIdentity,
    persistence: DistributedPersistence<F, D>,
    config: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError>
where
    C: CoordinationFacade,
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let mut scratch = Box::new(AcquireScratch::new());
    let mut report = DistributedRunReport::default();

    loop {
        let lease = match claim_next_lease(coordinator, &identity, &mut scratch) {
            Ok(Some(lease)) => lease,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    "worker loop terminating: shard claim failed",
                );
                return Err(error);
            }
        };
        report.leases_seen = report.leases_seen.saturating_add(1);

        let (scan_report, completion) = match run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            config,
        ) {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    shard_id = %lease.shard_id(),
                    "worker loop terminating: filesystem lease execution failed",
                );
                return Err(error);
            }
        };

        tracing::debug!(
            shard_id = %lease.shard_id(),
            items_scanned = scan_report.items_scanned,
            bytes_scanned = scan_report.bytes_scanned,
            findings_emitted = scan_report.findings_emitted,
            "shard scan complete",
        );

        if let Err(error) = advance_shard(coordinator, &identity, &lease, &completion) {
            tracing::warn!(
                error = %error,
                leases_seen = report.leases_seen,
                shards_scanned = report.shards_scanned,
                shard_id = %lease.shard_id(),
                "worker loop terminating: shard completion failed",
            );
            return Err(error);
        }

        report.shards_scanned = report.shards_scanned.saturating_add(1);
    }

    report.debug_assert_invariant();
    Ok(report)
}

/// Build a secret-shaped test fixture from non-secret fragments.
///
/// The assembled string matches gitleaks' generic-api-key rule at scan
/// time, but keeping the fragments separate avoids committing a literal
/// that trips secret-detection CI on the source file itself.
#[cfg(any(test, feature = "test-support"))]
pub fn secret_fixture() -> String {
    ["password=", "xK9mP2qL7wN4vR8t"].concat()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use gossip_contracts::{
        connector::{
            Cursor, EnumerateError, ItemKey, ItemRef, PageBuf, ReadError,
            ordered::OrderedContentCapabilities,
        },
        coordination::ShardSpec,
        identity::{
            FenceEpoch, FindingId, ObjectVersionId, ObservationId, OccurrenceId, OpId, PolicyHash,
            RuleFingerprint, RunId, ShardId, StableItemId, TenantId, TenantSecretKey, WorkerId,
            derive_rule_fingerprint,
        },
        persistence::{DoneLedgerKey, DoneLedgerStatus, WriteContext},
    };
    use gossip_coordination::{
        AcquireScratch, CoordinationBackend, CursorSemantics, CursorUpdate as CoordCursorUpdate,
        InMemoryCoordinator as CoordinationInMemoryCoordinator, InitialShardInput, RunConfig,
        RunManagement, ShardClaiming, ShardFilter, ShardStatus,
    };
    use gossip_frontier::{ShardSpecScratch, range_shard_ref};
    use gossip_orchestrator::{FilesystemShardPayload, FilesystemSourceMode};
    use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
    use scanner_scheduler::events::NullEventOutput;
    use tempfile::tempdir;

    use crate::{
        CancellationToken, OwnedCoreEvent,
        commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput},
        commit_sink::{FindingRecord, FindingsBatch, ItemMeta},
        coordination_sink::{CommitProgressRecord, StoredGitEvent},
        ordered_content::OrderedContentSkipReason,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StubFindings(u8);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct StubDoneLedger(u8);

    #[derive(Debug, Default)]
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

    fn tenant() -> TenantId {
        TenantId::from_bytes([0x11; 32])
    }

    fn run() -> RunId {
        RunId::from_raw(7)
    }

    fn worker(id: u64) -> WorkerId {
        WorkerId::from_raw(id)
    }

    fn policy_hash() -> PolicyHash {
        PolicyHash::from_bytes([0x22; 32])
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

    fn recorder() -> Arc<dyn CoordinationEventRecorder> {
        Arc::new(Recorder::default())
    }

    fn test_run_config(lease_duration_ms: u64) -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, lease_duration_ms, None).expect("run config")
    }

    fn base_scan_config(path: impl AsRef<Path>) -> FsScanConfig {
        FsScanConfig::new(path.as_ref().to_path_buf())
    }

    fn filesystem_payload(path: &Path, mode: FilesystemSourceMode) -> Vec<u8> {
        FilesystemShardPayload::new(
            mode,
            path.canonicalize()
                .expect("test filesystem payload paths must canonicalize"),
        )
        .encode()
        .expect("test filesystem payload must encode")
    }

    fn worker_identity(path: &Path) -> WorkerIdentity {
        WorkerIdentity::new(
            tenant(),
            run(),
            worker(13),
            policy_hash(),
            tenant_secret_key(),
            base_scan_config(path),
            recorder(),
        )
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

    fn clean_fixture() -> &'static str {
        "ordinary sample text for scanner tests"
    }

    fn binary_fixture() -> [u8; 8] {
        [0x7F, b'E', b'L', b'F', 0, 1, 2, 3]
    }

    fn setup_coordinator_with_connector_extra(
        connector_extra: &[Vec<u8>],
        lease_duration_ms: u64,
    ) -> CoordinationInMemoryCoordinator {
        let mut coordinator = CoordinationInMemoryCoordinator::new(lease_duration_ms);
        let now = wall_clock_now();
        coordinator
            .create_run(now, tenant(), run(), test_run_config(lease_duration_ms))
            .expect("create run");

        let mut scratch = ShardSpecScratch::new();
        let shard_entries: Vec<(ShardId, ShardSpec)> = connector_extra
            .iter()
            .enumerate()
            .map(|(idx, extra)| {
                let start = [idx as u8];
                let end = [(idx + 1) as u8];
                let spec_ref = range_shard_ref(&start, &end, extra.as_slice(), &mut scratch)
                    .expect("range shard spec");
                (
                    ShardId::from_raw(idx as u64 + 1),
                    ShardSpec::try_from_ref(spec_ref).expect("owned shard spec"),
                )
            })
            .collect();
        let shards: Vec<InitialShardInput<'_>> = shard_entries
            .iter()
            .map(|(shard_id, spec)| {
                InitialShardInput::new(*shard_id, spec.as_ref(), CoordCursorUpdate::initial())
            })
            .collect();
        let _ = coordinator
            .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
            .expect("register shards");

        coordinator
    }

    fn setup_coordinator_with_ranges(
        entries: &[(&Path, &[u8], &[u8])],
        lease_duration_ms: u64,
    ) -> CoordinationInMemoryCoordinator {
        let mut coordinator = CoordinationInMemoryCoordinator::new(lease_duration_ms);
        let now = wall_clock_now();
        coordinator
            .create_run(now, tenant(), run(), test_run_config(lease_duration_ms))
            .expect("create run");

        let mut scratch = ShardSpecScratch::new();
        let shard_entries: Vec<(ShardId, ShardSpec)> = entries
            .iter()
            .enumerate()
            .map(|(idx, (path, start, end))| {
                let connector_extra = filesystem_payload(path, FilesystemSourceMode::DirectoryRoot);
                let spec_ref = range_shard_ref(start, end, &connector_extra, &mut scratch)
                    .expect("range shard spec");
                (
                    ShardId::from_raw(idx as u64 + 1),
                    ShardSpec::try_from_ref(spec_ref).expect("owned shard spec"),
                )
            })
            .collect();
        let shards: Vec<InitialShardInput<'_>> = shard_entries
            .iter()
            .map(|(shard_id, spec)| {
                InitialShardInput::new(*shard_id, spec.as_ref(), CoordCursorUpdate::initial())
            })
            .collect();
        let _ = coordinator
            .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
            .expect("register shards");

        coordinator
    }

    fn claim_lease(
        coordinator: &mut CoordinationInMemoryCoordinator,
        identity: &WorkerIdentity,
    ) -> ShardLease {
        let mut scratch = AcquireScratch::new();
        let acquired = coordinator
            .claim_next_available(
                wall_clock_now(),
                identity.tenant,
                identity.run,
                identity.worker,
                &mut scratch,
            )
            .expect("claim next available");
        build_lease_from_acquire(acquired, identity).expect("runtime lease")
    }

    fn claim_coordination_lease(
        coordinator: &mut CoordinationInMemoryCoordinator,
        worker_id: WorkerId,
    ) -> gossip_coordination::Lease {
        let mut scratch = AcquireScratch::new();
        coordinator
            .claim_next_available(wall_clock_now(), tenant(), run(), worker_id, &mut scratch)
            .expect("claim next available")
            .lease
    }

    fn shard_summaries(
        coordinator: &CoordinationInMemoryCoordinator,
    ) -> Vec<gossip_coordination::ShardSummary> {
        let mut summaries = Vec::new();
        coordinator
            .list_shards_into(
                wall_clock_now(),
                tenant(),
                run(),
                ShardFilter::all(),
                &mut summaries,
            )
            .expect("list shards");
        summaries
    }

    fn run_progress(
        coordinator: &CoordinationInMemoryCoordinator,
    ) -> gossip_coordination::RunProgress {
        coordinator
            .get_run_progress(wall_clock_now(), tenant(), run())
            .expect("run progress")
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

    struct SinkSnapshot {
        done_keys: Vec<DoneLedgerKey>,
        finding_ids: Vec<FindingId>,
        occurrence_ids: Vec<OccurrenceId>,
        observation_ids: Vec<ObservationId>,
    }

    fn snapshot_sink_state(
        findings_sink: &InMemoryFindingsSink,
        done_ledger: &InMemoryDoneLedger,
        label: &str,
    ) -> SinkSnapshot {
        SinkSnapshot {
            done_keys: done_ledger
                .snapshot()
                .unwrap_or_else(|e| panic!("{label} done-ledger snapshot: {e}"))
                .into_iter()
                .map(|r| r.key())
                .collect(),
            finding_ids: findings_sink
                .findings_snapshot()
                .unwrap_or_else(|e| panic!("{label} findings snapshot: {e}"))
                .into_iter()
                .map(|r| r.finding_id())
                .collect(),
            occurrence_ids: findings_sink
                .occurrences_snapshot()
                .unwrap_or_else(|e| panic!("{label} occurrences snapshot: {e}"))
                .into_iter()
                .map(|r| r.occurrence_id())
                .collect(),
            observation_ids: findings_sink
                .observations_snapshot()
                .unwrap_or_else(|e| panic!("{label} observations snapshot: {e}"))
                .into_iter()
                .map(|r| r.observation_id())
                .collect(),
        }
    }

    #[test]
    fn shard_lease_preserves_claimed_coordination_metadata() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        assert_eq!(lease.shard_id(), "ShardId(1)");
        assert_eq!(lease.lease().tenant(), tenant());
        assert_eq!(lease.lease().run(), run());
        assert_eq!(lease.lease().shard(), ShardId::from_raw(1));
        assert_eq!(lease.lease().fence(), FenceEpoch::from_raw(2));
        assert_eq!(lease.write_context().tenant_id(), tenant());
        assert_eq!(lease.write_context().policy_hash(), policy_hash());
        assert_eq!(lease.tenant_secret_key(), tenant_secret_key());
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

        let lease_uncertain =
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed {
                deadline: LogicalTime::from_raw(10),
                observed: LogicalTime::from_raw(11),
            });
        assert_eq!(
            lease_uncertain.to_string(),
            "lease uncertainty: lease deadline elapsed during shard execution (deadline LogicalTime(10), observed LogicalTime(11))"
        );
        assert!(std::error::Error::source(&lease_uncertain).is_some());

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
    fn distributed_run_report_default_satisfies_invariant() {
        let report = DistributedRunReport::default();
        assert_eq!(report.leases_seen, 0);
        assert_eq!(report.shards_scanned, 0);
        assert!(report.shards_scanned <= report.leases_seen);

        // Non-trivial case: demonstrates the invariant holds for realistic
        // field values and guards against field-ordering mistakes in future
        // construction sites.
        let nonzero = DistributedRunReport {
            leases_seen: 10,
            shards_scanned: 7,
        };
        assert!(nonzero.shards_scanned <= nonzero.leases_seen);
    }

    #[test]
    fn lease_uncertainty_signal_preserves_first_reason() {
        let signal = LeaseUncertaintySignal::default();
        assert!(signal.current().is_none(), "new signal should be empty");

        let first = LeaseUncertainty::DeadlineElapsed {
            deadline: LogicalTime::from_raw(10),
            observed: LogicalTime::from_raw(11),
        };
        let second = LeaseUncertainty::CompletionStaleFence {
            presented: FenceEpoch::from_raw(1),
            current: FenceEpoch::from_raw(2),
        };

        assert!(
            signal.note(first.clone()),
            "first note() should record the reason"
        );
        assert!(
            !signal.note(second),
            "second note() must not overwrite the first reason"
        );

        assert_eq!(
            signal.current(),
            Some(first),
            "second note() must not overwrite the first reason"
        );
    }

    #[test]
    fn lease_uncertainty_signal_close_ignores_late_reason() {
        let signal = LeaseUncertaintySignal::default();
        signal.close();

        assert!(
            !signal.note(LeaseUncertainty::DeadlineElapsed {
                deadline: LogicalTime::from_raw(10),
                observed: LogicalTime::from_raw(11),
            }),
            "closed signal must reject late deadline notes"
        );
        assert!(
            signal.current().is_none(),
            "closed signal must not surface a late deadline reason"
        );
    }

    #[test]
    fn resolve_filesystem_lease_results_prefers_scan_failure_over_drain_failure() {
        let scan_error = ScanRuntimeError::Driver(AnyError::msg("scan boom"));
        let submitted_error = anyhow!("submitted boom");
        let stage_error = anyhow!("drain boom");

        // All three inputs fail so the test discriminates ordering: if the
        // function ever checked `submitted` before `outcome`, the returned
        // variant would be `Durability` instead of `Runtime`.
        let error = resolve_filesystem_lease_results(
            Err(scan_error),
            Err(submitted_error),
            Ok(Err(stage_error)),
            None,
        )
        .expect_err("scan failure should win when all three paths fail");

        assert!(
            matches!(error, DistributedRuntimeError::Runtime(_)),
            "expected Runtime variant, got: {error:?}"
        );
        assert!(
            error.to_string().contains("scan boom"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_filesystem_lease_results_returns_drain_failure_after_successful_scan() {
        let stage_error = anyhow!("drain boom");

        let error = resolve_filesystem_lease_results(
            Ok(OrderedSourceAssignmentOutcome {
                report: ScanReport::default(),
                termination: PageLoopTermination::Partial,
            }),
            Ok(Vec::new()),
            Ok(Err(stage_error)),
            None,
        )
        .expect_err("drain failure should surface after a successful scan");

        assert!(
            matches!(error, DistributedRuntimeError::Durability(_)),
            "expected Durability variant, got: {error:?}"
        );
        assert!(
            error.to_string().contains("drain boom"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_filesystem_lease_results_maps_submitted_failure_to_durability() {
        let submitted_error = anyhow!("submitted boom");

        let error = resolve_filesystem_lease_results(
            Ok(OrderedSourceAssignmentOutcome {
                report: ScanReport::default(),
                termination: PageLoopTermination::Partial,
            }),
            Err(submitted_error),
            // stage_result is never reached because submitted fails first.
            Err(anyhow!("unused")),
            None,
        )
        .expect_err("submitted failure should surface as Durability");

        assert!(
            matches!(error, DistributedRuntimeError::Durability(_)),
            "expected Durability variant, got: {error:?}"
        );
        assert!(
            error.to_string().contains("submitted boom"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_filesystem_lease_results_maps_drain_thread_panic_to_durability() {
        let panic_error = anyhow!("drain thread panicked");

        let error = resolve_filesystem_lease_results(
            Ok(OrderedSourceAssignmentOutcome {
                report: ScanReport::default(),
                termination: PageLoopTermination::Partial,
            }),
            Ok(Vec::new()),
            Err(panic_error),
            None,
        )
        .expect_err("thread panic should be a durability error");

        assert!(
            matches!(error, DistributedRuntimeError::Durability(_)),
            "expected Durability variant, got: {error:?}"
        );
        assert!(
            error.to_string().contains("drain thread panicked"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_filesystem_lease_results_prefers_lease_uncertainty_over_cancellation_gaps() {
        let reason = LeaseUncertainty::DeadlineElapsed {
            deadline: LogicalTime::from_raw(20),
            observed: LogicalTime::from_raw(21),
        };

        let error = resolve_filesystem_lease_results(
            Ok(OrderedSourceAssignmentOutcome {
                report: ScanReport::default(),
                termination: PageLoopTermination::ExhaustedEmptyConfirmed,
            }),
            Err(anyhow!("submit cancelled after lease expiry")),
            Err(anyhow!("unused")),
            Some(reason.clone()),
        )
        .expect_err("lease uncertainty should win over cancellation-induced submission gaps");

        assert_eq!(error.to_string(), format!("lease uncertainty: {reason}"));
        assert!(matches!(
            error,
            DistributedRuntimeError::LeaseUncertain(actual) if actual == reason
        ));
    }

    #[test]
    fn resolve_filesystem_lease_results_prefers_lease_uncertainty_over_scan_error() {
        let scan_error = ScanRuntimeError::Driver(AnyError::msg("scan boom"));
        let reason = LeaseUncertainty::DeadlineElapsed {
            deadline: LogicalTime::from_raw(20),
            observed: LogicalTime::from_raw(21),
        };

        let error = resolve_filesystem_lease_results(
            Err(scan_error),
            Err(anyhow!("submitted cancelled after lease expiry")),
            Err(anyhow!("unused")),
            Some(reason.clone()),
        )
        .expect_err("lease uncertainty should win over a concurrent scan error");

        assert_eq!(error.to_string(), format!("lease uncertainty: {reason}"));
        assert!(matches!(
            error,
            DistributedRuntimeError::LeaseUncertain(actual) if actual == reason
        ));
    }

    #[test]
    fn watch_lease_deadline_records_uncertainty_and_cancels_when_open() {
        let signal = LeaseUncertaintySignal::default();
        let cancel = CancellationToken::new();

        // Monotonic deadline in the past triggers immediate expiry.
        let expired = Instant::now() - Duration::from_secs(1);
        watch_lease_deadline(
            LogicalTime::from_raw(1),
            expired,
            cancel.clone(),
            Arc::new(AtomicBool::new(false)),
            signal.clone(),
        );

        assert!(cancel.is_cancelled(), "open signal should cancel on expiry");
        assert!(matches!(
            signal.current(),
            Some(LeaseUncertainty::DeadlineElapsed { deadline, .. })
                if deadline == LogicalTime::from_raw(1)
        ));
    }

    #[test]
    fn watch_lease_deadline_ignores_expiry_after_signal_closes() {
        let signal = LeaseUncertaintySignal::default();
        signal.close();
        let cancel = CancellationToken::new();

        let expired = Instant::now() - Duration::from_secs(1);
        watch_lease_deadline(
            LogicalTime::from_raw(1),
            expired,
            cancel.clone(),
            Arc::new(AtomicBool::new(false)),
            signal.clone(),
        );

        assert!(
            !cancel.is_cancelled(),
            "closed signal must suppress late deadline cancellation"
        );
        assert!(
            signal.current().is_none(),
            "closed signal must not surface a late deadline reason"
        );
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
    fn wait_for_submitted_commits_rejects_fewer_committed_than_submitted() {
        let err = wait_for_submitted_commits(vec![0, 1], vec![0])
            .expect_err("fewer committed than submitted should fail");

        let msg = err.to_string();
        assert!(
            msg.contains("submitted 2 commit(s) but commit stage produced 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wait_for_submitted_commits_rejects_more_committed_than_submitted() {
        let err = wait_for_submitted_commits(vec![0], vec![0, 1])
            .expect_err("more committed than submitted should fail");

        let msg = err.to_string();
        assert!(
            msg.contains("submitted 1 commit(s) but commit stage produced 2"),
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
    fn build_lease_from_acquire_hydrates_directory_root_payload() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator_with_connector_extra(
            &[filesystem_payload(
                dir.path(),
                FilesystemSourceMode::DirectoryRoot,
            )],
            30_000,
        );
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let canonical_dir = dir.path().canonicalize().expect("canonicalize directory");

        assert_eq!(lease.shard_id(), "ShardId(1)");
        assert_eq!(lease.scan_config().path, canonical_dir);
        assert_eq!(lease.source_mode(), FilesystemSourceMode::DirectoryRoot);
        assert_eq!(lease.write_context().tenant_id(), tenant());
        assert_eq!(lease.write_context().run_id(), run());
        assert_eq!(lease.write_context().shard_id(), ShardId::from_raw(1));
        assert_eq!(lease.write_context().policy_hash(), policy_hash());
        assert_eq!(lease.write_context().fence_epoch(), FenceEpoch::from_raw(2));
        assert_eq!(lease.range_start(), &[0u8]);
        assert_eq!(lease.range_end(), &[1u8]);
        assert!(lease.resume_cursor().last_key().is_none());
        assert!(lease.resume_cursor().token().is_none());
        assert_eq!(lease.cursor_semantics(), CursorSemantics::Completed);
    }

    #[test]
    fn build_lease_from_acquire_hydrates_single_file_payload() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("single-file.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let payload = filesystem_payload(&file_path, FilesystemSourceMode::SingleFile);
        let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let canonical_file = file_path.canonicalize().expect("canonicalize file");

        assert_eq!(lease.scan_config().path, canonical_file);
        assert_eq!(lease.source_mode(), FilesystemSourceMode::SingleFile);
    }

    #[test]
    fn build_lease_from_acquire_rejects_empty_filesystem_payload() {
        let mut coordinator = setup_coordinator_with_connector_extra(&[Vec::new()], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let mut scratch = AcquireScratch::new();
        let acquired = coordinator
            .claim_next_available(
                wall_clock_now(),
                identity.tenant,
                identity.run,
                identity.worker,
                &mut scratch,
            )
            .expect("claim next available");
        let err = build_lease_from_acquire(acquired, &identity)
            .expect_err("empty filesystem payload must be rejected");

        assert!(
            err.to_string().contains(
                "failed to decode filesystem shard payload: filesystem shard payload is empty"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_lease_from_acquire_preserves_restored_cursor_and_full_bounds() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = CoordinationInMemoryCoordinator::new(30_000);
        let now = wall_clock_now();
        coordinator
            .create_run(now, tenant(), run(), test_run_config(30_000))
            .expect("create run");

        let mut scratch = ShardSpecScratch::new();
        let connector_extra = filesystem_payload(dir.path(), FilesystemSourceMode::DirectoryRoot);
        let spec_ref =
            range_shard_ref(b"a", b"m", &connector_extra, &mut scratch).expect("range shard spec");
        let shard_spec = ShardSpec::try_from_ref(spec_ref).expect("owned shard spec");
        let initial_cursor = CoordCursorUpdate::with_token(b"f.txt", b"resume-token");
        let shards = [InitialShardInput::new(
            ShardId::from_raw(1),
            shard_spec.as_ref(),
            initial_cursor,
        )];
        let _ = coordinator
            .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
            .expect("register shards");

        let mut acquire_scratch = AcquireScratch::new();
        let acquired = coordinator
            .claim_next_available(
                wall_clock_now(),
                tenant(),
                run(),
                worker(1),
                &mut acquire_scratch,
            )
            .expect("claim next available");
        let lease = build_lease_from_acquire(acquired, &worker_identity(Path::new("/fallback")))
            .expect("runtime lease");

        assert_eq!(lease.range_start(), b"a");
        assert_eq!(lease.range_end(), b"m");
        assert_eq!(
            lease
                .resume_cursor()
                .last_key()
                .expect("resume cursor last_key")
                .as_bytes(),
            b"f.txt"
        );
        assert_eq!(
            lease
                .resume_cursor()
                .token()
                .expect("resume cursor token")
                .as_bytes(),
            b"resume-token"
        );
        assert_eq!(lease.cursor_semantics(), CursorSemantics::Completed);
    }

    #[test]
    fn deterministic_op_id_is_stable_and_input_sensitive() {
        let key = ShardKey::new(run(), ShardId::from_raw(9));
        let fence = FenceEpoch::from_raw(4);

        let baseline = deterministic_op_id(key, fence, OpKind::Complete);
        assert_eq!(baseline, deterministic_op_id(key, fence, OpKind::Complete));
        assert_ne!(
            baseline,
            deterministic_op_id(key, fence, OpKind::Checkpoint),
            "op-kind must influence the hash",
        );
        assert_ne!(
            baseline,
            deterministic_op_id(
                ShardKey::new(run(), ShardId::from_raw(10)),
                fence,
                OpKind::Complete
            ),
            "shard identity must influence the hash",
        );
        assert_ne!(
            baseline,
            deterministic_op_id(key, FenceEpoch::from_raw(5), OpKind::Complete),
            "fence epoch must influence the hash",
        );
    }

    #[test]
    fn advance_shard_exhausted_empty_uses_range_start_under_completed_semantics() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x05", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::ExhaustedEmpty,
        )
        .expect("zero-finding shard completion must succeed under Completed semantics");

        let progress = run_progress(&coordinator);
        assert_eq!(progress.active(), 0);
        assert_eq!(progress.done(), 1);

        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status(), ShardStatus::Done);
        assert_eq!(summaries[0].last_key(), Some(&[0x05u8][..]));
    }

    #[test]
    fn advance_shard_exhausted_empty_preserves_restored_cursor_after_checkpointed_progress() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"a", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let claimed = claim_lease(&mut coordinator, &identity);
        let checkpoint = Cursor::with_last_key(item_key("resume.txt"));

        advance_shard(
            &mut coordinator,
            &identity,
            &claimed,
            &ShardCompletionOutcome::Checkpoint {
                checkpoint: checkpoint.clone(),
            },
        )
        .expect("checkpoint-backed shard advance must succeed");

        let resumed = ShardLease::new(
            Arc::clone(claimed.shard_id_arc()),
            claimed.lease(),
            RestoredShardState::new(
                claimed.restored_state().shard_spec().clone(),
                checkpoint.clone(),
                claimed.cursor_semantics(),
            ),
            claimed.filesystem_source.clone(),
            claimed.write_context(),
            claimed.tenant_secret_key(),
        );

        advance_shard(
            &mut coordinator,
            &identity,
            &resumed,
            &ShardCompletionOutcome::ExhaustedEmpty,
        )
        .expect(
            "exhausted-empty completion after resumed progress must preserve the restored cursor",
        );

        let progress = run_progress(&coordinator);
        assert_eq!(progress.active(), 0);
        assert_eq!(progress.done(), 1);

        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status(), ShardStatus::Done);
        assert_eq!(
            summaries[0].last_key(),
            checkpoint.last_key().map(|key| key.as_bytes())
        );
    }

    #[test]
    fn advance_shard_complete_uses_receipt_cursor_under_completed_semantics() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"a", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let checkpoint = Cursor::with_last_key(item_key("secret.txt"));

        advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::Complete {
                checkpoint: checkpoint.clone(),
            },
        )
        .expect("checkpoint-backed shard completion must succeed");

        let progress = run_progress(&coordinator);
        assert_eq!(progress.active(), 0);
        assert_eq!(progress.done(), 1);

        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status(), ShardStatus::Done);
        assert_eq!(
            summaries[0].last_key(),
            Some(
                checkpoint
                    .last_key()
                    .expect("checkpoint key must be present")
                    .as_bytes()
            )
        );
        assert_ne!(
            summaries[0].last_key(),
            Some(lease.range_start()),
            "completion must honor the receipt-derived checkpoint instead of the shard range start",
        );
    }

    #[test]
    fn advance_shard_checkpoint_keeps_shard_active() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"a", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let checkpoint = Cursor::with_last_key(item_key("secret.txt"));

        advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::Checkpoint {
                checkpoint: checkpoint.clone(),
            },
        )
        .expect("checkpoint-backed shard advance must succeed");

        let progress = run_progress(&coordinator);
        assert_eq!(progress.active(), 1);
        assert_eq!(progress.done(), 0);

        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status(), ShardStatus::Active);
        assert_eq!(
            summaries[0].last_key(),
            checkpoint.last_key().map(|key| key.as_bytes())
        );
    }

    #[test]
    fn run_filesystem_lease_persists_checkpoint_cursor_for_secret_shard() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());
        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("filesystem lease should succeed");

        assert!(
            report.items_scanned >= 1,
            "scan report should record the scanned file"
        );
        let ShardCompletionOutcome::Complete { checkpoint } = completion else {
            panic!("non-empty shard should produce a progress-bearing completion");
        };
        assert!(
            checkpoint.last_key().is_some(),
            "receipt-driven checkpoint should carry a progress key"
        );
        assert!(
            checkpoint.token().is_none(),
            "receipt-driven checkpoint should be tokenless"
        );

        let observations = findings_sink
            .observations_snapshot()
            .expect("observations snapshot");
        assert!(
            !observations.is_empty(),
            "durable findings observations should be present"
        );

        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(rows[0].write_context(), lease.write_context());

        advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::Complete {
                checkpoint: checkpoint.clone(),
            },
        )
        .expect("complete shard");
        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries[0].status(), ShardStatus::Done);
        assert_eq!(
            summaries[0].last_key(),
            checkpoint.last_key().map(|key| key.as_bytes())
        );
    }

    #[test]
    fn run_filesystem_lease_zero_item_shard_returns_exhausted_empty_completion() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let done_ledger = InMemoryDoneLedger::new();
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("empty filesystem shard should succeed");

        assert_eq!(report.items_scanned, 0);
        assert_eq!(completion, ShardCompletionOutcome::ExhaustedEmpty);
        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty()
        );
    }

    #[test]
    fn run_filesystem_lease_processes_all_pages_under_ordered_item_budget() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a-secret.txt"), secret_fixture()).expect("write fixture a");
        fs::write(dir.path().join("b-secret.txt"), secret_fixture()).expect("write fixture b");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig {
                budgets: ScanBudgets {
                    max_items: 1,
                    max_bytes: 1_000_000,
                },
                ..DistributedRuntimeConfig::default()
            },
        )
        .expect("budgeted filesystem lease should succeed");

        assert_eq!(
            report.items_scanned, 2,
            "ordered-content lease should keep paging until the shard is exhausted"
        );
        let ShardCompletionOutcome::Complete { checkpoint } = completion else {
            panic!("final committed item should produce a progress-bearing completion");
        };
        assert_eq!(
            checkpoint
                .last_key()
                .expect("checkpoint last_key")
                .as_bytes(),
            b"b-secret.txt"
        );
        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            2,
            "both ordered items should commit across pages"
        );
        assert!(
            rows.iter()
                .all(|row| row.status() == DoneLedgerStatus::ScannedWithFindings),
            "each secret fixture should produce a findings-bearing done-ledger row"
        );
        assert!(
            !findings_sink
                .observations_snapshot()
                .expect("observations snapshot")
                .is_empty(),
            "the committed ordered items should still emit durable findings"
        );
    }

    #[test]
    fn run_filesystem_lease_binary_skip_produces_skipped_done_ledger_row() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("sample.bin"), binary_fixture()).expect("write binary fixture");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("binary filesystem lease should succeed");

        assert_eq!(report.binary_skipped, 1);
        let ShardCompletionOutcome::Complete { checkpoint } = completion else {
            panic!("skipped item should still produce a progress-bearing completion");
        };
        assert_eq!(
            checkpoint
                .last_key()
                .expect("checkpoint last_key")
                .as_bytes(),
            b"sample.bin"
        );
        assert!(
            findings_sink
                .observations_snapshot()
                .expect("observations snapshot")
                .is_empty(),
            "binary skip should not emit findings observations"
        );
        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status(), DoneLedgerStatus::Skipped);
    }

    #[test]
    fn run_filesystem_lease_clean_only_shard_produces_checkpoint_and_done_ledger_entry() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("readme.txt"), clean_fixture()).expect("write clean fixture");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("clean-only filesystem shard should succeed");

        assert_eq!(report.items_scanned, 1);
        // Clean files still produce a done-ledger entry ("scanned, nothing
        // found") and advance the checkpoint cursor so resume skips them.
        let ShardCompletionOutcome::Complete { checkpoint } = completion else {
            panic!("clean file should still produce a progress-bearing completion");
        };
        assert!(
            checkpoint.last_key().is_some(),
            "clean file should still produce a checkpoint cursor for resume"
        );
        assert!(
            findings_sink
                .observations_snapshot()
                .expect("observations snapshot")
                .is_empty()
        );
        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            1,
            "clean file should produce exactly one done-ledger row"
        );
    }

    #[test]
    fn run_filesystem_lease_commit_failure_prevents_completion() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .fail_next_commits(1)
            .expect("inject done-ledger commit failure");
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

        let error = run_filesystem_lease(
            Arc::clone(&identity.recorder),
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
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty()
        );
        assert!(
            !findings_sink
                .observations_snapshot()
                .expect("observations snapshot")
                .is_empty(),
            "findings may still be durable before the done-ledger failure"
        );
        assert_eq!(run_progress(&coordinator).active(), 1);
    }

    #[test]
    fn run_worker_returns_zero_report_when_all_shards_are_terminal() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let raw_lease = claim_coordination_lease(&mut coordinator, worker(1));
        let final_cursor = CoordCursorUpdate::with_last_key(b"done");
        let _ = coordinator
            .complete(
                wall_clock_now(),
                tenant(),
                &raw_lease,
                &final_cursor,
                OpId::from_raw(99),
            )
            .expect("complete shard");

        let report = run_worker(
            &mut coordinator,
            worker_identity(Path::new("/fallback")),
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect("settled run should succeed");

        assert_eq!(report.leases_seen, 0);
        assert_eq!(report.shards_scanned, 0);
    }

    #[test]
    fn run_worker_processes_multiple_shards_from_queue() {
        let dir_a = tempdir().expect("tempdir a");
        let dir_b = tempdir().expect("tempdir b");
        fs::write(dir_a.path().join("alpha-secret.txt"), secret_fixture())
            .expect("write fixture a");
        fs::write(dir_b.path().join("omega-secret.txt"), secret_fixture())
            .expect("write fixture b");

        let mut coordinator = setup_coordinator_with_ranges(
            &[(dir_a.path(), b"a", b"n"), (dir_b.path(), b"n", b"\xFF")],
            30_000,
        );
        let report = run_worker(
            &mut coordinator,
            worker_identity(Path::new("/fallback")),
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect("multi-shard run should succeed");

        assert_eq!(report.leases_seen, 2);
        assert_eq!(report.shards_scanned, 2);
        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 2);
        assert!(
            summaries
                .iter()
                .all(|summary| summary.status() == ShardStatus::Done)
        );
    }

    #[test]
    fn run_worker_retries_until_live_lease_expires() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 2_000);
        let _ = claim_coordination_lease(&mut coordinator, worker(99));

        let report = run_worker(
            &mut coordinator,
            worker_identity(Path::new("/fallback")),
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect("lease expiry retry should eventually claim the shard");

        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(run_progress(&coordinator).done(), 1);
    }

    #[test]
    fn run_worker_recovers_from_partial_done_ledger_failure_without_duplicate_rows() {
        const SECRET_FILE_COUNT: usize = 12;
        const SUCCESSFUL_COMMITS_BEFORE_CRASH: usize = 4;
        const POLL_ITERATIONS: usize = 2_000;
        const POLL_INTERVAL: Duration = Duration::from_millis(5);

        let dir = tempdir().expect("tempdir");
        for index in 0..SECRET_FILE_COUNT {
            let path = dir.path().join(format!("secret-{index:02}.txt"));
            fs::write(path, secret_fixture()).expect("write secret fixture");
        }

        let config = DistributedRuntimeConfig {
            commit_queue_capacity: NonZeroUsize::new(1).expect("non-zero queue capacity"),
            ..DistributedRuntimeConfig::default()
        };

        let expected_findings_sink = InMemoryFindingsSink::new();
        let expected_done_ledger = InMemoryDoneLedger::new();
        let mut expected_coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        run_worker(
            &mut expected_coordinator,
            worker_identity(Path::new("/fallback")),
            DistributedPersistence::new(
                expected_findings_sink.clone(),
                expected_done_ledger.clone(),
            ),
            config,
        )
        .expect("baseline run should succeed");

        let expected =
            snapshot_sink_state(&expected_findings_sink, &expected_done_ledger, "baseline");
        let expected_last_key = shard_summaries(&expected_coordinator)[0]
            .last_key()
            .expect("completed baseline shard should have a last_key")
            .to_vec();

        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .set_auto_complete(false)
            .expect("disable done-ledger auto-complete");

        let coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 2_000);
        let first_run = std::thread::spawn({
            let findings_sink = findings_sink.clone();
            let done_ledger = done_ledger.clone();
            move || {
                let mut coordinator = coordinator;
                let result = run_worker(
                    &mut coordinator,
                    worker_identity(Path::new("/fallback")),
                    DistributedPersistence::new(findings_sink, done_ledger),
                    config,
                );
                (coordinator, result)
            }
        });

        let next_pending_done_commit = || {
            for _ in 0..POLL_ITERATIONS {
                let pending = done_ledger.pending_ids().expect("pending done-ledger ids");
                match pending.as_slice() {
                    [op_id] => return *op_id,
                    [] => std::thread::sleep(POLL_INTERVAL),
                    _ => panic!(
                        "expected one pending done-ledger commit with queue capacity 1, got {}",
                        pending.len()
                    ),
                }
            }
            panic!("timed out waiting for a pending done-ledger commit (10s)");
        };

        for committed in 0..SUCCESSFUL_COMMITS_BEFORE_CRASH {
            let op_id = next_pending_done_commit();
            assert!(
                done_ledger
                    .release_specific(op_id)
                    .expect("release successful done-ledger commit"),
                "pending done-ledger op should release"
            );

            for _ in 0..POLL_ITERATIONS {
                let durable_rows = done_ledger.snapshot().expect("done-ledger snapshot");
                if durable_rows.len() == committed + 1 {
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            assert_eq!(
                done_ledger.snapshot().expect("done-ledger snapshot").len(),
                committed + 1,
                "done-ledger durability did not converge within 10s for commit {committed}"
            );
        }

        let failing_op = next_pending_done_commit();
        done_ledger
            .fail_next_commits(1)
            .expect("inject done-ledger commit failure");
        assert!(
            done_ledger
                .release_specific(failing_op)
                .expect("release failing done-ledger commit"),
            "failing done-ledger op should release"
        );

        // The findings sink is in auto-complete mode, so observations for the
        // failing commit are already durable before its done-ledger commit was
        // submitted. No synchronization wait is needed before snapshotting.
        let partial_done_keys = done_ledger
            .snapshot()
            .expect("partial done-ledger snapshot")
            .into_iter()
            .map(|record| record.key())
            .collect::<Vec<_>>();
        let partial_observation_ids = findings_sink
            .observations_snapshot()
            .expect("partial observations snapshot")
            .into_iter()
            .map(|record| record.observation_id())
            .collect::<Vec<_>>();

        assert_eq!(partial_done_keys.len(), SUCCESSFUL_COMMITS_BEFORE_CRASH);
        assert!(partial_done_keys.len() < expected.done_keys.len());
        assert!(
            partial_observation_ids.len() > partial_done_keys.len(),
            "the failed item should leave durable observations ahead of the done-ledger"
        );

        done_ledger
            .set_auto_complete(true)
            .expect("re-enable done-ledger auto-complete");
        for _ in 0..POLL_ITERATIONS {
            if first_run.is_finished() {
                break;
            }
            for op_id in done_ledger.pending_ids().expect("pending done-ledger ids") {
                assert!(
                    done_ledger
                        .release_specific(op_id)
                        .expect("release pending done-ledger commit"),
                    "pending done-ledger op should release"
                );
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        assert!(
            first_run.is_finished(),
            "worker thread did not terminate within 10s after releasing all pending commits"
        );

        let (mut coordinator, first_result) =
            first_run.join().expect("worker thread should not panic");
        let first_error =
            first_result.expect_err("first worker invocation should fail on done-ledger commit");
        assert!(
            matches!(
                &first_error,
                DistributedRuntimeError::Durability(_) | DistributedRuntimeError::Runtime(_)
            ),
            "expected runtime or durability error, got: {first_error:?}"
        );

        let summaries_after_crash = shard_summaries(&coordinator);
        assert_eq!(summaries_after_crash.len(), 1);
        assert_eq!(summaries_after_crash[0].status(), ShardStatus::Active);
        assert!(
            summaries_after_crash[0].last_key().is_none(),
            "coordinator cursor must not advance before complete_shard runs"
        );
        let acquire_count_after_crash = summaries_after_crash[0].acquire_count();

        let progress_after_crash = run_progress(&coordinator);
        assert_eq!(progress_after_crash.active(), 1);
        assert_eq!(progress_after_crash.done(), 0);

        let done_keys_before_recovery: std::collections::HashSet<_> = done_ledger
            .snapshot()
            .expect("pre-recovery done-ledger snapshot")
            .into_iter()
            .map(|r| r.key())
            .collect();

        let recovery_report = run_worker(
            &mut coordinator,
            worker_identity(Path::new("/fallback")),
            DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
            config,
        )
        .expect("second worker invocation should recover after lease expiry");
        assert_eq!(recovery_report.leases_seen, 1);
        assert_eq!(recovery_report.shards_scanned, 1);

        let done_keys_after_recovery: std::collections::HashSet<_> = done_ledger
            .snapshot()
            .expect("post-recovery done-ledger snapshot")
            .into_iter()
            .map(|r| r.key())
            .collect();
        let new_keys_from_recovery: std::collections::HashSet<_> = done_keys_after_recovery
            .difference(&done_keys_before_recovery)
            .copied()
            .collect();
        let expected_new_keys: std::collections::HashSet<_> = expected
            .done_keys
            .iter()
            .copied()
            .filter(|k| !done_keys_before_recovery.contains(k))
            .collect();
        assert_eq!(
            new_keys_from_recovery, expected_new_keys,
            "recovery should only commit items not already in the done-ledger"
        );

        let recovered = snapshot_sink_state(&findings_sink, &done_ledger, "recovered");

        assert_eq!(recovered.done_keys, expected.done_keys);
        assert_eq!(recovered.finding_ids, expected.finding_ids);
        assert_eq!(recovered.occurrence_ids, expected.occurrence_ids);
        assert_eq!(recovered.observation_ids, expected.observation_ids);

        let summaries_after_recovery = shard_summaries(&coordinator);
        assert_eq!(summaries_after_recovery.len(), 1);
        assert_eq!(summaries_after_recovery[0].status(), ShardStatus::Done);
        assert_eq!(
            summaries_after_recovery[0].last_key(),
            Some(expected_last_key.as_slice())
        );
        assert!(
            summaries_after_recovery[0].acquire_count() > acquire_count_after_crash,
            "recovery must reacquire the shard under a higher fence epoch"
        );
        assert_eq!(run_progress(&coordinator).done(), 1);
    }

    #[test]
    fn run_worker_returns_missing_run_as_coordinator_error() {
        let mut coordinator = CoordinationInMemoryCoordinator::new(30_000);
        let error = run_worker(
            &mut coordinator,
            worker_identity(Path::new("/fallback")),
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("missing run should surface a coordinator error");

        assert!(
            matches!(error, DistributedRuntimeError::Coordinator(_)),
            "missing run should produce Coordinator variant, got: {error:?}"
        );
        assert!(error.to_string().contains("run not found"));
    }

    #[test]
    fn claim_retry_delay_with_future_deadline() {
        let now = LogicalTime::from_raw(1000);
        let deadline = Some(LogicalTime::from_raw(1050));
        assert_eq!(claim_retry_delay(now, deadline), Duration::from_millis(50));
    }

    #[test]
    fn claim_retry_delay_clamps_stale_deadline_to_one_ms() {
        let now = LogicalTime::from_raw(2000);
        let stale = Some(LogicalTime::from_raw(1000));
        assert_eq!(claim_retry_delay(now, stale), Duration::from_millis(1));
    }

    #[test]
    fn claim_retry_delay_falls_back_without_deadline() {
        let now = LogicalTime::from_raw(1000);
        assert_eq!(claim_retry_delay(now, None), CLAIM_RACE_RETRY_DELAY);
    }

    #[test]
    fn jittered_delay_stays_within_bounds() {
        for base_ms in [2, 10, 25, 100, 1000] {
            let base = Duration::from_millis(base_ms);
            for _ in 0..20 {
                let result = jittered_delay(base);
                assert!(
                    result >= Duration::from_millis(1),
                    "jittered delay must be at least 1 ms, got {result:?} for base {base_ms} ms"
                );
                assert!(
                    result <= base,
                    "jittered delay must not exceed base, got {result:?} for base {base_ms} ms"
                );
                // Yield briefly so the nanosecond input changes between iterations.
                std::thread::yield_now();
            }
        }
    }

    #[test]
    fn jittered_delay_returns_base_for_one_ms() {
        assert_eq!(
            jittered_delay(Duration::from_millis(1)),
            Duration::from_millis(1),
            "1 ms base must pass through without jitter"
        );
    }

    #[test]
    fn watch_lease_deadline_exits_promptly_on_unpark() {
        let signal = LeaseUncertaintySignal::default();
        let cancel = CancellationToken::new();
        let done = Arc::new(AtomicBool::new(false));

        // Deadline far in the future — the watchdog should park, not fire.
        let far_future = Instant::now() + Duration::from_secs(60);
        let done_clone = Arc::clone(&done);
        let signal_clone = signal.clone();
        let cancel_clone = cancel.clone();
        let handle = std::thread::spawn(move || {
            watch_lease_deadline(
                LogicalTime::from_raw(u64::MAX),
                far_future,
                cancel_clone,
                done_clone,
                signal_clone,
            );
        });

        // Signal completion and unpark immediately.
        done.store(true, Ordering::Release);
        handle.thread().unpark();

        // The watchdog should exit almost instantly rather than sleeping 25 ms.
        handle.join().expect("watchdog thread should not panic");

        assert!(
            !cancel.is_cancelled(),
            "early exit via unpark must not trigger cancellation"
        );
        assert!(
            signal.current().is_none(),
            "early exit via unpark must not record a deadline reason"
        );
    }

    #[test]
    fn build_lease_from_acquire_rejects_non_utf8_filesystem_payload_path() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let mut payload = filesystem_payload(&file_path, FilesystemSourceMode::SingleFile);
        // Wire format: byte 0 = mode tag, bytes 1.. = UTF-8 path.
        // Overwriting byte 2 injects an invalid UTF-8 byte into the path portion.
        payload[2] = 0xFF;
        let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
        let mut scratch = AcquireScratch::new();
        let acquired = coordinator
            .claim_next_available(wall_clock_now(), tenant(), run(), worker(1), &mut scratch)
            .expect("claim next available");
        let identity = worker_identity(Path::new("/fallback"));

        let err = build_lease_from_acquire(acquired, &identity)
            .expect_err("non-UTF-8 filesystem payload path must be rejected");
        assert!(
            err.to_string()
                .contains("filesystem shard payload mode 'single_file' path is not valid UTF-8"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_lease_from_acquire_rejects_payload_mode_path_mismatch() {
        let dir = tempdir().expect("tempdir");
        let payload = FilesystemShardPayload::new(FilesystemSourceMode::SingleFile, dir.path())
            .encode()
            .expect("mismatched payload should still encode");
        let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
        let mut scratch = AcquireScratch::new();
        let acquired = coordinator
            .claim_next_available(wall_clock_now(), tenant(), run(), worker(1), &mut scratch)
            .expect("claim next available");
        let identity = worker_identity(Path::new("/fallback"));

        let err = build_lease_from_acquire(acquired, &identity)
            .expect_err("mode/path mismatch must fail during hydration");
        assert!(
            err.to_string()
                .contains("filesystem shard payload mode 'single_file' requires a regular file"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn build_lease_from_acquire_rejects_symlink_payload_path() {
        use std::os::unix::fs as unix_fs;

        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("real.txt");
        fs::write(&target, "fixture").expect("write target");
        let link = dir.path().join("link.txt");
        unix_fs::symlink(&target, &link).expect("create symlink");

        let payload = FilesystemShardPayload::new(FilesystemSourceMode::SingleFile, &link)
            .encode()
            .expect("symlink payload should encode");
        let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
        let mut scratch = AcquireScratch::new();
        let acquired = coordinator
            .claim_next_available(wall_clock_now(), tenant(), run(), worker(1), &mut scratch)
            .expect("claim next available");
        let identity = worker_identity(Path::new("/fallback"));

        let err = build_lease_from_acquire(acquired, &identity)
            .expect_err("symlink payload path must be rejected");
        assert!(
            err.to_string().contains("is a symlink"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_filesystem_lease_succeeds_with_mixed_finding_and_clean_files() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write secret fixture");
        fs::write(dir.path().join("readme.txt"), clean_fixture()).expect("write clean fixture");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("mixed shard should succeed");

        assert!(
            report.items_scanned >= 2,
            "both files should be scanned, got {}",
            report.items_scanned,
        );
        let ShardCompletionOutcome::Complete { checkpoint } = completion else {
            panic!("shard with findings should produce a progress-bearing completion");
        };
        assert!(
            checkpoint.last_key().is_some(),
            "shard with findings should checkpoint"
        );

        let observations = findings_sink
            .observations_snapshot()
            .expect("observations snapshot");
        assert!(
            !observations.is_empty(),
            "secret file should produce durable findings"
        );

        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            2,
            "both files (finding-bearing and clean) produce a done-ledger row"
        );
    }

    #[test]
    fn complete_shard_reports_lease_uncertainty_when_lease_is_fenced() {
        let dir = tempdir().expect("tempdir");

        // Use a very short TTL so our lease expires quickly.
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        // Wait for our lease to expire, then let a rival claim the same
        // shard. This bumps the fence epoch, making our lease stale.
        std::thread::sleep(Duration::from_millis(100));
        let _rival_lease = claim_coordination_lease(&mut coordinator, worker(99));

        let err = advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::ExhaustedEmpty,
        )
        .expect_err("completion with stale fence should fail");
        assert!(
            matches!(
                err,
                DistributedRuntimeError::LeaseUncertain(
                    LeaseUncertainty::CompletionStaleFence { .. }
                )
            ),
            "expected LeaseUncertain stale-fence variant, got: {err:?}"
        );
    }

    #[test]
    fn complete_shard_reports_lease_uncertainty_when_lease_has_expired() {
        let dir = tempdir().expect("tempdir");

        // Use a very short TTL so our lease expires quickly.
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        // Wait for the lease to expire WITHOUT a rival claim. This triggers
        // LeaseExpired (no fence bump) rather than StaleFence.
        std::thread::sleep(Duration::from_millis(100));

        let err = advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::ExhaustedEmpty,
        )
        .expect_err("completion after lease expiry should fail");
        assert!(
            matches!(
                err,
                DistributedRuntimeError::LeaseUncertain(
                    LeaseUncertainty::CompletionLeaseExpired { .. }
                )
            ),
            "expected LeaseUncertain lease-expired variant, got: {err:?}"
        );
    }

    #[test]
    fn checkpoint_shard_reports_lease_uncertainty_when_lease_is_fenced() {
        let dir = tempdir().expect("tempdir");

        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let checkpoint =
            Cursor::try_from_update(CoordCursorUpdate::new(b"\x05")).expect("checkpoint cursor");

        std::thread::sleep(Duration::from_millis(100));
        let _rival_lease = claim_coordination_lease(&mut coordinator, worker(99));

        let err = advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::Checkpoint {
                checkpoint: checkpoint.clone(),
            },
        )
        .expect_err("checkpoint with stale fence should fail");
        assert!(
            matches!(
                err,
                DistributedRuntimeError::LeaseUncertain(
                    LeaseUncertainty::CompletionStaleFence { .. }
                )
            ),
            "expected LeaseUncertain stale-fence variant, got: {err:?}"
        );
    }

    #[test]
    fn checkpoint_shard_reports_lease_uncertainty_when_lease_has_expired() {
        let dir = tempdir().expect("tempdir");

        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let checkpoint =
            Cursor::try_from_update(CoordCursorUpdate::new(b"\x05")).expect("checkpoint cursor");

        std::thread::sleep(Duration::from_millis(100));

        let err = advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::Checkpoint { checkpoint },
        )
        .expect_err("checkpoint after lease expiry should fail");
        assert!(
            matches!(
                err,
                DistributedRuntimeError::LeaseUncertain(
                    LeaseUncertainty::CompletionLeaseExpired { .. }
                )
            ),
            "expected LeaseUncertain lease-expired variant, got: {err:?}"
        );
    }

    #[test]
    fn advance_shard_maps_terminal_shard_to_coordinator_error() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x05", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        // Complete the shard successfully first.
        advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::ExhaustedEmpty,
        )
        .expect("first completion should succeed");

        // Use the checkpoint path on the terminal shard so the deterministic
        // OpId differs from the first completion and reaches terminal-state
        // validation rather than idempotent replay handling.
        let err = advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::Checkpoint {
                checkpoint: Cursor::with_last_key(item_key("z.txt")),
            },
        )
        .expect_err("checkpointing an already-done shard should fail");

        assert!(
            matches!(err, DistributedRuntimeError::Coordinator(_)),
            "expected Coordinator error for terminal shard, got: {err:?}"
        );
        assert!(
            !matches!(err, DistributedRuntimeError::LeaseUncertain(_)),
            "ShardTerminal must not be misclassified as LeaseUncertain"
        );
    }

    #[test]
    fn run_filesystem_lease_reports_deadline_expiry_before_completion() {
        const POLL_ITERATIONS: usize = 2_000;
        const POLL_INTERVAL: Duration = Duration::from_millis(5);

        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 500);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .set_auto_complete(false)
            .expect("disable done-ledger auto-complete");

        let recorder = Arc::clone(&identity.recorder);
        let lease_for_thread = lease.clone();
        let findings_for_thread = findings_sink.clone();
        let done_for_thread = done_ledger.clone();
        let handle = std::thread::spawn(move || {
            let persistence = DistributedPersistence::new(findings_for_thread, done_for_thread);
            run_filesystem_lease(
                recorder,
                &persistence,
                &lease_for_thread,
                DistributedRuntimeConfig {
                    commit_queue_capacity: NonZeroUsize::new(1)
                        .expect("non-zero commit queue capacity"),
                    ..DistributedRuntimeConfig::default()
                },
            )
        });

        let pending_op = loop {
            let pending = done_ledger.pending_ids().expect("pending done-ledger ids");
            match pending.as_slice() {
                [op_id] => break *op_id,
                [] => std::thread::sleep(POLL_INTERVAL),
                _ => panic!(
                    "expected one pending done-ledger commit, got {}",
                    pending.len()
                ),
            }
        };

        std::thread::sleep(Duration::from_millis(650));
        assert!(
            done_ledger
                .release_specific(pending_op)
                .expect("release blocked done-ledger commit"),
            "pending done-ledger op should release"
        );

        for _ in 0..POLL_ITERATIONS {
            if handle.is_finished() {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        assert!(
            handle.is_finished(),
            "filesystem lease thread did not terminate within 10s after the blocked commit released"
        );

        let error = handle
            .join()
            .expect("filesystem lease thread should not panic")
            .expect_err("deadline expiry should stop the lease before completion");
        assert!(
            matches!(
                error,
                DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed { .. })
            ),
            "expected deadline-based lease uncertainty, got: {error:?}"
        );

        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            1,
            "the in-flight commit may still finish durably before the worker aborts"
        );

        let progress = run_progress(&coordinator);
        assert_eq!(progress.active(), 1);
        assert_eq!(progress.done(), 0);

        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status(), ShardStatus::Active);
        assert!(
            summaries[0].last_key().is_none(),
            "lease uncertainty must not attempt terminal completion"
        );
    }

    #[test]
    fn run_filesystem_lease_rejects_already_expired_lease() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        // TTL of 1ms — the lease will have expired by the time we call
        // run_filesystem_lease.
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 1);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        std::thread::sleep(Duration::from_millis(50));

        let done_ledger = InMemoryDoneLedger::new();
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

        let error = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect_err("already-expired lease should be rejected before starting the scan pipeline");

        assert!(
            matches!(
                error,
                DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed { .. })
            ),
            "expected immediate deadline-elapsed rejection, got: {error:?}"
        );

        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty(),
            "no done-ledger entries should exist because the scan pipeline never started"
        );
    }

    #[test]
    fn ordered_content_error_codes_are_valid_and_match_expected_values() {
        let failure = OrderedContentReadStop::failure_code();
        assert_eq!(failure.as_str(), "READ_FAILED");

        let truncation = OrderedContentReadStop::truncation_code();
        assert_eq!(truncation.as_str(), "TRUNCATED");

        let binary = OrderedContentSkipReason::Binary.done_ledger_code();
        assert_eq!(binary.as_str(), "BINARY");

        let extractable = OrderedContentSkipReason::BinaryExtractable.done_ledger_code();
        assert_eq!(extractable.as_str(), "BINARY_EXTRACTABLE");
    }

    /// Capturing event sink that converts borrowed `CoreEvent`s into owned
    /// snapshots so tests can assert on structured fields after the call.
    #[derive(Default)]
    struct CapturingEventOutput {
        events: Mutex<Vec<OwnedCoreEvent>>,
    }

    impl EventOutput for CapturingEventOutput {
        fn emit_core(&self, event: CoreEvent<'_>) {
            self.events
                .lock()
                .expect("capturing sink lock")
                .push(OwnedCoreEvent::from_core(event));
        }

        fn flush(&self) {}
    }

    impl CapturingEventOutput {
        fn take(&self) -> Vec<OwnedCoreEvent> {
            std::mem::take(&mut *self.events.lock().expect("capturing sink lock"))
        }
    }

    #[test]
    fn emit_ordered_summary_emits_summary_event_with_correct_metrics() {
        let report = ScanReport {
            items_scanned: 42,
            bytes_scanned: 10 * 1024 * 1024,
            chunks_scanned: 100,
            findings_emitted: 3,
            errors: 1,
            scan_ns: 2_000_000_000,
            ..ScanReport::default()
        };

        let sink = CapturingEventOutput::default();
        emit_ordered_summary(&sink, report);

        let events = sink.take();
        assert_eq!(events.len(), 1, "exactly one summary event expected");

        let OwnedCoreEvent::Summary {
            source,
            status,
            elapsed_ms,
            bytes_scanned,
            findings_emitted,
            errors,
            throughput_mib_s,
        } = &events[0]
        else {
            panic!("expected Summary event, got: {:?}", events[0]);
        };

        assert_eq!(*source, SourceKind::Fs);
        assert_eq!(
            *status, "error",
            "non-zero errors must produce status=error"
        );
        // 2_000_000_000 ns = 2000 ms
        assert_eq!(*elapsed_ms, 2000);
        assert_eq!(*bytes_scanned, 10 * 1024 * 1024);
        assert_eq!(*findings_emitted, 3);
        assert_eq!(*errors, 1);
        // 10 MiB / 2s = 5.0 MiB/s
        assert!(
            (*throughput_mib_s - 5.0).abs() < 0.001,
            "expected ~5.0 MiB/s, got {throughput_mib_s}"
        );
    }

    #[test]
    fn emit_ordered_summary_reports_ok_when_no_errors() {
        let report = ScanReport {
            items_scanned: 10,
            bytes_scanned: 500,
            errors: 0,
            scan_ns: 1_000_000,
            ..ScanReport::default()
        };

        let sink = CapturingEventOutput::default();
        emit_ordered_summary(&sink, report);

        let events = sink.take();
        let OwnedCoreEvent::Summary { status, .. } = &events[0] else {
            panic!("expected Summary event");
        };
        assert_eq!(*status, "ok", "zero errors must produce status=ok");
    }

    /// Deferred items (too large for the byte budget) must not advance the
    /// checkpoint past their key positions. If they did, the next shard claim
    /// would start after the deferred key and permanently lose the item.
    #[test]
    fn run_filesystem_lease_stops_checkpoint_before_deferred_item() {
        let dir = tempdir().expect("tempdir");
        // a-small.txt will be admitted (key order: first)
        fs::write(dir.path().join("a-small.txt"), clean_fixture()).expect("write a");
        // b-large.txt exceeds the byte budget and will be deferred
        fs::write(dir.path().join("b-large.txt"), vec![b'x'; 100_000]).expect("write b");
        // c-small.txt is admitted but comes after b-large.txt in key order
        fs::write(dir.path().join("c-small.txt"), clean_fixture()).expect("write c");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let done_ledger = InMemoryDoneLedger::new();
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

        let (_report, checkpoint) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig {
                budgets: ScanBudgets {
                    max_items: 100,
                    // b-large.txt (100 KB) exceeds this budget, triggering deferral.
                    max_bytes: 1_000,
                },
                ..DistributedRuntimeConfig::default()
            },
        )
        .expect("lease with deferred item should succeed");

        let ShardCompletionOutcome::Checkpoint { checkpoint } = checkpoint else {
            panic!("at least one terminal item should be committed before the deferral");
        };
        assert_eq!(
            checkpoint
                .last_key()
                .expect("checkpoint last_key")
                .as_bytes(),
            b"a-small.txt",
            "checkpoint must not advance past the deferred item (b-large.txt)"
        );

        // Only a-small.txt should have a done-ledger entry.
        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            1,
            "only items committed before the deferred boundary get done-ledger entries"
        );
    }

    #[test]
    fn run_filesystem_lease_rejects_zero_progress_partial_shard_without_exhaustion() {
        let dir = tempdir().expect("tempdir");
        // a-large.txt sorts first and exceeds the byte budget, so execution
        // stops before any receipt-backed progress is possible.
        fs::write(dir.path().join("a-large.txt"), vec![b'x'; 100_000]).expect("write a");
        // b-small.txt comes later in key order and must not be used to infer
        // exhausted-empty completion for the shard.
        fs::write(dir.path().join("b-small.txt"), clean_fixture()).expect("write b");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new());

        let err = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig {
                budgets: ScanBudgets {
                    max_items: 100,
                    max_bytes: 1_000,
                },
                ..DistributedRuntimeConfig::default()
            },
        )
        .expect_err("partial shard without durable progress must not complete as exhausted-empty");

        assert!(
            err.to_string()
                .contains("stopped before confirming exhaustion"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn advance_shard_exhausted_empty_unbounded_lower_bound_uses_range_safe_sentinel() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let claimed = claim_lease(&mut coordinator, &identity);
        let lease = ShardLease::new(
            Arc::clone(claimed.shard_id_arc()),
            claimed.lease(),
            RestoredShardState::new(
                ShardSpec::with_range(vec![], vec![0x01]),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
            claimed.filesystem_source.clone(),
            claimed.write_context(),
            claimed.tenant_secret_key(),
        );

        advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::ExhaustedEmpty,
        )
        .expect("unbounded-lower-bound exhausted-empty completion must succeed");

        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status(), ShardStatus::Done);
        assert_eq!(
            summaries[0].last_key(),
            Some(EMPTY_RANGE_SENTINEL_KEY),
            "exhausted-empty completion should use the sentinel key when the shard has no lower bound",
        );
    }

    #[test]
    fn advance_shard_rejects_out_of_range_exhausted_empty_fallback() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let claimed = claim_lease(&mut coordinator, &identity);
        let lease = ShardLease::new(
            Arc::clone(claimed.shard_id_arc()),
            claimed.lease(),
            RestoredShardState::new(
                ShardSpec::with_range(vec![], vec![0x00]),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
            claimed.filesystem_source.clone(),
            claimed.write_context(),
            claimed.tenant_secret_key(),
        );

        let err = advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::ExhaustedEmpty,
        )
        .expect_err("out-of-range exhausted-empty fallback must be rejected");

        assert!(
            matches!(err, DistributedRuntimeError::Runtime(_)),
            "expected Runtime error for out-of-range completion cursor, got: {err:?}"
        );
        assert!(
            err.to_string().contains("not in bounds"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn advance_shard_rejects_out_of_range_complete_checkpoint() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let claimed = claim_lease(&mut coordinator, &identity);
        let lease = ShardLease::new(
            Arc::clone(claimed.shard_id_arc()),
            claimed.lease(),
            RestoredShardState::new(
                ShardSpec::with_range(vec![0x01], vec![0x0F]),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
            claimed.filesystem_source.clone(),
            claimed.write_context(),
            claimed.tenant_secret_key(),
        );

        let err = advance_shard(
            &mut coordinator,
            &identity,
            &lease,
            &ShardCompletionOutcome::Complete {
                checkpoint: Cursor::with_last_key(item_key("\x0F")),
            },
        )
        .expect_err("out-of-range progress checkpoint must be rejected");

        assert!(
            matches!(err, DistributedRuntimeError::Runtime(_)),
            "expected Runtime error for out-of-range completion cursor, got: {err:?}"
        );
        assert!(
            err.to_string().contains("not in bounds"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_filesystem_lease_complete_path_scans_required_exhausted_empty_suffix() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("only.txt"), clean_fixture()).expect("write clean fixture");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new());

        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("single-page complete shard should succeed");

        assert_eq!(report.items_scanned, 1);
        let ShardCompletionOutcome::Complete { checkpoint } = completion else {
            panic!("single terminal page should still produce progress-bearing completion");
        };
        assert_eq!(
            checkpoint
                .last_key()
                .expect("checkpoint last_key")
                .as_bytes(),
            b"only.txt"
        );
    }

    #[test]
    fn run_filesystem_lease_multi_page_terminal_exhausted_empty_sequence() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.txt"), clean_fixture()).expect("write a");
        fs::write(dir.path().join("b.txt"), clean_fixture()).expect("write b");
        fs::write(dir.path().join("c.txt"), clean_fixture()).expect("write c");

        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let done_ledger = InMemoryDoneLedger::new();
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

        let (report, completion) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig {
                budgets: ScanBudgets {
                    max_items: 1,
                    max_bytes: 1_000_000,
                },
                ..DistributedRuntimeConfig::default()
            },
        )
        .expect("multi-page shard should succeed");

        assert_eq!(
            report.items_scanned, 3,
            "all three files should be scanned across multiple pages"
        );
        let ShardCompletionOutcome::Complete { checkpoint } = completion else {
            panic!("3-item shard should produce progress-bearing completion");
        };
        assert_eq!(
            checkpoint
                .last_key()
                .expect("checkpoint last_key")
                .as_bytes(),
            b"c.txt"
        );
        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(
            rows.len(),
            3,
            "all three items should have done-ledger entries"
        );
    }

    // ── Suffix-protocol test infrastructure ──────────────────────────

    /// Multi-call scripted source for testing page-loop control flow.
    ///
    /// Each `fill_page` call pops the next result from the front of the
    /// queue, increments a counter for test assertions, and panics if
    /// called more times than scripted. An optional `cancel_on_call` fires
    /// a [`CancellationToken`] on a specific call index (0-based) to test
    /// cancellation during the page loop.
    struct MultiStepScriptedSource {
        pages: std::collections::VecDeque<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
        fill_page_calls: Arc<AtomicU64>,
        cancel_on_call: Option<(usize, CancellationToken)>,
        call_count: usize,
    }

    impl MultiStepScriptedSource {
        fn new(
            pages: Vec<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
        ) -> (Self, Arc<AtomicU64>) {
            let fill_page_calls = Arc::new(AtomicU64::new(0));
            (
                Self {
                    pages: pages.into(),
                    fill_page_calls: Arc::clone(&fill_page_calls),
                    cancel_on_call: None,
                    call_count: 0,
                },
                fill_page_calls,
            )
        }
    }

    impl Drop for MultiStepScriptedSource {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                assert!(
                    self.pages.is_empty(),
                    "MultiStepScriptedSource: {} scripted page(s) were never consumed",
                    self.pages.len()
                );
            }
        }
    }

    impl OrderedContentSource for MultiStepScriptedSource {
        fn capabilities(&self) -> OrderedContentCapabilities {
            OrderedContentCapabilities::default()
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
            self.fill_page_calls.fetch_add(1, Ordering::Relaxed);
            let index = self.call_count;
            self.call_count += 1;
            if let Some((target, ref token)) = self.cancel_on_call
                && index == target
            {
                token.cancel();
            }
            self.pages
                .pop_front()
                .expect("MultiStepScriptedSource: unexpected extra fill_page call")
        }

        /// Scripted suffix tests do not care about file bytes; they only
        /// need a stable clean payload when the scan runtime opens an item.
        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn std::io::Read + Send>, ReadError> {
            Ok(Box::new(std::io::Cursor::new(b"clean".to_vec())))
        }
    }

    fn suffix_test_item(name: &[u8], size: u64) -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(name).expect("item key"),
            ItemRef::try_from_slice(name).expect("item ref"),
            StableItemId::from_bytes([name[0]; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(name)),
        )
        .with_size_hint(size)
    }

    /// Run the source-generic page loop with a scripted source and return
    /// the result. Uses a real engine, commit pipeline, and done-ledger
    /// so the first page can complete successfully before the second call
    /// triggers a suffix-protocol violation.
    fn run_suffix_protocol_test(
        pages: Vec<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
    ) -> Result<(OrderedSourceAssignmentOutcome, u64), ScanRuntimeError> {
        let (source, fill_page_calls) = MultiStepScriptedSource::new(pages);
        let cancel = CancellationToken::new();
        run_suffix_protocol_test_core(source, cancel, fill_page_calls)
    }

    /// Core pipeline setup for suffix-protocol tests, accepting a
    /// pre-configured source and externally-provided cancellation token.
    fn run_suffix_protocol_test_core(
        mut source: MultiStepScriptedSource,
        cancel: CancellationToken,
        fill_page_calls: Arc<AtomicU64>,
    ) -> Result<(OrderedSourceAssignmentOutcome, u64), ScanRuntimeError> {
        let dir = tempdir().expect("tempdir");
        let mut coordinator =
            setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/suffix"));
        let lease = claim_lease(&mut coordinator, &identity);

        let done_ledger = InMemoryDoneLedger::new();
        let scan_config = lease
            .scan_config()
            .clone()
            .with_workers(1)
            .with_persist_findings(true);

        let engine = build_runtime_engine(
            scan_config.rules_file.as_deref(),
            &scan_config.transform_filter,
            scan_config.decode_depth,
            scan_config.anchor_mode,
        )
        .expect("engine");

        let pipeline = CommitPipeline::start(
            InMemoryFindingsSink::new(),
            done_ledger.clone(),
            CommitPipelineConfig {
                execution_queue_capacity: 64,
                outcome_queue_capacity: 64,
            },
            cancel.clone(),
        )
        .expect("pipeline");

        let recorder = Arc::new(Recorder::default());
        let rule_fingerprint = {
            let engine = Arc::clone(&engine);
            Arc::new(move |rule_id: u32| {
                RuleFingerprint::from_bytes(engine.rule_fingerprint_bytes(rule_id))
            }) as Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>
        };

        let (submitter, drainer) = pipeline.split();
        let commit = ReceiptCommitSink::new(
            recorder,
            Arc::clone(lease.shard_id_arc()),
            lease.write_context(),
            lease.tenant_secret_key(),
            rule_fingerprint,
            submitter,
        );

        let out = NullEventOutput;

        std::thread::scope(|scope| {
            let write_context = lease.write_context();
            let stage_handle = scope.spawn(move || drain_commit_stage(drainer, write_context, 64));

            let result = scan_ordered_source_with_engine(
                &mut source,
                &lease,
                &scan_config,
                &done_ledger,
                engine,
                &out,
                &commit,
                &cancel,
            );
            let submitted = commit.finish().expect("suffix test sink finish");
            let CommitStageDrainResult {
                committed_sequence_nos,
                ..
            } = join_scoped(stage_handle, "suffix test drain")
                .expect("suffix test drain join")
                .expect("suffix test drain");
            wait_for_submitted_commits(submitted, committed_sequence_nos)
                .expect("suffix test durable outcomes");
            result.map(|outcome| (outcome, fill_page_calls.load(Ordering::Relaxed)))
        })
    }

    #[test]
    fn suffix_protocol_accepts_terminal_page_followed_by_exhausted_empty() {
        let terminal_page =
            PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
                .expect("terminal page");

        let (outcome, fill_page_calls) =
            run_suffix_protocol_test(vec![Ok(Some(terminal_page)), Ok(None)])
                .expect("terminal page followed by exhausted-empty should succeed");

        assert_eq!(
            outcome.termination,
            PageLoopTermination::ExhaustedEmptyConfirmed
        );
        assert_eq!(outcome.report.items_scanned, 1);
        assert_eq!(
            fill_page_calls, 2,
            "suffix protocol must perform a second fill_page call to confirm exhausted-empty"
        );
    }

    #[test]
    fn suffix_protocol_rejects_page_after_terminal_page() {
        let terminal_page =
            PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
                .expect("terminal page");
        let follow_up_page = PageBuf::try_new(
            vec![suffix_test_item(b"b.txt", 20)],
            PageState::HasMore {
                cursor: Cursor::with_last_key(item_key("b.txt")),
            },
        )
        .expect("follow-up page");

        let err = run_suffix_protocol_test(vec![Ok(Some(terminal_page)), Ok(Some(follow_up_page))])
            .expect_err("page after terminal should be rejected");

        assert!(
            err.to_string()
                .contains("non-empty page after a terminal non-empty page"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn suffix_protocol_rejects_second_terminal_page() {
        let first = PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
            .expect("first terminal page");
        let second = PageBuf::try_new(vec![suffix_test_item(b"b.txt", 20)], PageState::Complete)
            .expect("second terminal page");

        let err = run_suffix_protocol_test(vec![Ok(Some(first)), Ok(Some(second))])
            .expect_err("second terminal page should be rejected");

        assert!(
            err.to_string()
                .contains("non-empty page after a terminal non-empty page"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn suffix_protocol_preserves_progress_on_retryable_stop_after_terminal_page() {
        let terminal_page =
            PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
                .expect("terminal page");

        let (outcome, fill_page_calls) = run_suffix_protocol_test(vec![
            Ok(Some(terminal_page)),
            Err(EnumerateError::rate_limited("simulated rate limit", 100)),
        ])
        .expect("retryable stop after terminal should preserve progress");

        assert!(
            outcome.report.items_scanned >= 1,
            "committed work from the terminal page should be preserved"
        );
        assert_eq!(outcome.termination, PageLoopTermination::Partial);
        assert_eq!(fill_page_calls, 2);
    }

    #[test]
    fn suffix_protocol_rejects_permanent_stop_after_terminal_page() {
        let terminal_page =
            PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
                .expect("terminal page");

        let err = run_suffix_protocol_test(vec![
            Ok(Some(terminal_page)),
            Err(EnumerateError::permanent("simulated permanent failure")),
        ])
        .expect_err("permanent stop after terminal should still be rejected");

        assert!(
            err.to_string()
                .contains("stopped before confirming exhausted-empty suffix"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn suffix_protocol_accepts_immediate_exhausted_empty() {
        let (outcome, _fill_page_calls) = run_suffix_protocol_test(vec![Ok(None)])
            .expect("immediate exhausted-empty should succeed");

        assert_eq!(outcome.report.items_scanned, 0);
    }

    #[test]
    fn suffix_protocol_cancellation_during_exhausted_empty_wait_preserves_progress() {
        let terminal_page =
            PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
                .expect("terminal page");

        let cancel = CancellationToken::new();
        let fill_page_calls = Arc::new(AtomicU64::new(0));
        let source = MultiStepScriptedSource {
            pages: vec![Ok(Some(terminal_page))].into(),
            fill_page_calls: Arc::clone(&fill_page_calls),
            cancel_on_call: Some((0, cancel.clone())),
            call_count: 0,
        };

        // The cancel fires during fill_page call #0, so the inner
        // item-submission loop also sees cancellation and skips commits.
        // The key assertion: the function returns Ok (graceful break in
        // the AwaitingExhaustedEmpty phase), not Err.
        let _outcome = run_suffix_protocol_test_core(source, cancel, fill_page_calls)
            .expect("cancellation during suffix wait should break gracefully, not error");
    }

    #[test]
    fn scan_ordered_source_breaks_on_mid_page_cancellation() {
        let page = PageBuf::try_new(
            vec![
                suffix_test_item(b"a.txt", 10),
                suffix_test_item(b"b.txt", 20),
            ],
            PageState::HasMore {
                cursor: Cursor::with_last_key(item_key("b.txt")),
            },
        )
        .expect("page");

        let cancel = CancellationToken::new();
        // cancel_on_call fires during fill_page call #0 -- after the cancel
        // fires, fill_page still returns the page. The item submission loop
        // then sees cancel.is_cancelled() on its first iteration and breaks
        // with hit_non_terminal = true, so no items are submitted.
        let fill_page_calls = Arc::new(AtomicU64::new(0));
        let source = MultiStepScriptedSource {
            pages: vec![Ok(Some(page))].into(),
            fill_page_calls: Arc::clone(&fill_page_calls),
            cancel_on_call: Some((0, cancel.clone())),
            call_count: 0,
        };

        let (outcome, _) = run_suffix_protocol_test_core(source, cancel, fill_page_calls)
            .expect("mid-page cancellation should break gracefully, not error");

        // The page was acquired and scan-misses were executed, but the item
        // submission loop broke before submitting any items because
        // cancel.is_cancelled() fired.
        assert_eq!(
            outcome.report.items_scanned, 0,
            "no items should be submitted when cancellation fires before item processing"
        );
    }

    #[test]
    fn retryable_stop_on_first_call_returns_error_instead_of_completing_shard() {
        let err = run_suffix_protocol_test(vec![Err(EnumerateError::rate_limited(
            "transient failure",
            100,
        ))])
        .expect_err("retryable stop on first call should propagate error");

        assert!(
            err.to_string().contains("no prior progress"),
            "unexpected error: {err}"
        );
    }
}
