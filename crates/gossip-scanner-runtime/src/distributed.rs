//! Distributed worker runtime for receipt-driven shard execution.
//!
//! This module is the entry point for distributed scanning. It implements a
//! claim-execute-complete loop: the worker claims shards from a
//! [`CoordinationFacade`], executes each shard's filesystem scan, commits
//! findings and done-ledger rows through a bounded commit pipeline, and then
//! completes the shard lease with a receipt-driven checkpoint cursor.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐    claim     ┌────────────────────┐
//! │ Coordinator  │ ──────────>  │  run_worker loop   │
//! │ (CoordFacade)│ <────────── │  (claim/scan/done) │
//! └──────────────┘   complete   └────────┬───────────┘
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
//! 4. **Fail-fast after claim.** Once a shard is claimed, any scan, commit, or
//!    completion error terminates the worker loop. Uncompleted leases expire
//!    via coordination-layer deadlines.
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
use std::fmt;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Error as AnyError, Result, anyhow};
use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{
        CanonicalBytes, FenceEpoch, LogicalTime, ObjectVersionId, OpId, PolicyHash,
        RuleFingerprint, RunId, ShardKey, TenantId, TenantSecretKey, WorkerId, domain_hasher,
        finalize_64,
    },
    persistence::{CheckpointCommitReceipt, DoneLedger, FindingsSink, WriteContext},
};
use gossip_coordination::{
    AcquireResultView, AcquireScratch, ClaimError, CoordinationFacade, Lease, OpKind,
};
use gossip_frontier::decode_connector_extra;
use scanner_scheduler::store::FsFindingRecord;

use crate::{
    AssignmentOutcome, CancellationToken, FsScanConfig, ScanBudgets, ScanReport, ScanRuntimeError,
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

/// Lease payload consumed by the distributed runtime.
///
/// One lease corresponds to one shard from the coordination layer. It carries
/// everything needed to scan and commit that shard without additional lookups:
///
/// - **`shard_id`** — string label for telemetry routing.
/// - **`lease`** — authoritative coordination lease used for terminal completion.
/// - **`range_start`** — inclusive lower bound of the shard's key range, used as
///   the fallback cursor when no items are committed.
/// - **`scan_config`** — filesystem scan configuration for this shard, derived
///   from the worker template with optional shard-level path overrides.
/// - **`write_context`** — numeric shard identity plus fencing epoch for all
///   persistence writes.
/// - **`tenant_secret_key`** — key material for secret-hash derivation.
///
/// The coordination lease and range start are kept together so that
/// shard completion can finalize the lease without a side-map.
#[derive(Clone, Debug)]
pub struct ShardLease {
    /// String shard label used for routing recorder events.
    shard_id: Arc<str>,
    /// Authoritative coordination-layer lease used for terminal completion.
    lease: Lease,
    /// Inclusive lower bound of the shard's key range.
    range_start: Vec<u8>,
    /// Filesystem scan configuration for this shard.
    scan_config: FsScanConfig,
    /// Shared routing and fencing metadata for all writes emitted under the
    /// lease.
    write_context: WriteContext,
    /// Tenant secret key used for secret-hash derivation.
    tenant_secret_key: TenantSecretKey,
}

impl ShardLease {
    /// Construct one concrete filesystem shard lease.
    pub fn new(
        shard_id: Arc<str>,
        lease: Lease,
        range_start: Vec<u8>,
        scan_config: FsScanConfig,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
    ) -> Self {
        Self {
            shard_id,
            lease,
            range_start,
            scan_config,
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

    /// Inclusive lower bound of the shard's key range.
    #[inline]
    #[must_use]
    pub fn range_start(&self) -> &[u8] {
        &self.range_start
    }

    /// Filesystem scan configuration for this shard.
    #[inline]
    #[must_use]
    pub fn scan_config(&self) -> &FsScanConfig {
        &self.scan_config
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

/// Layered error from the distributed runtime.
///
/// Classifies failures by origin so callers can distinguish coordinator
/// connectivity issues from local scan crashes from durability pipeline
/// stalls. The variant determines whether the error is retryable (e.g.,
/// coordinator transient failures) or terminal (e.g., scan panics).
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

/// Compatibility adapter that bridges scan-loop `CommitSink` callbacks into the
/// receipt-driven commit pipeline.
///
/// # Problem
///
/// The scan scheduler emits compact `ItemMeta` + `FindingRecord` batches via
/// the `CommitSink` trait. The downstream commit pipeline expects richer
/// `QueuedCommit` work items containing full persistence translations
/// (findings, occurrences, observations, done-ledger rows). This adapter
/// reconstructs those deterministic translations in `finish_item` so
/// ordered-content execution can produce durable receipts without changing
/// the scheduler callback surface.
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
/// Scan failures are surfaced before durability failures because a broken scan
/// often cascades into downstream drain errors. Returning the runtime error
/// first gives operators the closest cause.
fn resolve_filesystem_lease_results(
    outcome: Result<AssignmentOutcome, ScanRuntimeError>,
    submitted: Result<Vec<u64>>,
    stage_result: anyhow::Result<anyhow::Result<CommitStageDrainResult>>,
) -> Result<(AssignmentOutcome, Vec<u64>, CommitStageDrainResult), DistributedRuntimeError> {
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
/// sequence-number cross-check. If external cancellation were introduced,
/// callers would need to distinguish cancellation-induced outcome gaps from
/// genuine durability failures.
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

/// Build a filesystem scan config by overlaying shard metadata onto a template.
///
/// If the shard's `connector_extra` field contains a non-empty UTF-8 path,
/// that path overrides the template's `path` field. Otherwise the template
/// path is used as-is.
fn scan_config_from_spec(
    spec: gossip_coordination::ShardSpecRef<'_>,
    scan_template: &FsScanConfig,
) -> Result<FsScanConfig> {
    let mut scan_config = scan_template.clone();
    let connector_extra = decode_connector_extra(spec)
        .map_err(|err| anyhow!("failed to decode shard metadata envelope: {err}"))?;

    if !connector_extra.is_empty() {
        let path = std::str::from_utf8(connector_extra)
            .map_err(|err| anyhow!("filesystem shard metadata path is not valid UTF-8: {err}"))?;
        scan_config.path = PathBuf::from(path);
    }

    Ok(scan_config)
}

/// Convert an acquired coordination lease into the concrete runtime payload.
///
/// Constructs a [`WriteContext`] from the lease's fencing fields and the
/// worker's policy hash, then decodes the shard spec's `connector_extra`
/// to derive the filesystem scan path.
fn build_lease_from_acquire(
    acquired: AcquireResultView<'_>,
    identity: &WorkerIdentity,
) -> Result<ShardLease> {
    let spec = acquired.snapshot.spec();
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
        spec.key_range_start().to_vec(),
        scan_config_from_spec(spec, &identity.scan_template)?,
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
                std::thread::sleep(claim_retry_delay(now, earliest_deadline));
            }
            Err(ClaimError::Throttled { retry_after }) => {
                std::thread::sleep(claim_retry_delay(now, Some(retry_after)));
            }
            Err(error) => {
                return Err(DistributedRuntimeError::Coordinator(AnyError::new(error)));
            }
        }
    }
}

/// Complete a claimed shard directly against the coordination backend.
///
/// The final cursor is chosen as:
/// - The receipt-driven `checkpoint` cursor when items were committed.
/// - The shard's `range_start` when the shard produced zero items but has
///   a non-empty range (ensures forward progress on re-scan).
/// - A synthetic sentinel key ([`EMPTY_RANGE_SENTINEL_KEY`]) when the shard
///   has no range start. In practice this branch is unreachable because the
///   coordination layer rejects unbounded shards at registration time, but
///   the guard exists to prevent a `CursorUpdate::new` panic on empty input
///   (and `CursorUpdate::initial()` would fail validation).
///
/// Completion uses a deterministic [`OpId`] so replayed calls are idempotent.
/// If the coordination backend reports the completion was already applied
/// (idempotent replay), the function logs an info message but succeeds.
fn complete_shard<C>(
    coordinator: &mut C,
    identity: &WorkerIdentity,
    lease: &ShardLease,
    checkpoint: Option<&Cursor>,
) -> Result<(), DistributedRuntimeError>
where
    C: CoordinationFacade,
{
    assert_eq!(lease.lease().tenant(), identity.tenant);

    let final_cursor = match checkpoint {
        Some(cursor) => cursor.as_update(),
        None if lease.range_start().is_empty() => {
            gossip_coordination::CursorUpdate::new(EMPTY_RANGE_SENTINEL_KEY)
        }
        None => gossip_coordination::CursorUpdate::new(lease.range_start()),
    };
    let op_id = deterministic_op_id(
        lease.lease().shard_key(),
        lease.lease().fence(),
        OpKind::Complete,
    );
    let outcome = coordinator
        .complete(
            wall_clock_now(),
            identity.tenant,
            &lease.lease(),
            &final_cursor,
            op_id,
        )
        .map_err(|error| DistributedRuntimeError::Coordinator(AnyError::new(error)))?;

    if !outcome.is_executed() {
        tracing::info!(
            shard_id = %lease.shard_id(),
            "completion was an idempotent replay",
        );
    }

    Ok(())
}

/// Execute one filesystem lease under the receipt-driven durability model.
///
/// This is the per-shard work function called by [`run_worker`]. It
/// orchestrates the full scan-commit-checkpoint pipeline for one shard:
///
/// 1. **Setup**: validates budgets, builds the scan engine, creates the
///    commit pipeline and `ReceiptCommitSink`.
/// 2. **Concurrent execution**: spawns a scoped thread to drain the commit
///    pipeline's outcome stream while the main thread runs the filesystem
///    scan through `scan_fs_with_prebuilt_engine`.
/// 3. **Post-scan verification**: checks that every submitted sequence
///    number produced exactly one durable outcome (via
///    [`wait_for_submitted_commits`]).
/// 4. **Checkpoint**: prepares and acknowledges the receipt-driven
///    checkpoint prefix through [`PrefixCheckpointAggregator`].
///
/// Returns `(ScanReport, None)` when the shard produced zero committed
/// items (empty directory or all-clean scan). Returns
/// `(ScanReport, Some(cursor))` when at least one item was committed.
///
/// The caller owns the coordination-layer completion step (calling
/// [`complete_shard`] with the returned cursor).
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
) -> Result<(ScanReport, Option<Cursor>), DistributedRuntimeError>
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

    let (outcome, submitted, stage_result) =
        resolve_filesystem_lease_results(outcome, submitted, stage_result)?;
    let CommitStageDrainResult {
        mut aggregator,
        committed_sequence_nos,
    } = stage_result;
    let committed_units = committed_sequence_nos.len() as u64;

    if committed_units == 0 {
        return Ok((outcome.report, None));
    }

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

    Ok((outcome.report, Some(checkpoint_cursor)))
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
/// 3. **Completes** the shard lease against the coordinator, advancing the
///    coordination cursor to the receipt-derived checkpoint position.
/// 4. **Repeats** until no shards remain (returns `Ok(report)`) or an error
///    occurs (returns `Err`).
///
/// # Fail-fast semantics
///
/// The loop terminates on the first claim, scan, or completion error.
/// Uncompleted leases are not explicitly released; the coordination backend
/// reclaims them when their deadlines expire.
///
/// # Errors
///
/// - [`DistributedRuntimeError::Coordinator`] — shard claiming, progress
///   lookup, or completion failed.
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

        let (scan_report, checkpoint) = match run_filesystem_lease(
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

        if let Err(error) = complete_shard(coordinator, &identity, &lease, checkpoint.as_ref()) {
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
        connector::{Cursor, ItemKey},
        coordination::ShardSpec,
        identity::{
            FenceEpoch, OpId, PolicyHash, RuleFingerprint, RunId, ShardId, StableItemId, TenantId,
            TenantSecretKey, WorkerId, derive_rule_fingerprint,
        },
        persistence::{DoneLedgerStatus, WriteContext},
    };
    use gossip_coordination::{
        AcquireScratch, CoordinationBackend, CursorSemantics, CursorUpdate as CoordCursorUpdate,
        InMemoryCoordinator as CoordinationInMemoryCoordinator, InitialShardInput, RunConfig,
        RunManagement, ShardClaiming, ShardFilter, ShardStatus,
    };
    use gossip_frontier::{ShardSpecScratch, range_shard_ref};
    use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
    use tempfile::tempdir;

    use crate::{
        CancellationToken, OwnedCoreEvent,
        commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput},
        commit_sink::{FindingRecord, FindingsBatch, ItemMeta},
        coordination_sink::{CommitProgressRecord, StoredGitEvent},
    };

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

    fn setup_coordinator(
        paths: &[&Path],
        lease_duration_ms: u64,
    ) -> CoordinationInMemoryCoordinator {
        let connector_extra: Vec<Vec<u8>> = paths
            .iter()
            .map(|path| {
                path.to_str()
                    .expect("test paths must be valid UTF-8")
                    .as_bytes()
                    .to_vec()
            })
            .collect();
        setup_coordinator_with_connector_extra(&connector_extra, lease_duration_ms)
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
                let connector_extra = path
                    .to_str()
                    .expect("test paths must be valid UTF-8")
                    .as_bytes();
                let spec_ref = range_shard_ref(start, end, connector_extra, &mut scratch)
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

    #[test]
    fn shard_lease_preserves_claimed_coordination_metadata() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator(&[dir.path()], 30_000);
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
            Ok(AssignmentOutcome {
                report: ScanReport::default(),
                checkpoint_hint: None,
                debug_output: None,
            }),
            Ok(Vec::new()),
            Ok(Err(stage_error)),
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
            Ok(AssignmentOutcome {
                report: ScanReport::default(),
                checkpoint_hint: None,
                debug_output: None,
            }),
            Err(submitted_error),
            // stage_result is never reached because submitted fails first.
            Err(anyhow!("unused")),
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
            Ok(AssignmentOutcome {
                report: ScanReport::default(),
                checkpoint_hint: None,
                debug_output: None,
            }),
            Ok(Vec::new()),
            Err(panic_error),
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
    fn build_lease_from_acquire_uses_metadata_path_override() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator(&[dir.path()], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        assert_eq!(lease.shard_id(), "ShardId(1)");
        assert_eq!(lease.scan_config().path, dir.path());
        assert_eq!(lease.write_context().tenant_id(), tenant());
        assert_eq!(lease.write_context().run_id(), run());
        assert_eq!(lease.write_context().shard_id(), ShardId::from_raw(1));
        assert_eq!(lease.write_context().policy_hash(), policy_hash());
        assert_eq!(lease.write_context().fence_epoch(), FenceEpoch::from_raw(2));
        assert_eq!(lease.range_start(), &[0u8]);
    }

    #[test]
    fn build_lease_from_acquire_falls_back_to_template_path_when_metadata_empty() {
        let mut coordinator = setup_coordinator_with_connector_extra(&[Vec::new()], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        assert_eq!(lease.scan_config().path, Path::new("/fallback"));
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
    fn complete_shard_without_checkpoint_uses_range_start_under_completed_semantics() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator(&[dir.path()], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        complete_shard(&mut coordinator, &identity, &lease, None)
            .expect("zero-finding shard completion must succeed under Completed semantics");

        let progress = run_progress(&coordinator);
        assert_eq!(progress.active(), 0);
        assert_eq!(progress.done(), 1);

        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status(), ShardStatus::Done);
        assert_eq!(summaries[0].last_key(), Some(&[0u8][..]));
    }

    #[test]
    fn complete_shard_with_checkpoint_uses_receipt_cursor_under_completed_semantics() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"a", b"\xFF")], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let checkpoint = Cursor::with_last_key(item_key("secret.txt"));

        complete_shard(&mut coordinator, &identity, &lease, Some(&checkpoint))
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
        let (report, checkpoint) = run_filesystem_lease(
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
        let checkpoint = checkpoint.expect("non-empty shard should checkpoint");
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

        complete_shard(&mut coordinator, &identity, &lease, Some(&checkpoint))
            .expect("complete shard");
        let summaries = shard_summaries(&coordinator);
        assert_eq!(summaries[0].status(), ShardStatus::Done);
        assert_eq!(
            summaries[0].last_key(),
            checkpoint.last_key().map(|key| key.as_bytes())
        );
    }

    #[test]
    fn run_filesystem_lease_zero_item_shard_returns_no_checkpoint() {
        let dir = tempdir().expect("tempdir");
        let mut coordinator = setup_coordinator(&[dir.path()], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let done_ledger = InMemoryDoneLedger::new();
        let persistence =
            DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

        let (report, checkpoint) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("empty filesystem shard should succeed");

        assert_eq!(report.items_scanned, 0);
        assert!(checkpoint.is_none());
        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty()
        );
    }

    #[test]
    fn run_filesystem_lease_clean_only_shard_returns_no_checkpoint() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("readme.txt"), clean_fixture()).expect("write clean fixture");

        let mut coordinator = setup_coordinator(&[dir.path()], 30_000);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

        let (report, checkpoint) = run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            DistributedRuntimeConfig::default(),
        )
        .expect("clean-only filesystem shard should succeed");

        assert_eq!(report.items_scanned, 1);
        assert!(checkpoint.is_none());
        assert!(
            findings_sink
                .observations_snapshot()
                .expect("observations snapshot")
                .is_empty()
        );
        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot")
                .is_empty()
        );
    }

    #[test]
    fn run_filesystem_lease_commit_failure_prevents_completion() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let mut coordinator = setup_coordinator(&[dir.path()], 30_000);
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
    fn build_lease_from_acquire_rejects_non_utf8_connector_extra() {
        let mut coordinator = setup_coordinator_with_connector_extra(&[vec![0xFF, 0xFE]], 30_000);
        let mut scratch = AcquireScratch::new();
        let acquired = coordinator
            .claim_next_available(wall_clock_now(), tenant(), run(), worker(1), &mut scratch)
            .expect("claim next available");
        let identity = worker_identity(Path::new("/fallback"));

        let err = build_lease_from_acquire(acquired, &identity)
            .expect_err("non-UTF-8 connector_extra must be rejected");
        assert!(
            err.to_string().contains("not valid UTF-8"),
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

        let (report, checkpoint) = run_filesystem_lease(
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
        assert!(
            checkpoint.is_some(),
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
            1,
            "only the finding-bearing file produces a done-ledger row"
        );
    }

    #[test]
    fn complete_shard_fails_when_lease_is_fenced() {
        let dir = tempdir().expect("tempdir");

        // Use a very short TTL so our lease expires quickly.
        let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
        let identity = worker_identity(Path::new("/fallback"));
        let lease = claim_lease(&mut coordinator, &identity);

        // Wait for our lease to expire, then let a rival claim the same
        // shard. This bumps the fence epoch, making our lease stale.
        std::thread::sleep(Duration::from_millis(100));
        let _rival_lease = claim_coordination_lease(&mut coordinator, worker(99));

        let err = complete_shard(&mut coordinator, &identity, &lease, None)
            .expect_err("completion with stale fence should fail");
        assert!(
            matches!(err, DistributedRuntimeError::Coordinator(_)),
            "expected Coordinator error variant, got: {err:?}"
        );
    }
}
