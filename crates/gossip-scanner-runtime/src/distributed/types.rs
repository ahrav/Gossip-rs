//! Distributed runtime types, errors, and shared definitions.
//!
//! Contains all public and module-internal data structures used across the
//! distributed worker subsystem: worker identity bundles, shard lease
//! payloads, coordination error types, and small utilities.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Error as AnyError;
use gossip_contracts::{
    connector::{Budgets, Cursor},
    coordination::{RestoredShardState, ShardSpec},
    identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, TenantId, TenantSecretKey, WorkerId},
    persistence::WriteContext,
};
use gossip_coordination::{CursorSemantics, Lease};
use gossip_orchestrator::{FilesystemSourceMode, GitShardPayload};

use crate::{
    FsScanConfig, GitScanConfig, ScanBudgets, ScanReport, ScanRuntimeError,
    coordination_sink::CoordinationEventRecorder,
};

// ---------------------------------------------------------------------------
// Worker identity bundles
// ---------------------------------------------------------------------------

/// Immutable worker identity threaded through shard claiming and completion.
///
/// Bundles all tenant-scoped, run-scoped, and worker-scoped state that
/// [`super::run_worker`] needs to claim shards and complete them against a
/// [`gossip_coordination::CoordinationFacade`]. Each field is constant for
/// the lifetime of one worker invocation; per-shard variability (scan path,
/// fencing epoch) lives on [`ShardLease`] instead.
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

/// Immutable worker identity for distributed Git repo-frontier execution.
///
/// Bundles tenant/run/worker coordination identity, a Git scan template, and
/// a shared recorder so each claimed repo-frontier shard can compose discovery,
/// mirror preparation, and durable Git finalize state.
#[derive(Clone)]
pub struct GitWorkerIdentity {
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
    /// Base Git scan configuration cloned per shard and overlaid with payload
    /// settings plus the prepared mirror path.
    pub scan_template: GitScanConfig,
    /// Shared recorder used by event telemetry.
    pub recorder: Arc<dyn CoordinationEventRecorder>,
}

impl GitWorkerIdentity {
    /// Construct one distributed Git worker identity bundle.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        policy_hash: PolicyHash,
        tenant_secret_key: TenantSecretKey,
        scan_template: GitScanConfig,
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

// ---------------------------------------------------------------------------
// Hydrated filesystem source
// ---------------------------------------------------------------------------

/// Hydrated filesystem scan config bundled with the explicit source mode decoded from shard metadata.
#[derive(Clone, Debug)]
pub(super) struct HydratedFilesystemSource {
    scan_config: FsScanConfig,
    source_mode: FilesystemSourceMode,
}

impl HydratedFilesystemSource {
    pub(super) fn new(scan_config: FsScanConfig, source_mode: FilesystemSourceMode) -> Self {
        Self {
            scan_config,
            source_mode,
        }
    }

    pub(super) fn scan_config(&self) -> &FsScanConfig {
        &self.scan_config
    }

    pub(super) fn source_mode(&self) -> FilesystemSourceMode {
        self.source_mode
    }
}

// ---------------------------------------------------------------------------
// Shard lease payloads
// ---------------------------------------------------------------------------

/// Lease payload consumed by the distributed runtime.
///
/// One lease corresponds to one shard from the coordination layer. Key fields
/// include:
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
/// - **`claim_wall_clock`** / **`claim_instant`** — wall-clock and monotonic
///   timestamps captured at claim time, anchoring the lease-deadline watchdog.
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
    pub(super) filesystem_source: HydratedFilesystemSource,
    /// Shared routing and fencing metadata for all writes emitted under the
    /// lease.
    write_context: WriteContext,
    /// Tenant secret key used for secret-hash derivation.
    tenant_secret_key: TenantSecretKey,
    /// Wall-clock timestamp captured at claim time, used to anchor the
    /// lease deadline to the monotonic clock without NTP skew.
    claim_wall_clock: LogicalTime,
    /// Monotonic instant captured alongside `claim_wall_clock`.
    claim_instant: Instant,
}

impl ShardLease {
    /// Construct one concrete filesystem shard lease.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        shard_id: Arc<str>,
        lease: Lease,
        state: RestoredShardState,
        filesystem_source: HydratedFilesystemSource,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
        claim_wall_clock: LogicalTime,
        claim_instant: Instant,
    ) -> Self {
        Self {
            shard_id,
            lease,
            state,
            filesystem_source,
            write_context,
            tenant_secret_key,
            claim_wall_clock,
            claim_instant,
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

    /// Wall-clock timestamp captured at claim time, anchoring the monotonic
    /// deadline calculation to the coordinator's view of time.
    #[inline]
    #[must_use]
    pub(super) fn claim_wall_clock(&self) -> LogicalTime {
        self.claim_wall_clock
    }

    /// Monotonic instant captured alongside `claim_wall_clock`.
    #[inline]
    #[must_use]
    pub(super) fn claim_instant(&self) -> Instant {
        self.claim_instant
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

/// Lease payload consumed by the distributed Git repo-frontier runtime.
///
/// One lease corresponds to one repo-frontier shard from the coordination
/// layer. The shard metadata decodes into a single [`GitShardPayload`] whose
/// repo target and scan settings define the worker-side Git execution path.
#[derive(Clone, Debug)]
pub struct GitShardLease {
    /// String shard label used for telemetry routing and log correlation.
    shard_id: Arc<str>,
    /// Authoritative coordination-layer lease used for terminal completion
    /// and shard advancement.
    lease: Lease,
    /// Shard bounds, resume cursor, and cursor semantics restored from
    /// the acquire/restore coordination payload.
    state: RestoredShardState,
    /// Decoded Git shard payload carrying the repo target, selection policy,
    /// and execution limits for this shard.
    payload: GitShardPayload,
    /// Shared routing and fencing metadata for all writes emitted under
    /// this lease.
    write_context: WriteContext,
    /// Tenant secret key used for secret-hash derivation in persistence
    /// identity computation.
    tenant_secret_key: TenantSecretKey,
    /// Wall-clock timestamp captured at claim time, anchoring the monotonic
    /// deadline calculation to the coordinator's view of time.
    claim_wall_clock: LogicalTime,
    /// Monotonic instant captured alongside `claim_wall_clock` so elapsed
    /// time can be measured without NTP skew.
    claim_instant: Instant,
}

impl GitShardLease {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        shard_id: Arc<str>,
        lease: Lease,
        state: RestoredShardState,
        payload: GitShardPayload,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
        claim_wall_clock: LogicalTime,
        claim_instant: Instant,
    ) -> Self {
        Self {
            shard_id,
            lease,
            state,
            payload,
            write_context,
            tenant_secret_key,
            claim_wall_clock,
            claim_instant,
        }
    }

    /// String shard label used for telemetry routing and log correlation.
    #[inline]
    #[must_use]
    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    /// Arc-wrapped shard label for zero-allocation sharing across subsystems.
    #[inline]
    #[must_use]
    pub fn shard_id_arc(&self) -> &Arc<str> {
        &self.shard_id
    }

    /// Coordination-layer lease used for shard advancement and terminal
    /// completion.
    #[inline]
    pub fn lease(&self) -> Lease {
        self.lease
    }

    /// Restored coordination state (shard spec, resume cursor, cursor
    /// semantics) from the acquire/restore payload.
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

    /// Coordination cursor semantics governing how checkpoint cursors are
    /// interpreted on re-claim.
    #[inline]
    #[must_use]
    pub fn cursor_semantics(&self) -> CursorSemantics {
        self.state.cursor_semantics()
    }

    /// Decoded Git shard payload carrying the repo target, selection policy,
    /// and execution limits for this shard.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &GitShardPayload {
        &self.payload
    }

    /// Shared routing and fencing metadata for all writes emitted under
    /// this lease.
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

    /// Wall-clock timestamp captured at claim time, anchoring the monotonic
    /// deadline calculation to the coordinator's view of time.
    #[inline]
    #[must_use]
    pub(super) fn claim_wall_clock(&self) -> LogicalTime {
        self.claim_wall_clock
    }

    /// Monotonic instant captured alongside `claim_wall_clock`.
    #[inline]
    #[must_use]
    pub(super) fn claim_instant(&self) -> Instant {
        self.claim_instant
    }
}

// ---------------------------------------------------------------------------
// LeaseView trait — shared read-only view over both lease types
// ---------------------------------------------------------------------------

/// Common read-only view over both filesystem and Git shard leases.
///
/// Abstracts the shared subset of [`ShardLease`] and [`GitShardLease`] so
/// generic helpers (e.g., `advance_shard`) can operate on either
/// lease family without monomorphizing the entire worker loop.
pub(super) trait LeaseView {
    /// String shard label for telemetry and log correlation.
    fn shard_id(&self) -> &str;
    /// Coordination-layer lease for shard advancement.
    fn lease(&self) -> Lease;
    /// Restored shard state (spec, resume cursor, cursor semantics).
    fn restored_state(&self) -> &RestoredShardState;
    /// Authoritative resume cursor from the acquire/restore payload.
    fn resume_cursor(&self) -> &Cursor;
    /// Inclusive lower bound of the shard's key range.
    fn range_start(&self) -> &[u8];
}

impl LeaseView for ShardLease {
    fn shard_id(&self) -> &str {
        self.shard_id()
    }

    fn lease(&self) -> Lease {
        self.lease()
    }

    fn restored_state(&self) -> &RestoredShardState {
        self.restored_state()
    }

    fn resume_cursor(&self) -> &Cursor {
        self.resume_cursor()
    }

    fn range_start(&self) -> &[u8] {
        self.range_start()
    }
}

impl LeaseView for GitShardLease {
    fn shard_id(&self) -> &str {
        self.shard_id()
    }

    fn lease(&self) -> Lease {
        self.lease()
    }

    fn restored_state(&self) -> &RestoredShardState {
        self.restored_state()
    }

    fn resume_cursor(&self) -> &Cursor {
        self.resume_cursor()
    }

    fn range_start(&self) -> &[u8] {
        self.range_start()
    }
}

// ---------------------------------------------------------------------------
// Persistence and configuration
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Reports and metrics
// ---------------------------------------------------------------------------

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
    /// Aggregate claim latency in milliseconds across the invocation.
    /// Populated only by Git repo-frontier worker runs; zero for filesystem runs.
    pub total_claim_ms: u64,
    /// Aggregate Git mirror-sync latency in milliseconds.
    /// Populated only by Git repo-frontier worker runs; zero for filesystem runs.
    pub total_mirror_sync_ms: u64,
    /// Aggregate Git execution latency in milliseconds.
    /// Populated only by Git repo-frontier worker runs; zero for filesystem runs.
    pub total_scan_ms: u64,
    /// Aggregate durable receipt latency in milliseconds.
    /// Populated only by Git repo-frontier worker runs; zero for filesystem runs.
    pub total_durable_receipt_ms: u64,
    /// Aggregate shard-advance latency in milliseconds.
    /// Populated only by Git repo-frontier worker runs; zero for filesystem runs.
    pub total_checkpoint_ms: u64,
}

impl DistributedRunReport {
    /// Assert the structural invariant in debug builds.
    pub(super) fn debug_assert_invariant(&self) {
        debug_assert!(
            self.shards_scanned <= self.leases_seen,
            "report invariant violated: scanned({}) > seen({})",
            self.shards_scanned,
            self.leases_seen,
        );
    }
}

/// Per-lease Git stage timings aggregated into [`DistributedRunReport`].
///
/// Covers only the stages measured inside `run_git_repo_lease`. Claim and
/// checkpoint timings are measured by the outer worker loop and added to
/// the report directly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct GitRunStageMetrics {
    pub(super) mirror_sync_ms: u64,
    pub(super) scan_ms: u64,
    pub(super) durable_receipt_ms: u64,
}

impl GitRunStageMetrics {
    /// Folds these per-lease timings into the aggregate report.
    pub(super) fn accumulate_into(self, report: &mut DistributedRunReport) {
        report.total_mirror_sync_ms = report
            .total_mirror_sync_ms
            .saturating_add(self.mirror_sync_ms);
        report.total_scan_ms = report.total_scan_ms.saturating_add(self.scan_ms);
        report.total_durable_receipt_ms = report
            .total_durable_receipt_ms
            .saturating_add(self.durable_receipt_ms);
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Explicit reason the worker can no longer trust a claimed lease.
///
/// `DeadlineElapsed` is raised by local monotonic deadline checks (the
/// watchdog thread, arming validation, and phase-boundary guards).
/// `AdvanceStaleFence` and `AdvanceLeaseExpired` are raised by the
/// coordinator during shard advancement after local durability has completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
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
    /// The coordinator rejected shard advancement because another worker
    /// already owns a newer fence epoch.
    #[error(
        "shard advance rejected by a stale fence (presented {presented:?}, current {current:?})"
    )]
    AdvanceStaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// The coordinator rejected shard advancement because the lease already
    /// expired.
    #[error("shard advance rejected after lease expiry (deadline {deadline:?}, now {now:?})")]
    AdvanceLeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
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

// ---------------------------------------------------------------------------
// Page-loop and shard-completion enums
// ---------------------------------------------------------------------------

/// Explicit shard-advance outcome from the ordered-content path.
///
/// `Complete` means the scan observed the exhausted-empty suffix required for
/// terminal completion and may transition the shard to `Done` using the
/// authoritative receipt-backed checkpoint cursor. `Checkpoint` means the scan
/// stopped early after a checkpointable cursor was available, so the worker
/// must preserve progress without terminally completing the shard.
/// `ExhaustedEmpty` means the scan observed exhausted-empty without producing a
/// new receipt-backed checkpoint in this claim. Completion preserves the
/// restored resume cursor when the shard already had prior progress and falls
/// back to a range-safe cursor only for truly initial empty shards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ShardCompletionOutcome {
    ExhaustedEmpty,
    Checkpoint { checkpoint: Cursor },
    Complete { checkpoint: Cursor },
}

/// Phase of the ordered-content page loop.
///
/// After processing a terminal non-empty page (`PageState::Complete`),
/// the loop transitions to `AwaitingExhaustedEmpty` and expects one
/// more `ExhaustedEmpty` outcome before the shard is fully enumerated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PageLoopPhase {
    /// Normal paging: the loop requests successive content pages from the
    /// source until one returns `PageState::Complete`.
    Paging,
    /// A terminal non-empty page has been observed. The loop expects one
    /// more `ExhaustedEmpty` response to confirm the source has no
    /// remaining items before marking the shard fully enumerated.
    AwaitingExhaustedEmpty,
}

/// How the ordered-content page loop terminated.
///
/// Determines whether the downstream shard-advance step can mark the shard
/// as `Done` (exhausted-empty confirmed) or must preserve progress with a
/// non-terminal checkpoint (partial).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PageLoopTermination {
    /// The source confirmed that no items remain after the terminal page.
    /// The shard can be terminally completed.
    ExhaustedEmptyConfirmed,
    /// The loop exited before observing the exhausted-empty suffix — due to
    /// cancellation, a budget-deferred item, a retryable stop, or a
    /// retryable item outcome. Progress is preserved via a non-terminal
    /// checkpoint so the next claim resumes where this one stopped.
    Partial,
}

/// Accumulated result from scanning all pages of one ordered-content shard.
///
/// Produced by `scan_ordered_source_with_engine` and consumed by the
/// enclosing `run_filesystem_lease` to select the shard-advance action.
#[derive(Clone, Debug)]
pub(super) struct OrderedSourceAssignmentOutcome {
    /// Aggregate scan metrics (items scanned, bytes, findings, errors)
    /// accumulated across all submitted pages.
    pub(super) report: ScanReport,
    /// Whether the page loop fully enumerated the source or stopped early.
    pub(super) termination: PageLoopTermination,
    /// The cursor to resume from on the next claim. Reflects the last
    /// committed item's key position when the loop stopped early, or the
    /// source's own resume cursor when all pages were processed.
    pub(super) resume_cursor: Cursor,
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

pub(super) fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

pub(super) fn elapsed_ms(start: Instant) -> u64 {
    duration_ms(start.elapsed())
}

/// Convert the wall clock to [`LogicalTime`] (milliseconds since Unix epoch).
///
/// Delegates to [`crate::epoch_millis_now`] for the raw timestamp.
pub(super) fn wall_clock_now() -> LogicalTime {
    LogicalTime::from_raw(crate::epoch_millis_now())
}
