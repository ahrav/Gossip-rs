//! Full simulation harness for deterministic coordination testing.
//!
//! Drives a [`SimulationBackend`] (defaulting to [`InMemoryCoordinator`]) under
//! configurable fault injection, verifying protocol invariants (S1--S7) at every
//! step. Inspired by FoundationDB's simulation framework and TigerBeetle's VOPR.
//!
//! # Execution model
//!
//! A simulation run consists of three sequential stages:
//!
//! 1. **Zombie scenario** (deterministic preamble): A scripted sequence that
//!    exercises the bookkeeping-cleanup path (B1) by expiring a lease and
//!    re-acquiring on a different worker. Runs unconditionally before random ops.
//! 2. **Safety phase** (`safety_ops` iterations): Weighted random operations
//!    with fault injection. The first [`WARMUP_OPS`] suppress faults to let
//!    workers establish leases before time-jumps can expire them. Verifies that
//!    no invariant is ever violated regardless of operation ordering.
//! 3. **Liveness phase** (`liveness_ops` iterations): Biased toward acquire +
//!    complete, verifying that the system converges to terminal states.
//!
//! Every operation in every phase is followed by a full invariant sweep
//! ([`InvariantChecker::check_all`]). This is the core safety guarantee.
//!
//! # Two entry points
//!
//! - **[`CoordinationSim::run`]**: Canned three-stage execution (zombie preamble +
//!   safety phase + liveness phase) that returns a [`SimReport`]. Suitable for
//!   proptest and regression tests.
//! - **[`CoordinationSim::step`]**: Execute a single [`SimOp`] and check
//!   invariants. Suitable for custom simulation loops that need fine-grained
//!   control over operation sequencing.
//!
//! # Key design decisions
//!
//! - **Forward-only cursors**: [`generate_forward_cursor`](CoordinationSim::generate_forward_cursor)
//!   tracks per-worker cursor progress and only generates cursors that advance.
//!   Without this, random cursors would frequently regress, flooding the run with
//!   expected `CursorRegression` rejections that mask real bugs.
//!
//! - **Stale lease tracking**: When worker B acquires a shard previously held by
//!   worker A, the harness saves A's superseded lease. These stale leases feed
//!   [`SimOp::ZombieCheckpoint`], which bypasses bookkeeping cleanup to exercise
//!   the coordinator's fence-based `StaleFence` rejection path directly.
//!
//! - **Active shard set**: The harness maintains [`active_shard_keys`](CoordinationSim::active_shard_keys)
//!   as a subset of all shard keys, excluding terminal shards. This prevents op
//!   generation from selecting shards that would always be rejected, improving
//!   coverage of meaningful coordinator paths.
//!
//! - **Allocation-free rejections**: [`RejectionKind`] is a `Copy` enum rather
//!   than a `String`, avoiding heap allocation on the hot path where fault-heavy
//!   modes produce many rejections per run.

use std::collections::BTreeMap;

use rand::Rng;

use crate::coordination::Lease;
use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, CheckpointError, CompleteError, IdempotentOutcome, ParkError, RenewError,
    SplitError,
};
use crate::coordination::facade::ClaimError;
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::record::{ParkReason, ShardRecord};
use crate::coordination::session::WorkerSession;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::split::{SplitReplaceChild, SplitReplacePlan, SplitResidualPlan};
use crate::identity::{
    FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
};
use crate::sim::backend::SimulationBackend;

use super::invariants::{InvariantChecker, InvariantViolation};
use super::worker::SimWorker;
use super::{FaultConfig, FaultLevel, SimContext};

// ---------------------------------------------------------------------------
// SimOp
// ---------------------------------------------------------------------------

/// A single operation in the simulation.
///
/// Operations fall into three categories:
///
/// - **Coordinator ops** (`Acquire`, `Renew`, `Checkpoint`, `Complete`, `Park`,
///   `SplitReplace`, `SplitResidual`, `ClaimNext`, `SessionLifecycle`): invoke
///   real coordinator methods through the [`SimulationBackend`] trait.
/// - **Idempotency/conflict ops** (`ReplayCheckpoint`, `ConflictCheckpoint`,
///   `ZombieCheckpoint`): exercise edge cases in the coordinator's op-log and
///   fencing protocol.
/// - **Environmental ops** (`AdvanceTime`, `PauseWorker`, `ResumeWorker`):
///   manipulate simulation state (clock, worker health) without touching the
///   coordinator.
///
/// All variants carry enough context (worker, shard key) for the harness to
/// dispatch to the appropriate executor. The harness generates ops via weighted
/// random selection in [`CoordinationSim::generate_random_op`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SimOp {
    /// Attempt to acquire (or re-acquire) a lease on a shard.
    Acquire { worker: WorkerId, key: ShardKey },
    /// Renew an existing lease to extend its deadline.
    Renew { worker: WorkerId, key: ShardKey },
    /// Checkpoint cursor progress on a held shard.
    Checkpoint { worker: WorkerId, key: ShardKey },
    /// Mark a shard as fully processed (terminal).
    Complete { worker: WorkerId, key: ShardKey },
    /// Park a shard for later retry (terminal).
    Park { worker: WorkerId, key: ShardKey },
    /// Split-replace: parent shard → 2 children covering parent's range (terminal).
    SplitReplace { worker: WorkerId, key: ShardKey },
    /// Split-residual: parent shrinks, residual shard covers remainder (non-terminal).
    SplitResidual { worker: WorkerId, key: ShardKey },
    /// Replay a previous checkpoint with the same OpId + payload (idempotency test).
    ReplayCheckpoint { worker: WorkerId, key: ShardKey },
    /// Replay a previous OpId with a different payload (conflict test).
    ConflictCheckpoint { worker: WorkerId, key: ShardKey },
    /// Attempt a checkpoint using a previously superseded (stale) lease,
    /// bypassing B1 bookkeeping cleanup to exercise the coordinator's
    /// fence-based zombie rejection (`StaleFence`).
    ZombieCheckpoint,
    /// Claim the next available shard for a run without specifying a key.
    /// Exercises the list-then-acquire retry loop in `claim_next_available`.
    ClaimNext { worker: WorkerId },
    /// Advance the logical clock by `ticks`.
    AdvanceTime { ticks: u64 },
    /// Simulate a worker stall (GC pause, network partition).
    PauseWorker { worker: WorkerId },
    /// Resume a previously paused worker.
    ResumeWorker { worker: WorkerId },
    /// Execute a complete WorkerSession lifecycle on a shard:
    /// acquire → checkpoint(1–3x) → complete|park.
    ///
    /// Exercises the ergonomic `WorkerSession` wrapper that the real
    /// orchestrator uses. The session holds `&mut coordinator` exclusively,
    /// so invariant checking happens at the session boundary (after drop),
    /// not between individual session operations.
    SessionLifecycle { worker: WorkerId, key: ShardKey },
}

// ---------------------------------------------------------------------------
// SimEvent
// ---------------------------------------------------------------------------

/// Outcome of executing a [`SimOp`].
///
/// Every execution produces exactly one `SimEvent`. Successful operations carry
/// their result payloads (e.g., the new fence epoch from an acquire); rejected
/// operations carry a [`RejectionKind`] that categorizes the failure without
/// heap allocation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SimEvent {
    /// Lease acquired; `fence` is the new fence epoch for the shard.
    AcquireOk { fence: FenceEpoch },
    /// Lease renewed; `new_deadline` is the extended expiry time.
    RenewOk { new_deadline: LogicalTime },
    /// Cursor checkpoint committed.
    CheckpointOk,
    /// Shard marked done (terminal).
    CompleteOk,
    /// Shard parked (terminal).
    ParkOk,
    /// Parent shard replaced by children (terminal).
    SplitReplaceOk { children: Vec<ShardId> },
    /// Parent shrunk; residual shard created (non-terminal).
    SplitResidualOk { residual: ShardId },
    /// Idempotent replay returned cached result.
    ReplayedOk,
    /// Shard claimed via `claim_next_available` (list-then-acquire loop).
    ClaimOk { shard: ShardId },
    /// No available shards for the run (all leased/terminal).
    ClaimNoneAvailable,
    /// Operation was rejected by the coordinator or skipped due to precondition.
    Rejected { kind: RejectionKind },
    /// Logical clock advanced.
    TimeAdvanced { new_time: LogicalTime },
    /// Worker entered paused state.
    WorkerPaused { worker: WorkerId },
    /// Worker resumed from paused state.
    WorkerResumed { worker: WorkerId },
    /// Operation could not be dispatched (e.g., unknown worker).
    Skipped,
    /// WorkerSession lifecycle completed (acquire → checkpoints → terminal).
    SessionLifecycleOk,
}

/// Categorized rejection reason (no heap allocation).
///
/// Used instead of `String` to avoid hot-path allocation in fault-heavy
/// simulation modes where a large fraction of operations are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectionKind {
    /// Worker does not hold a lease on the target shard.
    NotLeased,
    /// Lease fence epoch is stale (another worker acquired since).
    StaleFence,
    /// Lease has expired.
    LeaseExpired,
    /// Shard is already in a terminal state.
    TerminalState,
    /// Cursor would move backward (monotonicity violation).
    /// Not produced by the built-in harness (forward-cursor generation prevents
    /// it), but available for custom `step()` callers.
    CursorRegression,
    /// Cursor is outside the shard spec range.
    /// Not produced by the built-in harness (cursor generation stays in-bounds),
    /// but available for custom `step()` callers.
    CursorOutOfBounds,
    /// Target worker is paused.
    WorkerPaused,
    /// Worker holds no shards to operate on.
    /// Not produced by the built-in harness (op generation retries instead),
    /// but available for custom `step()` callers.
    NoShardsHeld,
    /// OpId conflict: same OpId with different payload hash.
    OpIdConflict,
    /// Target shard was not found in the coordinator.
    ShardNotFound,
    /// Tenant ID does not match the shard's tenant.
    TenantMismatch,
    /// Shard is already held by another worker with a valid lease.
    AlreadyLeased,
    /// Checkpoint is missing a required key field.
    CheckpointMissingKey,
    /// Split validation failed (bad coverage, bad plan, etc.).
    SplitValidation,
    /// No stale lease available for zombie injection.
    NoStaleLease,
    /// No previous checkpoint to replay.
    NoPriorCheckpoint,
    /// Coordinator returned an error not matching a specific category.
    Other,
}

impl From<AcquireError> for RejectionKind {
    fn from(e: AcquireError) -> Self {
        match e {
            AcquireError::ShardTerminal { .. } => Self::TerminalState,
            AcquireError::ShardNotFound { .. } => Self::ShardNotFound,
            AcquireError::TenantMismatch { .. } => Self::TenantMismatch,
            AcquireError::AlreadyLeased { .. } => Self::AlreadyLeased,
        }
    }
}

impl From<RenewError> for RejectionKind {
    fn from(e: RenewError) -> Self {
        match e {
            RenewError::StaleFence { .. } => Self::StaleFence,
            RenewError::LeaseExpired { .. } => Self::LeaseExpired,
            RenewError::ShardTerminal { .. } => Self::TerminalState,
            RenewError::ShardNotFound { .. } => Self::ShardNotFound,
            RenewError::TenantMismatch { .. } => Self::TenantMismatch,
        }
    }
}

impl From<CheckpointError> for RejectionKind {
    fn from(e: CheckpointError) -> Self {
        match e {
            CheckpointError::StaleFence { .. } => Self::StaleFence,
            CheckpointError::LeaseExpired { .. } => Self::LeaseExpired,
            CheckpointError::ShardTerminal { .. } => Self::TerminalState,
            CheckpointError::OpIdConflict { .. } => Self::OpIdConflict,
            CheckpointError::CursorRegression { .. } => Self::CursorRegression,
            CheckpointError::CursorOutOfBounds(_) => Self::CursorOutOfBounds,
            CheckpointError::ShardNotFound { .. } => Self::ShardNotFound,
            CheckpointError::TenantMismatch { .. } => Self::TenantMismatch,
            CheckpointError::CheckpointMissingKey => Self::CheckpointMissingKey,
        }
    }
}

impl From<CompleteError> for RejectionKind {
    fn from(e: CompleteError) -> Self {
        match e {
            CompleteError::StaleFence { .. } => Self::StaleFence,
            CompleteError::LeaseExpired { .. } => Self::LeaseExpired,
            CompleteError::ShardTerminal { .. } => Self::TerminalState,
            CompleteError::OpIdConflict { .. } => Self::OpIdConflict,
            CompleteError::CursorRegression { .. } => Self::CursorRegression,
            CompleteError::CursorOutOfBounds(_) => Self::CursorOutOfBounds,
            CompleteError::ShardNotFound { .. } => Self::ShardNotFound,
            CompleteError::TenantMismatch { .. } => Self::TenantMismatch,
            CompleteError::CheckpointMissingKey => Self::CheckpointMissingKey,
        }
    }
}

impl From<ParkError> for RejectionKind {
    fn from(e: ParkError) -> Self {
        match e {
            ParkError::StaleFence { .. } => Self::StaleFence,
            ParkError::LeaseExpired { .. } => Self::LeaseExpired,
            ParkError::ShardTerminal { .. } => Self::TerminalState,
            ParkError::OpIdConflict { .. } => Self::OpIdConflict,
            ParkError::ShardNotFound { .. } => Self::ShardNotFound,
            ParkError::TenantMismatch { .. } => Self::TenantMismatch,
        }
    }
}

impl From<SplitError> for RejectionKind {
    fn from(e: SplitError) -> Self {
        match e {
            SplitError::StaleFence { .. } => Self::StaleFence,
            SplitError::LeaseExpired { .. } => Self::LeaseExpired,
            SplitError::ShardTerminal { .. } => Self::TerminalState,
            SplitError::OpIdConflict { .. } => Self::OpIdConflict,
            SplitError::SplitInvalid(_) => Self::SplitValidation,
            SplitError::ShardNotFound { .. } => Self::ShardNotFound,
            SplitError::TenantMismatch { .. } => Self::TenantMismatch,
        }
    }
}

/// Payload-free event discriminant for histogram counting.
///
/// Used by [`SimReport::event_counts`] to summarize operation coverage
/// without carrying per-event payloads. The `Ord` derive enables `BTreeMap`
/// keying for deterministic report output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimEventKind {
    AcquireOk,
    RenewOk,
    CheckpointOk,
    CompleteOk,
    ParkOk,
    SplitReplaceOk,
    SplitResidualOk,
    ReplayedOk,
    ClaimOk,
    ClaimNoneAvailable,
    Rejected,
    TimeAdvanced,
    WorkerPaused,
    WorkerResumed,
    Skipped,
    SessionLifecycleOk,
}

impl SimEvent {
    fn kind(&self) -> SimEventKind {
        match self {
            SimEvent::AcquireOk { .. } => SimEventKind::AcquireOk,
            SimEvent::RenewOk { .. } => SimEventKind::RenewOk,
            SimEvent::CheckpointOk => SimEventKind::CheckpointOk,
            SimEvent::CompleteOk => SimEventKind::CompleteOk,
            SimEvent::ParkOk => SimEventKind::ParkOk,
            SimEvent::SplitReplaceOk { .. } => SimEventKind::SplitReplaceOk,
            SimEvent::SplitResidualOk { .. } => SimEventKind::SplitResidualOk,
            SimEvent::ReplayedOk => SimEventKind::ReplayedOk,
            SimEvent::ClaimOk { .. } => SimEventKind::ClaimOk,
            SimEvent::ClaimNoneAvailable => SimEventKind::ClaimNoneAvailable,
            SimEvent::Rejected { .. } => SimEventKind::Rejected,
            SimEvent::TimeAdvanced { .. } => SimEventKind::TimeAdvanced,
            SimEvent::WorkerPaused { .. } => SimEventKind::WorkerPaused,
            SimEvent::WorkerResumed { .. } => SimEventKind::WorkerResumed,
            SimEvent::Skipped => SimEventKind::Skipped,
            SimEvent::SessionLifecycleOk => SimEventKind::SessionLifecycleOk,
        }
    }
}

// ---------------------------------------------------------------------------
// SimReport
// ---------------------------------------------------------------------------

/// Summary of a simulation run.
///
/// Includes both safety results (invariant violations) and liveness results
/// (convergence to terminal states), plus enough metadata to reproduce the
/// exact run from its seed.
///
/// The typical assertion pattern in tests is:
///
/// ```rust,ignore
/// let report = sim.run(500, 200);
/// assert!(report.violations.is_empty(), "seed {}: {:?}", report.seed, report.violations);
/// assert!(report.converged, "seed {}: not converged", report.seed);
/// ```
#[must_use]
#[derive(Debug)]
pub struct SimReport {
    /// Total operations executed (zombie scenario setup + safety + liveness).
    pub ops_executed: usize,
    /// All invariant violations detected (empty on success).
    pub violations: Vec<InvariantViolation>,
    /// Per-event-kind counters for coverage analysis.
    pub event_counts: BTreeMap<SimEventKind, usize>,
    /// The seed that produced this run (for reproduction).
    pub seed: u64,
    /// Logical time at the end of the simulation.
    pub end_time: LogicalTime,
    /// Whether all shards are in a terminal state at the end of the simulation.
    pub converged: bool,
}

// ---------------------------------------------------------------------------
// CoordinationSim
// ---------------------------------------------------------------------------

/// Default lease duration (in logical ticks) for the simulated coordinator.
///
/// Chosen to be large enough that warmup operations can acquire and checkpoint
/// before expiry, but small enough that moderate time-jumps (50--200 ticks in
/// Stormy mode) can expire leases and create interesting fault scenarios.
const DEFAULT_LEASE_DURATION: u64 = 100;

/// Number of initial operations where faults are suppressed to let the
/// system reach a healthy baseline.
///
/// Without warmup, early time-jumps can expire leases before any worker
/// acquires a shard, causing the entire safety phase to degenerate into
/// rejected-op noise with no meaningful coverage.
const WARMUP_OPS: usize = 5;

/// Maximum retries when generating a random op before falling back to
/// `AdvanceTime`.
///
/// Op generation can fail when no suitable target exists (e.g., no active
/// workers, no held shards for a renew). Retrying with a fresh random roll
/// usually finds a valid op within a few attempts. The `AdvanceTime` fallback
/// is always valid and advances the simulation meaningfully.
const MAX_OP_RETRIES: usize = 10;

/// Maximum number of stale leases retained for zombie checkpoint injection.
///
/// Capped to prevent unbounded growth in long-running simulations. When
/// the limit is exceeded, random entries are evicted via `swap_remove`.
const MAX_STALE_LEASES: usize = 64;

/// Saved checkpoint data for idempotency and conflict testing.
///
/// Keyed by `(worker_raw, run_raw, shard_raw)` because `ShardKey` intentionally
/// omits `Ord`. Each entry stores the `(OpId, Cursor, WorkerId, ShardKey)` from
/// the last successful checkpoint, enabling [`SimOp::ReplayCheckpoint`] (same
/// OpId + payload) and [`SimOp::ConflictCheckpoint`] (same OpId, different payload).
type CheckpointOpMap = BTreeMap<(u64, u64, u64), (OpId, Cursor, WorkerId, ShardKey)>;

/// Check that `worker` exists, is not paused, holds a lease on `key`,
/// and advance its op-id counter.
///
/// Free function (not `&mut self`) so callers retain mutable access to
/// the remaining `CoordinationSim` fields (`coordinator`, `context`, etc.)
/// while borrowing only `workers`.
fn require_lease_and_op(
    workers: &mut BTreeMap<WorkerId, SimWorker>,
    worker: WorkerId,
    key: &ShardKey,
) -> Result<(Lease, OpId), SimEvent> {
    let w = workers
        .get_mut(&worker)
        .filter(|w| !w.is_paused())
        .ok_or(SimEvent::Rejected {
            kind: RejectionKind::WorkerPaused,
        })?;
    let lease = *w.lease_for(key).ok_or(SimEvent::Rejected {
        kind: RejectionKind::NotLeased,
    })?;
    let op_id = w.next_op_id();
    Ok((lease, op_id))
}

/// Full deterministic simulation harness for the coordination protocol.
///
/// Maintains two parallel views of the world:
///
/// - **Coordinator truth** (`coordinator: B`): the real shard records, leases,
///   and fence epochs. All mutations go through the [`SimulationBackend`] trait.
/// - **Worker bookkeeping** (`workers: BTreeMap<WorkerId, SimWorker>`): each
///   worker's *local belief* about which shards it holds. This view can diverge
///   from coordinator truth (e.g., after a lease expires silently), which is
///   intentional -- the divergence is what creates interesting fault scenarios.
///
/// The [`InvariantChecker`] always validates against coordinator truth, never
/// against worker bookkeeping, to avoid masking real violations.
///
/// # Generics
///
/// Generic over the backend type `B`, defaulting to [`InMemoryCoordinator`]
/// so `CoordinationSim::new(...)` compiles without turbofish. The generic impl
/// block provides all simulation logic; `InMemoryCoordinator`-specific setup
/// methods (`new`, `register_shard`, `with_workers_and_shards`, `seed_all_runs`)
/// live in a specialized impl block.
///
/// # State management
///
/// | Field | Purpose |
/// |-------|---------|
/// | `shard_keys` | All registered shard keys (including terminal). Grows on splits. |
/// | `active_shard_keys` | Non-terminal subset. Shrinks on complete/park/split-replace. |
/// | `stale_leases` | Superseded leases for zombie checkpoint injection. Capped at [`MAX_STALE_LEASES`]. |
/// | `last_checkpoint_ops` | Per-(worker, run, shard) checkpoint history for replay/conflict testing. |
/// | `run_shard_ids` | Shard IDs per run, seeded into the coordinator for `claim_next_available`. |
pub struct CoordinationSim<B: SimulationBackend = InMemoryCoordinator> {
    context: SimContext,
    coordinator: B,
    workers: BTreeMap<WorkerId, SimWorker>,
    fault_config: FaultConfig,
    checker: InvariantChecker,
    shard_keys: Vec<ShardKey>,
    /// Subset of `shard_keys` containing only non-terminal shards.
    /// Used by `pick_random_shard_key` to avoid selecting terminal shards
    /// that would always be rejected.
    active_shard_keys: Vec<ShardKey>,
    tenant: TenantId,
    ops_executed: usize,
    /// Stale leases saved when B1 cleanup supersedes them, used for
    /// zombie checkpoint injection to exercise the `StaleFence` path.
    stale_leases: Vec<(WorkerId, ShardKey, Lease)>,
    /// Last successful checkpoint info per `(worker_raw, run_raw, shard_raw)`.
    /// Uses raw u64 keys because `ShardKey` intentionally omits `Ord`.
    last_checkpoint_ops: CheckpointOpMap,
    /// Shard IDs per run, used to seed run records for `claim_next_available`.
    run_shard_ids: BTreeMap<RunId, Vec<ShardId>>,
}

// ============================================================================
// InMemoryCoordinator-specific constructors and setup
// ============================================================================

impl CoordinationSim<InMemoryCoordinator> {
    /// Create a new simulation backed by [`InMemoryCoordinator`] with default
    /// lease duration.
    ///
    /// Call [`with_workers_and_shards`](Self::with_workers_and_shards) to add
    /// participants, or use [`add_worker`](CoordinationSim::add_worker) and
    /// [`register_shard`](Self::register_shard) for fine-grained setup.
    pub fn new(seed: u64, level: FaultLevel) -> Self {
        Self::with_backend(
            seed,
            level,
            InMemoryCoordinator::new(DEFAULT_LEASE_DURATION),
        )
    }

    /// Register a shard in the coordinator with a default spec range `[b'a', b'z')`.
    ///
    /// The shard is added to `shard_keys` and its run is tracked in `run_shard_ids`
    /// for later `claim_next_available` seeding. Does **not** add to
    /// `active_shard_keys` -- call [`with_workers_and_shards`](Self::with_workers_and_shards)
    /// or set `active_shard_keys` manually after registration.
    pub fn register_shard(&mut self, run: RunId, shard: ShardId) {
        let record = ShardRecord::new_active(
            self.tenant,
            run,
            shard,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            CursorSemantics::Completed,
        );
        self.coordinator.seed_shard(record);
        self.shard_keys.push(ShardKey::new(run, shard));
        self.run_shard_ids.entry(run).or_default().push(shard);
    }

    /// Builder: add `n_workers` workers (IDs `1..=n`) and `n_shards` shards
    /// (run=1, shard IDs `1..=m`), seed run records, and initialize the active
    /// shard set.
    ///
    /// This is the standard one-liner for test setup. For multi-run scenarios,
    /// use [`register_shard`](Self::register_shard) directly.
    pub fn with_workers_and_shards(mut self, n_workers: u64, n_shards: u64) -> Self {
        for i in 1..=n_workers {
            self.add_worker(WorkerId::from_raw(i));
        }
        let run = RunId::from_raw(1);
        for i in 1..=n_shards {
            self.register_shard(run, ShardId::from_raw(i));
        }
        // Seed run records so `claim_next_available` can discover shards.
        self.seed_all_runs();
        // At creation all shards are active (non-terminal).
        self.active_shard_keys = self.shard_keys.clone();
        self
    }

    /// Create run records for all registered runs.
    pub fn seed_all_runs(&mut self) {
        for (run, shard_ids) in &self.run_shard_ids {
            self.coordinator
                .seed_run(self.tenant, *run, shard_ids.clone(), DEFAULT_LEASE_DURATION);
        }
    }
}

// ============================================================================
// Generic simulation logic
// ============================================================================

impl<B: SimulationBackend> CoordinationSim<B> {
    /// Create a simulation harness with a custom [`SimulationBackend`].
    ///
    /// The backend is used as-is; callers are responsible for seeding shards
    /// and configuring run records before calling [`run`](Self::run) or
    /// [`step`](Self::step).
    pub fn with_backend(seed: u64, level: FaultLevel, backend: B) -> Self {
        Self {
            context: SimContext::new(seed),
            coordinator: backend,
            workers: BTreeMap::new(),
            fault_config: FaultConfig::for_level(level),
            checker: InvariantChecker::new(),
            shard_keys: Vec::new(),
            active_shard_keys: Vec::new(),
            tenant: TenantId::from_bytes([0x01; 32]),
            ops_executed: 0,
            stale_leases: Vec::new(),
            last_checkpoint_ops: BTreeMap::new(),
            run_shard_ids: BTreeMap::new(),
        }
    }

    /// Add a worker to the simulation.
    pub fn add_worker(&mut self, id: WorkerId) {
        self.workers.insert(id, SimWorker::new(id));
    }

    /// Execute a single step: run the operation, then check **all** invariants.
    ///
    /// Every operation—successful or rejected—is followed by a full invariant
    /// sweep (S1–S7). This is the core simulation guarantee: no operation can
    /// leave the coordinator in a state that violates any checked invariant
    /// without immediate detection.
    pub fn step(&mut self, op: SimOp) -> (SimEvent, Vec<InvariantViolation>) {
        let event = self.execute_op(&op);
        self.ops_executed += 1;

        let worker_refs: Vec<&SimWorker> = self.workers.values().collect();
        let violations = self.checker.check_all(
            &self.coordinator,
            &worker_refs,
            self.tenant,
            self.context.now(),
        );
        (event, violations)
    }

    /// Run a complete simulation and consume the harness, returning a report.
    ///
    /// Execution proceeds in three stages (see module docs):
    ///
    /// 1. **Zombie preamble**: One scripted acquire-expire-reacquire-checkpoint
    ///    sequence that deterministically exercises the B1 bookkeeping cleanup
    ///    path.
    /// 2. **Safety phase** (`safety_ops` random ops): The first [`WARMUP_OPS`]
    ///    suppress faults; the remainder use full fault injection including
    ///    random time-jumps that can expire leases mid-flight.
    /// 3. **Liveness phase** (`liveness_ops` convergence-biased ops): Weighted
    ///    toward acquire + complete to drive shards to terminal states.
    ///
    /// After all phases, checks whether every registered shard reached a
    /// terminal state (`converged` flag in the report).
    ///
    /// Consumes `self` to prevent accidental reuse of simulation state.
    pub fn run(mut self, safety_ops: usize, liveness_ops: usize) -> SimReport {
        let mut all_violations = Vec::new();
        let mut event_counts = BTreeMap::new();

        // TigerBeetle-inspired: advance time before first coordinator op
        // so that `now > ZERO` (some validation requires this).
        let initial_ticks = self.context.rng().random_range(1u64..=10);
        self.context.advance(initial_ticks);

        // Inject one deterministic zombie sequence before random ops.
        self.inject_zombie_scenario(&mut all_violations, &mut event_counts);

        // --- Safety phase ---
        for i in 0..safety_ops {
            let suppress_faults = i < WARMUP_OPS;
            let op = self.generate_random_op(suppress_faults);
            let (event, violations) = self.step(op);
            *event_counts.entry(event.kind()).or_insert(0) += 1;
            all_violations.extend(violations);
        }

        // --- Liveness phase ---
        for _ in 0..liveness_ops {
            let op = self.generate_liveness_op();
            let (event, violations) = self.step(op);
            *event_counts.entry(event.kind()).or_insert(0) += 1;
            all_violations.extend(violations);
        }

        let converged = self.check_convergence();

        SimReport {
            ops_executed: self.ops_executed,
            violations: all_violations,
            event_counts,
            seed: self.context.seed(),
            end_time: self.context.now(),
            converged,
        }
    }

    // -----------------------------------------------------------------------
    // Op execution
    // -----------------------------------------------------------------------

    /// Top-level dispatch: route a [`SimOp`] to the appropriate executor.
    ///
    /// Does **not** increment `ops_executed` or run invariant checks -- that
    /// is [`step`](Self::step)'s responsibility. This separation allows
    /// internal callers (like `inject_zombie_scenario`) to use `step` and
    /// get full invariant coverage.
    fn execute_op(&mut self, op: &SimOp) -> SimEvent {
        match op {
            SimOp::Acquire { worker, key }
            | SimOp::Renew { worker, key }
            | SimOp::Checkpoint { worker, key }
            | SimOp::Complete { worker, key }
            | SimOp::Park { worker, key } => self.execute_lease_op(op, *worker, *key),

            SimOp::SplitReplace { worker, key } | SimOp::SplitResidual { worker, key } => {
                self.execute_split_op(op, *worker, *key)
            }

            SimOp::ReplayCheckpoint { worker, key } | SimOp::ConflictCheckpoint { worker, key } => {
                self.execute_replay_op(op, *worker, *key)
            }

            SimOp::ZombieCheckpoint => self.exec_zombie_checkpoint(),

            SimOp::ClaimNext { worker } => self.exec_claim_next(*worker),

            SimOp::SessionLifecycle { worker, key } => self.exec_session_lifecycle(*worker, *key),

            SimOp::AdvanceTime { ticks } => {
                self.context.advance(*ticks);
                SimEvent::TimeAdvanced {
                    new_time: self.context.now(),
                }
            }
            SimOp::PauseWorker { worker } => {
                if let Some(w) = self.workers.get_mut(worker) {
                    w.pause();
                    SimEvent::WorkerPaused { worker: *worker }
                } else {
                    SimEvent::Skipped
                }
            }
            SimOp::ResumeWorker { worker } => {
                if let Some(w) = self.workers.get_mut(worker) {
                    w.resume();
                    SimEvent::WorkerResumed { worker: *worker }
                } else {
                    SimEvent::Skipped
                }
            }
        }
    }

    fn execute_lease_op(&mut self, op: &SimOp, worker: WorkerId, key: ShardKey) -> SimEvent {
        match op {
            SimOp::Acquire { .. } => self.exec_acquire(worker, key),
            SimOp::Renew { .. } => self.exec_renew(worker, key),
            SimOp::Checkpoint { .. } => self.exec_checkpoint(worker, key),
            SimOp::Complete { .. } => self.exec_complete(worker, key),
            SimOp::Park { .. } => self.exec_park(worker, key),
            _ => unreachable!("execute_lease_op called with non-lease op"),
        }
    }

    fn execute_split_op(&mut self, op: &SimOp, worker: WorkerId, key: ShardKey) -> SimEvent {
        match op {
            SimOp::SplitReplace { .. } => self.exec_split_replace(worker, key),
            SimOp::SplitResidual { .. } => self.exec_split_residual(worker, key),
            _ => unreachable!("execute_split_op called with non-split op"),
        }
    }

    fn execute_replay_op(&mut self, op: &SimOp, worker: WorkerId, key: ShardKey) -> SimEvent {
        match op {
            SimOp::ReplayCheckpoint { .. } => self.exec_replay_checkpoint(worker, key),
            SimOp::ConflictCheckpoint { .. } => self.exec_conflict_checkpoint(worker, key),
            _ => unreachable!("execute_replay_op called with non-replay op"),
        }
    }

    /// Update worker bookkeeping after a successful acquire.
    ///
    /// Records the new lease on `worker`, clears the shard from every
    /// other worker (saving superseded leases for zombie injection),
    /// and trims `stale_leases` to prevent unbounded growth.
    fn record_acquire_bookkeeping(&mut self, worker: WorkerId, key: ShardKey, lease: Lease) {
        for (wid, w) in &mut self.workers {
            if *wid == worker {
                w.record_acquire(key, lease);
            } else if let Some(stale) = w.lease_for(&key) {
                self.stale_leases.push((*wid, key, *stale));
                w.record_release(&key);
            }
        }

        while self.stale_leases.len() > MAX_STALE_LEASES {
            let idx = self.context.rng().random_range(0..self.stale_leases.len());
            let _ = self.stale_leases.swap_remove(idx);
        }
    }

    /// Attempt to acquire a shard lease.
    ///
    /// On success, updates worker bookkeeping via [`record_acquire_bookkeeping`](Self::record_acquire_bookkeeping),
    /// which also saves any superseded leases for zombie checkpoint injection.
    fn exec_acquire(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        let now = self.context.now();
        match self
            .coordinator
            .acquire_and_restore(now, self.tenant, key, worker)
        {
            Ok(result) => {
                let fence = result.lease.fence();
                let lease = result.lease;
                self.record_acquire_bookkeeping(worker, key, lease);
                SimEvent::AcquireOk { fence }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Renew a lease and update the worker's local copy to reflect the new deadline.
    ///
    /// The worker's lease object is reconstructed with the coordinator-returned
    /// deadline to keep bookkeeping consistent. Without this update, subsequent
    /// operations using the stale deadline would misrepresent expiry timing.
    fn exec_renew(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        let lease = match self.workers.get(&worker).and_then(|w| w.lease_for(&key)) {
            Some(l) => *l,
            None => {
                return SimEvent::Rejected {
                    kind: RejectionKind::NotLeased,
                };
            }
        };

        let now = self.context.now();
        match self.coordinator.renew(now, self.tenant, &lease) {
            Ok(result) => {
                // Update the worker's local lease to reflect the new deadline,
                // keeping bookkeeping consistent with coordinator truth.
                if let Some(w) = self.workers.get_mut(&worker) {
                    let updated = Lease::new(
                        lease.tenant(),
                        lease.run(),
                        lease.shard(),
                        lease.owner(),
                        lease.fence(),
                        result.new_deadline,
                    );
                    w.record_acquire(key, updated);
                }
                SimEvent::RenewOk {
                    new_deadline: result.new_deadline,
                }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Checkpoint cursor progress on a held shard.
    ///
    /// On success, records the cursor position on the worker (for forward-cursor
    /// generation) and saves the `(OpId, Cursor)` pair for replay/conflict testing.
    fn exec_checkpoint(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        let cursor = self.generate_forward_cursor(worker, key);

        let now = self.context.now();
        match self
            .coordinator
            .checkpoint(now, self.tenant, &lease, cursor.clone(), op_id)
        {
            Ok(_) => {
                // Track cursor progress on the worker.
                if let Some(last_key) = cursor.last_key()
                    && let Some(w) = self.workers.get_mut(&worker)
                {
                    w.record_cursor(key.run(), key.shard(), last_key.to_vec());
                }
                // Save for OpId replay/conflict testing.
                let ck = (worker.as_raw(), key.run().as_raw(), key.shard().as_raw());
                self.last_checkpoint_ops
                    .insert(ck, (op_id, cursor, worker, key));
                SimEvent::CheckpointOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Mark a shard as done (terminal). Releases the shard from the worker
    /// and removes it from the active set.
    fn exec_complete(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        let cursor = self.generate_forward_cursor(worker, key);

        let now = self.context.now();
        match self
            .coordinator
            .complete(now, self.tenant, &lease, cursor, op_id)
        {
            Ok(_) => {
                // Release the shard from the worker.
                if let Some(w) = self.workers.get_mut(&worker) {
                    w.record_release(&key);
                }
                // Shard is now terminal — remove from active set.
                self.active_shard_keys.retain(|k| *k != key);
                SimEvent::CompleteOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Park a shard for later retry (terminal). Releases the shard from the
    /// worker and removes it from the active set.
    fn exec_park(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        let now = self.context.now();
        match self
            .coordinator
            .park_shard(now, self.tenant, &lease, ParkReason::Other, op_id)
        {
            Ok(_) => {
                if let Some(w) = self.workers.get_mut(&worker) {
                    w.record_release(&key);
                }
                // Shard is now terminal — remove from active set.
                self.active_shard_keys.retain(|k| *k != key);
                SimEvent::ParkOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    // -----------------------------------------------------------------------
    // Split helpers
    // -----------------------------------------------------------------------

    /// Look up a shard's spec from the coordinator, returning a rejection
    /// event if the shard does not exist.
    fn lookup_shard_spec(&self, key: ShardKey) -> Result<ShardSpec, SimEvent> {
        match self.coordinator.shard_lookup(&self.tenant, &key) {
            Some(record) => Ok(record.spec.clone()),
            None => Err(SimEvent::Rejected {
                kind: RejectionKind::ShardNotFound,
            }),
        }
    }

    /// Compute a random single-byte split point in `(start[0], end[0])`.
    ///
    /// Returns `Err(Rejected)` if the range is too narrow (fewer than 2 byte
    /// values between start and end), which can happen after repeated splits
    /// shrink a shard's range down to adjacent bytes.
    fn compute_split_byte(&mut self, start: &[u8], end: &[u8]) -> Result<u8, SimEvent> {
        if start.is_empty() || end.is_empty() || start >= end || end[0] - start[0] < 2 {
            return Err(SimEvent::Rejected {
                kind: RejectionKind::SplitValidation,
            });
        }
        let lo = start[0] + 1;
        let hi = end[0];
        if lo >= hi {
            return Err(SimEvent::Rejected {
                kind: RejectionKind::SplitValidation,
            });
        }
        Ok(self.context.rng().random_range(lo..hi))
    }

    // -----------------------------------------------------------------------
    // Split operations
    // -----------------------------------------------------------------------

    /// Execute a split-replace: parent is retired (terminal) and replaced by
    /// 2 children whose ranges together cover the parent's full range.
    ///
    /// On success, releases the parent from the worker, registers both child
    /// shard keys in `shard_keys` and `active_shard_keys`, and removes the
    /// parent from the active set. The children start with `Cursor::initial()`
    /// (no progress) and are available for future acquire operations.
    fn exec_split_replace(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        // Look up parent's spec to compute a valid split point.
        let parent_spec = match self.lookup_shard_spec(key) {
            Ok(spec) => spec,
            Err(event) => return event,
        };

        let start = parent_spec.key_range_start();
        let end = parent_spec.key_range_end();

        let mid = match self.compute_split_byte(start, end) {
            Ok(m) => m,
            Err(event) => return event,
        };

        let child_a_spec = ShardSpec::with_range(start.to_vec(), vec![mid]);
        let child_b_spec = ShardSpec::with_range(vec![mid], end.to_vec());

        let plan = match SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(child_a_spec, Cursor::initial()),
            SplitReplaceChild::new(child_b_spec, Cursor::initial()),
        ]) {
            Ok(p) => p,
            Err(_) => {
                return SimEvent::Rejected {
                    kind: RejectionKind::SplitValidation,
                };
            }
        };

        let now = self.context.now();
        match self
            .coordinator
            .split_replace(now, self.tenant, &lease, plan, op_id)
        {
            Ok(outcome) => {
                let result = outcome.into_inner();
                let children = result.children;
                // Release parent from worker (it's now terminal).
                if let Some(w) = self.workers.get_mut(&worker) {
                    w.record_release(&key);
                }
                // Register child shards so future ops can exercise them.
                let run = key.run();
                for &child_id in &children {
                    let child_key = ShardKey::new(run, child_id);
                    self.shard_keys.push(child_key);
                    self.active_shard_keys.push(child_key);
                }
                // Parent is now terminal — remove from active set.
                self.active_shard_keys.retain(|k| *k != key);
                SimEvent::SplitReplaceOk { children }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Execute a split-residual: parent's range shrinks to cover only the
    /// already-scanned prefix, and a new residual shard covers the remainder.
    ///
    /// Unlike split-replace, the parent remains active (non-terminal) and the
    /// worker keeps its lease. The split point is chosen after the parent's
    /// current cursor position so the parent retains all scanned data.
    /// The residual shard is registered in `shard_keys` and `active_shard_keys`.
    fn exec_split_residual(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        // Look up parent's current spec and cursor to compute a valid split.
        let parent_spec = match self.lookup_shard_spec(key) {
            Ok(spec) => spec,
            Err(event) => return event,
        };
        let parent_cursor_key = self
            .coordinator
            .shard_lookup(&self.tenant, &key)
            .and_then(|r| r.cursor.last_key().map(|k| k.to_vec()));

        let start = parent_spec.key_range_start();
        let end = parent_spec.key_range_end();

        // Basic range validation (reuse helper logic).
        if start.is_empty() || end.is_empty() || start >= end || end[0] - start[0] < 2 {
            return SimEvent::Rejected {
                kind: RejectionKind::SplitValidation,
            };
        }

        // Split point must be after the current cursor (parent keeps the
        // prefix it already scanned). If no cursor yet, split anywhere.
        let cursor_byte = parent_cursor_key
            .as_ref()
            .and_then(|k| k.first().copied())
            .unwrap_or(start[0]);

        let lo = cursor_byte.saturating_add(1).max(start[0] + 1);
        let hi = end[0];
        if lo >= hi {
            return SimEvent::Rejected {
                kind: RejectionKind::SplitValidation,
            };
        }
        let mid = self.context.rng().random_range(lo..hi);

        let new_parent_spec = ShardSpec::with_range(start.to_vec(), vec![mid]);
        let residual_spec = ShardSpec::with_range(vec![mid], end.to_vec());

        let plan = match SplitResidualPlan::try_new(new_parent_spec, residual_spec) {
            Ok(p) => p,
            Err(_) => {
                return SimEvent::Rejected {
                    kind: RejectionKind::SplitValidation,
                };
            }
        };

        let now = self.context.now();
        match self
            .coordinator
            .split_residual(now, self.tenant, &lease, plan, op_id)
        {
            Ok(outcome) => {
                let result = outcome.into_inner();
                let residual = result.residual;
                // Parent stays active (non-terminal) -- worker keeps lease.
                // Register residual shard for future ops.
                let residual_key = ShardKey::new(key.run(), residual);
                self.shard_keys.push(residual_key);
                self.active_shard_keys.push(residual_key);
                SimEvent::SplitResidualOk { residual }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    // -----------------------------------------------------------------------
    // OpId replay/conflict
    // -----------------------------------------------------------------------

    /// Common preamble for replay and conflict checkpoint operations.
    ///
    /// Validates the worker is active, looks up the prior checkpoint for
    /// the given `(worker, key)`, and retrieves the worker's current lease.
    fn checkpoint_preamble(
        &self,
        worker: WorkerId,
        key: ShardKey,
    ) -> Result<(OpId, Cursor, Lease), SimEvent> {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return Err(SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            });
        }

        let ck = (worker.as_raw(), key.run().as_raw(), key.shard().as_raw());
        let (prev_op_id, prev_cursor, ..) =
            self.last_checkpoint_ops
                .get(&ck)
                .ok_or(SimEvent::Rejected {
                    kind: RejectionKind::NoPriorCheckpoint,
                })?;

        let lease = self
            .workers
            .get(&worker)
            .and_then(|w| w.lease_for(&key))
            .copied()
            .ok_or(SimEvent::Rejected {
                kind: RejectionKind::NotLeased,
            })?;

        Ok((*prev_op_id, prev_cursor.clone(), lease))
    }

    /// Replay a previous checkpoint with the same OpId and payload.
    /// Exercises the `IdempotentOutcome::Replayed` path.
    fn exec_replay_checkpoint(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (prev_op_id, prev_cursor, lease) = match self.checkpoint_preamble(worker, key) {
            Ok(t) => t,
            Err(rejection) => return rejection,
        };

        let now = self.context.now();
        match self
            .coordinator
            .checkpoint(now, self.tenant, &lease, prev_cursor, prev_op_id)
        {
            Ok(outcome) => match outcome {
                IdempotentOutcome::Replayed(()) => SimEvent::ReplayedOk,
                IdempotentOutcome::Executed(()) => {
                    // Op-log entry was evicted -- treated as new execution.
                    SimEvent::CheckpointOk
                }
            },
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Replay a previous OpId with a different cursor payload.
    /// Exercises the `OpIdConflict` error path.
    fn exec_conflict_checkpoint(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (prev_op_id, _prev_cursor, lease) = match self.checkpoint_preamble(worker, key) {
            Ok(t) => t,
            Err(rejection) => return rejection,
        };

        // Generate a *different* cursor to trigger a payload hash mismatch.
        let different_cursor = self.generate_forward_cursor(worker, key);

        let now = self.context.now();
        match self
            .coordinator
            .checkpoint(now, self.tenant, &lease, different_cursor, prev_op_id)
        {
            Ok(_) => {
                // Op-log entry was evicted -- old OpId not found, so this
                // was treated as a fresh execution. Still valid.
                SimEvent::CheckpointOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    // -----------------------------------------------------------------------
    // Zombie checkpoint
    // -----------------------------------------------------------------------

    /// Execute a checkpoint using a stale lease saved when another worker
    /// acquired the same shard. Exercises the coordinator's fence-based
    /// `StaleFence` rejection path that bookkeeping cleanup otherwise shadows.
    fn exec_zombie_checkpoint(&mut self) -> SimEvent {
        if self.stale_leases.is_empty() {
            return SimEvent::Rejected {
                kind: RejectionKind::NoStaleLease,
            };
        }

        // Pick a random stale lease and remove it to bound growth.
        let idx = self.context.rng().random_range(0..self.stale_leases.len());
        let (stale_worker, _key, stale_lease) = self.stale_leases.swap_remove(idx);

        // Generate a fresh op-ID from the stale worker.
        let op_id = match self.workers.get_mut(&stale_worker) {
            Some(w) => w.next_op_id(),
            None => {
                return SimEvent::Rejected {
                    kind: RejectionKind::Other,
                };
            }
        };

        // Use the stale lease directly -- bypasses B1 bookkeeping.
        let cursor = Cursor::with_last_key(vec![b'm']);
        let now = self.context.now();
        match self
            .coordinator
            .checkpoint(now, self.tenant, &stale_lease, cursor, op_id)
        {
            Ok(_) => {
                panic!(
                    "zombie checkpoint succeeded with stale lease — \
                     fencing protocol is broken"
                );
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    // -----------------------------------------------------------------------
    // Claim next available
    // -----------------------------------------------------------------------

    /// Exercise `claim_next_available`: list-then-acquire retry loop.
    ///
    /// Picks a random run from the active shard keys and delegates to
    /// [`ShardClaiming::claim_next_available`]. On success, records the
    /// lease in the worker's bookkeeping (same as `exec_acquire`).
    fn exec_claim_next(&mut self, worker: WorkerId) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        // Collect unique runs from active shard keys and pick one randomly,
        // ensuring multi-run scenarios exercise claiming across all runs.
        if self.active_shard_keys.is_empty() {
            return SimEvent::ClaimNoneAvailable;
        }
        let mut runs: Vec<RunId> = self.active_shard_keys.iter().map(|k| k.run()).collect();
        runs.sort();
        runs.dedup();
        let idx = self.context.rng().random_range(0..runs.len());
        let run = runs[idx];

        let now = self.context.now();
        match self
            .coordinator
            .claim_next_available(now, self.tenant, run, worker)
        {
            Ok(result) => {
                let shard = result.lease.shard();
                let key = ShardKey::new(run, shard);
                let lease = result.lease;
                self.record_acquire_bookkeeping(worker, key, lease);
                SimEvent::ClaimOk { shard }
            }
            Err(ClaimError::NoneAvailable) => SimEvent::ClaimNoneAvailable,
            Err(ClaimError::RunNotFound) => SimEvent::Rejected {
                kind: RejectionKind::ShardNotFound,
            },
            Err(ClaimError::TenantMismatch { .. }) => SimEvent::Rejected {
                kind: RejectionKind::TenantMismatch,
            },
        }
    }

    // -----------------------------------------------------------------------
    // Op generation
    // -----------------------------------------------------------------------

    /// Generate a random operation with weighted distribution.
    ///
    /// During warmup (`suppress_faults = true`), only generates basic
    /// lease-lifecycle operations (acquire, renew, checkpoint, complete, park).
    ///
    /// Weight rationale (normal mode):
    /// - acquire (13%) and checkpoint (13%) exercise the happy path
    /// - renew (10%) keeps leases alive
    /// - complete (8%) and park (4%) are terminal (over-weighting starves coverage)
    /// - split_replace (4%) and split_residual (4%) exercise split paths
    /// - replay/conflict (4%) exercise idempotency
    /// - zombie (3%) exercises stale-fence rejection
    /// - claim_next (3%) exercises the list-then-acquire retry loop
    /// - session_lifecycle (8%) exercises WorkerSession wrapper end-to-end
    /// - time advances (10%) create expiry windows
    /// - pause (8%) and resume (8%) model worker failures
    fn generate_random_op(&mut self, suppress_faults: bool) -> SimOp {
        for _ in 0..MAX_OP_RETRIES {
            // Weighted selection.
            let roll: u32 = self.context.rng().random_range(0..100);
            let op = if suppress_faults {
                // Warmup: only coordinator ops (no faults, no splits, no idempotency).
                match roll {
                    0..30 => self.try_gen_acquire(),
                    30..50 => self.try_gen_renew(),
                    50..75 => self.try_gen_checkpoint(),
                    75..90 => self.try_gen_complete(),
                    _ => self.try_gen_park(),
                }
            } else {
                match roll {
                    0..13 => self.try_gen_acquire(),
                    13..23 => self.try_gen_renew(),
                    23..36 => self.try_gen_checkpoint(),
                    36..44 => self.try_gen_complete(),
                    44..48 => self.try_gen_park(),
                    48..52 => self.try_gen_split_replace(),
                    52..56 => self.try_gen_split_residual(),
                    56..58 => self.try_gen_replay_checkpoint(),
                    58..60 => self.try_gen_conflict_checkpoint(),
                    60..63 => self.try_gen_zombie_checkpoint(),
                    63..66 => self.try_gen_claim_next(),
                    66..74 => self.try_gen_session_lifecycle(),
                    74..84 => Some(self.gen_advance_time()),
                    84..92 => self.try_gen_pause(),
                    _ => self.try_gen_resume(),
                }
            };

            if let Some(op) = op {
                // Inject time-jump fault.
                if !suppress_faults && self.fault_config.should_time_jump(self.context.rng()) {
                    let ticks = self.fault_config.time_jump_ticks(self.context.rng());
                    if ticks > 0 {
                        self.context.advance(ticks);
                    }
                }
                return op;
            }
        }

        // Fallback: always-valid AdvanceTime.
        self.gen_advance_time()
    }

    /// Generate a liveness-biased operation for the convergence phase.
    ///
    /// Heavily weighted toward acquire (30%) and complete (30%) to drive all
    /// shards to terminal states. Omits faults, splits, idempotency tests,
    /// and pauses to avoid creating new non-terminal shards or blocking
    /// progress. Includes AdvanceTime and resume as environmental ops
    /// (time advances keep leases cycling; resume unblocks workers paused
    /// during the safety phase).
    fn generate_liveness_op(&mut self) -> SimOp {
        for _ in 0..MAX_OP_RETRIES {
            let roll: u32 = self.context.rng().random_range(0..100);
            let op = match roll {
                0..30 => self.try_gen_acquire(),
                30..40 => self.try_gen_renew(),
                40..55 => self.try_gen_checkpoint(),
                55..85 => self.try_gen_complete(),
                85..95 => Some(self.gen_advance_time()),
                _ => self.try_gen_resume(),
            };
            if let Some(op) = op {
                return op;
            }
        }
        self.gen_advance_time()
    }

    /// Select a uniformly random non-paused worker, or `None` if all are paused.
    fn pick_random_active_worker(&mut self) -> Option<WorkerId> {
        let count = self.workers.values().filter(|w| !w.is_paused()).count();
        if count == 0 {
            return None;
        }
        let idx = self.context.rng().random_range(0..count);
        self.workers
            .iter()
            .filter(|(_, w)| !w.is_paused())
            .map(|(id, _)| *id)
            .nth(idx)
    }

    /// Select a uniformly random active (non-terminal) shard key, or `None` if empty.
    fn pick_random_shard_key(&mut self) -> Option<ShardKey> {
        if self.active_shard_keys.is_empty() {
            return None;
        }
        let idx = self
            .context
            .rng()
            .random_range(0..self.active_shard_keys.len());
        Some(self.active_shard_keys[idx])
    }

    /// Collect a worker's held shard keys in deterministic order.
    ///
    /// `SimWorker::held_keys()` iterates in deterministic `(run, shard)`
    /// order (backed by `BTreeMap`), so no post-hoc sort is needed.
    fn sorted_held_keys(&self, worker: WorkerId) -> Vec<ShardKey> {
        self.workers
            .get(&worker)
            .map(|w| w.held_keys().copied().collect())
            .unwrap_or_default()
    }

    fn try_gen_acquire(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let key = self.pick_random_shard_key()?;
        Some(SimOp::Acquire { worker, key })
    }

    fn try_gen_claim_next(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        Some(SimOp::ClaimNext { worker })
    }

    /// Pick an active worker, select a random held shard, and wrap both
    /// in a `SimOp` via the supplied constructor.
    ///
    /// Six `try_gen_*` methods share this exact pattern; factoring it here
    /// removes ~60 lines of duplicated logic while preserving the PRNG
    /// call sequence (pick worker → sorted keys → random index).
    fn try_gen_held_shard_op(&mut self, f: fn(WorkerId, ShardKey) -> SimOp) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let held = self.sorted_held_keys(worker);
        if held.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..held.len());
        Some(f(worker, held[idx]))
    }

    fn try_gen_renew(&mut self) -> Option<SimOp> {
        self.try_gen_held_shard_op(|worker, key| SimOp::Renew { worker, key })
    }

    fn try_gen_checkpoint(&mut self) -> Option<SimOp> {
        self.try_gen_held_shard_op(|worker, key| SimOp::Checkpoint { worker, key })
    }

    fn try_gen_complete(&mut self) -> Option<SimOp> {
        self.try_gen_held_shard_op(|worker, key| SimOp::Complete { worker, key })
    }

    fn try_gen_park(&mut self) -> Option<SimOp> {
        self.try_gen_held_shard_op(|worker, key| SimOp::Park { worker, key })
    }

    fn gen_advance_time(&mut self) -> SimOp {
        let ticks = self.context.rng().random_range(1u64..=50);
        SimOp::AdvanceTime { ticks }
    }

    fn try_gen_pause(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        Some(SimOp::PauseWorker { worker })
    }

    fn try_gen_resume(&mut self) -> Option<SimOp> {
        let count = self.workers.values().filter(|w| w.is_paused()).count();
        if count == 0 {
            return None;
        }
        let idx = self.context.rng().random_range(0..count);
        let worker = self
            .workers
            .iter()
            .filter(|(_, w)| w.is_paused())
            .map(|(id, _)| *id)
            .nth(idx)?;
        Some(SimOp::ResumeWorker { worker })
    }

    fn try_gen_split_replace(&mut self) -> Option<SimOp> {
        self.try_gen_held_shard_op(|worker, key| SimOp::SplitReplace { worker, key })
    }

    fn try_gen_split_residual(&mut self) -> Option<SimOp> {
        self.try_gen_held_shard_op(|worker, key| SimOp::SplitResidual { worker, key })
    }

    fn try_gen_replay_checkpoint(&mut self) -> Option<SimOp> {
        if self.last_checkpoint_ops.is_empty() {
            return None;
        }
        // Pick a random entry from last_checkpoint_ops.
        let idx = self
            .context
            .rng()
            .random_range(0..self.last_checkpoint_ops.len());
        let (.., worker, key) = self.last_checkpoint_ops.values().nth(idx)?;
        Some(SimOp::ReplayCheckpoint {
            worker: *worker,
            key: *key,
        })
    }

    fn try_gen_conflict_checkpoint(&mut self) -> Option<SimOp> {
        if self.last_checkpoint_ops.is_empty() {
            return None;
        }
        let idx = self
            .context
            .rng()
            .random_range(0..self.last_checkpoint_ops.len());
        let (.., worker, key) = self.last_checkpoint_ops.values().nth(idx)?;
        Some(SimOp::ConflictCheckpoint {
            worker: *worker,
            key: *key,
        })
    }

    fn try_gen_zombie_checkpoint(&mut self) -> Option<SimOp> {
        if self.stale_leases.is_empty() {
            return None;
        }
        Some(SimOp::ZombieCheckpoint)
    }

    fn try_gen_session_lifecycle(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let key = self.pick_random_shard_key()?;
        Some(SimOp::SessionLifecycle { worker, key })
    }

    // -----------------------------------------------------------------------
    // Cursor generation
    // -----------------------------------------------------------------------

    /// Generate a cursor that is lexicographically >= the worker's last cursor
    /// for this shard and within the shard spec bounds.
    ///
    /// Naively random cursors would frequently regress behind the worker's
    /// last checkpoint, causing the coordinator to correctly reject the
    /// operation. That masks real bugs behind a flood of expected
    /// `CursorRegression` rejections. By tracking per-worker cursor progress
    /// and only generating forward cursors, rejections in the simulation
    /// signal actual protocol violations rather than test-harness noise.
    ///
    /// Generates variable-length keys (1–3 bytes) to exercise multi-byte
    /// lexicographic comparison paths in the coordinator.
    fn generate_forward_cursor(&mut self, worker: WorkerId, key: ShardKey) -> Cursor {
        let last = self
            .workers
            .get(&worker)
            .and_then(|w| w.last_cursor_for(key.run(), key.shard()));

        // Look up this shard's actual spec bounds from the coordinator.
        let (spec_start, spec_end) = self
            .coordinator
            .shard_lookup(&self.tenant, &key)
            .map(|r| {
                (
                    r.spec.key_range_start().to_vec(),
                    r.spec.key_range_end().to_vec(),
                )
            })
            .unwrap_or_else(|| (vec![b'a'], vec![b'z']));

        // The first byte determines the "slot". We advance forward from the
        // last cursor's first byte (or the spec start).
        let last_first = last.and_then(|k| k.first().copied());

        let range_lo = spec_start.first().copied().unwrap_or(b'a');
        let range_hi = spec_end.first().copied().unwrap_or(b'z');

        let start = match last_first {
            Some(k) => k.saturating_add(1).max(range_lo),
            None => range_lo,
        };

        if start >= range_hi {
            // Range exhausted — return previous cursor (idempotent retry) to
            // maintain the forward-only guarantee. Without this, a single-byte
            // fallback could regress behind a multi-byte previous cursor.
            if let Some(prev) = last {
                return Cursor::with_last_key(prev.to_vec());
            }
            return Cursor::with_last_key(vec![range_hi.saturating_sub(1)]);
        }

        let first_byte = self.context.rng().random_range(start..range_hi);

        // Variable-length key: 1–3 bytes. Extra bytes are random suffix
        // that exercises multi-byte lex comparison in the coordinator.
        let key_len: usize = self.context.rng().random_range(1..=3);
        let mut cursor_key = Vec::with_capacity(key_len);
        cursor_key.push(first_byte);
        for _ in 1..key_len {
            cursor_key.push(self.context.rng().random_range(0u8..=255));
        }

        Cursor::with_last_key(cursor_key)
    }

    // -----------------------------------------------------------------------
    // Zombie scenario
    // -----------------------------------------------------------------------

    /// Inject one deterministic zombie-worker scenario.
    ///
    /// 1. Worker A acquires a shard.
    /// 2. Time advances past lease deadline.
    /// 3. Worker B acquires the same shard (bumps fence).
    /// 4. Worker A attempts checkpoint — rejected with `NotLeased` because
    ///    B1 bookkeeping cleanup cleared Worker A's lease when Worker B
    ///    acquired. This exercises the **B1 bookkeeping cleanup** path,
    ///    not the coordinator's fence-based `StaleFence` rejection.
    ///
    /// The coordinator's `StaleFence` path (fence-epoch mismatch) is
    /// separately exercised by [`exec_zombie_checkpoint`], which uses
    /// saved stale leases to bypass B1 cleanup entirely.
    fn inject_zombie_scenario(
        &mut self,
        all_violations: &mut Vec<InvariantViolation>,
        event_counts: &mut BTreeMap<SimEventKind, usize>,
    ) {
        let worker_ids: Vec<WorkerId> = self.workers.keys().copied().collect();
        if worker_ids.len() < 2 || self.shard_keys.is_empty() {
            return;
        }

        let worker_a = worker_ids[0];
        let worker_b = worker_ids[1];
        let key = self.shard_keys[0];

        // Step 1: Worker A acquires.
        let (event, violations) = self.step(SimOp::Acquire {
            worker: worker_a,
            key,
        });
        assert!(
            matches!(event, SimEvent::AcquireOk { .. }),
            "zombie setup: worker A acquire failed: {event:?}",
        );
        *event_counts.entry(event.kind()).or_insert(0) += 1;
        all_violations.extend(violations);

        // Step 2: Advance past lease deadline.
        let (event, violations) = self.step(SimOp::AdvanceTime {
            ticks: DEFAULT_LEASE_DURATION + 1,
        });
        *event_counts.entry(event.kind()).or_insert(0) += 1;
        all_violations.extend(violations);

        // Step 3: Worker B acquires (bumps fence).
        let (event, violations) = self.step(SimOp::Acquire {
            worker: worker_b,
            key,
        });
        assert!(
            matches!(event, SimEvent::AcquireOk { .. }),
            "zombie setup: worker B acquire failed: {event:?}",
        );
        *event_counts.entry(event.kind()).or_insert(0) += 1;
        all_violations.extend(violations);

        // Step 4: Worker A attempts checkpoint — B1 bookkeeping cleanup
        // cleared its lease on Worker B's acquire, so this is rejected with
        // NotLeased (exercises B1 path, not StaleFence).
        let (event, violations) = self.step(SimOp::Checkpoint {
            worker: worker_a,
            key,
        });
        *event_counts.entry(event.kind()).or_insert(0) += 1;
        all_violations.extend(violations);

        // The checkpoint must have been rejected (either NotLeased or StaleFence).
        assert!(
            matches!(event, SimEvent::Rejected { .. }),
            "zombie worker checkpoint should be rejected, got: {event:?}",
        );
    }

    // -----------------------------------------------------------------------
    // Session lifecycle
    // -----------------------------------------------------------------------

    /// Execute a complete WorkerSession lifecycle on a shard.
    ///
    /// acquire → checkpoint(1–3x) → complete|park
    ///
    /// All random decisions are pre-computed before the session is created
    /// so the PRNG stream position is deterministic regardless of session
    /// outcome. The session block borrows only `self.coordinator`; sim-level
    /// bookkeeping runs after the session drops.
    ///
    /// Invariant checks happen at the session boundary (after drop), not
    /// between individual session operations. This is justified because:
    /// - WorkerSession's `&mut B` prevents external observation mid-session
    /// - Backend-internal `record.assert_invariants()` maintains per-op safety
    /// - S1 cannot be violated mid-session (exclusive borrow prevents concurrent acquire)
    fn exec_session_lifecycle(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        // --- Pre-compute all random decisions (touches self.context only) ---

        // Look up spec bounds before session acquires exclusive coordinator access.
        let (range_lo, range_hi) = self
            .coordinator
            .shard_lookup(&self.tenant, &key)
            .map(|r| {
                let lo = r.spec.key_range_start().first().copied().unwrap_or(b'a');
                let hi = r.spec.key_range_end().first().copied().unwrap_or(b'z');
                (lo, hi)
            })
            .unwrap_or((b'a', b'z'));

        let num_checkpoints: u32 = self.context.rng().random_range(1..=3);
        let should_park: bool = self.context.rng().random_range(0u32..10) < 2;

        // Build forward-progressing cursor sequence.
        let total_cursors = num_checkpoints as usize + 1;
        let mut cursors: Vec<Cursor> = Vec::with_capacity(total_cursors);
        let mut lo = range_lo;
        for _ in 0..total_cursors {
            if lo >= range_hi {
                let byte = cursors
                    .last()
                    .and_then(|c| c.last_key().and_then(|k| k.first().copied()))
                    .unwrap_or(range_hi.saturating_sub(1));
                cursors.push(Cursor::with_last_key(vec![byte]));
            } else {
                let byte = self.context.rng().random_range(lo..range_hi);
                cursors.push(Cursor::with_last_key(vec![byte]));
                lo = byte.saturating_add(1);
            }
        }

        // Generate op IDs from the worker.
        let w = match self.workers.get_mut(&worker) {
            Some(w) => w,
            None => return SimEvent::Skipped,
        };
        let op_ids: Vec<OpId> = (0..total_cursors).map(|_| w.next_op_id()).collect();

        // --- Execute session in a scoped block (borrows only self.coordinator) ---

        let now = self.context.now();
        let tenant = self.tenant;

        let session_result: Result<(Lease, bool), SimEvent> = (|| {
            let mut sess = WorkerSession::new(&mut self.coordinator, now, tenant, key, worker)
                .map_err(|e| SimEvent::Rejected {
                    kind: RejectionKind::from(e),
                })?;

            let lease = *sess.lease();

            // Checkpoint phase.
            for i in 0..num_checkpoints as usize {
                let _ = sess.checkpoint(now, cursors[i].clone(), op_ids[i]);
            }

            // Terminal phase.
            let terminal_idx = num_checkpoints as usize;
            let is_terminal = if should_park {
                sess.park(now, ParkReason::Other, op_ids[terminal_idx])
                    .is_ok()
            } else {
                sess.complete(now, cursors[terminal_idx].clone(), op_ids[terminal_idx])
                    .is_ok()
            };

            Ok((lease, is_terminal))
        })();
        // Session dropped here — coordinator borrow released.

        // --- Sim-level bookkeeping (touches self.workers, self.active_shard_keys) ---

        let (lease, is_terminal) = match session_result {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        self.record_acquire_bookkeeping(worker, key, lease);

        if is_terminal {
            if let Some(w) = self.workers.get_mut(&worker) {
                w.record_release(&key);
            }
            self.active_shard_keys.retain(|k| *k != key);
        }

        SimEvent::SessionLifecycleOk
    }

    // -----------------------------------------------------------------------
    // Convergence check
    // -----------------------------------------------------------------------

    /// Check whether every registered shard reached a terminal state.
    ///
    /// Terminal states are `Done`, `Split`, and `Parked`. This iterates
    /// `shard_keys` (which includes split children registered during the run),
    /// so the convergence check covers the full expanded shard population.
    ///
    /// # Panics
    ///
    /// Panics if a shard key is not found in the coordinator, which indicates
    /// a registration bug in the harness.
    fn check_convergence(&self) -> bool {
        for key in &self.shard_keys {
            let record = self
                .coordinator
                .shard_lookup(&self.tenant, key)
                .expect("shard key missing from coordinator — registration bug");
            if !record.status.is_terminal() {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;

    fn default_sim(seed: u64, level: FaultLevel) -> CoordinationSim {
        CoordinationSim::new(seed, level).with_workers_and_shards(3, 5)
    }

    fn sim_proptest_config() -> proptest::test_runner::Config {
        let mut cfg = miri_proptest_config();
        if !cfg!(miri) {
            cfg.cases = 50;
        }
        cfg
    }

    fn ops_for_level(level: FaultLevel) -> (usize, usize) {
        match level {
            FaultLevel::SunnyDay => (200, 100),
            FaultLevel::Stormy => (500, 200),
            FaultLevel::Radioactive => (1000, 500),
        }
    }

    fn arb_fault_level() -> impl Strategy<Value = FaultLevel> {
        prop_oneof![
            Just(FaultLevel::SunnyDay),
            Just(FaultLevel::Stormy),
            Just(FaultLevel::Radioactive),
        ]
    }

    // -- Cluster 1: no-violations property (replaces 5 tests) ----------------

    proptest! {
        #![proptest_config(sim_proptest_config())]

        #[test]
        fn no_violations_across_seeds_and_levels(
            seed in any::<u64>(),
            level in arb_fault_level(),
        ) {
            let (safety, liveness) = ops_for_level(level);
            let report = default_sim(seed, level).run(safety, liveness);
            prop_assert!(
                report.violations.is_empty(),
                "seed {}, level {:?}: {:?}",
                seed, level, report.violations,
            );
        }
    }

    // -- Cluster 2: report properties (merges 2 tests) -----------------------

    #[test]
    fn report_properties() {
        let report = default_sim(42, FaultLevel::Stormy).run(500, 200);
        assert!(report.event_counts.values().sum::<usize>() > 0);
        assert!(report.ops_executed > 0);
        let rejected = report
            .event_counts
            .get(&SimEventKind::Rejected)
            .copied()
            .unwrap_or(0);
        assert!(
            rejected > 0,
            "seed {}: expected rejections in Stormy mode",
            report.seed,
        );
    }

    // -- Unique tests (unchanged) --------------------------------------------

    #[test]
    fn deterministic_replay() {
        let seed = 99;
        let report_a = default_sim(seed, FaultLevel::Stormy).run(200, 100);
        let report_b = default_sim(seed, FaultLevel::Stormy).run(200, 100);
        assert_eq!(report_a.event_counts, report_b.event_counts);
        assert_eq!(report_a.ops_executed, report_b.ops_executed);
        assert_eq!(report_a.end_time, report_b.end_time);
    }

    #[test]
    fn two_phase_converges() {
        let report = default_sim(42, FaultLevel::SunnyDay).run(50, 500);
        assert!(
            report.converged,
            "seed {}: not all shards converged",
            report.seed
        );
    }

    #[test]
    fn zombie_worker_rejected() {
        let report = default_sim(42, FaultLevel::SunnyDay).run(10, 10);
        assert!(
            report.violations.is_empty(),
            "zombie scenario caused violations: {:?}",
            report.violations,
        );
        let rejected = report
            .event_counts
            .get(&SimEventKind::Rejected)
            .copied()
            .unwrap_or(0);
        assert!(
            rejected > 0,
            "expected at least one rejection from zombie scenario"
        );
    }

    /// When the cursor's first byte is one below range_hi and the cursor is
    /// multi-byte, `generate_forward_cursor` must NOT produce a shorter cursor
    /// that is lexicographically less than the previous one.
    #[test]
    fn forward_cursor_no_regression_at_range_boundary() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);

        let worker = WorkerId::from_raw(1);
        let key = sim.shard_keys[0];

        // Advance time so acquire works.
        sim.context.advance(1);

        // Worker acquires the shard.
        let event = sim.execute_op(&SimOp::Acquire { worker, key });
        assert!(matches!(event, SimEvent::AcquireOk { .. }));

        // Manually set the worker's cursor to a multi-byte value near range end.
        // Shard spec range is [b'a', b'z']. A cursor of [b'y', 0x42] means
        // first byte = b'y', so start = b'z' which >= range_hi (b'z').
        let prev_cursor = vec![b'y', 0x42];
        sim.workers.get_mut(&worker).unwrap().record_cursor(
            key.run(),
            key.shard(),
            prev_cursor.clone(),
        );

        // Generate a forward cursor -- must be >= previous.
        let cursor = sim.generate_forward_cursor(worker, key);
        let cursor_key = cursor.last_key().expect("cursor should have a key");

        assert!(
            cursor_key >= prev_cursor.as_slice(),
            "cursor regression: generated {:?} < previous {:?}",
            cursor_key,
            prev_cursor,
        );
    }

    /// After a successful renew, the worker's local lease must reflect the
    /// new deadline from the coordinator.
    #[test]
    fn renew_updates_worker_lease_deadline() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);

        let worker = WorkerId::from_raw(1);
        let key = sim.shard_keys[0];

        sim.context.advance(1);

        // Acquire.
        let event = sim.execute_op(&SimOp::Acquire { worker, key });
        assert!(matches!(event, SimEvent::AcquireOk { .. }));

        let old_deadline = sim
            .workers
            .get(&worker)
            .unwrap()
            .lease_for(&key)
            .unwrap()
            .deadline();

        // Advance time but stay within lease.
        sim.context.advance(50);

        // Renew.
        let event = sim.execute_op(&SimOp::Renew { worker, key });
        match event {
            SimEvent::RenewOk { new_deadline } => {
                let worker_deadline = sim
                    .workers
                    .get(&worker)
                    .unwrap()
                    .lease_for(&key)
                    .unwrap()
                    .deadline();
                assert_eq!(
                    worker_deadline, new_deadline,
                    "worker lease deadline ({worker_deadline:?}) should match \
                     coordinator ({new_deadline:?}) after renew; \
                     old deadline was {old_deadline:?}",
                );
            }
            other => panic!("expected RenewOk, got {other:?}"),
        }
    }

    // -- Multi-tenant (multi-run) isolation -------------------------------------

    /// Interleave operations on shards from two different runs and verify no
    /// invariant violations occur. Since the coordinator uses a single tenant,
    /// this exercises cross-run isolation within the same tenant.
    #[test]
    fn multi_tenant_isolation() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);

        // Add workers.
        for i in 1..=3 {
            sim.add_worker(WorkerId::from_raw(i));
        }

        // Register shards across two runs.
        let run1 = RunId::from_raw(1);
        let run2 = RunId::from_raw(2);
        for i in 1..=3 {
            sim.register_shard(run1, ShardId::from_raw(i));
            sim.register_shard(run2, ShardId::from_raw(i));
        }

        // Seed run records for claim_next_available.
        sim.seed_all_runs();
        // All registered shards start as active (non-terminal).
        sim.active_shard_keys = sim.shard_keys.clone();

        // Run simulation — interleaved ops on both runs' shards.
        let report = sim.run(300, 150);
        assert!(
            report.violations.is_empty(),
            "multi-run isolation: {:?}",
            report.violations,
        );
    }

    // -- generate_forward_cursor edge cases ------------------------------------

    /// Worker with no prior cursor generates a cursor within spec bounds.
    #[test]
    fn generate_forward_cursor_no_prior() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);

        let worker = WorkerId::from_raw(1);
        let key = sim.shard_keys[0];

        // Advance time so acquire works.
        sim.context.advance(1);

        // Acquire the shard.
        let event = sim.execute_op(&SimOp::Acquire { worker, key });
        assert!(matches!(event, SimEvent::AcquireOk { .. }));

        // No prior cursor recorded — generate a fresh one.
        let cursor = sim.generate_forward_cursor(worker, key);
        let cursor_key = cursor.last_key().expect("cursor should have a key");

        // Spec range is [b'a', b'z'). First byte must be in [b'a', b'z').
        let first_byte = cursor_key[0];
        assert!(
            first_byte >= b'a',
            "cursor first byte {first_byte:#x} below spec start 0x61"
        );
        assert!(
            first_byte < b'z',
            "cursor first byte {first_byte:#x} >= spec end 0x7a"
        );
    }

    /// After setting cursor at b'c', next cursor's first byte must be >= b'd'
    /// (strict forward progress).
    #[test]
    fn generate_forward_cursor_forward_progress() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);

        let worker = WorkerId::from_raw(1);
        let key = sim.shard_keys[0];

        sim.context.advance(1);

        let event = sim.execute_op(&SimOp::Acquire { worker, key });
        assert!(matches!(event, SimEvent::AcquireOk { .. }));

        // Record cursor at b'c'.
        sim.workers
            .get_mut(&worker)
            .unwrap()
            .record_cursor(key.run(), key.shard(), vec![b'c']);

        let cursor = sim.generate_forward_cursor(worker, key);
        let cursor_key = cursor.last_key().expect("cursor should have a key");

        assert!(
            cursor_key[0] >= b'd',
            "expected first byte >= 0x64 (b'd'), got {:#x}",
            cursor_key[0],
        );
    }

    /// When cursor is at b'y' and range end is b'z', the range is exhausted.
    /// `generate_forward_cursor` returns the previous cursor (idempotent retry).
    #[test]
    fn generate_forward_cursor_range_exhausted() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);

        let worker = WorkerId::from_raw(1);
        let key = sim.shard_keys[0];

        sim.context.advance(1);

        let event = sim.execute_op(&SimOp::Acquire { worker, key });
        assert!(matches!(event, SimEvent::AcquireOk { .. }));

        // Set cursor at b'y' — start becomes b'z' which >= range_hi (b'z').
        let prev_cursor = vec![b'y'];
        sim.workers.get_mut(&worker).unwrap().record_cursor(
            key.run(),
            key.shard(),
            prev_cursor.clone(),
        );

        let cursor = sim.generate_forward_cursor(worker, key);
        let cursor_key = cursor.last_key().expect("cursor should have a key");

        // Must return the previous cursor since range is exhausted.
        assert_eq!(
            cursor_key,
            prev_cursor.as_slice(),
            "range-exhausted cursor should repeat previous; got {:?}, expected {:?}",
            cursor_key,
            prev_cursor,
        );
    }

    /// With a narrow spec [b'a', b'c'), after setting cursor at b'a', the
    /// next cursor's first byte must be >= b'b' and < b'c'.
    #[test]
    fn generate_forward_cursor_single_byte_range() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);

        // Add one worker.
        let worker = WorkerId::from_raw(1);
        sim.add_worker(worker);

        // Manually seed a shard with narrow spec [b'a', b'c').
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let record = ShardRecord::new_active(
            sim.tenant,
            run,
            shard,
            ShardSpec::with_range(vec![b'a'], vec![b'c']),
            CursorSemantics::Completed,
        );
        sim.coordinator.seed_shard(record);
        let key = ShardKey::new(run, shard);
        sim.shard_keys.push(key);
        sim.active_shard_keys.push(key);

        sim.context.advance(1);

        let event = sim.execute_op(&SimOp::Acquire { worker, key });
        assert!(matches!(event, SimEvent::AcquireOk { .. }));

        // Set cursor at b'a'.
        sim.workers
            .get_mut(&worker)
            .unwrap()
            .record_cursor(run, shard, vec![b'a']);

        let cursor = sim.generate_forward_cursor(worker, key);
        let cursor_key = cursor.last_key().expect("cursor should have a key");

        // First byte must be >= b'b' (forward from b'a') and < b'c' (range end).
        // With spec [b'a', b'c'), the only valid first byte is b'b'.
        let first_byte = cursor_key[0];
        assert_eq!(
            first_byte, b'b',
            "cursor first byte {first_byte:#x} should be 0x62 (b'b') for spec [b'a', b'c')",
        );
    }

    /// Verify the new operation types (split, replay, conflict) are exercised
    /// across multiple seeds. This catches regressions where op generation
    /// weights produce zero coverage.
    #[test]
    fn new_op_types_exercised() {
        let mut split_replace_seen = false;
        let mut split_residual_seen = false;
        let mut replayed_seen = false;
        let mut claim_seen = false;
        let mut session_lifecycle_seen = false;
        // Run with a large enough op count and enough seeds to trigger
        // the probabilistic generation paths.
        for seed in 0..20u64 {
            let report = default_sim(seed, FaultLevel::Stormy).run(1000, 200);
            assert!(
                report.violations.is_empty(),
                "seed {seed}: violations: {:?}",
                report.violations,
            );
            if report
                .event_counts
                .contains_key(&SimEventKind::SplitReplaceOk)
            {
                split_replace_seen = true;
            }
            if report
                .event_counts
                .contains_key(&SimEventKind::SplitResidualOk)
            {
                split_residual_seen = true;
            }
            if report.event_counts.contains_key(&SimEventKind::ReplayedOk) {
                replayed_seen = true;
            }
            if report.event_counts.contains_key(&SimEventKind::ClaimOk) {
                claim_seen = true;
            }
            if report
                .event_counts
                .contains_key(&SimEventKind::SessionLifecycleOk)
            {
                session_lifecycle_seen = true;
            }
        }
        assert!(
            split_replace_seen,
            "SplitReplaceOk never observed across 20 seeds"
        );
        assert!(
            split_residual_seen,
            "SplitResidualOk never observed across 20 seeds"
        );
        assert!(replayed_seen, "ReplayedOk never observed across 20 seeds");
        assert!(claim_seen, "ClaimOk never observed across 20 seeds");
        assert!(
            session_lifecycle_seen,
            "SessionLifecycleOk never observed across 20 seeds"
        );
    }
}
