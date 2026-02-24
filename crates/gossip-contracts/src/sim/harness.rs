//! Full simulation harness for deterministic coordination testing.
//!
//! Drives a [`SimulationBackend`] (defaulting to [`InMemoryCoordinator`]) under
//! configurable fault injection, verifying protocol invariants (S1--S9) at every
//! step. Inspired by FoundationDB's simulation framework and TigerBeetle's VOPR.
//!
//! # Execution model
//!
//! A simulation run consists of three sequential stages:
//!
//! 1. **Zombie scenario** (deterministic preamble): A scripted sequence that
//!    exercises the bookkeeping-cleanup path (B1) by expiring a lease and
//!    re-acquiring on a different worker. Attempted before random ops; it
//!    returns early when fewer than two workers or zero shards are available.
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
//! # Three entry points
//!
//! - **[`CoordinationSim::run`]**: Canned three-stage execution (zombie preamble +
//!   safety phase + liveness phase) that returns a [`SimReport`]. Suitable for
//!   proptest and regression tests.
//! - **[`CoordinationSim::step`]**: Execute a single [`SimOp`] and check
//!   invariants. Suitable for custom simulation loops that need fine-grained
//!   control over operation sequencing.
//! - **[`CoordinationSim::run_overload`]**: Warmup + scripted overload rounds +
//!   bounded recovery, returning an [`OverloadReport`](super::OverloadReport)
//!   with D1/L1 diagnostics.
//!
//! # Key design decisions
//!
//! - **Non-regressing cursors**: [`generate_forward_cursor`](CoordinationSim::generate_forward_cursor)
//!   tracks per-worker cursor progress and generates cursors that are never
//!   less than the previous value (the exhausted-range case may reuse the
//!   previous cursor exactly). Without this, random cursors would frequently
//!   regress, flooding the run with expected `CursorRegression` rejections
//!   that mask real bugs.
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
use rand_chacha::ChaCha8Rng;

use crate::coordination::Lease;
use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, CheckpointError, CompleteError, IdempotentOutcome, ParkError, RenewError,
    SplitError,
};
use crate::coordination::facade::ClaimError;
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::record::{ParkReason, ShardRecord, ShardStatus};
use crate::coordination::run_errors::{RunTransitionError, UnparkError};
use crate::coordination::session::WorkerSession;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::split::{SplitReplaceChild, SplitReplacePlan, SplitResidualPlan};
use crate::identity::{
    FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
};
use crate::sim::backend::SimulationBackend;

use super::invariants::{InvariantChecker, InvariantViolation};
use super::overload::{
    D1Observation, GoodputTracker, OverloadKind, OverloadReport, OverloadScenario,
    generate_burst_claim, generate_burst_shards, generate_capacity_drop,
};
use super::worker::SimWorker;
use super::{FaultConfig, FaultLevel, SimContext};

// ---------------------------------------------------------------------------
// SimOp
// ---------------------------------------------------------------------------

/// Which terminal transition to apply to a run.
///
/// All three share identical coordinator signatures
/// `(now, tenant, run, op_id) -> Result<IdempotentOutcome<()>, RunTransitionError>`
/// so a single `SimOp::TerminateRun { run, kind }` variant covers all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunTerminalKind {
    Complete,
    Fail,
    Cancel,
}

/// A single operation in the simulation.
///
/// Operations fall into four categories:
///
/// - **Coordinator ops** (`Acquire`, `Renew`, `Checkpoint`, `Complete`, `Park`,
///   `SplitReplace`, `SplitResidual`, `ClaimNext`, `SessionLifecycle`): invoke
///   real coordinator methods through the [`SimulationBackend`] trait.
/// - **Admin ops** (`Unpark`, `TerminateRun`): invoke run-management methods
///   that operate outside the worker-lease model (no worker/lease required).
/// - **Idempotency/conflict ops** (`ReplayCheckpoint`, `ConflictCheckpoint`,
///   `ZombieCheckpoint`): exercise edge cases in the coordinator's op-log and
///   fencing protocol.
/// - **Environmental ops** (`AdvanceTime`, `PauseWorker`, `ResumeWorker`):
///   manipulate simulation state (clock, worker health) without touching the
///   coordinator.
///
/// All variants carry sufficient context for the harness to dispatch to the
/// appropriate executor -- most carry `(worker, shard key)`, while
/// environmental ops and `ZombieCheckpoint` carry only what they need.
/// The harness generates ops via weighted random selection in
/// `CoordinationSim::generate_random_op`.
#[derive(Debug, Clone)]
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
    /// acquire → checkpoint(1–3x) → complete|park|split_replace|split_residual+complete.
    ///
    /// Exercises the ergonomic `WorkerSession` wrapper that the real
    /// orchestrator uses. The session holds `&mut coordinator` exclusively,
    /// so invariant checking happens at the session boundary (after drop),
    /// not between individual session operations.
    SessionLifecycle { worker: WorkerId, key: ShardKey },
    /// Unpark a parked shard (admin operation). Transitions Parked→Active
    /// with a fence epoch bump, invalidating prior zombie workers.
    /// No worker field — unpark is not worker-initiated.
    Unpark { key: ShardKey },
    /// Apply a terminal transition (complete/fail/cancel) to a run.
    /// Admin operation — no worker or lease required.
    TerminateRun { run: RunId, kind: RunTerminalKind },
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
    /// Worker's claim was throttled by per-worker cooldown; `retry_after`
    /// indicates the earliest logical time the worker may retry.
    ClaimThrottled { retry_after: LogicalTime },
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
    ///
    /// Carries checkpoint outcome counts so the report accurately reflects
    /// checkpoint throughput during session lifecycles.
    SessionLifecycleOk {
        checkpoints_ok: u32,
        checkpoints_rejected: u32,
    },
    /// WorkerSession lifecycle completed with partial success — acquire succeeded but
    /// one or more checkpoints or the terminal operation failed. This is expected under
    /// fault injection (lease expiry mid-session) but must be visible for coverage analysis.
    SessionLifecyclePartial {
        checkpoints_ok: u32,
        checkpoints_rejected: u32,
    },
    /// Parked shard successfully unparked (admin, Parked→Active + fence bump).
    UnparkOk,
    /// Run terminal transition succeeded (complete/fail/cancel).
    RunTerminalOk { kind: RunTerminalKind },
}

/// Categorized rejection reason (no heap allocation).
///
/// Used instead of `String` to avoid hot-path allocation in fault-heavy
/// simulation modes where a large fraction of operations are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Cursor key exceeds MAX_KEY_SIZE.
    /// Not produced by the built-in harness (cursor generation keeps keys
    /// small), but available for custom `step()` callers.
    CursorKeyTooLarge,
    /// Target worker is paused.
    WorkerPaused,
    /// Worker holds no shards to operate on.
    /// Reserved for external/custom harness integrations; the built-in
    /// operation generators currently do not emit this variant.
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
    /// Target shard is not in Parked status (unpark on non-parked shard).
    NotParked,
    /// No stale lease available for zombie injection.
    NoStaleLease,
    /// No previous checkpoint to replay.
    NoPriorCheckpoint,
    /// Target worker does not exist in the simulation's worker registry.
    WorkerNotFound,
    /// Target run does not exist in the coordinator.
    RunNotFound,
    /// Run is not in the required status for this terminal transition
    /// (e.g., `complete_run` on an `Initializing` run).
    WrongRunStatus,
    /// Byte slab could not satisfy an allocation request.
    ResourceExhausted,
    /// Coordinator returned an error not matching a specific category.
    Other,
}

// -- Error-to-RejectionKind conversions ------------------------------------
//
// Each error variant maps to exactly one RejectionKind, centralizing
// rejection categorization so executor methods can use
// `e.into()` without repeating match arms. The mapping is exhaustive:
// every error variant is covered, and adding a new variant triggers a
// compile error here (thanks to non-wildcard matches).

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
            CheckpointError::CursorKeyTooLarge { .. } => Self::CursorKeyTooLarge,
            CheckpointError::ShardNotFound { .. } => Self::ShardNotFound,
            CheckpointError::TenantMismatch { .. } => Self::TenantMismatch,
            CheckpointError::CheckpointMissingKey => Self::CheckpointMissingKey,
            CheckpointError::ResourceExhausted(_) => Self::ResourceExhausted,
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
            CompleteError::CursorKeyTooLarge { .. } => Self::CursorKeyTooLarge,
            CompleteError::ShardNotFound { .. } => Self::ShardNotFound,
            CompleteError::TenantMismatch { .. } => Self::TenantMismatch,
            CompleteError::CheckpointMissingKey => Self::CheckpointMissingKey,
            CompleteError::ResourceExhausted(_) => Self::ResourceExhausted,
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
            SplitError::ResourceExhausted(_) => Self::ResourceExhausted,
        }
    }
}

impl From<UnparkError> for RejectionKind {
    fn from(e: UnparkError) -> Self {
        match e {
            UnparkError::ShardNotFound => Self::ShardNotFound,
            UnparkError::TenantMismatch { .. } => Self::TenantMismatch,
            UnparkError::RunTerminal { .. } => Self::TerminalState,
            UnparkError::NotParked { .. } => Self::NotParked,
            UnparkError::OpIdConflict(_) => Self::OpIdConflict,
        }
    }
}

impl From<RunTransitionError> for RejectionKind {
    fn from(e: RunTransitionError) -> Self {
        match e {
            RunTransitionError::RunNotFound => Self::RunNotFound,
            RunTransitionError::TenantMismatch { .. } => Self::TenantMismatch,
            RunTransitionError::RunTerminal { .. } => Self::TerminalState,
            RunTransitionError::WrongStatus { .. } => Self::WrongRunStatus,
            RunTransitionError::OpIdConflict(_) => Self::OpIdConflict,
        }
    }
}

/// Payload-free event discriminant for histogram counting.
///
/// Every [`SimEvent`] maps to exactly one `SimEventKind` via its `kind()` method.
/// [`SimReport::event_counts`] aggregates these to summarize operation coverage
/// without carrying per-event payloads. The `Ord` derive enables `BTreeMap`
/// keying for deterministic report output.
///
/// Coverage analysis uses these counts to verify that weighted op generation
/// actually exercises all coordinator paths. A kind with zero count across
/// many seeds indicates a generation weight or precondition bug.
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
    ClaimThrottled,
    Rejected,
    TimeAdvanced,
    WorkerPaused,
    WorkerResumed,
    Skipped,
    SessionLifecycleOk,
    SessionLifecyclePartial,
    UnparkOk,
    RunTerminalOk,
}

impl SimEvent {
    /// Extract the payload-free discriminant for histogram counting.
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
            SimEvent::ClaimThrottled { .. } => SimEventKind::ClaimThrottled,
            SimEvent::Rejected { .. } => SimEventKind::Rejected,
            SimEvent::TimeAdvanced { .. } => SimEventKind::TimeAdvanced,
            SimEvent::WorkerPaused { .. } => SimEventKind::WorkerPaused,
            SimEvent::WorkerResumed { .. } => SimEventKind::WorkerResumed,
            SimEvent::Skipped => SimEventKind::Skipped,
            SimEvent::SessionLifecycleOk { .. } => SimEventKind::SessionLifecycleOk,
            SimEvent::SessionLifecyclePartial { .. } => SimEventKind::SessionLifecyclePartial,
            SimEvent::UnparkOk => SimEventKind::UnparkOk,
            SimEvent::RunTerminalOk { .. } => SimEventKind::RunTerminalOk,
        }
    }
}

// ---------------------------------------------------------------------------
// SessionTerminalAction
// ---------------------------------------------------------------------------

/// Terminal action selection for [`exec_session_lifecycle`](CoordinationSim::exec_session_lifecycle).
///
/// Determines how a `WorkerSession` lifecycle ends. Probabilities assume
/// the shard's byte range is wide enough for splits (at least 2 distinct
/// values between start and end):
///
/// - `Complete` (50%): mark shard done
/// - `Park` (20%): park shard for later retry
/// - `SplitReplace` (20%): replace parent with two children (terminal)
/// - `SplitResidualThenComplete` (10%): shrink parent, create residual,
///   then complete the narrowed parent -- exercises the `WorkerSession`
///   snapshot-rebuild path under simulation fault injection.
///
/// See the `random_range(0u32..10)` match in `exec_session_lifecycle` for
/// the authoritative weight table.
///
/// When the range is too narrow for splits, `SplitReplace` and
/// `SplitResidualThenComplete` fall back to `Complete`, raising its
/// effective rate to up to 80%.
#[derive(Debug, Clone, Copy)]
enum SessionTerminalAction {
    Complete,
    Park,
    SplitReplace,
    SplitResidualThenComplete,
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
    /// Number of shards not in a terminal state at end of run.
    /// Zero when `converged` is true.
    pub non_terminal_count: usize,
}

// ---------------------------------------------------------------------------
// CoordinationSim
// ---------------------------------------------------------------------------

/// Default lease duration (in logical ticks) for the simulated coordinator.
///
/// Balances two competing needs:
/// - **Long enough** that warmup operations (5 ops) can acquire, checkpoint,
///   and renew before expiry, even with small time advances (1--50 ticks each).
/// - **Short enough** that a single Stormy time-jump (50--200 ticks) or two
///   Radioactive time-jumps (100--500 ticks) can expire a lease mid-flight,
///   creating the stale-lease and zombie-worker scenarios the simulation
///   is designed to stress-test.
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
/// omits `Ord` (it is an opaque identity, not an ordered quantity). Each entry
/// stores the `(OpId, Cursor, WorkerId, ShardKey)` from the last successful
/// checkpoint, enabling:
///
/// - [`SimOp::ReplayCheckpoint`]: resubmit the same OpId + same payload to
///   exercise idempotent deduplication.
/// - [`SimOp::ConflictCheckpoint`]: resubmit the same OpId with a *different*
///   payload to exercise at-most-once conflict detection.
///
/// Only the most recent checkpoint per `(worker, run, shard)` is retained.
/// Earlier entries are overwritten, which is correct because the op-log's
/// dedup window is bounded and older ops may already be evicted.
type CheckpointOpMap = BTreeMap<(u64, u64, u64), (OpId, Cursor, WorkerId, ShardKey)>;

/// Validate worker preconditions and consume the next op-ID in one shot.
///
/// Checks that `worker` exists and is not paused (both conditions return
/// `WorkerPaused` — the harness registers all workers at init, so a missing
/// worker is a harness bug, not an expected rejection), holds a lease on `key`,
/// and advances its op-ID counter. Returns the lease and fresh op-ID on
/// success, or a `Rejected` event on failure.
///
/// This is a free function (not `&mut self`) to enable borrow splitting:
/// callers can pass `&mut self.workers` while retaining mutable access to
/// `self.coordinator`, `self.context`, and other fields. Without this
/// split, the borrow checker would reject code that reads a lease from
/// `self.workers` and then calls `self.coordinator.checkpoint(...)` in
/// the same expression.
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

/// Compute a random split midpoint in the half-open interval `[lo, hi)`.
///
/// Returns `None` when the interval is empty (`lo >= hi`).
/// Used by the precompute functions (session lifecycle Phase 1) and
/// `compute_split_byte` (standalone split ops) to eliminate the duplicated
/// range-check + sample pattern.
fn random_midpoint(rng: &mut ChaCha8Rng, lo: u8, hi: u8) -> Option<u8> {
    if lo >= hi {
        return None;
    }
    Some(rng.random_range(lo..hi))
}

/// Pre-compute a split-replace plan from the parent's key range.
///
/// Chooses a random midpoint to divide the parent's `[range_lo, range_hi)`
/// range into two children. Returns `None` when the range is too narrow for
/// a valid split (fewer than 2 byte values between lo and hi).
///
/// This duplicates the plan construction logic from
/// [`CoordinationSim::exec_split_replace`] — if that function's split-point
/// selection changes, update this function to match. Operates on bare range
/// bounds and an external RNG so it can run *before* the exclusive coordinator
/// borrow in `exec_session_lifecycle`.
fn precompute_split_replace_plan(
    rng: &mut ChaCha8Rng,
    range_lo: u8,
    range_hi: u8,
) -> Option<SplitReplacePlan> {
    let mid = random_midpoint(rng, range_lo + 1, range_hi)?;
    let child_a = ShardSpec::with_range(vec![range_lo], vec![mid]);
    let child_b = ShardSpec::with_range(vec![mid], vec![range_hi]);
    match SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(child_a, Cursor::initial()),
        SplitReplaceChild::new(child_b, Cursor::initial()),
    ]) {
        Ok(plan) => Some(plan),
        Err(e) => {
            debug_assert!(
                false,
                "precompute_split_replace_plan: validated range produced invalid plan: {e:?}"
            );
            None
        }
    }
}

/// Pre-compute a split-residual plan and a post-split completion cursor.
///
/// Chooses a random midpoint *after* `last_checkpoint_byte` so the parent
/// retains all previously scanned data. Returns the plan and a cursor
/// suitable for completing the narrowed parent after the split.
///
/// `last_checkpoint_byte` is the first byte of the last checkpoint cursor
/// in the pre-computed sequence — the split point must land after it so the
/// narrowed parent's range still covers every byte the session checkpointed.
///
/// Returns `None` when the range is too narrow for a valid split.
///
/// This duplicates the plan construction logic from
/// [`CoordinationSim::exec_split_residual`] — if that function's split-point
/// selection changes, update this function to match. Operates on bare range
/// bounds and an external RNG so it can run *before* the exclusive coordinator
/// borrow in `exec_session_lifecycle`.
fn precompute_split_residual_plan(
    rng: &mut ChaCha8Rng,
    range_lo: u8,
    range_hi: u8,
    last_checkpoint_byte: u8,
) -> Option<(SplitResidualPlan, Cursor)> {
    let split_lo = last_checkpoint_byte.saturating_add(1).max(range_lo + 1);
    let mid = random_midpoint(rng, split_lo, range_hi)?;
    let new_parent = ShardSpec::with_range(vec![range_lo], vec![mid]);
    let residual = ShardSpec::with_range(vec![mid], vec![range_hi]);
    match SplitResidualPlan::try_new(new_parent, residual) {
        Ok(plan) => Some(plan),
        Err(e) => {
            debug_assert!(
                false,
                "precompute_split_residual_plan: validated range produced invalid plan: {e:?}"
            );
            None
        }
    }
    .map(|plan| {
        let complete_byte = if last_checkpoint_byte < mid.saturating_sub(1) {
            rng.random_range(last_checkpoint_byte.saturating_add(1)..mid)
        } else {
            // Range is very tight — reuse the last checkpoint byte.
            last_checkpoint_byte.min(mid.saturating_sub(1))
        };
        (plan, Cursor::with_last_key(vec![complete_byte]))
    })
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
/// | `stale_leases` | Superseded leases for zombie checkpoint injection. Capped at `MAX_STALE_LEASES`. |
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
    /// Monotonic op-ID counter for admin operations (`Unpark`, `TerminateRun`).
    /// Uses partition 0 (workers start at 1), guaranteeing no collisions.
    admin_next_op: u64,
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

    /// Enable per-worker claim cooldown for the simulation.
    ///
    /// Replaces the internal coordinator with one configured for the
    /// given `interval`. Must be called **before**
    /// [`with_workers_and_shards`](Self::with_workers_and_shards) --
    /// calling it after seeding discards registered shards and runs.
    ///
    /// An interval of 0 disables throttling (the default when
    /// constructed via [`new`](Self::new)).
    pub fn with_cooldown(mut self, interval: u64) -> Self {
        self.coordinator = InMemoryCoordinator::with_cooldown(
            DEFAULT_LEASE_DURATION,
            100_000,
            1_000_000,
            interval,
        );
        self.checker.set_cooldown_interval(interval);
        self
    }

    /// Register a shard in the coordinator with a default spec range `[b'a', b'z')`.
    ///
    /// The 25-byte range (`b'a'`..`b'z'`) is wide enough for multiple cascaded
    /// splits (each split needs at least 2 byte values) while staying within
    /// printable ASCII for readable test output.
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
            &ShardSpec::with_range(vec![b'a'], vec![b'z']),
            CursorSemantics::Completed,
            self.coordinator.slab_mut(),
        )
        .expect("slab large enough for test shard");
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

    /// Run a three-phase overload simulation and return a rich report.
    ///
    /// Phases:
    /// 1. warmup (`warmup_ops`) to establish baseline leases
    /// 2. scripted overload rounds (`scenario.rounds`)
    /// 3. bounded recovery (`recovery_ops`) with periodic claim injection
    ///
    /// Consumes `self` to prevent accidental state reuse.
    pub fn run_overload(
        mut self,
        warmup_ops: usize,
        scenario: OverloadScenario,
        recovery_ops: usize,
    ) -> OverloadReport {
        let mut all_violations = Vec::new();
        let mut event_counts = BTreeMap::new();
        let mut overload_goodput = GoodputTracker::default();
        let mut d1_observations = Vec::new();

        // Move clock off ZERO before lease-bearing operations.
        let initial_ticks = self.context.rng().random_range(1u64..=10);
        self.context.advance(initial_ticks);

        // Keep parity with the regular harness run model.
        self.inject_zombie_scenario(&mut all_violations, &mut event_counts);

        // Phase 1: warmup (faults suppressed for the first WARMUP_OPS ops).
        for i in 0..warmup_ops {
            let suppress_faults = i < WARMUP_OPS;
            let op = self.generate_random_op(suppress_faults);
            let (event, violations) = self.step(op);
            *event_counts.entry(event.kind()).or_insert(0) += 1;
            all_violations.extend(violations);
        }

        let run = self
            .run_shard_ids
            .keys()
            .next()
            .copied()
            .unwrap_or_else(|| RunId::from_raw(1));

        // Phase 2: scripted overload rounds.
        for _ in 0..scenario.rounds {
            let workers: Vec<WorkerId> = self.workers.keys().copied().collect();
            let held_shards: Vec<(WorkerId, ShardKey)> = workers
                .iter()
                .flat_map(|worker| {
                    self.workers
                        .get(worker)
                        .into_iter()
                        .flat_map(|w| w.held_keys().copied().map(|key| (*worker, key)))
                })
                .collect();

            let scripted_ops = match scenario.kind {
                OverloadKind::BurstClaim => generate_burst_claim(&workers),
                OverloadKind::CapacityDrop => generate_capacity_drop(&workers),
                OverloadKind::BurstShards => generate_burst_shards(&workers, &held_shards),
            };

            for op in scripted_ops {
                let (event, violations) = self.step(op);
                overload_goodput.record(&event);
                *event_counts.entry(event.kind()).or_insert(0) += 1;
                all_violations.extend(violations);

                if matches!(event, SimEvent::AcquireOk { .. } | SimEvent::ClaimOk { .. }) {
                    let now = self.context.now();
                    let reported = self
                        .coordinator
                        .count_available_for_run(now, self.tenant, run)
                        .available_count;
                    let ground_truth = self.count_available_ground_truth(run, now);
                    d1_observations.push(D1Observation {
                        at: now,
                        reported,
                        ground_truth,
                    });
                }
            }
        }

        // Phase 3 prelude: resume all paused workers explicitly.
        let workers: Vec<WorkerId> = self.workers.keys().copied().collect();
        for worker in workers {
            if self.workers.get(&worker).is_some_and(|w| w.is_paused()) {
                let (event, violations) = self.step(SimOp::ResumeWorker { worker });
                *event_counts.entry(event.kind()).or_insert(0) += 1;
                all_violations.extend(violations);
            }
        }

        // Phase 3: bounded recovery with periodic claim injection.
        let mut l1_any_completed = false;
        let mut l1_claim_attempts: u64 = 0;
        let mut l1_claim_successes: u64 = 0;

        for i in 0..recovery_ops {
            let maybe_claim = if i % 10 == 0 {
                self.pick_random_active_worker()
                    .map(|worker| SimOp::ClaimNext { worker })
            } else {
                None
            };
            let op = maybe_claim.unwrap_or_else(|| self.generate_liveness_op());
            if matches!(op, SimOp::ClaimNext { .. }) {
                l1_claim_attempts += 1;
            }

            let (event, violations) = self.step(op);
            if matches!(event, SimEvent::ClaimOk { .. }) {
                l1_claim_successes += 1;
            }
            if matches!(event, SimEvent::CompleteOk) {
                l1_any_completed = true;
            }
            *event_counts.entry(event.kind()).or_insert(0) += 1;
            all_violations.extend(violations);
        }

        let l1_claim_success_rate = if l1_claim_attempts == 0 {
            0.0
        } else {
            l1_claim_successes as f64 / l1_claim_attempts as f64
        };
        let l1_passed = l1_any_completed;

        OverloadReport {
            ops_executed: self.ops_executed,
            violations: all_violations,
            event_counts,
            seed: self.context.seed(),
            end_time: self.context.now(),
            overload_goodput: overload_goodput.rate(),
            d1_observations,
            l1_any_completed,
            l1_claim_success_rate,
            l1_passed,
        }
    }
}

// ============================================================================
// Generic simulation logic
// ============================================================================

impl<B: SimulationBackend> CoordinationSim<B> {
    /// Create a simulation harness with a custom [`SimulationBackend`].
    ///
    /// Use this when you need a non-default backend (e.g., a mock or a
    /// backend with custom lease durations). The backend is used as-is;
    /// callers are responsible for seeding shards and configuring run
    /// records before calling [`run`](Self::run) or [`step`](Self::step).
    /// The tenant is fixed at `TenantId::from_bytes([0x01; 32])`.
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
            admin_next_op: 0,
        }
    }

    /// Add a worker to the simulation.
    ///
    /// # Panics
    ///
    /// Panics if `id` is 0. Partition 0 is reserved for admin operations
    /// (e.g. unpark); allowing worker 0 would produce op-ID collisions.
    pub fn add_worker(&mut self, id: WorkerId) {
        assert!(
            id.as_raw() != 0,
            "worker ID 0 is reserved — partition 0 is used for admin op-IDs"
        );
        self.workers.insert(id, SimWorker::new(id));
    }

    /// Execute a single step: run the operation, then check **all** invariants.
    ///
    /// Every operation—successful or rejected—is followed by a full invariant
    /// sweep (S1–S9). This is the core simulation guarantee: no operation can
    /// leave the coordinator in a state that violates any checked invariant
    /// without immediate detection.
    pub fn step(&mut self, op: SimOp) -> (SimEvent, Vec<InvariantViolation>) {
        let event = self.execute_op(&op);
        self.ops_executed += 1;
        if let (SimOp::ClaimNext { worker }, SimEvent::ClaimOk { .. }) = (&op, &event) {
            self.checker
                .record_claim_success(*worker, self.context.now());
        }

        let violations = self
            .checker
            .check_all(&self.coordinator, self.tenant, self.context.now());
        (event, violations)
    }

    /// Run a complete simulation and consume the harness, returning a report.
    ///
    /// Execution proceeds in three stages (see module docs):
    ///
    /// 1. **Zombie preamble**: One scripted acquire-expire-reacquire-checkpoint
    ///    sequence that deterministically exercises the B1 bookkeeping cleanup
    ///    path.
    /// 2. **Safety phase** (`safety_ops` random ops): The first `WARMUP_OPS`
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

        // Advance clock off ZERO before any coordinator op. The coordinator
        // requires `now > LogicalTime::ZERO` for lease deadline computation
        // (a lease at time 0 would have deadline 0+duration, and checking
        // "is expired" at time 0 against deadline 0 is an ambiguous boundary).
        // The random offset (1--10) also exercises slightly different initial
        // clock positions across seeds.
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
        let non_terminal_count = if converged {
            0
        } else {
            self.shard_keys
                .iter()
                .filter(|k| {
                    self.coordinator
                        .shard_lookup(&self.tenant, k)
                        .is_some_and(|r| !r.status.is_terminal())
                })
                .count()
        };

        SimReport {
            ops_executed: self.ops_executed,
            violations: all_violations,
            event_counts,
            seed: self.context.seed(),
            end_time: self.context.now(),
            converged,
            non_terminal_count,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Remove a single shard key from `active_shard_keys`.
    ///
    /// Uses `position` + `swap_remove` instead of `retain`. Both scan the full
    /// Vec, but `swap_remove` moves only one element (a swap) whereas `retain`
    /// shifts all subsequent elements down by one. Order does not matter because
    /// the only consumer (`pick_random_shard_key`) accesses by random index.
    fn remove_active_shard(&mut self, key: ShardKey) {
        if let Some(pos) = self.active_shard_keys.iter().position(|k| *k == key) {
            self.active_shard_keys.swap_remove(pos);
        }
    }

    /// Release a shard from its owning worker and remove it from the active set.
    ///
    /// Consolidates the two-step terminal-shard bookkeeping
    /// (worker release + active-set removal) used by `exec_complete`,
    /// `exec_park`, `exec_split_replace`, and `exec_session_lifecycle`.
    fn mark_shard_terminal(&mut self, worker: WorkerId, key: ShardKey) {
        if let Some(w) = self.workers.get_mut(&worker) {
            w.record_release(&key);
        }
        self.remove_active_shard(key);
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

            SimOp::Unpark { key } => self.exec_unpark(*key),

            SimOp::TerminateRun { run, kind } => self.exec_run_terminal(*run, *kind),

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

    /// Route a lease-lifecycle op to the appropriate executor.
    ///
    /// Separated from [`execute_op`](Self::execute_op) to keep the top-level
    /// dispatch readable. The split between lease ops, split ops, and replay
    /// ops mirrors the three categories in [`SimOp`]'s doc comment.
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

    /// Route a split op to the appropriate executor.
    fn execute_split_op(&mut self, op: &SimOp, worker: WorkerId, key: ShardKey) -> SimEvent {
        match op {
            SimOp::SplitReplace { .. } => self.exec_split_replace(worker, key),
            SimOp::SplitResidual { .. } => self.exec_split_residual(worker, key),
            _ => unreachable!("execute_split_op called with non-split op"),
        }
    }

    /// Route an idempotency/conflict op to the appropriate executor.
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
                self.mark_shard_terminal(worker, key);
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
                self.mark_shard_terminal(worker, key);
                SimEvent::ParkOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Generate the next admin op-ID from the reserved partition 0.
    ///
    /// Worker IDs start at 1, so partition 0 `[0, OP_ID_PARTITION)` is unused
    /// by workers. Admin operations (`Unpark`, `TerminateRun`) draw from this
    /// partition so they cannot collide with worker-generated op-IDs.
    fn next_admin_op_id(&mut self) -> OpId {
        assert!(
            self.admin_next_op < super::worker::OP_ID_PARTITION,
            "admin op-ID partition exhausted"
        );
        let id = OpId::from_raw(self.admin_next_op);
        self.admin_next_op += 1;
        id
    }

    /// Execute an admin unpark operation on a parked shard.
    ///
    /// On success: transitions Parked→Active, bumps fence_epoch, adds the
    /// shard back to `active_shard_keys` (it was removed when parked).
    /// The `is_executed()` guard is defensive — `next_admin_op_id()` always
    /// produces a fresh op-ID, so replays won't occur through this path,
    /// but the check prevents double-push if the caller model ever changes.
    fn exec_unpark(&mut self, key: ShardKey) -> SimEvent {
        let op_id = self.next_admin_op_id();
        let now = self.context.now();
        match self.coordinator.unpark_shard(now, self.tenant, key, op_id) {
            Ok(outcome) => {
                if outcome.is_executed() {
                    self.active_shard_keys.push(key);
                }
                SimEvent::UnparkOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Execute a run terminal transition (complete, fail, or cancel).
    ///
    /// On success: `debug_assert!` that the outcome is executed (fresh op-ID
    /// means replay never occurs). No harness-side mutation is required: run
    /// status is coordinator-owned. This intentionally keeps shard lifecycle
    /// ops available while letting the coordinator reject run-scoped admin
    /// actions (for example, unpark after a run is terminal).
    ///
    /// On error: converts `RunTransitionError` to `RejectionKind` via the
    /// exhaustive `From` impl.
    fn exec_run_terminal(&mut self, run: RunId, kind: RunTerminalKind) -> SimEvent {
        let op_id = self.next_admin_op_id();
        let now = self.context.now();
        let result = match kind {
            RunTerminalKind::Complete => {
                self.coordinator.complete_run(now, self.tenant, run, op_id)
            }
            RunTerminalKind::Fail => self.coordinator.fail_run(now, self.tenant, run, op_id),
            RunTerminalKind::Cancel => self.coordinator.cancel_run(now, self.tenant, run, op_id),
        };
        match result {
            Ok(outcome) => {
                debug_assert!(
                    outcome.is_executed(),
                    "fresh admin op-ID should never replay"
                );
                SimEvent::RunTerminalOk { kind }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    // -----------------------------------------------------------------------
    // Split helpers
    // -----------------------------------------------------------------------

    /// Look up a shard's spec from the coordinator, returning a rejection
    /// event if the shard does not exist.
    ///
    /// This helper intentionally materializes an owned spec because split-plan
    /// builders own their `ShardSpec`s. Other harness paths prefer borrowed
    /// accessors (`spec_bounds`, `cursor_last_key`) to avoid extra copies.
    fn lookup_shard_spec(&self, key: ShardKey) -> Result<ShardSpec, SimEvent> {
        match self.coordinator.shard_lookup(&self.tenant, &key) {
            Some(record) => Ok(self.coordinator.materialize_spec(record)),
            None => Err(SimEvent::Rejected {
                kind: RejectionKind::ShardNotFound,
            }),
        }
    }

    /// Compute a random single-byte split point strictly within `(start[0], end[0])`.
    ///
    /// Uses only the first byte of each bound for simplicity. This is a
    /// deliberate simulation trade-off: real splits could use multi-byte
    /// midpoints, but single-byte splits are sufficient to exercise the
    /// split protocol and keep the key-space manageable across cascaded splits.
    ///
    /// Returns `Err(Rejected)` if the range is too narrow (fewer than 2 byte
    /// values between start and end), which naturally occurs after repeated
    /// splits shrink a shard's range down to adjacent bytes.
    fn compute_split_byte(&mut self, start: &[u8], end: &[u8]) -> Result<u8, SimEvent> {
        if start.is_empty() || end.is_empty() || start >= end || end[0] - start[0] < 2 {
            return Err(SimEvent::Rejected {
                kind: RejectionKind::SplitValidation,
            });
        }
        random_midpoint(self.context.rng(), start[0] + 1, end[0]).ok_or(SimEvent::Rejected {
            kind: RejectionKind::SplitValidation,
        })
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
                // Register child shards so future ops can exercise them.
                let run = key.run();
                for &child_id in &children {
                    let child_key = ShardKey::new(run, child_id);
                    self.shard_keys.push(child_key);
                    self.active_shard_keys.push(child_key);
                }
                // Parent is now terminal — release and remove.
                self.mark_shard_terminal(worker, key);
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
            .and_then(|r| self.coordinator.cursor_last_key(r).map(|k| k.to_vec()));

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

    /// Replay a previous checkpoint with the same OpId and identical payload.
    ///
    /// The coordinator's op-log deduplicates by `OpId`: if the entry is still
    /// cached and the payload hash matches, it returns `Replayed` without
    /// re-applying the mutation. If the op-log entry was evicted (bounded
    /// log), the coordinator treats it as a fresh execution (`Executed`).
    /// Both outcomes are correct; the test verifies neither panics nor
    /// violates invariants.
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

    /// Replay a previous OpId with a *different* cursor payload.
    ///
    /// When the op-log still holds the original entry, the payload hash
    /// mismatch triggers `OpIdConflict` -- detecting an at-most-once
    /// violation (same op ID, different intent). When the entry is evicted,
    /// the coordinator treats it as a fresh checkpoint, which is also
    /// correct (the bounded op-log provides best-effort dedup, not a
    /// guarantee).
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
                    kind: RejectionKind::WorkerNotFound,
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
                // A stale lease succeeding means the coordinator failed to
                // reject a write from a worker that no longer owns the shard.
                // This is a fundamental fencing protocol violation, not a
                // recoverable error, so we panic rather than log a violation.
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
            Err(ClaimError::NoneAvailable { .. }) => SimEvent::ClaimNoneAvailable,
            Err(ClaimError::Throttled { retry_after }) => SimEvent::ClaimThrottled { retry_after },
            Err(ClaimError::RunNotFound) => SimEvent::Rejected {
                kind: RejectionKind::RunNotFound,
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
    /// - complete (8%) and park (3%) are terminal (over-weighting starves coverage)
    /// - unpark (2%) exercises Parked→Active reversion with fence bump (S3 exemption)
    /// - split_replace (4%) and split_residual (4%) exercise split paths
    /// - replay (2%) and conflict (2%) exercise idempotency
    /// - zombie (3%) exercises stale-fence rejection
    /// - claim_next (3%) exercises the list-then-acquire retry loop
    /// - session_lifecycle (8%) exercises WorkerSession wrapper end-to-end
    /// - time advances (9%) create expiry windows
    /// - pause (8%) and resume (6%) model worker failures
    /// - terminate_run (2%) exercises run-level terminal transitions
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
                    44..47 => self.try_gen_park(),
                    47..49 => self.try_gen_unpark(),
                    49..53 => self.try_gen_split_replace(),
                    53..57 => self.try_gen_split_residual(),
                    57..59 => self.try_gen_replay_checkpoint(),
                    59..61 => self.try_gen_conflict_checkpoint(),
                    61..64 => self.try_gen_zombie_checkpoint(),
                    64..67 => self.try_gen_claim_next(),
                    67..75 => self.try_gen_session_lifecycle(),
                    75..84 => Some(self.gen_advance_time()),
                    84..92 => self.try_gen_pause(),
                    92..94 => self.try_gen_terminate_run(),
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

    /// Pick a random active worker and a random non-terminal shard for an acquire op.
    ///
    /// Unlike the `try_gen_held_shard_op` family, acquire targets any active
    /// shard (not just one the worker already holds), modeling contention.
    fn try_gen_acquire(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let key = self.pick_random_shard_key()?;
        Some(SimOp::Acquire { worker, key })
    }

    /// Pick a random active worker for a claim-next op.
    ///
    /// No shard key is needed — `claim_next_available` discovers the shard
    /// internally via the coordinator's run record.
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

    /// Pick a random parked shard for an admin unpark operation.
    ///
    /// Scans all `shard_keys` via coordinator lookup — O(N) where N is the
    /// total shard count (including terminal). Acceptable for simulation
    /// sizes (15–200 shards). Returns `None` if no parked shards exist
    /// (the op will be retried by `generate_random_op`'s retry loop,
    /// eventually falling back to AdvanceTime).
    fn try_gen_unpark(&mut self) -> Option<SimOp> {
        let is_parked = |k: &&ShardKey| {
            self.coordinator
                .shard_lookup(&self.tenant, k)
                .is_some_and(|r| r.status == ShardStatus::Parked)
        };
        let count = self.shard_keys.iter().filter(is_parked).count();
        if count == 0 {
            return None;
        }
        let idx = self.context.rng().random_range(0..count);
        let key = *self.shard_keys.iter().filter(is_parked).nth(idx)?;
        Some(SimOp::Unpark { key })
    }

    /// Pick a run and a random terminal kind for a run-termination op.
    ///
    /// Guards on `run_shard_ids` being non-empty (backends created via
    /// `with_backend()` may have no seeded runs). Picks a run uniformly
    /// across seeded run IDs (not weighted by shard count), then picks a
    /// terminal kind uniformly.
    /// No suppression after first success — subsequent attempts naturally
    /// exercise the `RunTerminal` rejection path (terminal irreversibility).
    fn try_gen_terminate_run(&mut self) -> Option<SimOp> {
        if self.run_shard_ids.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..self.run_shard_ids.len());
        let run = *self.run_shard_ids.keys().nth(idx)?;
        let kind = match self.context.rng().random_range(0u32..3) {
            0 => RunTerminalKind::Complete,
            1 => RunTerminalKind::Fail,
            _ => RunTerminalKind::Cancel,
        };
        Some(SimOp::TerminateRun { run, kind })
    }

    /// Generate a time-advance op with 1--50 ticks.
    ///
    /// The upper bound (50) is below `DEFAULT_LEASE_DURATION` (100), so a
    /// single time advance cannot expire a freshly acquired lease. Lease
    /// expiry during the safety phase requires either multiple advances or
    /// a fault-injected time jump (50--500 ticks depending on fault level).
    fn gen_advance_time(&mut self) -> SimOp {
        let ticks = self.context.rng().random_range(1u64..=50);
        SimOp::AdvanceTime { ticks }
    }

    /// Select a random active (non-paused) worker to pause.
    fn try_gen_pause(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        Some(SimOp::PauseWorker { worker })
    }

    /// Select a uniformly random *paused* worker and generate a resume op.
    ///
    /// Returns `None` when no workers are paused (symmetric with
    /// `try_gen_pause` which returns `None` when all workers are paused).
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

    /// Pick a random entry from the checkpoint history for idempotent replay.
    ///
    /// Returns `None` when no checkpoints have been recorded yet, which is
    /// the expected early-simulation case before any checkpoint succeeds.
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

    /// Pick a random entry from the checkpoint history for conflict testing.
    ///
    /// Same selection logic as [`try_gen_replay_checkpoint`](Self::try_gen_replay_checkpoint);
    /// the conflict (different payload, same OpId) is constructed at execution time.
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

    /// Generate a zombie checkpoint op if stale leases are available.
    fn try_gen_zombie_checkpoint(&mut self) -> Option<SimOp> {
        if self.stale_leases.is_empty() {
            return None;
        }
        Some(SimOp::ZombieCheckpoint)
    }

    /// Pick a random active worker and a random non-terminal shard for a
    /// full session lifecycle.
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

        // Borrow this shard's bounds from the coordinator and clone only the
        // two boundary slices needed for local RNG range calculations.
        let (spec_start, spec_end) = self
            .coordinator
            .shard_lookup(&self.tenant, &key)
            .map(|r| {
                let (start, end) = self.coordinator.spec_bounds(r);
                (start.to_vec(), end.to_vec())
            })
            .expect("generate_forward_cursor: shard missing from coordinator -- harness bug");

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

        // The checkpoint must have been rejected with NotLeased (B1 cleanup
        // cleared Worker A's lease when Worker B acquired).
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
    /// acquire → checkpoint(1–3x) → complete|park|split_replace|split_residual+complete
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

        // --- Phase 1: Pre-compute all random decisions (touches self.context only) ---
        //
        // Every RNG call that determines session behavior happens here, before
        // the coordinator borrow begins. This keeps the PRNG stream position
        // deterministic regardless of which session operations succeed or fail.

        // Look up spec bounds before session acquires exclusive coordinator access.
        let (range_lo, range_hi) = self
            .coordinator
            .shard_lookup(&self.tenant, &key)
            .map(|r| {
                let (start, end) = self.coordinator.spec_bounds(r);
                let lo = start.first().copied().unwrap_or(b'a');
                let hi = end.first().copied().unwrap_or(b'z');
                (lo, hi)
            })
            .expect("exec_session_lifecycle: shard missing from coordinator -- harness bug");

        let num_checkpoints: u32 = self.context.rng().random_range(1..=3);

        // Choose terminal action: 50% complete, 20% park, 20% split_replace,
        // 10% split_residual+complete. Splits require enough byte range (≥2
        // values between lo and hi); fall back to complete if the range is
        // too narrow.
        let range_wide_enough = range_hi.saturating_sub(range_lo) >= 2;
        let terminal_action = match self.context.rng().random_range(0u32..10) {
            0..2 => SessionTerminalAction::Park,
            2..4 if range_wide_enough => SessionTerminalAction::SplitReplace,
            4 if range_wide_enough => SessionTerminalAction::SplitResidualThenComplete,
            _ => SessionTerminalAction::Complete,
        };

        // Build forward-progressing cursor sequence.
        // split_residual+complete needs one extra cursor (split op + complete).
        let extra_ops = match terminal_action {
            SessionTerminalAction::SplitResidualThenComplete => 2,
            _ => 1,
        };
        let total_cursors = num_checkpoints as usize + extra_ops;
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

        // Pre-compute split plans (if applicable) while we still have
        // mutable access to self.context for the RNG.
        let split_replace_plan = if matches!(terminal_action, SessionTerminalAction::SplitReplace) {
            precompute_split_replace_plan(self.context.rng(), range_lo, range_hi)
        } else {
            None
        };

        let split_residual_plan = if matches!(
            terminal_action,
            SessionTerminalAction::SplitResidualThenComplete
        ) {
            let last_cp_byte = cursors
                .get(num_checkpoints.saturating_sub(1) as usize)
                .and_then(|c| c.last_key().and_then(|k| k.first().copied()))
                .unwrap_or(range_lo);
            precompute_split_residual_plan(self.context.rng(), range_lo, range_hi, last_cp_byte)
        } else {
            None
        };

        // Normalize split actions to Complete when the plan could not be constructed,
        // so the match below has a single Complete path instead of duplicated fallbacks.
        let terminal_action = match terminal_action {
            SessionTerminalAction::SplitReplace if split_replace_plan.is_none() => {
                SessionTerminalAction::Complete
            }
            SessionTerminalAction::SplitResidualThenComplete if split_residual_plan.is_none() => {
                SessionTerminalAction::Complete
            }
            other => other,
        };

        // Generate op IDs from the worker.
        let w = match self.workers.get_mut(&worker) {
            Some(w) => w,
            None => return SimEvent::Skipped,
        };
        let op_ids: Vec<OpId> = (0..total_cursors).map(|_| w.next_op_id()).collect();

        // --- Phase 2: Execute session (borrows only self.coordinator) -----------
        //
        // The session holds &mut self.coordinator exclusively, preventing any
        // sim-level observation (invariant checking, shard lookups) until it
        // drops. All results are captured in SessionOutcome and reconciled
        // with sim bookkeeping in Phase 3 below.

        struct SessionOutcome {
            lease: Lease,
            is_terminal: bool,
            checkpoints_ok: u32,
            checkpoints_rejected: u32,
            split_children: Vec<ShardId>,
        }

        let now = self.context.now();
        let tenant = self.tenant;

        let session_result: Result<SessionOutcome, SimEvent> = (|| {
            let mut sess = WorkerSession::new(&mut self.coordinator, now, tenant, key, worker)
                .map_err(|e| SimEvent::Rejected {
                    kind: RejectionKind::from(e),
                })?;

            let lease = *sess.lease();

            // Checkpoint phase — track outcomes for event reporting.
            let mut checkpoints_ok: u32 = 0;
            let mut checkpoints_rejected: u32 = 0;
            for i in 0..num_checkpoints as usize {
                match sess.checkpoint(now, cursors[i].clone(), op_ids[i]) {
                    Ok(_) => checkpoints_ok += 1,
                    Err(e) => {
                        debug_assert!(
                            !matches!(
                                e,
                                CheckpointError::TenantMismatch { .. }
                                    | CheckpointError::ShardNotFound { .. }
                            ),
                            "session checkpoint hit impossible error: {e:?}"
                        );
                        checkpoints_rejected += 1;
                    }
                }
            }

            // Terminal phase — dispatch based on pre-computed action.
            let terminal_idx = num_checkpoints as usize;
            match terminal_action {
                SessionTerminalAction::Park => {
                    let is_terminal = sess
                        .park(now, ParkReason::Other, op_ids[terminal_idx])
                        .is_ok();
                    Ok(SessionOutcome {
                        lease,
                        is_terminal,
                        checkpoints_ok,
                        checkpoints_rejected,
                        split_children: Vec::new(),
                    })
                }
                SessionTerminalAction::Complete => {
                    let is_terminal = match sess.complete(
                        now,
                        cursors[terminal_idx].clone(),
                        op_ids[terminal_idx],
                    ) {
                        Ok(_) => true,
                        Err(e) => {
                            debug_assert!(
                                !matches!(
                                    e,
                                    CompleteError::TenantMismatch { .. }
                                        | CompleteError::ShardNotFound { .. }
                                ),
                                "session complete hit impossible error: {e:?}"
                            );
                            false
                        }
                    };
                    Ok(SessionOutcome {
                        lease,
                        is_terminal,
                        checkpoints_ok,
                        checkpoints_rejected,
                        split_children: Vec::new(),
                    })
                }
                SessionTerminalAction::SplitReplace => {
                    let plan = split_replace_plan
                        .expect("terminal_action normalized away SplitReplace without plan");
                    match sess.split_replace(now, plan, op_ids[terminal_idx]) {
                        Ok(outcome) => {
                            let children = outcome.into_inner().children;
                            Ok(SessionOutcome {
                                lease,
                                is_terminal: true,
                                checkpoints_ok,
                                checkpoints_rejected,
                                split_children: children,
                            })
                        }
                        Err(e) => {
                            debug_assert!(
                                !matches!(
                                    e,
                                    SplitError::TenantMismatch { .. }
                                        | SplitError::ShardNotFound { .. }
                                ),
                                "session split_replace hit impossible error: {e:?}"
                            );
                            Ok(SessionOutcome {
                                lease,
                                is_terminal: false,
                                checkpoints_ok,
                                checkpoints_rejected,
                                split_children: Vec::new(),
                            })
                        }
                    }
                }
                SessionTerminalAction::SplitResidualThenComplete => {
                    let (plan, complete_cursor) = split_residual_plan.expect(
                        "terminal_action normalized away SplitResidualThenComplete without plan",
                    );
                    // split_residual is non-terminal (&mut self) — session stays active.
                    let split_ok = match sess.split_residual(now, plan, op_ids[terminal_idx]) {
                        Ok(_) => true,
                        Err(e) => {
                            debug_assert!(
                                !matches!(
                                    e,
                                    SplitError::TenantMismatch { .. }
                                        | SplitError::ShardNotFound { .. }
                                ),
                                "session split_residual hit impossible error: {e:?}"
                            );
                            false
                        }
                    };
                    if split_ok {
                        // Extract the residual shard ID from the narrowed session.
                        let residual_id = sess.initial_snapshot().spawned().last().copied();
                        // Complete the (now-narrowed) parent.
                        let complete_idx = terminal_idx + 1;
                        let is_terminal =
                            match sess.complete(now, complete_cursor, op_ids[complete_idx]) {
                                Ok(_) => true,
                                Err(e) => {
                                    debug_assert!(
                                        !matches!(
                                            e,
                                            CompleteError::TenantMismatch { .. }
                                                | CompleteError::ShardNotFound { .. }
                                        ),
                                        "session complete hit impossible error: {e:?}"
                                    );
                                    false
                                }
                            };
                        let children: Vec<ShardId> = residual_id.into_iter().collect();
                        Ok(SessionOutcome {
                            lease,
                            is_terminal,
                            checkpoints_ok,
                            checkpoints_rejected,
                            split_children: children,
                        })
                    } else {
                        // split_residual failed (e.g., lease expired) — session
                        // is still alive but in an uncertain state. Drop it.
                        Ok(SessionOutcome {
                            lease,
                            is_terminal: false,
                            checkpoints_ok,
                            checkpoints_rejected,
                            split_children: Vec::new(),
                        })
                    }
                }
            }
        })();
        // Session dropped here — coordinator borrow released.

        // --- Phase 3: Sim-level bookkeeping (coordinator borrow released) -----
        //
        // Reconcile session results with the harness's parallel bookkeeping:
        // record the lease, register child shards from splits, and mark the
        // parent terminal if the session completed successfully.

        let outcome = match session_result {
            Ok(o) => o,
            Err(event) => return event,
        };

        self.record_acquire_bookkeeping(worker, key, outcome.lease);

        // Register any child shards created by splits.
        let run = key.run();
        for &child_id in &outcome.split_children {
            let child_key = ShardKey::new(run, child_id);
            self.shard_keys.push(child_key);
            self.active_shard_keys.push(child_key);
        }

        if outcome.is_terminal {
            self.mark_shard_terminal(worker, key);
        }

        if outcome.is_terminal && outcome.checkpoints_rejected == 0 {
            SimEvent::SessionLifecycleOk {
                checkpoints_ok: outcome.checkpoints_ok,
                checkpoints_rejected: outcome.checkpoints_rejected,
            }
        } else {
            SimEvent::SessionLifecyclePartial {
                checkpoints_ok: outcome.checkpoints_ok,
                checkpoints_rejected: outcome.checkpoints_rejected,
            }
        }
    }

    // -----------------------------------------------------------------------
    // Convergence check
    // -----------------------------------------------------------------------

    /// Ground-truth available count for one run at `now`.
    ///
    /// Counts shards that are Active and not currently leased, derived purely
    /// from coordinator state. Used by overload diagnostics to validate D1
    /// (reported available-count accuracy).
    fn count_available_ground_truth(&self, run: RunId, now: LogicalTime) -> u32 {
        let count = self
            .coordinator
            .shards()
            .filter(|((tenant, key), record)| {
                *tenant == self.tenant
                    && key.run() == run
                    && record.status == ShardStatus::Active
                    && !record.is_leased_at(now)
            })
            .count();
        u32::try_from(count).expect("ground-truth available count exceeds u32::MAX")
    }

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

#[cfg(test)]
#[path = "harness_tests.rs"]
mod tests;
