//! Full simulation harness for deterministic coordination testing.
//!
//! Drives the real [`InMemoryCoordinator`] under configurable fault injection,
//! verifying protocol invariants at every step. Inspired by FoundationDB's
//! simulation framework and TigerBeetle's VOPR.
//!
//! # Two-phase run
//!
//! 1. **Safety phase**: Random operations under fault injection. Verifies that
//!    no invariant is ever violated regardless of operation ordering or timing.
//! 2. **Liveness phase**: Biased toward acquire + complete. Verifies that the
//!    system converges to terminal states.

use std::collections::BTreeMap;

use rand::Rng;

use crate::coordination::cursor::Cursor;
use crate::coordination::error::IdempotentOutcome;
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::record::{ParkReason, ShardRecord};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::split::{
    SplitReplaceChild, SplitReplacePlan, SplitResidualPlan, hash_checkpoint_payload,
};
use crate::coordination::traits::CoordinationBackend;
use crate::coordination::Lease;
use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId, ShardKey, TenantId, WorkerId};

use super::invariants::{InvariantChecker, InvariantViolation};
use super::worker::SimWorker;
use super::{FaultConfig, FaultLevel, SimContext};

// ---------------------------------------------------------------------------
// SimOp
// ---------------------------------------------------------------------------

/// A single operation in the simulation.
///
/// Operations fall into two categories: *coordinator ops* that invoke real
/// [`InMemoryCoordinator`] methods, and *environmental ops* that manipulate
/// simulation state (clock, worker health).
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
    /// Split-replace: parent shard → N children covering parent's range (terminal).
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
    /// Advance the logical clock by `ticks`.
    AdvanceTime { ticks: u64 },
    /// Simulate a worker stall (GC pause, network partition).
    PauseWorker { worker: WorkerId },
    /// Resume a previously paused worker.
    ResumeWorker { worker: WorkerId },
}

// ---------------------------------------------------------------------------
// SimEvent
// ---------------------------------------------------------------------------

/// Outcome of executing a [`SimOp`].
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
}

/// Categorized rejection reason (no heap allocation).
///
/// Used instead of `String` to avoid hot-path allocation in fault-heavy
/// simulation modes where 30-50% of operations are rejected.
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
    /// Split validation failed (bad coverage, bad plan, etc.).
    SplitValidation,
    /// No stale lease available for zombie injection.
    NoStaleLease,
    /// No previous checkpoint to replay.
    NoPriorCheckpoint,
    /// Coordinator returned an error not matching a specific category.
    Other,
}

/// Typed event category for counting (no payload).
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
    Rejected,
    TimeAdvanced,
    WorkerPaused,
    WorkerResumed,
    Skipped,
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
            SimEvent::Rejected { .. } => SimEventKind::Rejected,
            SimEvent::TimeAdvanced { .. } => SimEventKind::TimeAdvanced,
            SimEvent::WorkerPaused { .. } => SimEventKind::WorkerPaused,
            SimEvent::WorkerResumed { .. } => SimEventKind::WorkerResumed,
            SimEvent::Skipped => SimEventKind::Skipped,
        }
    }
}

// ---------------------------------------------------------------------------
// SimReport
// ---------------------------------------------------------------------------

/// Summary of a simulation run.
///
/// Includes both safety results (violations) and liveness results (convergence),
/// plus enough metadata to reproduce the exact run.
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

/// Default lease duration for the simulated coordinator.
const DEFAULT_LEASE_DURATION: u64 = 100;

/// Initial trace capacity (avoids early reallocs in typical runs).
const INITIAL_TRACE_CAPACITY: usize = 2048;

/// Number of initial operations where faults are suppressed to let the
/// system reach a healthy baseline.
///
/// Without warmup, early time-jumps can expire leases before any worker
/// acquires a shard, causing the entire safety phase to degenerate into
/// rejected-op noise with no meaningful coverage.
const WARMUP_OPS: usize = 5;

/// Maximum retries when generating a random op before falling back to
/// `AdvanceTime`.
const MAX_OP_RETRIES: usize = 10;

/// Full deterministic simulation harness.
///
/// Drives [`InMemoryCoordinator`] through random operations, injecting faults
/// per [`FaultConfig`], and checking invariants at every step.
pub struct CoordinationSim {
    context: SimContext,
    coordinator: InMemoryCoordinator,
    workers: BTreeMap<WorkerId, SimWorker>,
    fault_config: FaultConfig,
    checker: InvariantChecker,
    trace: Vec<(LogicalTime, SimOp, SimEvent)>,
    shard_keys: Vec<ShardKey>,
    tenant: TenantId,
    ops_executed: usize,
    /// Stale leases saved when B1 cleanup supersedes them, used for
    /// zombie checkpoint injection to exercise the `StaleFence` path.
    stale_leases: Vec<(WorkerId, ShardKey, Lease)>,
    /// Last successful (OpId, Cursor) per (WorkerId, ShardKey) for
    /// OpId replay/conflict testing.
    last_checkpoint_ops: BTreeMap<(WorkerId, ShardKey), (crate::identity::OpId, Cursor)>,
}

impl CoordinationSim {
    /// Create a new simulation with the given seed and fault level.
    pub fn new(seed: u64, level: FaultLevel) -> Self {
        Self {
            context: SimContext::new(seed),
            coordinator: InMemoryCoordinator::new(DEFAULT_LEASE_DURATION),
            workers: BTreeMap::new(),
            fault_config: FaultConfig::for_level(level),
            checker: InvariantChecker::new(),
            trace: Vec::with_capacity(INITIAL_TRACE_CAPACITY),
            shard_keys: Vec::new(),
            tenant: TenantId::from_bytes([0x01; 32]),
            ops_executed: 0,
            stale_leases: Vec::new(),
            last_checkpoint_ops: BTreeMap::new(),
        }
    }

    /// Add a worker to the simulation.
    pub fn add_worker(&mut self, id: WorkerId) {
        self.workers.insert(id, SimWorker::new(id));
    }

    /// Register a shard in the coordinator.
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
    }

    /// Convenience: add N workers (IDs 1..=n) and M shards (run=1, shard IDs 1..=m).
    pub fn with_workers_and_shards(mut self, n_workers: u64, n_shards: u64) -> Self {
        for i in 1..=n_workers {
            self.add_worker(WorkerId::from_raw(i));
        }
        let run = RunId::from_raw(1);
        for i in 1..=n_shards {
            self.register_shard(run, ShardId::from_raw(i));
        }
        self
    }

    /// Execute a single step: run the operation, then check **all** invariants.
    ///
    /// Every operation—successful or rejected—is followed by a full invariant
    /// sweep (S1–S6). This is the core simulation guarantee: no operation can
    /// leave the coordinator in a state that violates any checked invariant
    /// without immediate detection.
    pub fn step(&mut self, op: SimOp) -> (SimEvent, Vec<InvariantViolation>) {
        let now = self.context.now();
        let event = self.execute_op(&op);
        self.trace.push((now, op, event.clone()));
        self.ops_executed += 1;

        let violations =
            self.checker
                .check_all(&self.coordinator, &[], self.tenant, self.context.now());
        (event, violations)
    }

    /// Run a two-phase simulation.
    ///
    /// 1. Safety phase: `safety_ops` random operations (first [`WARMUP_OPS`]
    ///    without faults, remainder with full fault injection).
    /// 2. Liveness phase: `liveness_ops` convergence-biased operations.
    ///
    /// Returns a [`SimReport`] summarizing the run.
    pub fn run(mut self, safety_ops: usize, liveness_ops: usize) -> SimReport {
        let mut all_violations = Vec::new();
        let mut event_counts = BTreeMap::new();

        // TigerBeetle-inspired: advance time before first coordinator op
        // so that `now > ZERO` (some validation requires this).
        let initial_ticks = self.context.rng().random_range(1u64..=10);
        self.context.advance(initial_ticks);

        // --- Zombie-worker scenario (H6) ---
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

    fn execute_op(&mut self, op: &SimOp) -> SimEvent {
        match op {
            SimOp::Acquire { worker, key } => self.exec_acquire(*worker, *key),
            SimOp::Renew { worker, key } => self.exec_renew(*worker, *key),
            SimOp::Checkpoint { worker, key } => self.exec_checkpoint(*worker, *key),
            SimOp::Complete { worker, key } => self.exec_complete(*worker, *key),
            SimOp::Park { worker, key } => self.exec_park(*worker, *key),
            SimOp::SplitReplace { worker, key } => self.exec_split_replace(*worker, *key),
            SimOp::SplitResidual { worker, key } => self.exec_split_residual(*worker, *key),
            SimOp::ReplayCheckpoint { worker, key } => self.exec_replay_checkpoint(*worker, *key),
            SimOp::ConflictCheckpoint { worker, key } => {
                self.exec_conflict_checkpoint(*worker, *key)
            }
            SimOp::ZombieCheckpoint => self.exec_zombie_checkpoint(),
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

                // B1 fix: when worker W acquires shard K, clear K from every
                // other worker's local bookkeeping. Without this, a worker
                // whose lease expired silently still "thinks" it holds the
                // shard and would attempt checkpoint/complete with a stale
                // lease, producing confusing Rejected events instead of the
                // expected NotLeased rejection path.
                for (wid, w) in &mut self.workers {
                    if *wid == worker {
                        w.record_acquire(key, lease);
                    } else {
                        w.record_release(&key);
                    }
                }

                SimEvent::AcquireOk { fence }
            }
            Err(_) => SimEvent::Rejected {
                kind: RejectionKind::Other,
            },
        }
    }

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
            Ok(result) => SimEvent::RenewOk {
                new_deadline: result.new_deadline,
            },
            Err(_) => SimEvent::Rejected {
                kind: RejectionKind::LeaseExpired,
            },
        }
    }

    fn exec_checkpoint(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        let (lease, op_id) = match self.workers.get_mut(&worker) {
            Some(w) => match w.lease_for(&key) {
                Some(l) => {
                    let l = *l;
                    let op = w.next_op_id();
                    (l, op)
                }
                None => {
                    return SimEvent::Rejected {
                        kind: RejectionKind::NotLeased,
                    };
                }
            },
            None => {
                return SimEvent::Rejected {
                    kind: RejectionKind::NotLeased,
                };
            }
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
                SimEvent::CheckpointOk
            }
            Err(_) => SimEvent::Rejected {
                kind: RejectionKind::StaleFence,
            },
        }
    }

    fn exec_complete(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        let (lease, op_id) = match self.workers.get_mut(&worker) {
            Some(w) => match w.lease_for(&key) {
                Some(l) => {
                    let l = *l;
                    let op = w.next_op_id();
                    (l, op)
                }
                None => {
                    return SimEvent::Rejected {
                        kind: RejectionKind::NotLeased,
                    };
                }
            },
            None => {
                return SimEvent::Rejected {
                    kind: RejectionKind::NotLeased,
                };
            }
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
                SimEvent::CompleteOk
            }
            Err(_) => SimEvent::Rejected {
                kind: RejectionKind::TerminalState,
            },
        }
    }

    fn exec_park(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        let (lease, op_id) = match self.workers.get_mut(&worker) {
            Some(w) => match w.lease_for(&key) {
                Some(l) => {
                    let l = *l;
                    let op = w.next_op_id();
                    (l, op)
                }
                None => {
                    return SimEvent::Rejected {
                        kind: RejectionKind::NotLeased,
                    };
                }
            },
            None => {
                return SimEvent::Rejected {
                    kind: RejectionKind::NotLeased,
                };
            }
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
                SimEvent::ParkOk
            }
            Err(_) => SimEvent::Rejected {
                kind: RejectionKind::TerminalState,
            },
        }
    }

    // -----------------------------------------------------------------------
    // Op generation
    // -----------------------------------------------------------------------

    /// Generate a random operation with weighted distribution.
    ///
    /// During warmup (`suppress_faults = true`), only generates coordinator
    /// operations (no time jumps, pauses, or resumes).
    ///
    /// Weight rationale (normal mode): acquire (20%) and checkpoint (20%) are
    /// the most frequent to exercise the happy path; renew (15%) keeps leases
    /// alive to enable downstream ops; complete (10%) and park (5%) are
    /// terminal and would starve coverage if over-weighted; time advances
    /// (15%) create expiry windows; pause/resume (15%) model worker failures.
    ///
    /// Warmup weights differ: acquire (30%), renew (20%), checkpoint (25%),
    /// complete (15%), park (10%) — no environmental ops.
    fn generate_random_op(&mut self, suppress_faults: bool) -> SimOp {
        for _ in 0..MAX_OP_RETRIES {
            // Weighted selection.
            let roll: u32 = self.context.rng().random_range(0..100);
            let op = if suppress_faults {
                // Warmup: only coordinator ops.
                match roll {
                    0..30 => self.try_gen_acquire(),
                    30..50 => self.try_gen_renew(),
                    50..75 => self.try_gen_checkpoint(),
                    75..90 => self.try_gen_complete(),
                    _ => self.try_gen_park(),
                }
            } else {
                match roll {
                    0..20 => self.try_gen_acquire(),
                    20..35 => self.try_gen_renew(),
                    35..55 => self.try_gen_checkpoint(),
                    55..65 => self.try_gen_complete(),
                    65..70 => self.try_gen_park(),
                    70..85 => Some(self.gen_advance_time()),
                    85..95 => self.try_gen_pause(),
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

    /// Generate a liveness-biased operation (more acquire + complete).
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

    fn pick_random_active_worker(&mut self) -> Option<WorkerId> {
        let active: Vec<WorkerId> = self
            .workers
            .iter()
            .filter(|(_, w)| !w.is_paused())
            .map(|(id, _)| *id)
            .collect();
        if active.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..active.len());
        Some(active[idx])
    }

    fn pick_random_shard_key(&mut self) -> Option<ShardKey> {
        if self.shard_keys.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..self.shard_keys.len());
        Some(self.shard_keys[idx])
    }

    /// Collect a worker's held shard keys in deterministic order.
    ///
    /// `HashMap` iteration order is non-deterministic. Sorting by raw
    /// `(RunId, ShardId)` ensures reproducible op generation.
    fn sorted_held_keys(&self, worker: WorkerId) -> Vec<ShardKey> {
        let mut keys: Vec<ShardKey> = self
            .workers
            .get(&worker)
            .map(|w| w.held_keys().copied().collect())
            .unwrap_or_default();
        keys.sort_by_key(|k| (k.run().as_raw(), k.shard().as_raw()));
        keys
    }

    fn try_gen_acquire(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let key = self.pick_random_shard_key()?;
        Some(SimOp::Acquire { worker, key })
    }

    fn try_gen_renew(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let held = self.sorted_held_keys(worker);
        if held.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..held.len());
        Some(SimOp::Renew {
            worker,
            key: held[idx],
        })
    }

    fn try_gen_checkpoint(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let held = self.sorted_held_keys(worker);
        if held.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..held.len());
        Some(SimOp::Checkpoint {
            worker,
            key: held[idx],
        })
    }

    fn try_gen_complete(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let held = self.sorted_held_keys(worker);
        if held.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..held.len());
        Some(SimOp::Complete {
            worker,
            key: held[idx],
        })
    }

    fn try_gen_park(&mut self) -> Option<SimOp> {
        let worker = self.pick_random_active_worker()?;
        let held = self.sorted_held_keys(worker);
        if held.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..held.len());
        Some(SimOp::Park {
            worker,
            key: held[idx],
        })
    }

    fn gen_advance_time(&mut self) -> SimOp {
        let ticks = self.context.rng().random_range(1u64..=50);
        SimOp::AdvanceTime { ticks }
    }

    fn try_gen_pause(&mut self) -> Option<SimOp> {
        let active: Vec<WorkerId> = self
            .workers
            .iter()
            .filter(|(_, w)| !w.is_paused())
            .map(|(id, _)| *id)
            .collect();
        if active.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..active.len());
        Some(SimOp::PauseWorker {
            worker: active[idx],
        })
    }

    fn try_gen_resume(&mut self) -> Option<SimOp> {
        let paused: Vec<WorkerId> = self
            .workers
            .iter()
            .filter(|(_, w)| w.is_paused())
            .map(|(id, _)| *id)
            .collect();
        if paused.is_empty() {
            return None;
        }
        let idx = self.context.rng().random_range(0..paused.len());
        Some(SimOp::ResumeWorker {
            worker: paused[idx],
        })
    }

    // -----------------------------------------------------------------------
    // Cursor generation (H5 fix)
    // -----------------------------------------------------------------------

    /// Generate a cursor that is lexicographically >= the worker's last cursor
    /// for this shard, and within the shard spec bounds `[a, z)`.
    ///
    /// H5 fix: naively random cursors would frequently regress behind the
    /// worker's last checkpoint, causing the coordinator to correctly reject
    /// the operation. That masks real bugs behind a flood of expected
    /// `CursorRegression` rejections. By tracking per-worker cursor progress
    /// and only generating forward cursors, rejections in the simulation
    /// signal actual protocol violations rather than test-harness noise.
    fn generate_forward_cursor(&mut self, worker: WorkerId, key: ShardKey) -> Cursor {
        let last = self
            .workers
            .get(&worker)
            .and_then(|w| w.last_cursor_for(key.run(), key.shard()))
            .map(|k| k[0]);

        let start = match last {
            Some(k) => k.saturating_add(1),
            None => b'a',
        };
        let end = b'z';

        if start >= end {
            // Already at end of range -- produce max valid cursor.
            return Cursor::with_last_key(vec![end - 1]);
        }

        let key_byte = self.context.rng().random_range(start..end);
        Cursor::with_last_key(vec![key_byte])
    }

    // -----------------------------------------------------------------------
    // Zombie scenario (H6 fix)
    // -----------------------------------------------------------------------

    /// Inject one deterministic zombie-worker scenario.
    ///
    /// 1. Worker A acquires a shard.
    /// 2. Time advances past lease deadline.
    /// 3. Worker B acquires the same shard (bumps fence).
    /// 4. Worker A attempts checkpoint after losing its lease (B1 bookkeeping
    ///    cleanup cleared it on Worker B's acquire) -- must be rejected.
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
        *event_counts.entry(event.kind()).or_insert(0) += 1;
        all_violations.extend(violations);

        // Step 4: Worker A attempts checkpoint with stale lease.
        // The worker A should still have the old lease in its bookkeeping
        // (if not cleaned up by B1 fix -- but B1 fix does clean it up on
        // acquire by worker B). So we need to check: if worker A no longer
        // has the lease, the checkpoint will be rejected with NotLeased.
        let (event, violations) = self.step(SimOp::Checkpoint {
            worker: worker_a,
            key,
        });
        *event_counts.entry(event.kind()).or_insert(0) += 1;
        all_violations.extend(violations);

        // The checkpoint must have been rejected (either NotLeased or StaleFence).
        debug_assert!(
            matches!(event, SimEvent::Rejected { .. }),
            "zombie worker checkpoint should be rejected, got: {event:?}",
        );
    }

    // -----------------------------------------------------------------------
    // Convergence check
    // -----------------------------------------------------------------------

    /// Check if all shards reached a terminal state (Done, Split, or Parked).
    fn check_convergence(&self) -> bool {
        for key in &self.shard_keys {
            if let Some(record) = self.coordinator.shards().get(&(self.tenant, *key))
                && !record.status.is_terminal()
            {
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
}
