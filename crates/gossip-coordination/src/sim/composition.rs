//! Composition simulation harness: coordinator + done-ledger in one loop.
//!
//! Owns [`InMemoryCoordinator`] and [`InMemoryDoneLedger`] directly (not
//! wrapping the individual harnesses) so a single [`SimContext`] drives all
//! PRNG decisions, preserving the single-stream determinism contract
//! documented at [`super::SimContext`].
//!
//! # Purpose
//!
//! Individual components have strong isolated testing, but no simulation
//! covers the boundaries where distributed systems bugs cluster (Yuan et al.,
//! OSDI 2014). The coordinator operates on shards `(RunId, ShardId)` while
//! the done-ledger operates on object-versions `(TenantId, PolicyHash,
//! OvidHash)` — these two key spaces are bridged by [`DoneLedgerProvenance`]
//! carrying `(run_id, shard_id, fence_epoch)`.
//!
//! The harness drives a deterministic claim-scan-complete loop that exercises
//! both APIs and runs both invariant checker suites (S1–S9, I1–I10) after
//! every step. Cross-component invariants (C1–C4) are wired by a follow-on
//! task.
//!
//! # Determinism
//!
//! All randomness flows through the coordination [`SimContext`]'s single
//! [`ChaCha8Rng`] stream. The [`InMemoryDoneLedger`] does not consume a
//! `SimContext` — its fault injection hooks are called imperatively. The
//! [`DoneLedgerOracle`] tracks expected state via submit/commit/abort calls
//! and does not need a clock.
//!
//! [`DoneLedgerProvenance`]: gossip_contracts::persistence::DoneLedgerProvenance
//! [`ChaCha8Rng`]: rand_chacha::ChaCha8Rng

use std::collections::BTreeMap;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use gossip_contracts::coordination::cursor::{CursorUpdate, MAX_KEY_SIZE};
use gossip_contracts::coordination::manifest::InitialShardInput;
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpecRef};
use gossip_contracts::coordination::split::{
    plan_split_replace_at_points_initial_cursor, plan_split_residual_at_point,
};
use gossip_contracts::identity::{
    FenceEpoch, OpId, PolicyHash, RunId, ShardId, ShardKey, TenantId, WorkerId,
};
use gossip_contracts::persistence::{CommitHandle, DoneLedger, DoneLedgerRecord, OvidHash};
use gossip_persistence_inmemory::sim::{
    DoneLedgerFaultConfig, DoneLedgerInvariantChecker, DoneLedgerInvariantViolation,
    DoneLedgerOracle,
};
use gossip_persistence_inmemory::CompletionOrder;
use gossip_persistence_inmemory::InMemoryDoneLedger;

use crate::error::{AcquireScratch, CheckpointError, CompleteError, IdempotentOutcome, SplitError};
use crate::facade::{ClaimError, ShardClaiming};
use crate::in_memory::InMemoryCoordinator;
use crate::record::ParkReason;
use crate::run::{RunConfig, RunManagement};
use crate::session::WorkerSession;
use crate::traits::CoordinationBackend;
use crate::Lease;

use super::scan_driver_sim::generate_scan_outcome;
use super::worker::SimWorker;
use super::{
    FaultConfig, FaultLevel, InvariantChecker, InvariantViolation, RejectionKind, RunTerminalKind,
    SimContext, SimEvent, SimIntrospection, SimOp,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default shard lease duration (logical time ticks).
const DEFAULT_LEASE_DURATION: u64 = 100;

/// Maximum retained stale leases for zombie checkpoint injection.
const MAX_STALE_LEASES: usize = 64;

/// Size of the OVID hash pool used for synthetic done-ledger records.
/// Matches the pool size in DoneLedgerSim for consistency.
const OVID_POOL_SIZE: usize = 50;

/// Items generated per scan lifecycle (inclusive range).
const SCAN_ITEMS_MIN: usize = 1;
const SCAN_ITEMS_MAX: usize = 5;

/// PPM ceiling for fault probability calculations.
#[allow(dead_code)] // Used by random op generation to validate PPM ceilings.
const PPM_MAX: u32 = 1_000_000;

/// Saved checkpoint state: `(worker_raw, run_raw, shard_raw)` → `(op_id, cursor, worker, key)`.
type CheckpointOpMap = BTreeMap<(u64, u64, u64), (OpId, Vec<u8>, WorkerId, ShardKey)>;

/// Split spec bounds: `(start_buf, start_len, end_buf, end_len)`.
type SplitBoundsBuf = ([u8; MAX_KEY_SIZE], usize, [u8; MAX_KEY_SIZE], usize);

/// Split input snapshot: spec bounds + optional first cursor byte.
type SplitInputCopy = (SplitBoundsBuf, Option<u8>);

// ---------------------------------------------------------------------------
// DoneLedgerFaultOp
// ---------------------------------------------------------------------------

/// Fault-injection operation for the done-ledger backend.
///
/// Each variant maps 1:1 to an [`InMemoryDoneLedger`] imperative fault method.
/// Used by [`CompositionSimOp::InjectLedgerFault`] to control done-ledger
/// fault injection from the composition sim's step loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoneLedgerFaultOp {
    /// Cause the next `count` `batch_upsert` submissions to fail at submit time.
    InjectSubmitFailure { count: usize },
    /// Cause the next `count` committed writes to fail at commit time.
    InjectCommitFailure { count: usize },
    /// Delay the next `count` writes (enqueue as pending instead of auto-complete).
    ///
    /// After injecting a delay, use [`ReleasePendingWrites`](Self::ReleasePendingWrites)
    /// to release them. Without a release, any subsequent scan lifecycle that
    /// hits a delayed write will block indefinitely in `CommitHandle::wait()`.
    InjectDelay { count: usize },
    /// Release the next pending (delayed) write so its `CommitHandle::wait()`
    /// unblocks. Must be issued after `InjectDelay` to prevent deadlocks.
    ReleasePendingWrites,
}

// ---------------------------------------------------------------------------
// CompositionFaultConfig
// ---------------------------------------------------------------------------

/// Cross-boundary fault configuration for composition simulation.
///
/// Combines coordination-level faults (lease expiry, pause, time jump),
/// persistence-level faults (submit fail, commit fail, delay), and
/// cross-component faults unique to the composition boundary.
#[derive(Debug, Clone)]
pub struct CompositionFaultConfig {
    /// Coordination-level faults (lease expiry, pause, time jump).
    pub coordination: FaultConfig,
    /// Persistence-level faults (submit fail, commit fail, delay).
    pub persistence: DoneLedgerFaultConfig,
    /// Probability (PPM) of crashing between coordinator `complete()` and
    /// done-ledger `batch_upsert()`. Models the most dangerous cross-component
    /// failure mode: the coordinator believes the shard is done but the
    /// done-ledger has no record of it.
    crash_after_complete_ppm: u32,
    /// Probability (PPM) of writing done-ledger records with a stale
    /// `fence_epoch` in provenance. Models a worker using credentials from
    /// a prior lease acquisition.
    stale_provenance_ppm: u32,
}

impl CompositionFaultConfig {
    /// Probability (PPM) of crashing between `complete()` and `batch_upsert()`.
    #[must_use]
    pub fn crash_after_complete_ppm(&self) -> u32 {
        self.crash_after_complete_ppm
    }

    /// Probability (PPM) of writing done-ledger records with stale provenance.
    #[must_use]
    pub fn stale_provenance_ppm(&self) -> u32 {
        self.stale_provenance_ppm
    }

    /// Construct a fault configuration from a [`FaultLevel`].
    ///
    /// Cross-boundary fault rates scale with level:
    /// - SunnyDay: all zero
    /// - Stormy: 50k PPM crash, 30k PPM stale provenance
    /// - Radioactive: 100k PPM crash, 80k PPM stale provenance
    #[must_use]
    pub fn for_level(level: FaultLevel) -> Self {
        let (crash_ppm, stale_ppm) = match level {
            FaultLevel::SunnyDay => (0, 0),
            FaultLevel::Stormy => (50_000, 30_000),
            FaultLevel::Radioactive => (100_000, 80_000),
        };

        // Convert coordination FaultLevel to persistence FaultLevel.
        // Both enums have identical variants, so we map by discriminant.
        let persistence_level = match level {
            FaultLevel::SunnyDay => gossip_persistence_inmemory::sim::FaultLevel::SunnyDay,
            FaultLevel::Stormy => gossip_persistence_inmemory::sim::FaultLevel::Stormy,
            FaultLevel::Radioactive => gossip_persistence_inmemory::sim::FaultLevel::Radioactive,
        };

        Self {
            coordination: FaultConfig::for_level(level),
            persistence: DoneLedgerFaultConfig::for_level(persistence_level),
            crash_after_complete_ppm: crash_ppm,
            stale_provenance_ppm: stale_ppm,
        }
    }
}

// ---------------------------------------------------------------------------
// ProvenanceEntry
// ---------------------------------------------------------------------------

/// Record bridging coordinator shard completion and done-ledger record writes.
///
/// Appended to [`CompositionSim::write_log`] after each scan lifecycle.
/// Used by the cross-component invariant checker (C1–C4) to verify that
/// every completed shard has matching done-ledger records with correct
/// provenance, and vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceEntry {
    /// Worker that executed the scan.
    pub worker: WorkerId,
    /// Run that the shard belongs to.
    pub run_id: RunId,
    /// Shard within the run.
    pub shard_id: ShardId,
    /// Fence epoch from the lease at scan time.
    pub fence_epoch: FenceEpoch,
    /// Number of done-ledger records produced by the scan.
    pub record_count: usize,
    /// Whether the done-ledger write was actually committed.
    /// `false` when the ledger write failed (submit or commit failure)
    /// or a crash was simulated before `batch_upsert()`.
    pub committed: bool,
    /// Whether the coordinator `complete()` call succeeded.
    /// `false` when `complete()` failed (e.g., lease expired) or was
    /// skipped (crash scenario).
    pub coordinator_completed: bool,
}

// ---------------------------------------------------------------------------
// CompositionSimOp
// ---------------------------------------------------------------------------

/// Operation for the composition simulation harness.
///
/// Extends the coordination [`SimOp`] with cross-component scan lifecycle
/// operations that exercise the coordinator + done-ledger boundary.
#[derive(Debug, Clone)]
pub enum CompositionSimOp {
    /// Pass-through to coordinator (all [`SimOp`] variants supported).
    Coord(SimOp),
    /// Full scan lifecycle: claim shard → generate synthetic done-ledger
    /// records → write to done-ledger → complete shard.
    ScanLifecycle { worker: WorkerId },
    /// Scan lifecycle with crash between coordinator `complete()` and
    /// done-ledger `batch_upsert()`. The coordinator believes the shard
    /// is done but the done-ledger has no record.
    ScanLifecycleCrashAfterComplete { worker: WorkerId },
    /// Scan lifecycle where done-ledger records carry a stale `fence_epoch`
    /// in provenance, modeling a worker using credentials from a prior
    /// lease acquisition.
    ScanLifecycleStaleLeaseWrite { worker: WorkerId },
    /// Inject a fault into the done-ledger backend.
    InjectLedgerFault(DoneLedgerFaultOp),
}

// ---------------------------------------------------------------------------
// CompositionSimEvent
// ---------------------------------------------------------------------------

/// Outcome of executing a [`CompositionSimOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionSimEvent {
    /// Result of a pass-through coordination operation.
    Coord(SimEvent),
    /// Full scan lifecycle completed: shard claimed, done-ledger records
    /// committed, and coordinator `complete()` succeeded (shard is terminal).
    ScanCompleted {
        worker: WorkerId,
        records_written: usize,
    },
    /// Scan lifecycle could not start because no shard was available to claim.
    ScanClaimFailed { worker: WorkerId },
    /// Scan lifecycle where the done-ledger write was skipped (crash injected).
    ScanCrashedAfterComplete { worker: WorkerId },
    /// Scan lifecycle where done-ledger records carry stale provenance.
    ScanStaleLeaseWrite {
        worker: WorkerId,
        stale_fence: FenceEpoch,
    },
    /// Done-ledger write succeeded but coordinator `complete()` was rejected
    /// (e.g. cursor out of bounds, lease expired). The shard remains active in
    /// coordinator state despite having done-ledger records committed.
    ScanCoordinatorCompleteFailed {
        worker: WorkerId,
        records_written: usize,
    },
    /// Done-ledger write failed at submit or commit time during a scan lifecycle.
    ScanLedgerWriteFailed { worker: WorkerId },
    /// Done-ledger fault injection applied.
    LedgerFaultInjected,
}

// ---------------------------------------------------------------------------
// CompositionSimViolation
// ---------------------------------------------------------------------------

/// Invariant violation from either the coordination or persistence checker.
#[derive(Debug, Clone)]
pub enum CompositionSimViolation {
    /// Coordination invariant violation (S1–S9).
    Coordination(InvariantViolation),
    /// Done-ledger invariant violation (I1–I10).
    Persistence(DoneLedgerInvariantViolation),
    // Cross-component invariant violations (C1-C4) will be added when
    // the cross-boundary checker is implemented.
}

// ---------------------------------------------------------------------------
// CompositionSim
// ---------------------------------------------------------------------------

/// Composition simulation harness: coordinator + done-ledger.
///
/// Drives a deterministic claim-scan-complete loop with a single PRNG stream,
/// running both invariant checker suites (S1–S9, I1–I10) after every step.
///
/// # Ownership model
///
/// Owns backends directly instead of wrapping [`CoordinationSim`] and
/// [`DoneLedgerSim`], because both harnesses own their [`SimContext`]
/// privately. Wrapping them would produce two independent PRNG streams,
/// destroying determinism for cross-component interactions.
///
/// [`CoordinationSim`]: super::CoordinationSim
/// [`DoneLedgerSim`]: gossip_persistence_inmemory::sim::DoneLedgerSim
pub struct CompositionSim {
    context: SimContext,
    coordinator: InMemoryCoordinator,
    ledger: InMemoryDoneLedger,
    oracle: DoneLedgerOracle,
    coord_checker: InvariantChecker,
    ledger_checker: DoneLedgerInvariantChecker,
    workers: BTreeMap<WorkerId, SimWorker>,
    /// Cross-boundary fault rates. Used by random op generation and the
    /// cross-component invariant checker (C1-C4).
    #[allow(dead_code)]
    fault_config: CompositionFaultConfig,
    tenant: TenantId,
    policy: PolicyHash,
    ovid_pool: Vec<OvidHash>,
    shard_keys: Vec<ShardKey>,
    active_shard_keys: Vec<ShardKey>,
    run: RunId,
    ops_executed: usize,
    /// Provenance log for cross-component invariant checking.
    write_log: Vec<ProvenanceEntry>,
    /// Reusable scratch buffer for claim_next_available (zero-alloc hot path).
    scratch: AcquireScratch,
    /// Superseded leases saved for zombie checkpoint injection.
    stale_leases: Vec<(WorkerId, ShardKey, Lease)>,
    /// Admin op-ID counter (partition 0, distinct from worker partitions).
    admin_next_op: u64,
    /// Saved checkpoint ops for replay/conflict testing.
    last_checkpoint_ops: CheckpointOpMap,
    /// Run-to-shard mapping for terminate_run op generation.
    run_shard_ids: BTreeMap<RunId, Vec<ShardId>>,
}

impl CompositionSim {
    /// Create a new composition simulation with the given seed and fault config.
    ///
    /// The harness is not yet ready to run — call
    /// [`with_workers_and_shards`](Self::with_workers_and_shards) to set up
    /// the initial state.
    #[must_use]
    pub fn new(seed: u64, fault_config: CompositionFaultConfig) -> Self {
        let tenant = TenantId::from_bytes([0x01; 32]);
        let policy = PolicyHash::from_bytes([0x22; 32]);

        Self {
            context: SimContext::new(seed),
            coordinator: InMemoryCoordinator::new(DEFAULT_LEASE_DURATION),
            ledger: InMemoryDoneLedger::new(),
            oracle: DoneLedgerOracle::new(),
            coord_checker: InvariantChecker::new(),
            ledger_checker: DoneLedgerInvariantChecker::new(),
            workers: BTreeMap::new(),
            fault_config,
            tenant,
            policy,
            ovid_pool: Vec::new(),
            shard_keys: Vec::new(),
            active_shard_keys: Vec::new(),
            run: RunId::from_raw(1),
            ops_executed: 0,
            write_log: Vec::new(),
            scratch: AcquireScratch::new(),
            stale_leases: Vec::new(),
            admin_next_op: 0,
            last_checkpoint_ops: BTreeMap::new(),
            run_shard_ids: BTreeMap::new(),
        }
    }

    /// Set up workers, a run, and shards for the simulation.
    ///
    /// Follows the same setup pattern as
    /// [`CoordinationSim::with_workers_and_shards`](super::CoordinationSim::with_workers_and_shards):
    ///
    /// 1. Add `n_workers` workers
    /// 2. Create a run with `DEFAULT_LEASE_DURATION`
    /// 3. Partition the byte keyspace into `n_shards` non-overlapping ranges
    /// 4. Register shards with the coordinator
    /// 5. Generate the OVID hash pool from PRNG
    ///
    /// # Errors
    ///
    /// Returns an error string if coordinator setup fails (should not happen
    /// with valid parameters).
    pub fn with_workers_and_shards(
        mut self,
        n_workers: u32,
        n_shards: u32,
    ) -> Result<Self, String> {
        // Step 1: Add workers.
        for i in 1..=n_workers {
            let worker = SimWorker::new(WorkerId::from_raw(u64::from(i)));
            self.workers.insert(worker.id(), worker);
        }

        // Step 2: Advance clock and create run.
        self.context.advance(1);
        let run = self.run;
        let config =
            RunConfig::try_new(CursorSemantics::Completed, DEFAULT_LEASE_DURATION, Some(5))
                .map_err(|e| format!("RunConfig::try_new failed: {e}"))?;
        self.coordinator
            .create_run(self.context.now(), self.tenant, run, config)
            .map_err(|e| format!("create_run failed: {e}"))?;

        // Step 3: Partition keyspace into shards.
        // Pre-compute bounds so borrows outlive the manifest.
        let bounds: Vec<([u8; 1], Vec<u8>)> = (0..n_shards)
            .map(|i| {
                let start = ((i * 256) / n_shards) as u8;
                let end_val = ((i + 1) * 256) / n_shards;
                if end_val >= 256 {
                    ([start], vec![0xFF, 0x01])
                } else {
                    ([start], vec![end_val as u8])
                }
            })
            .collect();
        let manifest: Vec<_> = bounds
            .iter()
            .enumerate()
            .map(|(index, (start, end))| {
                InitialShardInput::new(
                    ShardId::from_raw((index as u64) + 1),
                    ShardSpecRef::with_range(start.as_slice(), end.as_slice()),
                    CursorUpdate::initial(),
                )
            })
            .collect();

        // Step 4: Register shards.
        self.context.advance(1);
        let reg_op_id = self.next_admin_op_id();
        self.coordinator
            .register_shards(self.context.now(), self.tenant, run, &manifest, reg_op_id)
            .map_err(|e| format!("register_shards failed: {e}"))?
            .into_inner();

        // Track shard keys.
        let mut shard_ids = Vec::with_capacity(n_shards as usize);
        for i in 0..n_shards {
            let shard_id = ShardId::from_raw(u64::from(i) + 1);
            let key = ShardKey::new(run, shard_id);
            self.shard_keys.push(key);
            self.active_shard_keys.push(key);
            shard_ids.push(shard_id);
        }
        self.run_shard_ids.insert(run, shard_ids);

        // Step 5: Generate OVID pool from PRNG.
        self.ovid_pool = (0..OVID_POOL_SIZE)
            .map(|_| {
                let mut bytes = [0u8; 32];
                for b in &mut bytes {
                    *b = self.context.rng().random_range(0u8..=255);
                }
                OvidHash::from_bytes(bytes)
            })
            .collect();

        Ok(self)
    }

    /// Number of operations executed so far.
    #[must_use]
    pub fn ops_executed(&self) -> usize {
        self.ops_executed
    }

    /// Access the provenance write log.
    #[must_use]
    pub fn write_log(&self) -> &[ProvenanceEntry] {
        &self.write_log
    }

    // -----------------------------------------------------------------------
    // Step entry point
    // -----------------------------------------------------------------------

    /// Execute a single operation and run invariant checkers.
    ///
    /// Draw order contract: `execute_op → check_coordination_invariants →
    /// check_persistence_invariants → return`. This matches the coordination
    /// harness pattern.
    pub fn step(
        &mut self,
        op: CompositionSimOp,
    ) -> (CompositionSimEvent, Vec<CompositionSimViolation>) {
        let (event, mut violations) = match op {
            CompositionSimOp::Coord(sim_op) => self.execute_coord_op(&sim_op),
            CompositionSimOp::ScanLifecycle { worker } => self.exec_scan_lifecycle(worker),
            CompositionSimOp::ScanLifecycleCrashAfterComplete { worker } => {
                self.exec_scan_crash_after_complete(worker)
            }
            CompositionSimOp::ScanLifecycleStaleLeaseWrite { worker } => {
                self.exec_scan_stale_lease(worker)
            }
            CompositionSimOp::InjectLedgerFault(fault_op) => {
                self.apply_ledger_fault(&fault_op);
                (CompositionSimEvent::LedgerFaultInjected, Vec::new())
            }
        };
        self.ops_executed += 1;

        // Record claim success for scan lifecycle claims (S9 cooldown) is
        // handled inside claim_shard_for_scan. For Coord(ClaimNext), it's
        // handled inside execute_coord_op.

        // Run coordination invariant checker after every op that may have
        // mutated coordinator state. LedgerFaultInjected is the only op
        // that cannot affect the coordinator.
        if !matches!(&event, CompositionSimEvent::LedgerFaultInjected) {
            let coord_viols =
                self.coord_checker
                    .check_all(&self.coordinator, self.tenant, self.context.now());
            violations.extend(
                coord_viols
                    .into_iter()
                    .map(CompositionSimViolation::Coordination),
            );
        }

        (event, violations)
    }

    // -----------------------------------------------------------------------
    // Coordination op dispatch
    // -----------------------------------------------------------------------

    /// Execute a coordination [`SimOp`] and return the event + violations.
    ///
    /// Mirrors the dispatch logic from `CoordinationSim::execute_op` but
    /// operates on `CompositionSim`'s fields. After execution, runs the
    /// coordination invariant checker.
    fn execute_coord_op(
        &mut self,
        op: &SimOp,
    ) -> (CompositionSimEvent, Vec<CompositionSimViolation>) {
        let event = match op {
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
        };

        // Record claim success for cooldown tracking (S9 invariant).
        if let (SimOp::ClaimNext { worker }, SimEvent::ClaimOk { .. }) = (op, &event) {
            self.coord_checker
                .record_claim_success(*worker, self.context.now());
        }

        // Invariant checking deferred to step() — single check site for
        // all op types, avoiding redundant double-checks.
        (CompositionSimEvent::Coord(event), Vec::new())
    }

    // -----------------------------------------------------------------------
    // Scan lifecycle operations
    // -----------------------------------------------------------------------

    /// Full scan lifecycle: claim → generate records → write to ledger → complete.
    fn exec_scan_lifecycle(
        &mut self,
        worker: WorkerId,
    ) -> (CompositionSimEvent, Vec<CompositionSimViolation>) {
        // Step 1: Claim a shard.
        let (lease, key) = match self.claim_shard_for_scan(worker) {
            Ok(pair) => pair,
            Err(event) => return (event, Vec::new()),
        };

        // Step 2: Generate synthetic scan outcome.
        let now = self.context.now();
        let bounds = self.shard_cursor_bounds(&key);
        let scan = generate_scan_outcome(
            &mut self.context,
            &lease,
            self.policy,
            &self.ovid_pool,
            SCAN_ITEMS_MIN..=SCAN_ITEMS_MAX,
            now,
            None,
            bounds,
        );

        // Step 3: Write to done-ledger.
        let mut violations = Vec::new();
        let records_written = scan.records.len();

        let (ledger_viols, ledger_committed) = self.write_scan_to_ledger(&scan.records);
        violations.extend(ledger_viols);

        // Step 4: Consume op-ID unconditionally (deterministic sequencing),
        // but only complete if the ledger write succeeded.
        let w = self.workers.get_mut(&worker).expect("worker must exist");
        let op_id = w.next_op_id();
        let cursor = CursorUpdate::with_last_key(&scan.cursor_bytes);

        let coordinator_completed = if ledger_committed {
            let complete_now = self.context.now();
            match self
                .coordinator
                .complete(complete_now, self.tenant, &lease, &cursor, op_id)
            {
                Ok(_) => {
                    self.mark_shard_terminal(worker, key);
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        };

        // Step 5: Record provenance.
        self.write_log.push(ProvenanceEntry {
            worker,
            run_id: lease.run(),
            shard_id: lease.shard(),
            fence_epoch: lease.fence(),
            record_count: records_written,
            committed: ledger_committed,
            coordinator_completed,
        });

        if !ledger_committed {
            return (
                CompositionSimEvent::ScanLedgerWriteFailed { worker },
                violations,
            );
        }

        if !coordinator_completed {
            return (
                CompositionSimEvent::ScanCoordinatorCompleteFailed {
                    worker,
                    records_written,
                },
                violations,
            );
        }

        (
            CompositionSimEvent::ScanCompleted {
                worker,
                records_written,
            },
            violations,
        )
    }

    /// Scan lifecycle with crash: claim → complete → skip ledger write.
    ///
    /// Persistence invariants are not checked here because no ledger mutation
    /// occurs — the crash prevents `batch_upsert()`. The resulting divergence
    /// (coordinator believes the shard is done, ledger has no record) is
    /// tracked via `ProvenanceEntry { committed: false, coordinator_completed: true }`
    /// for the C1–C4 cross-component invariant checker.
    fn exec_scan_crash_after_complete(
        &mut self,
        worker: WorkerId,
    ) -> (CompositionSimEvent, Vec<CompositionSimViolation>) {
        // Claim.
        let (lease, key) = match self.claim_shard_for_scan(worker) {
            Ok(pair) => pair,
            Err(event) => return (event, Vec::new()),
        };

        // Generate scan outcome (consumes PRNG draws for determinism).
        let now = self.context.now();
        let bounds = self.shard_cursor_bounds(&key);
        let scan = generate_scan_outcome(
            &mut self.context,
            &lease,
            self.policy,
            &self.ovid_pool,
            SCAN_ITEMS_MIN..=SCAN_ITEMS_MAX,
            now,
            None,
            bounds,
        );

        // Complete the shard in coordinator (before writing to ledger).
        let w = self.workers.get_mut(&worker).expect("worker must exist");
        let op_id = w.next_op_id();
        let cursor = CursorUpdate::with_last_key(&scan.cursor_bytes);
        let complete_now = self.context.now();
        let coordinator_completed =
            match self
                .coordinator
                .complete(complete_now, self.tenant, &lease, &cursor, op_id)
            {
                Ok(_) => {
                    self.mark_shard_terminal(worker, key);
                    true
                }
                Err(_) => false,
            };

        // Skip the done-ledger write — simulating a crash between complete
        // and batch_upsert.

        // Record provenance: ledger write was skipped, coordinator may or
        // may not have succeeded.
        self.write_log.push(ProvenanceEntry {
            worker,
            run_id: lease.run(),
            shard_id: lease.shard(),
            fence_epoch: lease.fence(),
            record_count: scan.records.len(),
            committed: false,
            coordinator_completed,
        });

        (
            CompositionSimEvent::ScanCrashedAfterComplete { worker },
            Vec::new(),
        )
    }

    /// Scan lifecycle with stale fence epoch in done-ledger provenance.
    fn exec_scan_stale_lease(
        &mut self,
        worker: WorkerId,
    ) -> (CompositionSimEvent, Vec<CompositionSimViolation>) {
        // Claim.
        let (lease, key) = match self.claim_shard_for_scan(worker) {
            Ok(pair) => pair,
            Err(event) => return (event, Vec::new()),
        };

        // Generate a stale fence epoch (any value < current fence).
        let current_fence = lease.fence().as_raw();
        let stale_raw = if current_fence > 1 {
            self.context.rng().random_range(1..current_fence)
        } else {
            // No epoch smaller than the current one exists, so a truly stale
            // write is impossible. Abort without consuming further PRNG draws
            // to avoid emitting a misleading ScanStaleLeaseWrite event whose
            // fence matches the real lease.
            return (CompositionSimEvent::ScanClaimFailed { worker }, Vec::new());
        };
        let stale_fence = FenceEpoch::from_raw(stale_raw);

        // Generate scan outcome with stale provenance.
        let now = self.context.now();
        let bounds = self.shard_cursor_bounds(&key);
        let scan = generate_scan_outcome(
            &mut self.context,
            &lease,
            self.policy,
            &self.ovid_pool,
            SCAN_ITEMS_MIN..=SCAN_ITEMS_MAX,
            now,
            Some(stale_fence),
            bounds,
        );

        // Write to done-ledger (with stale provenance).
        let mut violations = Vec::new();
        let (ledger_viols, ledger_committed) = self.write_scan_to_ledger(&scan.records);
        violations.extend(ledger_viols);

        // Complete shard (with real lease).
        let w = self.workers.get_mut(&worker).expect("worker must exist");
        let op_id = w.next_op_id();
        let cursor = CursorUpdate::with_last_key(&scan.cursor_bytes);
        let complete_now = self.context.now();
        let coordinator_completed =
            match self
                .coordinator
                .complete(complete_now, self.tenant, &lease, &cursor, op_id)
            {
                Ok(_) => {
                    self.mark_shard_terminal(worker, key);
                    true
                }
                Err(_) => false,
            };

        // Record provenance with the stale fence.
        self.write_log.push(ProvenanceEntry {
            worker,
            run_id: lease.run(),
            shard_id: lease.shard(),
            fence_epoch: stale_fence,
            record_count: scan.records.len(),
            committed: ledger_committed,
            coordinator_completed,
        });

        (
            CompositionSimEvent::ScanStaleLeaseWrite {
                worker,
                stale_fence,
            },
            violations,
        )
    }

    // -----------------------------------------------------------------------
    // Scan lifecycle helpers
    // -----------------------------------------------------------------------

    /// Claim a shard for a scan lifecycle operation.
    ///
    /// Returns the lease and shard key on success, or a `ScanClaimFailed`
    /// event if no shard is available.
    fn claim_shard_for_scan(
        &mut self,
        worker: WorkerId,
    ) -> Result<(Lease, ShardKey), CompositionSimEvent> {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return Err(CompositionSimEvent::ScanClaimFailed { worker });
        }

        if self.active_shard_keys.is_empty() {
            return Err(CompositionSimEvent::ScanClaimFailed { worker });
        }

        let now = self.context.now();
        let run = self.run;
        match self.coordinator.claim_next_available(
            now,
            self.tenant,
            run,
            worker,
            &mut self.scratch,
        ) {
            Ok(result) => {
                let shard = result.lease.shard();
                let key = ShardKey::new(run, shard);
                let lease = result.lease;
                self.record_acquire_bookkeeping(worker, key, lease);
                self.coord_checker
                    .record_claim_success(worker, self.context.now());
                Ok((lease, key))
            }
            Err(_) => Err(CompositionSimEvent::ScanClaimFailed { worker }),
        }
    }

    /// Look up the first-byte bounds of a shard's key range `[lo, hi)`.
    ///
    /// Returns `Some((lo, hi))` when the shard has a non-degenerate single-byte
    /// range, or `None` when the range is too narrow or the shard is missing.
    fn shard_cursor_bounds(&self, key: &ShardKey) -> Option<(u8, u8)> {
        self.coordinator
            .shard_lookup(&self.tenant, key)
            .map(|r| {
                let (start, end) = self.coordinator.spec_bounds(r);
                let lo = start.first().copied().unwrap_or(b'a');
                let hi = end.first().copied().unwrap_or(b'z');
                (lo, hi)
            })
            .filter(|(lo, hi)| lo < hi)
    }

    /// Write scan records to the done-ledger and track in oracle.
    ///
    /// Returns `(violations, committed)` where `committed` is `true` only
    /// when records were durably committed to the ledger.
    fn write_scan_to_ledger(
        &mut self,
        records: &[DoneLedgerRecord],
    ) -> (Vec<CompositionSimViolation>, bool) {
        // Take pre-submission snapshot for invariant checking.
        let pre_snapshot: Vec<Option<DoneLedgerRecord>> = records
            .iter()
            .map(|r| {
                self.ledger
                    .get_record(r.key())
                    .expect("get_record should not fail")
            })
            .collect();

        match self.ledger.batch_upsert(records) {
            Err(_) => {
                // Submit failed — check I4 rollback.
                let viols = self.ledger_checker.check_after_submit_failure(
                    &self.ledger,
                    records,
                    &pre_snapshot,
                );
                let v = viols
                    .into_iter()
                    .map(CompositionSimViolation::Persistence)
                    .collect();
                (v, false)
            }
            Ok(handle) => {
                let op_id = handle.operation_id();
                self.oracle.submit(op_id, records.to_vec());

                match handle.wait() {
                    Ok(receipt) => {
                        let was_pending = self.oracle.commit(op_id);
                        assert!(
                            was_pending,
                            "auto-complete: op {op_id:?} not pending in oracle"
                        );
                        let viols = self.ledger_checker.check_after_committed_upsert(
                            &self.ledger,
                            records,
                            &receipt,
                            &pre_snapshot,
                        );
                        let v = viols
                            .into_iter()
                            .map(CompositionSimViolation::Persistence)
                            .collect();
                        (v, true)
                    }
                    Err(_) => {
                        // Commit failed.
                        self.oracle.abort(op_id);
                        let viols = self.ledger_checker.check_after_commit_failure(
                            &self.ledger,
                            records,
                            &pre_snapshot,
                        );
                        let v = viols
                            .into_iter()
                            .map(CompositionSimViolation::Persistence)
                            .collect();
                        (v, false)
                    }
                }
            }
        }
    }

    /// Apply a done-ledger fault injection operation.
    fn apply_ledger_fault(&self, fault_op: &DoneLedgerFaultOp) {
        match fault_op {
            DoneLedgerFaultOp::InjectSubmitFailure { count } => {
                self.ledger
                    .fail_next_submissions(*count)
                    .expect("fail_next_submissions should not fail");
            }
            DoneLedgerFaultOp::InjectCommitFailure { count } => {
                self.ledger
                    .fail_next_commits(*count)
                    .expect("fail_next_commits should not fail");
            }
            DoneLedgerFaultOp::InjectDelay { count } => {
                self.ledger
                    .delay_next_writes(*count)
                    .expect("delay_next_writes should not fail");
            }
            DoneLedgerFaultOp::ReleasePendingWrites => {
                self.ledger
                    .release_next(CompletionOrder::OldestFirst)
                    .expect("release_next should not fail");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Coordination executor methods
    // -----------------------------------------------------------------------

    /// Attempt to acquire a shard lease.
    fn exec_acquire(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        let now = self.context.now();
        match self.coordinator.acquire_and_restore_into(
            now,
            self.tenant,
            key,
            worker,
            &mut self.scratch,
        ) {
            Ok(result) => {
                let fence = result.lease.fence();
                let lease = result.lease;
                self.record_acquire_bookkeeping(worker, key, lease);
                SimEvent::AcquireOk { fence }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Renew an existing lease.
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
    fn exec_checkpoint(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        let cursor = self.generate_forward_cursor(worker, key);
        let update = CursorUpdate::with_last_key(&cursor);

        let now = self.context.now();
        match self
            .coordinator
            .checkpoint(now, self.tenant, &lease, &update, op_id)
        {
            Ok(_) => {
                if let Some(w) = self.workers.get_mut(&worker) {
                    w.record_cursor(key.run(), key.shard(), cursor.clone());
                }
                let ck = (worker.as_raw(), key.run().as_raw(), key.shard().as_raw());
                self.last_checkpoint_ops
                    .insert(ck, (op_id, cursor, worker, key));
                SimEvent::CheckpointOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Mark a shard as done (terminal).
    fn exec_complete(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        let cursor = self.generate_forward_cursor(worker, key);
        let update = CursorUpdate::with_last_key(&cursor);

        let now = self.context.now();
        match self
            .coordinator
            .complete(now, self.tenant, &lease, &update, op_id)
        {
            Ok(_) => {
                self.mark_shard_terminal(worker, key);
                SimEvent::CompleteOk
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Park a shard for later retry (terminal).
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

    /// Claim next available shard for a run.
    fn exec_claim_next(&mut self, worker: WorkerId) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        if self.active_shard_keys.is_empty() {
            return SimEvent::ClaimNoneAvailable;
        }

        // Pick a random run from active shards.
        let mut runs: Vec<RunId> = self.active_shard_keys.iter().map(|k| k.run()).collect();
        runs.sort();
        runs.dedup();
        let idx = self.context.rng().random_range(0..runs.len());
        let run = runs[idx];

        let now = self.context.now();
        match self.coordinator.claim_next_available(
            now,
            self.tenant,
            run,
            worker,
            &mut self.scratch,
        ) {
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
            Err(ClaimError::BackendError(infra)) => {
                panic!("simulation backend produced unexpected infrastructure error: {infra}")
            }
        }
    }

    /// Execute a split-replace: parent is retired and replaced by 2 children.
    fn exec_split_replace(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        let ((start_buf, start_len, end_buf, end_len), _) = match self.copy_shard_split_inputs(key)
        {
            Ok(inputs) => inputs,
            Err(event) => return event,
        };
        let start = &start_buf[..start_len];
        let end = &end_buf[..end_len];

        let mid = match self.compute_split_byte(start, end) {
            Ok(m) => m,
            Err(event) => return event,
        };

        let mid_key = [mid];
        let parent_spec = ShardSpecRef::with_range(start, end);
        let plan =
            match plan_split_replace_at_points_initial_cursor(parent_spec, [mid_key.as_slice()]) {
                Ok(p) => p,
                Err(_e) => {
                    debug_assert!(false, "unexpected split-replace plan failure: {_e:?}");
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
                let run = key.run();
                for &child_id in &children {
                    let child_key = ShardKey::new(run, child_id);
                    self.shard_keys.push(child_key);
                    self.active_shard_keys.push(child_key);
                    self.run_shard_ids.entry(run).or_default().push(child_id);
                }
                self.mark_shard_terminal(worker, key);
                SimEvent::SplitReplaceOk {
                    children: children.iter().copied().collect(),
                }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Execute a split-residual: parent shrinks, residual shard covers remainder.
    fn exec_split_residual(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (lease, op_id) = match require_lease_and_op(&mut self.workers, worker, &key) {
            Ok(pair) => pair,
            Err(event) => return event,
        };

        let ((start_buf, start_len, end_buf, end_len), parent_cursor_first_byte) =
            match self.copy_shard_split_inputs(key) {
                Ok(inputs) => inputs,
                Err(event) => return event,
            };
        let start = &start_buf[..start_len];
        let end = &end_buf[..end_len];

        if start.is_empty() || end.is_empty() || start >= end || end[0] - start[0] < 2 {
            return SimEvent::Rejected {
                kind: RejectionKind::SplitValidation,
            };
        }

        let cursor_byte = parent_cursor_first_byte.unwrap_or(start[0]);
        let lo = cursor_byte.saturating_add(1).max(start[0] + 1);
        let hi = end[0];
        if lo >= hi {
            return SimEvent::Rejected {
                kind: RejectionKind::SplitValidation,
            };
        }
        let mid = self.context.rng().random_range(lo..hi);

        let mid_key = [mid];
        let parent_spec = ShardSpecRef::with_range(start, end);
        let plan = match plan_split_residual_at_point(parent_spec, mid_key.as_slice()) {
            Ok(p) => p,
            Err(_e) => {
                debug_assert!(false, "unexpected split-residual plan failure: {_e:?}");
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
                let run = key.run();
                let residual_key = ShardKey::new(run, residual);
                self.shard_keys.push(residual_key);
                self.active_shard_keys.push(residual_key);
                self.run_shard_ids.entry(run).or_default().push(residual);
                SimEvent::SplitResidualOk { residual }
            }
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Replay a previous checkpoint with the same OpId and payload.
    fn exec_replay_checkpoint(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (prev_op_id, prev_cursor, lease) = match self.checkpoint_preamble(worker, key) {
            Ok(t) => t,
            Err(rejection) => return rejection,
        };

        let now = self.context.now();
        let prev_update = CursorUpdate::with_last_key(&prev_cursor);
        match self
            .coordinator
            .checkpoint(now, self.tenant, &lease, &prev_update, prev_op_id)
        {
            Ok(outcome) => match outcome {
                IdempotentOutcome::Replayed(()) => SimEvent::ReplayedOk,
                IdempotentOutcome::Executed(()) => SimEvent::CheckpointOk,
            },
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Replay a previous OpId with a different cursor payload.
    fn exec_conflict_checkpoint(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        let (prev_op_id, _prev_cursor, lease) = match self.checkpoint_preamble(worker, key) {
            Ok(t) => t,
            Err(rejection) => return rejection,
        };

        let different_cursor = self.generate_forward_cursor(worker, key);
        let different_update = CursorUpdate::with_last_key(&different_cursor);

        let now = self.context.now();
        match self
            .coordinator
            .checkpoint(now, self.tenant, &lease, &different_update, prev_op_id)
        {
            Ok(_) => SimEvent::CheckpointOk,
            Err(e) => SimEvent::Rejected { kind: e.into() },
        }
    }

    /// Execute a checkpoint using a stale lease saved when another worker
    /// acquired the same shard.
    fn exec_zombie_checkpoint(&mut self) -> SimEvent {
        if self.stale_leases.is_empty() {
            return SimEvent::Rejected {
                kind: RejectionKind::NoStaleLease,
            };
        }

        let idx = self.context.rng().random_range(0..self.stale_leases.len());
        let (stale_worker, _key, stale_lease) = self.stale_leases.swap_remove(idx);

        let op_id = match self.workers.get_mut(&stale_worker) {
            Some(w) => w.next_op_id(),
            None => {
                return SimEvent::Rejected {
                    kind: RejectionKind::WorkerNotFound,
                };
            }
        };

        let update = CursorUpdate::new(b"m");
        let now = self.context.now();
        match self
            .coordinator
            .checkpoint(now, self.tenant, &stale_lease, &update, op_id)
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

    /// Admin unpark operation.
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

    /// Run terminal transition (complete, fail, or cancel).
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

    /// WorkerSession lifecycle: acquire → checkpoint(1-3x) → terminal.
    fn exec_session_lifecycle(&mut self, worker: WorkerId, key: ShardKey) -> SimEvent {
        if self.workers.get(&worker).is_none_or(|w| w.is_paused()) {
            return SimEvent::Rejected {
                kind: RejectionKind::WorkerPaused,
            };
        }

        // Phase 1: Pre-compute random decisions.
        let (range_lo, range_hi) = self
            .coordinator
            .shard_lookup(&self.tenant, &key)
            .map(|r| {
                let (start, end) = self.coordinator.spec_bounds(r);
                let lo = start.first().copied().unwrap_or(b'a');
                let hi = end.first().copied().unwrap_or(b'z');
                (lo, hi)
            })
            .expect("exec_session_lifecycle: shard missing from coordinator");

        let num_checkpoints: u32 = self.context.rng().random_range(1..=3);

        let range_wide_enough = range_hi.saturating_sub(range_lo) >= 2;
        let terminal_action = match self.context.rng().random_range(0u32..10) {
            0..2 => SessionTerminalAction::Park,
            2..4 if range_wide_enough => SessionTerminalAction::SplitReplace,
            4 if range_wide_enough => SessionTerminalAction::SplitResidualThenComplete,
            _ => SessionTerminalAction::Complete,
        };

        let extra_ops = match terminal_action {
            SessionTerminalAction::SplitResidualThenComplete => 2,
            _ => 1,
        };
        let total_cursors = num_checkpoints as usize + extra_ops;
        let mut cursors: Vec<Vec<u8>> = Vec::with_capacity(total_cursors);
        let mut lo = range_lo;
        for _ in 0..total_cursors {
            if lo >= range_hi {
                let byte = cursors
                    .last()
                    .and_then(|c| c.first().copied())
                    .unwrap_or(range_hi.saturating_sub(1));
                cursors.push(vec![byte]);
            } else {
                let byte = self.context.rng().random_range(lo..range_hi);
                cursors.push(vec![byte]);
                lo = byte.saturating_add(1);
            }
        }

        let split_replace_plan = if matches!(terminal_action, SessionTerminalAction::SplitReplace) {
            random_midpoint(self.context.rng(), range_lo + 1, range_hi)
        } else {
            None
        };

        let split_residual_plan = if matches!(
            terminal_action,
            SessionTerminalAction::SplitResidualThenComplete
        ) {
            let last_cp_byte = cursors
                .get(num_checkpoints.saturating_sub(1) as usize)
                .and_then(|c| c.first().copied())
                .unwrap_or(range_lo);
            precompute_split_residual_plan(self.context.rng(), range_lo, range_hi, last_cp_byte)
        } else {
            None
        };

        let terminal_action = match terminal_action {
            SessionTerminalAction::SplitReplace if split_replace_plan.is_none() => {
                SessionTerminalAction::Complete
            }
            SessionTerminalAction::SplitResidualThenComplete if split_residual_plan.is_none() => {
                SessionTerminalAction::Complete
            }
            other => other,
        };

        let w = match self.workers.get_mut(&worker) {
            Some(w) => w,
            None => return SimEvent::Skipped,
        };
        let op_ids: Vec<OpId> = (0..total_cursors).map(|_| w.next_op_id()).collect();

        // Phase 2: Execute session.
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

            let mut checkpoints_ok: u32 = 0;
            let mut checkpoints_rejected: u32 = 0;
            for i in 0..num_checkpoints as usize {
                let update = CursorUpdate::with_last_key(&cursors[i]);
                match sess.checkpoint(now, &update, op_ids[i]) {
                    Ok(_) => checkpoints_ok += 1,
                    Err(e) => {
                        if matches!(e, CheckpointError::BackendError(..)) {
                            panic!(
                                "simulation backend produced unexpected infrastructure error: {e:?}"
                            );
                        }
                        checkpoints_rejected += 1;
                    }
                }
            }

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
                    let terminal_update = CursorUpdate::with_last_key(&cursors[terminal_idx]);
                    let is_terminal = match sess.complete(
                        now,
                        &terminal_update,
                        op_ids[terminal_idx],
                    ) {
                        Ok(_) => true,
                        Err(CompleteError::BackendError(infra)) => {
                            panic!(
                                "simulation backend produced unexpected infrastructure error: {infra}"
                            )
                        }
                        Err(_) => false,
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
                    let mid = split_replace_plan
                        .expect("terminal_action normalized away SplitReplace without midpoint");
                    let range_lo_key = [range_lo];
                    let mid_key = [mid];
                    let range_hi_key = [range_hi];
                    let parent_spec = ShardSpecRef::with_range(&range_lo_key, &range_hi_key);
                    let plan = match plan_split_replace_at_points_initial_cursor(
                        parent_spec,
                        [mid_key.as_slice()],
                    ) {
                        Ok(plan) => plan,
                        Err(_) => {
                            return Ok(SessionOutcome {
                                lease,
                                is_terminal: false,
                                checkpoints_ok,
                                checkpoints_rejected,
                                split_children: Vec::new(),
                            });
                        }
                    };
                    match sess.split_replace(now, plan, op_ids[terminal_idx]) {
                        Ok(outcome) => {
                            let children = outcome.into_inner().children;
                            Ok(SessionOutcome {
                                lease,
                                is_terminal: true,
                                checkpoints_ok,
                                checkpoints_rejected,
                                split_children: children.iter().copied().collect(),
                            })
                        }
                        Err(SplitError::BackendError(infra)) => {
                            panic!(
                                "simulation backend produced unexpected infrastructure error: {infra}"
                            )
                        }
                        Err(_) => Ok(SessionOutcome {
                            lease,
                            is_terminal: false,
                            checkpoints_ok,
                            checkpoints_rejected,
                            split_children: Vec::new(),
                        }),
                    }
                }
                SessionTerminalAction::SplitResidualThenComplete => {
                    let (mid, complete_byte) = split_residual_plan.expect(
                        "terminal_action normalized away SplitResidualThenComplete without bytes",
                    );
                    let range_lo_key = [range_lo];
                    let mid_key = [mid];
                    let range_hi_key = [range_hi];
                    let parent_spec = ShardSpecRef::with_range(&range_lo_key, &range_hi_key);
                    let plan = match plan_split_residual_at_point(parent_spec, mid_key.as_slice()) {
                        Ok(plan) => plan,
                        Err(_) => {
                            return Ok(SessionOutcome {
                                lease,
                                is_terminal: false,
                                checkpoints_ok,
                                checkpoints_rejected,
                                split_children: Vec::new(),
                            });
                        }
                    };
                    let split_ok = match sess.split_residual(now, plan, op_ids[terminal_idx]) {
                        Ok(_) => true,
                        Err(SplitError::BackendError(infra)) => {
                            panic!(
                                "simulation backend produced unexpected infrastructure error: {infra}"
                            )
                        }
                        Err(_) => false,
                    };
                    if split_ok {
                        let residual_id = sess.initial_snapshot().spawned().last().copied();
                        let complete_idx = terminal_idx + 1;
                        let complete_key = [complete_byte];
                        let complete_cursor = CursorUpdate::with_last_key(&complete_key);
                        let is_terminal = match sess.complete(
                            now,
                            &complete_cursor,
                            op_ids[complete_idx],
                        ) {
                            Ok(_) => true,
                            Err(CompleteError::BackendError(infra)) => {
                                panic!(
                                    "simulation backend produced unexpected infrastructure error: {infra}"
                                )
                            }
                            Err(_) => false,
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

        // Phase 3: Reconcile bookkeeping.
        let outcome = match session_result {
            Ok(o) => o,
            Err(event) => return event,
        };

        self.record_acquire_bookkeeping(worker, key, outcome.lease);

        let run = key.run();
        for &child_id in &outcome.split_children {
            let child_key = ShardKey::new(run, child_id);
            self.shard_keys.push(child_key);
            self.active_shard_keys.push(child_key);
            self.run_shard_ids.entry(run).or_default().push(child_id);
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
    // Shared helpers
    // -----------------------------------------------------------------------

    /// Update worker bookkeeping after a successful acquire.
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

    /// Remove a shard from the active set.
    fn remove_active_shard(&mut self, key: ShardKey) {
        if let Some(pos) = self.active_shard_keys.iter().position(|k| *k == key) {
            self.active_shard_keys.swap_remove(pos);
        }
    }

    /// Release a shard from its owning worker and remove from active set.
    fn mark_shard_terminal(&mut self, worker: WorkerId, key: ShardKey) {
        if let Some(w) = self.workers.get_mut(&worker) {
            w.record_release(&key);
        }
        self.remove_active_shard(key);
    }

    /// Generate a monotonically forward-progressing cursor for a shard.
    ///
    /// Replicates [`CoordinationSim::generate_forward_cursor`] logic:
    /// advances from the last cursor position (or spec start), with variable
    /// key length (1-3 bytes).
    fn generate_forward_cursor(&mut self, worker: WorkerId, key: ShardKey) -> Vec<u8> {
        let last = self
            .workers
            .get(&worker)
            .and_then(|w| w.last_cursor_for(key.run(), key.shard()));

        let (spec_start, spec_end) = self
            .coordinator
            .shard_lookup(&self.tenant, &key)
            .map(|r| {
                let (start, end) = self.coordinator.spec_bounds(r);
                (start.to_vec(), end.to_vec())
            })
            .expect("generate_forward_cursor: shard missing from coordinator");

        let last_first = last.and_then(|k| k.first().copied());
        let range_lo = spec_start.first().copied().unwrap_or(b'a');
        let range_hi = spec_end.first().copied().unwrap_or(b'z');

        let start = match last_first {
            Some(k) => k.saturating_add(1).max(range_lo),
            None => range_lo,
        };

        if start >= range_hi {
            if let Some(prev) = last {
                return prev.to_vec();
            }
            return vec![range_hi.saturating_sub(1)];
        }

        let first_byte = self.context.rng().random_range(start..range_hi);
        let key_len: usize = self.context.rng().random_range(1..=3);
        let mut cursor_key = Vec::with_capacity(key_len);
        cursor_key.push(first_byte);
        for _ in 1..key_len {
            cursor_key.push(self.context.rng().random_range(0u8..=255));
        }

        cursor_key
    }

    /// Generate the next admin op-ID from the reserved partition 0.
    fn next_admin_op_id(&mut self) -> OpId {
        assert!(
            self.admin_next_op < super::worker::OP_ID_PARTITION,
            "admin op-ID partition exhausted"
        );
        let id = OpId::from_raw(self.admin_next_op);
        self.admin_next_op += 1;
        id
    }

    /// Common preamble for replay and conflict checkpoint operations.
    fn checkpoint_preamble(
        &self,
        worker: WorkerId,
        key: ShardKey,
    ) -> Result<(OpId, Vec<u8>, Lease), SimEvent> {
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

    /// Copy split-relevant shard inputs into stack-owned buffers.
    fn copy_shard_split_inputs(&self, key: ShardKey) -> Result<SplitInputCopy, SimEvent> {
        let record =
            self.coordinator
                .shard_lookup(&self.tenant, &key)
                .ok_or(SimEvent::Rejected {
                    kind: RejectionKind::ShardNotFound,
                })?;

        let (start, end) = self.coordinator.spec_bounds(record);
        debug_assert!(start.len() <= MAX_KEY_SIZE);
        debug_assert!(end.len() <= MAX_KEY_SIZE);

        let mut start_buf = [0u8; MAX_KEY_SIZE];
        let mut end_buf = [0u8; MAX_KEY_SIZE];
        start_buf[..start.len()].copy_from_slice(start);
        end_buf[..end.len()].copy_from_slice(end);

        let cursor_first_byte = self
            .coordinator
            .cursor_last_key(record)
            .and_then(|k| k.first().copied());

        Ok((
            (start_buf, start.len(), end_buf, end.len()),
            cursor_first_byte,
        ))
    }

    /// Compute a random single-byte split point within `(start[0], end[0])`.
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
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Validate worker preconditions and consume the next op-ID.
///
/// Free function for borrow splitting: callers pass `&mut self.workers`
/// while retaining mutable access to `self.coordinator` and `self.context`.
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
fn random_midpoint(rng: &mut ChaCha8Rng, lo: u8, hi: u8) -> Option<u8> {
    if lo >= hi {
        return None;
    }
    Some(rng.random_range(lo..hi))
}

/// Pre-compute a split-residual plan and a post-split completion cursor.
fn precompute_split_residual_plan(
    rng: &mut ChaCha8Rng,
    range_lo: u8,
    range_hi: u8,
    last_checkpoint_byte: u8,
) -> Option<(u8, u8)> {
    let lo = last_checkpoint_byte
        .saturating_add(1)
        .max(range_lo.saturating_add(1));
    let mid = random_midpoint(rng, lo, range_hi)?;
    // Completion cursor: random byte in `[mid, range_hi)` for the narrowed parent.
    let complete_byte = if mid >= range_hi {
        mid
    } else {
        rng.random_range(mid..range_hi)
    };
    Some((mid, complete_byte))
}

/// Terminal action selection for session lifecycle.
#[derive(Debug, Clone, Copy)]
enum SessionTerminalAction {
    Complete,
    Park,
    SplitReplace,
    SplitResidualThenComplete,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sunny_day_full_lifecycle_no_violations() {
        let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
        let mut sim = CompositionSim::new(42, config)
            .with_workers_and_shards(2, 4)
            .expect("setup should succeed");

        // Advance time to ensure clock is past initial.
        sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

        // Each worker claims and scans one shard.
        for i in 1..=2u64 {
            let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
                worker: WorkerId::from_raw(i),
            });
            assert!(
                violations.is_empty(),
                "worker {i} violations: {violations:?}"
            );
            assert!(
                matches!(event, CompositionSimEvent::ScanCompleted { .. }),
                "expected ScanCompleted, got {event:?}"
            );
        }

        // Verify provenance log.
        assert_eq!(sim.write_log().len(), 2);
        for entry in sim.write_log() {
            assert!(entry.committed);
            assert!(entry.record_count > 0);
        }
    }

    #[test]
    fn crash_after_complete_records_uncommitted_provenance() {
        let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
        let mut sim = CompositionSim::new(99, config)
            .with_workers_and_shards(1, 2)
            .expect("setup should succeed");

        sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

        let (event, violations) = sim.step(CompositionSimOp::ScanLifecycleCrashAfterComplete {
            worker: WorkerId::from_raw(1),
        });

        assert!(violations.is_empty(), "violations: {violations:?}");
        assert!(matches!(
            event,
            CompositionSimEvent::ScanCrashedAfterComplete { .. }
        ));

        assert_eq!(sim.write_log().len(), 1);
        assert!(!sim.write_log()[0].committed);
    }

    #[test]
    fn coord_pass_through_works() {
        let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
        let mut sim = CompositionSim::new(7, config)
            .with_workers_and_shards(2, 4)
            .expect("setup should succeed");

        sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

        // Pass-through a ClaimNext.
        let (event, violations) = sim.step(CompositionSimOp::Coord(SimOp::ClaimNext {
            worker: WorkerId::from_raw(1),
        }));
        assert!(violations.is_empty(), "violations: {violations:?}");
        assert!(
            matches!(event, CompositionSimEvent::Coord(SimEvent::ClaimOk { .. })),
            "expected ClaimOk, got {event:?}"
        );
    }

    #[test]
    fn seed_reproducibility() {
        /// Run a fixed op sequence and collect full event traces for comparison.
        fn run_seed(seed: u64) -> Vec<(CompositionSimEvent, usize)> {
            let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
            let mut sim = CompositionSim::new(seed, config)
                .with_workers_and_shards(2, 4)
                .expect("setup should succeed");

            sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

            let mut trace = Vec::new();
            for i in 1..=2u64 {
                let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
                    worker: WorkerId::from_raw(i),
                });
                trace.push((event, violations.len()));
            }
            // Also compare provenance log contents.
            assert_eq!(
                sim.write_log().len(),
                2,
                "expected 2 provenance entries per run"
            );
            trace
        }

        assert_eq!(run_seed(42), run_seed(42));
        assert_eq!(run_seed(123), run_seed(123));
    }

    #[test]
    fn inject_ledger_fault_records_uncommitted_provenance() {
        let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
        let mut sim = CompositionSim::new(55, config)
            .with_workers_and_shards(1, 2)
            .expect("setup should succeed");

        sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

        // Inject a submit failure so the ledger rejects the write.
        sim.step(CompositionSimOp::InjectLedgerFault(
            DoneLedgerFaultOp::InjectSubmitFailure { count: 1 },
        ));

        let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
            worker: WorkerId::from_raw(1),
        });
        // Ledger write failed → event is ScanLedgerWriteFailed, coordinator
        // complete() is not called, and the shard remains available.
        assert!(
            matches!(event, CompositionSimEvent::ScanLedgerWriteFailed { .. }),
            "expected ScanLedgerWriteFailed, got {event:?}"
        );
        assert!(
            violations.is_empty(),
            "submit-failure rollback should be clean: {violations:?}"
        );

        // The provenance entry must reflect that the ledger write did not commit.
        let entry = sim
            .write_log()
            .last()
            .expect("should have provenance entry");
        assert!(
            !entry.committed,
            "provenance should record uncommitted after submit failure"
        );
    }

    #[test]
    fn submit_failure_records_uncommitted_provenance() {
        let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
        let mut sim = CompositionSim::new(55, config)
            .with_workers_and_shards(1, 2)
            .expect("setup should succeed");

        sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

        // Inject a submit failure so the ledger write is rejected.
        sim.step(CompositionSimOp::InjectLedgerFault(
            DoneLedgerFaultOp::InjectSubmitFailure { count: 1 },
        ));

        let (_event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
            worker: WorkerId::from_raw(1),
        });
        assert!(
            violations.is_empty(),
            "submit-failure rollback should be clean: {violations:?}"
        );

        let entry = sim
            .write_log()
            .last()
            .expect("should have provenance entry");
        assert!(
            !entry.committed,
            "provenance should record uncommitted when ledger write fails"
        );
    }
}
