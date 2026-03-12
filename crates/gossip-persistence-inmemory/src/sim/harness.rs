//! Simulation harness driver for [`InMemoryDoneLedger`].
//!
//! Generates weighted random operation sequences via seeded PRNG,
//! injects persistence faults at PPM-configurable rates, and verifies
//! invariants after every step.
//!
//! # Two-phase execution
//!
//! The [`DoneLedgerSim::run`] method executes a safety phase followed
//! by a liveness phase:
//!
//! 1. **Safety phase**: random ops with fault injection. Invariants
//!    I1–I4, I7, I9–I10 are checked after every step. I5 and I8 are
//!    skipped for delayed-release operations (pre-snapshots are stale);
//!    the oracle convergence check (I6) covers those paths instead.
//! 2. **Liveness phase**: stop generating faults, drain pending writes
//!    one at a time (checking each outcome), run additional ops, verify
//!    I6 convergence via the oracle.
//!
//! [`InMemoryDoneLedger`]: crate::InMemoryDoneLedger

use std::collections::{BTreeMap, HashMap};

use gossip_contracts::{
    identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
    persistence::{
        CommitHandle, DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance,
        DoneLedgerRecord, DoneLedgerStatus, OvidHash,
    },
};
use rand::Rng;

use super::{
    DoneLedgerSimEvent, DoneLedgerSimEventKind, DoneLedgerSimOp, FaultLevel, PersistenceSim,
    SimContext,
    invariants::{DoneLedgerInvariantChecker, DoneLedgerInvariantViolation},
    oracle::DoneLedgerOracle,
};
use crate::{CompletionOrder, InMemoryDoneLedger, InMemoryDoneLedgerHandle, PendingWriteId};

// ── Constants ────────────────────────────────────────────────────────

/// Number of distinct OvidHash values in the shared key pool.
/// Overlapping keys force merge contention.
const OVID_POOL_SIZE: usize = 50;

/// First N safety ops suppress fault injection to allow initial state
/// population.
const WARMUP_OPS: usize = 5;

/// Maximum retries for weighted op generation before falling back.
const MAX_OP_RETRIES: usize = 10;

/// All possible DoneLedgerStatus values for random selection.
const ALL_STATUSES: [DoneLedgerStatus; 5] = [
    DoneLedgerStatus::FailedRetryable,
    DoneLedgerStatus::FailedPermanent,
    DoneLedgerStatus::Skipped,
    DoneLedgerStatus::ScannedClean,
    DoneLedgerStatus::ScannedWithFindings,
];

// ── FaultConfig ──────────────────────────────────────────────────────

/// PPM-based fault injection rates for the persistence simulation.
/// Integer rates in `[0, 1_000_000]` avoid IEEE 754 rounding variance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoneLedgerFaultConfig {
    /// Probability (PPM) of injecting a submit failure per step.
    pub submit_fail_ppm: u32,
    /// Probability (PPM) of injecting a commit failure per step.
    pub commit_fail_ppm: u32,
    /// Probability (PPM) of injecting a write delay per step.
    pub delay_ppm: u32,
}

impl DoneLedgerFaultConfig {
    /// Construct config for a given fault severity level.
    pub fn for_level(level: FaultLevel) -> Self {
        match level {
            FaultLevel::SunnyDay => Self {
                submit_fail_ppm: 0,
                commit_fail_ppm: 0,
                delay_ppm: 0,
            },
            FaultLevel::Stormy => Self {
                submit_fail_ppm: 100_000,
                commit_fail_ppm: 100_000,
                delay_ppm: 100_000,
            },
            FaultLevel::Radioactive => Self {
                submit_fail_ppm: 200_000,
                commit_fail_ppm: 200_000,
                delay_ppm: 200_000,
            },
        }
    }

    /// Returns `true` when all fault rates are zero.
    fn is_fault_free(&self) -> bool {
        self.submit_fail_ppm == 0 && self.commit_fail_ppm == 0 && self.delay_ppm == 0
    }
}

// ── DoneLedgerSimReport ──────────────────────────────────────────────

/// Summary of a simulation run.
#[must_use]
#[derive(Debug)]
pub struct DoneLedgerSimReport {
    /// The PRNG seed used for this run.
    pub seed: u64,
    /// Total operations executed across both phases. During drain
    /// phases, each pending batch release counts as one operation.
    pub ops_executed: usize,
    /// All invariant violations detected.
    pub violations: Vec<DoneLedgerInvariantViolation>,
    /// Per-event-kind counts.
    pub event_counts: BTreeMap<DoneLedgerSimEventKind, usize>,
    /// Whether the liveness phase achieved I6 convergence.
    pub converged: bool,
}

// ── PendingBatch ─────────────────────────────────────────────────────

/// A delayed write whose commit handle is retained so we can verify
/// the outcome after the store releases the op.
struct PendingBatch {
    records: Vec<DoneLedgerRecord>,
    handle: InMemoryDoneLedgerHandle,
}

// ── DoneLedgerSim ────────────────────────────────────────────────────

/// The main simulation harness. Composes the ledger, oracle, invariant
/// checker, and PRNG context into a single driver.
pub struct DoneLedgerSim {
    context: SimContext,
    ledger: InMemoryDoneLedger,
    oracle: DoneLedgerOracle,
    checker: DoneLedgerInvariantChecker,
    fault_config: DoneLedgerFaultConfig,

    /// Fixed tenant identity for all generated records.
    tenant: TenantId,
    /// Fixed policy identity for all generated records.
    policy: PolicyHash,
    /// Pool of OvidHash values shared across batches to force merge
    /// contention.
    ovid_pool: Vec<OvidHash>,

    /// Total operations executed.
    ops_executed: usize,

    /// Delayed writes keyed by operation ID. Each entry retains the
    /// commit handle and original records. Pre-snapshots are not stored;
    /// delayed-release paths use empty snapshots and skip I5/I8.
    pending_batches: HashMap<PendingWriteId, PendingBatch>,

    /// Cached error code for failure/skipped records to avoid
    /// per-record allocation of the same value.
    sim_error_code: DoneLedgerErrorCode,

    /// Monotonic counter for generating unique provenance values.
    next_run_id: u64,
}

impl DoneLedgerSim {
    /// Construct a new simulation harness.
    ///
    /// - `seed`: PRNG seed for deterministic replay.
    /// - `level`: fault injection severity.
    pub fn new(seed: u64, level: FaultLevel) -> Self {
        let mut context = SimContext::new(seed);

        // Generate the ovid pool deterministically from the PRNG.
        let ovid_pool: Vec<OvidHash> = (0..OVID_POOL_SIZE)
            .map(|_| {
                let mut bytes = [0u8; 32];
                context.rng().fill(&mut bytes);
                OvidHash::from_bytes(bytes)
            })
            .collect();

        let tenant = TenantId::from_bytes([0x01; 32]);
        let policy = PolicyHash::from_bytes([0x02; 32]);

        Self {
            context,
            ledger: InMemoryDoneLedger::new(),
            oracle: DoneLedgerOracle::new(),
            checker: DoneLedgerInvariantChecker::new(),
            fault_config: DoneLedgerFaultConfig::for_level(level),
            tenant,
            policy,
            ovid_pool,
            ops_executed: 0,
            pending_batches: HashMap::new(),
            sim_error_code: DoneLedgerErrorCode::try_new("SIM_ERROR").unwrap(),
            next_run_id: 1,
        }
    }

    /// Access the underlying ledger (for test assertions).
    pub fn ledger(&self) -> &InMemoryDoneLedger {
        &self.ledger
    }

    /// Access the oracle (for test assertions).
    pub fn oracle(&self) -> &DoneLedgerOracle {
        &self.oracle
    }

    /// Execute a safety phase followed by a liveness phase.
    ///
    /// Consumes `self` to prevent accidental state reuse after a run.
    pub fn run(mut self, safety_ops: usize, liveness_ops: usize) -> DoneLedgerSimReport {
        let seed = self.context.seed();
        let mut all_violations = Vec::new();
        let mut event_counts = BTreeMap::new();

        // ── Safety phase ─────────────────────────────────────────────
        for i in 0..safety_ops {
            let suppress_faults = i < WARMUP_OPS;
            let op = self.generate_random_op(suppress_faults);
            let (event, violations) = self.step(op);
            Self::record_event(&event, &mut event_counts);
            all_violations.extend(violations);
        }

        // ── Liveness phase ───────────────────────────────────────────
        // Set auto-complete so new writes commit immediately.
        self.ledger
            .set_auto_complete(true)
            .expect("set_auto_complete should not fail on InMemoryDoneLedger");

        // Drain pending writes accumulated during safety phase.
        let drain_violations = self.drain_all_pending(&mut event_counts);
        all_violations.extend(drain_violations);

        // Run additional fault-free ops to populate more state.
        // Some may still encounter residual fault counters from the
        // safety phase — the oracle handles this correctly via
        // submit/commit/abort tracking.
        for _ in 0..liveness_ops {
            let op = self.generate_liveness_op();
            let (event, violations) = self.step(op);
            Self::record_event(&event, &mut event_counts);
            all_violations.extend(violations);
        }

        // Final drain: release any ops that got delayed during liveness
        // due to residual delay counters from the safety phase.
        if !self.pending_batches.is_empty() {
            let drain_violations = self.drain_all_pending(&mut event_counts);
            all_violations.extend(drain_violations);
        }

        // ── Convergence check (I6) ──────────────────────────────────
        let convergence_violations = self.oracle.verify_convergence(&self.ledger);
        let converged = convergence_violations.is_empty();
        all_violations.extend(convergence_violations);

        DoneLedgerSimReport {
            seed,
            ops_executed: self.ops_executed,
            violations: all_violations,
            event_counts,
            converged,
        }
    }

    // ── Pending-drain logic ──────────────────────────────────────────

    /// Record an event in the histogram. For `ReleasedAll`, also records
    /// per-batch `Released`/`ReleasedCommitFailed` breakdown so the
    /// histogram is consistent with `drain_all_pending`.
    fn record_event(
        event: &DoneLedgerSimEvent,
        event_counts: &mut BTreeMap<DoneLedgerSimEventKind, usize>,
    ) {
        *event_counts.entry(event.kind()).or_insert(0) += 1;
        if let DoneLedgerSimEvent::ReleasedAll {
            committed, failed, ..
        } = event
        {
            *event_counts
                .entry(DoneLedgerSimEventKind::Released)
                .or_insert(0) += committed;
            *event_counts
                .entry(DoneLedgerSimEventKind::ReleasedCommitFailed)
                .or_insert(0) += failed;
        }
    }

    /// Release all pending writes, consuming the retained commit handles
    /// to verify each outcome. Returns any violations.
    ///
    /// Pre-snapshots taken at submission time are stale for delayed writes
    /// (other commits may have modified the same keys). We pass empty
    /// snapshots to skip I8 (ProvenanceFidelity) which relies on the
    /// pre-snapshot. I1/I2/I3/I9 still work correctly without it.
    /// I5 (CommitRollback) is skipped for the same reason.
    /// The oracle convergence check (I6) serves as the authoritative
    /// verification for delayed-write correctness.
    fn drain_all_pending(
        &mut self,
        event_counts: &mut BTreeMap<DoneLedgerSimEventKind, usize>,
    ) -> Vec<DoneLedgerInvariantViolation> {
        let mut all_violations = Vec::new();

        // Release all ops in the store in oldest-first order.
        self.ledger
            .release_all(CompletionOrder::OldestFirst)
            .expect("release_all should not fail on InMemoryDoneLedger");

        // Empty snapshot — I8 checks are skipped for stale pre-snapshots.
        let empty_snapshot: Vec<Option<DoneLedgerRecord>> = Vec::new();

        // Consume retained handles in op_id order to match the store's
        // oldest-first release order. This ensures the oracle commits
        // in the same sequence, producing identical merge results.
        let mut sorted_batches: Vec<(PendingWriteId, PendingBatch)> =
            self.pending_batches.drain().collect();
        sorted_batches.sort_by_key(|(id, _)| *id);

        for (op_id, batch) in sorted_batches {
            self.ops_executed += 1;
            self.context.tick();

            match batch.handle.wait() {
                Ok(receipt) => {
                    let was_pending = self.oracle.commit(op_id);
                    debug_assert!(
                        was_pending,
                        "drain_all_pending: op {op_id} was not pending in oracle"
                    );
                    // Use empty_snapshot so I8 is skipped (stale pre-snapshot).
                    let violations = self.checker.check_after_committed_upsert(
                        &self.ledger,
                        &batch.records,
                        &receipt,
                        &empty_snapshot,
                    );
                    *event_counts
                        .entry(DoneLedgerSimEventKind::Released)
                        .or_insert(0) += 1;
                    all_violations.extend(violations);
                }
                Err(_) => {
                    // Commit failed (residual fail_commit counter).
                    // Skip I5 check — pre-snapshot is stale, convergence
                    // check (I6) will catch any real bugs.
                    self.oracle.abort(op_id);
                    *event_counts
                        .entry(DoneLedgerSimEventKind::ReleasedCommitFailed)
                        .or_insert(0) += 1;
                }
            }
        }

        all_violations
    }

    // ── Op execution ─────────────────────────────────────────────────

    /// Execute a single operation against the ledger, update the oracle,
    /// run invariant checks, and return the event + violations.
    fn execute_op(
        &mut self,
        op: &DoneLedgerSimOp,
    ) -> (DoneLedgerSimEvent, Vec<DoneLedgerInvariantViolation>) {
        match op {
            DoneLedgerSimOp::BatchUpsert { records } => self.exec_batch_upsert(records),
            DoneLedgerSimOp::BatchGet { ovid_indices } => self.exec_batch_get(ovid_indices),
            DoneLedgerSimOp::ReleaseOldest => self.exec_release_next(CompletionOrder::OldestFirst),
            DoneLedgerSimOp::ReleaseNewest => self.exec_release_next(CompletionOrder::NewestFirst),
            DoneLedgerSimOp::ReleaseSpecific { op_id } => self.exec_release_specific(*op_id),
            DoneLedgerSimOp::ReleaseAll { order } => self.exec_release_all(*order),
            DoneLedgerSimOp::InjectSubmitFailure { count } => {
                self.ledger
                    .fail_next_submissions(*count)
                    .expect("fail_next_submissions should not fail on InMemoryDoneLedger");
                (DoneLedgerSimEvent::FaultConfigured, Vec::new())
            }
            DoneLedgerSimOp::InjectCommitFailure { count } => {
                self.ledger
                    .fail_next_commits(*count)
                    .expect("fail_next_commits should not fail on InMemoryDoneLedger");
                (DoneLedgerSimEvent::FaultConfigured, Vec::new())
            }
            DoneLedgerSimOp::InjectDelay { count } => {
                self.ledger
                    .delay_next_writes(*count)
                    .expect("delay_next_writes should not fail on InMemoryDoneLedger");
                (DoneLedgerSimEvent::FaultConfigured, Vec::new())
            }
        }
    }

    fn exec_batch_upsert(
        &mut self,
        records: &[DoneLedgerRecord],
    ) -> (DoneLedgerSimEvent, Vec<DoneLedgerInvariantViolation>) {
        // Take pre-submission snapshot for rollback checks.
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
                let violations =
                    self.checker
                        .check_after_submit_failure(&self.ledger, records, &pre_snapshot);
                (DoneLedgerSimEvent::UpsertSubmitFailed, violations)
            }
            Ok(handle) => {
                let op_id = handle.operation_id();

                // Register with oracle as pending.
                self.oracle.submit(op_id, records.to_vec());

                // Check if this is a delayed write by querying pending IDs.
                let pending_ids = self
                    .ledger
                    .pending_ids()
                    .expect("pending_ids should not fail on InMemoryDoneLedger");

                if pending_ids.contains(&op_id) {
                    // Write is delayed — retain handle for later verification.
                    // PendingWriteId is monotonically increasing, so collisions
                    // are structurally impossible; assert to catch store bugs.
                    debug_assert!(
                        !self.pending_batches.contains_key(&op_id),
                        "duplicate PendingWriteId {op_id} — store counter invariant violated"
                    );

                    // Verify the delayed write has not leaked into visible
                    // state. The ledger snapshot should be unchanged from
                    // pre-submission for every key in this batch.
                    let violations = self.checker.check_after_submit_failure(
                        &self.ledger,
                        records,
                        &pre_snapshot,
                    );

                    self.pending_batches.insert(
                        op_id,
                        PendingBatch {
                            records: records.to_vec(),
                            handle,
                        },
                    );
                    (DoneLedgerSimEvent::UpsertPending { op_id }, violations)
                } else {
                    // Auto-completed — wait() returns immediately.
                    match handle.wait() {
                        Ok(receipt) => {
                            self.oracle.commit(op_id);
                            let violations = self.checker.check_after_committed_upsert(
                                &self.ledger,
                                records,
                                &receipt,
                                &pre_snapshot,
                            );
                            (
                                DoneLedgerSimEvent::UpsertCommitted { op_id, receipt },
                                violations,
                            )
                        }
                        Err(_) => {
                            // Commit failed at auto-complete time.
                            self.oracle.abort(op_id);
                            let violations = self.checker.check_after_commit_failure(
                                &self.ledger,
                                records,
                                &pre_snapshot,
                            );
                            (DoneLedgerSimEvent::UpsertCommitFailed { op_id }, violations)
                        }
                    }
                }
            }
        }
    }

    fn exec_batch_get(
        &mut self,
        ovid_indices: &[usize],
    ) -> (DoneLedgerSimEvent, Vec<DoneLedgerInvariantViolation>) {
        let ovid_hashes: Vec<OvidHash> = ovid_indices
            .iter()
            .map(|&i| self.ovid_pool[i % self.ovid_pool.len()])
            .collect();

        let results = self
            .ledger
            .batch_get(self.tenant, self.policy, &ovid_hashes)
            .expect("batch_get should not fail on InMemoryDoneLedger");

        // I7: Validate read results against the oracle's committed view.
        // For keys the oracle has committed state for, the ledger must
        // return a matching record.
        let mut violations = Vec::new();
        for (i, ovid_hash) in ovid_hashes.iter().enumerate() {
            let key = DoneLedgerKey::new(self.tenant, self.policy, *ovid_hash);
            let oracle_record = self.oracle.expected_state(&key);
            let ledger_record = results.get(i).and_then(|r| r.as_ref());

            match (oracle_record, ledger_record) {
                (Some(expected), Some(actual)) if expected != actual => {
                    violations.push(DoneLedgerInvariantViolation::ReadConsistency {
                        key,
                        oracle: Some(Box::new(expected.clone())),
                        actual: Some(Box::new(actual.clone())),
                    });
                }
                (Some(expected), None) => {
                    violations.push(DoneLedgerInvariantViolation::ReadConsistency {
                        key,
                        oracle: Some(Box::new(expected.clone())),
                        actual: None,
                    });
                }
                (None, Some(actual)) => {
                    // Single-threaded sim: oracle commits synchronously,
                    // so a ledger record with no oracle entry means the
                    // oracle missed a commit or a delayed write leaked.
                    violations.push(DoneLedgerInvariantViolation::ReadConsistency {
                        key,
                        oracle: None,
                        actual: Some(Box::new(actual.clone())),
                    });
                }
                _ => {}
            }
        }

        (DoneLedgerSimEvent::GetOk { results }, violations)
    }

    fn exec_release_next(
        &mut self,
        order: CompletionOrder,
    ) -> (DoneLedgerSimEvent, Vec<DoneLedgerInvariantViolation>) {
        match self.ledger.release_next(order) {
            Ok(Some(op_id)) => {
                // The store has finished this op. Consume our retained
                // handle to learn whether the commit succeeded or failed.
                if let Some(batch) = self.pending_batches.remove(&op_id) {
                    // Pre-snapshot is stale (taken at submission time,
                    // not release time). Use empty snapshot to skip I8,
                    // and skip I5 on commit failure. Convergence (I6)
                    // is the authoritative check for delayed writes.
                    let empty_snapshot: Vec<Option<DoneLedgerRecord>> = Vec::new();
                    match batch.handle.wait() {
                        Ok(receipt) => {
                            self.oracle.commit(op_id);
                            let violations = self.checker.check_after_committed_upsert(
                                &self.ledger,
                                &batch.records,
                                &receipt,
                                &empty_snapshot,
                            );
                            (DoneLedgerSimEvent::Released { op_id, receipt }, violations)
                        }
                        Err(_) => {
                            self.oracle.abort(op_id);
                            // Skip I5 — stale pre-snapshot.
                            (
                                DoneLedgerSimEvent::ReleasedCommitFailed { op_id },
                                Vec::new(),
                            )
                        }
                    }
                } else {
                    // The store released an op the harness never tracked.
                    // This violates the invariant that every delayed write
                    // is recorded in pending_batches at submission time.
                    panic!(
                        "release_next returned op_id {op_id} which has no \
                         entry in pending_batches — harness tracking bug"
                    );
                }
            }
            Ok(None) => (DoneLedgerSimEvent::ReleaseNoop, Vec::new()),
            Err(e) => panic!("release_next failed on InMemoryDoneLedger: {e}"),
        }
    }

    fn exec_release_specific(
        &mut self,
        op_id: PendingWriteId,
    ) -> (DoneLedgerSimEvent, Vec<DoneLedgerInvariantViolation>) {
        match self.ledger.release_specific(op_id) {
            Ok(true) => {
                if let Some(batch) = self.pending_batches.remove(&op_id) {
                    // Stale pre-snapshot — use empty for I8, skip I5.
                    let empty_snapshot: Vec<Option<DoneLedgerRecord>> = Vec::new();
                    match batch.handle.wait() {
                        Ok(receipt) => {
                            self.oracle.commit(op_id);
                            let violations = self.checker.check_after_committed_upsert(
                                &self.ledger,
                                &batch.records,
                                &receipt,
                                &empty_snapshot,
                            );
                            (DoneLedgerSimEvent::Released { op_id, receipt }, violations)
                        }
                        Err(_) => {
                            self.oracle.abort(op_id);
                            (
                                DoneLedgerSimEvent::ReleasedCommitFailed { op_id },
                                Vec::new(),
                            )
                        }
                    }
                } else {
                    // The store released this op but the harness has no
                    // record of it — same invariant as exec_release_next.
                    panic!(
                        "release_specific returned Ok(true) for op_id {op_id} \
                         which has no entry in pending_batches — harness tracking bug"
                    );
                }
            }
            Ok(false) => (DoneLedgerSimEvent::ReleaseNoop, Vec::new()),
            Err(e) => panic!("release_specific failed on InMemoryDoneLedger: {e}"),
        }
    }

    fn exec_release_all(
        &mut self,
        order: CompletionOrder,
    ) -> (DoneLedgerSimEvent, Vec<DoneLedgerInvariantViolation>) {
        let mut all_violations = Vec::new();

        // Release all ops in the store.
        let count = self
            .ledger
            .release_all(order)
            .expect("release_all should not fail on InMemoryDoneLedger");

        // Empty snapshot for delayed writes (stale pre-snapshot).
        let empty_snapshot: Vec<Option<DoneLedgerRecord>> = Vec::new();

        // Sort by op_id to match the store's release order. The store
        // applies oldest-first or newest-first depending on `order`;
        // the oracle must commit in the same sequence so tie-breaking
        // in DoneLedgerRecord::merge produces identical results.
        let mut sorted_batches: Vec<(PendingWriteId, PendingBatch)> =
            self.pending_batches.drain().collect();
        sorted_batches.sort_by_key(|(id, _)| *id);
        if order == CompletionOrder::NewestFirst {
            sorted_batches.reverse();
        }

        let mut committed = 0usize;
        let mut failed = 0usize;

        for (op_id, batch) in sorted_batches {
            match batch.handle.wait() {
                Ok(receipt) => {
                    self.oracle.commit(op_id);
                    let violations = self.checker.check_after_committed_upsert(
                        &self.ledger,
                        &batch.records,
                        &receipt,
                        &empty_snapshot,
                    );
                    committed += 1;
                    all_violations.extend(violations);
                }
                Err(_) => {
                    self.oracle.abort(op_id);
                    failed += 1;
                }
            }
        }

        (
            DoneLedgerSimEvent::ReleasedAll {
                count,
                committed,
                failed,
            },
            all_violations,
        )
    }

    // ── Random op generation ─────────────────────────────────────────

    /// Generate a random operation for the safety phase.
    fn generate_random_op(&mut self, suppress_faults: bool) -> DoneLedgerSimOp {
        let faults_enabled = !suppress_faults && !self.fault_config.is_fault_free();

        for _ in 0..MAX_OP_RETRIES {
            let roll: u32 = self.context.rng().random_range(0..100);

            let op = if !faults_enabled {
                // Warmup or SunnyDay: only data + release ops.
                match roll {
                    0..55 => self.gen_batch_upsert(),
                    55..75 => self.gen_batch_get(),
                    75..85 => self.try_gen_release_oldest(),
                    85..95 => self.try_gen_release_newest(),
                    _ => self.try_gen_release_all(),
                }
            } else {
                match roll {
                    // Data operations (55% total).
                    0..35 => self.gen_batch_upsert(),
                    35..55 => self.gen_batch_get(),
                    // Release operations (15% total).
                    55..60 => self.try_gen_release_oldest(),
                    60..65 => self.try_gen_release_newest(),
                    65..70 => self.try_gen_release_specific(),
                    // Fault injection (25% total).
                    70..80 => self.gen_inject_submit_failure(),
                    80..87 => self.gen_inject_commit_failure(),
                    87..95 => self.gen_inject_delay(),
                    // Release all (5%).
                    _ => self.try_gen_release_all(),
                }
            };

            if let Some(op) = op {
                // PPM-based fault injection between ops, but only when the
                // generated op is not already a fault injection. This
                // prevents doubling fault pressure: explicit inject ops
                // (25% of the distribution) set up counters, while PPM
                // injection adds background noise between data/release ops.
                if faults_enabled && !op.is_fault_injection() {
                    self.maybe_inject_faults();
                }
                return op;
            }
        }

        // Fallback: always-valid batch_upsert.
        self.gen_batch_upsert().unwrap()
    }

    /// Generate a liveness-phase op (fault-free, focused on completing state).
    fn generate_liveness_op(&mut self) -> DoneLedgerSimOp {
        let roll: u32 = self.context.rng().random_range(0..100);
        match roll {
            0..60 => self.gen_batch_upsert().unwrap(),
            60..80 => self.gen_batch_get().unwrap(),
            _ => self.gen_batch_upsert().unwrap(),
        }
    }

    fn gen_batch_upsert(&mut self) -> Option<DoneLedgerSimOp> {
        let batch_size = self.context.rng().random_range(1u32..=20);
        let records: Vec<DoneLedgerRecord> = (0..batch_size)
            .map(|_| self.generate_random_record())
            .collect();
        Some(DoneLedgerSimOp::BatchUpsert { records })
    }

    fn gen_batch_get(&mut self) -> Option<DoneLedgerSimOp> {
        let count = self.context.rng().random_range(1usize..=10);
        let ovid_indices: Vec<usize> = (0..count)
            .map(|_| self.context.rng().random_range(0..self.ovid_pool.len()))
            .collect();
        Some(DoneLedgerSimOp::BatchGet { ovid_indices })
    }

    fn try_gen_release_oldest(&mut self) -> Option<DoneLedgerSimOp> {
        if self.pending_batches.is_empty() {
            return None;
        }
        Some(DoneLedgerSimOp::ReleaseOldest)
    }

    fn try_gen_release_newest(&mut self) -> Option<DoneLedgerSimOp> {
        if self.pending_batches.is_empty() {
            return None;
        }
        Some(DoneLedgerSimOp::ReleaseNewest)
    }

    fn try_gen_release_specific(&mut self) -> Option<DoneLedgerSimOp> {
        if self.pending_batches.is_empty() {
            return None;
        }
        // Pick a random pending op ID. Sort for deterministic order —
        // HashMap iteration is non-deterministic.
        let mut keys: Vec<PendingWriteId> = self.pending_batches.keys().copied().collect();
        keys.sort_unstable();
        let idx = self.context.rng().random_range(0..keys.len());
        Some(DoneLedgerSimOp::ReleaseSpecific { op_id: keys[idx] })
    }

    fn try_gen_release_all(&mut self) -> Option<DoneLedgerSimOp> {
        if self.pending_batches.is_empty() {
            return None;
        }
        let order = if self.context.rng().random_bool(0.5) {
            CompletionOrder::OldestFirst
        } else {
            CompletionOrder::NewestFirst
        };
        Some(DoneLedgerSimOp::ReleaseAll { order })
    }

    fn gen_inject_submit_failure(&mut self) -> Option<DoneLedgerSimOp> {
        let count = self.context.rng().random_range(1usize..=3);
        Some(DoneLedgerSimOp::InjectSubmitFailure { count })
    }

    fn gen_inject_commit_failure(&mut self) -> Option<DoneLedgerSimOp> {
        let count = self.context.rng().random_range(1usize..=3);
        Some(DoneLedgerSimOp::InjectCommitFailure { count })
    }

    fn gen_inject_delay(&mut self) -> Option<DoneLedgerSimOp> {
        let count = self.context.rng().random_range(1usize..=5);
        Some(DoneLedgerSimOp::InjectDelay { count })
    }

    /// Apply PPM-based fault injection between ops.
    fn maybe_inject_faults(&mut self) {
        use super::should_inject;

        if should_inject(self.context.rng(), self.fault_config.submit_fail_ppm) {
            self.ledger
                .fail_next_submissions(1)
                .expect("fail_next_submissions should not fail on InMemoryDoneLedger");
        }
        if should_inject(self.context.rng(), self.fault_config.commit_fail_ppm) {
            self.ledger
                .fail_next_commits(1)
                .expect("fail_next_commits should not fail on InMemoryDoneLedger");
        }
        if should_inject(self.context.rng(), self.fault_config.delay_ppm) {
            self.ledger
                .delay_next_writes(1)
                .expect("delay_next_writes should not fail on InMemoryDoneLedger");
        }
    }

    // ── Record generation ────────────────────────────────────────────

    /// Generate a random `DoneLedgerRecord` using the shared ovid pool
    /// and PRNG.
    fn generate_random_record(&mut self) -> DoneLedgerRecord {
        let ovid_idx = self.context.rng().random_range(0..self.ovid_pool.len());
        let ovid_hash = self.ovid_pool[ovid_idx];

        let status_idx = self.context.rng().random_range(0..ALL_STATUSES.len());
        let status = ALL_STATUSES[status_idx];

        let bytes_scanned = self.context.rng().random_range(0u64..=10_000);

        let findings_count = match status {
            DoneLedgerStatus::ScannedClean => 0,
            DoneLedgerStatus::ScannedWithFindings => self.context.rng().random_range(1u32..=50),
            _ => self.context.rng().random_range(0u32..=10),
        };

        let run_id = self.next_run_id;
        self.next_run_id += 1;
        let started_at = self.context.rng().random_range(1u64..=1000);
        let finished_at = started_at + self.context.rng().random_range(1u64..=500);

        let provenance = DoneLedgerProvenance::new(
            RunId::from_raw(run_id),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(started_at),
            LogicalTime::from_raw(finished_at),
        );

        let error_code = if status.is_failure() || status.is_skipped() {
            Some(self.sim_error_code.clone())
        } else {
            None
        };

        let key = DoneLedgerKey::new(self.tenant, self.policy, ovid_hash);

        DoneLedgerRecord::try_new(
            key,
            status,
            bytes_scanned,
            findings_count,
            provenance,
            error_code,
        )
        .unwrap()
    }
}

// ── PersistenceSim implementation ────────────────────────────────────

impl PersistenceSim for DoneLedgerSim {
    type Op = DoneLedgerSimOp;
    type Event = DoneLedgerSimEvent;
    type Violation = DoneLedgerInvariantViolation;

    fn step(&mut self, op: Self::Op) -> (Self::Event, Vec<Self::Violation>) {
        let (event, violations) = self.execute_op(&op);
        self.ops_executed += 1;
        self.context.tick();
        (event, violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gossip_contracts::identity::{FenceEpoch, LogicalTime, RunId, ShardId};
    use gossip_contracts::persistence::{
        DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus,
    };

    #[test]
    fn sunny_day_run_completes_without_violations() {
        let sim = DoneLedgerSim::new(42, FaultLevel::SunnyDay);
        let report = sim.run(100, 50);

        assert!(
            report.violations.is_empty(),
            "SunnyDay violations: {:?}",
            report.violations
        );
        assert!(report.converged, "SunnyDay should converge");
        assert!(report.ops_executed > 0);
    }

    #[test]
    fn sunny_day_exercises_multiple_event_kinds() {
        let sim = DoneLedgerSim::new(123, FaultLevel::SunnyDay);
        let report = sim.run(200, 50);

        assert!(report.violations.is_empty());
        assert!(report.converged);

        // Should have at least UpsertCommitted and GetOk.
        assert!(
            report
                .event_counts
                .contains_key(&DoneLedgerSimEventKind::UpsertCommitted),
            "expected UpsertCommitted events, got: {:?}",
            report.event_counts
        );
        assert!(
            report
                .event_counts
                .contains_key(&DoneLedgerSimEventKind::GetOk),
            "expected GetOk events, got: {:?}",
            report.event_counts
        );
    }

    #[test]
    fn stormy_run_completes_without_violations() {
        let sim = DoneLedgerSim::new(42, FaultLevel::Stormy);
        let report = sim.run(200, 100);

        assert!(
            report.violations.is_empty(),
            "Stormy violations: {:?}",
            report.violations
        );
        assert!(
            report.converged,
            "Stormy should converge after liveness phase"
        );
    }

    #[test]
    fn step_executes_single_op() {
        let mut sim = DoneLedgerSim::new(99, FaultLevel::SunnyDay);

        let rec = sim.generate_random_record();
        let op = DoneLedgerSimOp::BatchUpsert { records: vec![rec] };
        let (event, violations) = sim.step(op);

        assert!(violations.is_empty(), "violations: {violations:?}");
        assert!(matches!(event, DoneLedgerSimEvent::UpsertCommitted { .. }));
        assert_eq!(sim.ops_executed, 1);
    }

    #[test]
    fn fault_injection_exercises_submit_failure() {
        let mut sim = DoneLedgerSim::new(77, FaultLevel::SunnyDay);

        // Inject submit failure.
        let (event, _) = sim.step(DoneLedgerSimOp::InjectSubmitFailure { count: 1 });
        assert!(matches!(event, DoneLedgerSimEvent::FaultConfigured));

        // Next upsert should fail.
        let rec = sim.generate_random_record();
        let (event, violations) = sim.step(DoneLedgerSimOp::BatchUpsert { records: vec![rec] });
        assert!(matches!(event, DoneLedgerSimEvent::UpsertSubmitFailed));
        assert!(
            violations.is_empty(),
            "rollback should be clean: {violations:?}"
        );
    }

    #[test]
    fn fault_injection_exercises_delayed_write() {
        let mut sim = DoneLedgerSim::new(88, FaultLevel::SunnyDay);

        // Inject delay.
        let (event, _) = sim.step(DoneLedgerSimOp::InjectDelay { count: 1 });
        assert!(matches!(event, DoneLedgerSimEvent::FaultConfigured));

        // Next upsert should be pending.
        let rec = sim.generate_random_record();
        let (event, _) = sim.step(DoneLedgerSimOp::BatchUpsert { records: vec![rec] });
        assert!(
            matches!(event, DoneLedgerSimEvent::UpsertPending { .. }),
            "expected pending, got {event:?}"
        );
        assert_eq!(sim.pending_batches.len(), 1);

        // Release it.
        let (event, violations) = sim.step(DoneLedgerSimOp::ReleaseOldest);
        assert!(
            matches!(event, DoneLedgerSimEvent::Released { .. }),
            "expected released, got {event:?}"
        );
        assert!(violations.is_empty(), "release violations: {violations:?}");
        assert!(sim.pending_batches.is_empty());
    }

    #[test]
    fn commit_failure_at_auto_complete_emits_distinct_event() {
        // When auto-complete commit fails, the event should distinguish
        // it from a submit failure so the event histogram is accurate
        // and the op_id context is preserved.
        let mut sim = DoneLedgerSim::new(99, FaultLevel::SunnyDay);

        // Inject commit failure (not submit failure).
        sim.step(DoneLedgerSimOp::InjectCommitFailure { count: 1 });

        // Batch upsert auto-completes but commit fails.
        let rec = sim.generate_random_record();
        let (event, _) = sim.step(DoneLedgerSimOp::BatchUpsert { records: vec![rec] });

        // Must be UpsertCommitFailed — not UpsertSubmitFailed (wrong
        // failure mode) and not UpsertCommitted (unexpected success).
        assert!(
            matches!(event, DoneLedgerSimEvent::UpsertCommitFailed { .. }),
            "expected UpsertCommitFailed, got {event:?}"
        );
    }

    #[test]
    fn release_all_newest_first_oracle_matches_ledger_order() {
        // When exec_release_all is called with NewestFirst, the oracle
        // must commit batches in the same order the ledger applied them.
        // This test guards that release-order logic so oracle convergence
        // stays aligned with ledger merge tie-breaking.
        let mut sim = DoneLedgerSim::new(42, FaultLevel::SunnyDay);

        // Delay two writes.
        sim.step(DoneLedgerSimOp::InjectDelay { count: 2 });

        // Submit two batches for the SAME key with identical rank/timestamps
        // but different RunId (provenance). Merge tie-breaks on
        // finished_at > started_at, so tie → existing record wins.
        let key = DoneLedgerKey::new(sim.tenant, sim.policy, sim.ovid_pool[0]);
        let prov1 = DoneLedgerProvenance::new(
            RunId::from_raw(100),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(500),
            LogicalTime::from_raw(600),
        );
        let prov2 = DoneLedgerProvenance::new(
            RunId::from_raw(200),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(500),
            LogicalTime::from_raw(600),
        );

        let rec1 =
            DoneLedgerRecord::try_new(key, DoneLedgerStatus::ScannedClean, 100, 0, prov1, None)
                .unwrap();
        let rec2 =
            DoneLedgerRecord::try_new(key, DoneLedgerStatus::ScannedClean, 100, 0, prov2, None)
                .unwrap();

        // Submit both — they become pending.
        let (e1, _) = sim.step(DoneLedgerSimOp::BatchUpsert {
            records: vec![rec1],
        });
        assert!(
            matches!(e1, DoneLedgerSimEvent::UpsertPending { .. }),
            "expected pending, got {e1:?}"
        );
        let (e2, _) = sim.step(DoneLedgerSimOp::BatchUpsert {
            records: vec![rec2],
        });
        assert!(
            matches!(e2, DoneLedgerSimEvent::UpsertPending { .. }),
            "expected pending, got {e2:?}"
        );
        assert_eq!(sim.pending_batches.len(), 2);

        // Release all with NewestFirst — ledger applies op2 before op1.
        let (_, violations) = sim.step(DoneLedgerSimOp::ReleaseAll {
            order: CompletionOrder::NewestFirst,
        });
        assert!(
            violations.is_empty(),
            "release_all should not produce violations: {violations:?}"
        );

        // Verify convergence: oracle and ledger should agree.
        let convergence_violations = sim.oracle.verify_convergence(&sim.ledger);
        assert!(
            convergence_violations.is_empty(),
            "oracle/ledger divergence after NewestFirst release: {convergence_violations:?}"
        );
    }

    #[test]
    fn deterministic_replay_produces_same_report() {
        let report1 = DoneLedgerSim::new(42, FaultLevel::Stormy).run(100, 50);
        let report2 = DoneLedgerSim::new(42, FaultLevel::Stormy).run(100, 50);

        assert_eq!(report1.ops_executed, report2.ops_executed);
        assert_eq!(report1.event_counts, report2.event_counts);
        assert_eq!(
            format!("{:?}", report1.violations),
            format!("{:?}", report2.violations),
            "violation contents differ between replays with same seed"
        );
        assert_eq!(report1.converged, report2.converged);
    }
}
