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
use rand::seq::SliceRandom;

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
const ALL_STATUSES: [DoneLedgerStatus; 5] = DoneLedgerStatus::ALL;

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

    /// Execute the swizzle-clog pattern with delayed writes released in a
    /// PRNG-shuffled order.
    ///
    /// Every batch overlaps a small shared key pool but uses a different
    /// status/metric mix, forcing the ledger and oracle to prove that the
    /// lattice merge converges regardless of completion order.
    pub fn run_swizzle_clog(mut self, batch_count: usize) -> DoneLedgerSimReport {
        let seed = self.context.seed();
        let mut all_violations = Vec::new();
        let mut event_counts = BTreeMap::new();

        self.ledger
            .set_auto_complete(false)
            .expect("set_auto_complete should not fail on InMemoryDoneLedger");

        for batch_idx in 0..batch_count {
            // Inject PPM-based faults between batches when configured.
            // This exercises the interaction between submit failures,
            // delays, and out-of-order release — the scenario most
            // likely to reveal merge races.
            if !self.fault_config.is_fault_free() {
                self.maybe_inject_faults();
            }

            let op = DoneLedgerSimOp::BatchUpsert {
                records: self.build_swizzle_clog_batch(batch_idx),
            };
            let (event, violations) = self.step(op);
            Self::record_event(&event, &mut event_counts);
            all_violations.extend(violations);
        }

        let mut pending_ids = self
            .ledger
            .pending_ids()
            .expect("pending_ids should not fail on InMemoryDoneLedger");

        // Cross-check: the ledger's pending set must match the harness's
        // tracking exactly. A mismatch means either the ledger lost track
        // of a delayed write or the harness failed to record one.
        {
            let mut harness_ids: Vec<PendingWriteId> =
                self.pending_batches.keys().copied().collect();
            harness_ids.sort_unstable();
            let mut ledger_ids = pending_ids.clone();
            ledger_ids.sort_unstable();
            assert_eq!(
                harness_ids, ledger_ids,
                "seed={seed}: ledger.pending_ids() and pending_batches diverge — \
                 harness={harness_ids:?}, ledger={ledger_ids:?}"
            );
        }

        pending_ids.shuffle(self.context.rng());

        let mut fail_release = vec![false; pending_ids.len()];
        for should_fail in &mut fail_release {
            *should_fail = self.context.rng().random_bool(0.25);
        }
        // Guarantee at least one failure so the commit-failure path is
        // always exercised.
        if !pending_ids.is_empty() && !fail_release.iter().any(|flag| *flag) {
            let fail_idx = self.context.rng().random_range(0..fail_release.len());
            fail_release[fail_idx] = true;
        }
        // Guarantee at least one success so the convergence check is
        // non-vacuous (committed_count > 0). With 25% failure rate and
        // 10 batches P(all-fail) ≈ 1e-6 — rare but possible over many
        // CI runs.
        if pending_ids.len() >= 2 && fail_release.iter().all(|flag| *flag) {
            let pass_idx = self.context.rng().random_range(0..fail_release.len());
            fail_release[pass_idx] = false;
        }

        for (op_id, should_fail) in pending_ids.into_iter().zip(fail_release.into_iter()) {
            if should_fail {
                let (event, violations) =
                    self.step(DoneLedgerSimOp::InjectCommitFailure { count: 1 });
                Self::record_event(&event, &mut event_counts);
                all_violations.extend(violations);
            }

            let (event, violations) = self.step(DoneLedgerSimOp::ReleaseSpecific { op_id });
            Self::record_event(&event, &mut event_counts);
            all_violations.extend(violations);
        }

        let convergence_violations = self.oracle.verify_convergence(&self.ledger);
        let converged = convergence_violations.is_empty();
        all_violations.extend(convergence_violations);

        // Under fault-free conditions the at-least-one-success guarantee
        // (above) ensures non-vacuous convergence. Under Stormy/Radioactive,
        // residual PPM commit failures can legitimately cause all commits
        // to fail, so the assertion is only meaningful when faults are off.
        debug_assert!(
            !self.fault_config.is_fault_free() || self.oracle.committed_count() > 0,
            "seed={seed}: convergence is vacuous — no records were committed"
        );

        DoneLedgerSimReport {
            seed,
            ops_executed: self.ops_executed,
            violations: all_violations,
            event_counts,
            converged,
        }
    }

    /// Number of delayed writes still retained by the harness.
    #[cfg(test)]
    pub(super) fn pending_batch_count(&self) -> usize {
        self.pending_batches.len()
    }

    /// Verify I6 convergence once the caller has drained pending writes.
    #[cfg(test)]
    pub(super) fn check_convergence(&self) -> Vec<DoneLedgerInvariantViolation> {
        assert!(
            self.pending_batches.is_empty(),
            "check_convergence requires all pending batches to be drained first"
        );
        self.oracle.verify_convergence(&self.ledger)
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

    /// Consume a released pending batch: wait for the commit handle,
    /// update the oracle (commit or abort), and run invariant checks.
    ///
    /// Pre-snapshots are stale for delayed writes (taken at submission
    /// time, not release time), so I5 and I8 are skipped. The oracle
    /// convergence check (I6) is the authoritative verification.
    fn finish_released_batch(
        &mut self,
        op_id: PendingWriteId,
        batch: PendingBatch,
    ) -> (DoneLedgerSimEvent, Vec<DoneLedgerInvariantViolation>) {
        let empty_snapshot: Vec<Option<DoneLedgerRecord>> = Vec::new();
        match batch.handle.wait() {
            Ok(receipt) => {
                let was_pending = self.oracle.commit(op_id);
                assert!(
                    was_pending,
                    "finish_released_batch: op {op_id} was not pending in oracle"
                );
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
    }

    /// Release all pending writes, consuming the retained commit handles
    /// to verify each outcome. Returns any violations.
    ///
    /// Pre-snapshots taken at submission time are stale for delayed writes
    /// (other commits may have modified the same keys). The
    /// [`finish_released_batch`](Self::finish_released_batch) helper
    /// handles oracle commit/abort and invariant checks per batch.
    fn drain_all_pending(
        &mut self,
        event_counts: &mut BTreeMap<DoneLedgerSimEventKind, usize>,
    ) -> Vec<DoneLedgerInvariantViolation> {
        let mut all_violations = Vec::new();

        // Release all ops in the store in oldest-first order.
        self.ledger
            .release_all(CompletionOrder::OldestFirst)
            .expect("release_all should not fail on InMemoryDoneLedger");

        // Consume retained handles in op_id order to match the store's
        // oldest-first release order. This ensures the oracle commits
        // in the same sequence, producing identical merge results.
        let mut sorted_batches: Vec<(PendingWriteId, PendingBatch)> =
            self.pending_batches.drain().collect();
        sorted_batches.sort_by_key(|(id, _)| *id);

        for (op_id, batch) in sorted_batches {
            self.ops_executed += 1;
            self.context.tick();

            let (event, violations) = self.finish_released_batch(op_id, batch);
            *event_counts.entry(event.kind()).or_insert(0) += 1;
            all_violations.extend(violations);
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

                // Check if this is a delayed write by querying pending IDs.
                let pending_ids = self
                    .ledger
                    .pending_ids()
                    .expect("pending_ids should not fail on InMemoryDoneLedger");

                if pending_ids.contains(&op_id) {
                    // Write is delayed — retain handle for later verification.
                    // PendingWriteId is monotonically increasing, so collisions
                    // are structurally impossible; assert to catch store bugs.
                    assert!(
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

                    // Clone once; oracle and pending_batches share ownership.
                    let records_owned = records.to_vec();
                    self.oracle.submit(op_id, records_owned.clone());
                    self.pending_batches.insert(
                        op_id,
                        PendingBatch {
                            records: records_owned,
                            handle,
                        },
                    );
                    (DoneLedgerSimEvent::UpsertPending { op_id }, violations)
                } else {
                    // Auto-completed — oracle only needs one copy.
                    self.oracle.submit(op_id, records.to_vec());
                    match handle.wait() {
                        Ok(receipt) => {
                            let was_pending = self.oracle.commit(op_id);
                            assert!(
                                was_pending,
                                "auto-complete: op {op_id} not pending in oracle"
                            );
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
                let batch = self.pending_batches.remove(&op_id).unwrap_or_else(|| {
                    panic!(
                        "release_next returned op_id {op_id} which has no \
                         entry in pending_batches — harness tracking bug"
                    )
                });
                self.finish_released_batch(op_id, batch)
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
                let batch = self.pending_batches.remove(&op_id).unwrap_or_else(|| {
                    panic!(
                        "release_specific returned Ok(true) for op_id {op_id} \
                         which has no entry in pending_batches — harness tracking bug"
                    )
                });
                self.finish_released_batch(op_id, batch)
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
        debug_assert_eq!(
            count,
            sorted_batches.len(),
            "store/harness pending count mismatch"
        );

        let mut committed = 0usize;
        let mut failed = 0usize;

        for (op_id, batch) in sorted_batches {
            let (event, violations) = self.finish_released_batch(op_id, batch);
            match event.kind() {
                DoneLedgerSimEventKind::Released => committed += 1,
                DoneLedgerSimEventKind::ReleasedCommitFailed => failed += 1,
                _ => {}
            }
            all_violations.extend(violations);
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
            0..80 => self.gen_batch_upsert().unwrap(),
            _ => self.gen_batch_get().unwrap(),
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
        // Guarded: avoids burning retry budget on a guaranteed noop.
        // ReleaseNoop coverage comes from try_gen_release_newest (below)
        // which is intentionally unguarded.
        if self.pending_batches.is_empty() {
            return None;
        }
        Some(DoneLedgerSimOp::ReleaseOldest)
    }

    fn try_gen_release_newest(&mut self) -> Option<DoneLedgerSimOp> {
        // Intentionally unguarded: when the queue is empty this
        // produces a ReleaseNoop event, ensuring coverage of that
        // event kind in the histogram (DoneLedgerSimEventKind::ALL).
        Some(DoneLedgerSimOp::ReleaseNewest)
    }

    fn try_gen_release_specific(&mut self) -> Option<DoneLedgerSimOp> {
        // Intentionally unguarded: generates a synthetic ID when empty
        // so the store's not-found path is exercised uniformly.
        let op_id = if self.pending_batches.is_empty() {
            // No pending batches — generate a synthetic ID so the store
            // returns noop, exercising the not-found path uniformly.
            let raw = self.context.rng().random_range(1u64..=1024);
            PendingWriteId::from_raw(raw)
        } else {
            // Pick a random pending op ID. Sort for deterministic order —
            // HashMap iteration is non-deterministic.
            let mut keys: Vec<PendingWriteId> = self.pending_batches.keys().copied().collect();
            keys.sort_unstable();
            let idx = self.context.rng().random_range(0..keys.len());
            keys[idx]
        };
        Some(DoneLedgerSimOp::ReleaseSpecific { op_id })
    }

    fn try_gen_release_all(&mut self) -> Option<DoneLedgerSimOp> {
        // Intentionally unguarded: releasing an empty queue produces
        // a trivial ReleasedAll { count: 0 } — harmless and exercises
        // the zero-pending path.
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

    fn build_swizzle_clog_batch(&mut self, batch_index: usize) -> Vec<DoneLedgerRecord> {
        const BATCH_WIDTH: usize = 3;
        const OVERLAP_POOL: usize = 5;

        let status_cycle = [
            DoneLedgerStatus::FailedRetryable,
            DoneLedgerStatus::ScannedWithFindings,
            DoneLedgerStatus::ScannedClean,
            DoneLedgerStatus::FailedPermanent,
            DoneLedgerStatus::Skipped,
        ];
        let status = status_cycle[batch_index % status_cycle.len()];
        let base = batch_index % OVERLAP_POOL;
        let started_at = 1_000 + (batch_index as u64 * 10);

        (0..BATCH_WIDTH)
            .map(|offset| {
                let ovid_index = (base + offset) % OVERLAP_POOL;
                let bytes_scanned = 100 + (batch_index as u64 * 25) + offset as u64;
                let findings_count = match status {
                    DoneLedgerStatus::ScannedClean => 0,
                    DoneLedgerStatus::ScannedWithFindings => (offset as u32) + 1,
                    _ => offset as u32,
                };
                self.build_record(
                    ovid_index,
                    status,
                    bytes_scanned,
                    findings_count,
                    started_at + offset as u64,
                    started_at + offset as u64 + 5,
                )
            })
            .collect()
    }

    fn build_record(
        &mut self,
        ovid_index: usize,
        status: DoneLedgerStatus,
        bytes_scanned: u64,
        findings_count: u32,
        started_at: u64,
        finished_at: u64,
    ) -> DoneLedgerRecord {
        let run_id = self.next_run_id;
        self.next_run_id += 1;

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

        let key = DoneLedgerKey::new(
            self.tenant,
            self.policy,
            self.ovid_pool[ovid_index % self.ovid_pool.len()],
        );

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

    // ── Record generation ────────────────────────────────────────────

    /// Generate a random `DoneLedgerRecord` using the shared ovid pool
    /// and PRNG.
    fn generate_random_record(&mut self) -> DoneLedgerRecord {
        let ovid_idx = self.context.rng().random_range(0..self.ovid_pool.len());
        let status_idx = self.context.rng().random_range(0..ALL_STATUSES.len());
        let status = ALL_STATUSES[status_idx];

        let bytes_scanned = self.context.rng().random_range(0u64..=10_000);

        let findings_count = match status {
            DoneLedgerStatus::ScannedClean => 0,
            DoneLedgerStatus::ScannedWithFindings => self.context.rng().random_range(1u32..=50),
            _ => self.context.rng().random_range(0u32..=10),
        };

        let started_at = self.context.rng().random_range(1u64..=1000);
        let finished_at = started_at + self.context.rng().random_range(1u64..=500);
        self.build_record(
            ovid_idx,
            status,
            bytes_scanned,
            findings_count,
            started_at,
            finished_at,
        )
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
    fn read_consistency_detects_oracle_ledger_divergence() {
        // I7: batch_get should detect when the oracle has committed a
        // record that the ledger does not have (simulating a missed write
        // or a ledger data loss).
        let mut sim = DoneLedgerSim::new(42, FaultLevel::SunnyDay);

        // Build a record at ovid_pool[0] and commit it only in the oracle
        // (bypassing the ledger entirely).
        let rec = sim.build_record(0, DoneLedgerStatus::ScannedClean, 100, 0, 500, 600);
        let fake_op = crate::PendingWriteId::from_raw(9999);
        sim.oracle.submit(fake_op, vec![rec]);
        sim.oracle.commit(fake_op);

        // BatchGet for ovid_pool[0] — oracle has the key, ledger does not.
        let (event, violations) = sim.step(DoneLedgerSimOp::BatchGet {
            ovid_indices: vec![0],
        });
        assert!(matches!(event, DoneLedgerSimEvent::GetOk { .. }));
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::ReadConsistency { .. })),
            "expected ReadConsistency violation, got: {violations:?}"
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
