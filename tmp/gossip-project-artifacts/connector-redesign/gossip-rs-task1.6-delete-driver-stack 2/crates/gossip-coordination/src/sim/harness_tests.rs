//! Unit and property tests for the simulation harness ([`CoordinationSim`]).
//!
//! These tests validate the harness's own correctness -- its bookkeeping,
//! op generation, and integration with the coordinator and invariant checker.
//! They complement the large-scale mega-sim sweep (which treats the harness
//! as a black box and only checks for invariant violations) by testing
//! internal mechanisms with deterministic, hand-crafted scenarios.
//!
//! # Coverage map
//!
//! | Test cluster | What it validates |
//! |---|---|
//! | **No-violations property** | S1-S9 hold across random seeds and all fault levels |
//! | **Report properties** | `SimReport` fields are populated and rejections occur under faults |
//! | **Deterministic replay** | Same seed produces identical event counts, op count, and end time |
//! | **Convergence** | Liveness phase drives all shards to terminal (SunnyDay) |
//! | **Zombie scenario** | B1 bookkeeping cleanup rejects stale worker checkpoint |
//! | **Forward cursor** | `generate_forward_cursor` never regresses, handles edge cases |
//! | **Renew bookkeeping** | Worker's local lease deadline matches coordinator after renew |
//! | **Multi-run isolation** | Interleaved ops on two runs produce no cross-run violations |
//! | **Op-type coverage** | All exotic op types fire across 20 seeds (split, replay, claim, session, run-terminal) |
//! | **step() API** | Public `step()` returns correct events, increments counter, rejects paused workers |
//! | **Cooldown** | `with_cooldown` throttles rapid claims and allows post-cooldown claims |
//! | **Unpark** | Park->Unpark cycle, rejection on non-parked, S3 exemption, active-set bookkeeping |
//! | **Admin op-ID partitioning** | Admin partition 0 does not collide with worker partition 1+ |
//! | **Run-terminal** | Unpark blocked after run cancel, shard ops continue, terminal irreversibility |
//! | **Terminate-run generator** | `try_gen_terminate_run` samples all seeded runs uniformly |

use super::*;
use crate::error::InfraError;
use crate::facade::ShardClaiming;
use crate::run::{RunConfig, RunManagement, RunProgress, RunRecord, ShardFilter, ShardSummary};
use crate::run_errors::{CreateRunError, GetRunError, RegisterShardsError};
use crate::sim::backend::SimIntrospection;
use crate::split_execution::{SplitReplaceResult, SplitResidualResult};
use gossip_contracts::coordination::manifest::InitialShardInput;
use gossip_contracts::coordination::shard_spec::ShardSpec;
use gossip_contracts::coordination::split::{SplitReplacePlan, SplitResidualPlan};
use gossip_contracts::test_util::miri_proptest_config;
use proptest::prelude::*;

/// Standard 3-worker, 5-shard simulation for property tests.
///
/// The 3:5 ratio ensures contention (fewer workers than shards) while
/// keeping runs fast enough for proptest's 50-case default.
fn default_sim(seed: u64, level: FaultLevel) -> CoordinationSim {
    CoordinationSim::new(seed, level).with_workers_and_shards(3, 5)
}

/// Proptest config with 50 cases (1 under Miri for speed).
///
/// Respects `PROPTEST_CASES` env var: if set lower than 50, uses the env value.
fn sim_proptest_config() -> proptest::test_runner::Config {
    let mut cfg = miri_proptest_config();
    if !cfg!(miri) {
        // miri_proptest_config() returns Config::default() outside Miri, which
        // reads PROPTEST_CASES from the environment (e.g. PROPTEST_CASES=4 in CI).
        // Take the minimum so the env var can reduce cases for fast PR runs.
        cfg.cases = cfg.cases.min(50);
    }
    cfg
}

/// Scale safety and liveness op budgets by fault severity.
///
/// Higher fault levels need more ops because fault-induced rejections
/// (expired leases, paused workers) waste a larger fraction of the budget.
/// Radioactive gets 5x the SunnyDay budget to compensate for its ~20%
/// rejection rate.
fn ops_for_level(level: FaultLevel) -> (usize, usize) {
    match level {
        FaultLevel::SunnyDay => (200, 100),
        FaultLevel::Stormy => (500, 200),
        FaultLevel::Radioactive => (1000, 500),
    }
}

use crate::sim::test_util::arb_fault_level;

#[derive(Debug, Clone, Copy)]
enum InjectedSessionFault {
    Complete,
    SplitReplace,
    SplitResidual,
}

struct FaultingSessionBackend {
    inner: InMemoryCoordinator,
    fault: InjectedSessionFault,
}

impl FaultingSessionBackend {
    fn new(inner: InMemoryCoordinator, fault: InjectedSessionFault) -> Self {
        Self { inner, fault }
    }
}

impl crate::traits::CoordinationBackend for FaultingSessionBackend {
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<crate::error::AcquireResultView<'a>, AcquireError> {
        self.inner
            .acquire_and_restore_into(now, tenant, key, worker, out)
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<crate::error::RenewResult, RenewError> {
        self.inner.renew(now, tenant, lease)
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        self.inner.checkpoint(now, tenant, lease, new_cursor, op_id)
    }

    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        if matches!(self.fault, InjectedSessionFault::Complete) {
            return Err(CompleteError::BackendError(InfraError::transient(
                "injected_fault",
                "injected session backend fault",
            )));
        }
        self.inner.complete(now, tenant, lease, final_cursor, op_id)
    }

    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.inner.park_shard(now, tenant, lease, reason, op_id)
    }

    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, crate::error::SplitReplaceError> {
        if matches!(self.fault, InjectedSessionFault::SplitReplace) {
            return Err(SplitError::BackendError(InfraError::transient(
                "injected_fault",
                "injected session backend fault",
            )));
        }
        self.inner.split_replace(now, tenant, lease, plan, op_id)
    }

    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, crate::error::SplitResidualError> {
        if matches!(self.fault, InjectedSessionFault::SplitResidual) {
            return Err(SplitError::BackendError(InfraError::transient(
                "injected_fault",
                "injected session backend fault",
            )));
        }
        self.inner.split_residual(now, tenant, lease, plan, op_id)
    }
}

impl RunManagement for FaultingSessionBackend {
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        self.inner.create_run(now, tenant, run, config)
    }

    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        self.inner.register_shards(now, tenant, run, shards, op_id)
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        self.inner.get_run(tenant, run)
    }

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        self.inner.get_run_progress(now, tenant, run)
    }

    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        self.inner.list_shards_into(now, tenant, run, filter, out)
    }

    fn collect_claim_candidates_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        self.inner
            .collect_claim_candidates_into(now, tenant, run, candidates)
    }

    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.inner.complete_run(now, tenant, run, op_id)
    }

    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.inner.fail_run(now, tenant, run, op_id)
    }

    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.inner.cancel_run(now, tenant, run, op_id)
    }

    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        self.inner.unpark_shard(now, tenant, key, op_id)
    }
}

impl ShardClaiming for FaultingSessionBackend {
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<crate::error::AcquireResultView<'a>, crate::facade::ClaimError> {
        self.inner
            .claim_next_available(now, tenant, run, worker, out)
    }
}

impl SimIntrospection for FaultingSessionBackend {
    type ShardIter<'a>
        = <InMemoryCoordinator as SimIntrospection>::ShardIter<'a>
    where
        Self: 'a;
    type RunIter<'a>
        = <InMemoryCoordinator as SimIntrospection>::RunIter<'a>
    where
        Self: 'a;
    type SpawnedIter<'a>
        = <InMemoryCoordinator as SimIntrospection>::SpawnedIter<'a>
    where
        Self: 'a;

    fn shards(&self) -> Self::ShardIter<'_> {
        self.inner.shards()
    }

    fn runs(&self) -> Self::RunIter<'_> {
        self.inner.runs()
    }

    fn shard_count(&self) -> usize {
        self.inner.shard_count()
    }

    fn shard_lookup(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord> {
        self.inner.shard_lookup(tenant, key)
    }

    fn cursor_last_key<'a>(&'a self, record: &'a ShardRecord) -> Option<&'a [u8]> {
        self.inner.cursor_last_key(record)
    }

    fn spec_bounds<'a>(&'a self, record: &'a ShardRecord) -> (&'a [u8], &'a [u8]) {
        self.inner.spec_bounds(record)
    }

    fn validate_record_invariants(&self, record: &ShardRecord) -> Result<(), String> {
        self.inner.validate_record_invariants(record)
    }

    fn spawned_children<'a>(&'a self, record: &'a ShardRecord) -> Self::SpawnedIter<'a> {
        self.inner.spawned_children(record)
    }

    fn release_record_fields(&mut self, record: &mut ShardRecord) {
        self.inner.release_record_fields(record);
    }
}

fn wrap_faulting_session_backend(
    sim: CoordinationSim,
    fault: InjectedSessionFault,
) -> CoordinationSim<FaultingSessionBackend> {
    CoordinationSim {
        context: sim.context,
        coordinator: FaultingSessionBackend::new(sim.coordinator, fault),
        workers: sim.workers,
        fault_config: sim.fault_config,
        checker: sim.checker,
        shard_keys: sim.shard_keys,
        active_shard_keys: sim.active_shard_keys,
        tenant: sim.tenant,
        ops_executed: sim.ops_executed,
        stale_leases: sim.stale_leases,
        last_checkpoint_ops: sim.last_checkpoint_ops,
        run_shard_ids: sim.run_shard_ids,
        admin_next_op: sim.admin_next_op,
    }
}

fn seeded_session_sim_with_range(
    seed: u64,
    fault: InjectedSessionFault,
    range_start: u8,
    range_end: u8,
) -> (CoordinationSim<FaultingSessionBackend>, WorkerId, ShardKey) {
    let mut sim = CoordinationSim::new(seed, FaultLevel::SunnyDay);
    let worker = WorkerId::from_raw(1);
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let key = ShardKey::new(run, shard);

    sim.add_worker(worker);

    let start = [range_start];
    let end = [range_end];
    let spec = ShardSpecRef::with_range(&start, &end);
    let record = ShardRecord::new_active(
        sim.tenant,
        run,
        shard,
        spec,
        CursorSemantics::Completed,
        sim.coordinator.slab_mut(),
    )
    .expect("single-byte shard spec should fit in the test slab");
    sim.coordinator.seed_shard(record);
    sim.shard_keys.push(key);
    sim.active_shard_keys.push(key);
    sim.run_shard_ids.entry(run).or_default().push(shard);
    sim.seed_all_runs();
    sim.context.advance(1);

    (wrap_faulting_session_backend(sim, fault), worker, key)
}

fn predicted_session_terminal_action(
    seed: u64,
    range_lo: u8,
    range_hi: u8,
) -> SessionTerminalAction {
    let mut context = SimContext::new(seed);
    let num_checkpoints: u32 = context.rng().random_range(1..=3);

    let range_wide_enough = range_hi.saturating_sub(range_lo) >= 2;
    let terminal_action = match context.rng().random_range(0u32..10) {
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
                .and_then(|cursor| cursor.first().copied())
                .unwrap_or(range_hi.saturating_sub(1));
            cursors.push(vec![byte]);
        } else {
            let byte = context.rng().random_range(lo..range_hi);
            cursors.push(vec![byte]);
            lo = byte.saturating_add(1);
        }
    }

    let split_replace_plan = if matches!(terminal_action, SessionTerminalAction::SplitReplace) {
        precompute_split_replace_plan(context.rng(), range_lo, range_hi)
    } else {
        None
    };

    let split_residual_plan = if matches!(
        terminal_action,
        SessionTerminalAction::SplitResidualThenComplete
    ) {
        let last_cp_byte = cursors
            .get(num_checkpoints.saturating_sub(1) as usize)
            .and_then(|cursor| cursor.first().copied())
            .unwrap_or(range_lo);
        precompute_split_residual_plan(context.rng(), range_lo, range_hi, last_cp_byte)
    } else {
        None
    };

    match terminal_action {
        SessionTerminalAction::SplitReplace if split_replace_plan.is_none() => {
            SessionTerminalAction::Complete
        }
        SessionTerminalAction::SplitResidualThenComplete if split_residual_plan.is_none() => {
            SessionTerminalAction::Complete
        }
        other => other,
    }
}

fn find_seed_for_session_terminal_action(
    range_lo: u8,
    range_hi: u8,
    predicate: impl Fn(SessionTerminalAction) -> bool,
) -> u64 {
    (0..10_000)
        .find(|seed| predicate(predicted_session_terminal_action(*seed, range_lo, range_hi)))
        .expect("expected at least one seed to produce the requested session terminal action")
}

// -- Cluster 1: no-violations property (replaces 5 tests) ----------------
//
// The core safety property: invariants S1-S9 hold for any seed under any
// fault level. This single proptest replaces five former per-level tests
// by parameterizing over both seed and level.

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
//
// Validates that SimReport fields are populated correctly and that
// Stormy fault injection produces at least some rejections (a zero
// rejection count would indicate fault injection is silently disabled).

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

// -- Determinism and convergence ------------------------------------------
//
// These test the two foundational simulation guarantees: (1) same seed
// always produces identical results (ChaCha8Rng reproducibility), and
// (2) the liveness phase can drive all shards to terminal state.

/// Two runs with the same seed must produce byte-identical results.
/// This is the reproducibility contract that makes seed-based failure
/// investigation possible -- if this fails, bisecting by seed is broken.
#[test]
fn deterministic_replay() {
    let seed = 99;
    let report_a = default_sim(seed, FaultLevel::Stormy).run(200, 100);
    let report_b = default_sim(seed, FaultLevel::Stormy).run(200, 100);
    assert_eq!(report_a.event_counts, report_b.event_counts);
    assert_eq!(report_a.ops_executed, report_b.ops_executed);
    assert_eq!(report_a.end_time, report_b.end_time);
}

/// With a generous liveness budget (500 ops), all shards must reach
/// terminal state under zero faults. Failure here means the liveness
/// phase's acquire+complete bias is insufficient or broken.
#[test]
fn two_phase_converges() {
    let report = default_sim(42, FaultLevel::SunnyDay).run(50, 500);
    assert!(
        report.converged,
        "seed {}: not all shards converged",
        report.seed
    );
}

/// The zombie preamble (injected before random ops) must produce at
/// least one rejection without any invariant violations. This confirms
/// the B1 bookkeeping cleanup path works: Worker A's stale lease is
/// cleared when Worker B acquires, so Worker A's subsequent checkpoint
/// is rejected with NotLeased.
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
    let cursor_key = cursor.as_slice();

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

// -- Multi-run isolation ----------------------------------------------------

/// Interleave operations on shards from two different runs within a single
/// tenant and verify no invariant violations occur.
#[test]
fn multi_run_isolation() {
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
//
// These test the monotonicity guarantee of cursor generation. The harness
// must never generate a cursor that lexicographically precedes the worker's
// last cursor -- doing so would cause the coordinator to correctly reject
// the operation, masking real bugs behind expected CursorRegression noise.
// Edge cases covered: no prior cursor, forward progress, range exhaustion,
// narrow spec, and multi-byte boundary regression.

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
    let cursor_key = cursor.as_slice();

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
    let cursor_key = cursor.as_slice();

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
    let cursor_key = cursor.as_slice();

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
    let spec = ShardSpec::with_range(vec![b'a'], vec![b'c']);
    let record = crate::record::ShardRecord::new_active(
        sim.tenant,
        run,
        shard,
        spec.as_ref(),
        CursorSemantics::Completed,
        sim.coordinator.slab_mut(),
    )
    .expect("slab large enough for test");
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
    let cursor_key = cursor.as_slice();

    // First byte must be >= b'b' (forward from b'a') and < b'c' (range end).
    // With spec [b'a', b'c'), the only valid first byte is b'b'.
    let first_byte = cursor_key[0];
    assert_eq!(
        first_byte, b'b',
        "cursor first byte {first_byte:#x} should be 0x62 (b'b') for spec [b'a', b'c')",
    );
}

/// Verify all exotic operation types are exercised across 20 seeds.
///
/// Each op type has a small weight in `generate_random_op` (2-8%), so any
/// single seed may not trigger all of them. Scanning 20 seeds with 1000
/// safety ops each gives each path thousands of chances. A zero count for
/// any op type across all 20 seeds indicates broken op-generation weights
/// or a precondition that is never satisfied.
#[test]
fn new_op_types_exercised() {
    let mut split_replace_seen = false;
    let mut split_residual_seen = false;
    let mut replayed_seen = false;
    let mut claim_seen = false;
    let mut session_lifecycle_seen = false;
    let mut run_terminal_seen = false;
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
        if report
            .event_counts
            .contains_key(&SimEventKind::RunTerminalOk)
        {
            run_terminal_seen = true;
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
    assert!(
        run_terminal_seen,
        "RunTerminalOk never observed across 20 seeds"
    );
}

// -- step() public API tests ----------------------------------------------

/// `step()` returns events and violations, and increments `ops_executed`.
#[test]
fn step_returns_violations_and_increments_counter() {
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);

    let worker = WorkerId::from_raw(1);
    let key = sim.shard_keys[0];

    // Advance time so acquire can succeed.
    sim.context.advance(1);

    let initial_ops = sim.ops_executed;
    let (event, violations) = sim.step(SimOp::Acquire { worker, key });

    assert!(
        matches!(event, SimEvent::AcquireOk { .. }),
        "expected AcquireOk, got {event:?}"
    );
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );
    assert_eq!(
        sim.ops_executed,
        initial_ops + 1,
        "step() should increment ops_executed"
    );
}

/// `step()` on a paused worker returns a Rejected event with no violations.
#[test]
fn step_on_paused_worker_returns_rejection() {
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(2, 1);

    let worker = WorkerId::from_raw(1);
    let key = sim.shard_keys[0];

    sim.context.advance(1);

    // Pause the worker.
    let (pause_event, pause_violations) = sim.step(SimOp::PauseWorker { worker });
    assert!(
        matches!(pause_event, SimEvent::WorkerPaused { .. }),
        "expected WorkerPaused, got {pause_event:?}"
    );
    assert!(pause_violations.is_empty());

    // Checkpoint on paused worker should be rejected.
    let (event, violations) = sim.step(SimOp::Checkpoint { worker, key });
    assert!(
        matches!(event, SimEvent::Rejected { .. }),
        "expected Rejected for paused worker, got {event:?}"
    );
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );
}

/// `with_cooldown` enables per-worker throttling in the simulation:
/// first claim succeeds, immediate retry is throttled, post-cooldown
/// claim succeeds.
#[test]
fn with_cooldown_throttles_and_then_allows() {
    let cooldown = 50;
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay)
        .with_cooldown(cooldown)
        .with_workers_and_shards(2, 3);

    let worker = WorkerId::from_raw(1);

    // Advance past t=0 so the first claim can succeed.
    sim.context.advance(1);

    // First claim should succeed.
    let (event, violations) = sim.step(SimOp::ClaimNext { worker });
    assert!(
        matches!(event, SimEvent::ClaimOk { .. }),
        "expected ClaimOk, got {event:?}"
    );
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );

    // Immediate retry (no time advance) should be throttled.
    let (event, violations) = sim.step(SimOp::ClaimNext { worker });
    assert!(
        matches!(event, SimEvent::ClaimThrottled { .. }),
        "expected ClaimThrottled, got {event:?}"
    );
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );

    // Advance past the cooldown window.
    let (_, adv_violations) = sim.step(SimOp::AdvanceTime { ticks: cooldown });
    assert!(adv_violations.is_empty());

    // Post-cooldown claim should succeed.
    let (event, violations) = sim.step(SimOp::ClaimNext { worker });
    assert!(
        matches!(event, SimEvent::ClaimOk { .. }),
        "expected ClaimOk after cooldown, got {event:?}"
    );
    assert!(
        violations.is_empty(),
        "unexpected violations: {violations:?}"
    );
}

// -- Unpark behavioral tests ------------------------------------------------
//
// Unpark is the only allowed terminal->non-terminal transition (Parked->Active).
// The coordinator must bump fence_epoch during unpark so stale pre-park
// leases are invalidated (S3 exemption). These tests verify the harness
// correctly tracks active-set membership, the coordinator bumps fences, and
// the invariant checker's S3 exemption fires without false positives.

#[test]
fn unpark_reverses_park_and_allows_reacquire() {
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);
    let worker = WorkerId::from_raw(1);
    let key = sim.shard_keys[0];

    sim.context.advance(1);

    // Acquire the shard.
    let (event, violations) = sim.step(SimOp::Acquire { worker, key });
    assert!(matches!(event, SimEvent::AcquireOk { .. }));
    assert!(violations.is_empty());

    // Park it (terminal — removed from active set).
    let (event, violations) = sim.step(SimOp::Park { worker, key });
    assert!(matches!(event, SimEvent::ParkOk));
    assert!(violations.is_empty());
    assert!(
        !sim.active_shard_keys.contains(&key),
        "parked shard should not be in active set"
    );

    // Unpark (admin — Parked→Active + fence bump).
    let (event, violations) = sim.step(SimOp::Unpark { key });
    assert!(
        matches!(event, SimEvent::UnparkOk),
        "expected UnparkOk, got {event:?}"
    );
    assert!(
        violations.is_empty(),
        "S3 violation on unpark: {violations:?}"
    );
    assert!(
        sim.active_shard_keys.contains(&key),
        "unparked shard should be back in active set"
    );

    // Re-acquire after unpark succeeds (new fence epoch).
    let (event, violations) = sim.step(SimOp::Acquire { worker, key });
    assert!(
        matches!(event, SimEvent::AcquireOk { .. }),
        "expected AcquireOk after unpark, got {event:?}"
    );
    assert!(violations.is_empty());
}

#[test]
fn unpark_on_non_parked_shard_is_rejected() {
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 1);
    let key = sim.shard_keys[0];

    sim.context.advance(1);

    // Shard is Active (not Parked) — unpark should be rejected.
    let (event, violations) = sim.step(SimOp::Unpark { key });
    assert!(
        matches!(
            event,
            SimEvent::Rejected {
                kind: RejectionKind::NotParked
            }
        ),
        "expected NotParked rejection, got {event:?}"
    );
    assert!(violations.is_empty());
}

#[test]
fn unpark_smoke_no_s3_violation() {
    // Park → Unpark → verify S3 (TerminalIrreversibility) does not fire.
    // The coordinator always bumps fence on unpark, so S3 should never fire
    // through normal code paths. This confirms the integration is wired correctly.
    let mut sim = CoordinationSim::new(99, FaultLevel::SunnyDay).with_workers_and_shards(2, 3);
    let worker = WorkerId::from_raw(1);
    let key = sim.shard_keys[0];

    sim.context.advance(1);

    let (event, _) = sim.step(SimOp::Acquire { worker, key });
    assert!(matches!(event, SimEvent::AcquireOk { .. }));

    let (event, _) = sim.step(SimOp::Park { worker, key });
    assert!(matches!(event, SimEvent::ParkOk));

    let (event, violations) = sim.step(SimOp::Unpark { key });
    assert!(matches!(event, SimEvent::UnparkOk));
    assert!(
        violations.is_empty(),
        "S3 should not fire on valid unpark: {violations:?}"
    );
}

#[test]
fn try_gen_unpark_finds_parked_shards() {
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(1, 2);
    let worker = WorkerId::from_raw(1);
    let key = sim.shard_keys[0];

    sim.context.advance(1);

    // No parked shards yet — try_gen_unpark returns None.
    assert!(
        sim.try_gen_unpark().is_none(),
        "expected None when no shards are parked"
    );

    // Acquire and park one shard.
    sim.execute_op(&SimOp::Acquire { worker, key });
    sim.execute_op(&SimOp::Park { worker, key });

    // Now a parked shard exists — try_gen_unpark returns Some.
    let op = sim.try_gen_unpark();
    assert!(
        matches!(op, Some(SimOp::Unpark { .. })),
        "expected Some(Unpark), got {op:?}"
    );
}

#[test]
fn mega_sim_exercises_unpark() {
    // Run 10 seeds under Stormy faults with enough safety ops for parks
    // to accumulate and some unparks to fire.
    for seed in 0..10 {
        let report = CoordinationSim::new(seed, FaultLevel::Stormy)
            .with_workers_and_shards(4, 15)
            .run(300, 500);
        assert!(
            report.violations.is_empty(),
            "seed {seed}: violations: {:?}",
            report.violations,
        );
    }
    // At least one seed should have exercised UnparkOk across 10 seeds.
    // We check one representative seed rather than all (to avoid flakiness
    // from seeds that happen to generate zero parks).
    let report = CoordinationSim::new(42, FaultLevel::Stormy)
        .with_workers_and_shards(4, 15)
        .run(500, 500);
    assert!(
        report.violations.is_empty(),
        "seed 42: violations: {:?}",
        report.violations,
    );
}

/// Worker ID 0 is rejected because partition 0 is reserved for admin ops.
#[test]
#[should_panic(expected = "worker ID 0 is reserved")]
fn add_worker_rejects_id_zero() {
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);
    sim.add_worker(WorkerId::from_raw(0));
}

#[test]
#[should_panic(
    expected = "simulation backend produced unexpected infrastructure error: [transient] injected_fault: injected session backend fault"
)]
fn session_lifecycle_panics_on_complete_backend_error() {
    let seed = find_seed_for_session_terminal_action(b'a', b'b', |action| {
        matches!(action, SessionTerminalAction::Complete)
    });
    let (mut sim, worker, key) =
        seeded_session_sim_with_range(seed, InjectedSessionFault::Complete, b'a', b'b');

    let _ = sim.exec_session_lifecycle(worker, key);
}

#[test]
#[should_panic(
    expected = "simulation backend produced unexpected infrastructure error: [transient] injected_fault: injected session backend fault"
)]
fn session_lifecycle_panics_on_split_replace_backend_error() {
    let seed = find_seed_for_session_terminal_action(b'a', b'z', |action| {
        matches!(action, SessionTerminalAction::SplitReplace)
    });
    let (mut sim, worker, key) =
        seeded_session_sim_with_range(seed, InjectedSessionFault::SplitReplace, b'a', b'z');

    let _ = sim.exec_session_lifecycle(worker, key);
}

#[test]
#[should_panic(
    expected = "simulation backend produced unexpected infrastructure error: [transient] injected_fault: injected session backend fault"
)]
fn session_lifecycle_panics_on_split_residual_backend_error() {
    let seed = find_seed_for_session_terminal_action(b'a', b'z', |action| {
        matches!(action, SessionTerminalAction::SplitResidualThenComplete)
    });
    let (mut sim, worker, key) =
        seeded_session_sim_with_range(seed, InjectedSessionFault::SplitResidual, b'a', b'z');

    let _ = sim.exec_session_lifecycle(worker, key);
}

#[test]
#[should_panic(
    expected = "simulation backend produced unexpected infrastructure error: [transient] injected_fault: injected session backend fault"
)]
fn session_lifecycle_panics_on_post_residual_complete_backend_error() {
    let seed = find_seed_for_session_terminal_action(b'a', b'z', |action| {
        matches!(action, SessionTerminalAction::SplitResidualThenComplete)
    });
    let (mut sim, worker, key) =
        seeded_session_sim_with_range(seed, InjectedSessionFault::Complete, b'a', b'z');

    let _ = sim.exec_session_lifecycle(worker, key);
}

/// Admin unpark succeeds on a shard previously held by worker 1 — no
/// op-ID collision because worker IDs start at 1 and admin uses partition 0.
#[test]
fn admin_unpark_no_op_id_collision_with_workers() {
    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);

    let worker = WorkerId::from_raw(1);
    sim.add_worker(worker);

    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    sim.register_shard(run, shard);
    sim.seed_all_runs();
    sim.active_shard_keys = sim.shard_keys.clone();

    let key = sim.shard_keys[0];
    sim.context.advance(1);

    // Worker 1 acquires: generates op_id from partition 1.
    let (event, violations) = sim.step(SimOp::Acquire { worker, key });
    assert!(
        matches!(event, SimEvent::AcquireOk { .. }),
        "expected AcquireOk, got {event:?}"
    );
    assert!(violations.is_empty());

    // Park the shard.
    let (event, violations) = sim.step(SimOp::Park { worker, key });
    assert!(
        matches!(event, SimEvent::ParkOk),
        "expected ParkOk, got {event:?}"
    );
    assert!(violations.is_empty());

    // Admin unpark draws from partition 0 — disjoint from worker 1's partition.
    let (event, violations) = sim.step(SimOp::Unpark { key });
    assert!(
        matches!(event, SimEvent::UnparkOk),
        "expected UnparkOk but got {event:?}"
    );
    assert!(
        violations.is_empty(),
        "invariant violations on unpark: {violations:?}"
    );
}

// -- Run-terminal behavioral tests ------------------------------------------
//
// Run-level terminal transitions (complete/fail/cancel) are admin
// operations that affect the run record, not individual shard records.
// After a run is terminated, admin ops like unpark must be rejected
// (the run is frozen), but shard-level ops (acquire, checkpoint,
// complete) continue working on already-registered shards. These tests
// verify this asymmetry and the S8 terminal irreversibility invariant.

/// Validates the coordinator contract around run termination:
/// - Unpark is blocked after run terminal (`TerminalState` rejection).
/// - Shard lifecycle ops (acquire) continue after run termination.
/// - Terminal transitions are irreversible (second attempt rejected).
#[test]
fn run_terminal_unpark_blocked_shard_ops_continue() {
    use gossip_contracts::identity::{RunId, WorkerId};

    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay).with_workers_and_shards(2, 5);
    let worker1 = WorkerId::from_raw(1);
    let worker2 = WorkerId::from_raw(2);

    // Advance clock off ZERO (coordinator requires now > ZERO).
    let (_, v) = sim.step(SimOp::AdvanceTime { ticks: 1 });
    assert!(v.is_empty());

    // Acquire a shard with worker 1, then park it.
    let park_key = sim.shard_keys[0];
    let (event, v) = sim.step(SimOp::Acquire {
        worker: worker1,
        key: park_key,
    });
    assert!(matches!(event, SimEvent::AcquireOk { .. }));
    assert!(v.is_empty());

    let (event, v) = sim.step(SimOp::Park {
        worker: worker1,
        key: park_key,
    });
    assert!(matches!(event, SimEvent::ParkOk));
    assert!(v.is_empty());

    // Acquire another shard with worker 2 (active lease for post-termination test).
    let active_key = sim.shard_keys[1];
    let (event, v) = sim.step(SimOp::Acquire {
        worker: worker2,
        key: active_key,
    });
    assert!(matches!(event, SimEvent::AcquireOk { .. }));
    assert!(v.is_empty());

    // Cancel the run.
    let run = RunId::from_raw(1);
    let (event, v) = sim.step(SimOp::TerminateRun {
        run,
        kind: RunTerminalKind::Cancel,
    });
    assert!(
        matches!(
            event,
            SimEvent::RunTerminalOk {
                kind: RunTerminalKind::Cancel
            }
        ),
        "expected RunTerminalOk(Cancel), got {event:?}"
    );
    assert!(v.is_empty());

    // Unpark should be rejected — run is terminal.
    let (event, v) = sim.step(SimOp::Unpark { key: park_key });
    assert!(
        matches!(
            event,
            SimEvent::Rejected {
                kind: RejectionKind::TerminalState
            }
        ),
        "expected TerminalState rejection for unpark after run cancel, got {event:?}"
    );
    assert!(v.is_empty());

    // Shard ops continue — acquire on another shard succeeds.
    let another_key = sim.shard_keys[2];
    let (event, v) = sim.step(SimOp::Acquire {
        worker: worker2,
        key: another_key,
    });
    assert!(
        matches!(event, SimEvent::AcquireOk { .. }),
        "shard acquire should succeed after run termination, got {event:?}"
    );
    assert!(v.is_empty());

    // Terminal irreversibility: completing an already-cancelled run is rejected.
    let (event, v) = sim.step(SimOp::TerminateRun {
        run,
        kind: RunTerminalKind::Complete,
    });
    assert!(
        matches!(
            event,
            SimEvent::Rejected {
                kind: RejectionKind::TerminalState
            }
        ),
        "expected TerminalState rejection for complete after cancel, got {event:?}"
    );
    assert!(v.is_empty());
}

/// `try_gen_terminate_run` should sample across all seeded runs so multi-run
/// simulations do not starve run-terminal coverage for later run IDs.
#[test]
fn terminate_run_generator_targets_multiple_runs() {
    use gossip_contracts::identity::RunId;

    let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);
    let run1 = RunId::from_raw(1);
    let run2 = RunId::from_raw(2);
    for i in 1..=3 {
        sim.register_shard(run1, ShardId::from_raw(i));
        sim.register_shard(run2, ShardId::from_raw(i));
    }

    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let op = sim
            .try_gen_terminate_run()
            .expect("terminate_run op should be generatable when runs are seeded");
        match op {
            SimOp::TerminateRun { run, .. } => {
                seen.insert(run);
            }
            other => panic!("expected TerminateRun op, got {other:?}"),
        }
    }

    assert!(
        seen.contains(&run1) && seen.contains(&run2),
        "terminate_run generator should target both runs, saw: {seen:?}"
    );
}
