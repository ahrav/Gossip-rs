#![cfg(feature = "test-support")]

use std::collections::BTreeMap;

use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};
use gossip_coordination::sim::{
    CoordinationSim, FaultLevel, InvariantChecker, SimEventKind, SimReport,
};
use gossip_coordination::{
    AcquireScratch, CheckpointError, CoordinationBackend, IdempotentOutcome, InfraError,
};
use gossip_coordination_etcd::sim_etcd_kv::{SimEtcdFaultConfig, SimEtcdFaultStats};
use gossip_coordination_etcd::{EtcdCoordinatorConfig, SimEtcdCoordinator};

#[derive(Clone)]
struct SimCase {
    harness_level: FaultLevel,
    etcd_faults: SimEtcdFaultConfig,
    workers: u64,
    shards: u64,
    safety_ops: usize,
    liveness_ops: usize,
}

fn parse_seed_count(default: usize) -> usize {
    match std::env::var("GOSSIP_SIM_SEEDS") {
        Ok(value) => match value.parse() {
            Ok(count) => count,
            Err(err) => {
                eprintln!(
                    "warning: GOSSIP_SIM_SEEDS={value:?} is not a valid number ({err}), \
                     falling back to default {default}"
                );
                default
            }
        },
        Err(_) => default,
    }
}

fn parse_single_seed() -> Option<u64> {
    match std::env::var("GOSSIP_SIM_SEED") {
        Ok(value) => match value.parse() {
            Ok(seed) => Some(seed),
            Err(err) => {
                eprintln!(
                    "warning: GOSSIP_SIM_SEED={value:?} is not a valid number ({err}), ignoring"
                );
                None
            }
        },
        Err(_) => None,
    }
}

fn selected_seeds(default_count: usize) -> Vec<u64> {
    if let Some(seed) = parse_single_seed() {
        vec![seed]
    } else {
        (0..parse_seed_count(default_count) as u64).collect()
    }
}

fn test_config() -> EtcdCoordinatorConfig {
    EtcdCoordinatorConfig::new_with_tuning(
        ["http://127.0.0.1:2379"],
        "/gossip/sim-etcd-mega",
        60,
        8,
        8,
    )
    .expect("hard-coded mega-sim etcd config must be valid")
}

fn build_sim(seed: u64, case: &SimCase) -> CoordinationSim<SimEtcdCoordinator> {
    let config = test_config();
    let retry_budget = config.optimistic_txn_retries();
    let backend = SimEtcdCoordinator::new(config, seed).expect("sim etcd backend must construct");
    let mut sim = CoordinationSim::with_backend(seed, case.harness_level, backend)
        .with_workers_and_shards(case.workers, case.shards);
    // etcd-level faults are active from op 0, including during the harness
    // warmup window (first 5 ops). The harness WARMUP_OPS suppression only
    // affects harness-level fault scheduling, not backend fault injection.
    // This is intentional: the coordinator must handle transient failures at
    // any point, including during initial lease establishment.
    sim.backend_mut().set_fault_config(
        case.etcd_faults
            .clone()
            .with_retry_exhaustion_attempts(retry_budget),
    );
    sim
}

fn run_case(seed: u64, case: &SimCase) -> (SimReport, SimEtcdFaultStats) {
    let (report, backend) =
        build_sim(seed, case).run_and_return_backend(case.safety_ops, case.liveness_ops);
    (report, backend.fault_stats())
}

fn merge_event_counts(
    aggregate: &mut BTreeMap<SimEventKind, usize>,
    counts: &BTreeMap<SimEventKind, usize>,
) {
    for (kind, count) in counts {
        *aggregate.entry(*kind).or_insert(0) += count;
    }
}

fn repro_command(test_name: &str, seed: u64) -> String {
    format!(
        "GOSSIP_SIM_SEED={seed} cargo test -p gossip-coordination-etcd --features test-support \
         {test_name} -- --ignored --nocapture"
    )
}

fn assert_required_events(
    counts: &BTreeMap<SimEventKind, usize>,
    required: &[SimEventKind],
    seed_count: usize,
) {
    for kind in required {
        assert!(
            counts.contains_key(kind),
            "event kind {kind:?} never observed across {seed_count} seed(s)"
        );
    }
}

fn run_parallel_seed_sweep(
    test_name: &str,
    seeds: &[u64],
    case: &SimCase,
) -> (
    Vec<(u64, String)>,
    BTreeMap<SimEventKind, usize>,
    SimEtcdFaultStats,
) {
    if seeds.is_empty() {
        return (Vec::new(), BTreeMap::new(), SimEtcdFaultStats::default());
    }

    let parallelism = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4);
    let chunk_size = seeds.len().div_ceil(parallelism);

    let mut all_failures = Vec::new();
    let mut aggregate_counts = BTreeMap::new();
    let mut aggregate_faults = SimEtcdFaultStats::default();

    std::thread::scope(|scope| {
        let handles: Vec<_> = seeds
            .chunks(chunk_size)
            .map(|chunk| {
                let chunk = chunk.to_vec();
                let case = case.clone();
                scope.spawn(move || {
                    let mut failures = Vec::new();
                    let mut local_counts = BTreeMap::new();
                    let mut local_faults = SimEtcdFaultStats::default();

                    for seed in chunk {
                        let (report, stats) = run_case(seed, &case);
                        merge_event_counts(&mut local_counts, &report.event_counts);
                        local_faults += stats;

                        if !report.violations.is_empty() {
                            failures.push((seed, format!("{:#?}", report.violations)));
                        }
                    }

                    (failures, local_counts, local_faults)
                })
            })
            .collect();

        // Two-pass join: collect all outcomes before processing so that a
        // panic in one thread does not drop unjoined handles and discard
        // their invariant-violation data or fault counters.
        let results: Vec<_> = handles.into_iter().map(|h| h.join()).collect();

        for result in results {
            let (failures, local_counts, local_faults) = result.unwrap_or_else(|panic_val| {
                let msg = panic_val
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| panic_val.downcast_ref::<&str>().copied())
                    .unwrap_or("(non-string panic)");
                panic!("{test_name} worker thread panicked: {msg}");
            });
            all_failures.extend(failures);
            merge_event_counts(&mut aggregate_counts, &local_counts);
            aggregate_faults += local_faults;
        }
    });

    (all_failures, aggregate_counts, aggregate_faults)
}

fn assert_seed_sweep_clean(test_name: &str, seed_count: usize, failures: &[(u64, String)]) {
    assert!(
        failures.is_empty(),
        "invariant violations in {}/{} seed(s):\n{}",
        failures.len(),
        seed_count,
        failures
            .iter()
            .map(|(seed, violations)| format!(
                "  seed {seed}: {violations}\n  Reproduce: {}",
                repro_command(test_name, *seed)
            ))
            .collect::<Vec<_>>()
            .join("\n\n")
    );
}

fn stormy_cas_faults() -> SimEtcdFaultConfig {
    SimEtcdFaultConfig::for_level(FaultLevel::Stormy)
        .with_uncertain_commit_ppm(0)
        .with_lease_ttl_race_ppm(0)
        .with_retry_exhaustion_ppm(0)
}

fn elevated_cas_faults() -> SimEtcdFaultConfig {
    stormy_cas_faults().with_cas_compare_failure_ppm(300_000)
}

fn tenant() -> TenantId {
    TenantId::from_bytes([0x01; 32])
}

fn now(raw: u64) -> LogicalTime {
    LogicalTime::from_raw(raw)
}

#[test]
#[ignore]
fn mega_sim_10k_steps_sunny() {
    if cfg!(miri) {
        return;
    }

    let seeds = selected_seeds(100);
    if seeds.is_empty() {
        return;
    }

    let case = SimCase {
        harness_level: FaultLevel::SunnyDay,
        etcd_faults: SimEtcdFaultConfig::for_level(FaultLevel::SunnyDay),
        workers: 4,
        shards: 15,
        safety_ops: 10_000,
        liveness_ops: 2_000,
    };
    let (failures, aggregate_counts, aggregate_faults) =
        run_parallel_seed_sweep("mega_sim_10k_steps_sunny", &seeds, &case);

    assert_seed_sweep_clean("mega_sim_10k_steps_sunny", seeds.len(), &failures);
    assert_required_events(
        &aggregate_counts,
        &[
            SimEventKind::AcquireOk,
            SimEventKind::CheckpointOk,
            SimEventKind::CompleteOk,
            SimEventKind::Rejected,
            SimEventKind::TimeAdvanced,
        ],
        seeds.len(),
    );
    assert_eq!(
        aggregate_faults,
        SimEtcdFaultStats::default(),
        "SunnyDay etcd backend must not inject any faults"
    );
}

#[test]
#[ignore]
fn mega_sim_10k_steps_stormy() {
    if cfg!(miri) {
        return;
    }

    let seeds = selected_seeds(100);
    if seeds.is_empty() {
        return;
    }

    let case = SimCase {
        harness_level: FaultLevel::Stormy,
        etcd_faults: SimEtcdFaultConfig::for_level(FaultLevel::Stormy)
            .with_uncertain_commit_ppm(0)
            .with_retry_exhaustion_ppm(0),
        workers: 4,
        shards: 15,
        safety_ops: 10_000,
        liveness_ops: 2_000,
    };
    let (failures, aggregate_counts, aggregate_faults) =
        run_parallel_seed_sweep("mega_sim_10k_steps_stormy", &seeds, &case);

    assert_seed_sweep_clean("mega_sim_10k_steps_stormy", seeds.len(), &failures);
    assert_required_events(
        &aggregate_counts,
        &[
            SimEventKind::AcquireOk,
            SimEventKind::CheckpointOk,
            SimEventKind::CompleteOk,
            SimEventKind::Rejected,
            SimEventKind::TimeAdvanced,
            SimEventKind::SessionLifecyclePartial,
        ],
        seeds.len(),
    );
    assert!(
        aggregate_faults.cas_retry_failures() > 0,
        "Stormy seed sweep never observed CAS retry pressure"
    );
    assert!(
        aggregate_faults.lease_ttl_races > 0,
        "Stormy seed sweep never observed a lease-TTL race injection"
    );
}

#[test]
#[ignore]
fn convergence_stormy_cas_contention() {
    if cfg!(miri) {
        return;
    }

    let seeds = selected_seeds(20);
    if seeds.is_empty() {
        return;
    }

    let case = SimCase {
        harness_level: FaultLevel::Stormy,
        etcd_faults: stormy_cas_faults(),
        workers: 4,
        shards: 15,
        safety_ops: 500,
        liveness_ops: 20_000,
    };

    // Sequential: per-seed convergence assertion with individual repro commands.
    let mut total_cas_retries = 0usize;
    for seed in &seeds {
        let (report, stats) = run_case(*seed, &case);
        assert!(
            report.violations.is_empty(),
            "seed {seed}: safety violation under stormy CAS contention.\n\
             Reproduce: {}\n\
             Violations: {:#?}",
            repro_command("convergence_stormy_cas_contention", *seed),
            report.violations,
        );
        assert!(
            report.converged,
            "seed {seed}: failed to converge after {} ops ({} shard(s) still non-terminal).\n\
             Reproduce: {}",
            report.ops_executed,
            report.non_terminal_count,
            repro_command("convergence_stormy_cas_contention", *seed),
        );
        total_cas_retries += stats.cas_retry_failures();
    }

    assert!(
        total_cas_retries > 0,
        "convergence sweep never observed CAS retry pressure"
    );
}

#[test]
#[ignore]
fn cas_contention_stress() {
    if cfg!(miri) {
        return;
    }

    let seeds = selected_seeds(10);
    if seeds.is_empty() {
        return;
    }

    let case = SimCase {
        harness_level: FaultLevel::Stormy,
        etcd_faults: elevated_cas_faults(),
        workers: 12,
        shards: 4,
        safety_ops: 8_000,
        liveness_ops: 2_000,
    };

    // Sequential: per-seed violation check with individual repro reporting.
    let mut total_cas_retries = 0usize;
    for seed in &seeds {
        let (report, stats) = run_case(*seed, &case);
        assert!(
            report.violations.is_empty(),
            "seed {seed}: invariant violation under elevated CAS contention.\n\
             Reproduce: {}\n\
             Violations: {:#?}",
            repro_command("cas_contention_stress", *seed),
            report.violations,
        );
        total_cas_retries += stats.cas_retry_failures();
    }

    assert!(
        total_cas_retries > 0,
        "elevated CAS contention test never observed a synthetic CAS retry"
    );
}

#[test]
#[ignore]
fn uncertain_commit_resilience() {
    if cfg!(miri) {
        return;
    }

    let seeds = selected_seeds(10);
    if seeds.is_empty() {
        return;
    }

    // Sequential: manual sim construction and per-seed acquire/checkpoint ops.
    let mut total_uncertain_commits = 0usize;
    for seed in &seeds {
        let mut sim = build_sim(
            *seed,
            &SimCase {
                harness_level: FaultLevel::Stormy,
                etcd_faults: SimEtcdFaultConfig::default(),
                workers: 1,
                shards: 1,
                safety_ops: 0,
                liveness_ops: 0,
            },
        );
        let backend = sim.backend_mut();
        let shard_key = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(1));
        let worker = WorkerId::from_raw(1);
        let mut checker = InvariantChecker::new();
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), tenant(), shard_key, worker, &mut scratch)
            .expect("pre-fault acquire must succeed");
        assert!(
            checker.check_all(backend, tenant(), now(3)).is_empty(),
            "seed {seed}: invariants must hold after acquire"
        );

        backend.set_fault_config(
            SimEtcdFaultConfig::for_level(FaultLevel::Stormy)
                .with_cas_compare_failure_ppm(0)
                .with_lease_ttl_race_ppm(0)
                .with_retry_exhaustion_ppm(0)
                .with_uncertain_commit_ppm(1_000_000),
        );

        let op_id = OpId::from_raw(10_000 + *seed);
        let cursor = CursorUpdate::new(b"mid");
        let first = backend.checkpoint(now(4), tenant(), &acquire.lease, &cursor, op_id);
        assert!(
            matches!(
                first,
                Err(CheckpointError::BackendError(InfraError::Transient {
                    ref operation,
                    ..
                })) if operation == "checkpoint.txn"
            ),
            "seed {seed}: first checkpoint should surface an uncertain-commit retry, got: {first:?}"
        );
        assert!(
            checker.check_all(backend, tenant(), now(4)).is_empty(),
            "seed {seed}: invariants must hold after uncertain checkpoint commit"
        );

        let replay = backend
            .checkpoint(now(5), tenant(), &acquire.lease, &cursor, op_id)
            .expect("checkpoint retry should resolve through op-log replay");
        assert!(
            matches!(replay, IdempotentOutcome::Replayed(())),
            "seed {seed}: checkpoint retry must replay the committed outcome"
        );
        assert!(
            checker.check_all(backend, tenant(), now(5)).is_empty(),
            "seed {seed}: invariants must hold after checkpoint replay"
        );
        total_uncertain_commits += backend.fault_stats().uncertain_commits;
    }

    assert!(
        total_uncertain_commits >= seeds.len(),
        "uncertain-commit resilience sweep: expected one uncertain commit per seed \
         ({} seed(s)) but observed only {total_uncertain_commits}",
        seeds.len(),
    );
}

#[test]
#[ignore]
fn split_cascade_under_cas() {
    if cfg!(miri) {
        return;
    }

    let seeds = selected_seeds(10);
    if seeds.is_empty() {
        return;
    }

    let case = SimCase {
        harness_level: FaultLevel::Radioactive,
        etcd_faults: elevated_cas_faults().with_uncertain_commit_ppm(0),
        workers: 4,
        shards: 20,
        safety_ops: 3_000,
        liveness_ops: 1_000,
    };

    let mut total_split_replaces = 0usize;
    let mut total_cas_retries = 0usize;
    for seed in &seeds {
        let (report, stats) = run_case(*seed, &case);
        assert!(
            report.violations.is_empty(),
            "seed {seed}: invariant violation during split cascade under CAS.\n\
             Reproduce: {}\n\
             Violations: {:#?}",
            repro_command("split_cascade_under_cas", *seed),
            report.violations,
        );
        total_split_replaces += report
            .event_counts
            .get(&SimEventKind::SplitReplaceOk)
            .copied()
            .unwrap_or(0);
        total_cas_retries += stats.cas_retry_failures();
    }

    assert!(
        total_split_replaces > 0,
        "split cascade sweep never observed a SplitReplaceOk event"
    );
    assert!(
        total_cas_retries > 0,
        "split cascade sweep never observed CAS retry pressure"
    );
}
