use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use gossip_contracts::{
    persistence::{DoneLedgerRecord, DoneLedgerStatus},
    test_util::miri_proptest_config,
};
use proptest::{collection::vec, prelude::*};

use super::harness::PROPTEST_OVID_POOL_SIZE;
use super::{
    DoneLedgerSim, DoneLedgerSimEventKind, DoneLedgerSimOp, DoneLedgerSimReport, FaultLevel,
    PersistenceSim,
};
use crate::{CompletionOrder, PendingWriteId};

const SUNNY_DAY_OPS: usize = 200;
const STORMY_SWEEP_SEEDS: usize = 100;
const STORMY_SWEEP_OPS: usize = 500;
const SWIZZLE_SWEEP_SEEDS: usize = 100;
const SWIZZLE_BATCHES: usize = 10;
const RADIOACTIVE_SWEEP_SEEDS: usize = 50;
const RADIOACTIVE_SWEEP_OPS: usize = 1_000;

struct SweepOutcome {
    seed_count: usize,
    failures: Vec<(u64, String)>,
    aggregate_counts: BTreeMap<DoneLedgerSimEventKind, usize>,
    /// Wall-clock duration. Retained for diagnostic output; not asserted
    /// in tests to avoid CI flakiness.
    #[allow(dead_code)]
    elapsed: Duration,
}

#[derive(Debug, Clone)]
pub(super) struct RecordSpec {
    pub(super) ovid_index: usize,
    pub(super) status: DoneLedgerStatus,
    pub(super) bytes_scanned: u64,
    pub(super) findings_count: u32,
    pub(super) started_at: u64,
    pub(super) duration: u64,
}

#[derive(Debug, Clone)]
enum ProptestOp {
    BatchUpsert { records: Vec<RecordSpec> },
    BatchGet { ovid_indices: Vec<usize> },
    ReleaseOldest,
    ReleaseNewest,
    ReleaseSpecific { op_id: PendingWriteId },
    ReleaseAll { order: CompletionOrder },
    InjectSubmitFailure { count: usize },
    InjectCommitFailure { count: usize },
    InjectDelay { count: usize },
}

fn run_seed_sweep<F>(seed_count: usize, runner: F) -> SweepOutcome
where
    F: Fn(u64) -> DoneLedgerSimReport + Sync,
{
    let start = Instant::now();
    if seed_count == 0 {
        return SweepOutcome {
            seed_count,
            failures: Vec::new(),
            aggregate_counts: BTreeMap::new(),
            elapsed: start.elapsed(),
        };
    }

    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let seeds: Vec<u64> = (0..seed_count as u64).collect();
    let chunk_size = seeds.len().div_ceil(parallelism);

    let mut failures = Vec::new();
    let mut aggregate_counts = BTreeMap::new();

    std::thread::scope(|scope| {
        let handles: Vec<_> = seeds
            .chunks(chunk_size)
            .map(|chunk| {
                let chunk = chunk.to_vec();
                let runner = &runner;
                scope.spawn(move || {
                    let mut local_failures = Vec::new();
                    let mut local_counts = BTreeMap::new();

                    for seed in chunk {
                        let result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner(seed)));
                        match result {
                            Ok(report) => {
                                for (kind, count) in report.event_counts {
                                    *local_counts.entry(kind).or_insert(0) += count;
                                }

                                if !report.violations.is_empty() || !report.converged {
                                    local_failures.push((
                                        seed,
                                        format!(
                                            "converged={} violations={:#?}",
                                            report.converged, report.violations
                                        ),
                                    ));
                                }
                            }
                            Err(panic_val) => {
                                let msg = panic_val
                                    .downcast_ref::<String>()
                                    .map(|s| s.as_str())
                                    .or_else(|| panic_val.downcast_ref::<&str>().copied())
                                    .unwrap_or("(non-string panic)");
                                local_failures.push((seed, format!("PANIC: {msg}")));
                            }
                        }
                    }

                    (local_failures, local_counts)
                })
            })
            .collect();

        for handle in handles {
            let (local_failures, local_counts) = handle.join().expect("simulation thread aborted");
            failures.extend(local_failures);
            for (kind, count) in local_counts {
                *aggregate_counts.entry(kind).or_insert(0) += count;
            }
        }
    });

    SweepOutcome {
        seed_count,
        failures,
        aggregate_counts,
        elapsed: start.elapsed(),
    }
}

fn assert_no_failures(test_name: &str, outcome: &SweepOutcome) {
    assert!(
        outcome.failures.is_empty(),
        "{test_name} failures in {}/{} seeds:\n{}",
        outcome.failures.len(),
        outcome.seed_count,
        outcome
            .failures
            .iter()
            .map(|(seed, detail)| format!("  seed {seed}: {detail}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    );
}

fn assert_event_coverage(outcome: &SweepOutcome) {
    for kind in DoneLedgerSimEventKind::ALL {
        assert!(
            outcome.aggregate_counts.get(&kind).copied().unwrap_or(0) > 0,
            "event kind {kind:?} never observed across {} seeds: {:?}",
            outcome.seed_count,
            outcome.aggregate_counts
        );
    }
}

fn arb_fault_level() -> impl Strategy<Value = FaultLevel> {
    prop_oneof![
        Just(FaultLevel::SunnyDay),
        Just(FaultLevel::Stormy),
        Just(FaultLevel::Radioactive),
    ]
}

fn arb_done_ledger_status() -> impl Strategy<Value = DoneLedgerStatus> {
    prop_oneof![
        Just(DoneLedgerStatus::FailedRetryable),
        Just(DoneLedgerStatus::FailedPermanent),
        Just(DoneLedgerStatus::Skipped),
        Just(DoneLedgerStatus::ScannedClean),
        Just(DoneLedgerStatus::ScannedWithFindings),
    ]
}

fn arb_completion_order() -> impl Strategy<Value = CompletionOrder> {
    prop_oneof![
        Just(CompletionOrder::OldestFirst),
        Just(CompletionOrder::NewestFirst),
    ]
}

fn arb_record_spec() -> impl Strategy<Value = RecordSpec> {
    (
        0usize..PROPTEST_OVID_POOL_SIZE,
        arb_done_ledger_status(),
        0u64..=10_000,
        1u64..=1_000,
        1u64..=200,
    )
        .prop_map(
            |(ovid_index, status, bytes_scanned, started_at, duration)| {
                let findings_count = match status {
                    DoneLedgerStatus::ScannedClean => 0,
                    DoneLedgerStatus::ScannedWithFindings => ((bytes_scanned % 5) + 1) as u32,
                    _ => (bytes_scanned % 4) as u32,
                };
                RecordSpec {
                    ovid_index,
                    status,
                    bytes_scanned,
                    findings_count,
                    started_at,
                    duration,
                }
            },
        )
}

fn arb_proptest_op() -> impl Strategy<Value = ProptestOp> {
    prop_oneof![
        6 => vec(arb_record_spec(), 1..=10)
            .prop_map(|records| ProptestOp::BatchUpsert { records }),
        3 => vec(0usize..PROPTEST_OVID_POOL_SIZE, 1..=10)
            .prop_map(|ovid_indices| ProptestOp::BatchGet { ovid_indices }),
        1 => Just(ProptestOp::ReleaseOldest),
        1 => Just(ProptestOp::ReleaseNewest),
        2 => arb_completion_order()
            .prop_map(|order| ProptestOp::ReleaseAll { order }),
        1 => (1u64..=64)
            .prop_map(|raw| ProptestOp::ReleaseSpecific {
                op_id: PendingWriteId::from_raw(raw),
            }),
        1 => (1usize..=2)
            .prop_map(|count| ProptestOp::InjectSubmitFailure { count }),
        1 => (1usize..=2)
            .prop_map(|count| ProptestOp::InjectCommitFailure { count }),
        1 => (1usize..=3)
            .prop_map(|count| ProptestOp::InjectDelay { count }),
    ]
}

fn materialize_record(sim: &mut DoneLedgerSim, spec: &RecordSpec) -> DoneLedgerRecord {
    sim.build_test_record(spec)
}

fn map_batch_get_indices(raw_indices: &[usize], seen_ovid_indices: &BTreeSet<usize>) -> Vec<usize> {
    debug_assert!(!raw_indices.is_empty());

    let result: Vec<usize> = if seen_ovid_indices.is_empty() {
        raw_indices
            .iter()
            .map(|idx| idx % PROPTEST_OVID_POOL_SIZE)
            .collect()
    } else {
        let seen: Vec<usize> = seen_ovid_indices.iter().copied().collect();
        raw_indices
            .iter()
            .map(|idx| {
                // ~20% of reads target arbitrary pool keys to detect delayed-write
                // leaks for keys the oracle has no record of.
                if idx % 5 == 0 {
                    idx % PROPTEST_OVID_POOL_SIZE
                } else {
                    seen[idx % seen.len()]
                }
            })
            .collect()
    };

    debug_assert_eq!(result.len(), raw_indices.len());
    debug_assert!(result.iter().all(|&i| i < PROPTEST_OVID_POOL_SIZE));
    result
}

fn materialize_op(
    sim: &mut DoneLedgerSim,
    seen_ovid_indices: &mut BTreeSet<usize>,
    op: &ProptestOp,
) -> DoneLedgerSimOp {
    match op {
        ProptestOp::BatchUpsert { records } => {
            for spec in records {
                seen_ovid_indices.insert(spec.ovid_index);
            }
            DoneLedgerSimOp::BatchUpsert {
                records: records
                    .iter()
                    .map(|spec| materialize_record(sim, spec))
                    .collect(),
            }
        }
        ProptestOp::BatchGet { ovid_indices } => DoneLedgerSimOp::BatchGet {
            ovid_indices: map_batch_get_indices(ovid_indices, seen_ovid_indices),
        },
        ProptestOp::ReleaseOldest => DoneLedgerSimOp::ReleaseOldest,
        ProptestOp::ReleaseNewest => DoneLedgerSimOp::ReleaseNewest,
        ProptestOp::ReleaseSpecific { op_id } => DoneLedgerSimOp::ReleaseSpecific { op_id: *op_id },
        ProptestOp::ReleaseAll { order } => DoneLedgerSimOp::ReleaseAll { order: *order },
        ProptestOp::InjectSubmitFailure { count } => {
            DoneLedgerSimOp::InjectSubmitFailure { count: *count }
        }
        ProptestOp::InjectCommitFailure { count } => {
            DoneLedgerSimOp::InjectCommitFailure { count: *count }
        }
        ProptestOp::InjectDelay { count } => DoneLedgerSimOp::InjectDelay { count: *count },
    }
}

fn step_clean(
    sim: &mut DoneLedgerSim,
    op: DoneLedgerSimOp,
    context: &str,
) -> super::DoneLedgerSimEvent {
    let (event, violations) = sim.step(op);
    assert!(
        violations.is_empty(),
        "{context}: violations={violations:?}"
    );
    event
}

fn assert_get_presence(event: super::DoneLedgerSimEvent, expect_some: bool, context: &str) {
    match event {
        super::DoneLedgerSimEvent::GetOk { results } => {
            assert_eq!(results.len(), 1, "{context}: expected single-key batch_get");
            assert_eq!(
                results[0].is_some(),
                expect_some,
                "{context}: unexpected batch_get result {results:?}"
            );
        }
        other => panic!("{context}: expected GetOk event, got {other:?}"),
    }
}

/// Injects a delay fault, upserts a pending record, and verifies it is
/// invisible to reads while still pending.
fn fault_prefix_delayed_write(
    sim: &mut DoneLedgerSim,
    seen_ovid_indices: &mut BTreeSet<usize>,
    spec: &RecordSpec,
) {
    seen_ovid_indices.insert(spec.ovid_index);

    let event = step_clean(
        sim,
        DoneLedgerSimOp::InjectDelay { count: 1 },
        "fault prefix inject delay",
    );
    assert!(matches!(event, super::DoneLedgerSimEvent::FaultConfigured));

    let delayed_record = materialize_record(sim, spec);
    let event = step_clean(
        sim,
        DoneLedgerSimOp::BatchUpsert {
            records: vec![delayed_record],
        },
        "fault prefix delayed upsert",
    );
    assert!(matches!(
        event,
        super::DoneLedgerSimEvent::UpsertPending { .. }
    ));

    let event = step_clean(
        sim,
        DoneLedgerSimOp::BatchGet {
            ovid_indices: vec![spec.ovid_index],
        },
        "fault prefix read while pending",
    );
    assert_get_presence(event, false, "fault prefix read while pending");
}

/// Injects a commit failure, releases the oldest pending write (which fails),
/// and verifies the record remains invisible.
fn fault_prefix_commit_failure(sim: &mut DoneLedgerSim, spec: &RecordSpec) {
    let event = step_clean(
        sim,
        DoneLedgerSimOp::InjectCommitFailure { count: 1 },
        "fault prefix inject commit failure",
    );
    assert!(matches!(event, super::DoneLedgerSimEvent::FaultConfigured));

    let event = step_clean(
        sim,
        DoneLedgerSimOp::ReleaseOldest,
        "fault prefix release delayed write",
    );
    assert!(matches!(
        event,
        super::DoneLedgerSimEvent::ReleasedCommitFailed { .. }
    ));

    let event = step_clean(
        sim,
        DoneLedgerSimOp::BatchGet {
            ovid_indices: vec![spec.ovid_index],
        },
        "fault prefix read after failed commit",
    );
    assert_get_presence(event, false, "fault prefix read after failed commit");
}

/// Retries the upsert (now committed) and verifies the record becomes visible.
fn fault_prefix_successful_retry(sim: &mut DoneLedgerSim, spec: &RecordSpec) {
    let retry_record = materialize_record(sim, spec);
    let event = step_clean(
        sim,
        DoneLedgerSimOp::BatchUpsert {
            records: vec![retry_record],
        },
        "fault prefix retry upsert",
    );
    assert!(matches!(
        event,
        super::DoneLedgerSimEvent::UpsertCommitted { .. }
    ));

    let event = step_clean(
        sim,
        DoneLedgerSimOp::BatchGet {
            ovid_indices: vec![spec.ovid_index],
        },
        "fault prefix read after retry",
    );
    assert_get_presence(event, true, "fault prefix read after retry");
}

fn exercise_fault_prefix(sim: &mut DoneLedgerSim, seen_ovid_indices: &mut BTreeSet<usize>) {
    // Every proptest case starts with one delayed write that fails at commit
    // time, then retries successfully, so the random tail always builds on
    // observed delay/failure/retry behavior instead of hoping to hit it.
    //
    // Uses ovid pool slot 0 so random ops can overlap with it, exercising
    // merge contention on a key that already has fault-prefix write history.
    let retry_spec = RecordSpec {
        ovid_index: 0,
        status: DoneLedgerStatus::ScannedWithFindings,
        bytes_scanned: 512,
        findings_count: 3,
        started_at: 10,
        duration: 5,
    };

    fault_prefix_delayed_write(sim, seen_ovid_indices, &retry_spec);
    fault_prefix_commit_failure(sim, &retry_spec);
    fault_prefix_successful_retry(sim, &retry_spec);
}

fn run_op_sequence(seed: u64, level: FaultLevel, ops: &[ProptestOp]) {
    let mut sim = DoneLedgerSim::new(seed, level);
    // BTreeSet gives deterministic sorted iteration, which map_batch_get_indices
    // relies on for reproducible index remapping across proptest shrink attempts.
    let mut seen_ovid_indices = BTreeSet::new();

    exercise_fault_prefix(&mut sim, &mut seen_ovid_indices);
    assert_eq!(
        sim.pending_batch_count(),
        0,
        "fault prefix must drain all pending writes"
    );

    for (step_idx, op) in ops.iter().enumerate() {
        let materialized = materialize_op(&mut sim, &mut seen_ovid_indices, op);
        let (event, violations) = sim.step(materialized);
        assert!(
            violations.is_empty(),
            "seed={seed}, level={level:?}, step={step_idx}, op={op:?}: \
             event={event:?}, violations={violations:?}"
        );
    }

    // A single ReleaseAll is sufficient: exec_release_all calls
    // pending_batches.drain() which is total in single-threaded
    // execution — no new writes can arrive during the drain.
    if sim.pending_batch_count() > 0 {
        let (event, violations) = sim.step(DoneLedgerSimOp::ReleaseAll {
            order: CompletionOrder::OldestFirst,
        });
        assert!(
            violations.is_empty(),
            "seed={seed}, level={level:?}: drain event={event:?}, violations={violations:?}"
        );
    }

    let convergence = sim.check_convergence();
    assert!(
        convergence.is_empty(),
        "seed={seed}, level={level:?}: convergence violations={convergence:?}"
    );
}

#[test]
fn done_ledger_sim_sunny_day() {
    let report = DoneLedgerSim::new(0, FaultLevel::SunnyDay).run(SUNNY_DAY_OPS, 0);
    assert!(
        report.violations.is_empty(),
        "SunnyDay violations: {:?}",
        report.violations
    );
    assert!(report.converged, "SunnyDay run should converge");
}

#[test]
fn done_ledger_sim_stormy_sweep() {
    if cfg!(miri) {
        return;
    }

    let outcome = run_seed_sweep(STORMY_SWEEP_SEEDS, |seed| {
        DoneLedgerSim::new(seed, FaultLevel::Stormy).run(STORMY_SWEEP_OPS, 0)
    });
    assert_no_failures("done_ledger_sim_stormy_sweep", &outcome);
    assert_event_coverage(&outcome);
}

#[test]
fn done_ledger_sim_swizzle_clog_sweep() {
    if cfg!(miri) {
        return;
    }

    let outcome = run_seed_sweep(SWIZZLE_SWEEP_SEEDS, |seed| {
        DoneLedgerSim::new(seed, FaultLevel::SunnyDay).run_swizzle_clog(SWIZZLE_BATCHES)
    });
    assert_no_failures("done_ledger_sim_swizzle_clog_sweep", &outcome);

    assert!(
        outcome
            .aggregate_counts
            .get(&DoneLedgerSimEventKind::UpsertPending)
            .copied()
            .unwrap_or(0)
            > 0,
        "swizzle-clog should produce pending writes"
    );
    assert!(
        outcome
            .aggregate_counts
            .get(&DoneLedgerSimEventKind::ReleasedCommitFailed)
            .copied()
            .unwrap_or(0)
            > 0,
        "swizzle-clog should exercise at least one commit failure"
    );
}

#[test]
fn done_ledger_sim_swizzle_clog_stormy_sweep() {
    if cfg!(miri) {
        return;
    }

    let outcome = run_seed_sweep(SWIZZLE_SWEEP_SEEDS, |seed| {
        DoneLedgerSim::new(seed, FaultLevel::Stormy).run_swizzle_clog(SWIZZLE_BATCHES)
    });
    assert_no_failures("done_ledger_sim_swizzle_clog_stormy_sweep", &outcome);
}

#[test]
fn done_ledger_sim_radioactive_smoke() {
    if cfg!(miri) {
        return;
    }

    // Small always-on smoke test for Radioactive fault level.
    // The full sweep below is #[ignore] for CI speed; this exercises
    // the same code path with minimal seeds to catch regressions.
    let outcome = run_seed_sweep(5, |seed| {
        DoneLedgerSim::new(seed, FaultLevel::Radioactive).run(200, 0)
    });
    assert_no_failures("done_ledger_sim_radioactive_smoke", &outcome);
}

#[test]
#[ignore]
fn done_ledger_sim_radioactive() {
    if cfg!(miri) {
        return;
    }

    let outcome = run_seed_sweep(RADIOACTIVE_SWEEP_SEEDS, |seed| {
        DoneLedgerSim::new(seed, FaultLevel::Radioactive).run(RADIOACTIVE_SWEEP_OPS, 0)
    });
    assert_no_failures("done_ledger_sim_radioactive", &outcome);
}

proptest! {
    #![proptest_config({
        let mut cfg = miri_proptest_config();
        if !cfg!(miri) {
            cfg.cases = 128;
        }
        cfg.max_shrink_iters = 10_000;
        cfg
    })]

    // Shrinking note: the materialization layer (ProptestOp -> DoneLedgerSimOp)
    // means shrunk sequences produce different RunId values than the original
    // failure. Seed-based replay (seed=N in assertion messages) is the primary
    // debugging mechanism, not proptest's minimal counterexamples.
    #[test]
    fn prop_done_ledger_state_machine(
        seed in any::<u64>(),
        level in arb_fault_level(),
        ops in vec(arb_proptest_op(), 100..150),
    ) {
        run_op_sequence(seed, level, &ops);
    }
}
