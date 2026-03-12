use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use gossip_contracts::{
    identity::{FenceEpoch, LogicalTime, RunId, ShardId},
    persistence::{
        DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
        DoneLedgerStatus,
    },
    test_util::{miri_proptest_config, ovid, policy, tenant},
};
use proptest::{collection::vec, prelude::*};

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
    elapsed: Duration,
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
                        let report = runner(seed);
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

                    (local_failures, local_counts)
                })
            })
            .collect();

        for handle in handles {
            let (local_failures, local_counts) = handle.join().unwrap_or_else(|panic_val| {
                let msg = panic_val
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| panic_val.downcast_ref::<&str>().copied())
                    .unwrap_or("(non-string panic)");
                panic!("simulation thread panicked: {msg}");
            });
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

fn arb_done_ledger_record() -> impl Strategy<Value = DoneLedgerRecord> {
    (
        0u8..=7,
        arb_done_ledger_status(),
        0u64..=10_000,
        1u64..=1_000,
        1u64..=200,
    )
        .prop_map(|(seed, status, bytes_scanned, started_at, duration)| {
            let finished_at = started_at + duration;
            let findings_count = match status {
                DoneLedgerStatus::ScannedClean => 0,
                DoneLedgerStatus::ScannedWithFindings => ((bytes_scanned % 5) + 1) as u32,
                _ => (bytes_scanned % 4) as u32,
            };
            let error_code = if status.is_failure() || status.is_skipped() {
                Some(DoneLedgerErrorCode::try_new("PROP_ERROR").unwrap())
            } else {
                None
            };

            DoneLedgerRecord::try_new(
                DoneLedgerKey::new(tenant(0x11), policy(0x22), ovid(seed)),
                status,
                bytes_scanned,
                findings_count,
                DoneLedgerProvenance::new(
                    RunId::from_raw((seed as u64) + started_at + 1),
                    ShardId::from_raw(1),
                    FenceEpoch::from_raw(1),
                    LogicalTime::from_raw(started_at),
                    LogicalTime::from_raw(finished_at),
                ),
                error_code,
            )
            .unwrap()
        })
}

fn arb_done_ledger_sim_op() -> impl Strategy<Value = DoneLedgerSimOp> {
    prop_oneof![
        6 => vec(arb_done_ledger_record(), 1..=4)
            .prop_map(|records| DoneLedgerSimOp::BatchUpsert { records }),
        3 => vec(0usize..16, 1..=6)
            .prop_map(|ovid_indices| DoneLedgerSimOp::BatchGet { ovid_indices }),
        1 => Just(DoneLedgerSimOp::ReleaseOldest),
        1 => Just(DoneLedgerSimOp::ReleaseNewest),
        1 => arb_completion_order()
            .prop_map(|order| DoneLedgerSimOp::ReleaseAll { order }),
        1 => (1u64..=32)
            .prop_map(|raw| DoneLedgerSimOp::ReleaseSpecific {
                op_id: PendingWriteId::from_raw(raw),
            }),
        1 => (1usize..=2)
            .prop_map(|count| DoneLedgerSimOp::InjectSubmitFailure { count }),
        1 => (1usize..=2)
            .prop_map(|count| DoneLedgerSimOp::InjectCommitFailure { count }),
        1 => (1usize..=3)
            .prop_map(|count| DoneLedgerSimOp::InjectDelay { count }),
    ]
}

fn run_op_sequence(seed: u64, level: FaultLevel, ops: &[DoneLedgerSimOp]) {
    let mut sim = DoneLedgerSim::new(seed, level);

    for (step_idx, op) in ops.iter().enumerate() {
        let (event, violations) = sim.step(op.clone());
        assert!(
            violations.is_empty(),
            "seed={seed}, level={level:?}, step={step_idx}, op={op:?}: \
             event={event:?}, violations={violations:?}"
        );
    }

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
    assert!(
        outcome.elapsed < Duration::from_secs(10),
        "stormy sweep took {:?}, expected <10s",
        outcome.elapsed
    );
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
            cfg.cases = 256;
        }
        cfg.max_shrink_iters = 1_000;
        cfg
    })]

    #[test]
    fn prop_done_ledger_state_machine(
        seed in any::<u64>(),
        level in arb_fault_level(),
        ops in vec(arb_done_ledger_sim_op(), 5..50),
    ) {
        run_op_sequence(seed, level, &ops);
    }
}
