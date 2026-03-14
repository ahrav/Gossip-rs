#![cfg(any(test, feature = "sim-harness"))]
//! Bounded random archive simulations to exercise archive scanning paths.

use std::collections::BTreeMap;

use crate::scanner_rs::archive::ArchiveConfig;
use crate::scanner_rs::sim::FaultPlan;
use crate::scanner_rs::sim_scanner::{
    RunConfig, RunOutcome, ScannerSimRunner, ScenarioGenConfig, SecretRepr,
    build_engine_from_suite, generate_scenario,
};

#[test]
fn bounded_random_archive_sims() {
    let archive_cfg = ArchiveConfig {
        enabled: true,
        ..ArchiveConfig::default()
    };

    for seed in 0..10u64 {
        let gen_cfg = ScenarioGenConfig {
            rule_count: 2,
            file_count: 0,
            archive_count: 2,
            archive_entries: 2,
            secrets_per_file: 1,
            token_len: 10,
            min_noise_len: 4,
            max_noise_len: 16,
            representations: vec![SecretRepr::Raw],
            archive: archive_cfg.clone(),
            ..ScenarioGenConfig::default()
        };

        let scenario = generate_scenario(seed, &gen_cfg).expect("generate scenario");
        let mut run_cfg = RunConfig {
            workers: 2,
            chunk_size: 64,
            overlap: 64,
            max_in_flight_objects: 8,
            buffer_pool_cap: 8,
            max_file_size: u64::MAX,
            max_steps: 0,
            max_transform_depth: 3,
            scan_utf16_variants: true,
            archive: archive_cfg.clone(),
            stability_runs: 1,
            archive_deadline_countdown: None,
        };

        let engine = build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine");
        let required = engine.required_overlap() as u32;
        if run_cfg.overlap < required {
            run_cfg.overlap = required;
        }
        if run_cfg.chunk_size < run_cfg.overlap {
            run_cfg.chunk_size = run_cfg.overlap;
        }

        let runner = ScannerSimRunner::new(run_cfg, seed.wrapping_add(0xC0FF_EE20));
        let fault_plan = FaultPlan {
            per_file: BTreeMap::new(),
        };

        match runner.run(&scenario, &engine, &fault_plan) {
            RunOutcome::Ok { .. } => {}
            RunOutcome::Failed(fail) => {
                panic!("archive random sim failed (seed {seed}): {fail:?}");
            }
        }
    }
}
