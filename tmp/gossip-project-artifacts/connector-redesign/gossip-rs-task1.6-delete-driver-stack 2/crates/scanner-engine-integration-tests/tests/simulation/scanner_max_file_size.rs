#![cfg(any(test, feature = "sim-harness"))]
//! Scanner simulation coverage for open-time max file size enforcement.

use std::collections::BTreeMap;

use crate::scanner_rs::archive::ArchiveConfig;
use crate::scanner_rs::sim::FaultPlan;
use crate::scanner_rs::sim::SimNodeSpec;
use crate::scanner_rs::sim_scanner::{
    RunConfig, RunOutcome, ScannerSimRunner, ScenarioGenConfig, SecretRepr,
    build_engine_from_suite, generate_scenario,
};

#[test]
fn open_time_size_cap_skips_growth_after_discovery() {
    let gen_cfg = ScenarioGenConfig {
        rule_count: 1,
        file_count: 1,
        secrets_per_file: 1,
        token_len: 12,
        min_noise_len: 4,
        max_noise_len: 8,
        representations: vec![SecretRepr::Raw],
        ..ScenarioGenConfig::default()
    };

    let mut scenario = generate_scenario(777, &gen_cfg).expect("generate scenario");
    for node in &mut scenario.fs.nodes {
        if let SimNodeSpec::File {
            contents,
            discovery_len_hint,
            ..
        } = node
        {
            *discovery_len_hint = Some(4);
            contents.extend(std::iter::repeat_n(b'x', 128));
            break;
        }
    }

    let mut run_cfg = RunConfig {
        workers: 1,
        chunk_size: 64,
        overlap: 64,
        max_in_flight_objects: 4,
        buffer_pool_cap: 4,
        max_file_size: 32,
        max_steps: 0,
        max_transform_depth: 2,
        scan_utf16_variants: true,
        archive: ArchiveConfig::default(),
        stability_runs: 1,
        archive_deadline_countdown: None,
    };

    let engine =
        build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine from suite");
    let required = engine.required_overlap() as u32;
    if run_cfg.overlap < required {
        run_cfg.overlap = required;
    }
    if run_cfg.chunk_size < run_cfg.overlap {
        run_cfg.chunk_size = run_cfg.overlap;
    }

    let runner = ScannerSimRunner::new(run_cfg, 0xC0FF_EE02);
    let fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    let first = runner.run(&scenario, &engine, &fault_plan);
    let second = runner.run(&scenario, &engine, &fault_plan);

    match (first, second) {
        (RunOutcome::Ok { findings: a }, RunOutcome::Ok { findings: b }) => {
            assert_eq!(a, b);
            assert!(
                a.is_empty(),
                "expected size cap to skip scanning, got {a:?}"
            );
        }
        (RunOutcome::Failed(fail), _) | (_, RunOutcome::Failed(fail)) => {
            panic!("size-cap sim failed: {fail:?}");
        }
    }
}
