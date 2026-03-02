#![cfg(any(test, feature = "sim-harness"))]
//! Scanner simulation coverage for in-flight budget invariance under size-cap gating.
//!
//! Invariants:
//! - Discovery must respect `max_in_flight_objects` even when some files are
//!   skipped at open time due to `max_file_size`.
//! - Permits are released on all terminal paths, so the run completes without
//!   hangs or budget leaks under different schedule seeds.

use std::collections::BTreeMap;

use crate::scanner_rs::archive::ArchiveConfig;
use crate::scanner_rs::sim::{FaultPlan, SimNodeSpec};
use crate::scanner_rs::sim_scanner::{
    RunConfig, RunOutcome, ScannerSimRunner, ScenarioGenConfig, SecretRepr,
    build_engine_from_suite, generate_scenario,
};

#[test]
fn budget_invariance_with_size_cap_gating() {
    let gen_cfg = ScenarioGenConfig {
        rule_count: 1,
        file_count: 16,
        secrets_per_file: 1,
        token_len: 12,
        min_noise_len: 4,
        max_noise_len: 8,
        representations: vec![SecretRepr::Raw],
        ..ScenarioGenConfig::default()
    };

    let mut scenario = generate_scenario(4242, &gen_cfg).expect("generate scenario");
    // Capture the largest baseline file so we can set a cap that admits some
    // files while forcing others to grow past it at open time.
    let mut max_base_len = 0usize;
    for node in &scenario.fs.nodes {
        if let SimNodeSpec::File { contents, .. } = node {
            max_base_len = max_base_len.max(contents.len());
        }
    }

    let max_file_size = (max_base_len as u64).saturating_add(8);
    let extend_by = max_file_size as usize + 16;
    for (idx, node) in scenario.fs.nodes.iter_mut().enumerate() {
        if let SimNodeSpec::File {
            contents,
            discovery_len_hint,
            ..
        } = node
        {
            // Force discovery to admit the file even if it grows later.
            *discovery_len_hint = Some(4);
            // Every other file grows past the open-time cap to exercise skip paths.
            if idx % 2 == 0 {
                contents.extend(std::iter::repeat_n(b'x', extend_by));
            }
        }
    }

    let mut run_cfg = RunConfig {
        workers: 2,
        chunk_size: 64,
        overlap: 64,
        // Tight in-flight cap to stress permit reuse when files are skipped.
        max_in_flight_objects: 1,
        buffer_pool_cap: 2,
        max_file_size,
        max_steps: 0,
        max_transform_depth: 2,
        scan_utf16_variants: true,
        archive: ArchiveConfig::default(),
        // Two schedules to catch budget leaks or ordering dependence.
        stability_runs: 2,
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

    let runner = ScannerSimRunner::new(run_cfg, 0xC0FF_EE03);
    let fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    match runner.run(&scenario, &engine, &fault_plan) {
        RunOutcome::Ok { findings } => {
            assert!(
                !findings.is_empty(),
                "expected findings from files below the size cap"
            );
        }
        RunOutcome::Failed(fail) => {
            panic!("budget invariance sim failed: {fail:?}");
        }
    }
}
