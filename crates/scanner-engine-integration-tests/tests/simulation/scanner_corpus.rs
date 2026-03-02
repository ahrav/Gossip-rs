#![cfg(any(test, feature = "sim-harness"))]
//! Replay minimized scanner corpus cases and assert regressions stay fixed.

use std::fs;
use std::path::{Path, PathBuf};

use crate::scanner_rs::sim::ReproArtifact;
use crate::scanner_rs::sim_scanner::{RunOutcome, ScannerSimRunner, build_engine_from_suite};

fn corpus_dir() -> PathBuf {
    PathBuf::from("tests").join("corpus").join("scanner")
}

fn list_cases(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut cases: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|s| s.to_str())
                .map(|name| name.ends_with(".case.json"))
                .unwrap_or(false)
        })
        .collect();
    cases.sort();
    cases
}

#[test]
fn replay_scanner_corpus_cases() {
    let dir = corpus_dir();
    let cases = list_cases(&dir);
    if cases.is_empty() {
        return;
    }

    for path in cases {
        let bytes = fs::read(&path).expect("read corpus case");
        let artifact: ReproArtifact = serde_json::from_slice(&bytes).expect("parse corpus case");
        let engine = build_engine_from_suite(&artifact.scenario.rule_suite, &artifact.run_config)
            .expect("build engine from suite");
        let mut run_config = artifact.run_config.clone();
        let required = engine.required_overlap() as u32;
        if run_config.overlap < required {
            run_config.overlap = required;
        }
        if run_config.chunk_size < run_config.overlap {
            run_config.chunk_size = run_config.overlap;
        }
        let runner = ScannerSimRunner::new(run_config, artifact.schedule_seed);
        match runner.run(&artifact.scenario, &engine, &artifact.fault_plan) {
            RunOutcome::Ok { .. } => {}
            RunOutcome::Failed(fail) => {
                panic!("scanner corpus replay failed for {:?}: {:?}", path, fail);
            }
        }
    }
}
