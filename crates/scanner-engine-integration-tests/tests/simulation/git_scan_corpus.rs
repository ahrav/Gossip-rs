//! Replay minimized Git simulation corpus cases and assert regressions stay fixed.
//!
//! Each `.case.json` file under `tests/corpus/git_scan` is replayed with the
//! recorded run configuration and schedule seed. If the case includes a trace,
//! we hash the trace deterministically and compare against the run outcome's
//! `trace_hash`. Failures are written back to `tests/failures` to preserve a
//! repro artifact for debugging.

use std::fs;
use std::path::{Path, PathBuf};

use blake3::Hasher;

use crate::scanner_rs::sim_git_scan::{
    FailureKind, FailureReport, GitReproArtifact, GitSimRunner, GitTraceDump, GitTraceEvent,
    RunOutcome,
};

fn corpus_dir() -> PathBuf {
    PathBuf::from("tests").join("corpus").join("git_scan")
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
fn replay_git_scan_corpus_cases() {
    let dir = corpus_dir();
    let cases = list_cases(&dir);
    if cases.is_empty() {
        // Keep the test a no-op when the optional corpus is not present.
        return;
    }

    let regen = std::env::var("GIT_SIM_REGEN_CORPUS").is_ok();
    let mut validated = 0u32;
    let mut expected_failures = 0u32;

    for path in cases {
        let bytes = fs::read(&path).expect("read corpus case");
        let artifact: GitReproArtifact = serde_json::from_slice(&bytes).expect("parse corpus case");
        let runner = GitSimRunner::new(artifact.run_config.clone(), artifact.schedule_seed);
        match runner.run(&artifact.scenario, &artifact.fault_plan) {
            RunOutcome::Ok { report } => {
                if regen {
                    let mut updated = artifact.clone();
                    updated.trace = GitTraceDump {
                        ring: report.trace_dump.clone(),
                        full: None,
                    };
                    let json = serde_json::to_string_pretty(&updated).expect("serialize");
                    fs::write(&path, &json).expect("write corpus case");
                    eprintln!("regenerated trace for {:?}", path);
                    continue;
                }
                // Empty-trace cases are expected to fail. If they succeed,
                // a regression has silently turned a failure case into a
                // passing one.
                if expected_trace_hash(&artifact).is_none() {
                    panic!(
                        "git corpus replay unexpectedly succeeded for {:?} \
                         (empty-trace case should fail)",
                        path,
                    );
                }
                if let Some(expected) = expected_trace_hash(&artifact)
                    && expected != report.trace_hash
                {
                    let failure = FailureReport {
                        kind: FailureKind::OracleMismatch,
                        message: format!("trace hash mismatch for {path:?}"),
                        step: report.steps,
                    };
                    write_failure_artifact(&path, &artifact, failure);
                    panic!("git corpus replay trace mismatch for {:?}", path);
                }
                validated += 1;
            }
            RunOutcome::Failed(fail) => {
                if regen {
                    eprintln!("skipped {:?} (run failed: {})", path, fail.message);
                    continue;
                }
                // Empty-trace cases are failure-reproduction artifacts from
                // the random fuzzer. Verify the failure matches the recorded
                // kind so regressions that change the failure mode are caught.
                if expected_trace_hash(&artifact).is_none() {
                    if !same_failure_kind(&artifact.failure, &fail) {
                        write_failure_artifact(&path, &artifact, fail.clone());
                        panic!(
                            "git corpus replay failure kind mismatch for {:?}: \
                             expected {:?}, got {:?}",
                            path, artifact.failure.kind, fail.kind,
                        );
                    }
                    expected_failures += 1;
                    continue;
                }
                write_failure_artifact(&path, &artifact, fail.clone());
                panic!("git corpus replay failed for {:?}: {:?}", path, fail);
            }
        }
    }

    assert!(
        validated + expected_failures > 0 || regen,
        "no corpus cases were validated (validated={validated}, expected_failures={expected_failures})",
    );
}

/// Compares two failure reports by failure kind.
///
/// The message field is not compared because minor wording changes across
/// runner versions should not break corpus replay. The step counter is
/// also excluded because schedule-sensitive runs may diverge in step count
/// while producing the same logical failure.
fn same_failure_kind(expected: &FailureReport, actual: &FailureReport) -> bool {
    match (&expected.kind, &actual.kind) {
        (FailureKind::Panic, FailureKind::Panic)
        | (FailureKind::Hang, FailureKind::Hang)
        | (FailureKind::OracleMismatch, FailureKind::OracleMismatch)
        | (FailureKind::StabilityMismatch, FailureKind::StabilityMismatch) => true,
        (
            FailureKind::InvariantViolation { code: a },
            FailureKind::InvariantViolation { code: b },
        ) => a == b,
        _ => false,
    }
}

fn expected_trace_hash(artifact: &GitReproArtifact) -> Option<[u8; 32]> {
    // Prefer a full trace when available; otherwise fall back to the ring buffer.
    let events = if let Some(full) = artifact.trace.full.as_ref() {
        if !full.is_empty() {
            full
        } else {
            &artifact.trace.ring
        }
    } else {
        &artifact.trace.ring
    };

    if events.is_empty() {
        return None;
    }
    Some(hash_trace(events))
}

fn hash_trace(events: &[GitTraceEvent]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    // Stable encoding of trace events. Keep tags and field order in sync with
    // GitTraceEvent changes to avoid silent hash mismatches.
    for ev in events {
        match ev {
            GitTraceEvent::StageEnter { stage_id } => {
                hasher.update(&[1]);
                hasher.update(&stage_id.to_le_bytes());
            }
            GitTraceEvent::StageExit { stage_id, items } => {
                hasher.update(&[2]);
                hasher.update(&stage_id.to_le_bytes());
                hasher.update(&items.to_le_bytes());
            }
            GitTraceEvent::Decision { code } => {
                hasher.update(&[3]);
                hasher.update(&code.to_le_bytes());
            }
            GitTraceEvent::FaultInjected {
                resource_id,
                op,
                kind,
            } => {
                hasher.update(&[4]);
                hasher.update(&resource_id.to_le_bytes());
                hasher.update(&op.to_le_bytes());
                hasher.update(&kind.to_le_bytes());
            }
        }
    }
    *hasher.finalize().as_bytes()
}

fn write_failure_artifact(path: &Path, artifact: &GitReproArtifact, failure: FailureReport) {
    let out_dir = "tests/failures";
    if let Err(err) = fs::create_dir_all(out_dir) {
        eprintln!("git sim: failed to create {out_dir}: {err}");
        return;
    }

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("git_scan_case");
    let out_path = format!("{out_dir}/git_scan_{stem}.case.json");

    let out_artifact = GitReproArtifact {
        failure,
        trace: GitTraceDump {
            // Drop large traces in failure artifacts; the original case already has them.
            ring: Vec::new(),
            full: None,
        },
        ..artifact.clone()
    };

    match serde_json::to_string_pretty(&out_artifact) {
        Ok(json) => {
            if let Err(err) = fs::write(&out_path, json) {
                eprintln!("git sim: failed to write {out_path}: {err}");
            }
        }
        Err(err) => {
            eprintln!("git sim: failed to serialize artifact: {err}");
        }
    }
}
