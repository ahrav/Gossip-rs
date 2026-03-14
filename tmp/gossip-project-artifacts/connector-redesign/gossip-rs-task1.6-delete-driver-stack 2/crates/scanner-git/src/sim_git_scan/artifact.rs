//! Reproducible artifact schema for Git simulation failures.
//!
//! Artifacts are serialized to disk to allow deterministic replay and
//! minimization. The schema is versioned for forward-compatible evolution.
//! Determinism-critical inputs (scenario, seeds, fault plan, and run config)
//! are stored alongside diagnostic metadata such as build version and trace
//! snapshots.
//!
//! # Versioning
//! - `schema_version` governs this artifact wrapper.
//! - `scenario.schema_version` governs the embedded scenario payload.
//! - Callers should validate both before replaying across versions.
//!
//! # Replay Contract
//! For deterministic replay, callers should treat `scenario_seed`,
//! `schedule_seed`, `run_config`, `scenario`, and `fault_plan` as immutable
//! once captured. Fields such as `scanner_pkg_version`, `git_commit`, and
//! `target` are diagnostic metadata only.

use serde::{Deserialize, Serialize};

use super::fault::GitFaultPlan;
use super::runner::FailureReport;
use super::scenario::{GitRunConfig, GitScenario};
use super::trace::GitTraceEvent;

/// Trace data captured when a simulation run fails.
///
/// The ring snapshot is always present and cheap to store. The optional full
/// trace is larger but can provide exact event-by-event reconstruction during
/// debugging.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitTraceDump {
    /// Ring-buffer snapshot of recent events.
    ///
    /// Events are ordered from oldest to newest.
    pub ring: Vec<GitTraceEvent>,
    /// Optional full trace for exact replay.
    pub full: Option<Vec<GitTraceEvent>>,
}

/// Self-contained reproduction artifact for a failed Git simulation run.
///
/// # Guarantees
/// - Contains all determinism-critical inputs required to re-run the scenario.
/// - Separates replay inputs from diagnostic-only metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitReproArtifact {
    /// Artifact schema version (independent of the scenario schema).
    pub schema_version: u32,

    /// Version stamp for diagnostics (not determinism-critical).
    pub scanner_pkg_version: String,
    /// Optional git commit for the scanner build (diagnostics only).
    pub git_commit: Option<String>,
    /// Human-readable target label (for example repo name or path).
    ///
    /// This is informational only and must not affect replay.
    pub target: String,

    /// Scenario generation seed used to materialize repository state.
    pub scenario_seed: u64,
    /// Task scheduler seed used to drive execution ordering.
    pub schedule_seed: u64,

    /// Test case data.
    ///
    /// Together with the seeds above, these fields define the replay input.
    pub run_config: GitRunConfig,
    pub scenario: GitScenario,
    pub fault_plan: GitFaultPlan,

    /// Failure data.
    pub failure: FailureReport,
    /// Trace snapshots captured at failure time.
    pub trace: GitTraceDump,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_git_scan::scenario::{GitRepoModel, GIT_SCENARIO_SCHEMA_VERSION};

    #[test]
    fn artifact_round_trip() {
        let artifact = GitReproArtifact {
            schema_version: 1,
            scanner_pkg_version: "0.1.0".to_string(),
            git_commit: None,
            target: "test".to_string(),
            scenario_seed: 42,
            schedule_seed: 7,
            run_config: GitRunConfig::default(),
            scenario: GitScenario {
                schema_version: GIT_SCENARIO_SCHEMA_VERSION,
                repo: GitRepoModel::default(),
                artifacts: None,
            },
            fault_plan: GitFaultPlan::default(),
            failure: FailureReport {
                kind: crate::sim_git_scan::runner::FailureKind::OracleMismatch,
                message: "x".to_string(),
                step: 0,
            },
            trace: GitTraceDump {
                ring: Vec::new(),
                full: None,
            },
        };

        let json = serde_json::to_string(&artifact).expect("serialize artifact");
        let decoded: GitReproArtifact = serde_json::from_str(&json).expect("deserialize artifact");
        assert_eq!(decoded.schema_version, 1);
        assert_eq!(decoded.scenario_seed, 42);
    }
}
