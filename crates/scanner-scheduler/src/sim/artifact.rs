//! Reproducible artifact schema for simulation failures.
//!
//! Artifacts are serialized to disk to allow deterministic replay and
//! minimization. The schema is versioned for forward-compatible evolution.

use serde::{Deserialize, Serialize};

use crate::sim::fault::FaultPlan;
use crate::sim::trace::TraceEvent;
use crate::sim_scanner::runner::FailureReport;
use crate::sim_scanner::scenario::{RunConfig, Scenario};

/// Trace data captured for a failure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceDump {
    /// Ring-buffer snapshot of recent events.
    pub ring: Vec<TraceEvent>,
    /// Optional full trace for exact replay.
    pub full: Option<Vec<TraceEvent>>,
}

/// Self-contained reproduction artifact for a failed run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReproArtifact {
    pub schema_version: u32,

    /// Version stamp for diagnostics (not determinism).
    pub scanner_pkg_version: String,
    pub git_commit: Option<String>,
    pub target: String,

    /// Determinism keys.
    pub scenario_seed: u64,
    pub schedule_seed: u64,

    /// Test case data.
    pub run_config: RunConfig,
    pub scenario: Scenario,
    pub fault_plan: FaultPlan,

    /// Failure data.
    pub failure: FailureReport,
    pub trace: TraceDump,
}
