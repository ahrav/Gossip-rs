//! Scenario and runner types for the scanner simulation harness.
//!
//! This module hosts the scenario schema and will eventually include the
//! deterministic runner and replay logic. The schema is versioned to support
//! forward-compatible artifact evolution.

pub mod generator;
pub mod replay;
pub mod runner;
pub mod scenario;
pub mod vpath_table;

pub use crate::sim::fs::{SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
pub use generator::{
    build_engine_from_suite, generate_scenario, materialize_rules, synthetic_transforms,
    synthetic_tuning, ScenarioGenConfig,
};
pub use replay::replay_artifact;
pub use runner::{FailureKind, FailureReport, RunOutcome, ScannerSimRunner};
pub use scenario::{
    ArchiveCorruptionSpec, ArchiveEntrySpec, ArchiveFileSpec, ArchiveKindSpec,
    EntryCompressionSpec, EntryKindSpec, ExpectedDisposition, ExpectedSecret, RuleSuiteSpec,
    RunConfig, Scenario, SecretRepr, SpanU32, SyntheticRuleSpec,
};
pub use vpath_table::VirtualPathTable;
