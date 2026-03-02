//! Deterministic Git simulation harness.
//!
//! Purpose:
//! - Provide a replayable, schedule-deterministic harness for Git scan stages.
//! - Exercise stage invariants (ordering, gating, and resource bounds) without
//!   relying on OS time, filesystem races, or real repository layouts.
//!
//! Design principles:
//! - Keep production Git scanning untouched; introduce narrow seams only.
//! - Prefer data-driven scenarios and deterministic scheduling via `SimExecutor`.
//! - Emit bounded trace events that make failures reproducible and debuggable.
//!
//! Module layout:
//! - `scenario`: schema for Git simulation inputs and run configuration.
//! - `generator`: synthetic scenario generator for bounded random runs.
//! - `runner`: deterministic runner and failure taxonomy.
//! - `trace`: bounded trace ring and Git-specific events.
//! - `artifact`: reproducible failure artifact schema.
//! - `fault`: deterministic fault plan schema for Git resources.
//! - `persist`: deterministic persistence store for simulation.
//! - `replay`: load + replay artifacts.
//! - `minimize`: deterministic shrink passes for reproduction minimization.

pub mod artifact;
pub mod commit_graph;
pub mod convert;
pub mod error;
pub mod fault;
pub mod generator;
pub mod minimize;
pub mod pack_bytes;
pub mod pack_io;
pub mod persist;
pub mod replay;
pub mod runner;
pub mod scenario;
pub mod start_set;
pub mod trace;
pub mod tree_source;

pub use artifact::{GitReproArtifact, GitTraceDump};
pub use commit_graph::SimCommitGraph;
pub use convert::{to_object_format, to_oid_bytes};
pub use error::SimGitError;
pub use fault::{
    GitCorruption, GitFaultInjector, GitFaultPlan, GitIoFault, GitReadFault, GitResourceId,
};
pub use generator::{generate_scenario, GitScenarioGenConfig};
pub use minimize::{minimize_git_case, MinimizerCfg};
pub use pack_bytes::SimPackBytes;
pub use pack_io::SimPackIo;
pub use persist::{PersistPhase, SimPersistOp, SimPersistStore};
pub use replay::replay_artifact;
pub use runner::{FailureKind, FailureReport, GitSimRunner, RunOutcome, RunReport};
pub use scenario::{
    GitArtifactBundle, GitBlobSpec, GitCommitSpec, GitObjectFormat, GitOid, GitPackBytes,
    GitRefSpec, GitRepoModel, GitRunConfig, GitScenario, GitTreeEntryKind, GitTreeEntrySpec,
    GitTreeSpec,
};
pub use start_set::SimStartSet;
pub use trace::{GitTraceEvent, GitTraceRing};
pub use tree_source::SimTreeSource;
