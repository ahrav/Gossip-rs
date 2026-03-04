//! Scanner scheduler extraction crate.
//!
//! This crate owns the parallel execution runtime extracted from scanner-rs:
//! executor, local filesystem scanning, archive expansion, and scheduling
//! support primitives.
//!
//! The scheduler event surface is split into git-free core events (`events`)
//! and source tagging (`source_kind`) so downstream sinks can consume core
//! progress/finding/summary output without git-type dependencies.
//! The local [`api`] module is a compatibility shim that re-exports
//! `scanner-engine` API types so migrated scheduler modules can keep their
//! historical `crate::api::*` imports.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::all)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]

/// Provides compatibility re-exports for scanner engine public API types.
pub mod api;
/// Implements archive scanning: detection, config, budgets, and format handlers.
pub mod archive;
/// Re-exports scanner-engine content policy helpers for scheduler call sites.
pub mod content_policy;
/// Provides compatibility re-exports for scanner engine runtime types.
pub mod engine;
/// Defines structured event types and sinks for scanner scheduler output.
pub mod events;
/// Defines finding output contract aliases for scheduler extraction.
pub mod finding_output;
/// Provides git-scan compatibility surface (path-policy helpers).
pub mod git_scan;
/// Provides shared JSON write helpers for event encoding paths.
pub mod json_write;
/// Provides small arithmetic helpers for scan-time performance counters.
pub mod perf_stats;
/// Defines configuration and statistics types for file-scanning pipelines.
pub mod pipeline;
/// Re-exports scanner-engine pool types used by extracted runtime helpers.
pub mod pool;
/// Provides runtime utilities: file tables, buffer pools, and chunk readers.
pub mod runtime;
/// Implements the work-stealing scheduler for parallel secret scanning.
pub mod scheduler;
/// Re-exports scanner-engine fixed-capacity scratch helpers.
pub mod scratch_memory;
// Keep simulation surfaces behind feature gates: they are for harness/testing
// compatibility and are not part of the default runtime build.
/// Provides deterministic simulation primitives (RNG, clock, trace buffer).
#[cfg(feature = "sim-harness")]
pub mod sim;
/// Implements deterministic archive materializers for the simulation harness.
#[cfg(feature = "sim-harness")]
pub mod sim_archive;
/// Provides scenario and runner types for the scanner simulation harness.
#[cfg(feature = "sim-harness")]
pub mod sim_scanner;
/// Implements a scheduler-only simulation harness for task-program execution.
#[cfg(feature = "scheduler-sim")]
pub mod sim_scheduler;
/// Defines the common source-kind marker shared across scheduler event types.
pub mod source_kind;
/// Defines filesystem persistence producer contracts for finding output.
pub mod store;
#[cfg(test)]
pub mod test_utils;
#[cfg(feature = "sim-harness")]
pub mod demo {
    pub use scanner_engine::demo_tuning;
}

#[cfg(feature = "b64-stats")]
pub use scanner_engine::Base64DecodeStats;

pub use api::{FileId, Finding, FindingRec, RuleSpec, TransformConfig, Tuning, ValidatorKind};
pub use engine::{Engine, NormHash, ScanScratch};
pub use finding_output::FindingOutput;
pub use scheduler::*;
pub use store::{
    FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, InMemoryStoreProducer,
    NullStoreProducer, OwnedFsFindingBatch, StoreProducer,
};
