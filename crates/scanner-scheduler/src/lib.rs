//! Scanner scheduler extraction crate.
//!
//! This crate owns the parallel execution runtime extracted from scanner-rs:
//! executor, local filesystem scanning, archive expansion, and scheduling
//! support primitives.
//!
//! Step 2a preserves behavior while introducing crate-local compatibility
//! modules (`api`, `engine`, `unified::events`, `store`) so scheduler code
//! compiles independently of scanner-rs monolith modules. Step 2b will replace
//! the compatibility event surface with split core/git event contracts.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::all)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]

pub mod api;
pub mod archive;
pub mod content_policy;
pub mod engine;
pub mod finding_output;
pub mod git_scan;
pub mod perf_stats;
pub mod pipeline;
pub mod pool;
pub mod runtime;
pub mod scheduler;
pub mod scratch_memory;
pub mod store;
#[cfg(test)]
pub mod test_utils;
pub mod unified;

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
