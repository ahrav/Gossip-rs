//! Reusable control-plane surfaces for request normalization and planning.
//!
//! This crate owns the filesystem submission contract that later
//! orchestration steps consume for shard planning, payload encoding, and
//! run setup.

pub mod planner;
pub mod request;

pub use planner::{
    FilesystemInitialShardPlan, InitialShardGeometry, plan_filesystem_initial_shards,
};
pub use request::{
    FilesystemPathKind, FilesystemRequest, FilesystemRequestError, FilesystemSourceMode,
    NormalizedFilesystemRequest,
};
