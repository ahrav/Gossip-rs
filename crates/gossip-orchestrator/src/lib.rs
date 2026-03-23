//! Reusable control-plane surfaces for request normalization and planning.
//!
//! This crate owns the filesystem submission contract that later
//! orchestration steps consume for shard planning, payload encoding, and
//! run setup.
//!
//! # Stages
//!
//! 1. **Request normalization** ([`request`]): canonicalizes raw filesystem
//!    paths and validates them against the requested source mode (single file
//!    vs. directory root). Produces [`NormalizedFilesystemRequest`].
//! 2. **Initial shard geometry planning** ([`planner`]): maps normalized
//!    requests to deterministic startup shard geometries. The current policy
//!    emits one full-range shard per request; later coordination split flows
//!    handle fan-out after the worker makes progress.
//!
//! Both stages are stateless and synchronous.

pub mod planner;
pub mod request;

pub use planner::{
    FilesystemInitialShardPlan, InitialShardGeometry, plan_filesystem_initial_shards,
};
pub use request::{
    FilesystemPathKind, FilesystemRequest, FilesystemRequestError, FilesystemSourceMode,
    NormalizedFilesystemRequest,
};
