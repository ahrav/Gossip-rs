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
//! 3. **Shard payload encoding** ([`payload`]): defines the typed filesystem
//!    metadata bytes carried through shard registration and lease hydration.
//! 4. **Run setup** ([`setup`]): lowers normalized requests, planned
//!    geometry, and typed payloads into a validated initial manifest, then
//!    creates and registers the run through the coordination lifecycle.
//!
//! All stages are stateless and synchronous.

pub mod payload;
pub mod planner;
pub mod request;
pub mod setup;

#[cfg(test)]
mod test_support;

pub use payload::{
    FilesystemShardPayload, FilesystemShardPayloadDecodeError, FilesystemShardPayloadEncodeError,
};
pub use planner::{
    FilesystemInitialShardPlan, InitialShardGeometry, plan_filesystem_initial_shards,
};
pub use request::{
    FilesystemPathKind, FilesystemRequest, FilesystemRequestError, FilesystemSourceMode,
    NormalizedFilesystemRequest,
};
pub use setup::{
    FilesystemRunSetupError, FilesystemRunSetupInput, FilesystemRunSetupResult,
    setup_filesystem_run,
};
