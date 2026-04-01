//! Reusable control-plane surfaces for request normalization and planning.
//!
//! This crate owns the filesystem and Git submission contracts that later
//! orchestration steps consume for shard planning, payload encoding, and
//! run setup.
//!
//! # Stages
//!
//! 1. **Request normalization**:
//!    - [`request`] canonicalizes raw filesystem paths and validates them
//!      against the requested source mode (single file vs. directory root).
//!      Produces [`NormalizedFilesystemRequest`].
//!    - [`git_request`] canonicalizes raw Git repo requests, validates
//!      repository identity, and preserves request-side selection intent for
//!      later Git control-plane stages.
//! 2. **Initial shard geometry planning** ([`planner`]): maps normalized
//!    requests to deterministic startup shard geometries. The current policy
//!    emits one full-range shard per request; later coordination split flows
//!    handle fan-out after the worker makes progress.
//!    - [`git_planner`] maps normalized Git requests to one exact singleton
//!      startup shard per normalized repo target.
//! 3. **Shard payload encoding**:
//!    - [`payload`] defines the typed filesystem metadata bytes carried
//!      through shard registration and lease hydration.
//!    - [`git_payload`] defines the typed Git metadata bytes carried through
//!      repo-frontier shard registration and later Git lease hydration.
//! 4. **Run setup** ([`setup`]): lowers normalized requests, planned
//!    geometry, and typed payloads into a validated initial manifest, then
//!    creates and registers the run through the coordination lifecycle.
//!    - [`git_setup`] performs the same lowering for Git startup plans while
//!      preserving exact repo-target order and replay semantics.
//!
//! Stages 1-3 are stateless and synchronous.  Stage 4 is synchronous but
//! coordination-backed: it calls into
//! [`RunManagement`](gossip_coordination::RunManagement) and mutates
//! run/shard state.

pub mod git_payload;
pub mod git_planner;
pub mod git_request;
pub mod git_setup;
pub mod payload;
pub mod planner;
pub mod request;
pub mod setup;

#[cfg(test)]
mod test_support;

pub use git_payload::{GitShardPayload, GitShardPayloadDecodeError, GitShardPayloadEncodeError};
pub use git_planner::{GitInitialShardPlan, GitInitialShardPlanEntry, plan_git_initial_shards};
pub use git_request::{
    GitRequest, GitRequestError, GitRequestSelection, GitRequestTarget, NormalizedGitRequest,
    NormalizedGitSelection, NormalizedGitTarget,
};
pub use git_setup::{GitRunSetupError, GitRunSetupInput, GitRunSetupResult, setup_git_run};
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
