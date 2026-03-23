//! Shard data model: key ranges, cursor progress, split planning, pooled
//! wrappers, and manifest validation.
//!
//! This module defines the shared data types that both the coordination protocol
//! (`gossip-coordination`) and shard algebra (`gossip-frontier`) depend on.
//! Protocol traits, state machine, and the in-memory backend live in
//! `gossip-coordination`.
//!
//! ## Ownership Boundaries
//!
//! - This module owns data contracts and pure validation helpers.
//! - `gossip-coordination` owns protocol sequencing, lease/fence enforcement,
//!   idempotency behavior, and backend mutation semantics.
//! - Split planning (replace + residual) is defined here (`split.rs`);
//!   split execution result types and ID/hash derivation helpers live in
//!   `gossip-coordination::split_execution`.
//!
//! ## Module Map
//!
//! ```text
//! coordination/
//! ├── shard_spec.rs       ShardSpec, ShardSpecRef, CursorSemantics — key ranges and split validation
//! ├── cursor.rs           CursorUpdate — two-layer progress marker
//! ├── pooled.rs           PooledShardSpec, PooledCursor — arena-backed zero-alloc hot-path storage
//! ├── restored_state.rs   RestoredShardState — grouped acquire/restore coordination payload
//! ├── split.rs            Split planner core (replace + residual, backend-agnostic)
//! ├── manifest.rs         InitialShardInput, validate_manifest — shard registration validation
//! └── limits.rs           MAX_SPLIT_CHILDREN, MAX_SPAWNED_PER_SHARD — split capacity constants
//! ```

// ---- Sub-modules (alphabetical) ----

pub mod cursor;
pub mod limits;
pub mod manifest;
/// Arena-pooled wrappers for shard byte fields (spec, cursor, spawned).
///
/// Coordination backends interact with pooled types through
/// `gossip_coordination::ShardRecord` and `gossip_coordination::AcquireScratch`.
pub mod pooled;
pub mod restored_state;
pub mod shard_spec;
pub mod split;

// -- Progress tracking --
pub use cursor::{
    CursorAdvance, CursorBoundsCheck, CursorInputError, CursorUpdate, MAX_KEY_SIZE,
    MAX_TOKEN_SIZE as CursorMaxTokenSize, check_cursor_advance, check_cursor_bounds,
    key_successor_into, prefix_successor_into,
};

// -- Split capacity limits --
pub use limits::{MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN};

// -- Manifest validation --
pub use manifest::{
    InitialShardInput, MAX_INITIAL_SHARDS, ManifestValidationError, validate_manifest,
};

// -- Arena-pooled storage --
pub use pooled::{PooledCursor, PooledShardSpec, PooledSpawned, PooledSpawnedIter};

// -- Restored coordination state --
pub use restored_state::RestoredShardState;

// -- Key ranges and split validation --
pub use shard_spec::{
    CursorSemantics, MAX_METADATA_SIZE as ShardSpecMaxMetadataSize, ShardArena, ShardSpec,
    ShardSpecHandle, ShardSpecInputError, ShardSpecRef, SplitValidationError,
    validate_residual_split, validate_split_coverage,
};

// -- Split planning core (execution lives in gossip-coordination) --
pub use split::{
    SplitReplaceChild, SplitReplacePlan, SplitReplacePlanError, SplitReplacePlanningError,
    SplitResidualPlan, SplitResidualPlanError, SplitResidualPlanningError, plan_split_replace,
    plan_split_replace_at_points, plan_split_replace_at_points_initial_cursor, plan_split_residual,
    plan_split_residual_at_point, plan_split_residual_from_cursor,
};

// shard_spec_tests.rs is declared inside shard_spec.rs via #[path] attribute.
