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
//!
//! ## Invariant contracts
//!
//! - Cursor positions remain monotonic within a shard and never escape the shard's current key range.
//! - Split planning always observes the `ShardSpec` bounds that triggered the split so the replace/
//!   residual planner never sees stale coverage.
//! - Manifest validation rejects empty or overlapping shard intervals, keeping downstream coordination
//!   backends safe from range assertions.

/// Two-layer progress marker defining where a connector should resume.
pub mod cursor;

/// Split capacity constants and sizing limits.
pub mod limits;

/// Shard registration validation and initial shard input models.
pub mod manifest;

/// Arena-pooled wrappers for shard byte fields (spec, cursor, spawned).
///
/// Coordination backends interact with pooled types through
/// `gossip_coordination::ShardRecord` and `gossip_coordination::AcquireScratch`.
pub mod pooled;

/// Grouped acquire/restore coordination payload for backend state transitions.
pub mod restored_state;

/// Key ranges, split validation, and shard specification models.
pub mod shard_spec;

/// Split planner core for replace and residual splits (backend-agnostic).
pub mod split;

/// Expose cursor advancement/validation APIs so consumers can reason about monotonic progress without touching the module internals.
/// These helpers enforce the two-layer cursor invariants and provide lexicographic helpers for key/token successor math.
pub use cursor::{
    CursorAdvance, CursorBoundsCheck, CursorInputError, CursorUpdate, MAX_KEY_SIZE,
    MAX_TOKEN_SIZE as CursorMaxTokenSize, check_cursor_advance, check_cursor_bounds,
    key_successor_into, prefix_successor_into,
};

/// Split capacity constants shared between the planner and executors to keep spawn/split counts aligned.
pub use limits::{MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN};

/// Manifest validation surface ensuring shard registration payloads remain bounded and explicit.
pub use manifest::{
    InitialShardInput, MAX_INITIAL_SHARDS, ManifestValidationError, validate_manifest,
};

/// Arena-pooled wrappers for hot-path shard bytes so callers can avoid per-request allocations.
pub use pooled::{PooledCursor, PooledShardSpec, PooledSpawned, PooledSpawnedIter};

/// Restored-state helpers for backend transitions after a fence or acquire.
pub use restored_state::RestoredShardState;

/// Key-range validation primitives, shard metadata, and split coverage checks consumed by both planners and connectors.
pub use shard_spec::{
    CursorSemantics, MAX_METADATA_SIZE as ShardSpecMaxMetadataSize, ShardArena, ShardSpec,
    ShardSpecHandle, ShardSpecInputError, ShardSpecRef, SplitValidationError,
    validate_residual_split, validate_split_coverage,
};

/// Split planning core entry point that returns replace/residual plans modeled over abstract `ShardSpec`.
pub use split::{
    SplitReplaceChild, SplitReplacePlan, SplitReplacePlanError, SplitReplacePlanningError,
    SplitResidualPlan, SplitResidualPlanError, SplitResidualPlanningError, plan_split_replace,
    plan_split_replace_at_points, plan_split_replace_at_points_initial_cursor, plan_split_residual,
    plan_split_residual_at_point, plan_split_residual_from_cursor,
};
