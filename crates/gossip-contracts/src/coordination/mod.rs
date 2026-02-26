//! Shard data model: key ranges, cursor progress, pooled wrappers, and manifest
//! validation.
//!
//! This module defines the shared data types that both the coordination protocol
//! (`gossip-coordination`) and shard algebra (`gossip-frontier`) depend on.
//! Protocol traits, state machine, and the in-memory backend live in
//! `gossip-coordination`.
//!
//! ## Module Map
//!
//! ```text
//! coordination/
//! ├── shard_spec.rs    ShardSpec, ShardSpecRef, CursorSemantics — key ranges and split validation
//! ├── cursor.rs        CursorUpdate — two-layer progress marker
//! ├── pooled.rs        PooledShardSpec, PooledCursor — arena-backed zero-alloc hot-path storage
//! ├── manifest.rs      InitialShardInput, validate_manifest — shard registration validation
//! └── limits.rs        MAX_SPLIT_CHILDREN, MAX_SPAWNED_PER_SHARD — split capacity constants
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
pub mod shard_spec;

// -- Progress tracking --
pub use cursor::{
    CursorAdvance, CursorBoundsCheck, CursorInputError, CursorUpdate, MAX_KEY_SIZE,
    MAX_TOKEN_SIZE as CursorMaxTokenSize, check_cursor_advance, check_cursor_bounds,
};

// -- Split capacity limits --
pub use limits::{MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN};

// -- Manifest validation --
pub use manifest::{
    InitialShardInput, MAX_INITIAL_SHARDS, ManifestValidationError, validate_manifest,
};

// -- Arena-pooled storage --
pub use pooled::{PooledCursor, PooledShardSpec, PooledSpawned, PooledSpawnedIter};

// -- Key ranges and split validation --
pub use shard_spec::{
    CursorSemantics, MAX_METADATA_SIZE as ShardSpecMaxMetadataSize, ShardArena, ShardSpec,
    ShardSpecHandle, ShardSpecInputError, ShardSpecRef, SplitValidationError,
    validate_residual_split, validate_split_coverage,
};

// shard_spec_tests.rs is declared inside shard_spec.rs via #[path] attribute.
