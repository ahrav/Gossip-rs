//! Shard lifecycle, lease management, and the coordination backend trait.
//!
//! Owns the shard state machine (`Active → Done | Parked | Split`), lease
//! management (`Lease`, `FenceEpoch`), the `CoordinationBackend` trait that all
//! storage backends implement, run lifecycle (`RunRecord`, `RunConfig`,
//! `RunManagement`), and the ergonomic `WorkerSession` wrapper. Together these
//! define how shards are assigned to workers, how progress is checkpointed, and
//! how ownership is transferred via fencing tokens.
//!
//! **Dependency direction:** May depend on `identity` (for ID types and
//! `CanonicalBytes`). Must not reference `shard`, `connector`, or `persistence`.
//!
//! **Key invariants:**
//! - Tenant isolation — every operation verifies `request.tenant == record.tenant`.
//! - Fence monotonicity — `fence_epoch` is monotonically non-decreasing per shard;
//!   stale fences are rejected.
//! - Lease expiry — operations on expired leases are rejected; unrenewed leases
//!   allow re-acquisition by other workers.
//! - OpId idempotency — replayed operations return cached results; conflicting
//!   payloads for the same `OpId` are rejected.
//! - Terminal irreversibility — `Done`, `Parked`, and `Split` shards (and
//!   `Done` / `Failed` runs) reject all further mutations.

pub mod cursor;
pub mod shard_spec;

pub use cursor::{
    Cursor, CursorAdvance, CursorBoundsCheck, CursorInputError, MAX_KEY_SIZE as CursorMaxKeySize,
    MAX_TOKEN_SIZE as CursorMaxTokenSize, check_cursor_advance, check_cursor_bounds,
};
pub use shard_spec::{
    CursorSemantics, MAX_KEY_SIZE as ShardSpecMaxKeySize,
    MAX_METADATA_SIZE as ShardSpecMaxMetadataSize, ShardSpec, ShardSpecInputError,
    SplitValidationError, validate_residual_split, validate_split_coverage,
};
