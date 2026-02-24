//! Coordination types and backend trait.
//!
//! This module defines the shard lifecycle (status transitions, lease
//! management, fencing protocol), the `CoordinationBackend` trait that
//! storage backends implement, and the run-level administrative
//! operations. Depends on `identity` for all ID types.
//!
//! ## Module Layout
//!
//! ```text
//! coordination/
//! ├── cursor.rs       — Cursor, CursorAdvance, CursorBoundsCheck
//! ├── shard_spec.rs   — ShardSpec, CursorSemantics, split validation
//! ├── record.rs       — ShardStatus, ShardRecord, ShardSnapshot (Step 2)
//! ├── lease.rs        — Lease, OpLogEntry, OpKind, OpResult (Step 2)
//! ├── split.rs        — SplitReplace/ResidualPlan/Result, derive_split_shard_id (Step 2)
//! ├── error.rs        — CoordError, operation-specific error types (Step 3)
//! ├── validation.rs   — validate_lease, validate_cursor_update, check_op_idempotency (Step 3)
//! ├── traits.rs       — CoordinationBackend trait (Step 4)
//! ├── run.rs          — RunStatus, RunRecord, RunManagement trait (Step 6)
//! ├── admin.rs        — unpark_shard, cancel_run (Step 6)
//! ├── session.rs      — WorkerSession (Step 7)
//! ├── events.rs       — StateTransitionEvent, EventCollector (Step 7)
//! ├── facade.rs       — CoordinationFacade super-trait (Step 7)
//! └── in_memory.rs    — InMemoryCoordinator [test-support] (Steps 4-6)
//! ```

// Step 1: Value types — pure data + validation, no state.
pub mod cursor;
pub mod shard_spec;

pub use shard_spec::{
    CursorSemantics,
    ShardSpec,
    SplitValidationError,
    InitialShard,
    ManifestValidationError,
    validate_manifest,
    validate_split_coverage,
    validate_residual_split,
};

// Step 2+: To be added as implementation progresses.
// pub mod record;
// pub mod lease;
// pub mod split;
// pub mod error;
// pub mod validation;
// pub mod traits;
// pub mod run;
// pub mod admin;
// pub mod session;
// pub mod events;
// pub mod facade;
// #[cfg(any(test, feature = "test-support"))]
// pub mod in_memory;
