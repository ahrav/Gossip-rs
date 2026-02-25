//! Shard lifecycle, lease management, and the coordination backend trait.
//!
//! This module is the protocol layer for distributed shard scanning. It defines
//! how shards are assigned to workers, how progress is checkpointed, and how
//! ownership is transferred via fencing tokens — without dictating the storage
//! backend.
//!
//! ## Module Map
//!
//! ```text
//! coordination/
//! ├── traits.rs        CoordinationBackend — the semantic contract all backends implement
//! ├── record.rs        ShardRecord, ShardStatus — authoritative shard state
//! ├── shard_spec.rs    ShardSpec, ShardSpecRef, CursorSemantics — key ranges and split validation
//! ├── split.rs         SplitReplacePlan, SplitResidualPlan — split types and ID derivation
//! ├── error.rs         CoordError + per-operation error types + ShardSnapshotView
//! ├── cursor.rs        CursorUpdate — two-layer progress marker
//! ├── lease.rs         Lease, LeaseHolder, OpLogEntry — ownership tokens and idempotency log
//! ├── run.rs           RunRecord, RunManagement — run lifecycle and shard registration
//! ├── validation.rs    validate_lease, check_op_idempotency — shared precondition checks
//! ├── facade.rs        CoordinationFacade, ShardClaiming — orchestrator-facing super-trait
//! ├── session.rs       WorkerSession — ergonomic wrapper that threads tenant/lease params
//! ├── events.rs        StateTransitionEvent — inert observability data
//! ├── pooled.rs        PooledShardSpec, PooledCursor — arena-backed zero-alloc hot-path storage
//! ├── run_errors.rs    CreateRunError, GetRunError, RegisterShardsError — run operation errors
//! └── in_memory.rs     InMemoryCoordinator — executable reference specification
//! ```
//!
//! **Start here:** [`CoordinationBackend`] defines
//! the semantic contract. [`InMemoryCoordinator`]
//! is the executable reference spec. [`WorkerSession`]
//! shows the typical caller flow.
//!
//! ## Allocation Strategy
//!
//! Checkpoint/complete mutations take borrowed [`CursorUpdate`] inputs, and
//! acquire restores write into caller-owned [`AcquireScratch`] buffers. Runtime
//! coordination paths stay borrowed/slab-backed and avoid heap materialization
//! of cursor/spec payload bytes. Simulation split planning follows the same
//! pattern by building `ShardSpecRef` plans from stack-copied bounds.
//!
//! ## Dependency Direction
//!
//! May depend on `identity` (for ID types and `CanonicalBytes`).
//! Must not reference `shard`, `connector`, or `persistence`.
//!
//! ## Key Invariants
//!
//! - **Tenant isolation** — every operation verifies `request.tenant == record.tenant`.
//! - **Fence monotonicity** — `fence_epoch` is monotonically non-decreasing per shard;
//!   stale fences are rejected.
//! - **Lease expiry** — operations on expired leases are rejected; unrenewed leases
//!   allow re-acquisition by other workers.
//! - **OpId idempotency** — replayed operations return cached results; conflicting
//!   payloads for the same `OpId` are rejected.
//! - **Terminal irreversibility** — `Done`, `Parked`, and `Split` shards (and
//!   `Done` / `Failed` / `Cancelled` runs) reject all worker-level mutations.
//!   `Parked` shards may be resumed via `unpark_shard` (admin `RunManagement`
//!   operation).

// ---- Sub-modules (alphabetical) ----

pub mod cursor;
pub mod error;
pub mod events;
pub mod facade;
pub mod in_memory;
pub mod lease;
/// Arena-pooled wrappers for shard byte fields (spec, cursor, spawned).
/// Crate-internal -- callers interact through [`ShardRecord`] and
/// [`AcquireScratch`] rather than pooled types directly.
pub(crate) mod pooled;
pub mod record;
pub mod run;
pub mod run_errors;
pub mod session;
pub mod shard_spec;
pub mod split;
pub mod traits;
pub mod validation;

// -- Progress tracking --
pub use cursor::{
    CursorAdvance, CursorBoundsCheck, CursorInputError, CursorUpdate, MAX_KEY_SIZE,
    MAX_TOKEN_SIZE as CursorMaxTokenSize, check_cursor_advance, check_cursor_bounds,
};

// -- Error types and result wrappers --
pub use error::{
    AcquireError, AcquireResultView, AcquireScratch, CapacityHint, CheckpointError, CompleteError,
    CoordError, CursorOutOfBoundsDetail, IdempotentOutcome, ParkError, RenewError, RenewResult,
    ShardSnapshotView, SplitError, SplitReplaceError, SplitResidualError,
};

// -- Observability --
pub use events::{EventCollector, EventKind, RedactedKey, StateTransitionEvent};

// -- Orchestrator-facing super-trait --
pub use facade::{ClaimError, CoordinationFacade, ShardClaiming, default_claim_next_available};

// -- Reference backend --
pub use in_memory::InMemoryCoordinator;

// -- Lease and idempotency --
pub use lease::{Lease, LeaseHolder, OpKind, OpLogEntry, OpResult};

// -- Shard state --
pub use record::{ParkReason, ShardRecord, ShardStatus};

// -- Run lifecycle --
pub use run::RunManagement;
pub use run::{
    InitialShardInput, MAX_INITIAL_SHARDS, ManifestValidationError, RunConfig, RunConfigError,
    RunOpIdConflict, RunOpKind, RunOpLogEntry, RunOpResult, RunProgress, RunRecord, RunStatus,
    RunTerminalEvaluation, ShardFilter, ShardSummary, evaluate_run_terminal,
    hash_cancel_run_payload, hash_complete_run_payload, hash_fail_run_payload,
    hash_register_shards_payload, hash_unpark_payload, validate_manifest,
};
pub use run_errors::{
    CreateRunError, GetRunError, RegisterShardsError, RunTransitionError, UnparkError,
};

// -- Ergonomic session wrapper --
pub use session::WorkerSession;

// -- Key ranges and split validation --
pub use shard_spec::{
    CursorSemantics, MAX_METADATA_SIZE as ShardSpecMaxMetadataSize, ShardArena, ShardSpec,
    ShardSpecHandle, ShardSpecInputError, ShardSpecRef, SplitValidationError,
    validate_residual_split, validate_split_coverage,
};

// -- Split operation types --
pub use split::{
    DerivedShardKind, MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN, SplitReplaceChild,
    SplitReplacePlan, SplitReplacePlanError, SplitReplaceResult, SplitResidualPlan,
    SplitResidualPlanError, SplitResidualResult, derive_split_shard_id, hash_checkpoint_payload,
    hash_complete_payload, hash_park_payload, hash_split_replace_payload,
    hash_split_residual_payload,
};

// -- Core trait and validation --
pub use traits::CoordinationBackend;
pub use validation::{check_op_idempotency, validate_lease};

#[cfg(test)]
mod conformance_tests;
#[cfg(test)]
mod scenario_tests;
#[cfg(test)]
pub(crate) mod test_fixtures;
