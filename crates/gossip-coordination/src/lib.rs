//! Coordination protocol: traits, state machine, and in-memory reference backend.
//!
//! This crate implements the coordination protocol for distributed shard
//! scanning. It defines how shards are assigned to workers, how progress is
//! checkpointed, and how ownership is transferred via fencing tokens.
//!
//! The shared data model (shard spec, cursor, pooled wrappers) lives in
//! [`gossip_contracts::coordination`]. This crate provides the protocol
//! layer that consumes those types.
//!
//! Ownership boundary:
//! - `gossip-contracts` owns split planner types/constructors and shared
//!   validation contracts.
//! - `gossip-coordination` owns execution semantics: lease/fence validation,
//!   idempotency/op-log behavior, and backend mutation ordering.
//! - `split_execution` in this crate owns split execution helpers
//!   (derived IDs/payload hashes and split operation results) and consumes
//!   planner types from `gossip-contracts`.
//!
//! **Start here:** [`CoordinationBackend`] defines the semantic contract.
//! [`InMemoryCoordinator`] is the executable reference spec.
//! [`WorkerSession`] shows the typical caller flow.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Protocol modules
// ---------------------------------------------------------------------------

pub mod error;
pub mod events;
pub mod facade;
pub mod in_memory;
pub mod lease;
pub mod record;
pub mod run;
pub mod run_errors;
pub mod session;
pub mod split_execution;
pub mod traits;
pub mod validation;

// ---------------------------------------------------------------------------
// Simulation harness (test + test-support only)
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
pub mod sim;

// ---------------------------------------------------------------------------
// Re-exports: data model types from gossip-contracts for convenience
// ---------------------------------------------------------------------------

pub use gossip_contracts::coordination::{
    // Cursor types
    CursorAdvance,
    CursorBoundsCheck,
    CursorInputError,
    CursorMaxTokenSize,
    CursorSemantics,
    CursorUpdate,
    // Manifest types and limit constants
    InitialShardInput,
    MAX_INITIAL_SHARDS,
    MAX_KEY_SIZE,
    MAX_SPAWNED_PER_SHARD,
    MAX_SPLIT_CHILDREN,
    ManifestValidationError,
    // Pooled types
    PooledCursor,
    PooledShardSpec,
    PooledSpawned,
    PooledSpawnedIter,
    // Shard spec types
    ShardArena,
    ShardSpec,
    ShardSpecHandle,
    ShardSpecInputError,
    ShardSpecMaxMetadataSize,
    ShardSpecRef,
    SplitValidationError,
    // Validation functions
    check_cursor_advance,
    check_cursor_bounds,
    validate_manifest,
    validate_residual_split,
    validate_split_coverage,
};

// ---------------------------------------------------------------------------
// Protocol re-exports (flattened)
// ---------------------------------------------------------------------------

pub use error::{
    AcquireError, AcquireResultView, AcquireScratch, CapacityHint, CheckpointError, CompleteError,
    CoordError, CursorOutOfBoundsDetail, FixedBuf, IdempotentOutcome, ParkError, RenewError,
    RenewResult, ShardSnapshotView, SplitError, SplitReplaceError, SplitResidualError,
};
pub use events::{EventCollector, EventKind, RedactedKey, StateTransitionEvent};
pub use facade::{ClaimError, CoordinationFacade, ShardClaiming, default_claim_next_available};
pub use in_memory::InMemoryCoordinator;
pub use lease::{Lease, LeaseHolder, OpKind, OpLogEntry, OpResult};
pub use record::{ParkReason, ShardRecord, ShardStatus};
pub use run::{
    RunConfig, RunConfigError, RunManagement, RunOpIdConflict, RunOpKind, RunOpLogEntry,
    RunOpResult, RunProgress, RunRecord, RunStatus, RunTerminalEvaluation, ShardFilter,
    ShardSummary, evaluate_run_terminal, hash_cancel_run_payload, hash_complete_run_payload,
    hash_fail_run_payload, hash_register_shards_payload, hash_unpark_payload,
};
pub use run_errors::{
    CreateRunError, GetRunError, RegisterShardsError, RunTransitionError, UnparkError,
};
pub use session::WorkerSession;
pub use split_execution::{
    DerivedShardKind, SplitChildIds, SplitChildOrder, SplitReplaceResult, SplitResidualResult,
    derive_split_shard_id, find_replayed_residual, hash_checkpoint_payload, hash_complete_payload,
    hash_park_payload, hash_split_replace_payload, hash_split_residual_payload,
    split_replace_apply_parent, split_replace_validate_preconditions,
    split_residual_apply_parent, split_residual_build_record, split_residual_check_replay,
    split_residual_validate_cursor_bounds, split_residual_validate_preconditions,
};
pub use traits::CoordinationBackend;
pub use validation::{check_op_idempotency, validate_lease};

// Re-export split planner core from contracts for ergonomic call sites.
// Convention: coordination-layer code imports directly from
// `gossip_contracts::coordination::split`; these re-exports serve external
// consumers that depend only on `gossip-coordination`.
pub use gossip_contracts::coordination::split::{
    SplitReplaceChild, SplitReplacePlan, SplitReplacePlanError, SplitReplacePlanningError,
    SplitResidualPlan, SplitResidualPlanError, SplitResidualPlanningError, plan_split_replace,
    plan_split_replace_at_points, plan_split_replace_at_points_initial_cursor, plan_split_residual,
    plan_split_residual_at_point, plan_split_residual_from_cursor,
};

// Identity types re-exported for convenience (test files use `super::*`).
pub use gossip_contracts::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
};

// Re-export gossip_stdx types used by protocol and test code.
pub use gossip_stdx::{ByteSlab, InlineVec, RingBuffer};

// Re-export additional data model types for convenience.
pub use gossip_contracts::coordination::cursor::MAX_TOKEN_SIZE;
pub use gossip_contracts::coordination::shard_spec::{
    ShardLimitScope, validate_residual_split_bounds,
};

// Re-export in_memory types.
#[cfg(any(test, feature = "test-support"))]
pub use in_memory::{CoordinatorConfig, RUN_RECORD_PLANNING_BYTES, SHARD_RECORD_PLANNING_BYTES};
pub use in_memory::{
    CoordinatorRuntimeConfig, DEFAULT_MAX_AUTO_SLAB_CAPACITY, DEFAULT_MAX_SHARDS_PER_TENANT,
    DEFAULT_MAX_TOTAL_SHARDS,
};

// Re-export record internal types used by tests.
#[cfg(test)]
pub use record::SpawnedList;

// ---------------------------------------------------------------------------
// Test modules
// ---------------------------------------------------------------------------

#[cfg(test)]
mod conformance_tests;
#[cfg(test)]
mod scenario_tests;
/// Shared test fixtures: tenant/run/shard factories and seeded coordinators.
#[cfg(any(test, feature = "test-support"))]
pub mod test_fixtures;

// Individual module test files are declared inside their parent modules
// via `#[path = "..."]` attributes (error.rs, facade.rs, in_memory.rs,
// record.rs, run.rs, session.rs).
