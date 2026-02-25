//! Shard lifecycle, lease management, and the coordination backend trait.
//!
//! Owns the shard state machine (`Active → Done | Parked | Split`), lease
//! management (`Lease`, `FenceEpoch`), the `CoordinationBackend` trait that all
//! storage backends implement, run lifecycle (`RunRecord`, `RunConfig`,
//! `RunManagement`), and the ergonomic `WorkerSession` wrapper. Together these
//! define how shards are assigned to workers, how progress is checkpointed, and
//! how ownership is transferred via fencing tokens.
//!
//! Checkpoint/complete mutations take borrowed [`CursorUpdate`] inputs to
//! avoid transient heap allocations. Owned [`Cursor`] values are only used
//! for persisted snapshots and read-side materialization.
//!
//! Startup manifest registration also has a borrowed path:
//! [`InitialShardInput`] + [`ShardSpecRef`] can be validated and registered
//! without first materializing owned shard specs/cursors, while [`ShardArena`]
//! provides preallocated backing storage for those borrowed specs.
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
//!   `Done` / `Failed` / `Cancelled` runs) reject all worker-level mutations.
//!   `Parked` shards may be resumed via `unpark_shard` (admin `RunManagement`
//!   operation).

pub mod cursor;
pub mod error;
pub mod events;
pub mod facade;
pub mod in_memory;
pub mod lease;
pub(crate) mod pooled;
pub mod record;
pub mod run;
pub mod run_errors;
pub mod session;
pub mod shard_spec;
pub mod split;
pub mod traits;
pub mod validation;

pub use cursor::{
    Cursor, CursorAdvance, CursorBoundsCheck, CursorInputError, CursorUpdate, MAX_KEY_SIZE,
    MAX_TOKEN_SIZE as CursorMaxTokenSize, check_cursor_advance, check_cursor_bounds,
};
pub use error::{
    AcquireError, AcquireResult, CapacityHint, CheckpointError, CompleteError, CoordError,
    CursorOutOfBoundsDetail, IdempotentOutcome, ParkError, RenewError, RenewResult, SplitError,
    SplitReplaceError, SplitResidualError,
};
pub use events::{EventCollector, EventKind, RedactedKey, StateTransitionEvent};
pub use facade::{ClaimError, CoordinationFacade, ShardClaiming, default_claim_next_available};
pub use in_memory::InMemoryCoordinator;
pub use lease::{Lease, LeaseHolder, OpKind, OpLogEntry, OpResult};
pub use record::{ParkReason, ShardRecord, ShardSnapshot, ShardStatus};
pub use run::RunManagement;
pub use run::{
    InitialShardInput, MAX_INITIAL_SHARDS, ManifestValidationError, RunConfig, RunConfigError,
    RunOpIdConflict, RunOpKind, RunOpLogEntry, RunOpResult, RunProgress, RunRecord, RunStatus,
    RunTerminalEvaluation, ShardFilter, ShardSummary, evaluate_run_terminal,
    hash_cancel_run_payload, hash_complete_run_payload, hash_fail_run_payload,
    hash_register_shards_payload, hash_unpark_payload, validate_manifest_inputs,
};
pub use run_errors::{
    CreateRunError, GetRunError, RegisterShardsError, RunTransitionError, UnparkError,
};
pub use session::WorkerSession;
pub use shard_spec::{
    CursorSemantics, MAX_METADATA_SIZE as ShardSpecMaxMetadataSize, ShardArena, ShardSpec,
    ShardSpecHandle, ShardSpecInputError, ShardSpecRef, SplitValidationError,
    validate_residual_split, validate_split_coverage,
};
pub use split::{
    DerivedShardKind, MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN, SplitReplaceChild,
    SplitReplacePlan, SplitReplacePlanError, SplitReplaceResult, SplitResidualPlan,
    SplitResidualPlanError, SplitResidualResult, derive_split_shard_id, hash_checkpoint_payload,
    hash_complete_payload, hash_park_payload, hash_split_replace_payload,
    hash_split_residual_payload,
};
pub use traits::CoordinationBackend;
pub use validation::{check_op_idempotency, validate_lease};

#[cfg(test)]
mod conformance_tests;
#[cfg(test)]
mod scenario_tests;
#[cfg(test)]
pub(crate) mod test_fixtures;
