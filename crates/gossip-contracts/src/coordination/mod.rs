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
pub mod error;
pub mod in_memory;
pub mod lease;
pub mod record;
pub mod run;
pub mod run_errors;
pub mod shard_spec;
pub mod split;
pub mod traits;
pub mod validation;

pub use cursor::{
    Cursor, CursorAdvance, CursorBoundsCheck, CursorInputError, MAX_KEY_SIZE as CursorMaxKeySize,
    MAX_TOKEN_SIZE as CursorMaxTokenSize, check_cursor_advance, check_cursor_bounds,
};
pub use error::{
    AcquireError, AcquireResult, CheckpointError, CompleteError, CoordError,
    CursorOutOfBoundsDetail, IdempotentOutcome, ParkError, RenewError, RenewResult, SplitError,
    SplitReplaceError, SplitResidualError,
};
pub use in_memory::InMemoryCoordinator;
pub use lease::{Lease, LeaseHolder, OpKind, OpLogEntry, OpResult};
pub use record::{ParkReason, ShardRecord, ShardSnapshot, ShardStatus};
pub use run::RunManagement;
pub use run::{
    InitialShard, MAX_INITIAL_SHARDS, ManifestValidationError, RunConfig, RunConfigError,
    RunOpIdConflict, RunOpKind, RunOpLogEntry, RunOpResult, RunProgress, RunRecord, RunStatus,
    RunTerminalEvaluation, ShardFilter, ShardSummary, evaluate_run_terminal,
    hash_cancel_run_payload, hash_complete_run_payload, hash_fail_run_payload,
    hash_register_shards_payload, hash_unpark_payload, validate_manifest,
};
pub use run_errors::{
    CancelRunError, CompleteRunError, CreateRunError, FailRunError, GetRunError,
    RegisterShardsError, UnparkError,
};
pub use shard_spec::{
    CursorSemantics, MAX_KEY_SIZE as ShardSpecMaxKeySize,
    MAX_METADATA_SIZE as ShardSpecMaxMetadataSize, ShardSpec, ShardSpecInputError,
    SplitValidationError, validate_residual_split, validate_split_coverage,
};
pub use split::{
    DerivedShardKind, MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN, SplitReplaceChild,
    SplitReplacePlan, SplitReplacePlanError, SplitReplaceResult, SplitResidualPlan,
    SplitResidualPlanError, SplitResidualResult, derive_split_shard_id, hash_checkpoint_payload,
    hash_complete_payload, hash_park_payload, hash_split_replace_payload,
    hash_split_residual_payload,
};
pub use traits::CoordinationBackend;
pub use validation::{check_op_idempotency, validate_cursor_update, validate_lease};
