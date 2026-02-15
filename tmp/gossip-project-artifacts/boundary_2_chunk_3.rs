//! Boundary â‘¡ â€” Coordination & Shard Frontier: Chunk 3 (DRAFT)
//!
//! The coordination trait: the operation contract that all backends
//! (in-memory, FoundationDB, PostgreSQL, deterministic simulator)
//! must implement.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5) and Boundary â‘¡
//! chunks 1â€“2. It uses all types defined in prior chunks.
//!
//! ## Design Decisions (locked)
//!
//! D2.13: The trait is synchronous (returns `Result<T, E>`, not futures).
//!        Async adaptation is the backend's responsibility â€” the contract
//!        defines semantics, not execution model. This keeps the
//!        deterministic simulator simple (no async runtime needed).
//!
//!        Reference: FoundationDB's simulation approach â€” the simulation
//!        layer controls scheduling; the API surface is synchronous from
//!        the protocol's perspective (Zhou et al., SIGMOD 2021).
//!
//! D2.14: Every mutating operation takes `(TenantId, ShardKey, Lease)`
//!        as its first parameters. The backend validates:
//!        1. Tenant isolation (record.tenant == tenant)
//!        2. Lease validity (record.fence_epoch == lease.fence, not expired)
//!        3. Status preconditions (record.status == Active for mutations)
//!
//!        This is the "fencing token protocol" â€” all writes carry the
//!        fence epoch, and the backend rejects stale epochs.
//!
//!        Reference: Kleppmann, "How to do distributed locking" (2016);
//!        Gray & Cheriton, "Leases" (SOSP 1989).
//!
//! D2.15: `AcquireAndRestore` is the only operation that does NOT require
//!        a pre-existing lease. It creates or renews one. All other
//!        operations require the caller to present a valid lease.
//!
//! D2.16: Error types are operation-specific newtypes over a shared
//!        `CoordError` enum. This lets callers match on the specific
//!        error variants relevant to each operation without casting.
//!
//! D2.17: `now: LogicalTime` is passed explicitly to every operation.
//!        The coordinator never reads a clock â€” time is an input.
//!        This is essential for deterministic simulation.
//!
//!        Reference: Â§9 Anti-Pattern #5; FoundationDB simulation.

// Assumes all types from prior chunks are in scope:
// use crate::{
//     CanonicalBytes, Hasher,
//     TenantId, RunId, ShardId, WorkerId, OpId, FenceEpoch,
//     LogicalTime, JobId, PolicyHash, ShardKey,
//     Cursor, ShardSpec, CursorAdvance, CursorBoundsCheck,
//     check_cursor_advance, check_cursor_bounds,
//     ShardStatus, ParkReason, ShardRecord, ShardSnapshot,
//     Lease, OpLogEntry, OpKind, OpResult,
//     SplitReplacePlan, SplitReplaceResult,
//     SplitResidualPlan, SplitResidualResult,
//     SplitValidationError,
//     hash_checkpoint_payload, hash_complete_payload, hash_park_payload,
//     hash_split_replace_payload, hash_split_residual_payload,
// };

// ============================================================================
// Â§ Chunk 3: Coordination Trait & Error Types
// ============================================================================

// ---------------------------------------------------------------------------
// Â§3.1 Shared error building blocks
// ---------------------------------------------------------------------------

/// Core coordination error variants shared across operations.
///
/// Individual operation error types wrap this with operation-specific
/// variants where needed. This avoids a single mega-enum that forces
/// callers to handle irrelevant variants.
///
/// ## Fencing Protocol Errors
///
/// `StaleFence` and `LeaseExpired` implement the fencing token protocol:
/// - `StaleFence`: the lease's epoch is behind the record's epoch.
///   Another worker was granted ownership, and this worker is a "zombie."
/// - `LeaseExpired`: the lease's epoch matches but the deadline has passed.
///   The worker took too long; another worker may have been granted ownership.
///
/// In both cases, the worker MUST stop processing and re-acquire.
///
/// Reference: Kleppmann, "How to do distributed locking" (2016).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordError {
    /// The shard does not exist in the coordination store.
    ShardNotFound { shard: ShardKey },

    /// Tenant isolation violation: the request's tenant does not match
    /// the shard record's tenant. This is always a bug.
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },

    /// The lease's fence epoch is behind the record's current epoch.
    /// Another worker has been granted ownership. Stop processing.
    ///
    /// Reference: Kleppmann fencing tokens â€” monotonic epoch rejects
    /// zombie writes.
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },

    /// The lease's fence epoch matches but the lease has expired.
    /// The worker must re-acquire before continuing.
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },

    /// The shard is in a terminal state and cannot accept mutations.
    /// Terminal states: Done, Split, Parked.
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },

    /// The shard is not in the expected status for this operation.
    /// E.g., trying to checkpoint a shard that is not Active.
    WrongStatus {
        expected: ShardStatus,
        actual: ShardStatus,
    },

    /// Idempotency conflict: the OpId was previously used with a
    /// different payload hash. This is always a client bug â€” accidental
    /// reuse of an OpId for a semantically different operation.
    ///
    /// Reference: Stripe idempotency key pattern (Brandur Leach, 2017).
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },

    /// Cursor monotonicity violation: the new cursor's `last_key` is
    /// lexicographically less than the current cursor's `last_key`.
    ///
    /// Reference: Â§D2.3 â€” cursor monotonicity is a hard safety invariant.
    CursorRegression {
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },

    /// Cursor bounds violation: the cursor's `last_key` falls outside
    /// the shard's key range.
    ///
    /// Reference: Â§D2.4 â€” cursor bounds checking is a hard safety invariant.
    CursorOutOfBounds {
        last_key: Box<[u8]>,
        spec_start: Box<[u8]>,
        spec_end: Box<[u8]>,
    },

    /// Split validation failed. Wraps the detailed error from
    /// `validate_split_coverage` / `validate_residual_split`.
    SplitInvalid(SplitValidationError),

    /// Checkpoint requires a `last_key` but the provided cursor has none.
    ///
    /// Reference: Â§D2.5 â€” a checkpoint requires a `last_key`.
    CheckpointMissingKey,
}

// ---------------------------------------------------------------------------
// Â§3.2 Operation-specific error types
// ---------------------------------------------------------------------------

/// Error from `acquire_and_restore`.
///
/// Acquire is special: it does NOT require a pre-existing lease, so
/// it cannot produce `StaleFence` or `LeaseExpired`. It can fail if
/// the shard is terminal, or if another worker holds a live lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcquireError {
    /// The shard does not exist.
    ShardNotFound { shard: ShardKey },

    /// Tenant isolation violation.
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },

    /// The shard is terminal â€” cannot be acquired.
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },

    /// Another worker currently holds a valid (non-expired) lease.
    /// The caller must wait or try a different shard.
    AlreadyLeased {
        current_owner: WorkerId,
        lease_deadline: LogicalTime,
    },
}

/// Error from `renew`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
}

/// Error from `checkpoint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
    CursorRegression {
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },
    CursorOutOfBounds {
        last_key: Box<[u8]>,
        spec_start: Box<[u8]>,
        spec_end: Box<[u8]>,
    },
    CheckpointMissingKey,
}

/// Error from `complete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompleteError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
    /// Complete requires a final cursor with a `last_key` to confirm
    /// the worker reached the end of its assigned range.
    CheckpointMissingKey,
}

/// Error from `park_shard`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParkError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

/// Error from `split_replace`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitReplaceError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
    SplitInvalid(SplitValidationError),
}

/// Error from `split_residual`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitResidualError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
    SplitInvalid(SplitValidationError),
}

// ---------------------------------------------------------------------------
// Â§3.3 CoordError â†’ operation error conversions
// ---------------------------------------------------------------------------

// These `From` impls allow the validation helpers (Â§3.6) to return
// `CoordError` which callers map into operation-specific errors via `?`.
// Only variants that are valid for each operation type are converted;
// invalid conversions are unreachable and panic to catch logic bugs.

impl From<CoordError> for CheckpointError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected, actual } => {
                Self::TenantMismatch { expected, actual }
            }
            CoordError::StaleFence { presented, current } => {
                Self::StaleFence { presented, current }
            }
            CoordError::LeaseExpired { deadline, now } => Self::LeaseExpired { deadline, now },
            CoordError::ShardTerminal { shard, status } => Self::ShardTerminal { shard, status },
            CoordError::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            } => Self::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            },
            CoordError::CursorRegression { old_key, new_key } => {
                Self::CursorRegression { old_key, new_key }
            }
            CoordError::CursorOutOfBounds {
                last_key,
                spec_start,
                spec_end,
            } => Self::CursorOutOfBounds {
                last_key,
                spec_start,
                spec_end,
            },
            CoordError::CheckpointMissingKey => Self::CheckpointMissingKey,
            other => unreachable!("unexpected CoordError variant for CheckpointError: {other:?}"),
        }
    }
}

impl From<CoordError> for CompleteError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected, actual } => {
                Self::TenantMismatch { expected, actual }
            }
            CoordError::StaleFence { presented, current } => {
                Self::StaleFence { presented, current }
            }
            CoordError::LeaseExpired { deadline, now } => Self::LeaseExpired { deadline, now },
            CoordError::ShardTerminal { shard, status } => Self::ShardTerminal { shard, status },
            CoordError::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            } => Self::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            },
            CoordError::CheckpointMissingKey => Self::CheckpointMissingKey,
            other => unreachable!("unexpected CoordError variant for CompleteError: {other:?}"),
        }
    }
}

impl From<CoordError> for ParkError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected, actual } => {
                Self::TenantMismatch { expected, actual }
            }
            CoordError::StaleFence { presented, current } => {
                Self::StaleFence { presented, current }
            }
            CoordError::LeaseExpired { deadline, now } => Self::LeaseExpired { deadline, now },
            CoordError::ShardTerminal { shard, status } => Self::ShardTerminal { shard, status },
            CoordError::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            } => Self::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            },
            other => unreachable!("unexpected CoordError variant for ParkError: {other:?}"),
        }
    }
}

impl From<CoordError> for SplitReplaceError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected, actual } => {
                Self::TenantMismatch { expected, actual }
            }
            CoordError::StaleFence { presented, current } => {
                Self::StaleFence { presented, current }
            }
            CoordError::LeaseExpired { deadline, now } => Self::LeaseExpired { deadline, now },
            CoordError::ShardTerminal { shard, status } => Self::ShardTerminal { shard, status },
            CoordError::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            } => Self::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            },
            CoordError::SplitInvalid(e) => Self::SplitInvalid(e),
            other => unreachable!("unexpected CoordError variant for SplitReplaceError: {other:?}"),
        }
    }
}

impl From<CoordError> for SplitResidualError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected, actual } => {
                Self::TenantMismatch { expected, actual }
            }
            CoordError::StaleFence { presented, current } => {
                Self::StaleFence { presented, current }
            }
            CoordError::LeaseExpired { deadline, now } => Self::LeaseExpired { deadline, now },
            CoordError::ShardTerminal { shard, status } => Self::ShardTerminal { shard, status },
            CoordError::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            } => Self::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            },
            CoordError::SplitInvalid(e) => Self::SplitInvalid(e),
            other => {
                unreachable!("unexpected CoordError variant for SplitResidualError: {other:?}")
            }
        }
    }
}

impl From<CoordError> for RenewError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected, actual } => {
                Self::TenantMismatch { expected, actual }
            }
            CoordError::StaleFence { presented, current } => {
                Self::StaleFence { presented, current }
            }
            CoordError::LeaseExpired { deadline, now } => Self::LeaseExpired { deadline, now },
            CoordError::ShardTerminal { shard, status } => Self::ShardTerminal { shard, status },
            other => unreachable!("unexpected CoordError variant for RenewError: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Â§3.4 Operation result types
// ---------------------------------------------------------------------------

/// Result of a successful `acquire_and_restore` operation.
///
/// Contains everything a worker needs to start or resume scanning:
/// - `lease`: proof of ownership with fencing token
/// - `snapshot`: shard state (spec, cursor, cursor_semantics, lineage)
///
/// The worker uses `lease` for all subsequent operations and `snapshot`
/// to determine where to resume scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcquireResult {
    pub lease: Lease,
    pub snapshot: ShardSnapshot,
}

/// Result of a successful `renew` operation.
///
/// Returns the updated lease with a new deadline. The fence epoch
/// does not change on renewal â€” only on ownership transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenewResult {
    pub new_deadline: LogicalTime,
}

// Note: Checkpoint, Complete, and Park return `()` on success (via the
// IdempotentOutcome wrapper). SplitReplace and SplitResidual return
// their respective result types from chunk 2.

// ---------------------------------------------------------------------------
// Â§3.5 Idempotent operation outcome
// ---------------------------------------------------------------------------

/// The outcome of an idempotent operation: either freshly executed or
/// replayed from the op-log.
///
/// Callers generally don't need to distinguish â€” the result is the same.
/// The distinction is useful for observability (metrics, logging).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotentOutcome<T> {
    /// The operation was executed for the first time.
    Executed(T),
    /// The operation was a retry â€” result replayed from op-log.
    Replayed(T),
}

impl<T> IdempotentOutcome<T> {
    /// Extract the inner result regardless of execution path.
    pub fn into_inner(self) -> T {
        match self {
            Self::Executed(v) | Self::Replayed(v) => v,
        }
    }

    /// Returns `true` if this was a replay (retry).
    pub fn is_replay(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }

    /// Map the inner value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> IdempotentOutcome<U> {
        match self {
            Self::Executed(v) => IdempotentOutcome::Executed(f(v)),
            Self::Replayed(v) => IdempotentOutcome::Replayed(f(v)),
        }
    }
}

// ---------------------------------------------------------------------------
// Â§3.6 The Coordination Trait
// ---------------------------------------------------------------------------

/// The coordination contract for the distributed secret scanner.
///
/// Every backend (in-memory, FoundationDB, PostgreSQL, deterministic
/// simulator) implements this trait. The trait defines the **semantic
/// contract** â€” what each operation must do and what invariants it
/// must maintain. Backends choose their own concurrency control and
/// persistence strategies.
///
/// ## Design Principles
///
/// **Synchronous API**: The trait methods are synchronous. Async
/// backends wrap the implementation; the deterministic simulator
/// calls methods directly without an async runtime.
///
/// **Time as input**: Every method takes `now: LogicalTime`. The
/// backend never reads a clock. This makes all operations
/// deterministic given the same inputs, enabling simulation testing.
///
/// Reference: FoundationDB simulation (Zhou et al., SIGMOD 2021).
///
/// **Tenant-first**: Every method takes `TenantId` as its first
/// parameter (after `&mut self` and `now`). The backend asserts
/// tenant isolation on every call.
///
/// **Lease-gated mutations**: All mutating operations (except
/// `acquire_and_restore`) require a valid `Lease`. The backend
/// validates the lease's fence epoch and deadline before executing.
///
/// ## Invariants (must hold across ALL backends)
///
/// **Safety (tenant isolation)**: A request scoped to tenant A must
/// never read or write shard records belonging to tenant B.
///
/// **Safety (fence monotonicity)**: `fence_epoch` for a shard MUST
/// be monotonically non-decreasing. It increments on every ownership
/// transfer (acquire). It never decreases.
///
/// **Safety (idempotency)**: For any operation with an `OpId`:
/// - Same `(op_id, payload_hash)` â†’ return cached result, no mutation
/// - Same `op_id`, different `payload_hash` â†’ `OpIdConflict` error
/// - New `op_id` â†’ execute and record in op-log
///
/// Reference: Stripe idempotency key pattern (Brandur Leach, 2017);
///            IETF Draft: Idempotency-Key HTTP Header Field.
///
/// **Safety (cursor monotonicity)**: Across checkpoints within the
/// same lease epoch, `cursor.last_key` must be lexicographically
/// non-decreasing.
///
/// **Safety (cursor bounds)**: `cursor.last_key` must fall within
/// the shard's `[spec.start, spec.end)`.
///
/// **Safety (split coverage)**: Split children must exactly partition
/// the parent's key range â€” no gaps, no overlaps.
///
/// **Safety (terminal irreversibility)**: Once a shard reaches Done,
/// Split, or Parked, no protocol operation changes its status.
///
/// **Liveness (lease expiry)**: If a worker fails to renew, its lease
/// expires and the shard becomes available for another worker.
///
/// ## Verification Strategy
///
/// The deterministic simulator exercises all operations with fault
/// injection (simulated crashes, lease expirations, concurrent
/// acquisitions). Property-based tests verify invariants hold across
/// random operation sequences.
///
/// Reference: FoundationDB simulation (Zhou et al., SIGMOD 2021);
///            TigerBeetle VOPR; Jepsen methodology.
pub trait CoordinationBackend {
    // â”€â”€ Shard lifecycle operations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Acquire a shard for processing and restore its last checkpoint.
    ///
    /// This is the entry point for a worker to start or resume scanning
    /// a shard. If the shard is currently unleased (or its lease has
    /// expired), the backend grants a new lease to the requesting worker.
    ///
    /// ## Behavior
    ///
    /// 1. Look up the shard record by `(tenant, key)`.
    /// 2. Verify tenant isolation: `record.tenant == tenant`.
    /// 3. Verify shard is Active (not terminal).
    /// 4. If currently leased and lease is live at `now`: reject with
    ///    `AlreadyLeased`.
    /// 5. Increment `fence_epoch` (ownership transfer).
    /// 6. Set `lease_owner = worker`, `lease_deadline = now + lease_duration`.
    /// 7. Return `(Lease, ShardSnapshot)`.
    ///
    /// ## Idempotency
    ///
    /// `acquire_and_restore` is NOT idempotent via OpId. It is
    /// inherently non-idempotent: each call that succeeds increments
    /// the fence epoch. A worker that calls acquire twice gets two
    /// different leases (the first is immediately invalidated by the
    /// second's epoch bump).
    ///
    /// Workers that need to resume after a transient failure should
    /// simply call acquire again â€” the new lease supersedes the old.
    ///
    /// ## Invariants
    ///
    /// **Safety**: `fence_epoch` strictly increases on successful acquire.
    /// **Safety**: The returned `Lease.fence` matches the record's new epoch.
    /// **Safety**: The returned snapshot reflects the record's state at
    /// acquisition time (after epoch bump, before any worker mutations).
    fn acquire_and_restore(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
    ) -> Result<AcquireResult, AcquireError>;

    /// Renew an existing lease, extending the deadline.
    ///
    /// The worker calls this periodically to signal liveness and prevent
    /// its lease from expiring. The fence epoch does NOT change â€” this
    /// is a deadline extension, not an ownership transfer.
    ///
    /// ## Behavior
    ///
    /// 1. Validate lease (tenant, fence epoch, not expired at `now`).
    /// 2. Set `lease_deadline = now + lease_duration`.
    /// 3. Return the new deadline.
    ///
    /// ## Invariants
    ///
    /// **Safety**: The fence epoch does not change on renewal.
    /// **Safety**: The lease owner does not change on renewal.
    /// **Liveness**: The new deadline is strictly after `now`.
    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError>;

    /// Checkpoint: advance the cursor within the shard's key range.
    ///
    /// Records progress. The new cursor must satisfy:
    /// - Monotonicity: `new_cursor.last_key >= old_cursor.last_key`
    /// - Bounds: `new_cursor.last_key âˆˆ [spec.start, spec.end)`
    /// - Non-empty key: `new_cursor.last_key.is_some()`
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id`:
    /// - Same `(op_id, hash_checkpoint_payload(new_cursor))` â†’ `Replayed(())`
    /// - Same `op_id`, different hash â†’ `OpIdConflict`
    /// - New `op_id` â†’ execute, record in op-log, `Executed(())`
    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError>;

    /// Complete: mark the shard as successfully done.
    ///
    /// Terminal operation. After completion, the shard's status is `Done`
    /// and no further mutations are accepted.
    ///
    /// The `final_cursor` records the worker's final position. It must
    /// satisfy the same monotonicity and bounds constraints as a
    /// checkpoint cursor.
    ///
    /// ## Behavior
    ///
    /// 1. Validate lease and preconditions.
    /// 2. Apply cursor constraints (monotonicity, bounds, non-empty key).
    /// 3. Set `status = Done`, `cursor = final_cursor`.
    /// 4. Release lease (`lease_owner = None`, `lease_deadline = None`).
    /// 5. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_complete_payload(final_cursor)`.
    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError>;

    /// Park: halt the shard due to an error condition.
    ///
    /// Terminal operation. After parking, the shard's status is `Parked`
    /// with the given reason. No further mutations are accepted.
    ///
    /// Unparking is an out-of-band admin operation (not part of this trait).
    ///
    /// ## Behavior
    ///
    /// 1. Validate lease and preconditions.
    /// 2. Set `status = Parked`, `park_reason = Some(reason)`.
    /// 3. Release lease.
    /// 4. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_park_payload(reason)`.
    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError>;

    /// SplitReplace: replace this shard with N child shards.
    ///
    /// Terminal operation for the parent (status â†’ Split). Creates N
    /// new Active child shards whose key ranges collectively cover the
    /// parent's range exactly.
    ///
    /// ## Behavior
    ///
    /// 1. Validate lease and preconditions.
    /// 2. Validate split coverage via `validate_split_coverage`.
    /// 3. Derive deterministic child IDs via `derive_split_shard_id`
    ///    with `DerivedShardKind::Child` and index `0..N`.
    /// 4. Create child ShardRecords (Active, initial cursors from plan).
    /// 5. Set parent status to Split, record children in `spawned`.
    /// 6. Release parent lease.
    /// 7. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_split_replace_payload(plan)`.
    /// On replay, returns the same child IDs without creating duplicates.
    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError>;

    /// SplitResidual: shrink this shard and create a residual for the
    /// unprocessed remainder.
    ///
    /// Non-terminal for the parent (stays Active with a smaller range).
    /// Creates one new Active residual shard covering the upper portion
    /// of the original range.
    ///
    /// ## Behavior
    ///
    /// 1. Validate lease and preconditions.
    /// 2. Validate residual split via `validate_residual_split`.
    /// 3. Derive deterministic residual ID via `derive_split_shard_id`
    ///    with `DerivedShardKind::Residual` and index `0`.
    /// 4. Update parent's spec to `plan.parent_new_spec`.
    /// 5. Create residual ShardRecord (Active).
    /// 6. Record residual in parent's `spawned`.
    /// 7. Parent keeps its lease (continues processing).
    /// 8. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_split_residual_payload(plan)`.
    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError>;
}

// ---------------------------------------------------------------------------
// Â§3.7 Lease validation helper
// ---------------------------------------------------------------------------

/// Validate a lease against a shard record.
///
/// This is the common preamble for all lease-gated operations. It checks
/// tenant isolation, fence epoch, and lease expiry in a fixed order.
///
/// ## Check Order
///
/// The order matters for error reporting:
/// 1. Tenant mismatch (always a bug â€” fail loudly)
/// 2. Shard terminal (no mutations possible)
/// 3. Stale fence (zombie detection â€” most common operational error)
/// 4. Lease expired (timing issue â€” second most common)
///
/// This ordering ensures the most actionable error is returned first.
///
/// Returns `Ok(())` if the lease is valid for the given record at `now`.
pub fn validate_lease(
    now: LogicalTime,
    tenant: TenantId,
    lease: &Lease,
    record: &ShardRecord,
) -> Result<(), CoordError> {
    // 1. Tenant isolation.
    if record.tenant != tenant {
        return Err(CoordError::TenantMismatch {
            expected: tenant,
            actual: record.tenant,
        });
    }

    // 2. Terminal check.
    if record.status.is_terminal() {
        return Err(CoordError::ShardTerminal {
            shard: ShardKey {
                run: record.run,
                shard: record.shard,
            },
            status: record.status,
        });
    }

    // 3. Fence epoch.
    if lease.fence != record.fence_epoch {
        return Err(CoordError::StaleFence {
            presented: lease.fence,
            current: record.fence_epoch,
        });
    }

    // 4. Lease expiry.
    if !record.is_leased_at(now) {
        return Err(CoordError::LeaseExpired {
            deadline: record.lease_deadline.unwrap_or(LogicalTime::ZERO),
            now,
        });
    }

    // Note: We intentionally do NOT check `lease.owner == record.lease_owner`
    // separately. The fence epoch is the canonical ownership proof â€” if
    // epochs match, ownership must match (invariant maintained by
    // acquire_and_restore). Belt-and-suspenders owner checks can be added
    // in debug builds via `debug_assert!`.

    Ok(())
}

/// Validate a cursor update against the current record.
///
/// Checks monotonicity, bounds, and non-empty key in one pass.
/// Returns `Ok(())` if the new cursor is valid.
pub fn validate_cursor_update(
    new_cursor: &Cursor,
    record: &ShardRecord,
) -> Result<(), CoordError> {
    // Must have a last_key.
    if new_cursor.last_key.is_none() {
        return Err(CoordError::CheckpointMissingKey);
    }

    // Monotonicity.
    match check_cursor_advance(&record.cursor, new_cursor) {
        CursorAdvance::Forward => {}
        CursorAdvance::Regression => {
            return Err(CoordError::CursorRegression {
                old_key: record.cursor.last_key.clone(),
                new_key: new_cursor.last_key.clone(),
            });
        }
        CursorAdvance::ResetToNone => {
            return Err(CoordError::CursorRegression {
                old_key: record.cursor.last_key.clone(),
                new_key: None,
            });
        }
    }

    // Bounds.
    match check_cursor_bounds(new_cursor, &record.spec) {
        CursorBoundsCheck::NoKey => {
            // Unreachable â€” we checked for None above.
            return Err(CoordError::CheckpointMissingKey);
        }
        CursorBoundsCheck::InBounds => {}
        CursorBoundsCheck::BelowRange | CursorBoundsCheck::AboveRange => {
            return Err(CoordError::CursorOutOfBounds {
                last_key: new_cursor.last_key.clone().unwrap(),
                spec_start: record.spec.key_range_start.clone(),
                spec_end: record.spec.key_range_end.clone(),
            });
        }
    }

    Ok(())
}

/// Check op-log for idempotent replay or conflict.
///
/// Returns:
/// - `Ok(Some(entry))` â€” replay: same op_id + same payload_hash
/// - `Ok(None)` â€” new operation, proceed with execution
/// - `Err(OpIdConflict)` â€” same op_id, different payload_hash
pub fn check_op_idempotency(
    record: &ShardRecord,
    op_id: OpId,
    payload_hash: u64,
) -> Result<Option<&OpLogEntry>, CoordError> {
    match record.op_log_lookup(op_id) {
        None => Ok(None),
        Some(entry) => {
            if entry.payload_hash == payload_hash {
                Ok(Some(entry))
            } else {
                Err(CoordError::OpIdConflict {
                    op_id,
                    expected_hash: entry.payload_hash,
                    actual_hash: payload_hash,
                })
            }
        }
    }
}

// ============================================================================
// Â§ Tests (stubs â€” full implementations deferred)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ Test fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }
    fn other_tenant() -> TenantId {
        TenantId::from_bytes([0xFF; 32])
    }
    fn test_run() -> RunId {
        RunId {
            job: JobId(1),
            policy: PolicyHash::from_bytes([0xAA; 32]),
        }
    }
    fn test_key() -> ShardKey {
        ShardKey {
            run: test_run(),
            shard: ShardId(0),
        }
    }
    fn test_spec() -> ShardSpec {
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())
    }

    fn active_unleased_record() -> ShardRecord {
        ShardRecord {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
            status: ShardStatus::Active,
            park_reason: None,
            spec: test_spec(),
            cursor: Cursor::initial(),
            cursor_semantics: CursorSemantics::Completed,
            lease_owner: None,
            lease_deadline: None,
            fence_epoch: FenceEpoch::INITIAL,
            parent: None,
            spawned: vec![],
            op_log: vec![],
        }
    }

    fn active_leased_record() -> ShardRecord {
        ShardRecord {
            lease_owner: Some(WorkerId(1)),
            lease_deadline: Some(LogicalTime(100)),
            fence_epoch: FenceEpoch(2),
            ..active_unleased_record()
        }
    }

    fn valid_lease_for(record: &ShardRecord) -> Lease {
        Lease {
            tenant: record.tenant,
            run: record.run,
            shard: record.shard,
            owner: record.lease_owner.unwrap_or(WorkerId(1)),
            fence: record.fence_epoch,
            deadline: record.lease_deadline.unwrap_or(LogicalTime(100)),
        }
    }

    // â”€â”€ validate_lease â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn validate_lease_ok() {
        let record = active_leased_record();
        let lease = valid_lease_for(&record);
        assert!(validate_lease(LogicalTime(50), test_tenant(), &lease, &record).is_ok());
    }

    #[test]
    fn validate_lease_tenant_mismatch() {
        let record = active_leased_record();
        let lease = valid_lease_for(&record);
        let result = validate_lease(LogicalTime(50), other_tenant(), &lease, &record);
        assert!(matches!(result, Err(CoordError::TenantMismatch { .. })));
    }

    #[test]
    fn validate_lease_terminal_shard() {
        let record = ShardRecord {
            status: ShardStatus::Done,
            lease_owner: None,
            lease_deadline: None,
            ..active_unleased_record()
        };
        let lease = Lease {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
            owner: WorkerId(1),
            fence: record.fence_epoch,
            deadline: LogicalTime(100),
        };
        let result = validate_lease(LogicalTime(50), test_tenant(), &lease, &record);
        assert!(matches!(result, Err(CoordError::ShardTerminal { .. })));
    }

    #[test]
    fn validate_lease_stale_fence() {
        let record = active_leased_record();
        let stale_lease = Lease {
            fence: FenceEpoch(1), // record is at epoch 2
            ..valid_lease_for(&record)
        };
        let result = validate_lease(LogicalTime(50), test_tenant(), &stale_lease, &record);
        assert!(matches!(result, Err(CoordError::StaleFence { .. })));
    }

    #[test]
    fn validate_lease_expired() {
        let record = active_leased_record(); // deadline = 100
        let lease = valid_lease_for(&record);
        let result = validate_lease(LogicalTime(100), test_tenant(), &lease, &record);
        assert!(matches!(result, Err(CoordError::LeaseExpired { .. })));
    }

    #[test]
    fn validate_lease_error_priority_tenant_before_fence() {
        // Both tenant mismatch and stale fence â€” tenant should win.
        let record = active_leased_record();
        let bad_lease = Lease {
            fence: FenceEpoch(1),
            ..valid_lease_for(&record)
        };
        let result = validate_lease(LogicalTime(50), other_tenant(), &bad_lease, &record);
        assert!(matches!(result, Err(CoordError::TenantMismatch { .. })));
    }

    #[test]
    fn validate_lease_error_priority_terminal_before_fence() {
        let record = ShardRecord {
            status: ShardStatus::Done,
            lease_owner: None,
            lease_deadline: None,
            ..active_unleased_record()
        };
        let stale_lease = Lease {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
            owner: WorkerId(1),
            fence: FenceEpoch(999),
            deadline: LogicalTime(100),
        };
        let result = validate_lease(LogicalTime(50), test_tenant(), &stale_lease, &record);
        assert!(matches!(result, Err(CoordError::ShardTerminal { .. })));
    }

    // â”€â”€ validate_cursor_update â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn validate_cursor_update_ok_first_checkpoint() {
        let record = active_leased_record(); // cursor is initial
        let new_cursor = Cursor::with_last_key(b"f".to_vec());
        assert!(validate_cursor_update(&new_cursor, &record).is_ok());
    }

    #[test]
    fn validate_cursor_update_ok_forward() {
        let record = ShardRecord {
            cursor: Cursor::with_last_key(b"f".to_vec()),
            ..active_leased_record()
        };
        let new_cursor = Cursor::with_last_key(b"m".to_vec());
        assert!(validate_cursor_update(&new_cursor, &record).is_ok());
    }

    #[test]
    fn validate_cursor_update_missing_key() {
        let record = active_leased_record();
        let new_cursor = Cursor::initial();
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(matches!(result, Err(CoordError::CheckpointMissingKey)));
    }

    #[test]
    fn validate_cursor_update_regression() {
        let record = ShardRecord {
            cursor: Cursor::with_last_key(b"m".to_vec()),
            ..active_leased_record()
        };
        let new_cursor = Cursor::with_last_key(b"f".to_vec());
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(matches!(result, Err(CoordError::CursorRegression { .. })));
    }

    #[test]
    fn validate_cursor_update_below_range() {
        let record = ShardRecord {
            spec: ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            ..active_leased_record()
        };
        let new_cursor = Cursor::with_last_key(b"a".to_vec());
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(matches!(result, Err(CoordError::CursorOutOfBounds { .. })));
    }

    #[test]
    fn validate_cursor_update_above_range() {
        let record = ShardRecord {
            spec: ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ..active_leased_record()
        };
        let new_cursor = Cursor::with_last_key(b"z".to_vec());
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(matches!(result, Err(CoordError::CursorOutOfBounds { .. })));
    }

    // â”€â”€ check_op_idempotency â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn check_op_idempotency_new_op() {
        let record = active_leased_record();
        let result = check_op_idempotency(&record, OpId(42), 0xDEAD);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn check_op_idempotency_replay() {
        let mut record = active_leased_record();
        record.op_log_push(OpLogEntry {
            op_id: OpId(42),
            kind: OpKind::Checkpoint,
            payload_hash: 0xDEAD,
            result: OpResult::Ack,
        });
        let result = check_op_idempotency(&record, OpId(42), 0xDEAD);
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn check_op_idempotency_conflict() {
        let mut record = active_leased_record();
        record.op_log_push(OpLogEntry {
            op_id: OpId(42),
            kind: OpKind::Checkpoint,
            payload_hash: 0xDEAD,
            result: OpResult::Ack,
        });
        let result = check_op_idempotency(&record, OpId(42), 0xBEEF);
        assert!(matches!(result, Err(CoordError::OpIdConflict { .. })));
    }

    // â”€â”€ IdempotentOutcome â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn idempotent_outcome_into_inner() {
        assert_eq!(IdempotentOutcome::Executed(42).into_inner(), 42);
        assert_eq!(IdempotentOutcome::Replayed(42).into_inner(), 42);
    }

    #[test]
    fn idempotent_outcome_is_replay() {
        assert!(!IdempotentOutcome::Executed(()).is_replay());
        assert!(IdempotentOutcome::Replayed(()).is_replay());
    }

    #[test]
    fn idempotent_outcome_map() {
        let doubled = IdempotentOutcome::Executed(21).map(|v| v * 2);
        assert_eq!(doubled.into_inner(), 42);
        assert!(!doubled.is_replay());

        let doubled = IdempotentOutcome::Replayed(21).map(|v| v * 2);
        assert_eq!(doubled.into_inner(), 42);
        assert!(doubled.is_replay());
    }
}
