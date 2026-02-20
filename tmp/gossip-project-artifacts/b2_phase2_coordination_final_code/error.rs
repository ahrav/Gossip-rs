//! Error types, result types, and idempotent outcome wrapper for
//! the coordination protocol.
//!
//! ## Design Decisions (locked)
//!
//! D2.16: Error types are operation-specific newtypes over a shared
//!        `CoordError` enum. Callers get precise error matching (e.g.,
//!        `CheckpointError` can't produce `AlreadyLeased`). The tradeoff
//!        is boilerplate `From` impls, which are finite and mechanical.
//!
//! The `From<CoordError>` impls use `unreachable!()` for invalid
//! conversions. If a variant that shouldn't appear for a given operation
//! is converted, this is a logic bug and we panic immediately.

use crate::identity::{
    FenceEpoch, LogicalTime, OpId, ShardId, ShardKey, TenantId, WorkerId,
};
use crate::coordination::lease::Lease;
use crate::coordination::record::{ShardSnapshot, ShardStatus};
use crate::coordination::shard_spec::SplitValidationError;

// ============================================================================
// § CoordError — shared error building blocks
// ============================================================================

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
    /// Reference: Kleppmann fencing tokens — monotonic epoch rejects
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
    WrongStatus {
        expected: ShardStatus,
        actual: ShardStatus,
    },

    /// Idempotency conflict: the OpId was previously used with a
    /// different payload hash. This is always a client bug — accidental
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
    /// Reference: §D2.3 — cursor monotonicity is a hard safety invariant.
    CursorRegression {
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },

    /// Cursor bounds violation: the cursor's `last_key` falls outside
    /// the shard's key range.
    ///
    /// Reference: §D2.4 — cursor bounds checking is a hard safety invariant.
    CursorOutOfBounds {
        last_key: Box<[u8]>,
        spec_start: Box<[u8]>,
        spec_end: Box<[u8]>,
    },

    /// Split validation failed. Wraps the detailed error from
    /// `validate_split_coverage` / `validate_residual_split`.
    SplitInvalid(SplitValidationError),

    /// Checkpoint requires a `last_key` but the provided cursor has none.
    CheckpointMissingKey,
}

// ============================================================================
// § Operation-specific error types
// ============================================================================

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

    /// The shard is terminal — cannot be acquired.
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

// ============================================================================
// § From<CoordError> impls
// ============================================================================

// These allow the validation helpers to return `CoordError` which callers
// map into operation-specific errors via `?`. Only variants valid for each
// operation type are converted; invalid conversions panic (logic bugs).

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
            other => unreachable!(
                "unexpected CoordError variant for CheckpointError: {other:?}"
            ),
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
            other => unreachable!(
                "unexpected CoordError variant for CompleteError: {other:?}"
            ),
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
            other => unreachable!(
                "unexpected CoordError variant for ParkError: {other:?}"
            ),
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
            other => unreachable!(
                "unexpected CoordError variant for SplitReplaceError: {other:?}"
            ),
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
            other => unreachable!(
                "unexpected CoordError variant for SplitResidualError: {other:?}"
            ),
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
            other => unreachable!(
                "unexpected CoordError variant for RenewError: {other:?}"
            ),
        }
    }
}

// ============================================================================
// § Operation result types
// ============================================================================

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
/// does not change on renewal — only on ownership transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenewResult {
    pub new_deadline: LogicalTime,
}

// Note: Checkpoint, Complete, and Park return `()` on success (via the
// IdempotentOutcome wrapper). SplitReplace and SplitResidual return
// their respective result types from the split module.

// ============================================================================
// § IdempotentOutcome
// ============================================================================

/// The outcome of an idempotent operation: either freshly executed or
/// replayed from the op-log.
///
/// Callers generally don't need to distinguish — the result is the same.
/// The distinction is useful for observability (metrics, logging).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotentOutcome<T> {
    /// The operation was executed for the first time.
    Executed(T),
    /// The operation was a retry — result replayed from op-log.
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

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    // -- IdempotentOutcome --

    // TODO: test idempotent_outcome_into_inner
    //   - Executed(42).into_inner() == 42
    //   - Replayed(42).into_inner() == 42

    // TODO: test idempotent_outcome_is_replay
    //   - !Executed(()).is_replay()
    //   - Replayed(()).is_replay()

    // TODO: test idempotent_outcome_map
    //   - Executed(21).map(|v| v * 2) → Executed(42), !is_replay
    //   - Replayed(21).map(|v| v * 2) → Replayed(42), is_replay

    // -- From<CoordError> conversions --

    // TODO: test checkpoint_error_from_coord_error_valid_variants
    //   - Each valid variant converts correctly

    // TODO: test complete_error_from_coord_error_valid_variants

    // TODO: test park_error_from_coord_error_valid_variants

    // TODO: test split_replace_error_from_coord_error_valid_variants

    // TODO: test split_residual_error_from_coord_error_valid_variants

    // TODO: test renew_error_from_coord_error_valid_variants

    // -- From<CoordError> unreachable cases --
    // These would be #[should_panic] tests verifying that invalid
    // conversions hit unreachable!(). E.g.:

    // TODO: #[should_panic] test checkpoint_error_from_already_leased_panics
    //   - CoordError doesn't have AlreadyLeased, but if WrongStatus or
    //     SplitInvalid is converted to CheckpointError, it should panic.

    // TODO: #[should_panic] test renew_error_from_op_id_conflict_panics

    // TODO: #[should_panic] test park_error_from_split_invalid_panics
}
