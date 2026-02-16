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
//! The `From<CoordError>` impls enumerate all rejected variants explicitly
//! rather than using a wildcard `_` catch-all. This means adding a new
//! `CoordError` variant triggers a compile error in every `From` impl,
//! forcing a conscious decision about where the new variant maps.
//!
//! ## OpId CSPRNG Requirement
//!
//! `OpId` values MUST be generated via a cryptographically secure PRNG
//! (e.g., `rand::rngs::OsRng`) or a coordinated counter to prevent
//! accidental collisions. Two independent workers using the same `OpId`
//! for different operations will trigger `OpIdConflict`, which is
//! indistinguishable from a legitimate retry with a corrupted payload.

use std::fmt;

use crate::coordination::lease::Lease;
use crate::coordination::record::{ShardSnapshot, ShardStatus};
use crate::coordination::shard_spec::SplitValidationError;
use crate::identity::{FenceEpoch, LogicalTime, OpId, ShardKey, TenantId, WorkerId};

// ============================================================================
// CoordError -- shared error building blocks
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
/// - `StaleFence`: the lease's epoch does not match the record's epoch
///   (in practice, behind it due to monotonicity). Another worker was
///   granted ownership, and this worker is a "zombie."
/// - `LeaseExpired`: the lease's epoch matches but the deadline has passed.
///   The worker took too long; another worker may have been granted ownership.
///
/// In both cases, the worker MUST stop processing and re-acquire.
///
/// Reference: Kleppmann, "How to do distributed locking" (2016).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoordError {
    /// The shard does not exist in the coordination store.
    ShardNotFound { shard: ShardKey },

    /// Tenant isolation violation: the request's tenant does not match
    /// the shard record's tenant. This is always a bug.
    ///
    /// Only `expected` (the caller's tenant) is exposed. The actual
    /// tenant is deliberately omitted to prevent cross-tenant enumeration
    /// (SEC-1).
    TenantMismatch { expected: TenantId },

    /// The lease's fence epoch does not match the record's current epoch
    /// (in practice, behind it due to monotonicity).
    /// Another worker has been granted ownership. Stop processing.
    ///
    /// Reference: Kleppmann fencing tokens -- monotonic epoch rejects
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
    ///
    /// Reserved for status precondition checks not covered by
    /// `ShardTerminal`. Retained for coordinator backends that need
    /// finer-grained status checks.
    WrongStatus {
        expected: ShardStatus,
        actual: ShardStatus,
    },

    /// Idempotency conflict: the OpId was previously used with a
    /// different payload hash. This is always a client bug -- accidental
    /// reuse of an OpId for a semantically different operation.
    ///
    /// `OpId` values must be generated via CSPRNG or a coordinated
    /// counter to prevent collisions (SEC-6).
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
    /// Reference: D2.3 -- cursor monotonicity is a hard safety invariant.
    CursorRegression {
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },

    /// Cursor bounds violation: the cursor's `last_key` falls outside
    /// the shard's key range.
    ///
    /// Reference: D2.4 -- cursor bounds checking is a hard safety invariant.
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

impl fmt::Display for CoordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::StaleFence { presented, current } => write!(
                f,
                "stale fence epoch: presented {presented:?}, current {current:?}"
            ),
            Self::LeaseExpired { deadline, now } => {
                write!(f, "lease expired: deadline {deadline:?}, now {now:?}")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
            Self::WrongStatus { expected, actual } => {
                write!(f, "wrong status: expected {expected}, actual {actual}")
            }
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
            Self::CursorRegression { .. } => write!(f, "cursor regression: new key < old key"),
            Self::CursorOutOfBounds { last_key, .. } => write!(
                f,
                "cursor out of bounds: key ({} bytes) outside shard range",
                last_key.len()
            ),
            Self::SplitInvalid(inner) => write!(f, "split invalid: {inner}"),
            Self::CheckpointMissingKey => write!(f, "checkpoint requires a last_key"),
        }
    }
}

impl std::error::Error for CoordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SplitInvalid(inner) => Some(inner),
            _ => None,
        }
    }
}

// ============================================================================
// Operation-specific error types
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
    ///
    /// Only `expected` (the caller's tenant) is exposed (SEC-1).
    TenantMismatch { expected: TenantId },

    /// The shard is terminal -- cannot be acquired.
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },

    /// Another worker currently holds a valid (non-expired) lease.
    /// The caller must wait or try a different shard.
    ///
    /// **Security note (SEC-5):** `current_owner` exposes worker identity.
    /// Redact this field before surfacing to external clients.
    AlreadyLeased {
        current_owner: WorkerId,
        lease_deadline: LogicalTime,
    },
}

impl fmt::Display for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
            // Omit current_owner in Display output (SEC-5).
            Self::AlreadyLeased { lease_deadline, .. } => {
                write!(f, "shard already leased (deadline {lease_deadline:?})")
            }
        }
    }
}

impl std::error::Error for AcquireError {}

/// Error from `renew`.
///
/// Renew extends a lease deadline without modifying shard progress, so it
/// carries only the common precondition variants (shard lookup, tenant
/// isolation, fencing, terminal state). It excludes `OpIdConflict`,
/// cursor, and split variants because renew is not an idempotent
/// progress-advancing operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewError {
    ShardNotFound {
        shard: ShardKey,
    },
    TenantMismatch {
        expected: TenantId,
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

impl fmt::Display for RenewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::StaleFence { presented, current } => write!(
                f,
                "stale fence epoch: presented {presented:?}, current {current:?}"
            ),
            Self::LeaseExpired { deadline, now } => {
                write!(f, "lease expired: deadline {deadline:?}, now {now:?}")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
        }
    }
}

impl std::error::Error for RenewError {}

/// Error from `checkpoint`.
///
/// Checkpoint is the richest mutation: it advances the cursor and is
/// idempotent via the op-log. Accordingly this is among the widest error
/// types (tied with [`CompleteError`]), carrying all common precondition
/// variants plus `OpIdConflict`,
/// `CursorRegression`, `CursorOutOfBounds`, and `CheckpointMissingKey`.
/// It excludes only `WrongStatus` and `SplitInvalid`.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    ShardNotFound {
        shard: ShardKey,
    },
    TenantMismatch {
        expected: TenantId,
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

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::StaleFence { presented, current } => write!(
                f,
                "stale fence epoch: presented {presented:?}, current {current:?}"
            ),
            Self::LeaseExpired { deadline, now } => {
                write!(f, "lease expired: deadline {deadline:?}, now {now:?}")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
            Self::CursorRegression { .. } => write!(f, "cursor regression: new key < old key"),
            Self::CursorOutOfBounds { last_key, .. } => write!(
                f,
                "cursor out of bounds: key ({} bytes) outside shard range",
                last_key.len()
            ),
            Self::CheckpointMissingKey => write!(f, "checkpoint requires a last_key"),
        }
    }
}

impl std::error::Error for CheckpointError {}

/// Error from `complete`.
///
/// Complete shares most variants with [`CheckpointError`] (idempotency,
/// cursor checks) because it records a final cursor position. It excludes
/// `WrongStatus` and `SplitInvalid`. The `CheckpointMissingKey` variant
/// here means the worker did not supply a `last_key` proving it reached
/// the end of its assigned range.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompleteError {
    ShardNotFound {
        shard: ShardKey,
    },
    TenantMismatch {
        expected: TenantId,
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
    CursorRegression {
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },
    CursorOutOfBounds {
        last_key: Box<[u8]>,
        spec_start: Box<[u8]>,
        spec_end: Box<[u8]>,
    },
}

impl fmt::Display for CompleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::StaleFence { presented, current } => write!(
                f,
                "stale fence epoch: presented {presented:?}, current {current:?}"
            ),
            Self::LeaseExpired { deadline, now } => {
                write!(f, "lease expired: deadline {deadline:?}, now {now:?}")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
            Self::CheckpointMissingKey => write!(f, "complete requires a last_key"),
            Self::CursorRegression { .. } => write!(f, "cursor regression: new key < old key"),
            Self::CursorOutOfBounds { last_key, .. } => write!(
                f,
                "cursor out of bounds: key ({} bytes) outside shard range",
                last_key.len()
            ),
        }
    }
}

impl std::error::Error for CompleteError {}

/// Error from `park_shard`.
///
/// Park transitions a shard to the `Parked` terminal state. It is
/// idempotent (carries `OpIdConflict`) but does not advance the cursor,
/// so it excludes all cursor variants and `CheckpointMissingKey`.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParkError {
    ShardNotFound {
        shard: ShardKey,
    },
    TenantMismatch {
        expected: TenantId,
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

impl fmt::Display for ParkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::StaleFence { presented, current } => write!(
                f,
                "stale fence epoch: presented {presented:?}, current {current:?}"
            ),
            Self::LeaseExpired { deadline, now } => {
                write!(f, "lease expired: deadline {deadline:?}, now {now:?}")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
        }
    }
}

impl std::error::Error for ParkError {}

/// Error from `split_replace`.
///
/// Split-replace atomically replaces a parent shard with child shards.
/// It is idempotent and carries `SplitInvalid` for coverage validation
/// failures, but excludes cursor variants and `CheckpointMissingKey`
/// because splits do not advance a scan cursor.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitReplaceError {
    ShardNotFound {
        shard: ShardKey,
    },
    TenantMismatch {
        expected: TenantId,
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

impl fmt::Display for SplitReplaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::StaleFence { presented, current } => write!(
                f,
                "stale fence epoch: presented {presented:?}, current {current:?}"
            ),
            Self::LeaseExpired { deadline, now } => {
                write!(f, "lease expired: deadline {deadline:?}, now {now:?}")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
            Self::SplitInvalid(inner) => write!(f, "split invalid: {inner}"),
        }
    }
}

impl std::error::Error for SplitReplaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SplitInvalid(inner) => Some(inner),
            _ => None,
        }
    }
}

/// Error from `split_residual`.
///
/// Split-residual creates the leftover shard covering the unscanned
/// portion of the parent's key range. Its error surface mirrors
/// [`SplitReplaceError`] exactly: common preconditions, `OpIdConflict`,
/// and `SplitInvalid`, with no cursor variants.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitResidualError {
    ShardNotFound {
        shard: ShardKey,
    },
    TenantMismatch {
        expected: TenantId,
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

impl fmt::Display for SplitResidualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => write!(f, "shard not found: {shard:?}"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::StaleFence { presented, current } => write!(
                f,
                "stale fence epoch: presented {presented:?}, current {current:?}"
            ),
            Self::LeaseExpired { deadline, now } => {
                write!(f, "lease expired: deadline {deadline:?}, now {now:?}")
            }
            Self::ShardTerminal { shard, status } => {
                write!(f, "shard {shard:?} is terminal ({status})")
            }
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
            Self::SplitInvalid(inner) => write!(f, "split invalid: {inner}"),
        }
    }
}

impl std::error::Error for SplitResidualError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SplitInvalid(inner) => Some(inner),
            _ => None,
        }
    }
}

// ============================================================================
// From<CoordError> impls -- explicit rejection arms
// ============================================================================

// These allow the validation helpers to return `CoordError` which callers
// map into operation-specific errors via `?`. Only variants valid for each
// operation type are converted; invalid conversions hit `unreachable!()`.
//
// Every impl explicitly enumerates rejected variants so that adding a new
// `CoordError` variant triggers a compile error here, forcing a conscious
// routing decision.

impl From<CoordError> for CheckpointError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected } => Self::TenantMismatch { expected },
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
            // Explicitly reject all variants CheckpointError does not cover.
            // Adding a new CoordError variant triggers a compile error here.
            CoordError::WrongStatus { .. } | CoordError::SplitInvalid(_) => {
                unreachable!("CoordError::{e:?} is not valid for CheckpointError")
            }
        }
    }
}

impl From<CoordError> for CompleteError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected } => Self::TenantMismatch { expected },
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
            // Explicitly reject all variants CompleteError does not cover.
            CoordError::WrongStatus { .. } | CoordError::SplitInvalid(_) => {
                unreachable!("CoordError::{e:?} is not valid for CompleteError")
            }
        }
    }
}

impl From<CoordError> for ParkError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected } => Self::TenantMismatch { expected },
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
            // Explicitly reject all variants ParkError does not cover.
            CoordError::WrongStatus { .. }
            | CoordError::CursorRegression { .. }
            | CoordError::CursorOutOfBounds { .. }
            | CoordError::SplitInvalid(_)
            | CoordError::CheckpointMissingKey => {
                unreachable!("CoordError::{e:?} is not valid for ParkError")
            }
        }
    }
}

impl From<CoordError> for SplitReplaceError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected } => Self::TenantMismatch { expected },
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
            // Explicitly reject all variants SplitReplaceError does not cover.
            CoordError::WrongStatus { .. }
            | CoordError::CursorRegression { .. }
            | CoordError::CursorOutOfBounds { .. }
            | CoordError::CheckpointMissingKey => {
                unreachable!("CoordError::{e:?} is not valid for SplitReplaceError")
            }
        }
    }
}

impl From<CoordError> for SplitResidualError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected } => Self::TenantMismatch { expected },
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
            // Explicitly reject all variants SplitResidualError does not cover.
            CoordError::WrongStatus { .. }
            | CoordError::CursorRegression { .. }
            | CoordError::CursorOutOfBounds { .. }
            | CoordError::CheckpointMissingKey => {
                unreachable!("CoordError::{e:?} is not valid for SplitResidualError")
            }
        }
    }
}

impl From<CoordError> for RenewError {
    fn from(e: CoordError) -> Self {
        match e {
            CoordError::ShardNotFound { shard } => Self::ShardNotFound { shard },
            CoordError::TenantMismatch { expected } => Self::TenantMismatch { expected },
            CoordError::StaleFence { presented, current } => {
                Self::StaleFence { presented, current }
            }
            CoordError::LeaseExpired { deadline, now } => Self::LeaseExpired { deadline, now },
            CoordError::ShardTerminal { shard, status } => Self::ShardTerminal { shard, status },
            // Explicitly reject all variants RenewError does not cover.
            CoordError::WrongStatus { .. }
            | CoordError::OpIdConflict { .. }
            | CoordError::CursorRegression { .. }
            | CoordError::CursorOutOfBounds { .. }
            | CoordError::SplitInvalid(_)
            | CoordError::CheckpointMissingKey => {
                unreachable!("CoordError::{e:?} is not valid for RenewError")
            }
        }
    }
}

// ============================================================================
// Operation result types
// ============================================================================

/// Result of a successful `acquire_and_restore` operation.
///
/// Contains everything a worker needs to start or resume scanning:
/// - `lease`: proof of ownership with fencing token
/// - `snapshot`: shard state (status, spec, cursor, cursor_semantics, lineage)
///
/// The worker uses `lease` for all subsequent operations and `snapshot`
/// to determine where to resume scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "acquire result contains a lease that must be used"]
pub struct AcquireResult {
    pub lease: Lease,
    pub snapshot: ShardSnapshot,
}

/// Result of a successful `renew` operation.
///
/// Returns the new deadline. The fence epoch does not change on
/// renewal -- only on ownership transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "renew result contains the new deadline"]
pub struct RenewResult {
    pub new_deadline: LogicalTime,
}

// Note: Checkpoint, Complete, and Park return `()` on success (via the
// IdempotentOutcome wrapper). SplitReplace and SplitResidual return
// their respective result types from the split module.

// ============================================================================
// IdempotentOutcome
// ============================================================================

/// The outcome of an idempotent operation: either freshly executed or
/// replayed from the op-log.
///
/// Callers generally don't need to distinguish -- the result is the same.
/// The distinction is useful for observability (metrics, logging).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "idempotent outcome should be inspected"]
pub enum IdempotentOutcome<T> {
    /// The operation was executed for the first time.
    Executed(T),
    /// The operation was a retry -- result replayed from op-log.
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

    /// Returns `true` if this was a first execution (not a replay).
    #[inline]
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed(_))
    }

    /// Map the inner value, preserving the execution/replay distinction.
    #[must_use = "map produces a new outcome that should be used"]
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> IdempotentOutcome<U> {
        match self {
            Self::Executed(v) => IdempotentOutcome::Executed(f(v)),
            Self::Replayed(v) => IdempotentOutcome::Replayed(f(v)),
        }
    }
}

impl<T> AsRef<T> for IdempotentOutcome<T> {
    /// Borrow the inner value regardless of execution path.
    fn as_ref(&self) -> &T {
        match self {
            Self::Executed(v) | Self::Replayed(v) => v,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::identity::{FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId};

    // -- Test fixtures ---------------------------------------------------

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_key() -> ShardKey {
        ShardKey::new(RunId::from_raw(1), ShardId::from_raw(10))
    }

    // -- Variant group builders ------------------------------------------
    //
    // Shared `CoordError` construction extracted from 6 From tests.
    // Adding a new CoordError variant: add it to the appropriate group
    // (or `all_coord_error_variants`) and the compiler will ensure the
    // From impls handle it.

    /// 5 common precondition variants shared by all 6 From impls.
    fn common_precondition_variants() -> Vec<CoordError> {
        vec![
            CoordError::ShardNotFound { shard: test_key() },
            CoordError::TenantMismatch {
                expected: test_tenant(),
            },
            CoordError::StaleFence {
                presented: FenceEpoch::INITIAL,
                current: FenceEpoch::INITIAL.increment(),
            },
            CoordError::LeaseExpired {
                deadline: LogicalTime::from_raw(100),
                now: LogicalTime::from_raw(200),
            },
            CoordError::ShardTerminal {
                shard: test_key(),
                status: ShardStatus::Done,
            },
        ]
    }

    fn op_id_conflict_variant() -> CoordError {
        CoordError::OpIdConflict {
            op_id: OpId::from_raw(1),
            expected_hash: 1,
            actual_hash: 2,
        }
    }

    fn cursor_variants() -> Vec<CoordError> {
        vec![
            CoordError::CursorRegression {
                old_key: None,
                new_key: None,
            },
            CoordError::CursorOutOfBounds {
                last_key: b"k".as_slice().into(),
                spec_start: b"a".as_slice().into(),
                spec_end: b"z".as_slice().into(),
            },
        ]
    }

    fn split_invalid_variant() -> CoordError {
        CoordError::SplitInvalid(SplitValidationError::NoChildren)
    }

    fn checkpoint_missing_key_variant() -> CoordError {
        CoordError::CheckpointMissingKey
    }

    /// All 11 `CoordError` variants. Used by the display-determinism test.
    fn all_coord_error_variants() -> Vec<CoordError> {
        let mut v = common_precondition_variants();
        v.push(CoordError::WrongStatus {
            expected: ShardStatus::Active,
            actual: ShardStatus::Done,
        });
        v.push(op_id_conflict_variant());
        v.extend(cursor_variants());
        v.push(split_invalid_variant());
        v.push(checkpoint_missing_key_variant());
        v
    }

    /// Assert every variant in `variants` converts to `E` without panicking.
    fn assert_from_coord_error_accepted<E: From<CoordError> + fmt::Debug>(
        variants: Vec<CoordError>,
    ) {
        for v in variants {
            let _: E = v.into();
        }
    }

    // -- IdempotentOutcome -----------------------------------------------

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
    fn idempotent_outcome_is_executed() {
        assert!(IdempotentOutcome::Executed(()).is_executed());
        assert!(!IdempotentOutcome::Replayed(()).is_executed());
    }

    #[test]
    fn idempotent_outcome_map() {
        let ex = IdempotentOutcome::Executed(21).map(|v| v * 2);
        assert_eq!(ex, IdempotentOutcome::Executed(42));
        assert!(!ex.is_replay());

        let re = IdempotentOutcome::Replayed(21).map(|v| v * 2);
        assert_eq!(re, IdempotentOutcome::Replayed(42));
        assert!(re.is_replay());
    }

    #[test]
    fn idempotent_outcome_as_ref() {
        let ex = IdempotentOutcome::Executed(42);
        assert_eq!(ex.as_ref(), &42);
        let re = IdempotentOutcome::Replayed(99);
        assert_eq!(re.as_ref(), &99);
    }

    // -- From<CoordError> exhaustiveness tests ---------------------------
    //
    // Each test composes variant groups and converts them, verifying every
    // valid conversion succeeds. The explicit rejection arms in the From
    // impls (not wildcard `_`) guarantee that adding a new CoordError
    // variant triggers a compile error.

    #[test]
    fn checkpoint_error_from_coord_error_exhaustive() {
        let mut v = common_precondition_variants();
        v.push(op_id_conflict_variant());
        v.extend(cursor_variants());
        v.push(checkpoint_missing_key_variant());
        assert_from_coord_error_accepted::<CheckpointError>(v);
        // Rejected: WrongStatus, SplitInvalid
    }

    #[test]
    fn complete_error_from_coord_error_exhaustive() {
        let mut v = common_precondition_variants();
        v.push(op_id_conflict_variant());
        v.extend(cursor_variants());
        v.push(checkpoint_missing_key_variant());
        assert_from_coord_error_accepted::<CompleteError>(v);
        // Rejected: WrongStatus, SplitInvalid
    }

    #[test]
    fn park_error_from_coord_error_exhaustive() {
        let mut v = common_precondition_variants();
        v.push(op_id_conflict_variant());
        assert_from_coord_error_accepted::<ParkError>(v);
        // Rejected: WrongStatus, CursorRegression, CursorOutOfBounds,
        //           SplitInvalid, CheckpointMissingKey
    }

    #[test]
    fn split_replace_error_from_coord_error_exhaustive() {
        let mut v = common_precondition_variants();
        v.push(op_id_conflict_variant());
        v.push(split_invalid_variant());
        assert_from_coord_error_accepted::<SplitReplaceError>(v);
        // Rejected: WrongStatus, CursorRegression, CursorOutOfBounds,
        //           CheckpointMissingKey
    }

    #[test]
    fn split_residual_error_from_coord_error_exhaustive() {
        let mut v = common_precondition_variants();
        v.push(op_id_conflict_variant());
        v.push(split_invalid_variant());
        assert_from_coord_error_accepted::<SplitResidualError>(v);
        // Rejected: WrongStatus, CursorRegression, CursorOutOfBounds,
        //           CheckpointMissingKey
    }

    #[test]
    fn renew_error_from_coord_error_exhaustive() {
        let v = common_precondition_variants();
        assert_from_coord_error_accepted::<RenewError>(v);
        // Rejected: WrongStatus, OpIdConflict, CursorRegression,
        //           CursorOutOfBounds, SplitInvalid, CheckpointMissingKey
    }

    // -- Display + Security tests ----------------------------------------

    #[test]
    fn coord_error_display_no_actual_tenant() {
        let err = CoordError::TenantMismatch {
            expected: test_tenant(),
        };
        let display = err.to_string();
        // The display must contain "expected" but must not leak an "actual" tenant.
        assert!(display.contains("expected"), "should mention expected");
        assert!(
            !display.contains("actual"),
            "must not contain 'actual' tenant: {display}"
        );
    }

    #[test]
    fn coord_error_display_already_leased_no_owner() {
        let err = AcquireError::AlreadyLeased {
            current_owner: WorkerId::from_raw(42),
            lease_deadline: LogicalTime::from_raw(999),
        };
        let display = err.to_string();
        // Deadline is ok to show, but worker identity must not leak.
        assert!(
            !display.contains("42"),
            "must not contain worker id: {display}"
        );
        assert!(display.contains("999"), "should contain deadline");
    }

    #[test]
    fn error_display_deterministic() {
        let errors: Vec<CoordError> = all_coord_error_variants();
        for err in &errors {
            let s1 = err.to_string();
            let s2 = err.to_string();
            assert_eq!(s1, s2, "Display must be deterministic");
        }
    }

    #[test]
    fn op_id_conflict_display_no_hash_leak() {
        let err = CoordError::OpIdConflict {
            op_id: OpId::from_raw(1),
            expected_hash: 0xDEAD_BEEF,
            actual_hash: 0xCAFE_BABE,
        };
        let display = err.to_string();
        assert!(
            !display.contains("DEAD") && !display.contains("CAFE"),
            "display must not leak hash values: {display}"
        );
        assert!(
            !display.contains("3735928559") && !display.contains("3405691582"),
            "display must not leak hash values as decimal: {display}"
        );
    }

    // -- source() chain tests --------------------------------------------

    #[test]
    fn coord_error_split_invalid_source_returns_inner() {
        let inner = SplitValidationError::NoChildren;
        let err = CoordError::SplitInvalid(inner.clone());
        let src = err.source().expect("SplitInvalid should return source");
        assert_eq!(src.to_string(), inner.to_string());
    }

    #[test]
    fn coord_error_non_split_source_returns_none() {
        let err = CoordError::ShardNotFound { shard: test_key() };
        assert!(err.source().is_none());
    }

    #[test]
    fn split_replace_error_source_propagates() {
        let inner = SplitValidationError::NoChildren;
        let err = SplitReplaceError::SplitInvalid(inner.clone());
        let src = err.source().expect("SplitInvalid should return source");
        assert_eq!(src.to_string(), inner.to_string());

        // Non-SplitInvalid variant returns None.
        let err = SplitReplaceError::ShardNotFound { shard: test_key() };
        assert!(err.source().is_none());
    }

    #[test]
    fn split_residual_error_source_propagates() {
        let inner = SplitValidationError::NoChildren;
        let err = SplitResidualError::SplitInvalid(inner.clone());
        let src = err.source().expect("SplitInvalid should return source");
        assert_eq!(src.to_string(), inner.to_string());

        // Non-SplitInvalid variant returns None.
        let err = SplitResidualError::ShardNotFound { shard: test_key() };
        assert!(err.source().is_none());
    }

    // -- PartialEq value-equality tests ----------------------------------

    #[test]
    fn coord_error_eq_compares_box_bytes_by_value() {
        let a = CoordError::CursorOutOfBounds {
            last_key: b"key".to_vec().into_boxed_slice(),
            spec_start: b"a".to_vec().into_boxed_slice(),
            spec_end: b"z".to_vec().into_boxed_slice(),
        };
        let b = CoordError::CursorOutOfBounds {
            last_key: b"key".to_vec().into_boxed_slice(),
            spec_start: b"a".to_vec().into_boxed_slice(),
            spec_end: b"z".to_vec().into_boxed_slice(),
        };
        // Different allocations, same content -- should be equal.
        assert_eq!(a, b);
    }

    #[test]
    fn cursor_regression_eq_compares_option_box_by_value() {
        let a = CoordError::CursorRegression {
            old_key: Some(b"old".to_vec().into_boxed_slice()),
            new_key: Some(b"new".to_vec().into_boxed_slice()),
        };
        let b = CoordError::CursorRegression {
            old_key: Some(b"old".to_vec().into_boxed_slice()),
            new_key: Some(b"new".to_vec().into_boxed_slice()),
        };
        assert_eq!(a, b);

        // None vs Some should not be equal.
        let c = CoordError::CursorRegression {
            old_key: None,
            new_key: Some(b"new".to_vec().into_boxed_slice()),
        };
        assert_ne!(a, c);
    }
}
