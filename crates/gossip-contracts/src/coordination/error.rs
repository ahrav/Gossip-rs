//! Error types, result types, and idempotent outcome wrapper for
//! the coordination protocol.
//!
//! ## Architecture
//!
//! [`CoordError`] is the shared building block. Each coordination operation
//! has a dedicated error type ([`CheckpointError`], [`CompleteError`], etc.)
//! that accepts only the [`CoordError`] variants semantically valid for that
//! operation. This gives callers precise `match` arms: a [`CheckpointError`]
//! can never produce `AlreadyLeased`, and a [`RenewError`] can never produce
//! `OpIdConflict`.
//!
//! The tradeoff is boilerplate `From<CoordError>` impls -- one per operation
//! error type -- which are finite and mechanical.
//!
//! ## Compile-Time Exhaustiveness
//!
//! The `From<CoordError>` impls enumerate all rejected variants explicitly
//! rather than using a wildcard `_` catch-all. This means adding a new
//! `CoordError` variant triggers a compile error in every `From` impl,
//! forcing a conscious decision about where the new variant maps.
//!
//! All error enums are `#[non_exhaustive]` so that adding variants is a
//! non-breaking change for downstream crate consumers who match on them.
//!
//! ## Variant Routing Matrix
//!
//! Each operation error type accepts a subset of `CoordError` variants via
//! its `From<CoordError>` impl. Rejected variants panic at `unreachable!()`.
//!
//! | `CoordError` variant   | Renew | Checkpoint | Complete | Park | Split |
//! |------------------------|:-----:|:----------:|:--------:|:----:|:-----:|
//! | `ShardNotFound`        |  yes  |    yes     |   yes    | yes  |  yes  |
//! | `TenantMismatch`       |  yes  |    yes     |   yes    | yes  |  yes  |
//! | `StaleFence`           |  yes  |    yes     |   yes    | yes  |  yes  |
//! | `LeaseExpired`         |  yes  |    yes     |   yes    | yes  |  yes  |
//! | `ShardTerminal`        |  yes  |    yes     |   yes    | yes  |  yes  |
//! | `OpIdConflict`         |   --  |    yes     |   yes    | yes  |  yes  |
//! | `CursorRegression`     |   --  |    yes     |   yes    |  --  |   --  |
//! | `CursorOutOfBounds`    |   --  |    yes     |   yes    |  --  |   --  |
//! | `CursorKeyTooLarge`    |   --  |    yes     |   yes    |  --  |   --  |
//! | `CursorTokenTooLarge`  |   --  |    yes     |   yes    |  --  |   --  |
//! | `SplitInvalid`         |   --  |     --     |    --    |  --  |  yes  |
//! | `CheckpointMissingKey` |   --  |    yes     |   yes    |  --  |   --  |
//!
//! [`AcquireError`] is not in the table because it has **no**
//! `From<CoordError>` impl. It defines its own variants directly
//! (`ShardNotFound`, `TenantMismatch`, `ShardTerminal`, `AlreadyLeased`)
//! because acquire does not require a pre-existing lease and therefore
//! cannot produce `StaleFence` or `LeaseExpired`.
//!
//! ## Security: Debug and Display Redaction
//!
//! Custom `Debug` and `Display` impls on error types redact sensitive
//! fields to prevent information leakage in logs and error messages:
//!
//! - **`OpIdConflict`**: hash values are redacted in `Debug` and omitted
//!   from `Display` (prevents oracle attacks on payload hashing).
//! - **`AlreadyLeased`**: `current_owner` (worker identity) is redacted
//!   in both `Debug` and `Display`.
//! - **`CursorRegression` / `CursorOutOfBounds`**: raw key bytes are
//!   replaced with byte-length summaries (prevents data exfiltration).
//! - **`TenantMismatch`**: only the caller's `expected` tenant is shown;
//!   the record's actual tenant is deliberately omitted to prevent
//!   cross-tenant enumeration.
//!
//! ## OpId CSPRNG Requirement
//!
//! `OpId` values MUST be generated via a cryptographically secure PRNG
//! (e.g., `rand::rngs::OsRng`) or a coordinated counter to prevent
//! accidental collisions. Two independent workers using the same `OpId`
//! for different operations will trigger `OpIdConflict`, which is
//! indistinguishable from a legitimate retry with a corrupted payload.

use std::fmt;

use gossip_stdx::{InlineVec, SlabFull};

use crate::coordination::cursor::{CursorUpdate, MAX_KEY_SIZE, MAX_TOKEN_SIZE};
use crate::coordination::lease::Lease;
use crate::coordination::record::ShardStatus;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpecRef, SplitValidationError};
use crate::coordination::split::MAX_SPAWNED_PER_SHARD;
use crate::identity::{FenceEpoch, LogicalTime, OpId, ShardId, ShardKey, TenantId, WorkerId};

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
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoordError {
    /// The shard does not exist in the coordination store.
    ShardNotFound { shard: ShardKey },

    /// Tenant isolation violation: the request's tenant does not match
    /// the shard record's tenant. This is always a bug.
    ///
    /// Only `expected` (the caller's tenant) is exposed. The actual
    /// tenant is deliberately omitted to prevent cross-tenant enumeration.
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

    /// Idempotency conflict: the OpId was previously used with a
    /// different payload hash. This is always a client bug -- accidental
    /// reuse of an OpId for a semantically different operation.
    ///
    /// `OpId` values must be generated via CSPRNG or a coordinated
    /// counter to prevent collisions.
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
    /// Cursor monotonicity is a hard safety invariant.
    CursorRegression {
        old_key: Option<usize>,
        new_key: Option<usize>,
    },

    /// Cursor bounds violation: the cursor's `last_key` falls outside
    /// the shard's key range.
    ///
    /// Cursor bounds checking is a hard safety invariant.
    CursorOutOfBounds(CursorOutOfBoundsDetail),

    /// Cursor key exceeds the maximum allowed length.
    ///
    /// Emitted by `validate_cursor_update_pooled` before monotonicity/bounds checks.
    CursorKeyTooLarge { size: usize, max: usize },

    /// Cursor token exceeds the maximum allowed length.
    ///
    /// Emitted by `validate_cursor_update_pooled` before storing the token in the slab.
    CursorTokenTooLarge { size: usize, max: usize },

    /// Split validation failed. Wraps the detailed error from
    /// `validate_split_coverage` / `validate_residual_split`.
    ///
    SplitInvalid(SplitValidationError),

    /// Checkpoint requires a `last_key` but the provided cursor has none.
    CheckpointMissingKey,
}

/// Detail payload for [`CoordError::CursorOutOfBounds`].
///
/// Captures redacted lengths for the cursor key that violated bounds and
/// the shard spec's `[start, end)` range.
///
/// `Debug` is manually implemented to show byte lengths rather than raw
/// key bytes, matching the redaction policy for cursor data.
#[derive(Clone, PartialEq, Eq)]
pub struct CursorOutOfBoundsDetail {
    /// Length of the cursor key that fell outside the shard's range.
    pub last_key: usize,
    /// Length of the inclusive lower bound of the shard's key range.
    pub spec_start: usize,
    /// Length of the exclusive upper bound of the shard's key range.
    pub spec_end: usize,
}

#[derive(Clone, Copy)]
struct RedactedOptionalLen(Option<usize>);

impl fmt::Debug for RedactedOptionalLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(len) => write!(f, "Some([{len} bytes])"),
            None => write!(f, "None"),
        }
    }
}

impl fmt::Debug for CursorOutOfBoundsDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CursorOutOfBoundsDetail")
            .field("last_key", &format_args!("[{} bytes]", self.last_key))
            .field("spec_start", &format_args!("[{} bytes]", self.spec_start))
            .field("spec_end", &format_args!("[{} bytes]", self.spec_end))
            .finish()
    }
}

// Custom Debug: redacts sensitive fields -- hash values in OpIdConflict,
// raw key bytes in CursorRegression and CursorOutOfBounds.
impl fmt::Debug for CoordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => f
                .debug_struct("ShardNotFound")
                .field("shard", shard)
                .finish(),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::StaleFence { presented, current } => f
                .debug_struct("StaleFence")
                .field("presented", presented)
                .field("current", current)
                .finish(),
            Self::LeaseExpired { deadline, now } => f
                .debug_struct("LeaseExpired")
                .field("deadline", deadline)
                .field("now", now)
                .finish(),
            Self::ShardTerminal { shard, status } => f
                .debug_struct("ShardTerminal")
                .field("shard", shard)
                .field("status", status)
                .finish(),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
            Self::CursorRegression { old_key, new_key } => f
                .debug_struct("CursorRegression")
                .field("old_key", &RedactedOptionalLen(*old_key))
                .field("new_key", &RedactedOptionalLen(*new_key))
                .finish(),
            Self::CursorOutOfBounds(detail) => {
                f.debug_tuple("CursorOutOfBounds").field(detail).finish()
            }
            Self::CursorKeyTooLarge { size, max } => f
                .debug_struct("CursorKeyTooLarge")
                .field("size", size)
                .field("max", max)
                .finish(),
            Self::CursorTokenTooLarge { size, max } => f
                .debug_struct("CursorTokenTooLarge")
                .field("size", size)
                .field("max", max)
                .finish(),
            Self::SplitInvalid(inner) => f.debug_tuple("SplitInvalid").field(inner).finish(),
            Self::CheckpointMissingKey => write!(f, "CheckpointMissingKey"),
        }
    }
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
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
            Self::CursorRegression { .. } => write!(f, "cursor regression: new key < old key"),
            Self::CursorOutOfBounds(detail) => write!(
                f,
                "cursor out of bounds: key ({} bytes) outside shard range",
                detail.last_key
            ),
            Self::CursorKeyTooLarge { size, max } => {
                write!(f, "cursor key too large ({size} bytes, max {max})")
            }
            Self::CursorTokenTooLarge { size, max } => {
                write!(f, "cursor token too large ({size} bytes, max {max})")
            }
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

/// Error from `acquire_and_restore_into`.
///
/// Acquire is special: it does NOT require a pre-existing lease, so
/// it cannot produce `StaleFence` or `LeaseExpired`. It can fail if
/// the shard is terminal, or if another worker holds a live lease.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcquireError {
    /// The shard does not exist.
    ShardNotFound { shard: ShardKey },

    /// Tenant isolation violation.
    ///
    /// Only `expected` (the caller's tenant) is exposed.
    TenantMismatch { expected: TenantId },

    /// The shard is terminal -- cannot be acquired.
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },

    /// Another worker currently holds a valid (non-expired) lease.
    /// The caller must wait or try a different shard.
    ///
    /// **Security note:** `current_owner` exposes worker identity.
    /// Redact this field before surfacing to external clients.
    AlreadyLeased {
        current_owner: WorkerId,
        lease_deadline: LogicalTime,
    },
}

// Custom Debug: redacts `current_owner` to prevent worker identity
// leakage. Display already redacts via `..`.
impl fmt::Debug for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => f
                .debug_struct("ShardNotFound")
                .field("shard", shard)
                .finish(),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::ShardTerminal { shard, status } => f
                .debug_struct("ShardTerminal")
                .field("shard", shard)
                .field("status", status)
                .finish(),
            Self::AlreadyLeased { lease_deadline, .. } => f
                .debug_struct("AlreadyLeased")
                .field("current_owner", &"<redacted>")
                .field("lease_deadline", lease_deadline)
                .finish(),
        }
    }
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
            // Omit current_owner in Display output (redact worker identity).
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
#[non_exhaustive]
pub enum RenewError {
    /// See [`CoordError::ShardNotFound`].
    ShardNotFound { shard: ShardKey },
    /// See [`CoordError::TenantMismatch`].
    TenantMismatch { expected: TenantId },
    /// See [`CoordError::StaleFence`].
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// See [`CoordError::LeaseExpired`].
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    /// See [`CoordError::ShardTerminal`].
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
/// `CursorRegression`, `CursorOutOfBounds`, `CursorKeyTooLarge`, and
/// `CheckpointMissingKey`.
/// It excludes only `SplitInvalid`.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckpointError {
    /// See [`CoordError::ShardNotFound`].
    ShardNotFound { shard: ShardKey },
    /// See [`CoordError::TenantMismatch`].
    TenantMismatch { expected: TenantId },
    /// See [`CoordError::StaleFence`].
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// See [`CoordError::LeaseExpired`].
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    /// See [`CoordError::ShardTerminal`].
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    /// See [`CoordError::OpIdConflict`].
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
    /// See [`CoordError::CursorRegression`].
    CursorRegression {
        old_key: Option<usize>,
        new_key: Option<usize>,
    },
    /// See [`CoordError::CursorOutOfBounds`].
    CursorOutOfBounds(CursorOutOfBoundsDetail),
    /// See [`CoordError::CursorKeyTooLarge`].
    CursorKeyTooLarge { size: usize, max: usize },
    /// See [`CoordError::CursorTokenTooLarge`].
    CursorTokenTooLarge { size: usize, max: usize },
    /// The checkpoint cursor did not contain a `last_key`, which is required
    /// to track scan progress.
    CheckpointMissingKey,
    /// The byte slab could not satisfy an allocation request.
    /// Recoverable: the caller may retry after freeing slab space.
    ResourceExhausted(SlabFull),
}

impl fmt::Debug for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => f
                .debug_struct("ShardNotFound")
                .field("shard", shard)
                .finish(),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::StaleFence { presented, current } => f
                .debug_struct("StaleFence")
                .field("presented", presented)
                .field("current", current)
                .finish(),
            Self::LeaseExpired { deadline, now } => f
                .debug_struct("LeaseExpired")
                .field("deadline", deadline)
                .field("now", now)
                .finish(),
            Self::ShardTerminal { shard, status } => f
                .debug_struct("ShardTerminal")
                .field("shard", shard)
                .field("status", status)
                .finish(),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
            Self::CursorRegression { old_key, new_key } => f
                .debug_struct("CursorRegression")
                .field("old_key", &RedactedOptionalLen(*old_key))
                .field("new_key", &RedactedOptionalLen(*new_key))
                .finish(),
            Self::CursorOutOfBounds(detail) => {
                f.debug_tuple("CursorOutOfBounds").field(detail).finish()
            }
            Self::CursorKeyTooLarge { size, max } => f
                .debug_struct("CursorKeyTooLarge")
                .field("size", size)
                .field("max", max)
                .finish(),
            Self::CursorTokenTooLarge { size, max } => f
                .debug_struct("CursorTokenTooLarge")
                .field("size", size)
                .field("max", max)
                .finish(),
            Self::CheckpointMissingKey => write!(f, "CheckpointMissingKey"),
            Self::ResourceExhausted(e) => f.debug_tuple("ResourceExhausted").field(e).finish(),
        }
    }
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
            Self::CursorOutOfBounds(detail) => write!(
                f,
                "cursor out of bounds: key ({} bytes) outside shard range",
                detail.last_key
            ),
            Self::CursorKeyTooLarge { size, max } => {
                write!(f, "cursor key too large ({size} bytes, max {max})")
            }
            Self::CursorTokenTooLarge { size, max } => {
                write!(f, "cursor token too large ({size} bytes, max {max})")
            }
            Self::CheckpointMissingKey => write!(f, "checkpoint requires a last_key"),
            Self::ResourceExhausted(e) => write!(f, "slab full: {e}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

impl From<SlabFull> for CheckpointError {
    fn from(e: SlabFull) -> Self {
        Self::ResourceExhausted(e)
    }
}

/// Error from `complete`.
///
/// Complete shares most variants with [`CheckpointError`] (idempotency,
/// cursor checks) because it records a final cursor position. It excludes
/// `SplitInvalid`. The `CheckpointMissingKey` variant
/// here means the worker did not supply a `last_key` proving it reached
/// the end of its assigned range.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteError {
    /// See [`CoordError::ShardNotFound`].
    ShardNotFound { shard: ShardKey },
    /// See [`CoordError::TenantMismatch`].
    TenantMismatch { expected: TenantId },
    /// See [`CoordError::StaleFence`].
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// See [`CoordError::LeaseExpired`].
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    /// See [`CoordError::ShardTerminal`].
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    /// See [`CoordError::OpIdConflict`].
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
    /// See [`CoordError::CursorRegression`].
    CursorRegression {
        old_key: Option<usize>,
        new_key: Option<usize>,
    },
    /// See [`CoordError::CursorOutOfBounds`].
    CursorOutOfBounds(CursorOutOfBoundsDetail),
    /// See [`CoordError::CursorKeyTooLarge`].
    CursorKeyTooLarge { size: usize, max: usize },
    /// See [`CoordError::CursorTokenTooLarge`].
    CursorTokenTooLarge { size: usize, max: usize },
    /// Complete requires a final cursor with a `last_key` to confirm
    /// the worker reached the end of its assigned range.
    CheckpointMissingKey,
    /// The byte slab could not satisfy an allocation request.
    /// Recoverable: the caller may retry after freeing slab space.
    ResourceExhausted(SlabFull),
}

impl fmt::Debug for CompleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => f
                .debug_struct("ShardNotFound")
                .field("shard", shard)
                .finish(),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::StaleFence { presented, current } => f
                .debug_struct("StaleFence")
                .field("presented", presented)
                .field("current", current)
                .finish(),
            Self::LeaseExpired { deadline, now } => f
                .debug_struct("LeaseExpired")
                .field("deadline", deadline)
                .field("now", now)
                .finish(),
            Self::ShardTerminal { shard, status } => f
                .debug_struct("ShardTerminal")
                .field("shard", shard)
                .field("status", status)
                .finish(),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
            Self::CursorRegression { old_key, new_key } => f
                .debug_struct("CursorRegression")
                .field("old_key", &RedactedOptionalLen(*old_key))
                .field("new_key", &RedactedOptionalLen(*new_key))
                .finish(),
            Self::CursorOutOfBounds(detail) => {
                f.debug_tuple("CursorOutOfBounds").field(detail).finish()
            }
            Self::CursorKeyTooLarge { size, max } => f
                .debug_struct("CursorKeyTooLarge")
                .field("size", size)
                .field("max", max)
                .finish(),
            Self::CursorTokenTooLarge { size, max } => f
                .debug_struct("CursorTokenTooLarge")
                .field("size", size)
                .field("max", max)
                .finish(),
            Self::CheckpointMissingKey => write!(f, "CheckpointMissingKey"),
            Self::ResourceExhausted(e) => f.debug_tuple("ResourceExhausted").field(e).finish(),
        }
    }
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
            Self::CursorRegression { .. } => write!(f, "cursor regression: new key < old key"),
            Self::CursorOutOfBounds(detail) => write!(
                f,
                "cursor out of bounds: key ({} bytes) outside shard range",
                detail.last_key
            ),
            Self::CursorKeyTooLarge { size, max } => {
                write!(f, "cursor key too large ({size} bytes, max {max})")
            }
            Self::CursorTokenTooLarge { size, max } => {
                write!(f, "cursor token too large ({size} bytes, max {max})")
            }
            Self::CheckpointMissingKey => write!(f, "complete requires a last_key"),
            Self::ResourceExhausted(e) => write!(f, "slab full: {e}"),
        }
    }
}

impl std::error::Error for CompleteError {}

impl From<SlabFull> for CompleteError {
    fn from(e: SlabFull) -> Self {
        Self::ResourceExhausted(e)
    }
}

/// Error from `park_shard`.
///
/// Park transitions a shard to the `Parked` terminal state. It is
/// idempotent (carries `OpIdConflict`) but does not advance the cursor,
/// so it excludes all cursor variants and `CheckpointMissingKey`.
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParkError {
    /// See [`CoordError::ShardNotFound`].
    ShardNotFound { shard: ShardKey },
    /// See [`CoordError::TenantMismatch`].
    TenantMismatch { expected: TenantId },
    /// See [`CoordError::StaleFence`].
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// See [`CoordError::LeaseExpired`].
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    /// See [`CoordError::ShardTerminal`].
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    /// See [`CoordError::OpIdConflict`].
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

impl fmt::Debug for ParkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => f
                .debug_struct("ShardNotFound")
                .field("shard", shard)
                .finish(),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::StaleFence { presented, current } => f
                .debug_struct("StaleFence")
                .field("presented", presented)
                .field("current", current)
                .finish(),
            Self::LeaseExpired { deadline, now } => f
                .debug_struct("LeaseExpired")
                .field("deadline", deadline)
                .field("now", now)
                .finish(),
            Self::ShardTerminal { shard, status } => f
                .debug_struct("ShardTerminal")
                .field("shard", shard)
                .field("status", status)
                .finish(),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
        }
    }
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

/// Error from split operations (`split_replace` and `split_residual`).
///
/// Both split operations share identical error surfaces: common
/// preconditions, `OpIdConflict`, and `SplitInvalid`, with no cursor
/// variants or `CheckpointMissingKey` (splits do not advance a scan
/// cursor).
///
/// See [`CoordError`] variant docs for detailed semantics of each field.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SplitError {
    /// See [`CoordError::ShardNotFound`].
    ShardNotFound { shard: ShardKey },
    /// See [`CoordError::TenantMismatch`].
    TenantMismatch { expected: TenantId },
    /// See [`CoordError::StaleFence`].
    StaleFence {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// See [`CoordError::LeaseExpired`].
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    /// See [`CoordError::ShardTerminal`].
    ShardTerminal {
        shard: ShardKey,
        status: ShardStatus,
    },
    /// See [`CoordError::OpIdConflict`].
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
    /// See [`CoordError::SplitInvalid`].
    SplitInvalid(SplitValidationError),
    /// The byte slab could not satisfy an allocation request.
    /// Recoverable: the caller may retry after freeing slab space.
    ResourceExhausted(SlabFull),
}

impl fmt::Debug for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound { shard } => f
                .debug_struct("ShardNotFound")
                .field("shard", shard)
                .finish(),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::StaleFence { presented, current } => f
                .debug_struct("StaleFence")
                .field("presented", presented)
                .field("current", current)
                .finish(),
            Self::LeaseExpired { deadline, now } => f
                .debug_struct("LeaseExpired")
                .field("deadline", deadline)
                .field("now", now)
                .finish(),
            Self::ShardTerminal { shard, status } => f
                .debug_struct("ShardTerminal")
                .field("shard", shard)
                .field("status", status)
                .finish(),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
            Self::SplitInvalid(inner) => f.debug_tuple("SplitInvalid").field(inner).finish(),
            Self::ResourceExhausted(e) => f.debug_tuple("ResourceExhausted").field(e).finish(),
        }
    }
}

/// Semantic alias: `split_replace` returns this type.
///
/// Both split operations share the same error surface, so this is
/// a type alias rather than a distinct enum.
pub type SplitReplaceError = SplitError;

/// Semantic alias: `split_residual` returns this type.
///
/// Both split operations share the same error surface, so this is
/// a type alias rather than a distinct enum.
pub type SplitResidualError = SplitError;

impl fmt::Display for SplitError {
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
            Self::ResourceExhausted(e) => write!(f, "slab full: {e}"),
        }
    }
}

impl std::error::Error for SplitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SplitInvalid(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<SlabFull> for SplitError {
    fn from(e: SlabFull) -> Self {
        Self::ResourceExhausted(e)
    }
}

// ============================================================================
// From<CoordError> impls -- explicit rejection arms
// ============================================================================

// These impls are the routing layer between the shared `CoordError` (returned
// by `validate_lease`, `check_op_idempotency`, etc.) and the per-operation
// error types (returned to callers). The `?` operator in backend methods
// uses these conversions automatically.
//
// Every impl explicitly enumerates rejected variants (mapped to
// `unreachable!()`) rather than using a wildcard `_` arm. This is the
// compile-time exhaustiveness strategy documented in the module-level docs:
// adding a new `CoordError` variant triggers a compile error in every impl,
// forcing a conscious routing decision for the new variant.

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
            CoordError::CursorOutOfBounds(detail) => Self::CursorOutOfBounds(detail),
            CoordError::CursorKeyTooLarge { size, max } => Self::CursorKeyTooLarge { size, max },
            CoordError::CursorTokenTooLarge { size, max } => {
                Self::CursorTokenTooLarge { size, max }
            }
            CoordError::CheckpointMissingKey => Self::CheckpointMissingKey,
            // Explicitly reject all variants CheckpointError does not cover.
            // Adding a new CoordError variant triggers a compile error here.
            CoordError::SplitInvalid(_) => {
                unreachable!("CoordError::{e} is not valid for CheckpointError")
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
            CoordError::CursorRegression { old_key, new_key } => {
                Self::CursorRegression { old_key, new_key }
            }
            CoordError::CursorOutOfBounds(detail) => Self::CursorOutOfBounds(detail),
            CoordError::CursorKeyTooLarge { size, max } => Self::CursorKeyTooLarge { size, max },
            CoordError::CursorTokenTooLarge { size, max } => {
                Self::CursorTokenTooLarge { size, max }
            }
            CoordError::CheckpointMissingKey => Self::CheckpointMissingKey,
            // Explicitly reject all variants CompleteError does not cover.
            CoordError::SplitInvalid(_) => {
                unreachable!("CoordError::{e} is not valid for CompleteError")
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
            CoordError::CursorRegression { .. }
            | CoordError::CursorOutOfBounds(_)
            | CoordError::CursorKeyTooLarge { .. }
            | CoordError::CursorTokenTooLarge { .. }
            | CoordError::SplitInvalid(_)
            | CoordError::CheckpointMissingKey => {
                unreachable!("CoordError::{e} is not valid for ParkError")
            }
        }
    }
}

impl From<CoordError> for SplitError {
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
            // Explicitly reject all variants SplitError does not cover.
            CoordError::CursorRegression { .. }
            | CoordError::CursorOutOfBounds(_)
            | CoordError::CursorKeyTooLarge { .. }
            | CoordError::CursorTokenTooLarge { .. }
            | CoordError::CheckpointMissingKey => {
                unreachable!("CoordError::{e} is not valid for SplitError")
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
            CoordError::OpIdConflict { .. }
            | CoordError::CursorRegression { .. }
            | CoordError::CursorOutOfBounds(_)
            | CoordError::CursorKeyTooLarge { .. }
            | CoordError::CursorTokenTooLarge { .. }
            | CoordError::SplitInvalid(_)
            | CoordError::CheckpointMissingKey => {
                unreachable!("CoordError::{e} is not valid for RenewError")
            }
        }
    }
}

// ============================================================================
// CapacityHint
// ============================================================================

/// Advisory capacity information piggybacked on acquire/renew results.
///
/// Represents the post-operation state: how many shards are available
/// for acquisition in the run after the operation completed. Workers
/// may use this to inform backoff decisions:
///
/// - `available_count == 0` with `earliest_deadline.is_some()`: all shards
///   are claimed — back off until at least `earliest_deadline`.
/// - `available_count == 0` with `earliest_deadline.is_none()`: all shards
///   are terminal or the run has none — stop trying.
/// - `available_count > 0`: shards are available — acquire immediately.
///
/// This is fail-open advisory metadata — it does not affect correctness.
/// The hint is a point-in-time snapshot that may be stale by the time
/// the caller reads it. Workers MUST NOT rely on these values for
/// safety-critical decisions.
///
/// Reference: Breakwater (Cho et al., OSDI 2020) — credit piggybacking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "capacity hint should inform backoff/retry decisions"]
pub struct CapacityHint {
    /// Number of active, unleased shards in the run at operation time.
    pub available_count: u32,
    /// Earliest lease deadline among all active leased shards.  `None`
    /// when no active shards are currently leased — either because all
    /// active shards are available (unleased), or because no active shards
    /// exist in the run (all terminal or run has no shards).  Callers can
    /// check `available_count` to distinguish the two cases.
    pub earliest_deadline: Option<LogicalTime>,
}

impl CapacityHint {
    /// Sentinel returned when capacity cannot be determined (e.g., the
    /// run has no registered shards yet).  `is_saturated()` returns
    /// `true` but `earliest_deadline` is `None`, meaning there is
    /// no lease to wait on.
    pub const ZERO: Self = Self {
        available_count: 0,
        earliest_deadline: None,
    };

    /// Whether all active shards in the run are currently claimed.
    #[inline]
    pub const fn is_saturated(self) -> bool {
        self.available_count == 0
    }
}

// Compile-time size assertion: CapacityHint is embedded in AcquireResult
// and RenewResult which live on hot-path Result<T, E> return types. Keeping
// it at or below 24 bytes avoids inflating those Result enums.
const _: () = assert!(core::mem::size_of::<CapacityHint>() <= 24);

// ============================================================================
// Operation result types
// ============================================================================

/// Borrowed view of shard state returned by `acquire_and_restore_into`.
///
/// This is the allocation-free shard snapshot form. Instead
/// of heap-backed `Box<[u8]>` fields, all byte data borrows from the
/// caller-owned [`AcquireScratch`]. The view is valid only until that
/// scratch is reused or dropped.
///
/// Consumers that need owned data must copy fields out explicitly before the
/// scratch buffer is reused.
///
/// `ShardSnapshotView` keeps the hot acquire path allocation-free by
/// borrowing from stack-allocated scratch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "snapshot view should be consumed before scratch is reused"]
pub struct ShardSnapshotView<'a> {
    status: ShardStatus,
    spec: ShardSpecRef<'a>,
    cursor: CursorUpdate<'a>,
    cursor_semantics: CursorSemantics,
    parent: Option<ShardId>,
    spawned: &'a [ShardId],
}

impl<'a> ShardSnapshotView<'a> {
    /// Lifecycle status at acquisition time.
    #[must_use]
    pub fn status(&self) -> ShardStatus {
        self.status
    }

    /// Borrowed shard spec view (range + metadata).
    #[must_use]
    pub fn spec(&self) -> ShardSpecRef<'a> {
        self.spec
    }

    /// Borrowed cursor view captured at acquisition time.
    #[must_use]
    pub fn cursor(&self) -> CursorUpdate<'a> {
        self.cursor
    }

    /// Cursor semantics configured for the run.
    #[must_use]
    pub fn cursor_semantics(&self) -> CursorSemantics {
        self.cursor_semantics
    }

    /// Parent shard ID when this shard was split from another.
    #[must_use]
    pub fn parent(&self) -> Option<ShardId> {
        self.parent
    }

    /// Borrowed list of spawned child shard IDs.
    #[must_use]
    pub fn spawned(&self) -> &'a [ShardId] {
        self.spawned
    }
}

/// Borrowed acquire result that references caller-owned [`AcquireScratch`].
///
/// This is the allocation-free return type from `acquire_and_restore_into`.
/// The lease is `Copy` (small fixed-size struct), but the snapshot borrows
/// variable-size byte fields from the scratch buffer.
///
/// The `capacity` field is advisory metadata for backoff decisions; see
/// [`CapacityHint`] for usage guidance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "contains a lease and borrowed snapshot view"]
pub struct AcquireResultView<'a> {
    pub lease: Lease,
    pub snapshot: ShardSnapshotView<'a>,
    pub capacity: CapacityHint,
}

/// Fixed-capacity byte buffer with logical length tracking.
#[derive(Debug)]
struct FixedBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    #[inline]
    const fn new() -> Self {
        Self {
            bytes: [0u8; N],
            len: 0,
        }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8], oversized_msg: &'static str) {
        assert!(bytes.len() <= N, "{oversized_msg}");
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len();
    }

    #[inline]
    fn read(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[inline]
    fn reset(&mut self) {
        self.len = 0;
    }

    #[inline]
    fn has_data(&self) -> bool {
        self.len > 0
    }
}

/// Caller-owned scratch buffer for allocation-free acquire snapshots.
///
/// `AcquireScratch` pre-allocates fixed-capacity arrays on the stack (or
/// wherever the caller places it) for every variable-size field in a shard
/// snapshot: spec start/end, metadata, cursor last_key, cursor token, and
/// spawned shard IDs. The coordinator writes into these arrays during
/// `acquire_and_restore_into`, and the caller reads from them via the
/// returned [`AcquireResultView`].
///
/// ## Usage Pattern
///
/// ```text
/// let mut scratch = AcquireScratch::new();  // once per session
/// loop {
///     let view = backend.acquire_and_restore_into(now, tenant, key, worker, &mut scratch)?;
///     // use view.snapshot.spec(), view.snapshot.cursor(), etc.
///     // scratch is overwritten on next call — view is invalidated
/// }
/// ```
///
/// ## Invalidation
///
/// Methods on this type overwrite internal storage; any previously returned
/// [`ShardSnapshotView`] must be treated as invalid after the next write/reset.
/// The Rust borrow checker enforces this: `acquire_and_restore_into` takes
/// `&'a mut AcquireScratch` and returns `AcquireResultView<'a>`, preventing
/// the caller from calling it again while the view is still live.
///
/// ## Size
///
/// The scratch is intentionally large because it stores fixed-capacity buffers
/// for spec/cursor fields and spawned lineage IDs. Prefer heap allocation
/// (`Box::new(AcquireScratch::new())`) when stack size is a concern, and reuse
/// the same instance across calls.
#[derive(Debug)]
pub struct AcquireScratch {
    spec_start: FixedBuf<MAX_KEY_SIZE>,
    spec_end: FixedBuf<MAX_KEY_SIZE>,
    spec_metadata: FixedBuf<{ crate::coordination::shard_spec::MAX_METADATA_SIZE }>,
    cursor_last_key: FixedBuf<MAX_KEY_SIZE>,
    cursor_token: FixedBuf<MAX_TOKEN_SIZE>,
    spawned: InlineVec<ShardId, MAX_SPAWNED_PER_SHARD>,
}

impl Default for AcquireScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl AcquireScratch {
    /// Create empty reusable scratch with fixed-capacity internal buffers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spec_start: FixedBuf::new(),
            spec_end: FixedBuf::new(),
            spec_metadata: FixedBuf::new(),
            cursor_last_key: FixedBuf::new(),
            cursor_token: FixedBuf::new(),
            spawned: InlineVec::new(),
        }
    }

    /// Reset logical lengths without clearing backing bytes.
    ///
    /// Existing borrowed views become stale after reset.
    pub(crate) fn reset(&mut self) {
        self.spec_start.reset();
        self.spec_end.reset();
        self.spec_metadata.reset();
        self.cursor_last_key.reset();
        self.cursor_token.reset();
        self.spawned = InlineVec::new();
    }

    /// Copy spec bytes into scratch-owned storage.
    ///
    /// Inputs are validated against shard/key metadata size ceilings and then
    /// copied. No caller references are retained.
    ///
    /// # Panics
    ///
    /// Panics if `start`, `end`, or `metadata` exceed their respective size
    /// ceilings. These asserts are defense-in-depth: callers read spec data
    /// from a `PooledShardSpec` slab that only stores pre-validated specs,
    /// so a ceiling breach here indicates slab corruption. Panicking
    /// immediately is safer than writing truncated data.
    pub(crate) fn write_spec(&mut self, start: &[u8], end: &[u8], metadata: &[u8]) {
        self.spec_start
            .write(start, "spec start exceeds MAX_KEY_SIZE");
        self.spec_end.write(end, "spec end exceeds MAX_KEY_SIZE");
        self.spec_metadata
            .write(metadata, "spec metadata exceeds MAX_METADATA_SIZE");
    }

    /// Copy cursor bytes into scratch-owned storage.
    ///
    /// `None` clears the corresponding field; `token` is stored only when
    /// present in input. No caller references are retained.
    /// Empty slices are treated as absent values because presence is derived
    /// from internal `len > 0`.
    ///
    /// # Panics
    ///
    /// Panics if `last_key` or `token` exceed their respective size ceilings.
    /// Same defense-in-depth rationale as [`write_spec`](Self::write_spec):
    /// cursor bytes originate from pooled slab storage that enforces size
    /// limits at write time, so a breach here is internal corruption.
    pub(crate) fn write_cursor(&mut self, last_key: Option<&[u8]>, token: Option<&[u8]>) {
        match last_key {
            Some(last_key) => {
                self.cursor_last_key
                    .write(last_key, "cursor last_key exceeds MAX_KEY_SIZE");
            }
            None => {
                self.cursor_last_key.reset();
            }
        }
        match token {
            Some(token) => {
                self.cursor_token
                    .write(token, "cursor token exceeds MAX_TOKEN_SIZE");
            }
            None => {
                self.cursor_token.reset();
            }
        }
    }

    /// Copy lineage IDs from an iterator into scratch-owned inline storage.
    ///
    /// This keeps acquire callers allocation-free even when upstream storage
    /// is not represented as a `&[ShardId]`.
    pub(crate) fn write_spawned_iter<I>(&mut self, spawned: I)
    where
        I: IntoIterator<Item = ShardId>,
    {
        self.spawned = InlineVec::new();
        for shard in spawned {
            assert!(
                self.spawned.len() < MAX_SPAWNED_PER_SHARD,
                "spawned lineage exceeds MAX_SPAWNED_PER_SHARD",
            );
            self.spawned.push(shard);
        }
    }

    /// Borrow a spec view over the currently written scratch bytes.
    fn spec_view(&self) -> ShardSpecRef<'_> {
        ShardSpecRef::new(
            self.spec_start.read(),
            self.spec_end.read(),
            self.spec_metadata.read(),
        )
    }

    /// Borrow a cursor view over the currently written scratch bytes.
    ///
    /// Invariant preserved: token-only state is never produced. If `last_key`
    /// is absent (including empty), this returns [`CursorUpdate::initial`]
    /// and drops any token bytes.
    fn cursor_view(&self) -> CursorUpdate<'_> {
        if !self.cursor_last_key.has_data() {
            return CursorUpdate::initial();
        }
        if self.cursor_token.has_data() {
            CursorUpdate::with_token(self.cursor_last_key.read(), self.cursor_token.read())
        } else {
            CursorUpdate::new(self.cursor_last_key.read())
        }
    }

    /// Build a borrowed snapshot view backed by this scratch buffer.
    ///
    /// Returned references remain valid only until this scratch is next
    /// mutated or dropped.
    pub(crate) fn view(
        &self,
        status: ShardStatus,
        cursor_semantics: CursorSemantics,
        parent: Option<ShardId>,
    ) -> ShardSnapshotView<'_> {
        ShardSnapshotView {
            status,
            spec: self.spec_view(),
            cursor: self.cursor_view(),
            cursor_semantics,
            parent,
            spawned: self.spawned.as_slice(),
        }
    }
}

/// Result of a successful `renew` operation.
///
/// Returns the new deadline. The fence epoch does not change on
/// renewal -- only on ownership transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "renew result contains the new deadline"]
pub struct RenewResult {
    pub new_deadline: LogicalTime,
    pub capacity: CapacityHint,
}

// Compile-time size assertion: this type lives on hot-path return values.
const _: () = assert!(core::mem::size_of::<RenewResult>() <= 32);

// Checkpoint, Complete, and Park return `IdempotentOutcome<()>` on
// success (the operation either executed or was replayed, with no
// meaningful return value beyond that distinction). SplitReplace and
// SplitResidual return `IdempotentOutcome<SplitReplaceResult>` and
// `IdempotentOutcome<SplitResidualResult>` respectively, carrying
// the newly created child shard identifiers.

// ============================================================================
// IdempotentOutcome
// ============================================================================

/// The outcome of an idempotent operation: either freshly executed or
/// replayed from the op-log.
///
/// ## Design Rationale
///
/// Most callers do not need to distinguish `Executed` from `Replayed` — the
/// result `T` is the same either way. Use [`into_inner`](Self::into_inner)
/// to discard the execution-path metadata. The distinction exists for two
/// observability use cases:
///
/// 1. **Retry rate tracking**: production metrics can count `is_replay()`
///    results to detect client-side retry storms or network instability.
/// 2. **Correctness auditing**: simulation tests can assert that a
///    deliberately-repeated operation returns `Replayed` (confirming the
///    op-log detected the duplicate) rather than silently re-executing.
///
/// ## Generic over `T`
///
/// - Checkpoint and complete return `IdempotentOutcome<()>` (the operation
///   either succeeded or was replayed, with no additional data).
/// - `split_replace` returns `IdempotentOutcome<SplitReplaceResult>` (carrying
///   the child shard IDs).
/// - `split_residual` returns `IdempotentOutcome<SplitResidualResult>`.
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
    #[inline]
    pub fn into_inner(self) -> T {
        match self {
            Self::Executed(v) | Self::Replayed(v) => v,
        }
    }

    /// Returns `true` if this was a replay (retry).
    #[inline]
    pub fn is_replay(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }

    /// Returns `true` if this was a first execution (not a replay).
    #[inline]
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed(_))
    }

    /// Map the inner value, preserving the execution/replay distinction.
    #[inline]
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

// Compile-time size assertion: CoordError is returned in Result<T, E>
// on every coordination call path. Keep this compact so operation-specific
// Result types stay small in hot paths.
#[cfg(test)]
const _: () = {
    assert!(std::mem::size_of::<CoordError>() <= 48);
};

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
