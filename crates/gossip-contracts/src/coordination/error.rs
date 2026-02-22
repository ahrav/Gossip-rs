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

use gossip_stdx::SlabFull;

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
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },

    /// Cursor bounds violation: the cursor's `last_key` falls outside
    /// the shard's key range.
    ///
    /// Boxed to keep `CoordError` at ≤ 48 bytes (compile-time checked).
    ///
    /// Cursor bounds checking is a hard safety invariant.
    CursorOutOfBounds(Box<CursorOutOfBoundsDetail>),

    /// Split validation failed. Wraps the detailed error from
    /// `validate_split_coverage` / `validate_residual_split`.
    ///
    /// Boxed to keep `CoordError` at ≤ 48 bytes (compile-time checked).
    SplitInvalid(Box<SplitValidationError>),

    /// Checkpoint requires a `last_key` but the provided cursor has none.
    CheckpointMissingKey,
}

/// Detail payload for [`CoordError::CursorOutOfBounds`].
///
/// Captures the three values needed for a diagnostic message: the cursor
/// key that violated bounds and the shard spec's `[start, end)` range.
/// Boxed in `CoordError` to keep the enum at ~40 bytes.
///
/// `Debug` is manually implemented to show byte lengths rather than raw
/// key bytes, matching the redaction policy for cursor data.
#[derive(Clone, PartialEq, Eq)]
pub struct CursorOutOfBoundsDetail {
    /// The cursor key that fell outside the shard's range.
    pub last_key: Box<[u8]>,
    /// Inclusive lower bound of the shard's key range.
    pub spec_start: Box<[u8]>,
    /// Exclusive upper bound of the shard's key range.
    pub spec_end: Box<[u8]>,
}

impl fmt::Debug for CursorOutOfBoundsDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CursorOutOfBoundsDetail")
            .field("last_key", &format_args!("[{} bytes]", self.last_key.len()))
            .field(
                "spec_start",
                &format_args!("[{} bytes]", self.spec_start.len()),
            )
            .field("spec_end", &format_args!("[{} bytes]", self.spec_end.len()))
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
            Self::CursorRegression { old_key, new_key } => {
                let redact = |k: &Option<Box<[u8]>>| match k {
                    Some(b) => format!("Some([{} bytes])", b.len()),
                    None => "None".to_string(),
                };
                f.debug_struct("CursorRegression")
                    .field("old_key", &redact(old_key))
                    .field("new_key", &redact(new_key))
                    .finish()
            }
            Self::CursorOutOfBounds(detail) => {
                f.debug_tuple("CursorOutOfBounds").field(detail).finish()
            }
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
                detail.last_key.len()
            ),
            Self::SplitInvalid(inner) => write!(f, "split invalid: {inner}"),
            Self::CheckpointMissingKey => write!(f, "checkpoint requires a last_key"),
        }
    }
}

impl std::error::Error for CoordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SplitInvalid(inner) => Some(inner.as_ref()),
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
/// `CursorRegression`, `CursorOutOfBounds`, and `CheckpointMissingKey`.
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
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },
    /// See [`CoordError::CursorOutOfBounds`].
    CursorOutOfBounds(Box<CursorOutOfBoundsDetail>),
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
            Self::CursorRegression { old_key, new_key } => {
                let redact = |k: &Option<Box<[u8]>>| match k {
                    Some(b) => format!("Some([{} bytes])", b.len()),
                    None => "None".to_string(),
                };
                f.debug_struct("CursorRegression")
                    .field("old_key", &redact(old_key))
                    .field("new_key", &redact(new_key))
                    .finish()
            }
            Self::CursorOutOfBounds(detail) => {
                f.debug_tuple("CursorOutOfBounds").field(detail).finish()
            }
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
                detail.last_key.len()
            ),
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
        old_key: Option<Box<[u8]>>,
        new_key: Option<Box<[u8]>>,
    },
    /// See [`CoordError::CursorOutOfBounds`].
    CursorOutOfBounds(Box<CursorOutOfBoundsDetail>),
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
            Self::CursorRegression { old_key, new_key } => {
                let redact = |k: &Option<Box<[u8]>>| match k {
                    Some(b) => format!("Some([{} bytes])", b.len()),
                    None => "None".to_string(),
                };
                f.debug_struct("CursorRegression")
                    .field("old_key", &redact(old_key))
                    .field("new_key", &redact(new_key))
                    .finish()
            }
            Self::CursorOutOfBounds(detail) => {
                f.debug_tuple("CursorOutOfBounds").field(detail).finish()
            }
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
                detail.last_key.len()
            ),
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
    SplitInvalid(Box<SplitValidationError>),
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
            Self::SplitInvalid(inner) => Some(inner.as_ref()),
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
            CoordError::CursorOutOfBounds(detail) => Self::CursorOutOfBounds(detail),
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
/// for acquisition in the run after the operation completed.  Workers
/// may use this to inform backoff decisions (e.g., backing off when
/// `available_count` is zero, scheduling retry near `earliest_deadline`).
///
/// This is fail-open advisory metadata — it does not affect correctness.
/// The hint is a point-in-time snapshot that may be stale by the time
/// the caller reads it.  Workers MUST NOT rely on these values for
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
    pub capacity: CapacityHint,
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

// Compile-time size assertions: these types live on hot-path return types.
// RenewResult is Copy (two scalars + CapacityHint), so should stay compact.
// AcquireResult contains ShardSnapshot with inline SpawnedList, so its size
// is larger than a pure-pointer layout but still bounded.
const _: () = assert!(core::mem::size_of::<RenewResult>() <= 32);
const _: () = assert!(core::mem::size_of::<AcquireResult>() <= 288);

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
/// Callers generally don't need to distinguish -- the result is the same
/// either way. Use [`into_inner`](Self::into_inner) to discard the
/// execution-path metadata. The `Executed` vs `Replayed` distinction
/// exists for observability: metrics can track retry rates, and logging
/// can flag unexpected replay storms.
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
// on every coordination call path. The 48-byte ceiling (with ~40 bytes
// actual) is maintained by boxing the large payloads (CursorOutOfBounds,
// SplitInvalid). Exceeding this budget inflates every Result that wraps
// an operation-specific error type (which embeds the same variants).
#[cfg(test)]
const _: () = {
    assert!(std::mem::size_of::<CoordError>() <= 48);
};

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
