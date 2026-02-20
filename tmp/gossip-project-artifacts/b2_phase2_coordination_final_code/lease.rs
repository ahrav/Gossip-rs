//! Lease and per-shard op-log types.
//!
//! A `Lease` is the capability returned by `acquire_and_restore` and required
//! by lease-gated shard mutations. It contains a **fence epoch** used as a
//! fencing token.
//!
//! The op-log implements bounded idempotency per shard: mutating operations
//! (except `acquire_and_restore` and `renew`) carry an `OpId`. The shard record
//! caches the last N (cap=16) operation fingerprints so retries can be safely
//! replayed.

use crate::identity::{FenceEpoch, LogicalTime, OpId, RunId, ShardId, TenantId, WorkerId};

// ============================================================================
// § Lease
// ============================================================================

/// A lease grants exclusive, temporary rights to mutate a shard.
///
/// The `fence` field is a monotonically increasing epoch stored in the shard
/// record. Every time the shard is acquired (or administratively unparked), the
/// epoch increments. Workers must present the current fence epoch to mutate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub tenant: TenantId,
    pub run: RunId,
    pub shard: ShardId,
    pub owner: WorkerId,
    pub fence: FenceEpoch,
    pub deadline: LogicalTime,
}

// ============================================================================
// § OpKind / OpResult / OpLogEntry
// ============================================================================

/// Operation kinds that participate in per-shard idempotency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpKind {
    Checkpoint = 0,
    Complete = 1,
    Park = 2,
    SplitReplace = 3,
    SplitResidual = 4,
    /// Administrative (not lease-gated).
    Unpark = 5,
}

/// Stored result status for an executed operation.
///
/// The spec only needs `Completed` for Boundary 2, but keeping this as an enum
/// makes future extensions (e.g., storing failure metadata) easier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpResult {
    Completed = 0,
    Error = 1,
    Superseded = 2,
}

/// A single entry in the bounded per-shard operation log.
///
/// This log is used to safely replay retries when the client repeats an
/// operation with the same `op_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpLogEntry {
    pub op_id: OpId,
    pub kind: OpKind,
    pub result: OpResult,
    pub payload_hash: u64,
    pub executed_at: LogicalTime,
}
