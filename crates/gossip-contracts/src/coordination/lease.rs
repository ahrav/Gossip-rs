//! Lease and per-shard op-log types.
//!
//! A [`Lease`] is the capability returned by `acquire_and_restore` and required
//! by lease-gated shard mutations. It contains a **fence epoch** used as a
//! fencing token.
//!
//! The op-log implements bounded idempotency per shard: mutating operations
//! (except `acquire_and_restore` and `renew`, which are coordinator-level and
//! do not appear in the op-log) carry an [`OpId`]. The shard record caches the
//! last N (cap=16) operation fingerprints so the coordinator can detect retries
//! and return cached results instead of re-executing.
//!
//! ## Idempotency window semantics
//!
//! The op-log is a **bounded sliding window**, not a permanent record. Once an
//! entry is evicted (after 16 newer operations), the coordinator can no longer
//! distinguish a retry from a new operation with the same [`OpId`]. In this
//! case the coordinator re-executes the operation.
//!
//! This is safe because:
//! 1. The cap (16) covers several retry rounds of a single RPC.
//! 2. Callers must generate unique, non-recycled `OpId` values.
//! 3. An evicted operation was already durably persisted, so re-execution of
//!    an idempotent operation (e.g., checkpoint with the same cursor) produces
//!    the same result.
//!
//! If non-idempotent re-execution is a concern, callers must ensure retries
//! complete within the 16-operation window.

use crate::identity::{
    FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
};

// ============================================================================
// LeaseHolder
// ============================================================================

/// Identity and deadline of the worker currently holding a shard lease.
///
/// Bundles `owner` and `deadline` into a single value so that the
/// `ShardRecord` can store `Option<LeaseHolder>` instead of two separate
/// `Option` fields — making the "both-present-or-both-absent" invariant
/// structurally impossible to violate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseHolder {
    owner: WorkerId,
    deadline: LogicalTime,
}

impl LeaseHolder {
    /// Construct a new lease holder.
    #[must_use]
    pub fn new(owner: WorkerId, deadline: LogicalTime) -> Self {
        Self { owner, deadline }
    }

    /// The worker holding the lease.
    #[inline]
    #[must_use]
    pub fn owner(&self) -> WorkerId {
        self.owner
    }

    /// The logical time at which the lease expires.
    #[inline]
    #[must_use]
    pub fn deadline(&self) -> LogicalTime {
        self.deadline
    }
}

// ============================================================================
// Lease
// ============================================================================

/// A lease grants exclusive, temporary rights to mutate a shard.
///
/// The `fence` field is a monotonically increasing epoch stored in the shard
/// record. Every time the shard is acquired (or administratively unparked), the
/// epoch increments. Workers must present the current fence epoch to mutate.
///
/// Fields are private — the coordinator constructs leases and workers read
/// them via accessors (private fields, public getters).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    tenant: TenantId,
    run: RunId,
    shard: ShardId,
    owner: WorkerId,
    fence: FenceEpoch,
    deadline: LogicalTime,
}

impl Lease {
    /// Construct a new lease.
    ///
    /// Only callable within the crate — the coordinator is the sole producer.
    #[must_use]
    pub(crate) fn new(
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        owner: WorkerId,
        fence: FenceEpoch,
        deadline: LogicalTime,
    ) -> Self {
        assert!(
            fence >= FenceEpoch::INITIAL,
            "Lease fence epoch must be >= INITIAL (1), got {fence:?}",
        );
        assert!(
            deadline > LogicalTime::ZERO,
            "Lease deadline must be > ZERO, got {deadline:?}",
        );
        Self {
            tenant,
            run,
            shard,
            owner,
            fence,
            deadline,
        }
    }

    /// The tenant this lease belongs to.
    #[inline]
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The run this lease belongs to.
    #[inline]
    #[must_use]
    pub fn run(&self) -> RunId {
        self.run
    }

    /// The shard this lease grants access to.
    #[inline]
    #[must_use]
    pub fn shard(&self) -> ShardId {
        self.shard
    }

    /// The worker holding this lease.
    #[inline]
    #[must_use]
    pub fn owner(&self) -> WorkerId {
        self.owner
    }

    /// The fencing epoch for this lease.
    #[inline]
    #[must_use]
    pub fn fence(&self) -> FenceEpoch {
        self.fence
    }

    /// The logical time at which this lease expires.
    #[inline]
    #[must_use]
    pub fn deadline(&self) -> LogicalTime {
        self.deadline
    }

    /// Convenience: reconstruct the [`ShardKey`] for coordinator lookups.
    #[inline]
    #[must_use]
    pub fn shard_key(&self) -> ShardKey {
        ShardKey::new(self.run, self.shard)
    }
}

// ============================================================================
// OpKind
// ============================================================================

/// Operation kinds that participate in per-shard idempotency.
///
/// Every mutation in the shard's op-log carries an `OpKind` so the coordinator
/// can detect retries via [`OpId`] + payload hash and safely replay them.
///
/// Most variants are **lease-gated** — they require a valid lease held by the
/// calling worker. The exception is [`Unpark`](Self::Unpark), which is an
/// admin operation the coordinator may perform without a lease.
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted in the op-log. Existing values MUST NOT be reused or reordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpKind {
    /// Save progress without changing shard status.
    Checkpoint = 0,
    /// Mark the shard as fully processed (terminal — transitions to `Done`).
    Complete = 1,
    /// Suspend the shard (terminal — transitions to `Parked`; resumption
    /// requires an out-of-band [`Unpark`](Self::Unpark)).
    Park = 2,
    /// Replace the parent shard with split children (terminal — transitions to `Split`).
    SplitReplace = 3,
    /// Create the residual shard that covers the remainder of the key range.
    SplitResidual = 4,
    /// Administrative: resume a parked shard. Not lease-gated (the coordinator
    /// may unpark a shard without the worker that parked it). See
    /// [`ShardStatus`](super::record::ShardStatus) for the out-of-band
    /// unpark transition.
    Unpark = 5,
}

impl OpKind {
    /// Parse a `u8` discriminant to the corresponding variant.
    ///
    /// Returns `None` for unrecognized values — forward compatibility.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Checkpoint),
            1 => Some(Self::Complete),
            2 => Some(Self::Park),
            3 => Some(Self::SplitReplace),
            4 => Some(Self::SplitResidual),
            5 => Some(Self::Unpark),
            _ => None,
        }
    }

    /// Return the stable `u8` discriminant.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// Compile-time assertions for OpKind discriminant stability.
const _: () = assert!(OpKind::Checkpoint as u8 == 0);
const _: () = assert!(OpKind::Complete as u8 == 1);
const _: () = assert!(OpKind::Park as u8 == 2);
const _: () = assert!(OpKind::SplitReplace as u8 == 3);
const _: () = assert!(OpKind::SplitResidual as u8 == 4);
const _: () = assert!(OpKind::Unpark as u8 == 5);
const _: () = assert!(core::mem::size_of::<OpKind>() == 1);

// ============================================================================
// OpResult
// ============================================================================

/// Stored result status for an executed operation.
///
/// Recorded alongside [`OpKind`] in the op-log so retries can return the
/// original outcome without re-executing.
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted in the op-log. Existing values MUST NOT be reused or reordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpResult {
    /// The operation executed successfully.
    Completed = 0,
    /// The operation failed (the shard record was not mutated).
    Error = 1,
    /// The operation was valid but overtaken by a later mutation (e.g., a
    /// checkpoint whose cursor was already advanced past by a subsequent op).
    Superseded = 2,
}

impl OpResult {
    /// Parse a `u8` discriminant to the corresponding variant.
    ///
    /// Returns `None` for unrecognized values — forward compatibility.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Completed),
            1 => Some(Self::Error),
            2 => Some(Self::Superseded),
            _ => None,
        }
    }

    /// Return the stable `u8` discriminant.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// Compile-time assertions for OpResult discriminant stability.
const _: () = assert!(OpResult::Completed as u8 == 0);
const _: () = assert!(OpResult::Error as u8 == 1);
const _: () = assert!(OpResult::Superseded as u8 == 2);
const _: () = assert!(core::mem::size_of::<OpResult>() == 1);

// ============================================================================
// OpLogEntry
// ============================================================================

/// A single entry in the bounded per-shard operation log.
///
/// The shard record caches the last *N* entries (cap = 16). When a worker
/// retries an operation with the same [`OpId`], the coordinator looks up the
/// matching entry and returns the cached [`OpResult`] instead of re-executing.
/// If the retry carries a different `payload_hash`, it is rejected as a
/// conflicting mutation.
///
/// Fields are private — the coordinator constructs entries, tests and
/// snapshot consumers read via accessors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpLogEntry {
    op_id: OpId,
    kind: OpKind,
    result: OpResult,
    payload_hash: u64,
    executed_at: LogicalTime,
}

impl OpLogEntry {
    /// Construct a new op-log entry.
    ///
    /// Only callable within the crate — the coordinator is the sole producer.
    #[must_use]
    pub(crate) fn new(
        op_id: OpId,
        kind: OpKind,
        result: OpResult,
        payload_hash: u64,
        executed_at: LogicalTime,
    ) -> Self {
        assert!(
            executed_at > LogicalTime::ZERO,
            "OpLogEntry executed_at must be > ZERO, got {executed_at:?}",
        );
        assert!(
            payload_hash != 0,
            "OpLogEntry payload_hash must be non-zero (indicates hashing failure)",
        );
        Self {
            op_id,
            kind,
            result,
            payload_hash,
            executed_at,
        }
    }

    /// The operation's idempotency key.
    #[inline]
    #[must_use]
    pub fn op_id(&self) -> OpId {
        self.op_id
    }

    /// The kind of operation.
    #[inline]
    #[must_use]
    pub fn kind(&self) -> OpKind {
        self.kind
    }

    /// The result status.
    #[inline]
    #[must_use]
    pub fn result(&self) -> OpResult {
        self.result
    }

    /// Deterministic hash of the operation payload.
    ///
    /// On retry, if the new payload hash differs from the cached value the
    /// coordinator rejects the operation as a conflicting mutation for the
    /// same [`OpId`].
    #[inline]
    #[must_use]
    pub fn payload_hash(&self) -> u64 {
        self.payload_hash
    }

    /// The logical time at which the operation was executed.
    #[inline]
    #[must_use]
    pub fn executed_at(&self) -> LogicalTime {
        self.executed_at
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -- OpKind roundtrip ------------------------------------------------

    #[test]
    fn op_kind_roundtrip_table() {
        let cases: &[(u8, Option<OpKind>)] = &[
            (0, Some(OpKind::Checkpoint)),
            (1, Some(OpKind::Complete)),
            (2, Some(OpKind::Park)),
            (3, Some(OpKind::SplitReplace)),
            (4, Some(OpKind::SplitResidual)),
            (5, Some(OpKind::Unpark)),
            (6, None),
            (7, None),
            (u8::MAX, None),
        ];
        for &(disc, expected) in cases {
            assert_eq!(OpKind::from_u8(disc), expected, "OpKind::from_u8({disc})");
            if let Some(kind) = expected {
                assert_eq!(kind.as_u8(), disc, "OpKind::as_u8({kind:?})");
            }
        }
    }

    // -- OpResult roundtrip ----------------------------------------------

    #[test]
    fn op_result_roundtrip_table() {
        let cases: &[(u8, Option<OpResult>)] = &[
            (0, Some(OpResult::Completed)),
            (1, Some(OpResult::Error)),
            (2, Some(OpResult::Superseded)),
            (3, None),
            (u8::MAX, None),
        ];
        for &(disc, expected) in cases {
            assert_eq!(
                OpResult::from_u8(disc),
                expected,
                "OpResult::from_u8({disc})"
            );
            if let Some(result) = expected {
                assert_eq!(result.as_u8(), disc, "OpResult::as_u8({result:?})");
            }
        }
    }

    // -- Lease construction and accessors --------------------------------

    #[test]
    fn lease_construction_and_accessors() {
        let tenant = TenantId::from_bytes([0x01; 32]);
        let run = RunId::from_raw(42);
        let shard = ShardId::from_raw(7);
        let owner = WorkerId::from_raw(99);
        let fence = FenceEpoch::INITIAL;
        let deadline = LogicalTime::from_raw(1000);

        let lease = Lease::new(tenant, run, shard, owner, fence, deadline);

        assert_eq!(lease.tenant(), tenant);
        assert_eq!(lease.run(), run);
        assert_eq!(lease.shard(), shard);
        assert_eq!(lease.owner(), owner);
        assert_eq!(lease.fence(), fence);
        assert_eq!(lease.deadline(), deadline);
        assert_eq!(lease.shard_key(), ShardKey::new(run, shard));
    }

    // -- OpLogEntry construction and accessors ---------------------------

    #[test]
    fn op_log_entry_construction_and_accessors() {
        let op_id = OpId::from_raw(12345);
        let kind = OpKind::Checkpoint;
        let result = OpResult::Completed;
        let payload_hash = 0xDEAD_BEEF;
        let executed_at = LogicalTime::from_raw(500);

        let entry = OpLogEntry::new(op_id, kind, result, payload_hash, executed_at);

        assert_eq!(entry.op_id(), op_id);
        assert_eq!(entry.kind(), kind);
        assert_eq!(entry.result(), result);
        assert_eq!(entry.payload_hash(), payload_hash);
        assert_eq!(entry.executed_at(), executed_at);
    }

    // -- Property tests --------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn prop_op_kind_roundtrip(v in any::<u8>()) {
            if let Some(kind) = OpKind::from_u8(v) {
                prop_assert_eq!(kind.as_u8(), v);
            }
            // Unrecognized values must return None — no crash, no panic.
        }

        #[test]
        fn prop_lease_accessor_identity(
            tenant_bytes in proptest::array::uniform32(any::<u8>()),
            run_raw in any::<u64>(),
            shard_raw in any::<u64>(),
            owner_raw in any::<u64>(),
            fence_raw in 1u64..=u64::MAX,
            deadline_raw in 1u64..=u64::MAX,
        ) {
            let tenant = TenantId::from_bytes(tenant_bytes);
            let run = RunId::from_raw(run_raw);
            let shard = ShardId::from_raw(shard_raw);
            let owner = WorkerId::from_raw(owner_raw);
            let fence = FenceEpoch::from_raw(fence_raw);
            let deadline = LogicalTime::from_raw(deadline_raw);

            let lease = Lease::new(tenant, run, shard, owner, fence, deadline);

            prop_assert_eq!(lease.tenant(), tenant);
            prop_assert_eq!(lease.run(), run);
            prop_assert_eq!(lease.shard(), shard);
            prop_assert_eq!(lease.owner(), owner);
            prop_assert_eq!(lease.fence(), fence);
            prop_assert_eq!(lease.deadline(), deadline);
            prop_assert_eq!(lease.shard_key(), ShardKey::new(run, shard));
        }

        #[test]
        fn prop_op_log_entry_accessor_identity(
            op_raw in any::<u64>(),
            kind_disc in 0u8..=5u8,
            result_disc in 0u8..=2u8,
            payload_hash in 1u64..=u64::MAX,
            executed_raw in 1u64..=u64::MAX,
        ) {
            let op_id = OpId::from_raw(op_raw);
            let kind = OpKind::from_u8(kind_disc).unwrap();
            let result = OpResult::from_u8(result_disc).unwrap();
            let executed_at = LogicalTime::from_raw(executed_raw);

            let entry = OpLogEntry::new(op_id, kind, result, payload_hash, executed_at);

            prop_assert_eq!(entry.op_id(), op_id);
            prop_assert_eq!(entry.kind(), kind);
            prop_assert_eq!(entry.result(), result);
            prop_assert_eq!(entry.payload_hash(), payload_hash);
            prop_assert_eq!(entry.executed_at(), executed_at);
        }
    }
}
