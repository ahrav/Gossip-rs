//! ShardRecord: the coordinator's authoritative state for a single shard.
//!
//! Every shard in the system has exactly one `ShardRecord` that tracks its
//! lifecycle, ownership, progress, and lineage. The coordinator mutates this
//! record during state transitions (acquire, checkpoint, complete, park, split)
//! and validates invariants after every mutation.
//!
//! ## Contents
//!
//! - [`ShardStatus`] — lifecycle state machine (`Active -> Done | Parked | Split`)
//! - [`ParkReason`] — coordination-level categories for why a shard was halted
//! - [`ShardRecord`] — the full record with 10 runtime invariant assertions
//! - [`crate::coordination::error::ShardSnapshotView`] — worker-visible
//!   read-only view returned on acquisition
//!
//! ## Ownership Model
//!
//! `ShardRecord` fields are `pub(crate)` rather than private because the
//! coordinator backend directly mutates them during state transitions. Safety
//! comes from `assert_invariants()` called after every transition, not from
//! accessor-gated mutation. This is the "Tiger-style" invariant enforcement
//! pattern: allow direct field access, panic immediately on violation.
//!
//! ## Arena Pooling
//!
//! Variable-size byte fields (spec key ranges, cursor keys) are stored in a
//! shared [`ByteSlab`] via `PooledShardSpec` and `PooledCursor`, avoiding
//! per-field heap allocations on hot paths. The record does not implement
//! `Drop` — the coordinator must call `deallocate_fields()` before discarding.

use std::fmt;

use blake3::Hasher;
#[cfg(test)]
use gossip_stdx::InlineVec;
use gossip_stdx::{ByteSlab, RingBuffer};

use crate::coordination::cursor::CursorUpdate;
use crate::coordination::lease::{LeaseHolder, OpLogEntry};
use crate::coordination::pooled::{PooledCursor, PooledShardSpec, PooledSpawned};
#[cfg(test)]
use crate::coordination::shard_spec::ShardSpec;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpecRef};
use crate::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, OpId, RunId, ShardId, TenantId, WorkerId,
};

use super::split::MAX_SPAWNED_PER_SHARD;

/// Spawned-lineage input storage used by test helpers.
///
/// Runtime shard records store lineage in slab-backed [`PooledSpawned`], but
/// test constructors accept this inline container for ergonomics.
#[cfg(test)]
pub(crate) type SpawnedList = InlineVec<ShardId, MAX_SPAWNED_PER_SHARD>;

// ============================================================================
// ShardStatus
// ============================================================================

/// Shard lifecycle state.
///
/// ## State Machine
///
/// ```text
///                  ┌──────────────┐
///                  │    Active    │
///                  └──┬───┬───┬──┘
///                     │   │   │
///          Complete   │   │   │  Park
///            ┌────────┘   │   └────────┐
///            ▼            │            ▼
///       ┌────────┐   SplitReplace  ┌────────┐
///       │  Done  │        │        │ Parked │
///       └────────┘        ▼        └────────┘
///                    ┌────────┐
///                    │ Split  │
///                    └────────┘
/// ```
///
/// All transitions are from `Active` only. `Done`, `Split`, and `Parked`
/// are terminal within the coordination protocol.
///
/// Unparking (Parked → Active) is an out-of-band admin operation that
/// increments the fence epoch and clears the park reason.
///
/// ## Invariants
///
/// **Safety (terminal is irreversible)**: Once a shard reaches Done,
/// Split, or Parked, no protocol operation may change its status.
///
/// **Safety (discriminant stability)**: The `u8` values are persisted.
/// Existing values MUST NOT be reused or reordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ShardStatus {
    /// Shard is active and may be acquired by a worker.
    Active = 0,

    /// Shard completed successfully — all items in its range were scanned.
    Done = 1,

    /// Shard was replaced by children via SplitReplace.
    /// The children collectively cover the parent's key range.
    Split = 2,

    /// Shard halted due to a repeated or permanent error.
    /// Includes a `ParkReason` in the ShardRecord.
    Parked = 3,
}

impl ShardStatus {
    /// Returns `true` if this status is terminal (no further transitions
    /// within the coordination protocol).
    #[inline]
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Split | Self::Parked)
    }

    /// Parse a `u8` discriminant to the corresponding variant.
    ///
    /// Returns `None` for unrecognized values — forward compatibility.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Done),
            2 => Some(Self::Split),
            3 => Some(Self::Parked),
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

impl fmt::Display for ShardStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Active => "Active",
            Self::Done => "Done",
            Self::Split => "Split",
            Self::Parked => "Parked",
        })
    }
}

// Compile-time assertions for ShardStatus discriminant stability.
const _: () = assert!(ShardStatus::Active as u8 == 0);
const _: () = assert!(ShardStatus::Done as u8 == 1);
const _: () = assert!(ShardStatus::Split as u8 == 2);
const _: () = assert!(ShardStatus::Parked as u8 == 3);
const _: () = assert!(core::mem::size_of::<ShardStatus>() == 1);

// ============================================================================
// ParkReason
// ============================================================================

/// Reason a shard was parked.
///
/// These are coordination-level categories, not detailed error descriptions.
/// The coordination backend may store additional diagnostic context alongside
/// the record; this enum captures only what affects coordination decisions
/// (e.g., whether auto-retry is sensible).
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted. Existing values MUST NOT be reused or reordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ParkReason {
    /// The connector lacks permission to access the scan target.
    /// Likely requires credential rotation or access grant before unpark.
    PermissionDenied = 0,

    /// The scan target no longer exists (deleted repo, removed file).
    /// May be permanent; unpark only after confirming target exists.
    NotFound = 1,

    /// The shard's state or data is internally inconsistent.
    /// Requires manual investigation before unpark.
    Poisoned = 2,

    /// Too many transient errors accumulated during processing.
    /// May resolve on its own; suitable for time-delayed auto-retry.
    TooManyErrors = 3,

    /// Catch-all for reasons not covered by other variants.
    /// Coordination backend should log additional context separately.
    Other = 4,
}

impl ParkReason {
    /// Parse a `u8` discriminant to the corresponding variant.
    ///
    /// Returns `None` for unrecognized values — forward compatibility.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::PermissionDenied),
            1 => Some(Self::NotFound),
            2 => Some(Self::Poisoned),
            3 => Some(Self::TooManyErrors),
            4 => Some(Self::Other),
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

impl CanonicalBytes for ParkReason {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_u8().write_canonical(h);
    }
}

impl fmt::Display for ParkReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PermissionDenied => "permission denied",
            Self::NotFound => "not found",
            Self::Poisoned => "poisoned",
            Self::TooManyErrors => "too many errors",
            Self::Other => "other",
        })
    }
}

// Compile-time assertions for ParkReason discriminant stability.
const _: () = assert!(ParkReason::PermissionDenied as u8 == 0);
const _: () = assert!(ParkReason::NotFound as u8 == 1);
const _: () = assert!(ParkReason::Poisoned as u8 == 2);
const _: () = assert!(ParkReason::TooManyErrors as u8 == 3);
const _: () = assert!(ParkReason::Other as u8 == 4);
const _: () = assert!(core::mem::size_of::<ParkReason>() == 1);

// ============================================================================
// ShardRecord
// ============================================================================

/// The complete coordination state for a single shard.
///
/// This is the coordinator's authoritative record. All state transitions
/// (acquire, checkpoint, complete, park, split) are mutations of this
/// record. Durable backends persist this after transitions; the in-memory
/// reference backend keeps it in process memory only.
///
/// ## Visibility
///
/// Fields are `pub(crate)` — the coordinator backend directly mutates
/// fields during state transitions. Safety is enforced by
/// `assert_invariants()` after every transition, not by accessor-gated
/// field access.
///
/// ## Invariants (checked by `assert_invariants`)
///
/// 1. `park_reason.is_some()` iff `status == Parked`
/// 2. _(structural — enforced by `Option<LeaseHolder>`)_
/// 3. `status.is_terminal()` implies `lease.is_none()`
/// 4. `fence_epoch >= FenceEpoch::INITIAL`
/// 5. `op_log.len() <= OP_LOG_CAP`
/// 6. `status == Split` implies `!spawned.is_empty()`
/// 7. `parent.is_some()` iff `shard.is_derived()`
/// 8. All entries in `spawned` satisfy `is_derived() == true`
/// 9. `op_log` entries have unique `OpId` values
/// 10. `spawned.len() <= MAX_SPAWNED_PER_SHARD`
///
/// Reference: Gray & Cheriton, "Leases" (SOSP 1989);
///            Stripe idempotency keys — op-log pattern.
#[derive(Debug)]
pub struct ShardRecord {
    // -- Identity --
    pub(crate) tenant: TenantId,
    pub(crate) run: RunId,
    pub(crate) shard: ShardId,

    // -- Lifecycle --
    pub(crate) status: ShardStatus,
    /// Set when `status == Parked`, `None` otherwise.
    pub(crate) park_reason: Option<ParkReason>,

    // -- Coverage and progress (arena-pooled) --
    pub(crate) spec: PooledShardSpec,
    pub(crate) cursor: PooledCursor,
    pub(crate) cursor_semantics: CursorSemantics,

    // -- Lease / ownership --
    /// The current lease holder, or `None` if unleased.
    pub(crate) lease: Option<LeaseHolder>,
    /// Monotonically increasing fence epoch. Incremented on every
    /// ownership transfer to fence zombie workers.
    pub(crate) fence_epoch: FenceEpoch,

    // -- Lineage --
    /// Parent shard ID, if this shard was created by a split.
    /// `None` for root shards.
    pub(crate) parent: Option<ShardId>,
    /// Shards created by this shard via split operations.
    /// For `status == Split`: the replacement children.
    /// For `status == Active`: any residual shards spawned so far.
    pub(crate) spawned: PooledSpawned,

    // -- Idempotency --
    /// Bounded operation log for idempotent replay.
    /// Oldest entries are evicted when capacity is reached via O(1)
    /// ring buffer eviction. After eviction, retries are treated as new
    /// operations — safe because of convergent state transitions and
    /// [`FenceEpoch`] zombie fencing.
    /// See [`op_log_lookup`](Self::op_log_lookup) for details.
    pub(crate) op_log: RingBuffer<OpLogEntry, { ShardRecord::OP_LOG_CAP }>,
}

impl ShardRecord {
    /// Maximum number of retained op-log entries.
    ///
    /// 16 is enough to cover several rounds of retries. The op-log is
    /// a short-term idempotency window, not a permanent audit log.
    pub const OP_LOG_CAP: usize = 16;

    /// Construct a new active shard record (root shard).
    ///
    /// The cursor initializes to [`CursorUpdate::initial()`]. Borrowed inputs
    /// are copied into slab-owned storage; constructor callers do not need to
    /// keep source buffers alive after return.
    ///
    /// # Errors
    ///
    /// Returns `SlabFull` if the slab cannot allocate space for the spec.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new_active(
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        spec: ShardSpecRef<'_>,
        cursor_semantics: CursorSemantics,
        slab: &mut ByteSlab,
    ) -> Result<Self, gossip_stdx::SlabFull> {
        Self::new_active_with_cursor(
            tenant,
            run,
            shard,
            spec,
            CursorUpdate::initial(),
            cursor_semantics,
            slab,
        )
    }

    /// Construct a new active shard record (root shard) with explicit cursor.
    ///
    /// `spec`/`initial_cursor` may be borrowed views; bytes are copied into the
    /// coordinator slab before the record is returned.
    ///
    /// # Errors
    ///
    /// Returns `SlabFull` if the slab cannot allocate space for the spec.
    pub(crate) fn new_active_with_cursor(
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        spec: ShardSpecRef<'_>,
        initial_cursor: CursorUpdate<'_>,
        cursor_semantics: CursorSemantics,
        slab: &mut ByteSlab,
    ) -> Result<Self, gossip_stdx::SlabFull> {
        let pooled_spec = PooledShardSpec::from_spec_ref(spec, slab)?;
        let pooled_cursor = match PooledCursor::from_update(&initial_cursor, slab) {
            Ok(cursor) => cursor,
            Err(err) => {
                pooled_spec.deallocate(slab);
                return Err(err);
            }
        };
        let record = Self {
            tenant,
            run,
            shard,
            status: ShardStatus::Active,
            park_reason: None,
            spec: pooled_spec,
            cursor: pooled_cursor,
            cursor_semantics,
            lease: None,
            fence_epoch: FenceEpoch::INITIAL,
            parent: None,
            spawned: PooledSpawned::new(),
            op_log: RingBuffer::new(),
        };
        record.assert_invariants(slab);
        Ok(record)
    }

    /// Construct a new active shard record created by a split.
    ///
    /// As with root constructors, borrowed `spec`/`cursor` inputs are copied
    /// into slab-owned storage.
    ///
    /// # Errors
    ///
    /// Returns `SlabFull` if the slab cannot allocate space for the spec/cursor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_split_child(
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        spec: ShardSpecRef<'_>,
        cursor: CursorUpdate<'_>,
        cursor_semantics: CursorSemantics,
        parent: ShardId,
        slab: &mut ByteSlab,
    ) -> Result<Self, gossip_stdx::SlabFull> {
        let pooled_spec = PooledShardSpec::from_spec_ref(spec, slab)?;
        let pooled_cursor = match PooledCursor::from_update(&cursor, slab) {
            Ok(c) => c,
            Err(e) => {
                pooled_spec.deallocate(slab);
                return Err(e);
            }
        };
        let record = Self {
            tenant,
            run,
            shard,
            status: ShardStatus::Active,
            park_reason: None,
            spec: pooled_spec,
            cursor: pooled_cursor,
            cursor_semantics,
            lease: None,
            fence_epoch: FenceEpoch::INITIAL,
            parent: Some(parent),
            spawned: PooledSpawned::new(),
            op_log: RingBuffer::new(),
        };
        record.assert_invariants(slab);
        Ok(record)
    }

    /// Construct from raw parts, bypassing invariant validation.
    ///
    /// Only available in test builds — allows constructing intentionally
    /// invalid records for testing invariant checks.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_raw_parts(
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        status: ShardStatus,
        park_reason: Option<ParkReason>,
        spec: &ShardSpec,
        cursor: CursorUpdate<'_>,
        cursor_semantics: CursorSemantics,
        lease: Option<LeaseHolder>,
        fence_epoch: FenceEpoch,
        parent: Option<ShardId>,
        spawned: SpawnedList,
        op_log: RingBuffer<OpLogEntry, { ShardRecord::OP_LOG_CAP }>,
        slab: &mut ByteSlab,
    ) -> Self {
        let pooled_spec = PooledShardSpec::from_spec_ref(spec.as_ref(), slab)
            .expect("from_raw_parts: slab too small");
        let pooled_cursor =
            PooledCursor::from_update(&cursor, slab).expect("from_raw_parts: slab too small");
        let pooled_spawned = PooledSpawned::from_slice(spawned.as_slice(), slab)
            .expect("from_raw_parts: slab too small");
        Self {
            tenant,
            run,
            shard,
            status,
            park_reason,
            spec: pooled_spec,
            cursor: pooled_cursor,
            cursor_semantics,
            lease,
            fence_epoch,
            parent,
            spawned: pooled_spawned,
            op_log,
        }
    }

    /// Assert all structural invariants.
    ///
    /// Call after every state transition, before persisting. If any
    /// invariant fails, the coordinator panics — the operation is not
    /// persisted, and on crash-recovery the shard returns to its
    /// pre-operation state.
    ///
    /// # Panics
    ///
    /// Panics if any of the 10 invariants documented on [`ShardRecord`]
    /// are violated.
    ///
    /// # Complexity
    ///
    /// O(n²) for INV-9 (op-log uniqueness), where n ≤ [`OP_LOG_CAP`](Self::OP_LOG_CAP)
    /// (16). At most 120 comparisons — dominated by the per-transition
    /// persistence cost.
    ///
    /// ## Crash-to-prevent-corruption philosophy
    ///
    /// Panicking is the intentional recovery strategy. An invariant violation
    /// means the coordinator's in-memory state is inconsistent with its design
    /// contract — continuing would risk persisting corrupt data. By crashing
    /// *before* persistence, the coordinator ensures crash-recovery returns to
    /// the last valid state.
    ///
    /// **Operational guidance:** Invariant panics should be treated as critical
    /// bugs. Monitor for coordinator process crashes and alert immediately.
    /// The shard's durable state is safe (the failing operation was not
    /// persisted), but the root cause must be investigated.
    pub fn assert_invariants(&self, slab: &ByteSlab) {
        self.assert_lifecycle_invariants();
        self.assert_lineage_invariants(slab);
    }

    /// INV-1 through INV-5: status, park_reason, lease, fence, op-log cap.
    fn assert_lifecycle_invariants(&self) {
        // INV-1: park_reason consistency.
        match self.status {
            ShardStatus::Parked => {
                assert!(
                    self.park_reason.is_some(),
                    "Parked shard {:?} must have park_reason",
                    self.shard,
                );
            }
            _ => {
                assert!(
                    self.park_reason.is_none(),
                    "Non-parked shard {:?} (status: {:?}) must not have park_reason",
                    self.shard,
                    self.status,
                );
            }
        }

        // INV-2: (structural — `Option<LeaseHolder>` makes paired-ness implicit)

        // INV-3: Terminal shards must not hold a lease.
        if self.status.is_terminal() {
            assert!(
                self.lease.is_none(),
                "Terminal shard {:?} (status: {:?}) must not have a lease",
                self.shard,
                self.status,
            );
        }

        // INV-4: Fence epoch minimum.
        assert!(
            self.fence_epoch >= FenceEpoch::INITIAL,
            "Shard {:?}: fence_epoch must be >= INITIAL (1)",
            self.shard,
        );

        // INV-5: Op-log bounded — defense-in-depth: RingBuffer enforces capacity
        // structurally, but this assertion catches corruption before persistence.
        assert!(
            self.op_log.len() <= Self::OP_LOG_CAP,
            "Shard {:?}: op_log length {} exceeds cap {}",
            self.shard,
            self.op_log.len(),
            Self::OP_LOG_CAP,
        );
    }

    /// INV-6 through INV-10: split/spawned, parent/derived (biconditional),
    /// op-log uniqueness, spawned cap.
    fn assert_lineage_invariants(&self, slab: &ByteSlab) {
        // INV-6: Split implies spawned is non-empty.
        if self.status == ShardStatus::Split {
            assert!(
                !self.spawned.is_empty(),
                "Split shard {:?} must have spawned children",
                self.shard,
            );
        }

        // INV-7: parent.is_some() iff shard.is_derived().
        if self.parent.is_some() {
            assert!(
                self.shard.is_derived(),
                "Shard {:?} claims parentage but is not derived (bit 63 not set)",
                self.shard,
            );
        }
        if self.shard.is_derived() {
            assert!(
                self.parent.is_some(),
                "Shard {:?}: derived (bit 63 set) but has no parent",
                self.shard,
            );
        }

        // INV-8: All spawned entries must be derived.
        for (i, spawned_id) in self.spawned.iter(slab).enumerate() {
            assert!(
                spawned_id.is_derived(),
                "Shard {:?}: spawned[{i}] ({:?}) is not derived (bit 63 not set)",
                self.shard,
                spawned_id,
            );
        }

        // INV-9: Op-log entries have unique OpId values.
        for i in 0..self.op_log.len() {
            let a = self.op_log.get(i).unwrap();
            for j in (i + 1)..self.op_log.len() {
                let b = self.op_log.get(j).unwrap();
                assert!(
                    a.op_id() != b.op_id(),
                    "Shard {:?}: duplicate OpId {:?} in op_log at indices {i} and {j}",
                    self.shard,
                    a.op_id(),
                );
            }
        }

        // INV-10: Spawned count bounded.
        assert!(
            self.spawned.len() <= MAX_SPAWNED_PER_SHARD,
            "Shard {:?}: spawned count {} exceeds cap {}",
            self.shard,
            self.spawned.len(),
            MAX_SPAWNED_PER_SHARD,
        );
    }

    /// Validate all structural invariants without panicking.
    ///
    /// Returns `Ok(())` when all invariants hold, or `Err(message)` with
    /// a diagnostic string describing the first violated invariant.
    /// Suitable for contexts where panic-based detection is unavailable
    /// (e.g., `panic=abort` builds).
    ///
    /// This is the non-panicking counterpart to [`assert_invariants`](Self::assert_invariants).
    /// Both check the same set of invariants (INV-1 through INV-10).
    pub fn validate_invariants(&self, slab: &ByteSlab) -> Result<(), String> {
        self.validate_lifecycle_invariants()?;
        self.validate_lineage_invariants(slab)
    }

    /// INV-1 through INV-5 (non-panicking).
    fn validate_lifecycle_invariants(&self) -> Result<(), String> {
        // INV-1: park_reason consistency.
        match self.status {
            ShardStatus::Parked => {
                if self.park_reason.is_none() {
                    return Err(format!(
                        "Parked shard {:?} must have park_reason",
                        self.shard,
                    ));
                }
            }
            _ => {
                if self.park_reason.is_some() {
                    return Err(format!(
                        "Non-parked shard {:?} (status: {:?}) must not have park_reason",
                        self.shard, self.status,
                    ));
                }
            }
        }

        // INV-3: Terminal shards must not hold a lease.
        if self.status.is_terminal() && self.lease.is_some() {
            return Err(format!(
                "Terminal shard {:?} (status: {:?}) must not have a lease",
                self.shard, self.status,
            ));
        }

        // INV-4: Fence epoch minimum.
        if self.fence_epoch < FenceEpoch::INITIAL {
            return Err(format!(
                "Shard {:?}: fence_epoch must be >= INITIAL (1)",
                self.shard,
            ));
        }

        // INV-5: Op-log bounded.
        if self.op_log.len() > Self::OP_LOG_CAP {
            return Err(format!(
                "Shard {:?}: op_log length {} exceeds cap {}",
                self.shard,
                self.op_log.len(),
                Self::OP_LOG_CAP,
            ));
        }

        Ok(())
    }

    /// INV-6 through INV-10 (non-panicking).
    fn validate_lineage_invariants(&self, slab: &ByteSlab) -> Result<(), String> {
        // INV-6: Split implies spawned is non-empty.
        if self.status == ShardStatus::Split && self.spawned.is_empty() {
            return Err(format!(
                "Split shard {:?} must have spawned children",
                self.shard,
            ));
        }

        // INV-7: parent.is_some() iff shard.is_derived().
        if self.parent.is_some() && !self.shard.is_derived() {
            return Err(format!(
                "Shard {:?} claims parentage but is not derived (bit 63 not set)",
                self.shard,
            ));
        }
        if self.shard.is_derived() && self.parent.is_none() {
            return Err(format!(
                "Shard {:?}: derived (bit 63 set) but has no parent",
                self.shard,
            ));
        }

        // INV-8: All spawned entries must be derived.
        for (i, spawned_id) in self.spawned.iter(slab).enumerate() {
            if !spawned_id.is_derived() {
                return Err(format!(
                    "Shard {:?}: spawned[{i}] ({:?}) is not derived (bit 63 not set)",
                    self.shard, spawned_id,
                ));
            }
        }

        // INV-9: Op-log entries have unique OpId values.
        for i in 0..self.op_log.len() {
            let a = self.op_log.get(i).unwrap();
            for j in (i + 1)..self.op_log.len() {
                let b = self.op_log.get(j).unwrap();
                if a.op_id() == b.op_id() {
                    return Err(format!(
                        "Shard {:?}: duplicate OpId {:?} in op_log at indices {i} and {j}",
                        self.shard,
                        a.op_id(),
                    ));
                }
            }
        }

        // INV-10: Spawned count bounded.
        if self.spawned.len() > MAX_SPAWNED_PER_SHARD {
            return Err(format!(
                "Shard {:?}: spawned count {} exceeds cap {}",
                self.shard,
                self.spawned.len(),
                MAX_SPAWNED_PER_SHARD,
            ));
        }

        Ok(())
    }

    /// Deallocate all slab-backed fields.
    ///
    /// Must be called before dropping a `ShardRecord` to avoid slab leaks.
    /// After this call, spec and cursor fields are reset to empty/initial.
    /// Used by coordinator drop/rollback paths and by simulation wrappers
    /// via `SimIntrospection::release_record_fields`.
    pub(crate) fn deallocate_fields(&mut self, slab: &mut ByteSlab) {
        self.spec.release_fields(slab);
        self.cursor.release_fields(slab);
        self.spawned.release_fields(slab);
    }

    /// Look up an op-log entry by [`OpId`].
    ///
    /// Returns `None` if the OpId is not in the log (either never seen
    /// or evicted). Linear scan in reverse order — retries involve the
    /// most recent operations, so reverse iteration finds them sooner.
    ///
    /// ## Eviction failure mode
    ///
    /// When an [`OpId`] has been evicted, this method returns `None` and
    /// the caller treats the operation as new. This is safe because:
    ///
    /// 1. **Staleness guarantee** — eviction implies the `OpId` is at
    ///    least [`OP_LOG_CAP`](Self::OP_LOG_CAP) operations old.
    /// 2. **Convergent transitions** — shard operations are convergent
    ///    state transitions: re-executing either converges to the same
    ///    terminal state or is rejected by status guards (e.g., a split
    ///    on an already-split shard is a no-op or error).
    /// 3. **Primary zombie fence** — [`FenceEpoch`] is the primary
    ///    defense against zombie workers from prior leases. The op-log
    ///    is a *secondary* defense for in-lease retries only.
    pub fn op_log_lookup(&self, op: OpId) -> Option<&OpLogEntry> {
        debug_assert!(self.op_log.len() <= Self::OP_LOG_CAP);
        self.op_log.iter().rev().find(|e| e.op_id() == op)
    }

    /// Push an op-log entry, evicting the oldest if at capacity.
    ///
    /// Eviction is FIFO via O(1) ring buffer overwrite. Older operations
    /// are evicted first because they are less likely to be retried —
    /// retry storms typically involve the most recent operations.
    ///
    /// ## Persistence atomicity
    ///
    /// This method is called within coordinator mutations that invoke
    /// [`assert_invariants`](Self::assert_invariants) before persistence.
    /// If any assertion fails, the mutation panics and is **not**
    /// persisted — crash-recovery restores the last valid state. The
    /// op-log therefore never contains a partially-applied entry on disk.
    ///
    /// # Panics
    ///
    /// Panics if `entry.op_id()` is already in the log. Callers must
    /// check [`op_log_lookup`](Self::op_log_lookup) first for idempotent
    /// replay.
    pub(crate) fn op_log_push(&mut self, entry: OpLogEntry) {
        assert!(
            !self.op_log.iter().any(|e| e.op_id() == entry.op_id()),
            "Shard {:?}: attempt to push duplicate OpId {:?}",
            self.shard,
            entry.op_id(),
        );
        self.op_log.push_back_overwrite(entry);
        // Defense-in-depth: RingBuffer enforces capacity structurally, but
        // this assertion catches corruption before persistence.
        assert!(self.op_log.len() <= Self::OP_LOG_CAP);
    }

    /// Assert that transitioning to `new_status` is legal from the current state.
    ///
    /// The only legal transitions originate from `Active`:
    /// - Active → Done
    /// - Active → Split
    /// - Active → Parked
    ///
    /// Terminal states (Done, Split, Parked) cannot transition to any other state
    /// within the protocol. (Administrative `unpark` is handled separately and
    /// bumps the fence epoch.)
    ///
    /// # Panics
    ///
    /// Panics if the current status is terminal and `new_status` differs.
    pub(crate) fn assert_transition_legal(&self, new_status: ShardStatus) {
        assert!(
            !self.status.is_terminal() || self.status == new_status,
            "Shard {:?}: illegal transition from terminal {:?} to {:?}",
            self.shard,
            self.status,
            new_status,
        );
    }

    /// Returns `true` if this shard's status is terminal.
    #[inline]
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Atomically advance the fence epoch by one.
    ///
    /// This is the intended path for fence epoch mutation. Direct writes to
    /// `self.fence_epoch` should only occur in constructors (`new_active`,
    /// `new_split_child`).
    ///
    /// Returns the new (incremented) fence epoch.
    ///
    /// # Panics
    ///
    /// Panics at `u64::MAX` (via `FenceEpoch::increment`).
    pub(crate) fn advance_fence(&mut self) -> FenceEpoch {
        self.fence_epoch = self.fence_epoch.increment();
        self.fence_epoch
    }

    /// Returns `true` if this shard has an active (non-expired) lease
    /// at the given logical time.
    ///
    /// A lease is active iff `now < deadline`. At the deadline, the
    /// lease is considered expired — the safe direction.
    ///
    /// Reference: Gray & Cheriton, "Leases" (SOSP 1989).
    #[must_use]
    pub fn is_leased_at(&self, now: LogicalTime) -> bool {
        match &self.lease {
            Some(holder) => now < holder.deadline(),
            None => false,
        }
    }

    /// The current lease holder, if any.
    #[inline]
    #[must_use]
    pub fn lease(&self) -> Option<&LeaseHolder> {
        self.lease.as_ref()
    }

    /// The worker currently holding the lease, if any.
    #[inline]
    #[must_use]
    pub fn lease_owner(&self) -> Option<WorkerId> {
        self.lease.as_ref().map(|h| h.owner())
    }

    /// The lease deadline, if any.
    #[inline]
    #[must_use]
    pub fn lease_deadline(&self) -> Option<LogicalTime> {
        self.lease.as_ref().map(|h| h.deadline())
    }

    /// Returns `true` if the shard can accept `additional` spawned children
    /// without exceeding [`MAX_SPAWNED_PER_SHARD`].
    #[inline]
    #[must_use]
    pub fn can_spawn(&self, additional: usize) -> bool {
        self.spawned.len().saturating_add(additional) <= MAX_SPAWNED_PER_SHARD
    }
}

// Compile-time binding: OP_LOG_CAP matches the RingBuffer's const capacity.
// RingBuffer's own compile-time checks enforce N > 0 and power-of-2.
const _: () = assert!(ShardRecord::OP_LOG_CAP == 16);

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
