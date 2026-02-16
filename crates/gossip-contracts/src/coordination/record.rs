//! ShardRecord: the coordinator's authoritative state for a single shard.
//!
//! Contains the lifecycle state machine ([`ShardStatus`]), park reasons
//! ([`ParkReason`]), the full [`ShardRecord`] with Tiger Style invariant
//! assertions, and the worker-visible [`ShardSnapshot`].
//!
//! ## Design Decisions (locked)
//!
//! D2.6: ShardStatus has exactly 4 states: Active, Done, Split, Parked.
//!       Done, Split, and Parked are terminal within the coordination
//!       protocol. Unparking is an out-of-band admin operation.
//!
//! D2.7: `park_reason.is_some()` iff `status == Parked`.
//!       Asserted at every state transition via `assert_invariants`.
//!       Reference: TigerBeetle's Tiger Style — assert at every boundary.
//!
//! D2.11: ShardRecord is self-contained — no back-references to RunConfig.
//!        `cursor_semantics` is embedded directly.
//!
//! D2.12: ShardSnapshot excludes lease, fence, op_log, tenant, and
//!        park_reason. Identity fields (run, shard) are also omitted —
//!        the worker knows these from the acquire context. Workers get
//!        lease info from the Lease return value.

use std::fmt;

use blake3::Hasher;

use crate::coordination::cursor::Cursor;
use crate::coordination::lease::OpLogEntry;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, OpId, RunId, ShardId, TenantId, WorkerId,
};

use super::split::MAX_SPAWNED_PER_SHARD;

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
/// record. The coordinator persists this to durable storage after every
/// state transition.
///
/// ## Visibility
///
/// Fields are `pub(crate)` — the coordinator backend directly mutates
/// fields during state transitions. Safety is enforced by Tiger Style
/// `assert_invariants()` after every transition, not by accessor-gated
/// field access.
///
/// ## Invariants (checked by `assert_invariants`)
///
/// 1. `park_reason.is_some()` iff `status == Parked`
/// 2. `lease_owner.is_some() == lease_deadline.is_some()` (paired or both None)
/// 3. `status.is_terminal()` implies `lease_owner.is_none()`
/// 4. `fence_epoch >= FenceEpoch::INITIAL`
/// 5. `op_log.len() <= OP_LOG_CAP`
/// 6. `status == Split` implies `!spawned.is_empty()` (INV-S16)
/// 7. `parent.is_some()` implies `shard.is_derived()`
/// 8. All entries in `spawned` satisfy `is_derived() == true`
/// 9. `op_log` entries have unique `OpId` values
/// 10. `spawned.len() <= MAX_SPAWNED_PER_SHARD`
///
/// Reference: TigerBeetle's Tiger Style — assert at every boundary;
///            Gray & Cheriton, "Leases" (SOSP 1989);
///            Stripe idempotency keys — op-log pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRecord {
    // -- Identity --
    pub(crate) tenant: TenantId,
    pub(crate) run: RunId,
    pub(crate) shard: ShardId,

    // -- Lifecycle --
    pub(crate) status: ShardStatus,
    /// Set when `status == Parked`, `None` otherwise.
    pub(crate) park_reason: Option<ParkReason>,

    // -- Coverage and progress --
    pub(crate) spec: ShardSpec,
    pub(crate) cursor: Cursor,
    pub(crate) cursor_semantics: CursorSemantics,

    // -- Lease / ownership --
    /// The worker currently holding the lease, or `None` if unleased.
    pub(crate) lease_owner: Option<WorkerId>,
    /// Logical time at which the lease expires, or `None` if unleased.
    pub(crate) lease_deadline: Option<LogicalTime>,
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
    pub(crate) spawned: Vec<ShardId>,

    // -- Idempotency --
    /// Bounded operation log for idempotent replay.
    /// Oldest entries are evicted when capacity is reached.
    pub(crate) op_log: Vec<OpLogEntry>,
}

impl ShardRecord {
    /// Maximum number of retained op-log entries.
    ///
    /// 16 is enough to cover several rounds of retries. The op-log is
    /// a short-term idempotency window, not a permanent audit log.
    pub const OP_LOG_CAP: usize = 16;

    /// Construct a new active shard record (root shard).
    #[allow(dead_code)] // Used by coordinator backend (Task 4).
    pub(crate) fn new_active(
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        spec: ShardSpec,
        cursor_semantics: CursorSemantics,
    ) -> Self {
        let record = Self {
            tenant,
            run,
            shard,
            status: ShardStatus::Active,
            park_reason: None,
            spec,
            cursor: Cursor::initial(),
            cursor_semantics,
            lease_owner: None,
            lease_deadline: None,
            fence_epoch: FenceEpoch::INITIAL,
            parent: None,
            spawned: Vec::new(),
            op_log: Vec::with_capacity(Self::OP_LOG_CAP),
        };
        record.assert_invariants();
        record
    }

    /// Construct a new active shard record created by a split.
    #[allow(dead_code)] // Used by coordinator backend (Task 4).
    pub(crate) fn new_split_child(
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        spec: ShardSpec,
        cursor: Cursor,
        cursor_semantics: CursorSemantics,
        parent: ShardId,
    ) -> Self {
        let record = Self {
            tenant,
            run,
            shard,
            status: ShardStatus::Active,
            park_reason: None,
            spec,
            cursor,
            cursor_semantics,
            lease_owner: None,
            lease_deadline: None,
            fence_epoch: FenceEpoch::INITIAL,
            parent: Some(parent),
            spawned: Vec::new(),
            op_log: Vec::with_capacity(Self::OP_LOG_CAP),
        };
        record.assert_invariants();
        record
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
        spec: ShardSpec,
        cursor: Cursor,
        cursor_semantics: CursorSemantics,
        lease_owner: Option<WorkerId>,
        lease_deadline: Option<LogicalTime>,
        fence_epoch: FenceEpoch,
        parent: Option<ShardId>,
        spawned: Vec<ShardId>,
        op_log: Vec<OpLogEntry>,
    ) -> Self {
        Self {
            tenant,
            run,
            shard,
            status,
            park_reason,
            spec,
            cursor,
            cursor_semantics,
            lease_owner,
            lease_deadline,
            fence_epoch,
            parent,
            spawned,
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
    /// Reference: TigerBeetle's Tiger Style — assert at every boundary.
    pub fn assert_invariants(&self) {
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

        // INV-2: Lease consistency: both present or both absent.
        assert_eq!(
            self.lease_owner.is_some(),
            self.lease_deadline.is_some(),
            "Shard {:?}: lease_owner and lease_deadline must both be Some or both be None",
            self.shard,
        );

        // INV-3: Terminal shards must not hold a lease.
        if self.status.is_terminal() {
            assert!(
                self.lease_owner.is_none(),
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

        // INV-5: Op-log bounded.
        assert!(
            self.op_log.len() <= Self::OP_LOG_CAP,
            "Shard {:?}: op_log length {} exceeds cap {}",
            self.shard,
            self.op_log.len(),
            Self::OP_LOG_CAP,
        );

        // INV-6: Split implies spawned is non-empty.
        if self.status == ShardStatus::Split {
            assert!(
                !self.spawned.is_empty(),
                "Split shard {:?} must have spawned children",
                self.shard,
            );
        }

        // INV-7: parent.is_some() implies shard.is_derived().
        if self.parent.is_some() {
            assert!(
                self.shard.is_derived(),
                "Shard {:?} claims parentage but is not derived (bit 63 not set)",
                self.shard,
            );
        }

        // INV-8: All spawned entries must be derived.
        for (i, spawned_id) in self.spawned.iter().enumerate() {
            assert!(
                spawned_id.is_derived(),
                "Shard {:?}: spawned[{i}] ({:?}) is not derived (bit 63 not set)",
                self.shard,
                spawned_id,
            );
        }

        // INV-9: Op-log entries have unique OpId values.
        for i in 0..self.op_log.len() {
            for j in (i + 1)..self.op_log.len() {
                assert!(
                    self.op_log[i].op_id() != self.op_log[j].op_id(),
                    "Shard {:?}: duplicate OpId {:?} in op_log at indices {i} and {j}",
                    self.shard,
                    self.op_log[i].op_id(),
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

    /// Create a [`ShardSnapshot`] for returning to a worker on acquisition.
    ///
    /// Contains only the information a worker needs to resume scanning.
    /// Excludes lease, fence, op_log, tenant, park_reason, and identity
    /// fields (run, shard). The worker gets lease info from the Lease
    /// return value and already knows its tenant and shard identity.
    #[must_use]
    pub fn snapshot(&self) -> ShardSnapshot {
        self.assert_invariants();
        ShardSnapshot::new(
            self.status,
            self.spec.clone(),
            self.cursor.clone(),
            self.cursor_semantics,
            self.parent,
            self.spawned.clone(),
        )
    }

    /// Look up an op-log entry by [`OpId`].
    ///
    /// Returns `None` if the OpId is not in the log (either never seen
    /// or evicted). Linear scan in reverse order for retry optimization
    /// (~5ns avg improvement — retries involve the most recent operations).
    pub fn op_log_lookup(&self, op: OpId) -> Option<&OpLogEntry> {
        debug_assert!(self.op_log.len() <= Self::OP_LOG_CAP);
        self.op_log.iter().rev().find(|e| e.op_id() == op)
    }

    /// Push an op-log entry, evicting the oldest if at capacity.
    ///
    /// Eviction is FIFO: the oldest entry (index 0) is removed first.
    /// This is correct because older operations are less likely to be
    /// retried — retry storms typically involve the most recent operations.
    ///
    /// # Panics
    ///
    /// Panics if `entry.op_id()` is already in the log. Callers must
    /// check [`op_log_lookup`](Self::op_log_lookup) first for idempotent
    /// replay.
    #[allow(dead_code)] // Used by coordinator backend (Task 4).
    pub(crate) fn op_log_push(&mut self, entry: OpLogEntry) {
        assert!(
            !self.op_log.iter().any(|e| e.op_id() == entry.op_id()),
            "Shard {:?}: attempt to push duplicate OpId {:?}",
            self.shard,
            entry.op_id(),
        );
        if self.op_log.len() >= Self::OP_LOG_CAP {
            self.op_log.remove(0);
        }
        self.op_log.push(entry);
        assert!(self.op_log.len() <= Self::OP_LOG_CAP);
    }

    /// Returns `true` if this shard's status is terminal.
    #[inline]
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
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
        match self.lease_deadline {
            Some(deadline) => now < deadline,
            None => false,
        }
    }
}

// Guard against future cap increases — Vec::remove(0) on more than 64
// entries would become a noticeable memcpy.
const _: () = assert!(ShardRecord::OP_LOG_CAP > 0);
const _: () = assert!(ShardRecord::OP_LOG_CAP <= 64);

// ============================================================================
// ShardSnapshot
// ============================================================================

/// Read-only snapshot of shard state returned to a worker on acquisition.
///
/// Contains everything a worker needs to resume scanning:
/// - Current lifecycle state (`status`)
/// - What to scan (`spec` — the key range and connector metadata)
/// - Where to resume (`cursor` — the two-layer progress marker)
/// - How to interpret the cursor (`cursor_semantics`)
/// - Lineage context (`parent`, `spawned`)
///
/// Excludes coordination-internal state:
/// - `run`, `shard` — the worker already knows its identity from the acquire call
/// - `tenant` — the worker already knows its tenant
/// - `lease_*`, `fence_epoch` — the worker gets these from the Lease
/// - `op_log` — internal to the coordinator
/// - `park_reason` — only relevant for parked shards, which aren't acquired
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSnapshot {
    status: ShardStatus,
    spec: ShardSpec,
    cursor: Cursor,
    cursor_semantics: CursorSemantics,
    parent: Option<ShardId>,
    spawned: Vec<ShardId>,
}

impl ShardSnapshot {
    /// Construct a new snapshot from individual fields.
    ///
    /// Prefer [`ShardRecord::snapshot()`] which validates invariants
    /// before constructing.
    pub(crate) fn new(
        status: ShardStatus,
        spec: ShardSpec,
        cursor: Cursor,
        cursor_semantics: CursorSemantics,
        parent: Option<ShardId>,
        spawned: Vec<ShardId>,
    ) -> Self {
        Self {
            status,
            spec,
            cursor,
            cursor_semantics,
            parent,
            spawned,
        }
    }

    /// The shard's lifecycle status.
    #[inline]
    #[must_use]
    pub fn status(&self) -> ShardStatus {
        self.status
    }

    /// The shard specification (key range and metadata).
    #[inline]
    #[must_use]
    pub fn spec(&self) -> &ShardSpec {
        &self.spec
    }

    /// The current cursor position.
    #[inline]
    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }

    /// The cursor semantics (Completed vs Dispatched).
    #[inline]
    #[must_use]
    pub fn cursor_semantics(&self) -> CursorSemantics {
        self.cursor_semantics
    }

    /// The parent shard, if this shard was created by a split.
    #[inline]
    #[must_use]
    pub fn parent(&self) -> Option<ShardId> {
        self.parent
    }

    /// Shards spawned by this shard.
    #[inline]
    #[must_use]
    pub fn spawned(&self) -> &[ShardId] {
        &self.spawned
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::lease::{OpKind, OpResult};
    use crate::test_util::canonical_digest;
    use proptest::prelude::*;

    // -- Test fixtures ---------------------------------------------------

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_spec() -> ShardSpec {
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())
    }

    fn active_record() -> ShardRecord {
        ShardRecord::new_active(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            test_spec(),
            CursorSemantics::Completed,
        )
    }

    fn leased_record() -> ShardRecord {
        let mut r = active_record();
        r.lease_owner = Some(WorkerId::from_raw(99));
        r.lease_deadline = Some(LogicalTime::from_raw(1000));
        r
    }

    fn make_entry(op_raw: u64) -> OpLogEntry {
        OpLogEntry::new(
            OpId::from_raw(op_raw),
            OpKind::Checkpoint,
            OpResult::Completed,
            0xABCD,
            LogicalTime::from_raw(100),
        )
    }

    /// Helper to create a derived ShardId (bit 63 set).
    fn derived_shard_id(base: u64) -> ShardId {
        ShardId::from_raw(base | (1u64 << 63))
    }

    // -- ShardStatus -----------------------------------------------------

    #[test]
    fn shard_status_terminal_truth_table() {
        assert!(!ShardStatus::Active.is_terminal());
        assert!(ShardStatus::Done.is_terminal());
        assert!(ShardStatus::Split.is_terminal());
        assert!(ShardStatus::Parked.is_terminal());
    }

    #[test]
    fn shard_status_roundtrip_table() {
        let cases: &[(u8, Option<ShardStatus>)] = &[
            (0, Some(ShardStatus::Active)),
            (1, Some(ShardStatus::Done)),
            (2, Some(ShardStatus::Split)),
            (3, Some(ShardStatus::Parked)),
            (4, None),
            (u8::MAX, None),
        ];
        for &(disc, expected) in cases {
            assert_eq!(
                ShardStatus::from_u8(disc),
                expected,
                "ShardStatus::from_u8({disc})"
            );
            if let Some(status) = expected {
                assert_eq!(status.as_u8(), disc, "ShardStatus::as_u8({status:?})");
            }
        }
    }

    #[test]
    fn shard_status_display() {
        assert_eq!(ShardStatus::Active.to_string(), "Active");
        assert_eq!(ShardStatus::Done.to_string(), "Done");
        assert_eq!(ShardStatus::Split.to_string(), "Split");
        assert_eq!(ShardStatus::Parked.to_string(), "Parked");
    }

    // -- ParkReason ------------------------------------------------------

    #[test]
    fn park_reason_roundtrip_table() {
        let cases: &[(u8, Option<ParkReason>)] = &[
            (0, Some(ParkReason::PermissionDenied)),
            (1, Some(ParkReason::NotFound)),
            (2, Some(ParkReason::Poisoned)),
            (3, Some(ParkReason::TooManyErrors)),
            (4, Some(ParkReason::Other)),
            (5, None),
            (u8::MAX, None),
        ];
        for &(disc, expected) in cases {
            assert_eq!(
                ParkReason::from_u8(disc),
                expected,
                "ParkReason::from_u8({disc})"
            );
            if let Some(reason) = expected {
                assert_eq!(reason.as_u8(), disc, "ParkReason::as_u8({reason:?})");
            }
        }
    }

    #[test]
    fn park_reason_display() {
        assert_eq!(
            ParkReason::PermissionDenied.to_string(),
            "permission denied"
        );
        assert_eq!(ParkReason::NotFound.to_string(), "not found");
        assert_eq!(ParkReason::Poisoned.to_string(), "poisoned");
        assert_eq!(ParkReason::TooManyErrors.to_string(), "too many errors");
        assert_eq!(ParkReason::Other.to_string(), "other");
    }

    // -- assert_invariants (success) -------------------------------------

    #[test]
    fn assert_invariants_active_unleased_ok() {
        active_record().assert_invariants();
    }

    #[test]
    fn assert_invariants_active_leased_ok() {
        leased_record().assert_invariants();
    }

    #[test]
    fn assert_invariants_done_ok() {
        let mut r = active_record();
        r.status = ShardStatus::Done;
        r.assert_invariants();
    }

    #[test]
    fn assert_invariants_parked_ok() {
        let mut r = active_record();
        r.status = ShardStatus::Parked;
        r.park_reason = Some(ParkReason::TooManyErrors);
        r.assert_invariants();
    }

    #[test]
    fn assert_invariants_split_ok() {
        let mut r = active_record();
        r.status = ShardStatus::Split;
        r.spawned = vec![derived_shard_id(1), derived_shard_id(2)];
        r.assert_invariants();
    }

    // -- assert_invariants (panics) --------------------------------------

    #[test]
    #[should_panic(expected = "must have park_reason")]
    fn assert_invariants_parked_without_reason_panics() {
        let mut r = active_record();
        r.status = ShardStatus::Parked;
        // park_reason left as None.
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must not have park_reason")]
    fn assert_invariants_active_with_reason_panics() {
        let mut r = active_record();
        r.park_reason = Some(ParkReason::Other);
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must both be Some or both be None")]
    fn assert_invariants_lease_owner_without_deadline_panics() {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Active,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            Some(WorkerId::from_raw(1)),
            None, // deadline missing
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must both be Some or both be None")]
    fn assert_invariants_lease_deadline_without_owner_panics() {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Active,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None, // owner missing
            Some(LogicalTime::from_raw(100)),
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must not have a lease")]
    fn assert_invariants_done_with_lease_panics() {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Done,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            Some(WorkerId::from_raw(1)),
            Some(LogicalTime::from_raw(100)),
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must not have a lease")]
    fn assert_invariants_parked_with_lease_panics() {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Parked,
            Some(ParkReason::TooManyErrors),
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            Some(WorkerId::from_raw(1)),
            Some(LogicalTime::from_raw(100)),
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must not have a lease")]
    fn assert_invariants_split_with_lease_panics() {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Split,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            Some(WorkerId::from_raw(1)),
            Some(LogicalTime::from_raw(100)),
            FenceEpoch::INITIAL,
            None,
            vec![derived_shard_id(1), derived_shard_id(2)],
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "exceeds cap")]
    fn assert_invariants_op_log_overflow_panics() {
        let entries: Vec<OpLogEntry> = (0..=ShardRecord::OP_LOG_CAP as u64)
            .map(make_entry)
            .collect();
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Active,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            entries,
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "not derived")]
    fn assert_invariants_parent_some_but_not_derived_panics() {
        // ShardId with bit 63 clear but claiming a parent.
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10), // NOT derived
            ShardStatus::Active,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            None,
            FenceEpoch::INITIAL,
            Some(ShardId::from_raw(5)), // has parent
            vec![],
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "not derived")]
    fn assert_invariants_spawned_contains_non_derived_panics() {
        let mut r = active_record();
        r.status = ShardStatus::Split;
        r.spawned = vec![ShardId::from_raw(42)]; // NOT derived (bit 63 clear)
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "fence_epoch must be >= INITIAL")]
    fn assert_invariants_fence_epoch_zero_panics() {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Active,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            None,
            FenceEpoch::ZERO,
            None,
            vec![],
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must have spawned children")]
    fn assert_invariants_split_without_spawned_panics() {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Split,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![], // empty spawned
            vec![],
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "duplicate OpId")]
    fn assert_invariants_duplicate_op_id_panics() {
        let entries = vec![make_entry(42), make_entry(42)]; // same OpId
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Active,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            entries,
        );
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "spawned count")]
    fn assert_invariants_spawned_exceeds_cap_panics() {
        let spawned: Vec<ShardId> = (0..=MAX_SPAWNED_PER_SHARD as u64)
            .map(|i| derived_shard_id(i + 1))
            .collect();
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(10),
            ShardStatus::Split,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            None,
            FenceEpoch::INITIAL,
            None,
            spawned,
            vec![],
        );
        r.assert_invariants();
    }

    // -- Op-log ----------------------------------------------------------

    #[test]
    fn op_log_lookup_found() {
        let mut r = active_record();
        let entry = make_entry(42);
        r.op_log_push(entry);
        assert_eq!(
            r.op_log_lookup(OpId::from_raw(42)).unwrap().op_id(),
            OpId::from_raw(42)
        );
    }

    #[test]
    fn op_log_lookup_not_found() {
        let r = active_record();
        assert!(r.op_log_lookup(OpId::from_raw(999)).is_none());
    }

    #[test]
    fn op_log_push_evicts_oldest() {
        let mut r = active_record();
        // Fill to capacity.
        for i in 0..ShardRecord::OP_LOG_CAP as u64 {
            r.op_log_push(make_entry(i));
        }
        assert_eq!(r.op_log.len(), ShardRecord::OP_LOG_CAP);

        // Push one more — oldest (op_id=0) should be evicted.
        r.op_log_push(make_entry(999));
        assert_eq!(r.op_log.len(), ShardRecord::OP_LOG_CAP);
        assert!(r.op_log_lookup(OpId::from_raw(0)).is_none());
        assert!(r.op_log_lookup(OpId::from_raw(999)).is_some());
    }

    #[test]
    fn op_log_lookup_reverse_finds_recent_first() {
        let mut r = active_record();
        r.op_log_push(make_entry(1));
        r.op_log_push(make_entry(2));
        r.op_log_push(make_entry(3));
        // Should find op 3 first (reverse scan).
        assert_eq!(
            r.op_log_lookup(OpId::from_raw(3)).unwrap().op_id(),
            OpId::from_raw(3)
        );
    }

    // -- Snapshot --------------------------------------------------------

    #[test]
    fn snapshot_preserves_fields() {
        let r = active_record();
        let snap = r.snapshot();
        assert_eq!(snap.status(), r.status);
        assert_eq!(snap.spec(), &r.spec);
        assert_eq!(snap.cursor(), &r.cursor);
        assert_eq!(snap.cursor_semantics(), r.cursor_semantics);
        assert_eq!(snap.parent(), r.parent);
        assert_eq!(snap.spawned(), r.spawned.as_slice());
    }

    #[test]
    fn snapshot_does_not_leak_coordination_state() {
        let r = leased_record();
        let snap = r.snapshot();
        let debug = format!("{snap:?}");
        assert!(
            !debug.contains("TenantId"),
            "snapshot Debug must not contain TenantId"
        );
        assert!(
            !debug.contains("WorkerId"),
            "snapshot Debug must not contain WorkerId"
        );
        assert!(
            !debug.contains("FenceEpoch"),
            "snapshot Debug must not contain FenceEpoch"
        );
    }

    // -- is_leased_at ----------------------------------------------------

    #[test]
    fn is_leased_at_no_lease() {
        let r = active_record();
        assert!(!r.is_leased_at(LogicalTime::from_raw(0)));
    }

    // -- Property tests --------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn op_log_push_bounded(ops in proptest::collection::vec(1u64..10000, 0..64)) {
            let mut r = active_record();
            for (i, &raw) in ops.iter().enumerate() {
                // Ensure unique op IDs by adding index offset.
                r.op_log_push(make_entry(raw * 10000 + i as u64));
            }
            prop_assert!(r.op_log.len() <= ShardRecord::OP_LOG_CAP);
        }

        #[test]
        fn park_reason_canonical_stable(v in 0u8..5) {
            let reason = ParkReason::from_u8(v).unwrap();
            prop_assert_eq!(canonical_digest(&reason), canonical_digest(&reason));
        }

        #[test]
        fn park_reason_canonical_collision_free(a in 0u8..5, b in 0u8..5) {
            prop_assume!(a != b);
            let ra = ParkReason::from_u8(a).unwrap();
            let rb = ParkReason::from_u8(b).unwrap();
            prop_assert_ne!(canonical_digest(&ra), canonical_digest(&rb));
        }

        #[test]
        fn is_leased_at_boundary_property(
            deadline_raw in 1u64..u64::MAX,
            now_raw in 0u64..u64::MAX,
        ) {
            let mut r = active_record();
            r.lease_owner = Some(WorkerId::from_raw(99));
            r.lease_deadline = Some(LogicalTime::from_raw(deadline_raw));
            prop_assert_eq!(
                r.is_leased_at(LogicalTime::from_raw(now_raw)),
                now_raw < deadline_raw,
            );
        }
    }
}
