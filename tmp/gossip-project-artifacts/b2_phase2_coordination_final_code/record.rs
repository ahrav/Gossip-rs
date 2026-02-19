//! ShardRecord: the coordinator's authoritative state for a single shard.
//!
//! Contains the lifecycle state machine (ShardStatus), park reasons,
//! the full ShardRecord with Tiger Style invariant assertions, and the
//! worker-visible ShardSnapshot.
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
//! D2.12: ShardSnapshot excludes lease, fence, op_log, and tenant.
//!        Workers get lease info from the Lease return value.

use crate::identity::{
    FenceEpoch, LogicalTime, OpId, RunId, ShardId, TenantId,
    WorkerId,
};
use crate::coordination::cursor::Cursor;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::lease::OpLogEntry;

// ============================================================================
// § ShardStatus
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

// ============================================================================
// § ParkReason
// ============================================================================

/// Reason a shard was parked.
///
/// These are coordination-level categories, not detailed error descriptions.
/// The coordination backend may store additional diagnostic context
/// alongside the record; this enum captures only what affects coordination
/// decisions (e.g., whether auto-retry is sensible).
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

use blake3::Hasher;
use crate::identity::CanonicalBytes;

impl CanonicalBytes for ParkReason {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_u8().write_canonical(h);
    }
}

// ============================================================================
// § ShardRecord
// ============================================================================

/// The complete coordination state for a single shard.
///
/// This is the coordinator's authoritative record. All state transitions
/// (acquire, checkpoint, complete, park, split) are mutations of this
/// record. The coordinator persists this to durable storage after every
/// state transition.
///
/// ## Invariants (checked by `assert_invariants`)
///
/// **Safety (park_reason consistency)**: `park_reason.is_some()` iff
/// `status == Parked`.
///
/// **Safety (lease consistency)**: `lease_owner.is_some()` iff
/// `lease_deadline.is_some()`.
///
/// **Safety (terminal implies no lease)**: If `status.is_terminal()`,
/// then `lease_owner` and `lease_deadline` are `None`.
///
/// **Safety (fence minimum)**: `fence_epoch >= FenceEpoch::INITIAL`.
///
/// **Safety (op-log bounded)**: `op_log.len() <= OP_LOG_CAP`.
///
/// **Safety (cursor bounds)**: `cursor.last_key`, if present, falls
/// within `[spec.key_range_start, spec.key_range_end)`. Enforced at
/// checkpoint time via `check_cursor_bounds`, not by `assert_invariants`
/// — cursor bounds require domain-specific comparison logic.
///
/// Reference: TigerBeetle's Tiger Style — assert at every boundary;
///            Gray & Cheriton, "Leases" (SOSP 1989);
///            Stripe idempotency keys — op-log pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRecord {
    // -- Identity --
    pub tenant: TenantId,
    pub run: RunId,
    pub shard: ShardId,

    // -- Lifecycle --
    pub status: ShardStatus,
    /// Set when `status == Parked`, `None` otherwise.
    pub park_reason: Option<ParkReason>,

    // -- Coverage and progress --
    pub spec: ShardSpec,
    pub cursor: Cursor,
    pub cursor_semantics: CursorSemantics,

    // -- Lease / ownership --
    /// The worker currently holding the lease, or `None` if unleased.
    pub lease_owner: Option<WorkerId>,
    /// Logical time at which the lease expires, or `None` if unleased.
    pub lease_deadline: Option<LogicalTime>,
    /// Monotonically increasing fence epoch. Incremented on every
    /// ownership transfer to fence zombie workers.
    pub fence_epoch: FenceEpoch,

    // -- Lineage --
    /// Parent shard ID, if this shard was created by a split.
    /// `None` for root shards.
    pub parent: Option<ShardId>,
    /// Shards created by this shard via split operations.
    /// For `status == Split`: the replacement children.
    /// For `status == Active`: any residual shards spawned so far.
    pub spawned: Vec<ShardId>,

    // -- Idempotency --
    /// Bounded operation log for idempotent replay.
    /// Oldest entries are evicted when capacity is reached.
    pub op_log: Vec<OpLogEntry>,
}

impl ShardRecord {
    /// Maximum number of retained op-log entries.
    ///
    /// 16 is enough to cover several rounds of retries. The op-log is
    /// a short-term idempotency window, not a permanent audit log.
    pub const OP_LOG_CAP: usize = 16;

    /// Assert all structural invariants.
    ///
    /// Call after every state transition, before persisting. If any
    /// invariant fails, the coordinator panics — the operation is not
    /// persisted, and on crash-recovery the shard returns to its
    /// pre-operation state.
    ///
    /// Reference: TigerBeetle's Tiger Style — assert at every boundary.
    pub fn assert_invariants(&self) {
        // park_reason consistency.
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

        // Lease consistency: both present or both absent.
        assert_eq!(
            self.lease_owner.is_some(),
            self.lease_deadline.is_some(),
            "Shard {:?}: lease_owner and lease_deadline must both be Some or both be None",
            self.shard,
        );

        // Terminal shards must not hold a lease.
        if self.status.is_terminal() {
            assert!(
                self.lease_owner.is_none(),
                "Terminal shard {:?} (status: {:?}) must not have a lease",
                self.shard,
                self.status,
            );
        }

        // Fence epoch minimum.
        assert!(
            self.fence_epoch.0 >= FenceEpoch::INITIAL.0,
            "Shard {:?}: fence_epoch must be >= INITIAL (1)",
            self.shard,
        );

        // Op-log bounded.
        assert!(
            self.op_log.len() <= Self::OP_LOG_CAP,
            "Shard {:?}: op_log length {} exceeds cap {}",
            self.shard,
            self.op_log.len(),
            Self::OP_LOG_CAP,
        );
    }

    /// Create a ShardSnapshot for returning to a worker on acquisition.
    ///
    /// Contains only the information a worker needs to resume scanning.
    /// Excludes lease, fence, op_log, and tenant (the worker gets lease
    /// info from the Lease return value and already knows its tenant).
    pub fn snapshot(&self) -> ShardSnapshot {
        ShardSnapshot {
            status: self.status,
            spec: self.spec.clone(),
            cursor: self.cursor.clone(),
            cursor_semantics: self.cursor_semantics,
            parent: self.parent,
            spawned: self.spawned.clone(),
        }
    }

    /// Look up an op-log entry by OpId.
    ///
    /// Returns `None` if the OpId is not in the log (either never seen
    /// or evicted). Linear scan is fine — the log is bounded at
    /// `OP_LOG_CAP` entries.
    pub fn op_log_lookup(&self, op: OpId) -> Option<&OpLogEntry> {
        self.op_log.iter().find(|e| e.op_id == op)
    }

    /// Push an op-log entry, evicting the oldest if at capacity.
    ///
    /// Eviction is FIFO: the oldest entry (index 0) is removed first.
    /// This is correct because older operations are less likely to be
    /// retried — retry storms typically involve the most recent operations.
    pub fn op_log_push(&mut self, entry: OpLogEntry) {
        if self.op_log.len() >= Self::OP_LOG_CAP {
            self.op_log.remove(0);
        }
        self.op_log.push(entry);
    }

    /// Returns `true` if this shard's status is terminal.
    #[inline]
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
    pub fn is_leased_at(&self, now: LogicalTime) -> bool {
        match self.lease_deadline {
            Some(deadline) => now.0 < deadline.0,
            None => false,
        }
    }
}

// ============================================================================
// § ShardSnapshot
// ============================================================================

/// Read-only snapshot of shard state returned to a worker on acquisition.
///
/// Contains everything a worker needs to resume scanning:
/// - What to scan (`spec` — the key range and connector metadata)
/// - Where to resume (`cursor` — the two-layer progress marker)
/// - How to interpret the cursor (`cursor_semantics`)
/// - Lineage context (`parent`, `spawned`)
///
/// Excludes coordination-internal state:
/// - `tenant` — the worker already knows its tenant
/// - `lease_*`, `fence_epoch` — the worker gets these from the Lease
/// - `op_log` — internal to the coordinator
/// - `park_reason` — only relevant for parked shards, which aren't acquired
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSnapshot {
    pub status: ShardStatus,
    pub spec: ShardSpec,
    pub cursor: Cursor,
    pub cursor_semantics: CursorSemantics,
    pub parent: Option<ShardId>,
    pub spawned: Vec<ShardId>,
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    // -- Test fixtures --

    // TODO: fn test_tenant() -> TenantId { TenantId::from_bytes([0x01; 32]) }
    // TODO: fn test_run() -> RunId
    // TODO: fn test_spec() -> ShardSpec
    // TODO: fn active_record() -> ShardRecord (unleased, Active)
    // TODO: fn leased_record() -> ShardRecord (Active, lease_owner + deadline)

    // -- ShardStatus --

    // TODO: test shard_status_terminal
    //   - !Active.is_terminal(), Done/Split/Parked.is_terminal()

    // TODO: test shard_status_roundtrip
    //   - from_u8(0..=3) all Some, from_u8(4) == None

    // TODO: test shard_status_discriminants_stable
    //   - Active=0, Done=1, Split=2, Parked=3

    // -- ParkReason --

    // TODO: test park_reason_roundtrip (0..=4 → Some, 5 → None)
    // TODO: test park_reason_discriminants_stable
    // TODO: test park_reason_canonical_bytes_all_distinct

    // -- ShardRecord: assert_invariants --

    // TODO: test assert_invariants_active_unleased_ok
    // TODO: test assert_invariants_active_leased_ok
    // TODO: test assert_invariants_done_ok
    // TODO: test assert_invariants_parked_ok
    // TODO: test assert_invariants_split_ok

    // TODO: test assert_invariants_parked_without_reason_panics
    //   #[should_panic(expected = "must have park_reason")]

    // TODO: test assert_invariants_active_with_reason_panics
    //   #[should_panic(expected = "must not have park_reason")]

    // TODO: test assert_invariants_lease_owner_without_deadline_panics
    //   #[should_panic(expected = "must both be Some or both be None")]

    // TODO: test assert_invariants_lease_deadline_without_owner_panics
    //   #[should_panic(expected = "must both be Some or both be None")]

    // TODO: test assert_invariants_done_with_lease_panics
    //   #[should_panic(expected = "must not have a lease")]

    // TODO: test assert_invariants_op_log_overflow_panics
    //   #[should_panic(expected = "exceeds cap")]

    // -- ShardRecord: op_log --

    // TODO: test op_log_lookup_found
    // TODO: test op_log_lookup_not_found
    // TODO: test op_log_push_evicts_oldest
    //   - Fill to OP_LOG_CAP, push one more, verify oldest evicted

    // -- ShardRecord: snapshot --

    // TODO: test snapshot_preserves_fields
    // TODO: test snapshot_does_not_leak_coordination_state
    //   - Debug output of snapshot must not contain "TenantId"

    // -- ShardRecord: is_leased_at --

    // TODO: test is_leased_at_no_lease → false
    // TODO: test is_leased_at_before_deadline → true
    // TODO: test is_leased_at_at_deadline_is_expired → false
    // TODO: test is_leased_at_after_deadline → false
}
