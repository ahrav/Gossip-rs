//! Boundary â‘¡ â€” Coordination & Shard Frontier: Chunk 2 (DRAFT)
//!
//! Lifecycle types, operation log, split operations, and ShardRecord:
//! the types that manage shard state through the coordination protocol.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5) and Boundary â‘¡
//! chunk 1 (Cursor, ShardSpec, validation functions). It uses
//! `CanonicalBytes`, `domain_hasher`, `finalize_64`, `domain::*` from
//! Boundary â‘  chunk 1, and all ID types from Boundary â‘  chunk 2.
//!
//! ## Design Decisions (locked)
//!
//! D2.6: ShardStatus has exactly 4 states: Active, Done, Split, Parked.
//!       Done, Split, and Parked are terminal within the coordination
//!       protocol. Unparking is an out-of-band admin operation (new
//!       fence epoch, status reset to Active).
//!
//! D2.7: `park_reason` is stored in ShardRecord as `Option<ParkReason>`.
//!       Invariant: `park_reason.is_some()` iff `status == Parked`.
//!       Asserted at every state transition via `assert_invariants`.
//!
//!       Reference: TigerBeetle's Tiger Style â€” assert at every boundary.
//!
//! D2.8: OpLogEntry carries a `payload_hash: u64` for conflict detection.
//!       Not cryptographic â€” a collision-resistant guardrail against
//!       accidental OpId reuse with different inputs.
//!
//!       Reference: Stripe idempotency key pattern (Brandur Leach, 2017).
//!
//! D2.9: Split operations carry structured ShardSpecs. The coordinator
//!       validates range coverage via `validate_split_coverage` /
//!       `validate_residual_split` from chunk 1 before executing.
//!
//! D2.10: `derive_split_shard_id` uses `CanonicalBytes` internally and
//!        sets bit 63 to distinguish derived IDs from root IDs. Pure
//!        function: same inputs â†’ same output. Idempotent splits.
//!
//! D2.11: ShardRecord is self-contained â€” no back-references to RunConfig.
//!        `cursor_semantics` is embedded directly. The coordinator copies
//!        it from RunConfig at shard creation time.
//!
//! D2.12: ShardSnapshot excludes lease, fence, op_log, and tenant.
//!        Workers get lease info from the Lease return value. Snapshot
//!        carries only what a worker needs to resume scanning.

// Assumes these are in scope from prior chunks:
// use crate::{
//     CanonicalBytes, Hasher, domain_hasher, finalize_64,
//     TenantId, RunId, ShardId, WorkerId, OpId, FenceEpoch,
//     LogicalTime, ShardKey, PolicyHash, JobId,
//     domain,
//     Cursor, ShardSpec,
// };

use core::fmt;

// ============================================================================
// Â§ Chunk 2: Lifecycle, Operations, and ShardRecord
// ============================================================================

// ---------------------------------------------------------------------------
// Â§2.1 CursorSemantics â€” cursor advancement mode
// ---------------------------------------------------------------------------

/// Determines when cursor advancement counts as committed progress.
///
/// This is a per-run configuration choice that affects the strength of
/// the progress guarantee:
///
/// - `Completed`: strongest guarantee. The cursor only advances after
///   all work up to that point is fully processed and results are durable.
///   Failure after checkpoint means no work is lost.
///
/// - `Dispatched`: weaker but higher throughput. The cursor advances
///   after work is durably *dispatched* (e.g., to a separate work queue)
///   but not necessarily fully processed. Requires the dispatch target
///   to provide its own exactly-once guarantee.
///
/// ## Invariants
///
/// **Safety**: The coordinator enforces monotonicity and bounds checking
/// identically under both semantics. The difference is in what the
/// worker promises the cursor position represents.
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted in coordination state. Existing values MUST NOT be reused
/// or reordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CursorSemantics {
    /// Cursor advances only after work prior to the cursor is fully
    /// scanned and authoritative progress is committed.
    Completed = 0,

    /// Cursor advances after work prior to the cursor is durably
    /// dispatched to a separate work log. The work log is responsible
    /// for its own delivery guarantees.
    Dispatched = 1,
}

impl CursorSemantics {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Completed),
            1 => Some(Self::Dispatched),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for CursorSemantics {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_u8().write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§2.2 ShardStatus â€” lifecycle state machine
// ---------------------------------------------------------------------------

/// Shard lifecycle state.
///
/// ## State Machine
///
/// ```text
///                  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///                  â”‚    Active    â”‚
///                  â””â”€â”€â”¬â”€â”€â”€â”¬â”€â”€â”€â”¬â”€â”€â”˜
///                     â”‚   â”‚   â”‚
///          Complete   â”‚   â”‚   â”‚  Park
///            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚   â””â”€â”€â”€â”€â”€â”€â”€â”€â”
///            â–¼            â”‚            â–¼
///       â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”   SplitReplace  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”
///       â”‚  Done  â”‚        â”‚        â”‚ Parked â”‚
///       â””â”€â”€â”€â”€â”€â”€â”€â”€â”˜        â–¼        â””â”€â”€â”€â”€â”€â”€â”€â”€â”˜
///                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”
///                    â”‚ Split  â”‚
///                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// All transitions are from `Active` only. `Done`, `Split`, and `Parked`
/// are terminal within the coordination protocol.
///
/// Unparking (Parked â†’ Active) is an out-of-band admin operation that
/// increments the fence epoch and clears the park reason. It is not
/// modeled as a protocol operation.
///
/// ## Invariants
///
/// **Safety (terminal is irreversible)**: Once a shard reaches Done,
/// Split, or Parked, no protocol operation may change its status.
///
/// **Safety (single transition)**: Each shard transitions from Active
/// to exactly one terminal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ShardStatus {
    /// Shard is active and may be acquired by a worker.
    Active = 0,

    /// Shard completed successfully â€” all items in its range were scanned.
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

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Done),
            2 => Some(Self::Split),
            3 => Some(Self::Parked),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Â§2.3 ParkReason â€” why a shard was parked
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Â§2.4 OpKind, OpResult, OpLogEntry â€” operation log types
// ---------------------------------------------------------------------------

/// Operation kind recorded in the bounded op-log.
///
/// The op-log provides idempotent replay: if a worker retries an
/// operation with the same `OpId`, the coordinator returns the cached
/// `OpResult` without re-executing.
///
/// Reference: Stripe idempotency key pattern (Brandur Leach, 2017);
///            IETF Draft: Idempotency-Key HTTP Header Field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpKind {
    /// Advance the cursor within the shard's key range.
    Checkpoint,
    /// Replace this shard with N child shards covering its range.
    SplitReplace,
    /// Shrink this shard and create a residual for the remainder.
    SplitResidual,
    /// Mark this shard as successfully completed.
    Complete,
    /// Park this shard due to an error condition.
    Park,
}

/// The result of an operation, stored in the op-log for idempotent replay.
///
/// On retry, the coordinator returns this cached result instead of
/// re-executing the operation. The result must contain all information
/// the caller needs to proceed (e.g., derived shard IDs from splits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpResult {
    /// Simple acknowledgment (Checkpoint, Complete, Park).
    Ack,

    /// SplitReplace result: the derived IDs of the child shards.
    SplitReplace { children: Vec<ShardId> },

    /// SplitResidual result: the derived ID of the residual shard.
    SplitResidual { residual: ShardId },
}

impl OpResult {
    /// Extract child shard IDs if this is a SplitReplace result.
    pub fn children(&self) -> Option<&[ShardId]> {
        match self {
            OpResult::SplitReplace { children } => Some(children),
            _ => None,
        }
    }

    /// Extract the residual shard ID if this is a SplitResidual result.
    pub fn residual(&self) -> Option<ShardId> {
        match self {
            OpResult::SplitResidual { residual } => Some(*residual),
            _ => None,
        }
    }
}

/// A single entry in the bounded operation log.
///
/// The log supports idempotent operation replay. When a worker retries
/// an operation with the same `OpId`:
///
/// 1. Coordinator finds the existing entry by `op_id`.
/// 2. Compares `payload_hash` â€” if different, rejects as a conflict
///    (accidental OpId reuse with different inputs).
/// 3. If `payload_hash` matches, returns the cached `result`.
///
/// ## Invariants
///
/// **Safety (bounded)**: The log never exceeds `ShardRecord::OP_LOG_CAP`.
/// Oldest entries are evicted first.
///
/// **Safety (payload conflict)**: Same OpId + different payload_hash =
/// hard reject. This catches bugs where a client reuses an OpId for
/// a semantically different operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpLogEntry {
    pub op_id: OpId,
    pub kind: OpKind,
    /// Truncated BLAKE3 hash of the operation's inputs.
    /// Used for conflict detection, not cryptographic security.
    pub payload_hash: u64,
    pub result: OpResult,
}

// ---------------------------------------------------------------------------
// Â§2.5 Split operation types
// ---------------------------------------------------------------------------

/// A single child in a SplitReplace plan.
///
/// Each child has a structured ShardSpec (with key range) and an initial
/// cursor. Typically the cursor is initial (no progress), but a worker
/// that has partially processed a sub-range may set a non-initial cursor
/// for the child covering that sub-range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplaceChild {
    pub spec: ShardSpec,
    pub cursor: Cursor,
}

impl CanonicalBytes for SplitReplaceChild {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.spec.write_canonical(h);
        self.cursor.write_canonical(h);
    }
}

/// Plan for replacing a shard with N children.
///
/// The coordinator validates that the children's key ranges collectively
/// cover the parent's range exactly (no gaps, no overlaps) using
/// `validate_split_coverage` from chunk 1.
///
/// After validation, the coordinator:
/// 1. Derives deterministic ShardIds for each child via `derive_split_shard_id`.
/// 2. Creates child ShardRecords (status: Active).
/// 3. Sets the parent's status to Split.
/// 4. Records the child IDs in the parent's `spawned` list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplacePlan {
    pub children: Vec<SplitReplaceChild>,
}

impl CanonicalBytes for SplitReplacePlan {
    fn write_canonical(&self, h: &mut Hasher) {
        (self.children.len() as u32).write_canonical(h);
        for child in &self.children {
            child.write_canonical(h);
        }
    }
}

/// Result of a SplitReplace operation â€” the derived child shard IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplaceResult {
    pub children: Vec<ShardId>,
}

/// Plan for shrinking a shard and creating a residual.
///
/// A residual split is for when a worker realizes its assigned range is
/// too large and wants to hand off the unprocessed portion:
///
/// ```text
/// old_parent:  [â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”)
/// new_parent:  [â”â”â”â”â”â”â”â”â”â”)
/// residual:                [â”â”â”â”â”â”â”â”â”â”â”â”â”)
/// ```
///
/// The parent keeps the left portion (lower keys, already partially
/// processed). The residual gets the right portion (higher keys,
/// unprocessed). This aligns with cursor monotonicity: the parent's
/// cursor has been advancing through the lower keys.
///
/// The coordinator validates coverage via `validate_residual_split`
/// from chunk 1.
///
/// After validation:
/// 1. Derives a deterministic ShardId for the residual.
/// 2. Updates the parent's spec to `parent_new_spec`.
/// 3. Creates the residual ShardRecord (status: Active).
/// 4. Records the residual ID in the parent's `spawned` list.
/// 5. Parent remains Active (it continues processing its shrunk range).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResidualPlan {
    pub parent_new_spec: ShardSpec,
    pub residual_spec: ShardSpec,
    pub residual_cursor: Cursor,
}

impl CanonicalBytes for SplitResidualPlan {
    fn write_canonical(&self, h: &mut Hasher) {
        self.parent_new_spec.write_canonical(h);
        self.residual_spec.write_canonical(h);
        self.residual_cursor.write_canonical(h);
    }
}

/// Result of a SplitResidual operation â€” the derived residual shard ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitResidualResult {
    pub residual: ShardId,
}

// ---------------------------------------------------------------------------
// Â§2.6 derive_split_shard_id â€” deterministic shard ID derivation
// ---------------------------------------------------------------------------

/// Discriminant for the kind of shard being derived from a split.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DerivedShardKind {
    /// A child shard in a SplitReplace operation.
    Child = 0,
    /// The residual shard in a SplitResidual operation.
    Residual = 1,
}

impl CanonicalBytes for DerivedShardKind {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        (*self as u8).write_canonical(h);
    }
}

/// Derive a deterministic `ShardId` for a split operation.
///
/// Makes split operations idempotent under retries: the same inputs
/// always produce the same shard ID, so retrying a split doesn't
/// create duplicate shards.
///
/// ## Derivation
///
/// ```text
/// raw = blake3("gossip/coord/v1/split-id",
///     run_id || parent_shard_id || op_id || kind || index)
/// shard_id = truncate_64(raw) | (1 << 63)
/// ```
///
/// The top bit is set to distinguish derived IDs from root shard IDs
/// (which are small sequential integers 0..N). This is a deterministic
/// convention, not a cryptographic guarantee â€” it prevents collisions
/// with the most common root ID patterns.
///
/// ## Invariants
///
/// **Safety (determinism)**: Pure function of inputs. Same inputs â†’
/// same ShardId, always.
///
/// **Safety (uniqueness)**: Different (run, parent, op, kind, index)
/// tuples produce different ShardIds (with ~64-bit collision resistance,
/// reduced to ~63 bits by the top-bit convention).
///
/// Reference: Content-addressed identity pattern (Git, IPFS);
///            Â§3.1 exactly-once semantics via deterministic IDs.
pub fn derive_split_shard_id(
    run: RunId,
    parent: ShardId,
    op: OpId,
    kind: DerivedShardKind,
    index: u32,
) -> ShardId {
    let mut h = domain_hasher(domain::SPLIT_ID_V1);
    run.write_canonical(&mut h);
    parent.write_canonical(&mut h);
    op.write_canonical(&mut h);
    kind.write_canonical(&mut h);
    index.write_canonical(&mut h);

    let out = h.finalize();
    let bytes: [u8; 8] = out.as_bytes()[0..8].try_into().expect("8 bytes from 32");
    let mut id = u64::from_le_bytes(bytes);

    // Reserve the top half of the ID space for derived shards.
    id |= 1u64 << 63;

    ShardId(id)
}

// ---------------------------------------------------------------------------
// Â§2.7 Payload hash functions
// ---------------------------------------------------------------------------

/// Compute a 64-bit payload hash for an operation.
///
/// Used for op-log conflict detection: same OpId with different payload
/// hash = accidental reuse, rejected. Same OpId with same payload hash
/// = legitimate retry, cached result returned.
///
/// Not cryptographic. 64 bits of collision resistance is sufficient for
/// this guardrail purpose (birthday bound â‰ˆ 2^32 operations before
/// expected collision, far beyond any single shard's lifetime).
///
/// The `op_tag` provides domain separation between operation types
/// within the `OP_PAYLOAD_V1` namespace.
fn op_payload_hash(op_tag: &[u8], write_fields: impl FnOnce(&mut Hasher)) -> u64 {
    let mut h = domain_hasher(domain::OP_PAYLOAD_V1);
    op_tag.write_canonical(&mut h);
    write_fields(&mut h);
    finalize_64(&h)
}

/// Payload hash for a Checkpoint operation.
pub fn hash_checkpoint_payload(new_cursor: &Cursor) -> u64 {
    op_payload_hash(b"checkpoint", |h| {
        new_cursor.write_canonical(h);
    })
}

/// Payload hash for a Complete operation.
pub fn hash_complete_payload(final_cursor: &Cursor) -> u64 {
    op_payload_hash(b"complete", |h| {
        final_cursor.write_canonical(h);
    })
}

/// Payload hash for a Park operation.
pub fn hash_park_payload(reason: ParkReason) -> u64 {
    op_payload_hash(b"park", |h| {
        reason.write_canonical(h);
    })
}

/// Payload hash for a SplitReplace operation.
pub fn hash_split_replace_payload(plan: &SplitReplacePlan) -> u64 {
    op_payload_hash(b"split_replace", |h| {
        plan.write_canonical(h);
    })
}

/// Payload hash for a SplitResidual operation.
pub fn hash_split_residual_payload(plan: &SplitResidualPlan) -> u64 {
    op_payload_hash(b"split_residual", |h| {
        plan.write_canonical(h);
    })
}

// ---------------------------------------------------------------------------
// Â§2.8 ShardRecord â€” full coordination state for a shard
// ---------------------------------------------------------------------------

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
/// checkpoint time via `check_cursor_bounds` (chunk 1), not by
/// `assert_invariants` â€” cursor bounds require domain-specific
/// comparison logic and are a semantic invariant checked at the
/// operation level.
///
/// Reference: TigerBeetle's Tiger Style â€” assert at every boundary;
///            Gray & Cheriton, "Leases" (SOSP 1989) â€” lease semantics;
///            Stripe idempotency keys â€” op-log pattern.
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
    /// invariant fails, the coordinator panics â€” the operation is not
    /// persisted, and on crash-recovery the shard returns to its
    /// pre-operation state.
    ///
    /// Reference: TigerBeetle's Tiger Style â€” assert at every boundary.
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
    /// or evicted). Linear scan is fine â€” the log is bounded at
    /// `OP_LOG_CAP` entries.
    pub fn op_log_lookup(&self, op: OpId) -> Option<&OpLogEntry> {
        self.op_log.iter().find(|e| e.op_id == op)
    }

    /// Push an op-log entry, evicting the oldest if at capacity.
    ///
    /// Eviction is FIFO: the oldest entry (index 0) is removed first.
    /// This is correct because older operations are less likely to be
    /// retried â€” retry storms typically involve the most recent operations.
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
    /// lease is considered expired â€” the safe direction.
    ///
    /// Reference: Gray & Cheriton, "Leases" (SOSP 1989).
    pub fn is_leased_at(&self, now: LogicalTime) -> bool {
        match self.lease_deadline {
            Some(deadline) => now.0 < deadline.0,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Â§2.9 ShardSnapshot â€” worker-visible view
// ---------------------------------------------------------------------------

/// Read-only snapshot of shard state returned to a worker on acquisition.
///
/// Contains everything a worker needs to resume scanning:
/// - What to scan (`spec` â€” the key range and connector metadata)
/// - Where to resume (`cursor` â€” the two-layer progress marker)
/// - How to interpret the cursor (`cursor_semantics`)
/// - Lineage context (`parent`, `spawned`)
///
/// Excludes coordination-internal state:
/// - `tenant` â€” the worker already knows its tenant
/// - `lease_*`, `fence_epoch` â€” the worker gets these from the Lease
/// - `op_log` â€” internal to the coordinator
/// - `park_reason` â€” only relevant for parked shards, which aren't acquired
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
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test fixtures --

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId {
            job: JobId(1),
            policy: PolicyHash::from_bytes([0xAA; 32]),
        }
    }

    fn test_spec() -> ShardSpec {
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())
    }

    fn active_record() -> ShardRecord {
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

    fn leased_record() -> ShardRecord {
        ShardRecord {
            lease_owner: Some(WorkerId(1)),
            lease_deadline: Some(LogicalTime(100)),
            ..active_record()
        }
    }

    // -- CursorSemantics --

    #[test]
    fn cursor_semantics_roundtrip() {
        assert_eq!(CursorSemantics::from_u8(0), Some(CursorSemantics::Completed));
        assert_eq!(CursorSemantics::from_u8(1), Some(CursorSemantics::Dispatched));
        assert_eq!(CursorSemantics::from_u8(2), None);
    }

    #[test]
    fn cursor_semantics_discriminants_stable() {
        assert_eq!(CursorSemantics::Completed.as_u8(), 0);
        assert_eq!(CursorSemantics::Dispatched.as_u8(), 1);
    }

    #[test]
    fn cursor_semantics_canonical_bytes_distinct() {
        let mut h_comp = Hasher::new();
        let mut h_disp = Hasher::new();
        CursorSemantics::Completed.write_canonical(&mut h_comp);
        CursorSemantics::Dispatched.write_canonical(&mut h_disp);
        assert_ne!(h_comp.finalize(), h_disp.finalize());
    }

    // -- ShardStatus --

    #[test]
    fn shard_status_terminal() {
        assert!(!ShardStatus::Active.is_terminal());
        assert!(ShardStatus::Done.is_terminal());
        assert!(ShardStatus::Split.is_terminal());
        assert!(ShardStatus::Parked.is_terminal());
    }

    #[test]
    fn shard_status_roundtrip() {
        for v in 0..=3u8 {
            assert!(ShardStatus::from_u8(v).is_some());
        }
        assert_eq!(ShardStatus::from_u8(4), None);
    }

    #[test]
    fn shard_status_discriminants_stable() {
        assert_eq!(ShardStatus::Active.as_u8(), 0);
        assert_eq!(ShardStatus::Done.as_u8(), 1);
        assert_eq!(ShardStatus::Split.as_u8(), 2);
        assert_eq!(ShardStatus::Parked.as_u8(), 3);
    }

    // -- ParkReason --

    #[test]
    fn park_reason_roundtrip() {
        for v in 0..=4u8 {
            assert!(ParkReason::from_u8(v).is_some());
        }
        assert_eq!(ParkReason::from_u8(5), None);
    }

    #[test]
    fn park_reason_discriminants_stable() {
        assert_eq!(ParkReason::PermissionDenied.as_u8(), 0);
        assert_eq!(ParkReason::NotFound.as_u8(), 1);
        assert_eq!(ParkReason::Poisoned.as_u8(), 2);
        assert_eq!(ParkReason::TooManyErrors.as_u8(), 3);
        assert_eq!(ParkReason::Other.as_u8(), 4);
    }

    #[test]
    fn park_reason_canonical_bytes_all_distinct() {
        let reasons = [
            ParkReason::PermissionDenied,
            ParkReason::NotFound,
            ParkReason::Poisoned,
            ParkReason::TooManyErrors,
            ParkReason::Other,
        ];
        let hashes: Vec<_> = reasons.iter().map(|r| {
            let mut h = Hasher::new();
            r.write_canonical(&mut h);
            h.finalize()
        }).collect();

        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "collision: {i} vs {j}");
            }
        }
    }

    // -- OpResult --

    #[test]
    fn op_result_children_accessor() {
        let ack = OpResult::Ack;
        assert!(ack.children().is_none());

        let split = OpResult::SplitReplace {
            children: vec![ShardId(1), ShardId(2)],
        };
        assert_eq!(split.children(), Some(&[ShardId(1), ShardId(2)][..]));
    }

    #[test]
    fn op_result_residual_accessor() {
        let ack = OpResult::Ack;
        assert!(ack.residual().is_none());

        let split = OpResult::SplitResidual { residual: ShardId(99) };
        assert_eq!(split.residual(), Some(ShardId(99)));
    }

    // -- derive_split_shard_id --

    #[test]
    fn derive_split_shard_id_deterministic() {
        let run = test_run();
        let id1 = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Child, 0);
        let id2 = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Child, 0);
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_split_shard_id_top_bit_set() {
        let id = derive_split_shard_id(
            test_run(), ShardId(0), OpId(1), DerivedShardKind::Child, 0,
        );
        assert!(id.0 & (1u64 << 63) != 0, "top bit must be set");
    }

    #[test]
    fn derive_split_shard_id_different_index_different_id() {
        let run = test_run();
        let id0 = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Child, 0);
        let id1 = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Child, 1);
        assert_ne!(id0, id1);
    }

    #[test]
    fn derive_split_shard_id_different_kind_different_id() {
        let run = test_run();
        let child = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Child, 0);
        let residual = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Residual, 0);
        assert_ne!(child, residual);
    }

    #[test]
    fn derive_split_shard_id_different_parent_different_id() {
        let run = test_run();
        let a = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Child, 0);
        let b = derive_split_shard_id(run, ShardId(1), OpId(1), DerivedShardKind::Child, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_split_shard_id_different_op_different_id() {
        let run = test_run();
        let a = derive_split_shard_id(run, ShardId(0), OpId(1), DerivedShardKind::Child, 0);
        let b = derive_split_shard_id(run, ShardId(0), OpId(2), DerivedShardKind::Child, 0);
        assert_ne!(a, b);
    }

    // -- Payload hash functions --

    #[test]
    fn hash_checkpoint_deterministic() {
        let cursor = Cursor::with_last_key(b"item_key".to_vec());
        assert_eq!(
            hash_checkpoint_payload(&cursor),
            hash_checkpoint_payload(&cursor),
        );
    }

    #[test]
    fn hash_checkpoint_sensitive_to_cursor() {
        let c1 = Cursor::with_last_key(b"a".to_vec());
        let c2 = Cursor::with_last_key(b"b".to_vec());
        assert_ne!(
            hash_checkpoint_payload(&c1),
            hash_checkpoint_payload(&c2),
        );
    }

    #[test]
    fn hash_complete_deterministic() {
        let cursor = Cursor::with_last_key(b"final".to_vec());
        assert_eq!(
            hash_complete_payload(&cursor),
            hash_complete_payload(&cursor),
        );
    }

    #[test]
    fn hash_checkpoint_vs_complete_different() {
        // Same cursor, different operation â†’ different hash.
        let cursor = Cursor::with_last_key(b"same".to_vec());
        assert_ne!(
            hash_checkpoint_payload(&cursor),
            hash_complete_payload(&cursor),
        );
    }

    #[test]
    fn hash_park_deterministic() {
        assert_eq!(
            hash_park_payload(ParkReason::NotFound),
            hash_park_payload(ParkReason::NotFound),
        );
    }

    #[test]
    fn hash_park_sensitive_to_reason() {
        assert_ne!(
            hash_park_payload(ParkReason::NotFound),
            hash_park_payload(ParkReason::PermissionDenied),
        );
    }

    #[test]
    fn hash_split_replace_deterministic() {
        let plan = SplitReplacePlan {
            children: vec![
                SplitReplaceChild {
                    spec: ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                    cursor: Cursor::initial(),
                },
                SplitReplaceChild {
                    spec: ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                    cursor: Cursor::initial(),
                },
            ],
        };
        assert_eq!(
            hash_split_replace_payload(&plan),
            hash_split_replace_payload(&plan),
        );
    }

    #[test]
    fn hash_split_replace_sensitive_to_children() {
        let plan_a = SplitReplacePlan {
            children: vec![
                SplitReplaceChild {
                    spec: ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                    cursor: Cursor::initial(),
                },
                SplitReplaceChild {
                    spec: ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                    cursor: Cursor::initial(),
                },
            ],
        };
        let plan_b = SplitReplacePlan {
            children: vec![
                SplitReplaceChild {
                    spec: ShardSpec::with_range(b"a".to_vec(), b"n".to_vec()),
                    cursor: Cursor::initial(),
                },
                SplitReplaceChild {
                    spec: ShardSpec::with_range(b"n".to_vec(), b"z".to_vec()),
                    cursor: Cursor::initial(),
                },
            ],
        };
        assert_ne!(
            hash_split_replace_payload(&plan_a),
            hash_split_replace_payload(&plan_b),
        );
    }

    #[test]
    fn hash_split_residual_deterministic() {
        let plan = SplitResidualPlan {
            parent_new_spec: ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            residual_spec: ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            residual_cursor: Cursor::initial(),
        };
        assert_eq!(
            hash_split_residual_payload(&plan),
            hash_split_residual_payload(&plan),
        );
    }

    // -- ShardRecord: assert_invariants --

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
        let r = ShardRecord {
            status: ShardStatus::Done,
            lease_owner: None,
            lease_deadline: None,
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    fn assert_invariants_parked_ok() {
        let r = ShardRecord {
            status: ShardStatus::Parked,
            park_reason: Some(ParkReason::TooManyErrors),
            lease_owner: None,
            lease_deadline: None,
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    fn assert_invariants_split_ok() {
        let r = ShardRecord {
            status: ShardStatus::Split,
            lease_owner: None,
            lease_deadline: None,
            spawned: vec![ShardId(100), ShardId(101)],
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must have park_reason")]
    fn assert_invariants_parked_without_reason_panics() {
        let r = ShardRecord {
            status: ShardStatus::Parked,
            park_reason: None,
            lease_owner: None,
            lease_deadline: None,
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must not have park_reason")]
    fn assert_invariants_active_with_reason_panics() {
        let r = ShardRecord {
            park_reason: Some(ParkReason::Other),
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must both be Some or both be None")]
    fn assert_invariants_lease_owner_without_deadline_panics() {
        let r = ShardRecord {
            lease_owner: Some(WorkerId(1)),
            lease_deadline: None,
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must both be Some or both be None")]
    fn assert_invariants_lease_deadline_without_owner_panics() {
        let r = ShardRecord {
            lease_owner: None,
            lease_deadline: Some(LogicalTime(100)),
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must not have a lease")]
    fn assert_invariants_done_with_lease_panics() {
        let r = ShardRecord {
            status: ShardStatus::Done,
            lease_owner: Some(WorkerId(1)),
            lease_deadline: Some(LogicalTime(100)),
            ..active_record()
        };
        r.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "exceeds cap")]
    fn assert_invariants_op_log_overflow_panics() {
        let mut r = active_record();
        for i in 0..=ShardRecord::OP_LOG_CAP {
            r.op_log.push(OpLogEntry {
                op_id: OpId(i as u64),
                kind: OpKind::Checkpoint,
                payload_hash: 0,
                result: OpResult::Ack,
            });
        }
        r.assert_invariants();
    }

    // -- ShardRecord: op_log --

    #[test]
    fn op_log_lookup_found() {
        let mut r = active_record();
        r.op_log_push(OpLogEntry {
            op_id: OpId(42),
            kind: OpKind::Checkpoint,
            payload_hash: 0xDEAD,
            result: OpResult::Ack,
        });
        let entry = r.op_log_lookup(OpId(42));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().payload_hash, 0xDEAD);
    }

    #[test]
    fn op_log_lookup_not_found() {
        let r = active_record();
        assert!(r.op_log_lookup(OpId(999)).is_none());
    }

    #[test]
    fn op_log_push_evicts_oldest() {
        let mut r = active_record();
        for i in 0..ShardRecord::OP_LOG_CAP {
            r.op_log_push(OpLogEntry {
                op_id: OpId(i as u64),
                kind: OpKind::Checkpoint,
                payload_hash: i as u64,
                result: OpResult::Ack,
            });
        }
        assert_eq!(r.op_log.len(), ShardRecord::OP_LOG_CAP);
        assert!(r.op_log_lookup(OpId(0)).is_some()); // oldest still present

        // Push one more â€” evicts oldest (OpId 0).
        r.op_log_push(OpLogEntry {
            op_id: OpId(999),
            kind: OpKind::Checkpoint,
            payload_hash: 999,
            result: OpResult::Ack,
        });
        assert_eq!(r.op_log.len(), ShardRecord::OP_LOG_CAP);
        assert!(r.op_log_lookup(OpId(0)).is_none()); // evicted
        assert!(r.op_log_lookup(OpId(999)).is_some()); // newest present
    }

    // -- ShardRecord: snapshot --

    #[test]
    fn snapshot_preserves_fields() {
        let r = ShardRecord {
            cursor: Cursor::with_last_key(b"progress".to_vec()),
            parent: Some(ShardId(10)),
            spawned: vec![ShardId(20)],
            ..leased_record()
        };
        let snap = r.snapshot();

        assert_eq!(snap.status, r.status);
        assert_eq!(snap.spec, r.spec);
        assert_eq!(snap.cursor, r.cursor);
        assert_eq!(snap.cursor_semantics, r.cursor_semantics);
        assert_eq!(snap.parent, r.parent);
        assert_eq!(snap.spawned, r.spawned);
    }

    #[test]
    fn snapshot_does_not_leak_coordination_state() {
        // ShardSnapshot has no lease, fence, op_log, or tenant fields.
        // This is a compile-time guarantee (the struct doesn't have them),
        // but we verify the snapshot doesn't carry tenant info through
        // any field by checking the Debug output.
        let r = leased_record();
        let snap = r.snapshot();
        let dbg = format!("{:?}", snap);
        // The tenant bytes (0x01 repeated) should not appear.
        assert!(!dbg.contains("TenantId"), "snapshot must not contain TenantId");
    }

    // -- ShardRecord: is_leased_at --

    #[test]
    fn is_leased_at_no_lease() {
        let r = active_record();
        assert!(!r.is_leased_at(LogicalTime(0)));
        assert!(!r.is_leased_at(LogicalTime(100)));
    }

    #[test]
    fn is_leased_at_before_deadline() {
        let r = leased_record(); // deadline = 100
        assert!(r.is_leased_at(LogicalTime(0)));
        assert!(r.is_leased_at(LogicalTime(99)));
    }

    #[test]
    fn is_leased_at_at_deadline_is_expired() {
        let r = leased_record(); // deadline = 100
        assert!(!r.is_leased_at(LogicalTime(100)));
    }

    #[test]
    fn is_leased_at_after_deadline() {
        let r = leased_record(); // deadline = 100
        assert!(!r.is_leased_at(LogicalTime(101)));
    }

    // -- Property-based --

    proptest::proptest! {
        #[test]
        fn derive_split_shard_id_is_pure(
            job in proptest::num::u64::ANY,
            policy in proptest::array::uniform32(proptest::num::u8::ANY),
            parent in proptest::num::u64::ANY,
            op in proptest::num::u64::ANY,
            kind_byte in 0u8..=1,
            index in proptest::num::u32::ANY,
        ) {
            let run = RunId {
                job: JobId(job),
                policy: PolicyHash::from_bytes(policy),
            };
            let kind = match kind_byte {
                0 => DerivedShardKind::Child,
                _ => DerivedShardKind::Residual,
            };
            let id1 = derive_split_shard_id(run, ShardId(parent), OpId(op), kind, index);
            let id2 = derive_split_shard_id(run, ShardId(parent), OpId(op), kind, index);
            prop_assert_eq!(id1, id2);
            prop_assert!(id1.0 & (1u64 << 63) != 0, "top bit must be set");
        }

        #[test]
        fn hash_checkpoint_is_pure(
            key in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
        ) {
            let cursor = Cursor::with_last_key(key);
            prop_assert_eq!(
                hash_checkpoint_payload(&cursor),
                hash_checkpoint_payload(&cursor),
            );
        }

        #[test]
        fn hash_park_is_pure(reason_byte in 0u8..=4) {
            let reason = ParkReason::from_u8(reason_byte).unwrap();
            prop_assert_eq!(
                hash_park_payload(reason),
                hash_park_payload(reason),
            );
        }
    }
}
