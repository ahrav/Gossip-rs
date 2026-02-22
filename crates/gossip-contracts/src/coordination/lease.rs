//! Lease and per-shard op-log types for the coordination protocol.
//!
//! This module defines the types that govern exclusive shard ownership and
//! idempotent mutation replay — the two mechanisms that allow workers to
//! mutate shard state safely in a distributed setting.
//!
//! ## Type overview
//!
//! ```text
//! ┌──────────────┐           ┌──────────────────┐
//! │  LeaseHolder  │◄─stored──│   ShardRecord    │
//! │(owner+deadline)│  in      │  Option<lease>   │
//! └──────────────┘           │  op_log: Ring<16> │
//!                            └────────┬─────────┘
//!      ┌───────┐                      │ entries
//!      │ Lease │─────fence────►  FenceEpoch
//!      │(token)│                      │
//!      └───────┘              ┌───────▼────────┐
//!                             │  OpLogEntry     │
//!                             │  op_id + kind   │
//!                             │  result + hash  │
//!                             │  executed_at    │
//!                             └────────────────┘
//! ```
//!
//! - [`LeaseHolder`] — stored *in* the [`ShardRecord`](super::record::ShardRecord)
//!   to track who currently owns the shard and when the lease expires.
//! - [`Lease`] — the capability *returned to the worker* by `acquire_and_restore`.
//!   Workers present this token on every subsequent mutation. The coordinator
//!   validates the embedded [`FenceEpoch`] against the record's current epoch.
//! - [`OpKind`], [`OpResult`], [`OpLogEntry`] — the vocabulary and storage for
//!   the per-shard idempotency log (see below).
//!
//! ## Fencing protocol
//!
//! The [`FenceEpoch`] is the primary defense against zombie workers — workers
//! that hold an expired lease but continue issuing mutations due to GC pauses,
//! network partitions, or slow processing. Every ownership transfer
//! (`acquire_and_restore`) increments the epoch; mutations carrying a stale
//! epoch are rejected before any state change.
//!
//! Reference: Kleppmann, "How to do distributed locking" (2016);
//!            Gray & Cheriton, "Leases" (SOSP 1989).
//!
//! ## Idempotency window
//!
//! Mutating operations (except `acquire_and_restore` and `renew`, which are
//! coordinator-level and do not appear in the op-log) carry an [`OpId`]. The
//! shard record caches the last 16 operation fingerprints in a ring buffer so
//! the coordinator can detect retries and return cached results instead of
//! re-executing.
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
//!
//! ## Replay detection flow
//!
//! When a mutation arrives with an `OpId`:
//! 1. Look up the `OpId` in the shard's op-log (reverse scan, most-recent first).
//! 2. **Found, same `payload_hash`** → return the cached [`OpResult`] (idempotent replay).
//! 3. **Found, different `payload_hash`** → reject as `OpIdConflict` (same key, different payload).
//! 4. **Not found** → execute the mutation, record the entry.
//!
//! See [`check_op_idempotency`](super::validation::check_op_idempotency) for
//! the implementation.

use std::fmt;

use crate::identity::{
    FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
};

// ============================================================================
// LeaseHolder
// ============================================================================

/// Identity and deadline of the worker currently holding a shard lease.
///
/// Bundles `owner` and `deadline` into a single value so that the
/// [`ShardRecord`](super::record::ShardRecord) can store
/// `Option<LeaseHolder>` instead of two separate `Option` fields — making the
/// "both-present-or-both-absent" invariant structurally impossible to violate.
///
/// This type lives *inside* the shard record (coordinator-side). Workers
/// receive a [`Lease`] instead, which additionally carries the
/// [`FenceEpoch`] and shard identity needed to present a fencing token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseHolder {
    owner: WorkerId,
    deadline: LogicalTime,
}

impl LeaseHolder {
    /// Create a new lease-holder binding.
    ///
    /// No validation is performed here — the coordinator is responsible
    /// for ensuring `deadline` is in the future relative to the current
    /// logical time.
    #[must_use]
    pub fn new(owner: WorkerId, deadline: LogicalTime) -> Self {
        debug_assert!(
            deadline > LogicalTime::ZERO,
            "LeaseHolder deadline must be non-zero"
        );
        Self { owner, deadline }
    }

    /// The worker holding the lease.
    #[inline]
    #[must_use]
    pub fn owner(&self) -> WorkerId {
        self.owner
    }

    /// The logical time at which the lease expires.
    ///
    /// The coordinator uses a half-open interval: `now < deadline` means
    /// the lease is active; `now >= deadline` means expired.
    #[inline]
    #[must_use]
    pub fn deadline(&self) -> LogicalTime {
        self.deadline
    }
}

// ============================================================================
// Lease
// ============================================================================

/// A capability token granting exclusive, temporary rights to mutate a shard.
///
/// Returned by `acquire_and_restore` and required by every lease-gated
/// op-log mutation (`checkpoint`, `complete`, `park_shard`, `split_replace`,
/// `split_residual`). The coordinator validates two properties on each call:
///
/// 1. **Fence epoch** — `lease.fence == record.fence_epoch`. A mismatch means
///    the lease was superseded by a newer acquisition and the caller is a
///    zombie. The epoch is monotonically increasing: it increments on every
///    `acquire_and_restore` and on administrative unpark.
///
/// 2. **Deadline** — `now < lease.deadline`. An expired lease does not
///    authorize mutations; the worker must re-acquire.
///
/// ## Construction and visibility
///
/// The constructor is `pub(crate)` — only the coordinator produces leases.
/// Workers receive them as opaque tokens and present them back via public
/// accessors. This prevents workers from forging or extending their own
/// leases.
#[must_use = "discarding a Lease wastes the shard's availability window until expiry"]
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
    /// Construct a new lease binding a worker to a shard for a bounded duration.
    ///
    /// Only callable within the crate — the coordinator is the sole producer.
    ///
    /// # Panics
    ///
    /// - If `fence` is less than [`FenceEpoch::INITIAL`] (epoch 1). A zero
    ///   epoch is reserved as a sentinel and must never appear in a live lease.
    /// - If `deadline` is [`LogicalTime::ZERO`]. A zero deadline would make
    ///   the lease instantly expired, which is never valid.
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

    /// The fencing epoch — compared against the shard record's current epoch
    /// on every lease-gated operation to detect zombie workers.
    #[inline]
    #[must_use]
    pub fn fence(&self) -> FenceEpoch {
        self.fence
    }

    /// The logical time at which this lease expires.
    ///
    /// The lease is active while `now < deadline` (half-open). At the
    /// deadline or after, the coordinator rejects mutations and allows
    /// other workers to re-acquire the shard.
    #[inline]
    #[must_use]
    pub fn deadline(&self) -> LogicalTime {
        self.deadline
    }

    /// Reconstruct the [`ShardKey`] for coordinator lookups.
    ///
    /// Avoids requiring callers to separately track the `(RunId, ShardId)`
    /// pair — the lease already carries both.
    #[inline]
    #[must_use]
    pub fn shard_key(&self) -> ShardKey {
        ShardKey::new(self.run, self.shard)
    }

    /// Extend the lease deadline after a successful renewal.
    ///
    /// Only callable within the crate — workers cannot extend their
    /// own deadlines without going through the coordinator's `renew` path.
    /// The fence epoch is **not** changed; renewal is a deadline extension,
    /// not an ownership transfer.
    ///
    /// # Panics
    ///
    /// - Panics if `deadline` is [`LogicalTime::ZERO`].
    /// - Debug-only: panics if `deadline` does not advance past the
    ///   current deadline (monotonicity violation).
    #[inline]
    pub(crate) fn set_deadline(&mut self, deadline: LogicalTime) {
        assert!(
            deadline > LogicalTime::ZERO,
            "Lease deadline must be > ZERO, got {deadline:?}",
        );
        debug_assert!(
            deadline > self.deadline,
            "set_deadline: new deadline {deadline:?} must advance past current {:?}",
            self.deadline,
        );
        self.deadline = deadline;
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
/// Most variants are **lease-gated** — they require a valid [`Lease`] held by
/// the calling worker. The exception is [`Unpark`](Self::Unpark), which is an
/// admin operation the coordinator may perform without a lease.
///
/// ## Relationship to shard status transitions
///
/// ```text
/// OpKind          │ Status change          │ Lease required?
/// ────────────────┼────────────────────────┼────────────────
/// Checkpoint      │ none (cursor advances) │ yes
/// Complete        │ Active → Done          │ yes
/// Park            │ Active → Parked        │ yes
/// SplitReplace    │ Active → Split         │ yes
/// SplitResidual   │ none (parent stays Active, residual created) │ yes
/// Unpark          │ Parked → Active (admin)│ no
/// ```
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted in the op-log. Existing values should not be reassigned
/// without updating all existing op-log entries. Compile-time assertions
/// below enforce the current mapping.
///
/// ## Convergence safety (bounded op-log)
///
/// The per-shard op-log is a 16-entry ring buffer. Once an entry is evicted,
/// the coordinator cannot distinguish a retry from a new operation and will
/// re-execute it. This is safe **only if every operation is convergent** —
/// re-executing a previously completed operation must produce the same
/// observable state as not re-executing it.
///
/// Convergence requires idempotency (f(f(x)) = f(x)) and, for operations
/// that may be reordered with concurrent mutations, commutativity. Each
/// variant documents its convergence justification below.
///
/// If a future variant is **not** convergent under re-execution, it must
/// either: (a) guarantee it is never evicted from the op-log (as
/// `SplitReplace` does — terminal status prevents further ops), or
/// (b) use an external deduplication mechanism with unbounded retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpKind {
    /// Save scan progress without changing shard status.
    ///
    /// Advances the shard's cursor to a new position within its key range.
    /// The most frequent operation during normal scanning.
    ///
    /// Convergence: if the op-log entry is present, replay returns the
    /// cached result. If evicted and re-executed, the cursor update
    /// either succeeds (setting the same value, idempotent by payload
    /// hash) or is rejected by cursor-monotonicity (no state change).
    /// Either outcome is convergent. Concurrent checkpoints are
    /// cursor-monotonic, so reordering produces the same final cursor
    /// (max of the two).
    Checkpoint = 0,

    /// Mark the shard as fully processed — terminal transition to
    /// [`Done`](super::record::ShardStatus::Done).
    ///
    /// After completion, the lease is released and no further mutations
    /// are accepted on this shard.
    ///
    /// Convergence: terminal transition is irreversible. The op-log entry
    /// is structurally never evicted — after Done, no further ops can
    /// push entries, so re-execution always hits the cached result. No
    /// state change on replay.
    Complete = 1,

    /// Suspend the shard due to an error condition — terminal transition to
    /// [`Parked`](super::record::ShardStatus::Parked).
    ///
    /// Resumption requires an out-of-band administrative [`Unpark`](Self::Unpark)
    /// which increments the fence epoch.
    ///
    /// Convergence: terminal within the lease scope. After Park, any
    /// admin Unpark bumps the fence epoch, invalidating the parking
    /// worker's lease. The old worker cannot re-execute Park after
    /// eviction because it fails fence validation. If the op-log entry
    /// is still present, re-execution returns the cached result.
    Park = 2,

    /// Replace the parent shard with N child shards — terminal transition to
    /// [`Split`](super::record::ShardStatus::Split).
    ///
    /// The children collectively cover the parent's key range (no gaps,
    /// no overlaps). The parent lease is released.
    ///
    /// Convergence: terminal transition to Split. Additionally, the op-log
    /// entry is structurally never evicted — after split, no further ops
    /// can push entries, so the entry persists indefinitely.
    SplitReplace = 3,

    /// Shrink the current shard and create a residual shard for the
    /// unprocessed upper portion of the key range.
    ///
    /// Unlike `SplitReplace`, this is **non-terminal** — the parent
    /// stays `Active` with a smaller range and retains its lease.
    ///
    /// Convergence: re-execution with the same plan produces the same
    /// residual shard (deterministic ID derivation from parent ID +
    /// index) and the same parent spec update (idempotent by payload
    /// hash). Duplicate creation is detected by the deterministic
    /// residual ID.
    SplitResidual = 4,

    /// Administrative: resume a parked shard (Parked -> Active).
    ///
    /// Not lease-gated — the coordinator may unpark a shard without
    /// the worker that originally parked it. Unparking increments the
    /// fence epoch and clears the park reason.
    ///
    /// Convergence: Parked -> Active is idempotent (unparking an
    /// already-Active shard is rejected by the status precondition
    /// check with `NotParked` — no state change). Fence epoch
    /// increment on re-execution is safe — it only invalidates stale
    /// leases, which is the conservative direction.
    Unpark = 5,
}

impl OpKind {
    /// Decode a `u8` discriminant to the corresponding variant.
    ///
    /// Returns `None` for values outside the known range, providing
    /// a safe parsing boundary when decoding potentially corrupt or
    /// unexpected `u8` values.
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

    /// Encode as the stable `u8` discriminant for persistence.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for OpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Checkpoint => "Checkpoint",
            Self::Complete => "Complete",
            Self::Park => "Park",
            Self::SplitReplace => "SplitReplace",
            Self::SplitResidual => "SplitResidual",
            Self::Unpark => "Unpark",
        })
    }
}

// Compile-time assertions: discriminant values must never drift from their
// persisted encoding. If a variant is added, add a corresponding assertion.
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
/// Recorded alongside [`OpKind`] in the [`OpLogEntry`] so retries can return
/// the original outcome without re-executing. When a worker retries with
/// the same `(OpId, payload_hash)`, the coordinator returns this cached
/// status directly.
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted in the op-log. Existing values should not be reassigned
/// without updating all existing op-log entries. Compile-time assertions
/// below enforce the current mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpResult {
    /// The operation executed successfully and the shard record was mutated.
    Completed = 0,

    /// The operation failed validation — the shard record was **not** mutated.
    ///
    /// On retry, the coordinator returns this cached failure rather than
    /// re-validating, since the same inputs will fail the same way.
    Error = 1,

    /// The operation was valid at the time of submission but was overtaken by
    /// a later mutation that makes it redundant.
    ///
    /// Example: a checkpoint whose cursor position was already advanced past
    /// by a subsequent checkpoint or complete. The shard's state is consistent
    /// but the specific mutation this entry records had no visible effect.
    Superseded = 2,
}

impl OpResult {
    /// Decode a `u8` discriminant to the corresponding variant.
    ///
    /// Returns `None` for values outside the known range.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Completed),
            1 => Some(Self::Error),
            2 => Some(Self::Superseded),
            _ => None,
        }
    }

    /// Encode as the stable `u8` discriminant for persistence.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for OpResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Completed => "Completed",
            Self::Error => "Error",
            Self::Superseded => "Superseded",
        })
    }
}

// Compile-time assertions: discriminant values must never drift.
const _: () = assert!(OpResult::Completed as u8 == 0);
const _: () = assert!(OpResult::Error as u8 == 1);
const _: () = assert!(OpResult::Superseded as u8 == 2);
const _: () = assert!(core::mem::size_of::<OpResult>() == 1);

// ============================================================================
// OpLogEntry
// ============================================================================

/// A single entry in the bounded per-shard operation log.
///
/// The shard record caches the last 16 entries in a ring buffer (see
/// [`ShardRecord::OP_LOG_CAP`](super::record::ShardRecord::OP_LOG_CAP)).
/// When a worker retries an operation with the same [`OpId`], the coordinator
/// looks up the matching entry and returns the cached [`OpResult`] instead of
/// re-executing. If the retry carries a different `payload_hash`, the
/// coordinator rejects it as a conflicting mutation.
///
/// ## Deduplication key
///
/// The deduplication key is `(OpId, payload_hash)`:
/// - **Same pair** → idempotent replay, return cached result.
/// - **Same `OpId`, different hash** → conflict, reject.
/// - **`OpId` not found** → new operation (or evicted; see module docs).
///
/// ## Construction
///
/// The constructor is `pub(crate)` — only the coordinator creates entries.
/// Tests and snapshot consumers read via public accessors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpLogEntry {
    op_id: OpId,
    kind: OpKind,
    result: OpResult,
    payload_hash: u64,
    executed_at: LogicalTime,
}

impl OpLogEntry {
    /// Record a completed operation in the op-log.
    ///
    /// Only callable within the crate — the coordinator is the sole producer.
    /// The caller must ensure `op_id` uniqueness within the shard's op-log
    /// (checked by [`ShardRecord::op_log_push`](super::record::ShardRecord::op_log_push)).
    ///
    /// # Panics
    ///
    /// - If `executed_at` is [`LogicalTime::ZERO`] — a zero timestamp would
    ///   violate the "time is always positive" invariant.
    /// - If `payload_hash` is 0 — zero is reserved as a sentinel indicating
    ///   the caller failed to compute a hash, which would break conflict
    ///   detection.
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

    /// The operation's unique idempotency key.
    ///
    /// Together with [`payload_hash`](Self::payload_hash), forms the
    /// deduplication pair used by
    /// [`check_op_idempotency`](super::validation::check_op_idempotency).
    #[inline]
    #[must_use]
    pub fn op_id(&self) -> OpId {
        self.op_id
    }

    /// The kind of operation that was executed.
    #[inline]
    #[must_use]
    pub fn kind(&self) -> OpKind {
        self.kind
    }

    /// The cached result status returned to retrying callers.
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

    // -- OpKind Display ---------------------------------------------------

    #[test]
    fn op_kind_display_all_variants() {
        let cases: &[(OpKind, &str)] = &[
            (OpKind::Checkpoint, "Checkpoint"),
            (OpKind::Complete, "Complete"),
            (OpKind::Park, "Park"),
            (OpKind::SplitReplace, "SplitReplace"),
            (OpKind::SplitResidual, "SplitResidual"),
            (OpKind::Unpark, "Unpark"),
        ];
        for &(kind, expected) in cases {
            assert_eq!(kind.to_string(), expected, "OpKind::Display for {kind:?}");
        }
    }

    // -- OpResult Display -------------------------------------------------

    #[test]
    fn op_result_display_all_variants() {
        let cases: &[(OpResult, &str)] = &[
            (OpResult::Completed, "Completed"),
            (OpResult::Error, "Error"),
            (OpResult::Superseded, "Superseded"),
        ];
        for &(result, expected) in cases {
            assert_eq!(
                result.to_string(),
                expected,
                "OpResult::Display for {result:?}"
            );
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
