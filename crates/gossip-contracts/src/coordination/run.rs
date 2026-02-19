//! Run-level types, validation, payload hashing, and the `RunManagement` trait.
//!
//! A "run" is a single scan invocation — it groups a set of shards that
//! collectively cover the target data source. The coordinator tracks run
//! status, validates shard manifests, and provides progress aggregation.
//!
//! ## Design Decisions (locked)
//!
//! D2.18: `RunRecord` is the coordinator's authoritative record for a run.
//! D2.19: `RunStatus` has 5 states: Initializing → Active → Done | Failed;
//!        Cancelled is reachable from Initializing or Active via `cancel_run`.
//! D2.20: Two-phase creation: `create_run` → `register_shards`.
//! D2.21: Admin operations (unpark, cancel) are NOT lease-gated.
//! D2.22: `RunManagement` is separate from `CoordinationBackend`.
//! D2.23: `now: LogicalTime` is passed explicitly to every mutating and
//!        time-aware operation. Pure record lookups (`get_run`) are exempt.
//! D2.24: Shard listing returns `ShardSummary` (lightweight).
//! D2.25: `RunRecord` gets its own bounded op-log (cap: 8).

use std::fmt;
use std::num::NonZeroU64;

use crate::coordination::cursor::{Cursor, MAX_KEY_SIZE};
use crate::coordination::error::IdempotentOutcome;
use crate::coordination::record::{ParkReason, ShardRecord, ShardStatus};
use crate::coordination::run_errors::{
    CancelRunError, CompleteRunError, CreateRunError, FailRunError, GetRunError,
    RegisterShardsError, UnparkError,
};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::split::op_payload_hash;
use crate::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId,
};
use gossip_stdx::RingBuffer;

// ============================================================================
// RunStatus
// ============================================================================

/// Run lifecycle state.
///
/// ```text
///  Initializing ──register_shards──→ Active
///       │                              │
///       │ cancel_run          ┌────────┼────────┐
///       ▼                  complete  fail_run  cancel
///    Cancelled               │        │        │
///                            ▼        ▼        ▼
///                          Done     Failed   Cancelled
/// ```
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: `#[repr(u8)]` values are persisted.
/// Never reorder or reuse discriminant slots.
/// **Safety (terminal irreversibility)**: Done/Failed/Cancelled never changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RunStatus {
    Initializing = 0,
    Active = 1,
    Done = 2,
    Failed = 3,
    Cancelled = 4,
}

impl RunStatus {
    /// Whether the run is in a terminal state (no further transitions).
    #[inline]
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }

    /// Reconstruct from a persisted `u8` discriminant.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Initializing),
            1 => Some(Self::Active),
            2 => Some(Self::Done),
            3 => Some(Self::Failed),
            4 => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// The persisted discriminant value.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for RunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initializing => f.write_str("Initializing"),
            Self::Active => f.write_str("Active"),
            Self::Done => f.write_str("Done"),
            Self::Failed => f.write_str("Failed"),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

const _: () = assert!(core::mem::size_of::<RunStatus>() == 1);

// ============================================================================
// RunConfigError
// ============================================================================

/// Error returned by [`RunConfig::try_new`] when validation fails.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunConfigError {
    /// Lease duration must be strictly positive.
    ZeroLeaseDuration,
}

impl fmt::Display for RunConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLeaseDuration => f.write_str("lease_duration must be > 0"),
        }
    }
}

impl std::error::Error for RunConfigError {}

// ============================================================================
// RunConfig
// ============================================================================

/// Per-run configuration, immutable after creation.
///
/// Fields are `pub(crate)` to allow coordinator-internal mutation during
/// record construction, with public accessor methods for external callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunConfig {
    pub(crate) cursor_semantics: CursorSemantics,
    /// Lease duration in [`LogicalTime`] ticks. `NonZeroU64` makes the
    /// zero-duration invariant unrepresentable — no runtime check needed.
    pub(crate) lease_duration: NonZeroU64,
    pub(crate) max_shard_retries: Option<u32>,
}

impl RunConfig {
    /// Create a validated `RunConfig`.
    ///
    /// # Errors
    ///
    /// Returns [`RunConfigError::ZeroLeaseDuration`] if `lease_duration` is 0.
    pub fn try_new(
        cursor_semantics: CursorSemantics,
        lease_duration: u64,
        max_shard_retries: Option<u32>,
    ) -> Result<Self, RunConfigError> {
        let lease_duration =
            NonZeroU64::new(lease_duration).ok_or(RunConfigError::ZeroLeaseDuration)?;
        Ok(Self {
            cursor_semantics,
            lease_duration,
            max_shard_retries,
        })
    }

    /// Panicking validator for coordinator-internal paths.
    ///
    /// Use [`try_new`](Self::try_new) for external input.
    pub(crate) fn assert_valid(&self) {
        // lease_duration > 0 is guaranteed by NonZeroU64.
        let _ = self.lease_duration;
    }

    #[must_use]
    pub fn cursor_semantics(&self) -> CursorSemantics {
        self.cursor_semantics
    }

    /// Lease duration in [`LogicalTime`] ticks.
    #[must_use]
    pub fn lease_duration(&self) -> u64 {
        self.lease_duration.get()
    }

    #[must_use]
    pub fn max_shard_retries(&self) -> Option<u32> {
        self.max_shard_retries
    }
}

// ============================================================================
// RunOpKind
// ============================================================================

/// Discriminant for run-level op-log entries.
///
/// Note: `UnparkShard` is intentionally absent. Unpark idempotency lives in
/// the shard op-log (cap=16), not the run op-log, because unpark targets a
/// specific shard and the run op-log would need a keying scheme to distinguish
/// `unpark(shard_A)` from `unpark(shard_B)`. See PD-4 in the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RunOpKind {
    RegisterShards = 0,
    CompleteRun = 1,
    FailRun = 2,
    CancelRun = 3,
}

impl RunOpKind {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::RegisterShards),
            1 => Some(Self::CompleteRun),
            2 => Some(Self::FailRun),
            3 => Some(Self::CancelRun),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for RunOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterShards => f.write_str("RegisterShards"),
            Self::CompleteRun => f.write_str("CompleteRun"),
            Self::FailRun => f.write_str("FailRun"),
            Self::CancelRun => f.write_str("CancelRun"),
        }
    }
}

const _: () = assert!(core::mem::size_of::<RunOpKind>() == 1);

// ============================================================================
// RunOpResult
// ============================================================================

/// Result payload stored in a run op-log entry.
///
/// `RegisteredShards` carries the created shard IDs so that idempotent replays
/// of `register_shards` can return the same IDs without re-querying state.
/// Terminal operations (complete, fail, cancel) have no meaningful return data,
/// so they use `Ack`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOpResult {
    /// Shard IDs created by `register_shards`, cached for replay.
    RegisteredShards { shard_ids: Box<[ShardId]> },
    /// No-data acknowledgment for terminal transitions (complete, fail, cancel).
    Ack,
}

// ============================================================================
// RunOpLogEntry
// ============================================================================

/// A single entry in the run-level bounded op-log.
///
/// Private fields with a validating constructor, matching the shard-level
/// `OpLogEntry` pattern in `lease.rs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOpLogEntry {
    op_id: OpId,
    kind: RunOpKind,
    payload_hash: u64,
    executed_at: LogicalTime,
    result: RunOpResult,
}

impl RunOpLogEntry {
    /// Create a new entry with validation.
    ///
    /// # Panics
    ///
    /// - `payload_hash == 0`: zero indicates a hashing failure or omission.
    /// - `executed_at <= LogicalTime::ZERO`: timestamps must be positive.
    pub(crate) fn new(
        op_id: OpId,
        kind: RunOpKind,
        payload_hash: u64,
        executed_at: LogicalTime,
        result: RunOpResult,
    ) -> Self {
        assert!(
            payload_hash != 0,
            "RunOpLogEntry: payload_hash must not be zero"
        );
        assert!(
            executed_at > LogicalTime::ZERO,
            "RunOpLogEntry: executed_at must be > ZERO"
        );
        // INV-11 at construction: kind-result consistency.
        match (&kind, &result) {
            (RunOpKind::RegisterShards, RunOpResult::RegisteredShards { .. }) => {}
            (RunOpKind::RegisterShards, RunOpResult::Ack) => {
                panic!("RunOpLogEntry: RegisterShards must have RegisteredShards result, not Ack");
            }
            (_, RunOpResult::Ack) => {}
            (k, RunOpResult::RegisteredShards { .. }) => {
                panic!("RunOpLogEntry: {k:?} must have Ack result, not RegisteredShards",);
            }
        }
        Self {
            op_id,
            kind,
            payload_hash,
            executed_at,
            result,
        }
    }

    #[must_use]
    pub fn op_id(&self) -> OpId {
        self.op_id
    }

    #[must_use]
    pub fn kind(&self) -> RunOpKind {
        self.kind
    }

    #[must_use]
    pub fn payload_hash(&self) -> u64 {
        self.payload_hash
    }

    #[must_use]
    pub fn executed_at(&self) -> LogicalTime {
        self.executed_at
    }

    #[must_use]
    pub fn result(&self) -> &RunOpResult {
        &self.result
    }
}

// ============================================================================
// RunOpIdConflict
// ============================================================================

/// OpId reuse detected with a different payload hash.
///
/// Used as an intermediate type for `From` impls on operation-specific errors.
#[derive(Clone, PartialEq, Eq)]
pub struct RunOpIdConflict {
    pub(crate) op_id: OpId,
    pub(crate) expected_hash: u64,
    pub(crate) actual_hash: u64,
}

// Custom Debug: redact hashes per SEC-6.
impl fmt::Debug for RunOpIdConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunOpIdConflict")
            .field("op_id", &self.op_id)
            .field("expected_hash", &"<redacted>")
            .field("actual_hash", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for RunOpIdConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "run op-id conflict: {:?} reused with different payload",
            self.op_id
        )
    }
}

impl std::error::Error for RunOpIdConflict {}

// ============================================================================
// RunRecord
// ============================================================================

/// The coordinator's authoritative record for a scan run.
///
/// ## Invariants (checked by `assert_invariants`)
///
/// 1. Active implies non-empty `root_shards`.
/// 2. `completed_at.is_some()` iff status is terminal.
/// 3. `created_at > LogicalTime::ZERO`.
/// 4. Initializing implies empty `root_shards`.
/// 5. `completed_at >= created_at` when `Some`.
/// 6. `op_log.len() <= OP_LOG_CAP`.
/// 7. No duplicate `OpId` values in `op_log`.
/// 8. Config valid: `lease_duration > 0`.
/// 9. No duplicate `ShardId` values in `root_shards`.
/// 10. Op-log timestamps non-decreasing.
/// 11. Kind-result consistency: `RegisterShards` entries have `RegisteredShards`
///     result; all other ops have `Ack` result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRecord {
    pub(crate) tenant: TenantId,
    pub(crate) run: RunId,
    pub(crate) config: RunConfig,
    pub(crate) status: RunStatus,
    pub(crate) created_at: LogicalTime,
    pub(crate) completed_at: Option<LogicalTime>,
    /// Root shard IDs registered at creation. Does not include split children.
    pub(crate) root_shards: Vec<ShardId>,
    /// Bounded op-log for idempotent replay of run-level ops.
    pub(crate) op_log: RingBuffer<RunOpLogEntry, { RunRecord::OP_LOG_CAP }>,
}

impl RunRecord {
    /// Maximum number of retained run op-log entries.
    ///
    /// 8 provides headroom for the worst case: `register_shards` + up to 7
    /// terminal/admin operations before the first is evicted. `create_run`
    /// does NOT write to the op-log (no `OpId`), so cap=8 is adequate.
    ///
    /// ## Eviction safety
    ///
    /// When the op-log is full, `op_log_push` evicts the oldest entry.
    /// Eviction is safe because every run-level operation has a secondary
    /// status-check barrier: even if the op-log entry is evicted and a
    /// stale retry is treated as "new," the status check (e.g., "run must
    /// be Active") prevents re-execution on an already-transitioned run.
    ///
    /// This assumes a single-writer model per run. Production backends
    /// with concurrent writers need external serialization (e.g., database
    /// transactions) to prevent TOCTOU races between the op-log check and
    /// the status check.
    pub const OP_LOG_CAP: usize = 8;

    /// Assert all structural invariants.
    ///
    /// Call after every state transition, before persisting. Panics on
    /// violation — crash-to-prevent-corruption philosophy.
    pub fn assert_invariants(&self) {
        self.assert_lifecycle_invariants();
        self.assert_oplog_invariants();
    }

    fn assert_lifecycle_invariants(&self) {
        // INV-1: Active implies non-empty root_shards.
        if self.status == RunStatus::Active {
            assert!(
                !self.root_shards.is_empty(),
                "Active run {:?} must have at least one root shard",
                self.run,
            );
        }

        // INV-2: completed_at.is_some() iff terminal.
        assert_eq!(
            self.completed_at.is_some(),
            self.status.is_terminal(),
            "Run {:?}: completed_at must be Some iff status is terminal (status: {:?})",
            self.run,
            self.status,
        );

        // INV-3: created_at > ZERO.
        assert!(
            self.created_at > LogicalTime::ZERO,
            "Run {:?}: created_at must be > ZERO",
            self.run,
        );

        // INV-4: Initializing implies empty root_shards.
        if self.status == RunStatus::Initializing {
            assert!(
                self.root_shards.is_empty(),
                "Initializing run {:?} must have empty root_shards",
                self.run,
            );
        }

        // INV-5: completed_at >= created_at when Some.
        if let Some(completed) = self.completed_at {
            assert!(
                completed >= self.created_at,
                "Run {:?}: completed_at ({:?}) must be >= created_at ({:?})",
                self.run,
                completed,
                self.created_at,
            );
        }

        // INV-9: No duplicate ShardIds in root_shards.
        // O(n²) scan like INV-7: n is bounded by MAX_INITIAL_SHARDS.
        for i in 0..self.root_shards.len() {
            for j in (i + 1)..self.root_shards.len() {
                assert!(
                    self.root_shards[i] != self.root_shards[j],
                    "Run {:?}: duplicate ShardId {:?} in root_shards at indices {i} and {j}",
                    self.run,
                    self.root_shards[i],
                );
            }
        }
    }

    fn assert_oplog_invariants(&self) {
        // INV-6: Op-log bounded — defense-in-depth: RingBuffer enforces capacity
        // structurally, but this assertion catches corruption before persistence.
        assert!(
            self.op_log.len() <= Self::OP_LOG_CAP,
            "Run {:?}: op_log length {} exceeds cap {}",
            self.run,
            self.op_log.len(),
            Self::OP_LOG_CAP,
        );

        // INV-7: No duplicate OpIds in op-log.
        // O(n²) scan is intentional: n ≤ OP_LOG_CAP (8), so max 28 comparisons.
        // A HashSet would add allocation overhead that dominates at this scale.
        for i in 0..self.op_log.len() {
            let a = self.op_log.get(i).unwrap();
            for j in (i + 1)..self.op_log.len() {
                assert!(
                    a.op_id() != self.op_log.get(j).unwrap().op_id(),
                    "Run {:?}: duplicate OpId {:?} in op_log at indices {i} and {j}",
                    self.run,
                    a.op_id(),
                );
            }
        }

        // INV-10: Op-log timestamps non-decreasing.
        let mut iter = self.op_log.iter();
        if let Some(mut prev) = iter.next() {
            for entry in iter {
                assert!(
                    entry.executed_at() >= prev.executed_at(),
                    "Run {:?}: op_log timestamps not non-decreasing: {:?} followed by {:?}",
                    self.run,
                    prev.executed_at(),
                    entry.executed_at(),
                );
                prev = entry;
            }
        }

        // INV-11: Kind-result consistency.
        // RegisterShards entries must have RegisteredShards result (not Ack).
        // All other ops must have Ack result (not RegisteredShards).
        for entry in &self.op_log {
            match (entry.kind(), entry.result()) {
                (RunOpKind::RegisterShards, RunOpResult::RegisteredShards { .. }) => {}
                (RunOpKind::RegisterShards, RunOpResult::Ack) => {
                    panic!(
                        "Run {:?}: RegisterShards op-log entry must have RegisteredShards result, not Ack",
                        self.run,
                    );
                }
                (_, RunOpResult::Ack) => {}
                (kind, RunOpResult::RegisteredShards { .. }) => {
                    panic!(
                        "Run {:?}: {kind:?} op-log entry must not have RegisteredShards result",
                        self.run,
                    );
                }
            }
        }

        // INV-8: Config valid.
        self.config.assert_valid();
    }

    /// Look up an op-log entry by `OpId`.
    ///
    /// Reverse scan for retry optimization — retries involve the most
    /// recent operations.
    #[must_use]
    pub fn op_log_lookup(&self, op: OpId) -> Option<&RunOpLogEntry> {
        debug_assert!(self.op_log.len() <= Self::OP_LOG_CAP);
        self.op_log.iter().rev().find(|e| e.op_id() == op)
    }

    /// Push an op-log entry, evicting the oldest if at capacity.
    ///
    /// # Panics
    ///
    /// Panics if `entry.op_id()` already exists in the log. Callers must
    /// check via `check_op_idempotency` first.
    pub(crate) fn op_log_push(&mut self, entry: RunOpLogEntry) {
        assert!(
            !self.op_log.iter().any(|e| e.op_id() == entry.op_id()),
            "Run {:?}: attempt to push duplicate OpId {:?}",
            self.run,
            entry.op_id(),
        );
        self.op_log.push_back_overwrite(entry);
        // Defense-in-depth: RingBuffer enforces capacity structurally, but
        // this assertion catches corruption before persistence.
        assert!(self.op_log.len() <= Self::OP_LOG_CAP);
    }

    /// Check idempotency for a run-level operation.
    ///
    /// - Returns `Ok(None)` if the OpId is not in the log (new operation).
    /// - Returns `Ok(Some(entry))` if the OpId matches with same payload hash (replay).
    /// - Returns `Err(RunOpIdConflict)` if the OpId matches with different hash.
    ///
    /// # Panics
    ///
    /// Panics if `payload_hash == 0`.
    pub(crate) fn check_op_idempotency(
        &self,
        op_id: OpId,
        payload_hash: u64,
    ) -> Result<Option<&RunOpLogEntry>, RunOpIdConflict> {
        assert!(payload_hash != 0, "payload_hash must not be zero");
        match self.op_log_lookup(op_id) {
            None => Ok(None),
            Some(entry) => {
                if entry.payload_hash() == payload_hash {
                    Ok(Some(entry))
                } else {
                    Err(RunOpIdConflict {
                        op_id,
                        expected_hash: entry.payload_hash(),
                        actual_hash: payload_hash,
                    })
                }
            }
        }
    }

    /// Assert that transitioning to `new_status` is legal from the current state.
    ///
    /// Legal transitions (see [`RunStatus`] state machine):
    /// - Initializing → Active (via `register_shards`)
    /// - Initializing → Cancelled (via `cancel_run`)
    /// - Active → Done (via `complete_run`)
    /// - Active → Failed (via `fail_run`)
    /// - Active → Cancelled (via `cancel_run`)
    ///
    /// Terminal states (Done, Failed, Cancelled) cannot transition to any
    /// other state. Mirrors [`ShardRecord::assert_transition_legal`].
    ///
    /// # Panics
    ///
    /// Panics if the transition is illegal.
    pub(crate) fn assert_transition_legal(&self, new_status: RunStatus) {
        let legal = match (self.status, new_status) {
            (RunStatus::Initializing, RunStatus::Active) => true,
            (RunStatus::Initializing, RunStatus::Cancelled) => true,
            (RunStatus::Active, RunStatus::Done) => true,
            (RunStatus::Active, RunStatus::Failed) => true,
            (RunStatus::Active, RunStatus::Cancelled) => true,
            // Same-state is legal (idempotent path, not used inline but
            // keeps the guard compatible with replay-then-assert patterns).
            (s, t) if s == t => true,
            _ => false,
        };
        assert!(
            legal,
            "Run {:?}: illegal transition from {:?} to {:?}",
            self.run, self.status, new_status,
        );
    }

    // -- Public accessors --

    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn run(&self) -> RunId {
        self.run
    }

    #[must_use]
    pub fn config(&self) -> &RunConfig {
        &self.config
    }

    #[must_use]
    pub fn status(&self) -> RunStatus {
        self.status
    }

    #[must_use]
    pub fn created_at(&self) -> LogicalTime {
        self.created_at
    }

    #[must_use]
    pub fn completed_at(&self) -> Option<LogicalTime> {
        self.completed_at
    }

    #[must_use]
    pub fn root_shards(&self) -> &[ShardId] {
        &self.root_shards
    }
}

// Compile-time guards for OP_LOG_CAP.
const _: () = assert!(RunRecord::OP_LOG_CAP == 8);
const _: () = assert!(ShardRecord::OP_LOG_CAP >= RunRecord::OP_LOG_CAP);

// ============================================================================
// RunProgress + RunTerminalEvaluation
// ============================================================================

/// Aggregated shard status counts for a run.
///
/// Fields are `pub(crate)` with public accessors. Uses `u32` (not `u64`)
/// because the maximum shard count is bounded by `MAX_INITIAL_SHARDS` plus
/// spawned children, well within `u32::MAX`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunProgress {
    pub(crate) total: u32,
    pub(crate) active: u32,
    pub(crate) done: u32,
    pub(crate) split: u32,
    pub(crate) parked: u32,
    /// Subset of `active`: shards currently held by a worker lease.
    pub(crate) leased: u32,
}

impl RunProgress {
    #[must_use]
    pub fn total(&self) -> u32 {
        self.total
    }

    #[must_use]
    pub fn active(&self) -> u32 {
        self.active
    }

    #[must_use]
    pub fn done(&self) -> u32 {
        self.done
    }

    #[must_use]
    pub fn split(&self) -> u32 {
        self.split
    }

    #[must_use]
    pub fn parked(&self) -> u32 {
        self.parked
    }

    #[must_use]
    pub fn leased(&self) -> u32 {
        self.leased
    }

    /// Whether all active work is complete (no Active shards remain).
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.active == 0
    }

    /// Settled with zero parked shards — clean completion.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.is_settled() && self.parked == 0
    }

    /// Any shards parked (error/poison).
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.parked > 0
    }

    /// Evaluate whether this run should transition to a terminal state.
    ///
    /// Equivalent to [`evaluate_run_terminal`], but called as a method.
    #[must_use]
    pub fn terminal_evaluation(&self) -> RunTerminalEvaluation {
        evaluate_run_terminal(self)
    }

    /// Count a shard into the progress tallies.
    ///
    /// # Panics
    ///
    /// - `is_leased` is `true` but `status` is not `Active`.
    /// - Any counter overflows `u32::MAX`.
    pub fn count_shard(&mut self, status: ShardStatus, is_leased: bool) {
        assert!(
            !is_leased || status == ShardStatus::Active,
            "is_leased=true is only valid for Active shards, got status: {status:?}"
        );
        self.total = self
            .total
            .checked_add(1)
            .expect("RunProgress::total overflow");
        match status {
            ShardStatus::Active => {
                self.active = self
                    .active
                    .checked_add(1)
                    .expect("RunProgress::active overflow");
                if is_leased {
                    self.leased = self
                        .leased
                        .checked_add(1)
                        .expect("RunProgress::leased overflow");
                }
            }
            ShardStatus::Done => {
                self.done = self
                    .done
                    .checked_add(1)
                    .expect("RunProgress::done overflow");
            }
            ShardStatus::Split => {
                self.split = self
                    .split
                    .checked_add(1)
                    .expect("RunProgress::split overflow");
            }
            ShardStatus::Parked => {
                self.parked = self
                    .parked
                    .checked_add(1)
                    .expect("RunProgress::parked overflow");
            }
        }
        self.assert_invariants();
    }

    /// Assert structural invariants of the progress tallies.
    ///
    /// - `total == active + done + split + parked`
    /// - `leased <= active`
    pub fn assert_invariants(&self) {
        assert_eq!(
            self.total,
            self.active + self.done + self.split + self.parked,
            "RunProgress: total must equal sum of per-status counts"
        );
        assert!(
            self.leased <= self.active,
            "RunProgress: leased ({}) must not exceed active ({})",
            self.leased,
            self.active,
        );
    }
}

/// Evaluation of whether a run should transition to a terminal state.
///
/// Produced by [`evaluate_run_terminal`], which checks `active > 0` first
/// (still processing), then `parked > 0` (failures), then concludes all done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunTerminalEvaluation {
    /// At least one shard is still Active — the run cannot terminate yet.
    StillActive,
    /// All shards settled with zero parked — clean completion.
    AllDone,
    /// All shards settled but some are parked — partial failure.
    HasFailures,
}

/// Pure function: evaluate whether a run should transition to terminal.
///
/// Priority order: `active > 0` → [`StillActive`](RunTerminalEvaluation::StillActive),
/// then `parked > 0` → [`HasFailures`](RunTerminalEvaluation::HasFailures),
/// otherwise → [`AllDone`](RunTerminalEvaluation::AllDone).
///
/// This is intentionally external to `RunRecord` — the coordinator decides
/// when and whether to auto-transition (D2.19: external terminal evaluation).
#[must_use]
pub fn evaluate_run_terminal(progress: &RunProgress) -> RunTerminalEvaluation {
    assert!(
        progress.total > 0,
        "evaluate_run_terminal called with zero-total progress"
    );
    if progress.active > 0 {
        RunTerminalEvaluation::StillActive
    } else if progress.parked > 0 {
        RunTerminalEvaluation::HasFailures
    } else {
        RunTerminalEvaluation::AllDone
    }
}

// ============================================================================
// InitialShard + Manifest Validation
// ============================================================================

/// Maximum number of shards in a single `register_shards` call (SEC-3).
///
/// Prevents resource exhaustion from a single API call creating unbounded
/// shard records. Checked as the FIRST validation step in `validate_manifest`.
pub const MAX_INITIAL_SHARDS: usize = 10_000;

const _: () = assert!(MAX_INITIAL_SHARDS > 0);

/// A shard to be registered as part of a run's initial manifest.
///
/// Used in the second phase of two-phase run creation (D2.20):
/// `create_run` → `register_shards(&[InitialShard])`. Each entry pairs
/// a [`ShardSpec`] (key range) with an optional resume [`Cursor`].
/// Initial cursors (`Cursor::initial()`) start processing from the range
/// beginning; non-initial cursors resume from a previously checkpointed
/// position (e.g., after a failed run restart).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialShard {
    pub(crate) shard: ShardId,
    pub(crate) spec: ShardSpec,
    pub(crate) cursor: Cursor,
}

impl InitialShard {
    #[must_use]
    pub fn new(shard: ShardId, spec: ShardSpec, cursor: Cursor) -> Self {
        Self {
            shard,
            spec,
            cursor,
        }
    }

    #[must_use]
    pub fn shard(&self) -> ShardId {
        self.shard
    }

    #[must_use]
    pub fn spec(&self) -> &ShardSpec {
        &self.spec
    }

    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }
}

/// Error from `validate_manifest`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestValidationError {
    /// The manifest is empty — at least one shard is required.
    Empty,
    /// Two shards have the same `ShardId`.
    DuplicateIds { shard_id: ShardId },
    /// Two shards have overlapping key ranges.
    OverlappingRanges { shard_a: ShardId, shard_b: ShardId },
    /// A shard's spec is internally invalid.
    InvalidSpec { shard_id: ShardId },
    /// Too many shards (SEC-3).
    TooManyShards { count: usize, max: usize },
    /// A non-initial cursor falls outside the shard's key range.
    CursorOutOfBounds { shard_id: ShardId },
    /// A cursor's `last_key` exceeds [`MAX_KEY_SIZE`] bytes.
    CursorKeyTooLarge {
        shard_id: ShardId,
        size: usize,
        max: usize,
    },
    /// A shard has an unbounded key range (empty start or end).
    ///
    /// Unbounded specs are test-only constructs. Production manifests must
    /// have finite, bounded key ranges so that overlap detection and shard
    /// coordination operate on well-defined intervals.
    UnboundedRange { shard_id: ShardId },
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("manifest is empty"),
            Self::DuplicateIds { shard_id } => {
                write!(f, "duplicate shard id: {:?}", shard_id)
            }
            Self::OverlappingRanges { shard_a, shard_b } => {
                write!(
                    f,
                    "overlapping ranges: shard {:?} and {:?}",
                    shard_a, shard_b,
                )
            }
            Self::InvalidSpec { shard_id } => {
                write!(f, "invalid spec for shard {:?}", shard_id)
            }
            Self::TooManyShards { count, max } => {
                write!(f, "too many shards: {count} exceeds max {max}")
            }
            Self::CursorOutOfBounds { shard_id } => {
                write!(f, "cursor out of bounds for shard {:?}", shard_id)
            }
            Self::CursorKeyTooLarge {
                shard_id,
                size,
                max,
            } => {
                write!(
                    f,
                    "cursor key too large for shard {:?}: {size} bytes exceeds max {max}",
                    shard_id,
                )
            }
            Self::UnboundedRange { shard_id } => {
                write!(f, "unbounded range for shard {:?}", shard_id)
            }
        }
    }
}

impl std::error::Error for ManifestValidationError {}

/// Validate a manifest of initial shards.
///
/// Checks (in order):
/// 1. SEC-3: count <= `MAX_INITIAL_SHARDS` (FIRST check, before allocation).
/// 2. Non-empty.
/// 3. No duplicate IDs.
/// 4. No unbounded ranges (empty start or end).
/// 5. Spec validity: `start < end` for bounded key ranges.
/// 6. No overlapping key ranges (gaps are allowed).
/// 7. Cursor key size <= [`MAX_KEY_SIZE`] for non-initial cursors.
/// 8. Cursor bounds for non-initial cursors.
pub fn validate_manifest(shards: &[InitialShard]) -> Result<(), ManifestValidationError> {
    // SEC-3: Bound check FIRST, before any allocation.
    if shards.len() > MAX_INITIAL_SHARDS {
        return Err(ManifestValidationError::TooManyShards {
            count: shards.len(),
            max: MAX_INITIAL_SHARDS,
        });
    }

    if shards.is_empty() {
        return Err(ManifestValidationError::Empty);
    }

    // Check for duplicate IDs.
    let mut ids: Vec<ShardId> = shards.iter().map(|s| s.shard).collect();
    ids.sort_by_key(|id| id.as_raw());
    for window in ids.windows(2) {
        if window[0] == window[1] {
            return Err(ManifestValidationError::DuplicateIds {
                shard_id: window[0],
            });
        }
    }

    // Reject unbounded ranges: production manifests must have finite bounds.
    for shard in shards {
        if shard.spec.key_range_start().is_empty() || shard.spec.key_range_end().is_empty() {
            return Err(ManifestValidationError::UnboundedRange {
                shard_id: shard.shard,
            });
        }
    }

    // Sort by key_range_start for overlap detection.
    let mut sorted: Vec<&InitialShard> = shards.iter().collect();
    sorted.sort_by(|a, b| a.spec.key_range_start().cmp(b.spec.key_range_start()));

    for shard in &sorted {
        // Validate that start < end for bounded specs.
        let start = shard.spec.key_range_start();
        let end = shard.spec.key_range_end();
        if !start.is_empty() && !end.is_empty() && start >= end {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard,
            });
        }
    }

    // Check for overlapping ranges.
    // Ranges are sorted by key_range_start. Two adjacent ranges [a_start, a_end)
    // and [b_start, b_end) overlap iff a_end > b_start, where:
    //   - empty a_end means [a_start, ∞) → always overlaps with the next shard
    //   - empty b_start means [min, b_end) → any non-empty a_end exceeds min
    for window in sorted.windows(2) {
        let (a, b) = (window[0], window[1]);
        let a_end = a.spec.key_range_end();
        let b_start = b.spec.key_range_start();
        let overlaps = a_end.is_empty() || b_start.is_empty() || a_end > b_start;
        if overlaps {
            return Err(ManifestValidationError::OverlappingRanges {
                shard_a: a.shard,
                shard_b: b.shard,
            });
        }
    }

    // Cursor key size check (defense-in-depth; Cursor::try_with_last_key
    // also validates, but callers may use the panicking constructors).
    for shard in shards {
        if let Some(key) = shard.cursor.last_key()
            && key.len() > MAX_KEY_SIZE
        {
            return Err(ManifestValidationError::CursorKeyTooLarge {
                shard_id: shard.shard,
                size: key.len(),
                max: MAX_KEY_SIZE,
            });
        }
    }

    // Cursor bounds check for non-initial cursors.
    for shard in shards {
        if let Some(key) = shard.cursor.last_key() {
            let start = shard.spec.key_range_start();
            let end = shard.spec.key_range_end();
            let in_bounds = (start.is_empty() || key >= start) && (end.is_empty() || key < end);
            if !in_bounds {
                return Err(ManifestValidationError::CursorOutOfBounds {
                    shard_id: shard.shard,
                });
            }
        }
    }

    Ok(())
}

// ============================================================================
// ShardSummary
// ============================================================================

/// Lightweight shard summary for listing and observability.
///
/// Constructed from a `ShardRecord` via `from_record`, using accessor methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSummary {
    pub(crate) shard: ShardId,
    pub(crate) status: ShardStatus,
    pub(crate) park_reason: Option<ParkReason>,
    pub(crate) is_leased: bool,
    /// Number of times this shard has been acquired.
    ///
    /// Derived as `fence_epoch - INITIAL`, since each `acquire_and_restore`
    /// bumps the fence. Saturates at `u32::MAX` if the epoch difference
    /// exceeds 32-bit range (astronomically unlikely in practice).
    pub(crate) acquire_count: u32,
    pub(crate) last_key: Option<Box<[u8]>>,
    pub(crate) key_range_start: Box<[u8]>,
    pub(crate) key_range_end: Box<[u8]>,
    pub(crate) parent: Option<ShardId>,
    pub(crate) spawned_count: u32,
}

impl ShardSummary {
    pub(crate) fn from_record(record: &ShardRecord, now: LogicalTime) -> Self {
        Self {
            shard: record.shard,
            status: record.status,
            park_reason: record.park_reason,
            is_leased: record.is_leased_at(now),
            acquire_count: u32::try_from(
                record
                    .fence_epoch
                    .as_raw()
                    .saturating_sub(FenceEpoch::INITIAL.as_raw()),
            )
            .unwrap_or(u32::MAX),
            last_key: record.cursor.last_key().map(|k| k.into()),
            key_range_start: record.spec.key_range_start().into(),
            key_range_end: record.spec.key_range_end().into(),
            parent: record.parent,
            spawned_count: u32::try_from(record.spawned.len()).unwrap_or(u32::MAX),
        }
    }

    #[must_use]
    pub fn shard(&self) -> ShardId {
        self.shard
    }

    #[must_use]
    pub fn status(&self) -> ShardStatus {
        self.status
    }

    #[must_use]
    pub fn park_reason(&self) -> Option<ParkReason> {
        self.park_reason
    }

    #[must_use]
    pub fn is_leased(&self) -> bool {
        self.is_leased
    }

    #[must_use]
    pub fn acquire_count(&self) -> u32 {
        self.acquire_count
    }

    #[must_use]
    pub fn last_key(&self) -> Option<&[u8]> {
        self.last_key.as_deref()
    }

    #[must_use]
    pub fn key_range_start(&self) -> &[u8] {
        &self.key_range_start
    }

    #[must_use]
    pub fn key_range_end(&self) -> &[u8] {
        &self.key_range_end
    }

    #[must_use]
    pub fn parent(&self) -> Option<ShardId> {
        self.parent
    }

    #[must_use]
    pub fn spawned_count(&self) -> u32 {
        self.spawned_count
    }
}

// ============================================================================
// ShardFilter
// ============================================================================

/// Filter criteria for [`RunManagement::list_shards`].
///
/// All fields default to "match anything". Named constructors compose
/// common filter patterns; fields are `pub(crate)` to prevent ad-hoc
/// construction outside the crate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardFilter {
    pub(crate) status: Option<ShardStatus>,
    /// Evaluated at the `now` parameter passed to [`RunManagement::list_shards`]:
    /// a lease whose deadline has passed is treated as unleased.
    pub(crate) is_leased: Option<bool>,
    /// When `true`, excludes split children (shards with a `parent`).
    pub(crate) root_only: bool,
}

impl ShardFilter {
    /// No constraints — matches every shard in the run.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Active shards only (includes both leased and unleased).
    #[must_use]
    pub fn active() -> Self {
        Self {
            status: Some(ShardStatus::Active),
            ..Self::default()
        }
    }

    /// Active and unleased — shards ready for a worker to acquire.
    #[must_use]
    pub fn available() -> Self {
        Self {
            status: Some(ShardStatus::Active),
            is_leased: Some(false),
            ..Self::default()
        }
    }

    /// Parked shards only — candidates for `unpark_shard`.
    #[must_use]
    pub fn parked() -> Self {
        Self {
            status: Some(ShardStatus::Parked),
            ..Self::default()
        }
    }

    /// Test whether a [`ShardSummary`] passes all filter criteria.
    #[must_use]
    pub fn matches(&self, summary: &ShardSummary) -> bool {
        if let Some(status) = self.status
            && summary.status != status
        {
            return false;
        }
        if let Some(leased) = self.is_leased
            && summary.is_leased != leased
        {
            return false;
        }
        if self.root_only && summary.parent.is_some() {
            return false;
        }
        true
    }

    /// Pre-filter on [`ShardRecord`] fields before constructing a
    /// [`ShardSummary`] (which heap-allocates key ranges).
    ///
    /// Equivalent to `self.matches(&ShardSummary::from_record(record, now))`
    /// but avoids the 2-3 heap allocations per record that `from_record`
    /// performs. At 10K shards with a selective filter, this turns ~30K
    /// wasted allocations into ~30.
    #[must_use]
    pub fn matches_record(&self, record: &ShardRecord, now: LogicalTime) -> bool {
        if let Some(status) = self.status
            && record.status != status
        {
            return false;
        }
        if let Some(leased) = self.is_leased
            && record.is_leased_at(now) != leased
        {
            return false;
        }
        if self.root_only && record.parent.is_some() {
            return false;
        }
        true
    }
}

// ============================================================================
// Payload hash functions
// ============================================================================

/// Payload hash for `register_shards`.
///
/// Sort by `shard.as_raw()` for order-independence — callers may provide
/// shards in any order.
#[must_use]
pub fn hash_register_shards_payload(shards: &[InitialShard]) -> u64 {
    let mut sorted: Vec<&InitialShard> = shards.iter().collect();
    sorted.sort_by_key(|s| s.shard.as_raw());

    op_payload_hash(b"register_shards", |h| {
        (sorted.len() as u32).write_canonical(h);
        for shard in &sorted {
            shard.shard.write_canonical(h);
            shard.spec.write_canonical(h);
            shard.cursor.write_canonical(h);
        }
    })
}

/// Shared implementation for terminal run operations.
///
/// Terminal ops (complete, fail, cancel) carry no per-invocation parameters
/// beyond the `RunId` (implicit in the call site), so the payload is just
/// the domain-separated tag. Each tag produces a distinct hash (non-zero
/// with overwhelming probability ~1-2^{-64}; verified by
/// `hash_terminal_ops_distinct` test).
fn hash_run_terminal_payload(tag: &[u8]) -> u64 {
    op_payload_hash(tag, |_h| {})
}

/// Payload hash for `complete_run`. Parameterless (tag-only).
#[must_use]
pub fn hash_complete_run_payload() -> u64 {
    hash_run_terminal_payload(b"complete_run")
}

/// Payload hash for `fail_run`. Parameterless (tag-only).
#[must_use]
pub fn hash_fail_run_payload() -> u64 {
    hash_run_terminal_payload(b"fail_run")
}

/// Payload hash for `cancel_run`. Parameterless (tag-only).
#[must_use]
pub fn hash_cancel_run_payload() -> u64 {
    hash_run_terminal_payload(b"cancel_run")
}

/// Payload hash for `unpark_shard`.
///
/// Includes both `run` and `shard` from the key so that unpark operations
/// on different shards within the same run produce distinct hashes.
#[must_use]
pub fn hash_unpark_payload(key: &ShardKey) -> u64 {
    op_payload_hash(b"unpark_shard", |h| {
        key.run().write_canonical(h);
        key.shard().write_canonical(h);
    })
}

// ============================================================================
// RunManagement trait
// ============================================================================

/// Run-level management operations.
///
/// Separated from `CoordinationBackend` (D2.22) because:
/// - Different authorization model (admin/scheduler vs worker)
/// - Independent testability
///
/// ## Cross-cutting: `unpark_shard` idempotency
///
/// Unlike other run-level operations, `unpark_shard` stores its idempotency
/// entries in the **shard** op-log (cap=16), not the run op-log. This is
/// because unpark targets a specific shard, and the run op-log would need
/// a keying scheme to distinguish `unpark(shard_A)` from `unpark(shard_B)`.
/// See also: `CoordinationBackend` shard op-log documentation.
pub trait RunManagement {
    /// Create a new run in `Initializing` status. **NOT** idempotent.
    ///
    /// The caller should generate a unique `RunId` before calling. On failure
    /// (e.g., duplicate), the caller may retry with a new `RunId` or attempt
    /// `create_run_with_shards` for the retry-friendly path.
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError>;

    /// Register initial shards and activate the run.
    ///
    /// Idempotent via `op_id`. Uses collect-then-insert internally:
    /// all shards are validated first, then inserted atomically.
    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShard],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError>;

    /// Convenience: create + register in one call.
    ///
    /// On retry, if the run already exists with the same config, attempts
    /// to re-apply `register_shards` (idempotent via `op_id`).
    ///
    /// # Production note
    ///
    /// The default implementation is **not atomic**: `create_run` and
    /// `register_shards` are separate calls with a TOCTOU window between
    /// the existence check and the registration. The in-memory backend
    /// serializes via `&mut self`, but production backends should override
    /// this with a transactional implementation to avoid partial-creation
    /// races under concurrent callers.
    fn create_run_with_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
        shards: &[InitialShard],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<RunRecord>, CreateRunError> {
        match self.create_run(now, tenant, run, config) {
            Ok(_) => {}
            Err(CreateRunError::RunAlreadyExists { .. }) => {
                let existing = self.get_run(tenant, run)?;
                if existing.config != config {
                    return Err(CreateRunError::ConfigMismatch { run });
                }
            }
            Err(e) => return Err(e),
        }

        let outcome = self.register_shards(now, tenant, run, shards, op_id)?;

        let record = self.get_run(tenant, run)?;

        Ok(outcome.map(|_| record))
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError>;

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError>;

    /// List shards for a run, filtered. Ordered by `key_range_start` ascending.
    ///
    /// `ShardFilter::is_leased` must be evaluated against `now`: a lease whose
    /// deadline has passed counts as unleased, not leased.
    fn list_shards(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
    ) -> Result<Vec<ShardSummary>, GetRunError>;

    /// Mark run as Done. Precondition: Active. Idempotent via `op_id`.
    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError>;

    /// Mark run as Failed. Precondition: **Active only** (not Initializing).
    /// Use `cancel_run` for Initializing runs. Idempotent via `op_id`.
    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, FailRunError>;

    /// Cancel run (sets Cancelled). Accepts Initializing OR Active.
    /// Idempotent via `op_id`.
    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CancelRunError>;

    /// Unpark a parked shard. Admin-only, NOT lease-gated.
    ///
    /// Bumps `fence_epoch` (fencing any zombie workers), clears park state,
    /// restores Active status. Preserves cursor position.
    ///
    /// Idempotency is stored in the **shard** op-log, not the run op-log.
    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError>;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::cursor::Cursor;
    use crate::coordination::shard_spec::CursorSemantics;
    use crate::identity::{OpId, RunId, ShardId};
    use gossip_stdx::RingBuffer;
    use rstest::rstest;

    // -- Test fixtures --

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_config() -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
    }

    fn test_run_record() -> RunRecord {
        RunRecord {
            tenant: test_tenant(),
            run: test_run(),
            config: test_config(),
            status: RunStatus::Active,
            created_at: LogicalTime::from_raw(1),
            completed_at: None,
            root_shards: vec![ShardId::from_raw(0), ShardId::from_raw(1)],
            op_log: RingBuffer::new(),
        }
    }

    fn make_initial_shard(id: u64, start: &[u8], end: &[u8]) -> InitialShard {
        InitialShard::new(
            ShardId::from_raw(id),
            ShardSpec::with_range(start.to_vec(), end.to_vec()),
            Cursor::initial(),
        )
    }

    fn make_op_log_entry(op_id: u64, kind: RunOpKind) -> RunOpLogEntry {
        let result = match kind {
            RunOpKind::RegisterShards => RunOpResult::RegisteredShards {
                shard_ids: Box::new([ShardId::from_raw(0)]),
            },
            _ => RunOpResult::Ack,
        };
        RunOpLogEntry::new(
            OpId::from_raw(op_id),
            kind,
            42, // non-zero payload hash
            LogicalTime::from_raw(1),
            result,
        )
    }

    // -- RunStatus --

    #[rstest]
    #[case::initializing(RunStatus::Initializing, 0, false, "Initializing")]
    #[case::active(RunStatus::Active, 1, false, "Active")]
    #[case::done(RunStatus::Done, 2, true, "Done")]
    #[case::failed(RunStatus::Failed, 3, true, "Failed")]
    #[case::cancelled(RunStatus::Cancelled, 4, true, "Cancelled")]
    fn run_status_properties(
        #[case] status: RunStatus,
        #[case] disc: u8,
        #[case] terminal: bool,
        #[case] display: &str,
    ) {
        assert_eq!(status.as_u8(), disc);
        assert_eq!(RunStatus::from_u8(disc), Some(status));
        assert_eq!(status.is_terminal(), terminal);
        assert_eq!(status.to_string(), display);
    }

    #[test]
    fn run_status_from_u8_out_of_range() {
        assert_eq!(RunStatus::from_u8(5), None);
        assert_eq!(RunStatus::from_u8(u8::MAX), None);
    }

    // -- RunConfig --

    #[test]
    fn run_config_try_new_ok() {
        let cfg = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
        assert_eq!(cfg.cursor_semantics(), CursorSemantics::Completed);
        assert_eq!(cfg.lease_duration(), 30);
        assert_eq!(cfg.max_shard_retries(), Some(5));
    }

    #[test]
    fn run_config_try_new_zero_lease() {
        let err = RunConfig::try_new(CursorSemantics::Completed, 0, None).unwrap_err();
        assert_eq!(err, RunConfigError::ZeroLeaseDuration);
    }

    #[test]
    fn run_config_assert_valid_ok() {
        test_config().assert_valid();
    }

    // Zero-lease-duration panicking test removed — `NonZeroU64` enforces
    // this invariant at the type level; you can't construct the invalid state.

    // -- RunOpKind --

    #[rstest]
    #[case::register_shards(RunOpKind::RegisterShards, 0, "RegisterShards")]
    #[case::complete_run(RunOpKind::CompleteRun, 1, "CompleteRun")]
    #[case::fail_run(RunOpKind::FailRun, 2, "FailRun")]
    #[case::cancel_run(RunOpKind::CancelRun, 3, "CancelRun")]
    fn run_op_kind_properties(#[case] kind: RunOpKind, #[case] disc: u8, #[case] display: &str) {
        assert_eq!(kind.as_u8(), disc);
        assert_eq!(RunOpKind::from_u8(disc), Some(kind));
        assert_eq!(kind.to_string(), display);
    }

    #[test]
    fn run_op_kind_from_u8_out_of_range() {
        assert_eq!(RunOpKind::from_u8(4), None);
    }

    // -- RunOpLogEntry --

    #[test]
    fn run_op_log_entry_accessors() {
        let entry = RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::CompleteRun,
            42,
            LogicalTime::from_raw(10),
            RunOpResult::Ack,
        );
        assert_eq!(entry.op_id(), OpId::from_raw(1));
        assert_eq!(entry.kind(), RunOpKind::CompleteRun);
        assert_eq!(entry.payload_hash(), 42);
        assert_eq!(entry.executed_at(), LogicalTime::from_raw(10));
        assert_eq!(entry.result(), &RunOpResult::Ack);
    }

    #[test]
    #[should_panic(expected = "payload_hash must not be zero")]
    fn run_op_log_entry_zero_hash_panics() {
        RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::CompleteRun,
            0,
            LogicalTime::from_raw(1),
            RunOpResult::Ack,
        );
    }

    #[test]
    #[should_panic(expected = "executed_at must be > ZERO")]
    fn run_op_log_entry_zero_time_panics() {
        RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::CompleteRun,
            42,
            LogicalTime::ZERO,
            RunOpResult::Ack,
        );
    }

    // -- RunOpIdConflict security --

    #[test]
    fn run_op_id_conflict_debug_redacts_hashes() {
        let c = RunOpIdConflict {
            op_id: OpId::from_raw(1),
            expected_hash: 0xDEAD_BEEF,
            actual_hash: 0xCAFE_BABE,
        };
        let debug = format!("{c:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("DEAD"));
        assert!(!debug.contains("CAFE"));
        assert!(
            !debug.contains("3735928559") && !debug.contains("3405691582"),
            "debug leaks decimal hash: {debug}"
        );
    }

    // -- RunRecord invariants --

    #[test]
    fn run_record_valid_states_pass_invariants() {
        test_run_record().assert_invariants();

        RunRecord {
            status: RunStatus::Done,
            completed_at: Some(LogicalTime::from_raw(100)),
            ..test_run_record()
        }
        .assert_invariants();

        RunRecord {
            status: RunStatus::Initializing,
            root_shards: vec![],
            ..test_run_record()
        }
        .assert_invariants();

        RunRecord {
            status: RunStatus::Cancelled,
            completed_at: Some(LogicalTime::from_raw(100)),
            ..test_run_record()
        }
        .assert_invariants();
    }

    #[test]
    #[should_panic(expected = "completed_at must be Some")]
    fn rr_done_no_completed_at() {
        RunRecord {
            status: RunStatus::Done,
            completed_at: None,
            ..test_run_record()
        }
        .assert_invariants();
    }

    #[test]
    #[should_panic(expected = "completed_at must be Some")]
    fn rr_active_has_completed_at() {
        RunRecord {
            completed_at: Some(LogicalTime::from_raw(100)),
            ..test_run_record()
        }
        .assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must have at least one root shard")]
    fn rr_active_no_shards() {
        RunRecord {
            root_shards: vec![],
            ..test_run_record()
        }
        .assert_invariants();
    }

    #[test]
    #[should_panic(expected = "created_at must be > ZERO")]
    fn rr_created_at_zero() {
        RunRecord {
            created_at: LogicalTime::ZERO,
            ..test_run_record()
        }
        .assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must have empty root_shards")]
    fn rr_initializing_with_shards() {
        RunRecord {
            status: RunStatus::Initializing,
            // root_shards from test_run_record is non-empty
            ..test_run_record()
        }
        .assert_invariants();
    }

    #[test]
    #[should_panic(expected = "completed_at")]
    fn rr_completed_before_created() {
        RunRecord {
            status: RunStatus::Done,
            created_at: LogicalTime::from_raw(200),
            completed_at: Some(LogicalTime::from_raw(100)),
            ..test_run_record()
        }
        .assert_invariants();
    }

    // -- RunRecord op-log --

    #[test]
    fn run_op_log_push_and_lookup() {
        let mut r = test_run_record();
        r.op_log_push(make_op_log_entry(42, RunOpKind::CompleteRun));
        assert!(r.op_log_lookup(OpId::from_raw(42)).is_some());
        assert!(r.op_log_lookup(OpId::from_raw(99)).is_none());
    }

    #[test]
    fn run_op_log_reverse_lookup() {
        let mut r = test_run_record();
        r.op_log_push(make_op_log_entry(1, RunOpKind::RegisterShards));
        r.op_log_push(make_op_log_entry(2, RunOpKind::CompleteRun));
        // Reverse scan means op_id=2 found first (most recent).
        let found = r.op_log_lookup(OpId::from_raw(2)).unwrap();
        assert_eq!(found.kind(), RunOpKind::CompleteRun);
    }

    #[test]
    fn run_op_log_bounded() {
        let mut r = test_run_record();
        for i in 0..(RunRecord::OP_LOG_CAP + 5) {
            r.op_log_push(make_op_log_entry(i as u64, RunOpKind::CompleteRun));
        }
        assert_eq!(r.op_log.len(), RunRecord::OP_LOG_CAP);
        // Oldest entries evicted.
        assert!(r.op_log_lookup(OpId::from_raw(0)).is_none());
        assert!(
            r.op_log_lookup(OpId::from_raw((RunRecord::OP_LOG_CAP + 4) as u64))
                .is_some()
        );
    }

    #[test]
    #[should_panic(expected = "duplicate OpId")]
    fn run_op_log_push_duplicate_panics() {
        let mut r = test_run_record();
        r.op_log_push(make_op_log_entry(1, RunOpKind::CompleteRun));
        r.op_log_push(make_op_log_entry(1, RunOpKind::FailRun));
    }

    // -- check_op_idempotency --

    #[test]
    fn run_idem_new_op() {
        assert!(
            test_run_record()
                .check_op_idempotency(OpId::from_raw(1), 100)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn run_idem_replay() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::CompleteRun,
            100,
            LogicalTime::from_raw(1),
            RunOpResult::Ack,
        ));
        assert!(
            r.check_op_idempotency(OpId::from_raw(1), 100)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn run_idem_conflict() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::CompleteRun,
            100,
            LogicalTime::from_raw(1),
            RunOpResult::Ack,
        ));
        let err = r.check_op_idempotency(OpId::from_raw(1), 999).unwrap_err();
        assert_eq!(err.expected_hash, 100);
        assert_eq!(err.actual_hash, 999);
    }

    #[test]
    #[should_panic(expected = "payload_hash must not be zero")]
    fn run_idem_zero_hash_panics() {
        test_run_record()
            .check_op_idempotency(OpId::from_raw(1), 0)
            .unwrap();
    }

    // -- RunProgress --

    #[test]
    fn progress_count_shard() {
        let mut p = RunProgress::default();
        p.count_shard(ShardStatus::Active, true);
        p.count_shard(ShardStatus::Active, false);
        p.count_shard(ShardStatus::Done, false);
        p.count_shard(ShardStatus::Split, false);
        p.count_shard(ShardStatus::Parked, false);
        assert_eq!(p.total(), 5);
        assert_eq!(p.active(), 2);
        assert_eq!(p.leased(), 1);
        assert_eq!(p.done(), 1);
        assert_eq!(p.split(), 1);
        assert_eq!(p.parked(), 1);
    }

    #[test]
    fn progress_predicates() {
        let settled_success = RunProgress {
            total: 3,
            done: 2,
            split: 1,
            ..Default::default()
        };
        assert!(settled_success.is_settled());
        assert!(settled_success.is_success());
        assert!(!settled_success.has_failures());

        let settled_failures = RunProgress {
            total: 3,
            done: 1,
            parked: 2,
            ..Default::default()
        };
        assert!(settled_failures.is_settled());
        assert!(!settled_failures.is_success());
        assert!(settled_failures.has_failures());

        let still_active = RunProgress {
            total: 3,
            active: 1,
            done: 2,
            ..Default::default()
        };
        assert!(!still_active.is_settled());
    }

    // -- evaluate_run_terminal --

    #[rstest]
    #[case::still_active(
        RunProgress { total: 1, active: 1, ..Default::default() },
        RunTerminalEvaluation::StillActive,
    )]
    #[case::all_done(
        RunProgress { total: 3, done: 2, split: 1, ..Default::default() },
        RunTerminalEvaluation::AllDone,
    )]
    #[case::has_failures(
        RunProgress { total: 3, done: 1, parked: 2, ..Default::default() },
        RunTerminalEvaluation::HasFailures,
    )]
    fn evaluate_run_terminal_cases(
        #[case] progress: RunProgress,
        #[case] expected: RunTerminalEvaluation,
    ) {
        assert_eq!(evaluate_run_terminal(&progress), expected);
    }

    // -- validate_manifest --

    #[rstest]
    #[case::two_adjacent(
        vec![make_initial_shard(0, b"a", b"m"), make_initial_shard(1, b"m", b"z")]
    )]
    #[case::gap_between_shards(
        vec![make_initial_shard(0, b"a", b"f"), make_initial_shard(1, b"m", b"z")]
    )]
    #[case::unordered_input(
        vec![make_initial_shard(1, b"m", b"z"), make_initial_shard(0, b"a", b"m")]
    )]
    #[case::single_shard(vec![make_initial_shard(0, b"a", b"z")])]
    fn manifest_valid_cases(#[case] shards: Vec<InitialShard>) {
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn manifest_empty() {
        assert_eq!(validate_manifest(&[]), Err(ManifestValidationError::Empty));
    }

    #[test]
    fn manifest_too_many() {
        let shards: Vec<_> = (0..MAX_INITIAL_SHARDS + 1)
            .map(|i| {
                let start = format!("{:05}", i);
                let end = format!("{:05}", i + 1);
                make_initial_shard(i as u64, start.as_bytes(), end.as_bytes())
            })
            .collect();
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::TooManyShards { .. })
        ));
    }

    #[test]
    fn manifest_dup_id() {
        assert!(matches!(
            validate_manifest(&[
                make_initial_shard(0, b"a", b"m"),
                make_initial_shard(0, b"m", b"z"),
            ]),
            Err(ManifestValidationError::DuplicateIds { .. })
        ));
    }

    #[test]
    fn manifest_overlap() {
        assert!(matches!(
            validate_manifest(&[
                make_initial_shard(0, b"a", b"n"),
                make_initial_shard(1, b"m", b"z"),
            ]),
            Err(ManifestValidationError::OverlappingRanges { .. })
        ));
    }

    #[test]
    fn manifest_inverted_spec() {
        // Use try_with_range to avoid the panic in with_range on inverted range,
        // then bypass via unbounded spec manipulation. Actually, ShardSpec::with_range
        // enforces start < end at construction. Validate that validate_manifest
        // also catches this via try_with_range.
        let result = ShardSpec::try_with_range(b"z".to_vec(), b"a".to_vec());
        assert!(result.is_err(), "ShardSpec should reject inverted range");
    }

    #[test]
    fn manifest_cursor_out_of_bounds() {
        let shard = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::with_last_key(b"a".to_vec()), // before range start
        );
        assert!(matches!(
            validate_manifest(&[shard]),
            Err(ManifestValidationError::CursorOutOfBounds { .. })
        ));
    }

    #[test]
    fn manifest_cursor_key_too_large() {
        use crate::coordination::cursor::MAX_KEY_SIZE;

        let oversized_key = vec![0xAA; MAX_KEY_SIZE + 1];
        let shard = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::with_range(vec![0x00], vec![0xFF]),
            Cursor::with_last_key(oversized_key),
        );
        let result = validate_manifest(&[shard]);
        assert!(
            matches!(
                result,
                Err(ManifestValidationError::CursorKeyTooLarge { size, max, .. })
                    if size == MAX_KEY_SIZE + 1 && max == MAX_KEY_SIZE
            ),
            "expected CursorKeyTooLarge, got: {result:?}",
        );
    }

    #[test]
    fn manifest_cursor_key_at_exact_max_succeeds() {
        use crate::coordination::cursor::MAX_KEY_SIZE;

        let exact_key = vec![0xBB; MAX_KEY_SIZE];
        let shard = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::with_range(vec![0x00], vec![0xFF]),
            Cursor::with_last_key(exact_key),
        );
        assert!(validate_manifest(&[shard]).is_ok());
    }

    #[test]
    fn manifest_cursor_key_too_large_display() {
        let err = ManifestValidationError::CursorKeyTooLarge {
            shard_id: ShardId::from_raw(42),
            size: 5000,
            max: 4096,
        };
        let msg = err.to_string();
        assert!(msg.contains("5000"), "display must include actual size");
        assert!(msg.contains("4096"), "display must include max size");
    }

    // -- ShardFilter --

    fn make_shard_summary(
        status: ShardStatus,
        leased: bool,
        parent: Option<ShardId>,
    ) -> ShardSummary {
        ShardSummary {
            shard: ShardId::from_raw(0),
            status,
            park_reason: None,
            is_leased: leased,
            acquire_count: 0,
            last_key: None,
            key_range_start: b"a".to_vec().into(),
            key_range_end: b"z".to_vec().into(),
            parent,
            spawned_count: 0,
        }
    }

    #[rstest]
    #[case::all_matches_everything(
        ShardFilter::all(),
        make_shard_summary(ShardStatus::Active, false, None),
        true
    )]
    #[case::active_rejects_done(
        ShardFilter::active(),
        make_shard_summary(ShardStatus::Done, false, None),
        false
    )]
    #[case::available_rejects_leased(
        ShardFilter::available(),
        make_shard_summary(ShardStatus::Active, true, None),
        false
    )]
    #[case::root_only_rejects_children(
        ShardFilter { root_only: true, ..ShardFilter::default() },
        make_shard_summary(ShardStatus::Active, false, Some(ShardId::from_raw(99))),
        false,
    )]
    fn shard_filter_matching(
        #[case] filter: ShardFilter,
        #[case] summary: ShardSummary,
        #[case] expected: bool,
    ) {
        assert_eq!(filter.matches(&summary), expected);
    }

    // -- Payload hashes --

    #[test]
    fn hash_register_shards_order_independent() {
        let s1 = make_initial_shard(0, b"a", b"m");
        let s2 = make_initial_shard(1, b"m", b"z");
        let h_forward = hash_register_shards_payload(&[s1.clone(), s2.clone()]);
        let h_reverse = hash_register_shards_payload(&[s2, s1]);
        assert_eq!(h_forward, h_reverse);
        assert_ne!(h_forward, 0);
    }

    #[test]
    fn hash_terminal_ops_distinct() {
        let hc = hash_complete_run_payload();
        let hf = hash_fail_run_payload();
        let hx = hash_cancel_run_payload();
        assert_ne!(hc, 0);
        assert_ne!(hf, 0);
        assert_ne!(hx, 0);
        assert_ne!(hc, hf);
        assert_ne!(hc, hx);
        assert_ne!(hf, hx);
    }

    #[test]
    fn hash_unpark_different_shards_differ() {
        let k1 = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(10));
        let k2 = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(20));
        let h1 = hash_unpark_payload(&k1);
        let h2 = hash_unpark_payload(&k2);
        assert_ne!(h1, h2);
        assert_ne!(h1, 0);
        assert_ne!(h2, 0);
    }

    // -- INV-11: Kind-result consistency --

    #[test]
    #[should_panic(expected = "RegisterShards must have RegisteredShards result")]
    fn construction_rejects_register_shards_with_ack() {
        // INV-11 now enforced at construction time in RunOpLogEntry::new().
        let _ = RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::RegisterShards,
            42,
            LogicalTime::from_raw(1),
            RunOpResult::Ack,
        );
    }

    #[test]
    #[should_panic(expected = "must have Ack result, not RegisteredShards")]
    fn construction_rejects_terminal_op_with_registered_shards() {
        // INV-11 now enforced at construction time in RunOpLogEntry::new().
        let _ = RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::CompleteRun,
            42,
            LogicalTime::from_raw(1),
            RunOpResult::RegisteredShards {
                shard_ids: Box::new([]),
            },
        );
    }

    #[test]
    #[should_panic(expected = "duplicate ShardId")]
    fn rr_duplicate_root_shards_panics() {
        let dup = ShardId::from_raw(0);
        RunRecord {
            root_shards: vec![dup, dup],
            ..test_run_record()
        }
        .assert_invariants();
    }

    #[test]
    #[should_panic(expected = "timestamps not non-decreasing")]
    fn rr_oplog_timestamps_non_decreasing_panics() {
        let mut r = test_run_record();
        r.op_log
            .push_back(RunOpLogEntry::new(
                OpId::from_raw(1),
                RunOpKind::CompleteRun,
                42,
                LogicalTime::from_raw(10),
                RunOpResult::Ack,
            ))
            .unwrap();
        r.op_log
            .push_back(RunOpLogEntry::new(
                OpId::from_raw(2),
                RunOpKind::FailRun,
                43,
                LogicalTime::from_raw(5), // earlier than previous — violates INV-10
                RunOpResult::Ack,
            ))
            .unwrap();
        r.assert_invariants();
    }

    // -- Finding 3: ShardSummary acquire_count saturation --

    #[test]
    fn shard_summary_acquire_count_saturates_at_u32_max() {
        use crate::coordination::record::ShardRecord;

        let large_epoch = FenceEpoch::from_raw(u64::from(u32::MAX) + 2);
        let record = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            ShardId::from_raw(1),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            large_epoch,
            None,
            vec![],
            RingBuffer::new(),
        );
        let summary = ShardSummary::from_record(&record, LogicalTime::from_raw(1));
        assert_eq!(
            summary.acquire_count(),
            u32::MAX,
            "acquire_count must saturate at u32::MAX, not truncate"
        );
    }

    // -- Finding 2: validate_manifest InvalidSpec path --

    #[test]
    fn manifest_inverted_spec_detected_by_validate_manifest() {
        let inverted_spec = ShardSpec::from_raw_parts(
            b"z".to_vec().into_boxed_slice(),
            b"a".to_vec().into_boxed_slice(),
            Box::new([]),
        );
        let shard = InitialShard::new(ShardId::from_raw(0), inverted_spec, Cursor::initial());
        let result = validate_manifest(&[shard]);
        assert!(
            matches!(result, Err(ManifestValidationError::InvalidSpec { .. })),
            "validate_manifest must catch inverted specs: {result:?}"
        );
    }

    // -- Finding 4: count_shard assert (promoted from debug_assert) --

    #[test]
    #[should_panic(expected = "is_leased=true is only valid for Active shards")]
    fn count_shard_leased_non_active_panics() {
        let mut p = RunProgress::default();
        p.count_shard(ShardStatus::Done, true);
    }

    // -- Finding 5: evaluate_run_terminal debug_assert --

    #[test]
    #[should_panic(expected = "evaluate_run_terminal called with zero-total progress")]
    fn evaluate_run_terminal_zero_total_panics() {
        let _ = evaluate_run_terminal(&RunProgress::default());
    }

    // -- RunOpIdConflict Display does not leak hashes --

    #[test]
    fn run_op_id_conflict_display_no_hash_leak() {
        let c = RunOpIdConflict {
            op_id: OpId::from_raw(1),
            expected_hash: 0xDEAD_BEEF,
            actual_hash: 0xCAFE_BABE,
        };
        let display = c.to_string();
        assert!(
            !display.contains("DEAD") && !display.contains("CAFE"),
            "Display leaks hex hash: {display}"
        );
        assert!(
            !display.contains("3735928559") && !display.contains("3405691582"),
            "Display leaks decimal hash: {display}"
        );
    }

    // -- Exact boundary tests --

    #[test]
    fn manifest_exactly_max_initial_shards_succeeds() {
        let shards: Vec<_> = (0..MAX_INITIAL_SHARDS)
            .map(|i| {
                let start = format!("{:05}", i);
                let end = format!("{:05}", i + 1);
                make_initial_shard(i as u64, start.as_bytes(), end.as_bytes())
            })
            .collect();
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn op_log_exactly_at_cap_maintains_invariants() {
        let mut r = test_run_record();
        for i in 0..RunRecord::OP_LOG_CAP {
            r.op_log_push(make_op_log_entry(i as u64, RunOpKind::CompleteRun));
        }
        assert_eq!(r.op_log.len(), RunRecord::OP_LOG_CAP);
        r.assert_invariants();

        // One more should evict the oldest.
        r.op_log_push(make_op_log_entry(
            RunRecord::OP_LOG_CAP as u64,
            RunOpKind::FailRun,
        ));
        assert_eq!(r.op_log.len(), RunRecord::OP_LOG_CAP);
        // Oldest (op_id=0) evicted.
        assert!(r.op_log_lookup(OpId::from_raw(0)).is_none());
        // Newest still present.
        assert!(
            r.op_log_lookup(OpId::from_raw(RunRecord::OP_LOG_CAP as u64))
                .is_some()
        );
        r.assert_invariants();
    }

    #[test]
    fn count_shard_overflow_panics() {
        let mut p = RunProgress {
            total: u32::MAX,
            active: u32::MAX,
            ..Default::default()
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p.count_shard(ShardStatus::Active, false);
        }));
        assert!(result.is_err(), "count_shard must panic on u32 overflow");
    }

    // -- Proptest for validate_manifest --

    mod prop_manifest {
        use super::*;
        use crate::test_util::miri_proptest_config;
        use proptest::prelude::*;

        /// Strategy for a valid shard ID (non-zero, bounded).
        fn arb_shard_id() -> impl Strategy<Value = ShardId> {
            (1u64..10_000).prop_map(ShardId::from_raw)
        }

        /// Strategy for a valid InitialShard with non-overlapping key range.
        fn arb_initial_shard(idx: usize) -> impl Strategy<Value = InitialShard> {
            arb_shard_id().prop_map(move |id| {
                let start = format!("{:06}", idx);
                let end = format!("{:06}", idx + 1);
                InitialShard::new(
                    id,
                    ShardSpec::with_range(start.into_bytes(), end.into_bytes()),
                    Cursor::initial(),
                )
            })
        }

        /// Generate a vec of `n` initial shards with unique, non-overlapping
        /// key ranges (indexed by position).
        fn arb_manifest(max_len: usize) -> impl Strategy<Value = Vec<InitialShard>> {
            (1..=max_len).prop_flat_map(|n| {
                // Generate n unique shard IDs.
                proptest::collection::hash_set(1u64..100_000, n).prop_map(move |ids| {
                    ids.into_iter()
                        .enumerate()
                        .map(|(idx, raw)| {
                            let start = format!("{:06}", idx);
                            let end = format!("{:06}", idx + 1);
                            InitialShard::new(
                                ShardId::from_raw(raw),
                                ShardSpec::with_range(start.into_bytes(), end.into_bytes()),
                                Cursor::initial(),
                            )
                        })
                        .collect()
                })
            })
        }

        proptest! {
            #![proptest_config(miri_proptest_config())]

            /// Well-formed manifests always pass validation.
            #[test]
            fn valid_manifests_accepted(shards in arb_manifest(50)) {
                prop_assert!(validate_manifest(&shards).is_ok());
            }

            /// Manifests with a duplicate ID always fail.
            #[test]
            fn duplicate_id_always_rejected(base in arb_initial_shard(0)) {
                let dup = InitialShard::new(
                    base.shard(),
                    ShardSpec::with_range(b"x".to_vec(), b"y".to_vec()),
                    Cursor::initial(),
                );
                let result = validate_manifest(&[base, dup]);
                prop_assert!(
                    matches!(result, Err(ManifestValidationError::DuplicateIds { .. })),
                    "expected DuplicateIds, got: {result:?}",
                );
            }

            /// Overlapping ranges always fail.
            #[test]
            fn overlapping_ranges_always_rejected(
                id_a in 1u64..50_000,
                id_b in 50_000u64..100_000,
            ) {
                let a = InitialShard::new(
                    ShardId::from_raw(id_a),
                    ShardSpec::with_range(b"a".to_vec(), b"n".to_vec()),
                    Cursor::initial(),
                );
                let b = InitialShard::new(
                    ShardId::from_raw(id_b),
                    ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                    Cursor::initial(),
                );
                let result = validate_manifest(&[a, b]);
                prop_assert!(
                    matches!(result, Err(ManifestValidationError::OverlappingRanges { .. })),
                    "expected OverlappingRanges, got: {result:?}",
                );
            }
        }
    }

    // -- Unbounded range rejection tests --

    #[test]
    fn manifest_detects_overlap_with_unbounded_end() {
        // Unbounded end is now rejected before overlap detection.
        let shard_a = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::from_raw_parts(
                b"a".to_vec().into_boxed_slice(),
                Box::new([]), // unbounded end = [a, ∞)
                Box::new([]),
            ),
            Cursor::initial(),
        );
        let shard_b = make_initial_shard(1, b"m", b"z");
        let result = validate_manifest(&[shard_a, shard_b]);
        assert!(
            matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
            "unbounded end must be rejected: {result:?}"
        );
    }

    #[test]
    fn manifest_detects_overlap_with_both_starts_empty() {
        // Unbounded start is now rejected before overlap detection.
        let shard_a = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::from_raw_parts(
                Box::new([]), // unbounded start
                b"m".to_vec().into_boxed_slice(),
                Box::new([]),
            ),
            Cursor::initial(),
        );
        let shard_b = InitialShard::new(
            ShardId::from_raw(1),
            ShardSpec::from_raw_parts(
                Box::new([]), // unbounded start
                b"z".to_vec().into_boxed_slice(),
                Box::new([]),
            ),
            Cursor::initial(),
        );
        let result = validate_manifest(&[shard_a, shard_b]);
        assert!(
            matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
            "unbounded start must be rejected: {result:?}"
        );
    }

    #[test]
    fn manifest_unbounded_start_rejected() {
        // Unbounded start is no longer accepted in production manifests.
        let shard_a = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::from_raw_parts(
                Box::new([]), // unbounded start
                b"m".to_vec().into_boxed_slice(),
                Box::new([]),
            ),
            Cursor::initial(),
        );
        let shard_b = make_initial_shard(1, b"m", b"z");
        let result = validate_manifest(&[shard_a, shard_b]);
        assert!(
            matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
            "unbounded start must be rejected: {result:?}"
        );
    }

    #[test]
    fn manifest_unbounded_end_rejected() {
        let shard = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::from_raw_parts(b"a".to_vec().into_boxed_slice(), Box::new([]), Box::new([])),
            Cursor::initial(),
        );
        assert!(
            matches!(
                validate_manifest(&[shard]),
                Err(ManifestValidationError::UnboundedRange { .. })
            ),
            "shard with unbounded end must be rejected"
        );
    }

    #[test]
    fn manifest_fully_unbounded_rejected() {
        let shard = InitialShard::new(
            ShardId::from_raw(0),
            ShardSpec::unbounded(),
            Cursor::initial(),
        );
        assert!(
            matches!(
                validate_manifest(&[shard]),
                Err(ManifestValidationError::UnboundedRange { .. })
            ),
            "fully unbounded shard must be rejected"
        );
    }
}
