//! Run-level types, validation, payload hashing, and the `RunManagement` trait.
//!
//! A "run" is a single scan invocation — it groups a set of shards that
//! collectively cover the target data source. The coordinator tracks run
//! status, validates shard manifests, and provides progress aggregation.
//!

use std::fmt;
use std::num::NonZeroU64;

use crate::coordination::cursor::{Cursor, MAX_KEY_SIZE};
use crate::coordination::error::IdempotentOutcome;
use crate::coordination::record::{ParkReason, ShardRecord, ShardStatus};
use crate::coordination::run_errors::{
    CreateRunError, GetRunError, RegisterShardsError, RunTransitionError, UnparkError,
};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::split::op_payload_hash;
use crate::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId,
};
use gossip_stdx::{ByteSlab, RingBuffer};

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
/// `unpark(shard_A)` from `unpark(shard_B)`.
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
    /// Deadline of the current lease, if any.  `Some` only when
    /// `is_leased` is `true`.  Callers use this to schedule retry
    /// attempts near the soonest expiry without a separate query.
    pub(crate) lease_deadline: Option<LogicalTime>,
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
    pub(crate) fn from_record(record: &ShardRecord, now: LogicalTime, slab: &ByteSlab) -> Self {
        Self {
            shard: record.shard,
            status: record.status,
            park_reason: record.park_reason,
            is_leased: record.is_leased_at(now),
            lease_deadline: if record.is_leased_at(now) {
                record.lease_deadline()
            } else {
                None
            },
            acquire_count: u32::try_from(
                record
                    .fence_epoch
                    .as_raw()
                    .saturating_sub(FenceEpoch::INITIAL.as_raw()),
            )
            .unwrap_or(u32::MAX),
            last_key: record.cursor.last_key(slab).map(|k| k.into()),
            key_range_start: record.spec.key_range_start(slab).into(),
            key_range_end: record.spec.key_range_end(slab).into(),
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
    pub fn lease_deadline(&self) -> Option<LogicalTime> {
        self.lease_deadline
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
    ///
    /// # Errors
    ///
    /// - [`RunTransitionError::RunNotFound`] — no run with this ID for the tenant.
    /// - [`RunTransitionError::TenantMismatch`] — tenant isolation violation.
    /// - [`RunTransitionError::RunTerminal`] — run is already in a terminal state.
    /// - [`RunTransitionError::WrongStatus`] (target = `Done`) — run is not `Active`.
    /// - [`RunTransitionError::OpIdConflict`] — `op_id` reused with different payload.
    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError>;

    /// Mark run as Failed. Precondition: **Active only** (not Initializing).
    /// Use `cancel_run` for Initializing runs. Idempotent via `op_id`.
    ///
    /// # Errors
    ///
    /// - [`RunTransitionError::RunNotFound`] — no run with this ID for the tenant.
    /// - [`RunTransitionError::TenantMismatch`] — tenant isolation violation.
    /// - [`RunTransitionError::RunTerminal`] — run is already in a terminal state.
    /// - [`RunTransitionError::WrongStatus`] (target = `Failed`) — run is not `Active`.
    /// - [`RunTransitionError::OpIdConflict`] — `op_id` reused with different payload.
    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError>;

    /// Cancel run (sets Cancelled). Accepts Initializing OR Active.
    /// Idempotent via `op_id`.
    ///
    /// # Errors
    ///
    /// - [`RunTransitionError::RunNotFound`] — no run with this ID for the tenant.
    /// - [`RunTransitionError::TenantMismatch`] — tenant isolation violation.
    /// - [`RunTransitionError::RunTerminal`] — run is already in a terminal state.
    /// - [`RunTransitionError::OpIdConflict`] — `op_id` reused with different payload.
    ///
    /// Never returns [`RunTransitionError::WrongStatus`] — both Initializing and
    /// Active are accepted.
    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError>;

    /// Unpark a parked shard. Admin-only, NOT lease-gated.
    ///
    /// Bumps `fence_epoch` (fencing any zombie workers), clears park state,
    /// restores Active status. Preserves cursor position.
    ///
    /// Idempotency is stored in the **shard** op-log, not the run op-log.
    ///
    /// # Errors
    ///
    /// - [`UnparkError::ShardNotFound`] — shard does not exist.
    /// - [`UnparkError::TenantMismatch`] — tenant isolation violation.
    /// - [`UnparkError::RunTerminal`] — run is already in a terminal state.
    /// - [`UnparkError::NotParked`] — shard is not in Parked status.
    /// - [`UnparkError::OpIdConflict`] — `op_id` reused with different payload.
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
#[path = "run_tests.rs"]
mod tests;
