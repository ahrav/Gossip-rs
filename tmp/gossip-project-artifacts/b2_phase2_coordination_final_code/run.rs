//! Run-level types, validation, error types, and the `RunManagement` trait.
//!
//! A "run" is a single scan invocation — it groups a set of shards that
//! collectively cover the target data source. The coordinator tracks run
//! status, validates shard manifests, and provides progress aggregation.
//!
//! ## Design Decisions (locked)
//!
//! D2.18: RunRecord is the coordinator's authoritative record for a run.
//! D2.19: RunStatus has 4 states: Initializing → Active → Done | Failed.
//! D2.20: Two-phase run creation (create_run → register_shards).
//! D2.21: Admin operations (unpark, cancel) are NOT lease-gated.
//! D2.22: RunManagement is separate from CoordinationBackend.
//! D2.23: `now: LogicalTime` is passed explicitly to every operation.
//! D2.24: Shard listing returns ShardSummary (lightweight).
//! D2.25: RunRecord gets its own bounded op-log (cap: 8).

use crate::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, OpId, RunId,
    ShardId, ShardKey, TenantId, WorkerId,
};
use crate::coordination::cursor::Cursor;
use crate::coordination::error::IdempotentOutcome;
use crate::coordination::record::{
    ParkReason, ShardRecord, ShardStatus,
};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::split::op_payload_hash;

// ============================================================================
// § RunStatus
// ============================================================================

/// Run lifecycle state.
///
/// ```text
///  Initializing ──register_shards──→ Active
///       │                              │
///       │ (timeout/cancel)    ┌────────┼────────┐
///       ▼                    all Done  Parked  cancel
///    Failed                    │        │        │
///                              ▼        ▼        ▼
///                            Done     Failed   Failed
/// ```
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: `#[repr(u8)]` values are persisted.
/// **Safety (terminal irreversibility)**: Done/Failed never changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RunStatus {
    Initializing = 0,
    Active = 1,
    Done = 2,
    Failed = 3,
}

impl RunStatus {
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Initializing),
            1 => Some(Self::Active),
            2 => Some(Self::Done),
            3 => Some(Self::Failed),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// § RunConfig
// ============================================================================

/// Per-run configuration, immutable after creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunConfig {
    pub cursor_semantics: CursorSemantics,
    /// Lease duration in logical time units.
    pub lease_duration: u64,
    /// Max re-acquisitions before auto-parking. `None` = unlimited.
    pub max_shard_retries: Option<u32>,
}

impl RunConfig {
    pub fn assert_valid(&self) {
        assert!(self.lease_duration > 0, "lease_duration must be positive");
    }
}

// ============================================================================
// § Run-level op-log types (B2C5 §5.1)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RunOpKind {
    RegisterShards,
    CompleteRun,
    FailRun,
    CancelRun,
    UnparkShard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOpResult {
    Ack,
    RegisteredShards { shard_ids: Vec<ShardId> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOpLogEntry {
    pub op_id: OpId,
    pub kind: RunOpKind,
    pub payload_hash: u64,
    pub result: RunOpResult,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOpIdConflict {
    pub op_id: OpId,
    pub expected_hash: u64,
    pub actual_hash: u64,
}

// ============================================================================
// § RunRecord
// ============================================================================

/// The coordinator's authoritative record for a scan run.
///
/// ## Invariants (checked by `assert_invariants`)
///
/// **Safety (terminal irreversible)**: Once Done/Failed, never changes.
/// **Safety (shards non-empty when active)**: Active ⇒ root_shards non-empty.
/// **Safety (completed_at consistency)**: `completed_at.is_some()` iff terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRecord {
    pub tenant: TenantId,
    pub run: RunId,
    pub config: RunConfig,
    pub status: RunStatus,
    pub created_at: LogicalTime,
    pub completed_at: Option<LogicalTime>,
    /// Root shard IDs registered at creation. Does not include split children.
    pub root_shards: Vec<ShardId>,
    /// Bounded op-log for idempotent replay of run-level ops.
    pub op_log: Vec<RunOpLogEntry>,
}

impl RunRecord {
    pub const OP_LOG_CAP: usize = 8;

    pub fn assert_invariants(&self) {
        if self.status == RunStatus::Active {
            assert!(
                !self.root_shards.is_empty(),
                "Active run {:?} must have at least one root shard",
                self.run,
            );
        }
        assert_eq!(
            self.completed_at.is_some(),
            self.status.is_terminal(),
            "Run {:?}: completed_at must be Some iff status is terminal \
             (status: {:?})",
            self.run,
            self.status,
        );
    }

    pub fn op_log_lookup(&self, op: OpId) -> Option<&RunOpLogEntry> {
        self.op_log.iter().find(|e| e.op_id == op)
    }

    pub fn op_log_push(&mut self, entry: RunOpLogEntry) {
        if self.op_log.len() >= Self::OP_LOG_CAP {
            self.op_log.remove(0);
        }
        self.op_log.push(entry);
    }

    pub fn check_op_idempotency(
        &self,
        op_id: OpId,
        payload_hash: u64,
    ) -> Result<Option<&RunOpLogEntry>, RunOpIdConflict> {
        match self.op_log_lookup(op_id) {
            None => Ok(None),
            Some(entry) => {
                if entry.payload_hash == payload_hash {
                    Ok(Some(entry))
                } else {
                    Err(RunOpIdConflict {
                        op_id,
                        expected_hash: entry.payload_hash,
                        actual_hash: payload_hash,
                    })
                }
            }
        }
    }
}

// ============================================================================
// § RunProgress + RunTerminalEvaluation
// ============================================================================

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunProgress {
    pub total: u64,
    pub active: u64,
    pub done: u64,
    pub split: u64,
    pub parked: u64,
    pub leased: u64,
}

impl RunProgress {
    #[inline]
    pub fn is_settled(&self) -> bool { self.active == 0 }
    #[inline]
    pub fn is_success(&self) -> bool { self.is_settled() && self.parked == 0 }
    #[inline]
    pub fn has_failures(&self) -> bool { self.parked > 0 }

    pub fn count_shard(&mut self, status: ShardStatus, is_leased: bool) {
        self.total += 1;
        match status {
            ShardStatus::Active => {
                self.active += 1;
                if is_leased { self.leased += 1; }
            }
            ShardStatus::Done => self.done += 1,
            ShardStatus::Split => self.split += 1,
            ShardStatus::Parked => self.parked += 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunTerminalEvaluation {
    StillActive,
    AllDone,
    HasFailures,
}

/// Evaluate whether a run should transition to a terminal state.
pub fn evaluate_run_terminal(progress: &RunProgress) -> RunTerminalEvaluation {
    if progress.active > 0 {
        RunTerminalEvaluation::StillActive
    } else if progress.parked > 0 {
        RunTerminalEvaluation::HasFailures
    } else {
        RunTerminalEvaluation::AllDone
    }
}

// ============================================================================
// § InitialShard + ManifestValidation
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialShard {
    pub shard_id: ShardId,
    pub spec: ShardSpec,
    pub cursor: Cursor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestValidationError {
    Empty,
    DuplicateId { shard_id: ShardId },
    OverlappingRanges {
        shard_a: ShardId,
        shard_b: ShardId,
        overlap_start: Box<[u8]>,
    },
    InvalidSpec { shard_id: ShardId, reason: String },
}

/// Validate a manifest of initial shards.
///
/// Checks: non-empty, no duplicate IDs, no overlapping key ranges,
/// each spec internally valid. Gaps are allowed.
pub fn validate_manifest(
    shards: &[InitialShard],
) -> Result<(), ManifestValidationError> {
    if shards.is_empty() {
        return Err(ManifestValidationError::Empty);
    }

    let mut ids: Vec<ShardId> = shards.iter().map(|s| s.shard_id).collect();
    ids.sort_by_key(|id| id.0);
    for window in ids.windows(2) {
        if window[0] == window[1] {
            return Err(ManifestValidationError::DuplicateId {
                shard_id: window[0],
            });
        }
    }

    for shard in shards {
        if shard.spec.key_range_start >= shard.spec.key_range_end {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard_id,
                reason: "key_range_start must be strictly less than key_range_end".into(),
            });
        }
    }

    let mut sorted: Vec<&InitialShard> = shards.iter().collect();
    sorted.sort_by(|a, b| a.spec.key_range_start.cmp(&b.spec.key_range_start));

    for window in sorted.windows(2) {
        let (a, b) = (window[0], window[1]);
        if a.spec.key_range_end > b.spec.key_range_start {
            return Err(ManifestValidationError::OverlappingRanges {
                shard_a: a.shard_id,
                shard_b: b.shard_id,
                overlap_start: b.spec.key_range_start.clone(),
            });
        }
    }

    Ok(())
}

// ============================================================================
// § ShardSummary
// ============================================================================

/// Lightweight shard summary for listing and observability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSummary {
    pub shard: ShardId,
    pub status: ShardStatus,
    pub park_reason: Option<ParkReason>,
    pub is_leased: bool,
    pub acquire_count: u64,
    pub last_key: Option<Box<[u8]>>,
    pub key_range_start: Box<[u8]>,
    pub key_range_end: Box<[u8]>,
    pub parent: Option<ShardId>,
    pub spawned_count: usize,
}

impl ShardSummary {
    pub fn from_record(record: &ShardRecord, now: LogicalTime) -> Self {
        Self {
            shard: record.shard,
            status: record.status,
            park_reason: record.park_reason,
            is_leased: record.is_leased_at(now),
            acquire_count: record.fence_epoch.0.saturating_sub(FenceEpoch::INITIAL.0),
            last_key: record.cursor.last_key.clone(),
            key_range_start: record.spec.key_range_start.clone(),
            key_range_end: record.spec.key_range_end.clone(),
            parent: record.parent,
            spawned_count: record.spawned.len(),
        }
    }
}

// ============================================================================
// § ShardFilter
// ============================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardFilter {
    pub status: Option<ShardStatus>,
    pub is_leased: Option<bool>,
    pub parent: Option<ShardId>,
    pub root_only: bool,
}

impl ShardFilter {
    pub fn all() -> Self { Self::default() }

    pub fn active() -> Self {
        Self { status: Some(ShardStatus::Active), ..Self::default() }
    }

    pub fn parked() -> Self {
        Self { status: Some(ShardStatus::Parked), ..Self::default() }
    }

    pub fn available() -> Self {
        Self {
            status: Some(ShardStatus::Active),
            is_leased: Some(false),
            ..Self::default()
        }
    }

    pub fn matches(&self, summary: &ShardSummary) -> bool {
        if let Some(status) = self.status {
            if summary.status != status { return false; }
        }
        if let Some(leased) = self.is_leased {
            if summary.is_leased != leased { return false; }
        }
        if let Some(parent) = self.parent {
            if summary.parent != Some(parent) { return false; }
        }
        if self.root_only && summary.parent.is_some() {
            return false;
        }
        true
    }
}

// ============================================================================
// § Run-level error types
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateRunError {
    RunAlreadyExists { run: RunId },
    TenantMismatch { expected: TenantId, actual: TenantId },
    InvalidConfig { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterShardsError {
    RunNotFound { run: RunId },
    TenantMismatch { expected: TenantId, actual: TenantId },
    WrongStatus { expected: RunStatus, actual: RunStatus },
    ManifestInvalid(ManifestValidationError),
    OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 },
}

impl From<RunOpIdConflict> for RegisterShardsError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetRunError {
    RunNotFound { run: RunId },
    TenantMismatch { expected: TenantId, actual: TenantId },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompleteRunError {
    RunNotFound { run: RunId },
    TenantMismatch { expected: TenantId, actual: TenantId },
    RunTerminal { run: RunId, status: RunStatus },
    WrongStatus { expected: RunStatus, actual: RunStatus },
    OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 },
}

impl From<RunOpIdConflict> for CompleteRunError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnparkError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch { expected: TenantId, actual: TenantId },
    NotParked { shard: ShardKey, status: ShardStatus },
    OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 },
}

impl From<RunOpIdConflict> for UnparkError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelRunError {
    RunNotFound { run: RunId },
    TenantMismatch { expected: TenantId, actual: TenantId },
    RunTerminal { run: RunId, status: RunStatus },
    OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 },
}

impl From<RunOpIdConflict> for CancelRunError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

// ============================================================================
// § Run-level payload hash functions
// ============================================================================

pub fn hash_register_shards_payload(shards: &[InitialShard]) -> u64 {
    let mut sorted: Vec<&InitialShard> = shards.iter().collect();
    sorted.sort_by_key(|s| s.shard_id.0);

    op_payload_hash(b"register_shards", |h| {
        (sorted.len() as u32).write_canonical(h);
        for shard in &sorted {
            shard.shard_id.write_canonical(h);
            shard.spec.write_canonical(h);
            shard.cursor.write_canonical(h);
        }
    })
}

fn hash_run_terminal_payload(tag: &[u8]) -> u64 {
    op_payload_hash(tag, |_h| {})
}

pub fn hash_complete_run_payload() -> u64 {
    hash_run_terminal_payload(b"complete_run")
}

pub fn hash_fail_run_payload() -> u64 {
    hash_run_terminal_payload(b"fail_run")
}

pub fn hash_cancel_run_payload() -> u64 {
    hash_run_terminal_payload(b"cancel_run")
}

pub fn hash_unpark_payload(key: &ShardKey) -> u64 {
    op_payload_hash(b"unpark_shard", |h| {
        key.run.write_canonical(h);
        key.shard.write_canonical(h);
    })
}

// ============================================================================
// § RunManagement trait
// ============================================================================

/// Run-level management operations.
///
/// Separated from `CoordinationBackend` because:
/// - Different authorization model (admin/scheduler vs worker)
/// - Independent testability
///
/// ## Invariants
///
/// **Safety (tenant isolation)**: All operations validate tenant match.
/// **Safety (terminal irreversibility)**: Done/Failed never changes.
/// **Safety (shard creation atomicity)**: `register_shards` is atomic.
pub trait RunManagement {
    /// Create a new run in Initializing status. NOT idempotent.
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError>;

    /// Register initial shards and activate the run.
    /// Idempotent via `op_id`.
    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: Vec<InitialShard>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError>;

    /// Convenience: create + register in one call.
    ///
    /// This is a helper for tests and small clients. It is best-effort:
    /// - `create_run` itself is not idempotent
    /// - `register_shards` is idempotent via `op_id`
    ///
    /// On retry, if the run already exists with the same config, we attempt
    /// to (re-)apply `register_shards` and then return the current run record.
    fn create_run_with_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
        shards: Vec<InitialShard>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<RunRecord>, CreateRunError> {
        match self.create_run(now, tenant, run, config.clone()) {
            Ok(_) => {}
            Err(CreateRunError::RunAlreadyExists { .. }) => {
                // Treat as a retry: require the existing run to match the requested config.
                let existing = self.get_run(tenant, run).map_err(|e| CreateRunError::InvalidConfig {
                    reason: format!("create_run_with_shards: run exists but get_run failed: {e:?}"),
                })?;
                if existing.config != config {
                    return Err(CreateRunError::InvalidConfig {
                        reason: "create_run_with_shards: run exists with different config".into(),
                    });
                }
            }
            Err(e) => return Err(e),
        }

        let outcome = self
            .register_shards(now, tenant, run, shards, op_id)
            .map_err(|e| CreateRunError::InvalidConfig {
                reason: format!("create_run_with_shards: register_shards failed: {e:?}"),
            })?;

        let record = self.get_run(tenant, run).map_err(|e| CreateRunError::InvalidConfig {
            reason: format!("create_run_with_shards: get_run after register_shards failed: {e:?}"),
        })?;

        Ok(outcome.map(|_| record))
    }

    // —— Queries ——

    fn get_run(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunRecord, GetRunError>;

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError>;

    /// List shards for a run, filtered. Ordered by key_range_start.
    fn list_shards(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
    ) -> Result<Vec<ShardSummary>, GetRunError>;

    // —— Terminal transitions ——

    /// Mark run as Done. Precondition: Active. Idempotent via `op_id`.
    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError>;

    /// Mark run as Failed. Precondition: non-terminal. Idempotent via `op_id`.
    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError>;

    // —— Admin operations ——

    /// Cancel run (sets Failed). Idempotent via `op_id`.
    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CancelRunError>;

    /// Unpark a parked shard. Admin-only, NOT lease-gated.
    /// Bumps fence_epoch, preserves cursor. Idempotent via `op_id`.
    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError>;
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{JobId, PolicyHash};

    fn test_tenant() -> TenantId { TenantId::from_bytes([0x01; 32]) }
    fn test_run() -> RunId {
        RunId { job: JobId(1), policy: PolicyHash::from_bytes([0xAA; 32]) }
    }
    fn test_config() -> RunConfig {
        RunConfig {
            cursor_semantics: CursorSemantics::Completed,
            lease_duration: 30,
            max_shard_retries: Some(5),
        }
    }
    fn test_run_record() -> RunRecord {
        RunRecord {
            tenant: test_tenant(),
            run: test_run(),
            config: test_config(),
            status: RunStatus::Active,
            created_at: LogicalTime(0),
            completed_at: None,
            root_shards: vec![ShardId(0), ShardId(1)],
            op_log: vec![],
        }
    }
    fn make_initial_shard(id: u64, start: &[u8], end: &[u8]) -> InitialShard {
        InitialShard {
            shard_id: ShardId(id),
            spec: ShardSpec::with_range(start.to_vec(), end.to_vec()),
            cursor: Cursor::initial(),
        }
    }
    fn test_shard_record(shard_id: u64, status: ShardStatus) -> ShardRecord {
        ShardRecord {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(shard_id),
            status,
            park_reason: if status == ShardStatus::Parked {
                Some(ParkReason::Other)
            } else { None },
            spec: ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
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

    // —— RunStatus ——
    #[test] fn run_status_terminal() {
        assert!(!RunStatus::Initializing.is_terminal());
        assert!(!RunStatus::Active.is_terminal());
        assert!(RunStatus::Done.is_terminal());
        assert!(RunStatus::Failed.is_terminal());
    }
    #[test] fn run_status_roundtrip() {
        for v in 0..=3u8 { assert!(RunStatus::from_u8(v).is_some()); }
        assert_eq!(RunStatus::from_u8(4), None);
    }
    #[test] fn run_status_discriminants_stable() {
        assert_eq!(RunStatus::Initializing.as_u8(), 0);
        assert_eq!(RunStatus::Active.as_u8(), 1);
        assert_eq!(RunStatus::Done.as_u8(), 2);
        assert_eq!(RunStatus::Failed.as_u8(), 3);
    }

    // —— RunConfig ——
    #[test] fn run_config_valid() { test_config().assert_valid(); }
    #[test] #[should_panic(expected = "lease_duration must be positive")]
    fn run_config_zero_lease() {
        RunConfig { lease_duration: 0, ..test_config() }.assert_valid();
    }

    // —— RunRecord invariants ——
    #[test] fn rr_active_ok() { test_run_record().assert_invariants(); }
    #[test] fn rr_done_ok() {
        RunRecord {
            status: RunStatus::Done, completed_at: Some(LogicalTime(100)),
            ..test_run_record()
        }.assert_invariants();
    }
    #[test] #[should_panic(expected = "completed_at must be Some")]
    fn rr_done_no_completed_at() {
        RunRecord { status: RunStatus::Done, completed_at: None,
            ..test_run_record() }.assert_invariants();
    }
    #[test] #[should_panic(expected = "completed_at must be Some")]
    fn rr_active_has_completed_at() {
        RunRecord { completed_at: Some(LogicalTime(100)),
            ..test_run_record() }.assert_invariants();
    }
    #[test] #[should_panic(expected = "must have at least one root shard")]
    fn rr_active_no_shards() {
        RunRecord { root_shards: vec![], ..test_run_record() }
            .assert_invariants();
    }
    #[test] fn rr_initializing_empty_shards_ok() {
        RunRecord {
            status: RunStatus::Initializing, root_shards: vec![],
            ..test_run_record()
        }.assert_invariants();
    }

    // —— RunRecord op-log ——
    #[test] fn run_op_log_push_and_lookup() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry {
            op_id: OpId(42), kind: RunOpKind::CompleteRun,
            payload_hash: 123, result: RunOpResult::Ack,
        });
        assert!(r.op_log_lookup(OpId(42)).is_some());
        assert!(r.op_log_lookup(OpId(99)).is_none());
    }
    #[test] fn run_op_log_bounded() {
        let mut r = test_run_record();
        for i in 0..(RunRecord::OP_LOG_CAP + 5) {
            r.op_log_push(RunOpLogEntry {
                op_id: OpId(i as u64), kind: RunOpKind::CompleteRun,
                payload_hash: i as u64, result: RunOpResult::Ack,
            });
        }
        assert_eq!(r.op_log.len(), RunRecord::OP_LOG_CAP);
        assert!(r.op_log_lookup(OpId(0)).is_none());
        assert!(r.op_log_lookup(OpId((RunRecord::OP_LOG_CAP + 4) as u64)).is_some());
    }
    #[test] fn run_op_log_idem_new() {
        assert!(test_run_record().check_op_idempotency(OpId(1), 100).unwrap().is_none());
    }
    #[test] fn run_op_log_idem_replay() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry {
            op_id: OpId(1), kind: RunOpKind::CompleteRun,
            payload_hash: 100, result: RunOpResult::Ack,
        });
        assert!(r.check_op_idempotency(OpId(1), 100).unwrap().is_some());
    }
    #[test] fn run_op_log_idem_conflict() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry {
            op_id: OpId(1), kind: RunOpKind::CompleteRun,
            payload_hash: 100, result: RunOpResult::Ack,
        });
        let err = r.check_op_idempotency(OpId(1), 999).unwrap_err();
        assert_eq!(err.expected_hash, 100);
        assert_eq!(err.actual_hash, 999);
    }

    // —— RunProgress ——
    #[test] fn progress_count() {
        let mut p = RunProgress::default();
        p.count_shard(ShardStatus::Active, true);
        p.count_shard(ShardStatus::Active, false);
        p.count_shard(ShardStatus::Done, false);
        p.count_shard(ShardStatus::Split, false);
        p.count_shard(ShardStatus::Parked, false);
        assert_eq!((p.total, p.active, p.leased, p.done, p.split, p.parked),
                   (5, 2, 1, 1, 1, 1));
    }
    #[test] fn progress_predicates() {
        let s = RunProgress { total: 3, done: 2, split: 1, ..Default::default() };
        assert!(s.is_settled() && s.is_success() && !s.has_failures());
        let f = RunProgress { total: 3, done: 1, parked: 2, ..Default::default() };
        assert!(f.is_settled() && !f.is_success() && f.has_failures());
    }

    // —— evaluate_run_terminal ——
    #[test] fn eval_still_active() {
        assert_eq!(evaluate_run_terminal(&RunProgress { active: 1, ..Default::default() }),
                   RunTerminalEvaluation::StillActive);
    }
    #[test] fn eval_all_done() {
        assert_eq!(evaluate_run_terminal(&RunProgress { total: 3, done: 2, split: 1, ..Default::default() }),
                   RunTerminalEvaluation::AllDone);
    }
    #[test] fn eval_has_failures() {
        assert_eq!(evaluate_run_terminal(&RunProgress { total: 3, done: 1, parked: 2, ..Default::default() }),
                   RunTerminalEvaluation::HasFailures);
    }

    // —— validate_manifest ——
    #[test] fn manifest_ok() {
        assert!(validate_manifest(&[
            make_initial_shard(0, b"a", b"m"),
            make_initial_shard(1, b"m", b"z"),
        ]).is_ok());
    }
    #[test] fn manifest_ok_gaps() {
        assert!(validate_manifest(&[
            make_initial_shard(0, b"a", b"f"),
            make_initial_shard(1, b"m", b"z"),
        ]).is_ok());
    }
    #[test] fn manifest_ok_unordered() {
        assert!(validate_manifest(&[
            make_initial_shard(1, b"m", b"z"),
            make_initial_shard(0, b"a", b"m"),
        ]).is_ok());
    }
    #[test] fn manifest_empty() {
        assert_eq!(validate_manifest(&[]), Err(ManifestValidationError::Empty));
    }
    #[test] fn manifest_dup_id() {
        assert!(matches!(validate_manifest(&[
            make_initial_shard(0, b"a", b"m"),
            make_initial_shard(0, b"m", b"z"),
        ]), Err(ManifestValidationError::DuplicateId { .. })));
    }
    #[test] fn manifest_overlap() {
        assert!(matches!(validate_manifest(&[
            make_initial_shard(0, b"a", b"n"),
            make_initial_shard(1, b"m", b"z"),
        ]), Err(ManifestValidationError::OverlappingRanges { .. })));
    }
    #[test] fn manifest_inverted_spec() {
        assert!(matches!(validate_manifest(&[InitialShard {
            shard_id: ShardId(0),
            spec: ShardSpec::with_range(b"z".to_vec(), b"a".to_vec()),
            cursor: Cursor::initial(),
        }]), Err(ManifestValidationError::InvalidSpec { .. })));
    }
    #[test] fn manifest_single_ok() {
        assert!(validate_manifest(&[make_initial_shard(0, b"a", b"z")]).is_ok());
    }

    // —— ShardSummary ——
    #[test] fn summary_active_unleased() {
        let s = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active), LogicalTime(50));
        assert!(!s.is_leased);
        assert_eq!(s.acquire_count, 0);
    }
    #[test] fn summary_leased() {
        let r = ShardRecord {
            lease_owner: Some(WorkerId(1)),
            lease_deadline: Some(LogicalTime(100)),
            fence_epoch: FenceEpoch(4),
            cursor: Cursor::with_last_key(b"p".to_vec()),
            ..test_shard_record(0, ShardStatus::Active)
        };
        let s = ShardSummary::from_record(&r, LogicalTime(50));
        assert!(s.is_leased);
        assert_eq!(s.acquire_count, 3);
    }
    #[test] fn summary_parked() {
        let s = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Parked), LogicalTime(50));
        assert_eq!(s.park_reason, Some(ParkReason::Other));
    }

    // —— ShardFilter ——
    #[test] fn filter_all() {
        let s = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active), LogicalTime(50));
        assert!(ShardFilter::all().matches(&s));
    }
    #[test] fn filter_active() {
        let a = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active), LogicalTime(50));
        let d = ShardSummary::from_record(
            &test_shard_record(1, ShardStatus::Done), LogicalTime(50));
        assert!(ShardFilter::active().matches(&a));
        assert!(!ShardFilter::active().matches(&d));
    }
    #[test] fn filter_available() {
        let u = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active), LogicalTime(50));
        let lr = ShardRecord {
            lease_owner: Some(WorkerId(1)),
            lease_deadline: Some(LogicalTime(100)),
            ..test_shard_record(1, ShardStatus::Active)
        };
        let l = ShardSummary::from_record(&lr, LogicalTime(50));
        assert!(ShardFilter::available().matches(&u));
        assert!(!ShardFilter::available().matches(&l));
    }
    #[test] fn filter_root_only() {
        let root = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active), LogicalTime(50));
        let child_r = ShardRecord {
            parent: Some(ShardId(0)),
            ..test_shard_record(1, ShardStatus::Active)
        };
        let child = ShardSummary::from_record(&child_r, LogicalTime(50));
        let f = ShardFilter { root_only: true, ..ShardFilter::default() };
        assert!(f.matches(&root));
        assert!(!f.matches(&child));
    }

    // —— Payload hashes ——
    // TODO: test hash_register_shards_deterministic
    // TODO: test hash_register_shards_order_independent
    // TODO: test hash_complete_vs_fail_vs_cancel_different
    // TODO: test hash_unpark_different_shards_different

    // —— RunManagement integration tests (on InMemoryCoordinator) ——
    // TODO: test create_run_ok
    // TODO: test create_run_duplicate → Err(RunAlreadyExists)
    // TODO: test register_shards_ok → Active with shards
    // TODO: test register_shards_idempotent_replay
    // TODO: test register_shards_op_id_conflict
    // TODO: test register_shards_wrong_status
    // TODO: test register_shards_invalid_manifest
    // TODO: test create_run_with_shards_ok
    // TODO: test get_run_ok / get_run_not_found
    // TODO: test get_run_progress_active / mixed
    // TODO: test list_shards_all / filtered / ordered
    // TODO: test complete_run_ok / idempotent / wrong_status / terminal
    // TODO: test fail_run_ok / from_initializing
    // TODO: test cancel_run_ok / already_terminal
    // TODO: test unpark_shard_ok / not_parked / idempotent
    // TODO: test unpark_fence_monotonicity / cursor_preserved / lease_cleared
}
