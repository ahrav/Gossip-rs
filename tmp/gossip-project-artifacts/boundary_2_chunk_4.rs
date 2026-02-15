//! Boundary â‘¡ â€” Coordination & Shard Frontier: Chunk 4 (DRAFT)
//!
//! Run-level types, run management operations, admin operations, and
//! shard query/listing. This completes the coordination contract.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5) and Boundary â‘¡
//! chunks 1â€“3. It uses all types defined in prior chunks.
//!
//! ## Design Decisions (locked)
//!
//! D2.18: RunRecord is the coordinator's authoritative record for a run.
//!        It stores configuration (RunConfig) plus coordination metadata
//!        (status, creation time, total shard count, shard manifest).
//!
//!        ShardRecords are self-contained (D2.11) and carry no back-ref
//!        to RunRecord â€” but RunRecord tracks which shards belong to it
//!        for completeness verification (Â§5.3 of the scanner instructions).
//!
//!        Reference: Scan Completeness Verification â€” "maintain an expected
//!        work manifest" (Â§5.3 of distributed-secret-scanner-instructions).
//!
//! D2.19: RunStatus has 4 states: Initializing â†’ Active â†’ Done | Failed.
//!        Initializing is for atomic run+shard creation. A run moves to
//!        Active once all initial shards are registered. Done/Failed are
//!        terminal.
//!
//!        The coordinator determines Done vs Failed based on whether all
//!        shards reached Done (success) or any shard is Parked (failure).
//!
//! D2.20: Run creation is a two-phase operation:
//!        1. `create_run` â€” creates RunRecord in Initializing status.
//!        2. `register_shards` â€” atomically registers initial shards and
//!           transitions the run to Active.
//!
//!        This split allows the coordinator to validate the shard manifest
//!        (no gaps, no overlaps) before committing. Backends that support
//!        transactions may combine these into a single atomic operation.
//!
//!        Single-phase creation (create_run with shards inline) is also
//!        supported as a convenience. The two-phase API exists for backends
//!        with limited transaction scope.
//!
//! D2.21: Admin operations (unpark, cancel_run) are NOT lease-gated.
//!        They are out-of-band interventions by operators, not workers.
//!        They DO use OpId for idempotency and they DO bump the fence
//!        epoch where applicable (unpark).
//!
//!        Reference: Â§D2.6 â€” "Unparking is an out-of-band admin operation
//!        (new fence epoch, status reset to Active)."
//!
//! D2.22: Run-level operations form a separate trait (`RunManagement`)
//!        from shard-level operations (`CoordinationBackend`). This
//!        separation allows:
//!        - Different authorization models (admin vs worker)
//!        - Independent testing of run lifecycle vs shard lifecycle
//!        - Backends to implement one or both
//!
//!        The full coordination backend implements both traits.
//!
//! D2.23: `now: LogicalTime` is passed explicitly to every operation,
//!        consistent with D2.17.
//!
//! D2.24: Shard listing returns `ShardSummary` (lightweight) rather than
//!        full `ShardRecord`. Workers that need full records call
//!        `acquire_and_restore` which returns a `ShardSnapshot`.
//!        Listing is for observability/admin, not for worker use.

// Assumes all types from prior chunks are in scope:
// use crate::{
//     CanonicalBytes, Hasher, domain_hasher, finalize_64,
//     TenantId, RunId, ShardId, WorkerId, OpId, FenceEpoch,
//     LogicalTime, JobId, PolicyHash, ShardKey,
//     Cursor, ShardSpec, CursorSemantics,
//     ShardStatus, ParkReason, ShardRecord,
//     Lease, OpLogEntry, OpKind, OpResult,
//     CoordError, IdempotentOutcome,
// };

// ============================================================================
// Â§ Chunk 4: Run-Level Types, Management, and Admin Operations
// ============================================================================

// ---------------------------------------------------------------------------
// Â§4.1 RunStatus â€” run lifecycle state machine
// ---------------------------------------------------------------------------

/// Run lifecycle state.
///
/// ## State Machine
///
/// ```text
///  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///  â”‚ Initializing â”‚â”€â”€â”€â”€ register_shards â”€â”€â”€â”€â”
///  â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜                         â”‚
///         â”‚                                 â”‚
///         â”‚ (timeout / cancel)              â”‚
///         â–¼                                 â–¼
///    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”                      â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///    â”‚ Failed  â”‚                      â”‚  Active  â”‚
///    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                      â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜
///                                          â”‚
///                          â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///                          â”‚               â”‚               â”‚
///                  all shards Done    any shard Parked   cancel
///                          â”‚               â”‚               â”‚
///                          â–¼               â–¼               â–¼
///                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///                     â”‚  Done  â”‚     â”‚ Failed  â”‚     â”‚ Failed  â”‚
///                     â””â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// `Initializing` is transient â€” the run should quickly move to Active.
/// If shard registration fails or times out, the run moves to Failed.
///
/// ## Run completion semantics
///
/// A run's terminal status is determined by its shards:
/// - **Done**: All shards (including split children) reached `ShardStatus::Done`.
/// - **Failed**: At least one shard is `ShardStatus::Parked` and no
///   further progress is possible without admin intervention.
///
/// The coordinator does NOT automatically compute terminal status.
/// A separate `evaluate_run_status` helper is provided for callers
/// to check whether a run has reached a terminal state.
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted. Existing values MUST NOT be reused or reordered.
///
/// **Safety (terminal irreversibility)**: Once a run reaches Done or
/// Failed, no operation changes its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RunStatus {
    /// Shards are being registered. Not yet ready for workers.
    Initializing = 0,

    /// All initial shards registered. Workers may acquire shards.
    Active = 1,

    /// All shards (including split children) completed successfully.
    Done = 2,

    /// The run failed or was cancelled. At least one shard is Parked,
    /// or the run was explicitly cancelled by an admin.
    Failed = 3,
}

impl RunStatus {
    /// Returns `true` if this status is terminal.
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

// ---------------------------------------------------------------------------
// Â§4.2 RunConfig â€” per-run configuration (expanded)
// ---------------------------------------------------------------------------

/// Per-run configuration stored in coordination.
///
/// This is the immutable configuration for a scan run, set at creation
/// time and never modified. It determines how shards within the run
/// behave.
///
/// ## Fields
///
/// - `cursor_semantics`: How cursor advancement is interpreted (Completed
///   vs Dispatched). Copied into each ShardRecord at creation time (D2.11).
///
/// - `lease_duration`: How long a worker's lease lasts before requiring
///   renewal, in logical time units. Workers must renew before this
///   expires or lose ownership.
///
/// - `max_shard_retries`: Maximum number of times a shard can be
///   re-acquired (via fence epoch bumps) before it is auto-parked.
///   `None` means unlimited retries (operator must manually park).
///   The fence epoch tracks how many times a shard has been acquired;
///   when `fence_epoch - INITIAL >= max_shard_retries`, the coordinator
///   auto-parks with `ParkReason::TooManyErrors`.
///
/// ## Invariants
///
/// **Safety (immutable after creation)**: RunConfig is set at `create_run`
/// time and never modified. Changing it mid-run would invalidate shard
/// state (e.g., changing cursor_semantics on a shard with progress).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunConfig {
    /// How cursor advancement is interpreted.
    pub cursor_semantics: CursorSemantics,

    /// Lease duration in logical time units.
    ///
    /// Reference: Gray & Cheriton, "Leases" (SOSP 1989).
    pub lease_duration: u64,

    /// Maximum number of re-acquisitions before auto-parking.
    /// `None` = unlimited retries.
    pub max_shard_retries: Option<u32>,
}

impl RunConfig {
    /// Assert configuration invariants.
    ///
    /// Call at creation time to reject invalid configurations early.
    pub fn assert_valid(&self) {
        assert!(
            self.lease_duration > 0,
            "lease_duration must be positive"
        );
    }
}

// ---------------------------------------------------------------------------
// Â§4.3 RunRecord â€” full coordination state for a run
// ---------------------------------------------------------------------------

/// The complete coordination state for a scan run.
///
/// This is the coordinator's authoritative record for a run. It tracks:
/// - Configuration (immutable after creation)
/// - Lifecycle status
/// - Shard manifest (the set of root shard IDs registered at creation)
/// - Creation and completion timestamps
///
/// ## Shard Manifest vs Live Shards
///
/// `root_shards` contains the shard IDs registered at creation time
/// (or via `register_shards`). It does NOT include dynamically created
/// split children â€” those are tracked via the ShardRecord lineage
/// (`parent`, `spawned`). To enumerate all shards for a run (including
/// children), the coordinator walks the lineage tree starting from
/// `root_shards`.
///
/// This design avoids unbounded growth of the RunRecord when shards
/// split repeatedly. The manifest is the "expected work" list for
/// completeness verification (Â§5.3).
///
/// ## Invariants (checked by `assert_invariants`)
///
/// **Safety (config immutable)**: Verified by the coordinator â€” not
/// structurally enforced in the record.
///
/// **Safety (terminal irreversible)**: Once `status` is Done or Failed,
/// it never changes.
///
/// **Safety (shards non-empty when active)**: If `status == Active`,
/// `root_shards` must be non-empty.
///
/// **Safety (completed_at consistency)**: `completed_at.is_some()` iff
/// `status.is_terminal()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRecord {
    // -- Identity --
    pub tenant: TenantId,
    pub run: RunId,

    // -- Configuration --
    pub config: RunConfig,

    // -- Lifecycle --
    pub status: RunStatus,

    // -- Timestamps --
    /// Logical time when the run was created.
    pub created_at: LogicalTime,
    /// Logical time when the run reached a terminal state.
    /// `None` while the run is active.
    pub completed_at: Option<LogicalTime>,

    // -- Shard manifest --
    /// Root shard IDs registered at creation. Does not include
    /// dynamically created split children.
    pub root_shards: Vec<ShardId>,
}

impl RunRecord {
    /// Assert structural invariants.
    ///
    /// Call after every state transition, before persisting.
    pub fn assert_invariants(&self) {
        // Active runs must have shards.
        if self.status == RunStatus::Active {
            assert!(
                !self.root_shards.is_empty(),
                "Active run {:?} must have at least one root shard",
                self.run,
            );
        }

        // completed_at consistency.
        assert_eq!(
            self.completed_at.is_some(),
            self.status.is_terminal(),
            "Run {:?}: completed_at must be Some iff status is terminal (status: {:?})",
            self.run,
            self.status,
        );
    }
}

// ---------------------------------------------------------------------------
// Â§4.4 ShardSummary â€” lightweight shard view for listing/observability
// ---------------------------------------------------------------------------

/// Lightweight shard summary for listing and observability.
///
/// Contains enough information to display run progress without loading
/// full ShardRecords (which include op_logs and full cursor/spec data).
///
/// Workers do not use this â€” they get full state via `acquire_and_restore`.
/// This is for admin dashboards, progress bars, and status queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSummary {
    pub shard: ShardId,
    pub status: ShardStatus,
    pub park_reason: Option<ParkReason>,

    /// Whether the shard currently has an active lease.
    /// Does not expose the worker ID or deadline (privacy/security).
    pub is_leased: bool,

    /// Number of ownership transfers (fence epoch - INITIAL).
    /// Useful for detecting "hot" shards that keep failing.
    pub acquire_count: u64,

    /// The last_key from the cursor, if any.
    /// For progress display. Does not expose the full cursor or token.
    pub last_key: Option<Box<[u8]>>,

    /// Key range boundaries for progress calculation.
    pub key_range_start: Box<[u8]>,
    pub key_range_end: Box<[u8]>,

    /// Parent shard ID, if this shard was created by a split.
    pub parent: Option<ShardId>,

    /// Number of child/residual shards spawned.
    pub spawned_count: usize,
}

impl ShardSummary {
    /// Create a summary from a full ShardRecord.
    ///
    /// This is the canonical way to produce summaries â€” ensures the
    /// mapping is consistent across backends.
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

// ---------------------------------------------------------------------------
// Â§4.5 RunProgress â€” aggregated progress metrics
// ---------------------------------------------------------------------------

/// Aggregated progress metrics for a run.
///
/// Computed by scanning all shards (root + children) for a run and
/// counting by status. This is a point-in-time snapshot, not a live view.
///
/// ## Completeness Check
///
/// A run is complete when `active == 0` and `initializing == 0`.
/// It succeeded if `parked == 0` (all shards Done or Split).
/// It failed if `parked > 0`.
///
/// Note: Split shards are "done" from the parent's perspective â€” their
/// children continue the work. A Split shard with all children Done
/// is effectively Done.
///
/// Reference: Â§5.3 â€” Scan Completeness Verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunProgress {
    /// Total number of shards (root + children).
    pub total: u64,

    /// Shards in Active status (including unleased ones awaiting workers).
    pub active: u64,

    /// Shards that completed successfully.
    pub done: u64,

    /// Shards that were replaced by children.
    pub split: u64,

    /// Shards that are parked (require intervention).
    pub parked: u64,

    /// Number of active shards that currently hold a lease
    /// (actively being processed by a worker).
    pub leased: u64,
}

impl RunProgress {
    /// Returns `true` if all work is in a terminal state.
    ///
    /// This means no shards are Active â€” they've all reached Done,
    /// Split, or Parked.
    #[inline]
    pub fn is_settled(&self) -> bool {
        self.active == 0
    }

    /// Returns `true` if the run completed successfully.
    ///
    /// All shards reached Done or Split, and none are Parked.
    #[inline]
    pub fn is_success(&self) -> bool {
        self.is_settled() && self.parked == 0
    }

    /// Returns `true` if any shard is parked.
    #[inline]
    pub fn has_failures(&self) -> bool {
        self.parked > 0
    }

    /// Accumulate a shard's status into this progress.
    pub fn count_shard(&mut self, status: ShardStatus, is_leased: bool) {
        self.total += 1;
        match status {
            ShardStatus::Active => {
                self.active += 1;
                if is_leased {
                    self.leased += 1;
                }
            }
            ShardStatus::Done => self.done += 1,
            ShardStatus::Split => self.split += 1,
            ShardStatus::Parked => self.parked += 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Â§4.6 Evaluate run terminal status
// ---------------------------------------------------------------------------

/// The evaluated terminal condition of a run.
///
/// Used by the coordinator to decide whether to transition the run
/// to Done or Failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunTerminalEvaluation {
    /// Some shards are still Active â€” the run is not yet settled.
    StillActive,
    /// All shards reached Done or Split. The run succeeded.
    AllDone,
    /// No active shards remain, but some are Parked. The run failed.
    HasFailures,
}

/// Evaluate whether a run should transition to a terminal state.
///
/// This is a pure function of `RunProgress`. The coordinator calls
/// this after shard state transitions (complete, park) to check
/// if the run as a whole has settled.
///
/// ## Usage
///
/// ```text
/// let progress = backend.get_run_progress(now, tenant, run_id)?;
/// match evaluate_run_terminal(&progress) {
///     RunTerminalEvaluation::StillActive => { /* nothing to do */ }
///     RunTerminalEvaluation::AllDone => {
///         backend.complete_run(now, tenant, run_id, op_id)?;
///     }
///     RunTerminalEvaluation::HasFailures => {
///         backend.fail_run(now, tenant, run_id, op_id)?;
///     }
/// }
/// ```
///
/// ## Why not automatic?
///
/// Run terminal evaluation is separated from shard operations because:
/// 1. It requires scanning all shards â€” expensive to do on every
///    checkpoint. Better done periodically or on terminal shard events.
/// 2. It's a policy decision â€” some deployments may want to keep runs
///    "Active" even with parked shards (to allow unparking).
/// 3. It keeps the shard-level operations simple and predictable.
pub fn evaluate_run_terminal(progress: &RunProgress) -> RunTerminalEvaluation {
    if progress.active > 0 {
        RunTerminalEvaluation::StillActive
    } else if progress.parked > 0 {
        RunTerminalEvaluation::HasFailures
    } else {
        RunTerminalEvaluation::AllDone
    }
}

// ---------------------------------------------------------------------------
// Â§4.7 Initial shard registration types
// ---------------------------------------------------------------------------

/// A shard to be registered as part of run initialization.
///
/// Contains the spec (key range + metadata) and an initial cursor
/// (typically `Cursor::initial()`). The coordinator assigns a ShardId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialShard {
    /// Shard ID. For root shards, these are small sequential integers
    /// (0, 1, 2, ...) assigned by the caller. The coordinator validates
    /// uniqueness.
    pub shard_id: ShardId,

    /// The shard's key range and connector metadata.
    pub spec: ShardSpec,

    /// Initial cursor (usually `Cursor::initial()`).
    /// A non-initial cursor is valid for resuming a partially-completed
    /// shard from a prior run.
    pub cursor: Cursor,
}

/// Validation result for a set of initial shards.
///
/// The coordinator validates the manifest before registering shards
/// to catch configuration errors early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestValidationError {
    /// No shards in the manifest.
    Empty,

    /// Duplicate shard IDs in the manifest.
    DuplicateId { shard_id: ShardId },

    /// Two shards have overlapping key ranges.
    OverlappingRanges {
        shard_a: ShardId,
        shard_b: ShardId,
        overlap_start: Box<[u8]>,
    },

    /// A shard has an invalid spec (e.g., start >= end).
    InvalidSpec {
        shard_id: ShardId,
        reason: String,
    },
}

/// Validate a manifest of initial shards.
///
/// Checks:
/// 1. Non-empty.
/// 2. No duplicate shard IDs.
/// 3. No overlapping key ranges.
/// 4. Each spec is internally valid (start < end).
///
/// Does NOT require shards to cover the entire keyspace â€” gaps are
/// allowed (some key ranges may be intentionally excluded from scanning).
///
/// ## Sorting
///
/// Shards are validated in key_range_start order. The caller may
/// provide them in any order; this function sorts internally.
pub fn validate_manifest(shards: &[InitialShard]) -> Result<(), ManifestValidationError> {
    if shards.is_empty() {
        return Err(ManifestValidationError::Empty);
    }

    // Check for duplicate IDs.
    let mut ids: Vec<ShardId> = shards.iter().map(|s| s.shard_id).collect();
    ids.sort_by_key(|id| id.0);
    for window in ids.windows(2) {
        if window[0] == window[1] {
            return Err(ManifestValidationError::DuplicateId {
                shard_id: window[0],
            });
        }
    }

    // Check each spec is valid.
    for shard in shards {
        if shard.spec.key_range_start >= shard.spec.key_range_end {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard_id,
                reason: "key_range_start must be strictly less than key_range_end".into(),
            });
        }
    }

    // Sort by key range start to check for overlaps.
    let mut sorted: Vec<&InitialShard> = shards.iter().collect();
    sorted.sort_by(|a, b| a.spec.key_range_start.cmp(&b.spec.key_range_start));

    for window in sorted.windows(2) {
        let a = window[0];
        let b = window[1];
        // Half-open intervals: a covers [a.start, a.end), b covers [b.start, b.end).
        // Overlap iff a.end > b.start.
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

// ---------------------------------------------------------------------------
// Â§4.8 Run-level error types
// ---------------------------------------------------------------------------

/// Error from `create_run`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateRunError {
    /// A run with this RunId already exists for this tenant.
    RunAlreadyExists { run: RunId },

    /// Tenant isolation violation.
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },

    /// The RunConfig is invalid (e.g., zero lease_duration).
    InvalidConfig { reason: String },
}

/// Error from `register_shards`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterShardsError {
    /// The run does not exist.
    RunNotFound { run: RunId },

    /// Tenant isolation violation.
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },

    /// The run is not in Initializing status.
    WrongStatus {
        expected: RunStatus,
        actual: RunStatus,
    },

    /// The shard manifest failed validation.
    ManifestInvalid(ManifestValidationError),

    /// Idempotency conflict.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

/// Error from `get_run`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetRunError {
    RunNotFound { run: RunId },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
}

/// Error from `complete_run` / `fail_run`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompleteRunError {
    RunNotFound { run: RunId },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    /// The run is already in a terminal state.
    RunTerminal { run: RunId, status: RunStatus },
    /// The run is still Initializing â€” cannot complete.
    WrongStatus {
        expected: RunStatus,
        actual: RunStatus,
    },
    /// OpId conflict.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

/// Error from `unpark_shard`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnparkError {
    ShardNotFound { shard: ShardKey },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    /// The shard is not Parked â€” cannot unpark.
    NotParked {
        shard: ShardKey,
        status: ShardStatus,
    },
    /// OpId conflict.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

/// Error from `cancel_run`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelRunError {
    RunNotFound { run: RunId },
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    /// The run is already terminal.
    RunTerminal { run: RunId, status: RunStatus },
    /// OpId conflict.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

// ---------------------------------------------------------------------------
// Â§4.9 Shard listing filter
// ---------------------------------------------------------------------------

/// Filter criteria for listing shards within a run.
///
/// All filters are conjunctive (AND). `None` means "no filter" for
/// that field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardFilter {
    /// Filter by shard status.
    pub status: Option<ShardStatus>,

    /// Filter by whether the shard is currently leased.
    pub is_leased: Option<bool>,

    /// Filter by parent shard ID (find children of a specific shard).
    pub parent: Option<ShardId>,

    /// Only include root shards (no parent).
    pub root_only: bool,
}

impl ShardFilter {
    /// No filtering â€” return all shards.
    pub fn all() -> Self {
        Self::default()
    }

    /// Filter to only active shards.
    pub fn active() -> Self {
        Self {
            status: Some(ShardStatus::Active),
            ..Self::default()
        }
    }

    /// Filter to only parked shards.
    pub fn parked() -> Self {
        Self {
            status: Some(ShardStatus::Parked),
            ..Self::default()
        }
    }

    /// Filter to active, unleased shards (available for acquisition).
    pub fn available() -> Self {
        Self {
            status: Some(ShardStatus::Active),
            is_leased: Some(false),
            ..Self::default()
        }
    }

    /// Test whether a shard summary matches this filter.
    pub fn matches(&self, summary: &ShardSummary) -> bool {
        if let Some(status) = self.status {
            if summary.status != status {
                return false;
            }
        }
        if let Some(leased) = self.is_leased {
            if summary.is_leased != leased {
                return false;
            }
        }
        if let Some(parent) = self.parent {
            if summary.parent != Some(parent) {
                return false;
            }
        }
        if self.root_only && summary.parent.is_some() {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Â§4.10 Run Management Trait
// ---------------------------------------------------------------------------

/// Run-level management operations.
///
/// Separated from `CoordinationBackend` (chunk 3) because:
/// - Different authorization model (admin/scheduler vs worker)
/// - Run operations are infrequent and non-performance-critical
/// - Independent testability
///
/// ## Design Principles
///
/// Same as CoordinationBackend (D2.13, D2.17, D2.23):
/// - Synchronous API
/// - `now: LogicalTime` as explicit input
/// - Tenant isolation on every call
///
/// ## Invariants
///
/// **Safety (tenant isolation)**: All operations validate that
/// `request.tenant == record.tenant`.
///
/// **Safety (run terminal irreversibility)**: Once a run reaches
/// Done or Failed, no operation changes its status.
///
/// **Safety (shard creation atomicity)**: `register_shards` creates
/// all shard records atomically with the run status transition to
/// Active. If any shard creation fails, none are created and the
/// run stays in Initializing.
pub trait RunManagement {
    // â”€â”€ Run lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Create a new run in Initializing status.
    ///
    /// ## Behavior
    ///
    /// 1. Validate `config` (lease_duration > 0).
    /// 2. Reject if a run with this RunId already exists for this tenant.
    /// 3. Create RunRecord with `status = Initializing`, empty `root_shards`.
    /// 4. Return the created record.
    ///
    /// ## Idempotency
    ///
    /// NOT idempotent â€” creating the same run twice is an error.
    /// Use `get_run` to check existence before creating.
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError>;

    /// Register initial shards and activate the run.
    ///
    /// Atomically:
    /// 1. Validate the shard manifest (no duplicates, no overlaps, valid specs).
    /// 2. Create ShardRecords for each shard (Active, initial cursor,
    ///    cursor_semantics from RunConfig).
    /// 3. Transition run status from Initializing â†’ Active.
    /// 4. Store root shard IDs in the RunRecord.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id`. On replay, returns the same shard IDs.
    ///
    /// ## Preconditions
    ///
    /// - Run must be in Initializing status.
    /// - Manifest must be valid (validated via `validate_manifest`).
    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: Vec<InitialShard>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError>;

    /// Convenience: create a run and register shards in one call.
    ///
    /// Equivalent to `create_run` + `register_shards`, but may be
    /// implemented more efficiently by backends that support transactions.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` (covers the register_shards portion).
    /// If the run already exists and is Active with matching shards,
    /// this is treated as a replay.
    fn create_run_with_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
        shards: Vec<InitialShard>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<RunRecord>, CreateRunError> {
        // Default implementation: two-phase.
        // Backends may override with a single-transaction implementation.

        // Phase 1: Create the run.
        let record = self.create_run(now, tenant, run, config)?;

        // Phase 2: Register shards.
        match self.register_shards(now, tenant, run, shards, op_id) {
            Ok(outcome) => {
                // Re-fetch the now-Active record.
                // (In a real implementation, this would be part of the
                // atomic transaction. The default impl is best-effort.)
                Ok(outcome.map(|_shard_ids| {
                    RunRecord {
                        status: RunStatus::Active,
                        ..record
                    }
                }))
            }
            Err(RegisterShardsError::OpIdConflict {
                op_id,
                expected_hash,
                actual_hash,
            }) => Err(CreateRunError::InvalidConfig {
                reason: format!(
                    "OpId conflict during shard registration: \
                     op_id={op_id:?}, expected_hash={expected_hash}, \
                     actual_hash={actual_hash}"
                ),
            }),
            Err(e) => Err(CreateRunError::InvalidConfig {
                reason: format!("shard registration failed: {e:?}"),
            }),
        }
    }

    // â”€â”€ Run queries â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Get the RunRecord for a run.
    fn get_run(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunRecord, GetRunError>;

    /// Get aggregated progress metrics for a run.
    ///
    /// Scans all shards (root + children) and counts by status.
    /// This is potentially expensive for runs with many shards.
    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError>;

    /// List shards for a run, optionally filtered.
    ///
    /// Returns lightweight `ShardSummary` values. For full shard state,
    /// workers use `acquire_and_restore`.
    ///
    /// Results are ordered by shard key_range_start (lexicographic).
    fn list_shards(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
    ) -> Result<Vec<ShardSummary>, GetRunError>;

    // â”€â”€ Run terminal transitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Mark a run as successfully completed (Done).
    ///
    /// ## Preconditions
    ///
    /// - Run must be Active.
    /// - Caller should verify all shards are terminal via
    ///   `evaluate_run_terminal` before calling.
    ///
    /// ## Behavior
    ///
    /// 1. Verify run is Active.
    /// 2. Set `status = Done`, `completed_at = now`.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id`.
    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError>;

    /// Mark a run as failed.
    ///
    /// ## Preconditions
    ///
    /// - Run must be Active (or Initializing for timeout failures).
    ///
    /// ## Behavior
    ///
    /// 1. Verify run is non-terminal.
    /// 2. Set `status = Failed`, `completed_at = now`.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id`.
    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError>;

    // â”€â”€ Admin operations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Cancel an active run.
    ///
    /// Sets the run status to Failed. Does NOT automatically park active
    /// shards â€” workers will discover the cancellation on their next
    /// renew/checkpoint and should self-park.
    ///
    /// ## Behavior
    ///
    /// 1. Verify run is non-terminal.
    /// 2. Set `status = Failed`, `completed_at = now`.
    ///
    /// This is semantically identical to `fail_run` but exists as a
    /// separate method for clarity of intent and potentially different
    /// authorization requirements.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id`.
    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CancelRunError>;

    /// Unpark a parked shard, resetting it to Active.
    ///
    /// This is an admin-only operation, NOT lease-gated. The admin is
    /// asserting that the underlying issue has been resolved and the
    /// shard should be retried.
    ///
    /// ## Behavior
    ///
    /// 1. Look up the shard by `(tenant, key)`.
    /// 2. Verify it is Parked.
    /// 3. Increment `fence_epoch` (invalidates any zombie leases).
    /// 4. Reset `status = Active`, `park_reason = None`.
    /// 5. Clear `lease_owner`, `lease_deadline` (shard is now available).
    /// 6. Do NOT reset cursor â€” the shard resumes from where it was
    ///    last checkpointed.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id`. Replay returns success without mutation.
    ///
    /// ## Invariants
    ///
    /// **Safety (fence monotonicity)**: `fence_epoch` increases on unpark.
    /// **Safety (cursor preserved)**: Cursor is not reset â€” progress is
    /// retained.
    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError>;
}

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ Test fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }
    fn test_run() -> RunId {
        RunId {
            job: JobId(1),
            policy: PolicyHash::from_bytes([0xAA; 32]),
        }
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
            } else {
                None
            },
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

    // â”€â”€ RunStatus â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn run_status_terminal() {
        assert!(!RunStatus::Initializing.is_terminal());
        assert!(!RunStatus::Active.is_terminal());
        assert!(RunStatus::Done.is_terminal());
        assert!(RunStatus::Failed.is_terminal());
    }

    #[test]
    fn run_status_roundtrip() {
        for v in 0..=3u8 {
            assert!(RunStatus::from_u8(v).is_some());
        }
        assert_eq!(RunStatus::from_u8(4), None);
    }

    #[test]
    fn run_status_discriminants_stable() {
        assert_eq!(RunStatus::Initializing.as_u8(), 0);
        assert_eq!(RunStatus::Active.as_u8(), 1);
        assert_eq!(RunStatus::Done.as_u8(), 2);
        assert_eq!(RunStatus::Failed.as_u8(), 3);
    }

    // â”€â”€ RunConfig â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn run_config_assert_valid_ok() {
        test_config().assert_valid(); // should not panic
    }

    #[test]
    #[should_panic(expected = "lease_duration must be positive")]
    fn run_config_assert_valid_zero_lease() {
        let config = RunConfig {
            lease_duration: 0,
            ..test_config()
        };
        config.assert_valid();
    }

    // â”€â”€ RunRecord invariants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn run_record_assert_invariants_active_ok() {
        test_run_record().assert_invariants();
    }

    #[test]
    fn run_record_assert_invariants_done_ok() {
        let record = RunRecord {
            status: RunStatus::Done,
            completed_at: Some(LogicalTime(100)),
            ..test_run_record()
        };
        record.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "completed_at must be Some iff status is terminal")]
    fn run_record_assert_invariants_done_without_completed_at() {
        let record = RunRecord {
            status: RunStatus::Done,
            completed_at: None,
            ..test_run_record()
        };
        record.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "completed_at must be Some iff status is terminal")]
    fn run_record_assert_invariants_active_with_completed_at() {
        let record = RunRecord {
            completed_at: Some(LogicalTime(100)),
            ..test_run_record()
        };
        record.assert_invariants();
    }

    #[test]
    #[should_panic(expected = "must have at least one root shard")]
    fn run_record_assert_invariants_active_no_shards() {
        let record = RunRecord {
            root_shards: vec![],
            ..test_run_record()
        };
        record.assert_invariants();
    }

    #[test]
    fn run_record_initializing_empty_shards_ok() {
        // Initializing runs may have empty root_shards.
        let record = RunRecord {
            status: RunStatus::Initializing,
            root_shards: vec![],
            ..test_run_record()
        };
        record.assert_invariants();
    }

    // â”€â”€ RunProgress â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn run_progress_count_shard() {
        let mut p = RunProgress::default();
        p.count_shard(ShardStatus::Active, true);
        p.count_shard(ShardStatus::Active, false);
        p.count_shard(ShardStatus::Done, false);
        p.count_shard(ShardStatus::Split, false);
        p.count_shard(ShardStatus::Parked, false);

        assert_eq!(p.total, 5);
        assert_eq!(p.active, 2);
        assert_eq!(p.leased, 1);
        assert_eq!(p.done, 1);
        assert_eq!(p.split, 1);
        assert_eq!(p.parked, 1);
    }

    #[test]
    fn run_progress_is_settled() {
        let settled = RunProgress {
            total: 3,
            active: 0,
            done: 2,
            split: 1,
            parked: 0,
            leased: 0,
        };
        assert!(settled.is_settled());
        assert!(settled.is_success());
        assert!(!settled.has_failures());

        let not_settled = RunProgress {
            active: 1,
            ..settled
        };
        assert!(!not_settled.is_settled());
    }

    #[test]
    fn run_progress_has_failures() {
        let failed = RunProgress {
            total: 3,
            active: 0,
            done: 1,
            split: 0,
            parked: 2,
            leased: 0,
        };
        assert!(failed.is_settled());
        assert!(!failed.is_success());
        assert!(failed.has_failures());
    }

    // â”€â”€ evaluate_run_terminal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn evaluate_still_active() {
        let p = RunProgress { active: 1, ..Default::default() };
        assert_eq!(evaluate_run_terminal(&p), RunTerminalEvaluation::StillActive);
    }

    #[test]
    fn evaluate_all_done() {
        let p = RunProgress {
            total: 3,
            done: 2,
            split: 1,
            ..Default::default()
        };
        assert_eq!(evaluate_run_terminal(&p), RunTerminalEvaluation::AllDone);
    }

    #[test]
    fn evaluate_has_failures() {
        let p = RunProgress {
            total: 3,
            done: 1,
            parked: 2,
            ..Default::default()
        };
        assert_eq!(evaluate_run_terminal(&p), RunTerminalEvaluation::HasFailures);
    }

    // â”€â”€ validate_manifest â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn validate_manifest_ok() {
        let shards = vec![
            make_initial_shard(0, b"a", b"m"),
            make_initial_shard(1, b"m", b"z"),
        ];
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn validate_manifest_ok_with_gaps() {
        // Gaps are allowed â€” some key ranges may be excluded.
        let shards = vec![
            make_initial_shard(0, b"a", b"f"),
            make_initial_shard(1, b"m", b"z"),
        ];
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn validate_manifest_ok_unordered_input() {
        // Shards provided out of order â€” should still pass.
        let shards = vec![
            make_initial_shard(1, b"m", b"z"),
            make_initial_shard(0, b"a", b"m"),
        ];
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn validate_manifest_empty() {
        assert_eq!(
            validate_manifest(&[]),
            Err(ManifestValidationError::Empty),
        );
    }

    #[test]
    fn validate_manifest_duplicate_id() {
        let shards = vec![
            make_initial_shard(0, b"a", b"m"),
            make_initial_shard(0, b"m", b"z"),
        ];
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::DuplicateId { .. }),
        ));
    }

    #[test]
    fn validate_manifest_overlap() {
        let shards = vec![
            make_initial_shard(0, b"a", b"n"),
            make_initial_shard(1, b"m", b"z"),
        ];
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::OverlappingRanges { .. }),
        ));
    }

    #[test]
    fn validate_manifest_invalid_spec() {
        let shards = vec![InitialShard {
            shard_id: ShardId(0),
            spec: ShardSpec::with_range(b"z".to_vec(), b"a".to_vec()),
            cursor: Cursor::initial(),
        }];
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::InvalidSpec { .. }),
        ));
    }

    #[test]
    fn validate_manifest_single_shard_ok() {
        let shards = vec![make_initial_shard(0, b"a", b"z")];
        assert!(validate_manifest(&shards).is_ok());
    }

    // â”€â”€ ShardSummary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn shard_summary_from_active_unleased() {
        let record = test_shard_record(0, ShardStatus::Active);
        let summary = ShardSummary::from_record(&record, LogicalTime(50));

        assert_eq!(summary.shard, ShardId(0));
        assert_eq!(summary.status, ShardStatus::Active);
        assert!(!summary.is_leased);
        assert_eq!(summary.acquire_count, 0);
        assert_eq!(summary.last_key, None);
        assert_eq!(summary.parent, None);
        assert_eq!(summary.spawned_count, 0);
    }

    #[test]
    fn shard_summary_from_leased() {
        let record = ShardRecord {
            lease_owner: Some(WorkerId(1)),
            lease_deadline: Some(LogicalTime(100)),
            fence_epoch: FenceEpoch(4), // acquired 3 times (4 - 1)
            cursor: Cursor::with_last_key(b"progress".to_vec()),
            ..test_shard_record(0, ShardStatus::Active)
        };
        let summary = ShardSummary::from_record(&record, LogicalTime(50));

        assert!(summary.is_leased);
        assert_eq!(summary.acquire_count, 3);
        assert_eq!(summary.last_key.as_deref(), Some(b"progress".as_slice()));
    }

    #[test]
    fn shard_summary_from_parked() {
        let record = test_shard_record(0, ShardStatus::Parked);
        let summary = ShardSummary::from_record(&record, LogicalTime(50));

        assert_eq!(summary.status, ShardStatus::Parked);
        assert_eq!(summary.park_reason, Some(ParkReason::Other));
        assert!(!summary.is_leased);
    }

    // â”€â”€ ShardFilter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn shard_filter_all_matches_everything() {
        let record = test_shard_record(0, ShardStatus::Active);
        let summary = ShardSummary::from_record(&record, LogicalTime(50));
        assert!(ShardFilter::all().matches(&summary));
    }

    #[test]
    fn shard_filter_active_matches_active() {
        let active = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active),
            LogicalTime(50),
        );
        let done = ShardSummary::from_record(
            &test_shard_record(1, ShardStatus::Done),
            LogicalTime(50),
        );
        assert!(ShardFilter::active().matches(&active));
        assert!(!ShardFilter::active().matches(&done));
    }

    #[test]
    fn shard_filter_available() {
        let unleased = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active),
            LogicalTime(50),
        );
        let leased_record = ShardRecord {
            lease_owner: Some(WorkerId(1)),
            lease_deadline: Some(LogicalTime(100)),
            ..test_shard_record(1, ShardStatus::Active)
        };
        let leased = ShardSummary::from_record(&leased_record, LogicalTime(50));

        assert!(ShardFilter::available().matches(&unleased));
        assert!(!ShardFilter::available().matches(&leased));
    }

    #[test]
    fn shard_filter_root_only() {
        let root = ShardSummary::from_record(
            &test_shard_record(0, ShardStatus::Active),
            LogicalTime(50),
        );
        let child_record = ShardRecord {
            parent: Some(ShardId(0)),
            ..test_shard_record(1, ShardStatus::Active)
        };
        let child = ShardSummary::from_record(&child_record, LogicalTime(50));

        let filter = ShardFilter {
            root_only: true,
            ..ShardFilter::default()
        };
        assert!(filter.matches(&root));
        assert!(!filter.matches(&child));
    }

    #[test]
    fn shard_filter_by_parent() {
        let child_record = ShardRecord {
            parent: Some(ShardId(42)),
            ..test_shard_record(1, ShardStatus::Active)
        };
        let child = ShardSummary::from_record(&child_record, LogicalTime(50));

        let filter = ShardFilter {
            parent: Some(ShardId(42)),
            ..ShardFilter::default()
        };
        assert!(filter.matches(&child));

        let wrong_parent = ShardFilter {
            parent: Some(ShardId(99)),
            ..ShardFilter::default()
        };
        assert!(!wrong_parent.matches(&child));
    }
}
