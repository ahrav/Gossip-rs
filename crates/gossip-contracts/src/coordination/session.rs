//! Ergonomic `WorkerSession` wrapper for shard operations.
//!
//! Most [`CoordinationBackend`] methods require `(now, tenant, lease, ...)`
//! parameters (`acquire_and_restore_into` takes `key` and `worker` instead, since
//! no lease exists yet). `WorkerSession` captures these at acquisition time
//! and threads them through every subsequent call, eliminating repetitive
//! boilerplate and preventing tenant/lease mismatches across operations on
//! the same shard.
//!
//! ## Typical Usage
//!
//! ```text
//! // 1. Acquire a shard and create a session.
//! let mut session = WorkerSession::new(&mut backend, now, tenant, key, worker)?;
//!
//! // 2. Read the initial snapshot to find where to resume.
//! let resume_cursor = session.cursor();
//! let spec = session.spec();
//!
//! // 3. Process items, periodically checkpointing progress.
//! loop {
//!     let items = scan_next_batch(spec, resume_cursor);
//!     if items.is_empty() { break; }
//!     process(&items);
//!     session.checkpoint(now, new_cursor, op_id)?;
//!     session.renew(now)?; // extend lease before deadline
//! }
//!
//! // 4. Terminal operation consumes the session.
//! session.complete(now, final_cursor, op_id)?;
//! // session is moved — compile error to use it again.
//! ```
//!
//! ## Design
//!
//! - **Generic over backend** — monomorphized per-backend; no trait object
//!   overhead on the hot path.
//! - **Exclusive borrow** (`&'b mut B`) — the Rust borrow checker enforces
//!   at most one session per backend reference, preventing interleaved
//!   mutations to different shards through the same backend handle.
//! - **No automatic lease renewal** — the worker is responsible for calling
//!   [`WorkerSession::renew`] before the deadline expires. Automatic renewal
//!   requires a timer or scheduler, which is a runtime concern outside the
//!   coordination contract layer.
//! - **Move semantics for terminal ops** — [`complete`](WorkerSession::complete),
//!   [`park`](WorkerSession::park), and [`split_replace`](WorkerSession::split_replace)
//!   consume `self`, making it a compile-time error to use the session after a
//!   terminal state transition.
//! - **Borrow semantics for non-terminal ops** —
//!   [`split_residual`](WorkerSession::split_residual) takes `&mut self`
//!   because the parent shard stays Active with a narrowed key range.
//! - **Error transparency** — all errors from the underlying
//!   [`CoordinationBackend`] are returned directly. The session adds no
//!   error variants of its own and performs no error translation. This means
//!   callers handle the same error types they would with the raw trait,
//!   just without the boilerplate of threading `(tenant, lease)` parameters.
//!
//! ## Lifetime `'b`
//!
//! The `&'b mut B` borrow means only one session per backend reference
//! at a time. This is intentionally restrictive and correct for
//! deterministic simulation (single-threaded, one shard at a time).
//! Production multi-shard workers use the raw [`CoordinationBackend`]
//! trait directly or scope sessions to short-lived blocks.
//!
//! Reference: FoundationDB simulation approach (synchronous, deterministic).
//!
//! ## Snapshot Staleness
//!
//! The session stores snapshot bytes in [`AcquireScratch`] and exposes them
//! through borrowed view accessors. The snapshot reflects shard state at
//! acquisition time. It is **not** updated by
//! [`checkpoint`](WorkerSession::checkpoint) because the worker already knows
//! the cursor it just wrote, and the backend validates cursor monotonicity
//! and bounds against the authoritative [`ShardRecord`](super::record::ShardRecord),
//! not the session's borrowed view. Updating snapshot state on every checkpoint
//! would add unnecessary work for no correctness benefit.
//! Similarly, [`renew`](WorkerSession::renew) updates the lease
//! deadline (via `Lease::set_deadline`) and the capacity hint, but
//! not the snapshot.
//!
//! The snapshot state **is** refreshed by
//! [`split_residual`](WorkerSession::split_residual) because the key range
//! narrows, and subsequent [`checkpoint`](WorkerSession::checkpoint) calls
//! must not present cursors outside the narrowed range. While the backend
//! would reject such cursors regardless, keeping the session view consistent
//! avoids confusing the worker's own bounds logic.

use gossip_stdx::InlineVec;

use crate::coordination::cursor::CursorUpdate;
use crate::coordination::error::{
    AcquireError, AcquireScratch, CapacityHint, CheckpointError, CompleteError, IdempotentOutcome,
    ParkError, RenewError, RenewResult, ShardSnapshotView, SplitReplaceError, SplitResidualError,
};
use crate::coordination::lease::Lease;
use crate::coordination::record::{ParkReason, ShardStatus};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec, ShardSpecRef};
use crate::coordination::split::{
    MAX_SPAWNED_PER_SHARD, SplitReplacePlan, SplitReplaceResult, SplitResidualPlan,
    SplitResidualResult,
};
use crate::coordination::traits::CoordinationBackend;
use crate::identity::{LogicalTime, OpId, ShardId, ShardKey, TenantId, WorkerId};

// ============================================================================
// SnapshotState
// ============================================================================

/// Grouped snapshot state for a `WorkerSession`.
///
/// Bundles the allocation-free scratch buffers, scalar metadata, spawned
/// lineage into a single struct. This reduces the field count on
/// `WorkerSession` and makes the refresh logic in
/// [`WorkerSession::split_residual`] more obviously complete.
struct SnapshotState {
    /// Allocation-free scratch buffers from acquisition time.
    ///
    /// Backed by fixed-capacity arrays so `split_residual` can refresh spec
    /// bounds without owned materialization.
    scratch: AcquireScratch,

    /// Shard status at acquisition time.
    status: ShardStatus,

    /// Cursor semantics for the shard.
    cursor_semantics: CursorSemantics,

    /// Parent shard ID (if this shard was created by a split).
    parent: Option<ShardId>,

    /// Lineage of spawned child shards, appended to on each `split_residual`.
    spawned: InlineVec<ShardId, MAX_SPAWNED_PER_SHARD>,
}

// ============================================================================
// WorkerSession
// ============================================================================

/// Ergonomic wrapper that binds a coordination backend, tenant, worker,
/// and active lease into a single handle for shard operations.
///
/// ## Lifecycle
///
/// ```text
///                WorkerSession::new(backend, now, tenant, key, worker)
///                          │
///                          ▼
///               ┌──── Active Session ◄──┐
///               │          │            │
///               │    renew / checkpoint │
///               │          │            │
///               │          ▼            │
///               │   split_residual ─────┘  (session stays active,
///               │                           snapshot narrowed)
///               │
///       ┌───────┼───────────┐
///       ▼       ▼           ▼
///   complete   park    split_replace
///   (Done)   (Parked)    (Split)
///       └───────┴───────────┘
///         session consumed ──► cannot be used again
/// ```
///
/// ## Drop Warning
///
/// Dropping a session without calling a terminal operation (`complete`,
/// `park`, or `split_replace`) wastes the lease until it expires at its
/// deadline. During that window no other worker can acquire the shard,
/// causing stalled progress.
#[must_use = "dropping a WorkerSession without completing, parking, or splitting \
              wastes the lease until expiry"]
pub struct WorkerSession<'b, B: CoordinationBackend> {
    /// Exclusive reference to the coordination backend. The `&mut` borrow
    /// enforces single-session-per-backend at compile time (see module docs
    /// on lifetime `'b`).
    backend: &'b mut B,

    /// Tenant this session is scoped to. Passed to every backend call for
    /// tenant isolation enforcement.
    tenant: TenantId,

    /// Worker that owns the lease. Captured at acquisition time and
    /// available via [`Self::worker()`] for diagnostics.
    worker: WorkerId,

    /// The active lease granted by `acquire_and_restore_into`. Updated in place
    /// by [`Self::renew()`] (deadline extension only; fence epoch is
    /// immutable after acquisition). Consumed by terminal operations.
    lease: Lease,

    /// Snapshot state from acquisition time, refreshed by `split_residual`.
    snapshot: SnapshotState,

    /// Advisory capacity hint from the last acquire or renew.
    ///
    /// Reflects the run's available-shard count at the time of the last
    /// acquire or renew.  Not updated by checkpoint, complete, park, or
    /// split operations.  Workers should not make safety decisions based
    /// on this value — it is a best-effort backoff signal.
    capacity: CapacityHint,
}

impl<'b, B: CoordinationBackend> WorkerSession<'b, B> {
    /// Acquire a shard and create a new session.
    ///
    /// Delegates to [`CoordinationBackend::acquire_and_restore_into`], which
    /// increments the shard's fence epoch and grants a new lease. The
    /// returned session caches the lease, tenant, worker, and the
    /// shard's snapshot (cursor + spec at acquisition time).
    ///
    /// The fence epoch increment means any prior lease for this shard
    /// (from a previous session, a crashed worker, or the same worker
    /// re-acquiring after expiry) is immediately invalidated. Operations
    /// using the stale lease will fail with `StaleFence`.
    ///
    /// The `backend` is exclusively borrowed for the session's lifetime,
    /// so no other session or raw backend call can be made until this
    /// session is dropped or consumed by a terminal operation.
    ///
    /// # Panics
    ///
    /// Panics (in all builds) if the returned lease's tenant does not
    /// match `tenant`. Tenant isolation is a security boundary: a
    /// backend that returns a cross-tenant lease is fatally broken.
    /// Additional debug-only assertions verify shard key, owner, and
    /// non-terminal status consistency.
    ///
    /// # Errors
    ///
    /// Returns [`AcquireError`] if:
    /// - The shard does not exist (`ShardNotFound`)
    /// - The shard is in a terminal state (`ShardTerminal`)
    /// - Another worker holds a live lease (`AlreadyLeased`)
    /// - The tenant does not match the shard's tenant (`TenantMismatch`)
    pub fn new(
        backend: &'b mut B,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
    ) -> Result<Self, AcquireError> {
        let mut snapshot_scratch = AcquireScratch::new();
        let result =
            backend.acquire_and_restore_into(now, tenant, key, worker, &mut snapshot_scratch)?;
        // Panic is intentional: the backend's slab only stores specs that
        // passed write_spec validation (size ceilings enforced by assert),
        // so an invalid spec here means internal slab corruption.
        ShardSpec::validate_ref(result.snapshot.spec())
            .expect("WorkerSession::new: backend returned invalid shard spec");
        if let Some(last_key) = result.snapshot.cursor().last_key() {
            assert!(
                !last_key.is_empty(),
                "WorkerSession::new: backend returned empty cursor last_key"
            );
        }
        let status = result.snapshot.status();
        let cursor_semantics = result.snapshot.cursor_semantics();
        let parent = result.snapshot.parent();
        let spawned = InlineVec::from_slice(result.snapshot.spawned());
        let lease = result.lease;
        let capacity = result.capacity;
        // Tenant is a security boundary — must hold in all builds.
        assert_eq!(lease.tenant(), tenant, "lease tenant mismatch");
        // The remaining assertions are correctness sanity checks: if the
        // backend returns inconsistent identity or a terminal shard, the
        // bug is in the backend, not the caller. These are debug-only to
        // avoid redundant checks on the hot path in release builds.
        debug_assert_eq!(lease.shard_key(), key, "lease shard_key mismatch");
        debug_assert_eq!(lease.owner(), worker, "lease owner mismatch");
        debug_assert!(!status.is_terminal(), "acquired terminal shard");
        Ok(Self {
            backend,
            tenant,
            worker,
            lease,
            snapshot: SnapshotState {
                scratch: snapshot_scratch,
                status,
                cursor_semantics,
                parent,
                spawned,
            },
            capacity,
        })
    }

    #[inline]
    fn snapshot_view(&self) -> ShardSnapshotView<'_> {
        self.snapshot.scratch.view(
            self.snapshot.status,
            self.snapshot.cursor_semantics,
            self.snapshot.parent,
        )
    }

    /// The active lease, including fence epoch and deadline.
    ///
    /// The deadline is updated in place after a successful [`renew`](Self::renew).
    #[inline]
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Borrowed shard snapshot view from acquisition time.
    ///
    /// Reflects shard state at acquisition, updated only after
    /// `split_residual` narrows the key range. Does not reflect
    /// subsequent checkpoints.
    #[inline]
    pub fn initial_snapshot(&self) -> ShardSnapshotView<'_> {
        self.snapshot_view()
    }

    /// Borrowed shard spec view (key range + metadata).
    ///
    /// Updated after `split_residual` to reflect the narrowed range.
    #[inline]
    #[must_use]
    pub fn spec(&self) -> ShardSpecRef<'_> {
        self.snapshot_view().spec()
    }

    /// Borrowed cursor view at acquisition time (the last checkpoint before this session).
    ///
    /// Not updated by [`checkpoint`](Self::checkpoint) or
    /// [`complete`](Self::complete) — the worker already knows
    /// the cursor it wrote. Use this to determine where to resume scanning
    /// after acquiring the shard.
    #[inline]
    #[must_use]
    pub fn cursor(&self) -> CursorUpdate<'_> {
        self.snapshot_view().cursor()
    }

    /// The tenant this session is scoped to.
    #[inline]
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The worker that owns this session.
    #[inline]
    #[must_use]
    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    /// The shard key (`RunId`, `ShardId`).
    #[inline]
    #[must_use]
    pub fn shard_key(&self) -> ShardKey {
        self.lease.shard_key()
    }

    /// Advisory capacity hint from the last acquire or renew.
    ///
    /// Reflects the run's available-shard count at the time of the last
    /// acquire or renew.  Not updated by checkpoint, complete, park, or
    /// split operations.  Workers should not make safety decisions based
    /// on this value — it is a best-effort backoff signal.
    #[inline]
    pub fn capacity(&self) -> CapacityHint {
        self.capacity
    }

    /// Renew the lease, extending the deadline.
    ///
    /// The worker must call this periodically before the current deadline
    /// (`session.lease().deadline()`) to maintain exclusive access. If the
    /// deadline passes without renewal, the lease expires and another
    /// worker may acquire the shard, causing all subsequent operations on
    /// this session to fail with `StaleFence` or `LeaseExpired`.
    ///
    /// On success, the session's cached lease deadline and capacity hint
    /// are updated in place so that `session.lease().deadline()` and
    /// `session.capacity()` reflect the refreshed values.
    ///
    /// The fence epoch does not change — renewal is a deadline extension,
    /// not an ownership transfer.
    ///
    /// # Panics
    ///
    /// Panics if the backend returns a new deadline that is not strictly
    /// after `now`. A renewal that does not extend the deadline into the
    /// future is always a backend bug.
    ///
    /// # Errors
    ///
    /// Returns [`RenewError`] if the shard does not exist, the lease
    /// has expired, the fence epoch is stale (another worker acquired
    /// the shard), the shard is in a terminal state, or tenant isolation
    /// fails.
    pub fn renew(&mut self, now: LogicalTime) -> Result<RenewResult, RenewError> {
        let fence_before = self.lease.fence();
        let result = self.backend.renew(now, self.tenant, &self.lease)?;
        // An expired deadline after a "successful" renewal is always a backend bug.
        assert!(result.new_deadline > now, "renewal deadline not after now");
        self.lease.set_deadline(result.new_deadline);
        self.capacity = result.capacity;
        debug_assert_eq!(
            self.lease.fence(),
            fence_before,
            "fence changed during renewal"
        );
        Ok(result)
    }

    /// Persist scan progress by advancing the cursor.
    ///
    /// Records the worker's current position so that a crash-recovery
    /// resumes from this checkpoint rather than from the beginning.
    /// Does not change the shard's status or the session's cached
    /// snapshot (see module-level "Snapshot Staleness" docs).
    ///
    /// The backend validates the cursor against the authoritative shard
    /// record, not the session's cached snapshot. This is safe because
    /// the shard record's spec only changes via `split_residual` (which
    /// updates the session's snapshot) or via a terminal operation
    /// (which consumes the session).
    ///
    /// # Idempotency
    ///
    /// Idempotent via `op_id`: if the same `(op_id, cursor)` pair was
    /// already executed, returns `Ok(Replayed(()))`. If the same `op_id`
    /// was used with a different cursor, returns `Err(OpIdConflict)`.
    ///
    /// # Preconditions
    ///
    /// - `new_cursor.last_key` must be `Some` (non-empty progress).
    /// - Cursor monotonicity: `new_cursor >= previous cursor` (lexicographic).
    /// - Cursor bounds: `last_key` must fall within `[spec.start, spec.end)`.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointError`] on lease validation failure, cursor
    /// monotonicity violation, out-of-bounds cursor, missing `last_key`,
    /// or `OpId` conflict.
    ///
    /// `new_cursor` is borrowed input only. The backend copies bytes into
    /// pooled storage and never retains references past the call boundary.
    pub fn checkpoint(
        &mut self,
        now: LogicalTime,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        self.backend
            .checkpoint(now, self.tenant, &self.lease, new_cursor, op_id)
    }

    /// Mark the shard as successfully done. **Consumes the session.**
    ///
    /// Terminal operation: the shard transitions to `Done`, the lease is
    /// released, and no further mutations are accepted. The `final_cursor`
    /// records the worker's final position and must satisfy the same
    /// monotonicity and bounds constraints as [`checkpoint`](Self::checkpoint).
    ///
    /// # Errors
    ///
    /// Returns [`CompleteError`] on lease validation failure, cursor
    /// constraint violation, or `OpId` conflict.
    ///
    /// `final_cursor` is borrowed input only. The backend copies bytes into
    /// pooled storage and never retains references past the call boundary.
    pub fn complete(
        self,
        now: LogicalTime,
        final_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.backend
            .complete(now, self.tenant, &self.lease, final_cursor, op_id)
    }

    /// Halt the shard due to a repeated or permanent error. **Consumes the session.**
    ///
    /// Terminal operation: the shard transitions to `Parked` with the
    /// given reason, the lease is released, and no further mutations
    /// are accepted. Resuming a parked shard is an out-of-band admin
    /// operation (not part of the coordination contract).
    ///
    /// The `reason` categorizes the failure for operational triage — see
    /// [`ParkReason`] for the coordination-level categories. Detailed
    /// error context should be recorded separately in the worker's logs
    /// or diagnostic store, not in the coordination record.
    ///
    /// # Errors
    ///
    /// Returns [`ParkError`] on lease validation failure or `OpId` conflict.
    pub fn park(
        self,
        now: LogicalTime,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.backend
            .park_shard(now, self.tenant, &self.lease, reason, op_id)
    }

    /// Replace this shard with N child shards. **Consumes the session.**
    ///
    /// Terminal operation: the parent transitions to `Split`, its lease
    /// is released, and the backend creates N new Active child shards
    /// whose key ranges exactly partition the parent's range (no gaps,
    /// no overlaps). Child shard IDs are derived deterministically from
    /// the parent's identity and spawn index via
    /// [`derive_split_shard_id`](crate::coordination::split::derive_split_shard_id).
    ///
    /// Use this when the entire range should be subdivided (e.g., the
    /// shard is too large for a single worker). For carving off just the
    /// unprocessed tail while continuing to process the prefix, use
    /// [`split_residual`](Self::split_residual) instead.
    ///
    /// # Errors
    ///
    /// Returns [`SplitReplaceError`] on lease validation failure, split
    /// coverage violation (gaps or overlaps in child ranges), or `OpId`
    /// conflict.
    pub fn split_replace(
        self,
        now: LogicalTime,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        self.backend
            .split_replace(now, self.tenant, &self.lease, plan, op_id)
    }

    /// Shrink this shard's key range and create a residual for the
    /// remainder. Does **not** consume the session — the parent stays
    /// Active with the narrowed range from `plan.parent_new_spec()`.
    ///
    /// Use this when the worker wants to offload the unprocessed upper
    /// portion of its range to another worker while continuing to
    /// process the lower portion. For full subdivision (retiring the
    /// parent entirely), use [`split_replace`](Self::split_replace).
    ///
    /// When the operation executes for the first time (`Executed`, not
    /// `Replayed`), the session refreshes allocation-free snapshot state with:
    /// - The narrowed spec from the plan (written into scratch storage)
    /// - The residual's `ShardId` appended to spawned lineage
    /// - Borrowed snapshot views automatically reflect the refreshed scratch
    ///
    /// On `Replayed`, snapshot state is left unchanged — the first call in
    /// this session already narrowed it, or (after crash-recovery) the
    /// state from `acquire_and_restore_into` already reflects the narrowed spec.
    ///
    /// This rebuild is necessary because the backend validates cursor
    /// bounds against the shard record's spec (which has been narrowed).
    /// If the session's snapshot were stale, the worker might attempt a
    /// checkpoint with a cursor outside the narrowed range, which the
    /// backend would correctly reject.
    ///
    /// # Errors
    ///
    /// Returns [`SplitResidualError`] on lease validation failure,
    /// residual range validation failure, or `OpId` conflict.
    ///
    /// # Op-log eviction caveat
    ///
    /// Because the parent stays Active, subsequent operations can evict
    /// the split_residual entry from the bounded op-log (cap = 16).
    /// If a retry occurs after eviction, the backend cannot detect the
    /// replay via op-log lookup. Instead, it checks whether the derived
    /// residual shard ID already exists — if it does, the backend
    /// returns `Replayed` (payload-hash verification is lost after
    /// op-log eviction; see `split_residual` in `in_memory.rs` for
    /// the full fallback rationale).
    pub fn split_residual(
        &mut self,
        now: LogicalTime,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        // Capture the narrowed spec before `plan` is moved into the backend call.
        let new_spec = plan.parent_new_spec();
        let result = self
            .backend
            .split_residual(now, self.tenant, &self.lease, plan, op_id)?;
        if let IdempotentOutcome::Executed(ref res) = result {
            // Panic is intentional: the plan's spec passed validation at
            // construction time, so an invalid spec here means internal
            // corruption in the plan or coordinator.
            ShardSpec::validate_ref(new_spec).expect("split_residual produced invalid parent spec");
            // Refresh allocation-free snapshot state so subsequent operations
            // (especially checkpoint) validate against the narrowed range.
            //
            // Only `Executed` triggers refresh. `Replayed` means one of:
            // (a) Same session retried the same OpId — snapshot was already
            //     narrowed by the first call in this session.
            // (b) New session retried after crash — the backend's shard
            //     record already reflects the narrowed spec, so the snapshot
            //     from `acquire_and_restore_into` is already correct.
            // In both cases, skipping refresh is safe.
            self.snapshot.scratch.write_spec(
                new_spec.key_range_start(),
                new_spec.key_range_end(),
                new_spec.metadata(),
            );
            self.snapshot.spawned.push(res.residual);
            self.snapshot
                .scratch
                .write_spawned_iter(self.snapshot.spawned.iter().copied());
            debug_assert_eq!(
                self.snapshot.status,
                ShardStatus::Active,
                "status changed after split_residual"
            );
        }
        if let IdempotentOutcome::Replayed(_) = &result {
            let cached_spec = self.snapshot_view().spec();
            debug_assert_eq!(
                cached_spec.key_range_end(),
                new_spec.key_range_end(),
                "Replayed split_residual but snapshot spec not yet narrowed"
            );
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
