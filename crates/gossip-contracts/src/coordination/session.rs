//! Ergonomic `WorkerSession` wrapper for shard operations.
//!
//! Most [`CoordinationBackend`] methods require `(now, tenant, lease, ...)`
//! parameters (`acquire_and_restore` takes `key` and `worker` instead, since
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
//! The cached [`ShardSnapshot`] reflects the shard state at acquisition
//! time. It is **not** updated by [`checkpoint`](WorkerSession::checkpoint)
//! because the worker already knows the cursor it just wrote, and the
//! backend validates cursor monotonicity and bounds against the
//! authoritative [`ShardRecord`](super::record::ShardRecord), not
//! the session's cached snapshot. Updating the snapshot on every
//! checkpoint would add allocation overhead for no correctness benefit.
//! Similarly, [`renew`](WorkerSession::renew) updates the lease
//! deadline (via `Lease::set_deadline`) and the capacity hint, but
//! not the snapshot.
//!
//! The snapshot **is** updated by [`split_residual`](WorkerSession::split_residual)
//! because the key range narrows, and subsequent [`checkpoint`](WorkerSession::checkpoint)
//! calls must not present cursors outside the narrowed range. While the
//! backend would reject such cursors regardless, keeping the session's
//! snapshot consistent avoids confusing the worker's own bounds logic.

use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, CapacityHint, CheckpointError, CompleteError, IdempotentOutcome, ParkError,
    RenewError, RenewResult, SplitReplaceError, SplitResidualError,
};
use crate::coordination::lease::Lease;
use crate::coordination::record::{ParkReason, ShardSnapshot, ShardStatus};
use crate::coordination::shard_spec::ShardSpec;
use crate::coordination::split::{
    SplitReplacePlan, SplitReplaceResult, SplitResidualPlan, SplitResidualResult,
};
use crate::coordination::traits::CoordinationBackend;
use crate::identity::{LogicalTime, OpId, ShardKey, TenantId, WorkerId};

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

    /// The active lease granted by `acquire_and_restore`. Updated in place
    /// by [`Self::renew()`] (deadline extension only; fence epoch is
    /// immutable after acquisition). Consumed by terminal operations.
    lease: Lease,

    /// Shard state snapshot from acquisition time. Intentionally not
    /// updated by [`Self::checkpoint()`] (the worker already knows its
    /// cursor). Rebuilt by [`Self::split_residual()`] to reflect the
    /// narrowed key range so subsequent cursor-bounds checks are accurate.
    snapshot: ShardSnapshot,

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
    /// Delegates to [`CoordinationBackend::acquire_and_restore`], which
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
        let result = backend.acquire_and_restore(now, tenant, key, worker)?;
        // Tenant is a security boundary — must hold in all builds.
        assert_eq!(result.lease.tenant(), tenant, "lease tenant mismatch");
        // The remaining assertions are correctness sanity checks: if the
        // backend returns inconsistent identity or a terminal shard, the
        // bug is in the backend, not the caller. These are debug-only to
        // avoid redundant checks on the hot path in release builds.
        debug_assert_eq!(result.lease.shard_key(), key, "lease shard_key mismatch");
        debug_assert_eq!(result.lease.owner(), worker, "lease owner mismatch");
        debug_assert!(
            !result.snapshot.status().is_terminal(),
            "acquired terminal shard"
        );
        Ok(Self {
            backend,
            tenant,
            worker,
            lease: result.lease,
            snapshot: result.snapshot,
            capacity: result.capacity,
        })
    }

    /// The active lease, including fence epoch and deadline.
    ///
    /// The deadline is updated in place after a successful [`renew`](Self::renew).
    #[inline]
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// The shard snapshot from acquisition time.
    ///
    /// Reflects the shard state at acquisition, updated only after
    /// `split_residual` narrows the key range. Does NOT reflect
    /// subsequent checkpoints.
    #[inline]
    #[must_use]
    pub fn initial_snapshot(&self) -> &ShardSnapshot {
        &self.snapshot
    }

    /// The shard's spec (key range + metadata).
    ///
    /// Updated after `split_residual` to reflect the narrowed range.
    #[inline]
    #[must_use]
    pub fn spec(&self) -> &ShardSpec {
        self.snapshot.spec()
    }

    /// The cursor at acquisition time (the last checkpoint before this session).
    ///
    /// Not updated by [`checkpoint`](Self::checkpoint) — the worker already
    /// knows the cursor it wrote. Use this to determine where to resume
    /// scanning after acquiring the shard.
    #[inline]
    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        self.snapshot.cursor()
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
    pub fn checkpoint(
        &mut self,
        now: LogicalTime,
        new_cursor: Cursor,
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
    pub fn complete(
        self,
        now: LogicalTime,
        final_cursor: Cursor,
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
        plan: SplitReplacePlan,
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
    /// `Replayed`), the session's cached snapshot is rebuilt with:
    /// - The narrowed spec from the plan
    /// - The original status, cursor, cursor semantics, and parent (unchanged)
    /// - The residual's `ShardId` appended to the spawned list
    ///
    /// On `Replayed`, the snapshot is left unchanged — the first call in
    /// this session already narrowed it, or (after crash-recovery) the
    /// snapshot from `acquire_and_restore` already reflects the narrowed spec.
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
        plan: SplitResidualPlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        // Capture the narrowed spec before `plan` is moved into the backend call.
        let new_spec = plan.parent_new_spec().clone();
        let result = self
            .backend
            .split_residual(now, self.tenant, &self.lease, plan, op_id)?;
        if let IdempotentOutcome::Executed(ref res) = result {
            // Rebuild the cached snapshot so that subsequent operations
            // (especially checkpoint) validate against the narrowed range.
            //
            // Only `Executed` triggers the rebuild. `Replayed` means one of:
            // (a) Same session retried the same OpId — snapshot was already
            //     narrowed by the first call in this session.
            // (b) New session retried after crash — the backend's shard
            //     record already reflects the narrowed spec, so the snapshot
            //     from `acquire_and_restore` is already correct.
            // In both cases, skipping the rebuild is safe.
            let mut spawned = self.snapshot.spawned().to_vec();
            spawned.push(res.residual);
            self.snapshot = ShardSnapshot::new(
                self.snapshot.status(),
                new_spec.clone(),
                self.snapshot.cursor().clone(),
                self.snapshot.cursor_semantics(),
                self.snapshot.parent(),
                spawned,
            );
            debug_assert_eq!(
                self.snapshot.status(),
                ShardStatus::Active,
                "status changed after split_residual"
            );
        }
        if let IdempotentOutcome::Replayed(_) = &result {
            debug_assert_eq!(
                self.snapshot.spec().key_range_end(),
                new_spec.key_range_end(),
                "Replayed split_residual but snapshot spec not yet narrowed"
            );
        }
        Ok(result)
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Tests exercise the `WorkerSession` API against the `InMemoryCoordinator`
/// reference implementation. Each test creates a fresh coordinator with a
/// single run and verifies that session methods correctly delegate to the
/// backend, update internal state (lease deadline, snapshot), and enforce
/// ownership semantics (terminal ops consume the session).
///
/// ## Test organization
///
/// - **Happy path**: `new_ok`, `complete_consumes`, `split_residual_keeps_session`,
///   `renew_updates_internal_deadline`, `park_consumes_session`,
///   `split_replace_consumes_session`, `checkpoint_advances_cursor_via_session`
/// - **Error paths**: expired lease, already-leased rejection, stale fence
/// - **Idempotency**: checkpoint and complete replays, split_residual replays
///   (including after op-log eviction)
/// - **Snapshot staleness**: checkpoint does not update cache, split_residual
///   error does not corrupt cache, successive splits accumulate spawned entries
/// - **Property tests**: random operation sequences preserve identity invariants
/// - **Capacity hints**: verify advisory shard availability counts
#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::in_memory::InMemoryCoordinator;
    use crate::coordination::run::{InitialShard, RunConfig, RunManagement};
    use crate::coordination::shard_spec::CursorSemantics;
    use crate::identity::{RunId, ShardId};
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_worker(id: u64) -> WorkerId {
        WorkerId::from_raw(id)
    }

    fn now(t: u64) -> LogicalTime {
        LogicalTime::from_raw(t)
    }

    /// Returns a run config with `CursorSemantics::Completed`, a 30-tick
    /// lease duration, and a max-workers-per-run of 5.
    fn test_run_config() -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
    }

    /// Set up a coordinator with a single run containing `shard_count` shards.
    ///
    /// Each shard covers a wide range: shard i covers `[i*0x40, (i+1)*0x40)`.
    /// This gives enough room for cursor values and split operations.
    /// The lease duration is 30 ticks (from `test_run_config`), so acquiring
    /// at `now(2)` yields a deadline of 32.
    fn setup_coordinator(shard_count: usize) -> (InMemoryCoordinator, Vec<ShardKey>) {
        let mut coord = InMemoryCoordinator::new(30);
        let tenant = test_tenant();
        let run = test_run();
        let config = test_run_config();

        coord.create_run(now(1), tenant, run, config).unwrap();

        let shards: Vec<InitialShard> = (0..shard_count)
            .map(|i| {
                let start = vec![(i as u8) * 0x40];
                let end = vec![((i + 1) as u8) * 0x40];
                InitialShard::new(
                    ShardId::from_raw(i as u64),
                    crate::coordination::shard_spec::ShardSpec::with_range(start, end),
                    Cursor::initial(),
                )
            })
            .collect();

        let _ = coord
            .register_shards(now(1), tenant, run, &shards, OpId::from_raw(100))
            .unwrap();

        let keys: Vec<ShardKey> = (0..shard_count)
            .map(|i| ShardKey::new(run, ShardId::from_raw(i as u64)))
            .collect();

        (coord, keys)
    }

    #[test]
    fn new_ok() {
        let (mut coord, keys) = setup_coordinator(1);
        let session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        assert_eq!(session.tenant(), test_tenant());
        assert_eq!(session.worker(), test_worker(1));
        assert_eq!(session.shard_key(), keys[0]);
        assert_eq!(session.lease().shard(), ShardId::from_raw(0));
        assert_eq!(
            session.initial_snapshot().spec().key_range_start(),
            [0x00u8]
        );
    }

    #[test]
    fn complete_consumes() {
        let (mut coord, keys) = setup_coordinator(1);
        let session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        // Cursor must be within shard range [0x00, 0x40).
        let cursor = Cursor::with_last_key(vec![0x10]);
        let result = session.complete(now(3), cursor, OpId::from_raw(200));
        assert!(result.is_ok());
    }

    #[test]
    fn split_residual_keeps_session() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        // Shard 0 covers [0x00, 0x40). Split into [0x00, 0x20) + residual [0x20, 0x40).
        let parent_new_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
        let residual_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
        let plan = SplitResidualPlan::try_new(parent_new_spec.clone(), residual_spec).unwrap();

        let result = session.split_residual(now(3), plan, OpId::from_raw(300));
        assert!(result.is_ok());

        // Session is still usable — checkpoint should work.
        // Cursor must be within narrowed range [0x00, 0x20).
        let cursor = Cursor::with_last_key(vec![0x10]);
        let cp_result = session.checkpoint(now(4), cursor, OpId::from_raw(301));
        assert!(cp_result.is_ok());

        // Snapshot spec should reflect the narrowed range.
        assert_eq!(session.spec().key_range_end(), &[0x20]);
    }

    #[test]
    fn renew_updates_internal_deadline() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let old_deadline = session.lease().deadline();
        let _result = session.renew(now(10)).unwrap();
        let new_deadline = session.lease().deadline();

        // Deadline must have advanced.
        assert!(new_deadline > old_deadline);
    }

    #[test]
    fn park_consumes_session() {
        let (mut coord, keys) = setup_coordinator(1);
        let session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let result = session.park(now(3), ParkReason::Other, OpId::from_raw(400));
        assert!(result.is_ok());
    }

    #[test]
    fn split_replace_consumes_session() {
        let (mut coord, keys) = setup_coordinator(1);
        let session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        // Shard 0 covers [0x00, 0x40). Split into children [0x00, 0x20) + [0x20, 0x40).
        let child1_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
        let child2_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);

        use crate::coordination::split::SplitReplaceChild;
        let plan = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(child1_spec, Cursor::initial()),
            SplitReplaceChild::new(child2_spec, Cursor::initial()),
        ])
        .unwrap();

        let result = session.split_replace(now(3), plan, OpId::from_raw(500));
        assert!(result.is_ok());
        if let Ok(outcome) = result {
            let inner = outcome.into_inner();
            assert_eq!(inner.children.len(), 2);
        }
    }

    #[test]
    fn checkpoint_advances_cursor_via_session() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let cursor = Cursor::with_last_key(vec![0x10]);
        let result = session.checkpoint(now(3), cursor, OpId::from_raw(600));
        assert!(result.is_ok());
        assert!(result.unwrap().is_executed());
    }

    // -- Error-path & edge-case tests ------------------------------------

    /// Replaying the same `split_residual` OpId must NOT rebuild the
    /// cached snapshot. The `is_executed()` guard in `split_residual`
    /// is the only thing preventing double-rebuild, which would corrupt
    /// the spawned list by appending the residual ID twice.
    #[test]
    fn split_residual_replayed_does_not_rebuild_snapshot() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let parent_new_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
        let residual_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);

        // First call: Executed — snapshot is rebuilt with narrowed range.
        let plan1 =
            SplitResidualPlan::try_new(parent_new_spec.clone(), residual_spec.clone()).unwrap();
        let op = OpId::from_raw(700);
        let r1 = session.split_residual(now(3), plan1, op).unwrap();
        assert!(r1.is_executed());

        let spec_after_first = session.spec().clone();
        let spawned_after_first: Vec<_> = session.initial_snapshot().spawned().to_vec();
        assert_eq!(spawned_after_first.len(), 1);

        // Second call with same OpId: Replayed — snapshot must NOT change.
        let plan2 = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
        let r2 = session.split_residual(now(4), plan2, op).unwrap();
        assert!(r2.is_replay());

        assert_eq!(session.spec(), &spec_after_first);
        assert_eq!(session.initial_snapshot().spawned(), &spawned_after_first);
    }

    /// After op-log eviction (16+ subsequent ops), the backend falls
    /// back to a spawned-probe to detect the residual. This test
    /// verifies that the fallback returns `Replayed` even though the
    /// original op-log entry has been evicted.
    #[test]
    fn split_residual_replayed_after_oplog_eviction() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        // Shard 0 covers [0x00, 0x40). Split into [0x00, 0x20) + residual [0x20, 0x40).
        let parent_new_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
        let residual_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
        let split_op = OpId::from_raw(700);
        let plan =
            SplitResidualPlan::try_new(parent_new_spec.clone(), residual_spec.clone()).unwrap();
        let r = session.split_residual(now(3), plan, split_op).unwrap();
        assert!(r.is_executed(), "first call must be Executed");

        // Execute 17 checkpoints to evict the split op-log entry.
        // OP_LOG_CAP = 16, so 17 pushes guarantee eviction.
        let mut t = 10u64;
        for i in 0..17u64 {
            // Cursor bytes 0x01..=0x11, all within narrowed range [0x00, 0x20).
            let cursor = Cursor::with_last_key(vec![(i + 1) as u8]);
            let _ = session
                .checkpoint(now(t), cursor, OpId::from_raw(801 + i))
                .unwrap();
            t += 1;
        }

        // Retry split_residual with the same OpId — op-log entry is
        // evicted, but the spawned-probe fallback detects the residual.
        let plan2 = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
        let r2 = session.split_residual(now(t), plan2, split_op).unwrap();
        assert!(
            r2.is_replay(),
            "must return Replayed via spawned-probe fallback after op-log eviction"
        );
    }

    /// Renewing a lease must not change the fence epoch — renewal is a
    /// deadline extension, not an ownership transfer.
    #[test]
    fn renew_postconditions_fence_stable() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let fence_before = session.lease().fence();

        // First renewal.
        let _ = session.renew(now(10)).unwrap();
        assert_eq!(
            session.lease().fence(),
            fence_before,
            "fence must not change after first renewal"
        );

        // Second renewal.
        let _ = session.renew(now(20)).unwrap();
        assert_eq!(
            session.lease().fence(),
            fence_before,
            "fence must not change after second renewal"
        );
    }

    /// After `split_residual` narrows `[0x00, 0x40)` → `[0x00, 0x20)`,
    /// a checkpoint within the narrowed range succeeds but a cursor
    /// outside it is rejected with `CursorOutOfBounds`.
    #[test]
    fn checkpoint_after_split_validates_narrowed_bounds() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        // Narrow to [0x00, 0x20).
        let parent_new_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
        let residual_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
        let plan = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
        let _ = session
            .split_residual(now(3), plan, OpId::from_raw(800))
            .unwrap();

        // Within narrowed range — succeeds.
        let ok_cursor = Cursor::with_last_key(vec![0x10]);
        assert!(
            session
                .checkpoint(now(4), ok_cursor, OpId::from_raw(801))
                .is_ok()
        );

        // Outside narrowed range — rejected.
        let bad_cursor = Cursor::with_last_key(vec![0x30]);
        let err = session
            .checkpoint(now(5), bad_cursor, OpId::from_raw(802))
            .unwrap_err();
        assert!(
            matches!(err, CheckpointError::CursorOutOfBounds(_)),
            "expected CursorOutOfBounds, got {err:?}"
        );
    }

    /// Advancing time past the lease deadline causes both `renew` and
    /// `checkpoint` to return their respective `LeaseExpired` errors.
    /// Verifies session correctly threads `now` and `lease` to the backend.
    #[test]
    fn expired_lease_rejected_through_session() {
        let (mut coord, keys) = setup_coordinator(1);
        // Acquire at now(2) with lease_duration=30 → deadline=32.
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        // Renew past deadline.
        let renew_err = session.renew(now(50)).unwrap_err();
        assert!(
            matches!(renew_err, RenewError::LeaseExpired { .. }),
            "expected LeaseExpired, got {renew_err:?}"
        );

        // Checkpoint past deadline.
        let cp_err = session
            .checkpoint(
                now(50),
                Cursor::with_last_key(vec![0x10]),
                OpId::from_raw(900),
            )
            .unwrap_err();
        assert!(
            matches!(cp_err, CheckpointError::LeaseExpired { .. }),
            "expected LeaseExpired, got {cp_err:?}"
        );
    }

    /// When another worker holds a live lease, `WorkerSession::new`
    /// surfaces `AlreadyLeased` without wrapping or translating the error.
    #[test]
    fn already_leased_rejected_through_session() {
        let (mut coord, keys) = setup_coordinator(1);

        // Worker 1 acquires via raw backend call (borrow released on return).
        let _w1 = coord
            .acquire_and_restore(now(2), test_tenant(), keys[0], test_worker(1))
            .unwrap();

        // Worker 2 tries to create a session on the same shard.
        match WorkerSession::new(&mut coord, now(3), test_tenant(), keys[0], test_worker(2)) {
            Err(AcquireError::AlreadyLeased { .. }) => {} // expected
            Err(other) => panic!("expected AlreadyLeased, got {other:?}"),
            Ok(_) => panic!("expected AlreadyLeased, but session was created"),
        }
    }

    // -- Stale-fence & crash-recovery tests ------------------------------

    /// A stale lease (from a previous session whose fence was superseded)
    /// is rejected with `StaleFence` when presented for a checkpoint.
    /// Tests the fencing protocol through the coordination backend after
    /// two successive session acquisitions on the same shard.
    #[test]
    fn stale_fence_rejected_through_session() {
        let (mut coord, keys) = setup_coordinator(1);
        // Worker 1 acquires at t=2, deadline=32.
        let session_w1 =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
        let stale_lease = *session_w1.lease();
        // Drop session (release borrow), expire the lease, then worker 2 acquires.
        drop(session_w1);
        let _session_w2 =
            WorkerSession::new(&mut coord, now(50), test_tenant(), keys[0], test_worker(2))
                .unwrap();
        drop(_session_w2);
        // Use raw backend with stale_lease to verify StaleFence.
        let cp_err = coord
            .checkpoint(
                now(51),
                test_tenant(),
                &stale_lease,
                Cursor::with_last_key(vec![0x10]),
                OpId::from_raw(950),
            )
            .unwrap_err();
        assert!(
            matches!(cp_err, CheckpointError::StaleFence { .. }),
            "expected StaleFence, got {cp_err:?}"
        );
    }

    /// Simulates a crash by dropping session 1 without a terminal op, then
    /// re-acquiring. The checkpoint written by session 1 must be restored
    /// in session 2's initial cursor.
    #[test]
    fn crash_recovery_restores_cursor() {
        let (mut coord, keys) = setup_coordinator(1);
        // Session 1: acquire and checkpoint to 0x15.
        {
            let mut s1 =
                WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1))
                    .unwrap();
            let cursor = Cursor::with_last_key(vec![0x15]);
            let _ = s1.checkpoint(now(3), cursor, OpId::from_raw(1000)).unwrap();
            // Session dropped (simulated crash) without terminal op.
        }
        // Session 2: re-acquire after lease expiry, verify restored cursor.
        let s2 = WorkerSession::new(&mut coord, now(50), test_tenant(), keys[0], test_worker(2))
            .unwrap();
        assert_eq!(s2.cursor().last_key(), Some(&[0x15u8][..]));
    }

    // -- Idempotency tests ------------------------------------------------

    /// Replaying a checkpoint with the same OpId and identical cursor
    /// returns `Replayed` rather than `Executed`.
    #[test]
    fn checkpoint_replayed_returns_replayed() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let cursor = Cursor::with_last_key(vec![0x10]);
        let op = OpId::from_raw(1100);
        let first = session.checkpoint(now(3), cursor.clone(), op).unwrap();
        assert!(first.is_executed());

        let second = session.checkpoint(now(4), cursor, op).unwrap();
        assert!(second.is_replay());
    }

    /// Replaying a complete with the same OpId returns `Replayed`.
    /// Since `complete` consumes the session, the replay is tested via
    /// a raw backend call with the same lease.
    #[test]
    fn complete_replayed_returns_replayed() {
        let (mut coord, keys) = setup_coordinator(1);
        let session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
        let lease = *session.lease();

        let cursor = Cursor::with_last_key(vec![0x10]);
        let op = OpId::from_raw(1200);
        let first = session.complete(now(3), cursor.clone(), op).unwrap();
        assert!(first.is_executed());

        // Replay via raw backend — the shard is now Done, but the backend
        // recognizes the idempotent replay by matching the OpId.
        let second = coord
            .complete(now(4), test_tenant(), &lease, cursor, op)
            .unwrap();
        assert!(second.is_replay());
    }

    // -- Snapshot staleness tests ----------------------------------------

    /// Checkpoint does NOT update the session's cached snapshot.
    /// The cursor returned by `session.cursor()` should still reflect
    /// the acquisition-time cursor, not the checkpoint value.
    #[test]
    fn checkpoint_does_not_update_cached_snapshot() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let initial_cursor = session.cursor().clone();

        let checkpoint_cursor = Cursor::with_last_key(vec![0x10]);
        let result = session.checkpoint(now(3), checkpoint_cursor.clone(), OpId::from_raw(600));
        assert!(result.is_ok());

        // Session's cached cursor must still be the acquisition-time value.
        assert_eq!(
            session.cursor(),
            &initial_cursor,
            "checkpoint must not update cached snapshot cursor"
        );
        assert_ne!(
            session.cursor(),
            &checkpoint_cursor,
            "cached cursor must differ from checkpointed cursor"
        );
    }

    /// A failed `split_residual` must not corrupt the session's cached
    /// snapshot. We trigger a `LeaseExpired` error by advancing time
    /// past the deadline.
    #[test]
    fn split_residual_error_does_not_corrupt_snapshot() {
        let (mut coord, keys) = setup_coordinator(1);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

        let spec_before = session.spec().clone();
        let cursor_before = session.cursor().clone();
        let spawned_before: Vec<_> = session.initial_snapshot().spawned().to_vec();

        // Attempt split_residual with expired lease (deadline=32, now=50).
        let parent_new_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
        let residual_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
        let plan = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
        let err = session.split_residual(now(50), plan, OpId::from_raw(900));
        assert!(
            err.is_err(),
            "split_residual should fail with expired lease"
        );

        // Snapshot must be unchanged after the error.
        assert_eq!(session.spec(), &spec_before);
        assert_eq!(session.cursor(), &cursor_before);
        assert_eq!(session.initial_snapshot().spawned(), &spawned_before);
    }

    // -- Successive split_residual test ------------------------------------

    /// Two successive `split_residual` calls accumulate spawned entries and
    /// correctly narrow the shard's key range at each step.
    /// Shard starts as [0x00, 0x60). First split -> [0x00, 0x40) + residual
    /// [0x40, 0x60). Second split -> [0x00, 0x20) + residual [0x20, 0x40).
    #[test]
    fn successive_split_residual_accumulates_spawned() {
        // Use a shard with range [0x00, 0x60) for room.
        let mut coord = InMemoryCoordinator::new(30);
        let tenant = test_tenant();
        let run = test_run();
        let config = test_run_config();
        coord.create_run(now(1), tenant, run, config).unwrap();

        let shard_spec =
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x60]);
        let shard = InitialShard::new(ShardId::from_raw(0), shard_spec, Cursor::initial());
        let _ = coord
            .register_shards(now(1), tenant, run, &[shard], OpId::from_raw(100))
            .unwrap();
        let key = ShardKey::new(run, ShardId::from_raw(0));

        let mut session =
            WorkerSession::new(&mut coord, now(2), tenant, key, test_worker(1)).unwrap();

        // First split: [0x00, 0x60) -> [0x00, 0x40) + residual [0x40, 0x60).
        let plan1 = SplitResidualPlan::try_new(
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x40]),
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x40], vec![0x60]),
        )
        .unwrap();
        let r1 = session
            .split_residual(now(3), plan1, OpId::from_raw(300))
            .unwrap();
        assert!(r1.is_executed());
        assert_eq!(session.spec().key_range_end(), &[0x40]);
        assert_eq!(session.initial_snapshot().spawned().len(), 1);

        // Second split: [0x00, 0x40) -> [0x00, 0x20) + residual [0x20, 0x40).
        let plan2 = SplitResidualPlan::try_new(
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]),
            crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]),
        )
        .unwrap();
        let r2 = session
            .split_residual(now(4), plan2, OpId::from_raw(301))
            .unwrap();
        assert!(r2.is_executed());
        assert_eq!(session.spec().key_range_end(), &[0x20]);
        assert_eq!(session.initial_snapshot().spawned().len(), 2);

        // Checkpoint within the twice-narrowed range succeeds.
        let cursor = Cursor::with_last_key(vec![0x10]);
        let cp = session
            .checkpoint(now(5), cursor, OpId::from_raw(302))
            .unwrap();
        assert!(cp.is_executed());
    }

    // -- Property tests --------------------------------------------------

    /// Operation kinds for the property test.
    ///
    /// Generated up front by proptest and then interpreted against
    /// runtime state (current key range, last cursor position).
    /// Operations that are invalid in the current state (e.g., a
    /// checkpoint with a cursor that would regress, or a split on
    /// a range too narrow to subdivide) are skipped rather than
    /// rejected, keeping the shrinking behavior stable.
    #[derive(Debug, Clone)]
    enum PropOp {
        Renew,
        Checkpoint(u8),
        SplitResidual,
    }

    // Random operation sequences — including split_residual — preserve
    // identity invariants throughout the session lifecycle.
    //
    // Generates random Renew / Checkpoint(byte) / SplitResidual sequences
    // and verifies that:
    // - `tenant()`, `worker()`, and `shard_key()` never change (identity stability)
    // - All valid operations succeed (no spurious errors)
    // - `complete()` succeeds at the end (session terminates cleanly)
    //
    // The weight distribution (2:5:1) biases toward checkpoints (the
    // most common real-world operation) while still exercising renew
    // and the tricky split_residual path.
    proptest! {
        #![proptest_config(miri_proptest_config())]

        #[test]
        fn prop_session_lifecycle_invariants(
            ops in proptest::collection::vec(
                prop_oneof![
                    2 => Just(PropOp::Renew),
                    5 => (0x01u8..=0x3Eu8).prop_map(PropOp::Checkpoint),
                    1 => Just(PropOp::SplitResidual),
                ],
                0..10,
            ),
        ) {
            let (mut coord, keys) = setup_coordinator(1);
            // Acquire at t=2, deadline=32. All ops use times in [3, 30].
            let mut session = WorkerSession::new(
                &mut coord, now(2), test_tenant(), keys[0], test_worker(1),
            ).unwrap();

            let expected_tenant = session.tenant();
            let expected_worker = session.worker();
            let expected_key = session.shard_key();

            let mut t = 3u64;
            let mut last_cursor_byte: u8 = 0;
            let mut op_counter = 1000u64;
            // Track current key range (single-byte boundaries).
            let range_start: u8 = 0x00;
            let mut range_end: u8 = 0x40;

            for op in &ops {
                // Identity invariants hold before every operation.
                prop_assert_eq!(session.tenant(), expected_tenant);
                prop_assert_eq!(session.worker(), expected_worker);
                prop_assert_eq!(session.shard_key(), expected_key);

                match op {
                    PropOp::Renew => {
                        let _ = session.renew(now(t)).map_err(|e| {
                            TestCaseError::Fail(format!("renew failed at t={t}: {e:?}").into())
                        })?;
                    }
                    PropOp::Checkpoint(byte) => {
                        // Skip if out of narrowed range or would regress cursor.
                        if *byte <= last_cursor_byte
                            || *byte < range_start
                            || *byte >= range_end
                        {
                            continue;
                        }
                        let cursor = Cursor::with_last_key(vec![*byte]);
                        let _ = session
                            .checkpoint(now(t), cursor, OpId::from_raw(op_counter))
                            .map_err(|e| {
                                TestCaseError::Fail(
                                    format!("checkpoint({byte:#04x}) failed at t={t}: {e:?}")
                                        .into(),
                                )
                            })?;
                        last_cursor_byte = *byte;
                        op_counter += 1;
                    }
                    PropOp::SplitResidual => {
                        // Need at least 4 bytes of range to split meaningfully.
                        if range_end.saturating_sub(range_start) < 4 {
                            continue;
                        }
                        let mid = range_start + (range_end - range_start) / 2;
                        // Split point must leave the cursor inside the new
                        // parent range [range_start, mid).
                        if mid <= last_cursor_byte {
                            continue;
                        }
                        let parent_new =
                            crate::coordination::shard_spec::ShardSpec::with_range(
                                vec![range_start],
                                vec![mid],
                            );
                        let residual =
                            crate::coordination::shard_spec::ShardSpec::with_range(
                                vec![mid],
                                vec![range_end],
                            );
                        let plan =
                            SplitResidualPlan::try_new(parent_new, residual).unwrap();
                        let result = session
                            .split_residual(now(t), plan, OpId::from_raw(op_counter))
                            .map_err(|e| {
                                TestCaseError::Fail(
                                    format!("split_residual at t={t}: {e:?}").into(),
                                )
                            })?;
                        prop_assert!(result.is_executed());
                        prop_assert_eq!(session.spec().key_range_end(), &[mid]);
                        range_end = mid;
                        op_counter += 1;
                    }
                }
                t += 1;
            }

            // Terminal operation — cursor must be in [range_start, range_end).
            let final_byte = last_cursor_byte.max(range_start + 1);
            if final_byte < range_end {
                let final_cursor = Cursor::with_last_key(vec![final_byte]);
                let _ = session.complete(now(t), final_cursor, OpId::from_raw(op_counter)).map_err(|e| {
                    TestCaseError::Fail(format!("complete failed: {e:?}").into())
                })?;
            }
            // If range too narrow for any valid cursor, session is dropped.
        }
    }

    // -- capacity hint tests --

    /// After acquiring one of two shards, the session's capacity hint
    /// shows the remaining shard as available.
    #[test]
    fn session_capacity_updated_on_renew() {
        let (mut coord, keys) = setup_coordinator(2);
        let mut session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
        // 2 shards total, 1 just acquired ⇒ 1 available.
        assert_eq!(session.capacity().available_count, 1);
        assert!(session.capacity().has_capacity());

        // Renew — capacity hint is refreshed.
        let _ = session.renew(now(10)).unwrap();
        assert_eq!(session.capacity().available_count, 1);
    }

    /// With a single shard, after acquiring it the session sees 0 available.
    #[test]
    fn session_capacity_zero_when_all_leased() {
        let (mut coord, keys) = setup_coordinator(1);
        let session =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
        assert_eq!(session.capacity().available_count, 0);
        assert!(session.capacity().is_saturated());
        assert!(session.capacity().earliest_deadline.is_some());
    }
}
