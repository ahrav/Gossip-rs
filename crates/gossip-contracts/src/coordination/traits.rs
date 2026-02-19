//! The coordination trait: the operation contract that all backends
//! (in-memory, FoundationDB, PostgreSQL, deterministic simulator)
//! must implement.
//!
//! The trait is synchronous (returns `Result<T, E>`, not futures). Async
//! adaptation is the backend's responsibility — the contract defines
//! semantics, not execution model. This keeps the deterministic simulator
//! simple (no async runtime needed).
//!
//! Lease-gated operations take `(TenantId, Lease)` — the backend extracts
//! the `ShardKey` from the lease via `lease.shard_key()`.
//! `acquire_and_restore` is the exception: it takes
//! `(TenantId, ShardKey, WorkerId)` since no lease exists yet.
//! The backend validates:
//! 1. Tenant isolation (`record.tenant == tenant`)
//! 2. Lease validity (`record.fence_epoch == lease.fence`, not expired)
//! 3. Status preconditions (`record.status == Active` for mutations)
//!
//! This is the "fencing token protocol" — all writes carry the
//! fence epoch, and the backend rejects stale epochs.
//! Reference: Kleppmann, "How to do distributed locking" (2016);
//! Gray & Cheriton, "Leases" (SOSP 1989).
//!
//! `now: LogicalTime` is passed explicitly to every operation. The
//! coordinator never reads a clock — time is an input. This is
//! essential for deterministic simulation.
//! Reference: FoundationDB simulation (Zhou et al., SIGMOD 2021).

use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, AcquireResult, CheckpointError, CompleteError, IdempotentOutcome, ParkError,
    RenewError, RenewResult, SplitReplaceError, SplitResidualError,
};
use crate::coordination::lease::Lease;
use crate::coordination::record::ParkReason;
use crate::coordination::split::{
    SplitReplacePlan, SplitReplaceResult, SplitResidualPlan, SplitResidualResult,
};
use crate::identity::{LogicalTime, OpId, ShardKey, TenantId, WorkerId};

/// The coordination contract for the distributed secret scanner.
///
/// Every backend (in-memory, FoundationDB, PostgreSQL, deterministic
/// simulator) implements this trait. The trait defines the **semantic
/// contract** — what each operation must do and what invariants it
/// must maintain. Backends choose their own concurrency control and
/// persistence strategies.
///
/// ## Design Principles
///
/// **Synchronous API**: The trait methods are synchronous. Async
/// backends wrap the implementation; the deterministic simulator
/// calls methods directly without an async runtime.
///
/// **Time as input**: Every method takes `now: LogicalTime`. The
/// backend never reads a clock. This makes all operations
/// deterministic given the same inputs, enabling simulation testing.
///
/// Reference: FoundationDB simulation (Zhou et al., SIGMOD 2021).
///
/// **Tenant-first**: Every method takes `TenantId` as its first
/// parameter (after `&mut self` and `now`). The backend asserts
/// tenant isolation on every call.
///
/// **Lease-gated mutations**: All mutating operations (except
/// `acquire_and_restore`) require a valid `Lease`. The backend
/// validates the lease's fence epoch and deadline before executing.
///
/// ## Invariants (must hold across ALL backends)
///
/// **Safety (tenant isolation)**: A request scoped to tenant A must
/// never read or write shard records belonging to tenant B.
///
/// **Safety (fence monotonicity)**: `fence_epoch` for a shard MUST
/// be monotonically non-decreasing. It increments on every ownership
/// transfer (acquire). It never decreases.
///
/// **Safety (idempotency)**: For any operation with an `OpId`:
/// - Same `(op_id, payload_hash)` → return cached result, no mutation
/// - Same `op_id`, different `payload_hash` → `OpIdConflict` error
/// - New `op_id` → execute and record in op-log
///
/// Reference: Stripe idempotency key pattern (Brandur Leach, 2017);
///            IETF Draft: Idempotency-Key HTTP Header Field.
///
/// **Safety (cursor monotonicity)**: Across checkpoints within the
/// same lease epoch, `cursor.last_key` must be lexicographically
/// non-decreasing.
///
/// **Safety (cursor bounds)**: `cursor.last_key` must fall within
/// the shard's `[spec.start, spec.end)`.
///
/// **Safety (split coverage)**: Split children must exactly partition
/// the parent's key range — no gaps, no overlaps.
///
/// **Safety (terminal irreversibility)**: Once a shard reaches Done,
/// Split, or Parked, no protocol operation changes its status.
///
/// **Liveness (lease expiry)**: If a worker fails to renew, its lease
/// expires and the shard becomes available for another worker.
///
/// ## Verification Strategy
///
/// The deterministic simulator exercises all operations with fault
/// injection (simulated crashes, lease expirations, concurrent
/// acquisitions). Property-based tests verify invariants hold across
/// random operation sequences.
///
/// Reference: FoundationDB simulation (Zhou et al., SIGMOD 2021);
///            TigerBeetle VOPR; Jepsen methodology.
pub trait CoordinationBackend {
    // —— Shard lifecycle operations ——————————————————————————————

    /// Acquire a shard for processing and restore its last checkpoint.
    ///
    /// This is the entry point for a worker to start or resume scanning
    /// a shard. If the shard is currently unleased (or its lease has
    /// expired), the backend grants a new lease to the requesting worker.
    ///
    /// ## Behavior
    ///
    /// 1. Look up the shard record by `(tenant, key)`.
    /// 2. Verify tenant isolation: `record.tenant == tenant`.
    /// 3. Verify shard is Active (not terminal).
    /// 4. If currently leased and lease is live at `now`: reject with
    ///    `AlreadyLeased`.
    /// 5. Increment `fence_epoch` (ownership transfer).
    /// 6. Set `lease_owner = worker`, `lease_deadline = now + lease_duration`.
    ///    `lease_duration` is a backend configuration parameter, not a
    ///    per-call argument.
    /// 7. Return `(Lease, ShardSnapshot)`.
    ///
    /// ## Idempotency
    ///
    /// `acquire_and_restore` is NOT idempotent via OpId. It is
    /// inherently non-idempotent: each call that succeeds increments
    /// the fence epoch. A worker that calls acquire twice gets two
    /// different leases (the first is immediately invalidated by the
    /// second's epoch bump).
    ///
    /// Workers that need to resume after a transient failure should
    /// simply call acquire again — the new lease supersedes the old.
    ///
    /// ## Invariants
    ///
    /// **Safety**: `fence_epoch` strictly increases on successful acquire.
    /// **Safety**: The returned `Lease.fence` matches the record's new epoch.
    /// **Safety**: The returned snapshot reflects the record's state at
    /// acquisition time (after epoch bump, before any worker mutations).
    fn acquire_and_restore(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
    ) -> Result<AcquireResult, AcquireError>;

    /// Renew an existing lease, extending the deadline.
    ///
    /// The worker calls this periodically to signal liveness and prevent
    /// its lease from expiring. The fence epoch does NOT change — this
    /// is a deadline extension, not an ownership transfer.
    ///
    /// ## Behavior
    ///
    /// 1. Validate lease (tenant, fence epoch, not expired at `now`).
    /// 2. Set `lease_deadline = now + lease_duration`.
    /// 3. Return the new deadline.
    ///
    /// ## Idempotency
    ///
    /// `renew` is NOT idempotent via OpId and has no op-log entry.
    /// Duplicate calls simply extend the deadline further, which is
    /// harmless — the lease remains valid for longer.
    ///
    /// ## Invariants
    ///
    /// **Safety**: The fence epoch does not change on renewal.
    /// **Safety**: The lease owner does not change on renewal.
    /// **Liveness**: The new deadline is strictly after `now`.
    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError>;

    /// Checkpoint: advance the cursor within the shard's key range.
    ///
    /// Records progress without changing shard status. The worker
    /// calls this periodically to persist scan progress so that
    /// a crash-recovery resumes from the last checkpoint, not from
    /// the beginning.
    ///
    /// ## Behavior
    ///
    /// 1. Check idempotency via `op_id` (see Idempotency below).
    ///    Idempotency is checked first so that replays succeed even
    ///    after the lease has expired or the shard has reached a
    ///    terminal status.
    /// 2. Validate lease (tenant, fence epoch, not expired at `now`).
    /// 3. Validate `new_cursor.last_key.is_some()`.
    /// 4. Validate cursor monotonicity: `new >= old` (lexicographic).
    /// 5. Validate cursor bounds: `last_key ∈ [spec.start, spec.end)`.
    /// 6. Update `cursor = new_cursor`.
    /// 7. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id`:
    /// - Same `(op_id, hash_checkpoint_payload(new_cursor))` → `Replayed(())`
    /// - Same `op_id`, different hash → `OpIdConflict`
    /// - New `op_id` → execute, record in op-log, `Executed(())`
    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError>;

    /// Complete: mark the shard as successfully done.
    ///
    /// Terminal operation. After completion, the shard's status is `Done`
    /// and no further mutations are accepted.
    ///
    /// The `final_cursor` records the worker's final position. It must
    /// satisfy the same monotonicity and bounds constraints as a
    /// checkpoint cursor.
    ///
    /// ## Behavior
    ///
    /// 1. Check idempotency via `op_id` (replay succeeds even after
    ///    lease expiry or terminal status).
    /// 2. Validate lease and preconditions.
    /// 3. Apply cursor constraints (monotonicity, bounds, non-empty key).
    /// 4. Set `status = Done`, `cursor = final_cursor`.
    /// 5. Release lease (`lease = None`).
    /// 6. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_complete_payload(final_cursor)`.
    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError>;

    /// Park: halt the shard due to an error condition.
    ///
    /// Terminal operation. After parking, the shard's status is `Parked`
    /// with the given reason. No further mutations are accepted.
    ///
    /// Unparking is an out-of-band admin operation (not part of this trait).
    ///
    /// ## Behavior
    ///
    /// 1. Check idempotency via `op_id` (replay succeeds even after
    ///    lease expiry or terminal status).
    /// 2. Validate lease and preconditions.
    /// 3. Set `status = Parked`, `park_reason = Some(reason)`.
    /// 4. Release lease.
    /// 5. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_park_payload(reason)`.
    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError>;

    /// SplitReplace: replace this shard with N child shards.
    ///
    /// Terminal operation for the parent (status → Split). Creates N
    /// new Active child shards whose key ranges collectively cover the
    /// parent's range exactly.
    ///
    /// ## Behavior
    ///
    /// 1. Check idempotency via `op_id` (replay succeeds even after
    ///    lease expiry or terminal status).
    /// 2. Validate lease and preconditions.
    /// 3. Validate split coverage via `validate_split_coverage`.
    /// 4. Derive deterministic child IDs via `derive_split_shard_id`
    ///    with `DerivedShardKind::Child` and index `spawned.len() + i`.
    /// 5. Create child ShardRecords (Active, initial cursors from plan).
    /// 6. Set parent status to Split, record children in `spawned`.
    /// 7. Release parent lease.
    /// 8. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_split_replace_payload(plan)`.
    /// On replay, returns the same child IDs without creating duplicates.
    ///
    /// NOTE(safety): Op-log eviction cannot affect split_replace replays.
    /// After split_replace, parent status becomes Split (terminal). No further
    /// ops can push entries, so the split_replace op_log entry is never evicted.
    /// `check_op_idempotency()` will always detect the replay.
    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError>;

    /// SplitResidual: shrink this shard and create a residual for the
    /// unprocessed remainder.
    ///
    /// Non-terminal for the parent (stays Active with a smaller range).
    /// Creates one new Active residual shard covering the upper portion
    /// of the original range.
    ///
    /// ## Behavior
    ///
    /// 1. Check idempotency via `op_id` (replay succeeds even after
    ///    lease expiry or terminal status).
    /// 2. Validate lease and preconditions.
    /// 3. Validate residual split via `validate_residual_split`.
    /// 4. Derive deterministic residual ID via `derive_split_shard_id`
    ///    with `DerivedShardKind::Residual` and index `spawned.len()`.
    /// 5. Update parent's spec to `plan.parent_new_spec`.
    /// 6. Create residual ShardRecord (Active).
    /// 7. Record residual in parent's `spawned`.
    /// 8. Parent keeps its lease (continues processing).
    /// 9. Record in op-log.
    ///
    /// ## Idempotency
    ///
    /// Idempotent via `op_id` + `hash_split_residual_payload(plan)`.
    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError>;
}
