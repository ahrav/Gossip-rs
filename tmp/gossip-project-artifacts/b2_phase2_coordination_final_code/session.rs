//! Ergonomic `WorkerSession` wrapper for shard operations.
//!
//! Binds a coordination backend, tenant, worker, and active lease into
//! a convenient handle that threads common parameters through every call.
//!
//! ## Design (D2.26)
//!
//! - Generic over backend (no trait object overhead on hot path)
//! - Borrows the backend mutably (`&'b mut B`) — enforces single session
//!   per backend reference via Rust's borrow checker
//! - Does NOT auto-renew the lease — the worker is responsible for
//!   calling `renew()` before deadline; automatic renewal requires a
//!   timer/scheduler, which is a runtime concern outside the contract
//! - Terminal operations (`complete`, `park`, `split_replace`) consume
//!   the session — the session cannot be used after terminal transition
//! - `split_residual` borrows `&mut self` — the parent stays Active
//!
//! Reference: FoundationDB simulation approach (synchronous, deterministic).

use crate::identity::{
    LogicalTime, OpId, ShardKey, TenantId, WorkerId,
};
use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, AcquireResult, CheckpointError, CompleteError,
    IdempotentOutcome, ParkError, RenewError, RenewResult,
    SplitReplaceError, SplitResidualError,
};
use crate::coordination::lease::Lease;
use crate::coordination::record::{ParkReason, ShardSnapshot};
use crate::coordination::shard_spec::ShardSpec;
use crate::coordination::split::{
    SplitReplacePlan, SplitReplaceResult,
    SplitResidualPlan, SplitResidualResult,
};
use crate::coordination::traits::CoordinationBackend;

/// Ergonomic wrapper that binds a coordination backend, tenant, worker,
/// and active lease for less repetitive API usage.
///
/// ## Lifecycle
///
/// ```text
/// 1. WorkerSession::acquire(backend, now, tenant, key, worker)
/// 2. session.checkpoint(...), session.renew(...)
/// 3. session.complete(...) or session.park(...)  [consumes session]
/// ```
pub struct WorkerSession<'b, B: CoordinationBackend> {
    backend: &'b mut B,
    tenant: TenantId,
    worker: WorkerId,
    lease: Lease,
    snapshot: ShardSnapshot,
}

impl<'b, B: CoordinationBackend> WorkerSession<'b, B> {
    /// Acquire a shard and create a new session.
    pub fn acquire(
        backend: &'b mut B,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
    ) -> Result<Self, AcquireError> {
        let result = backend.acquire_and_restore(now, tenant, key, worker)?;
        Ok(Self {
            backend,
            tenant,
            worker,
            lease: result.lease,
            snapshot: result.snapshot,
        })
    }

    /// The active lease.
    #[inline]
    pub fn lease(&self) -> &Lease { &self.lease }

    /// The shard snapshot from acquisition time.
    ///
    /// Does NOT reflect subsequent checkpoints — use this to determine
    /// where to resume scanning.
    #[inline]
    pub fn snapshot(&self) -> &ShardSnapshot { &self.snapshot }

    /// The shard's spec (key range + metadata).
    #[inline]
    pub fn spec(&self) -> &ShardSpec { &self.snapshot.spec }

    /// The cursor at acquisition time.
    #[inline]
    pub fn cursor(&self) -> &Cursor { &self.snapshot.cursor }

    /// The tenant this session is scoped to.
    #[inline]
    pub fn tenant(&self) -> TenantId { self.tenant }

    /// The worker that owns this session.
    #[inline]
    pub fn worker(&self) -> WorkerId { self.worker }

    /// The shard key (run + shard_id).
    #[inline]
    pub fn shard_key(&self) -> ShardKey {
        ShardKey {
            run: self.lease.run,
            shard: self.lease.shard,
        }
    }

    /// Renew the lease, extending the deadline.
    /// Updates the internal lease deadline on success.
    pub fn renew(
        &mut self,
        now: LogicalTime,
    ) -> Result<RenewResult, RenewError> {
        let result = self.backend.renew(now, self.tenant, &self.lease)?;
        self.lease.deadline = result.new_deadline;
        Ok(result)
    }

    /// Checkpoint: advance the cursor.
    pub fn checkpoint(
        &mut self,
        now: LogicalTime,
        new_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        self.backend
            .checkpoint(now, self.tenant, &self.lease, new_cursor, op_id)
    }

    /// Complete: mark the shard as done. **Consumes the session.**
    pub fn complete(
        self,
        now: LogicalTime,
        final_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.backend
            .complete(now, self.tenant, &self.lease, final_cursor, op_id)
    }

    /// Park: halt the shard. **Consumes the session.**
    pub fn park(
        self,
        now: LogicalTime,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.backend
            .park_shard(now, self.tenant, &self.lease, reason, op_id)
    }

    /// SplitReplace: replace this shard with children.
    /// **Consumes the session** (parent becomes terminal).
    pub fn split_replace(
        self,
        now: LogicalTime,
        plan: SplitReplacePlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        self.backend
            .split_replace(now, self.tenant, &self.lease, plan, op_id)
    }

    /// SplitResidual: shrink this shard and create a residual.
    /// Does **NOT** consume the session — parent stays Active.
    pub fn split_residual(
        &mut self,
        now: LogicalTime,
        plan: SplitResidualPlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        self.backend
            .split_residual(now, self.tenant, &self.lease, plan, op_id)
    }
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    // WorkerSession is a thin delegation wrapper. Its correctness follows
    // from the correctness of the underlying CoordinationBackend methods.
    // Full behavioral tests live in the in_memory.rs test suite.

    // TODO: test session_acquire_ok
    //   - Acquire via WorkerSession::acquire → verify lease, snapshot
    //   - session.tenant() == tenant, session.worker() == worker

    // TODO: test session_renew_updates_deadline
    //   - Acquire → renew → session.lease().deadline updated

    // TODO: test session_checkpoint_delegates
    //   - Acquire → checkpoint → verify cursor advanced in backend

    // TODO: test session_complete_consumes
    //   - Acquire → complete → session dropped (compile-time: can't reuse)

    // TODO: test session_park_consumes
    //   - Acquire → park → session dropped

    // TODO: test session_split_replace_consumes
    //   - Acquire → split_replace → session dropped, children exist

    // TODO: test session_split_residual_keeps_session
    //   - Acquire → split_residual → session still usable
    //   - Can still checkpoint/renew after split_residual

    // TODO: test session_shard_key
    //   - session.shard_key() matches the acquired shard
}
