//! Shared internal types for the pending-write queue used by both the
//! done-ledger and findings backends.
//!
//! These types are crate-private — they encode the lifecycle state of a
//! single in-memory write operation and its buffered payload.
//!
//! [`PendingOps`] is the extracted queue that both [`DoneLedgerState`] and
//! [`FindingsState`] embed. It owns the operation map, insertion-order queue,
//! id counter, and all fault-injection counters. Domain-specific apply logic
//! (lattice merge for done-ledger, referential integrity for findings) remains
//! in each backend module.
//!
//! [`DoneLedgerState`]: crate::done_ledger
//! [`FindingsState`]: crate::findings

use std::collections::{HashMap, VecDeque};

use crate::error::{CompletionOrder, InMemoryPersistenceError, InMemoryStoreKind, PendingWriteId};

/// Lifecycle state of a single in-memory write operation.
///
/// `Pending` -> `Finished(Some(...))` is the only valid transition.
/// The `Option` wrapper inside `Finished` exists so that
/// [`CommitHandle::wait`](gossip_contracts::persistence::CommitHandle::wait)
/// can `take()` the result exactly once — a second `wait` on the same
/// operation sees `None` and returns `UnknownOperation`.
pub(crate) enum PendingState<R> {
    Pending,
    Finished(Option<Result<R, InMemoryPersistenceError>>),
}

impl<R> PendingState<R> {
    #[inline]
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// A buffered write operation: the payload to apply and its lifecycle state.
pub(crate) struct PendingOp<P, R> {
    pub(crate) payload: P,
    pub(crate) state: PendingState<R>,
}

/// Pending-write queue shared by both the done-ledger and findings backends.
///
/// Manages operation lifecycle (allocation, enqueue, finish), fault-injection
/// counters (submit/commit failures, delay), and query helpers. Domain-specific
/// apply logic (lattice merge for done-ledger, referential integrity for
/// findings) remains in each backend module — only the mechanical bookkeeping
/// is unified here.
pub(crate) struct PendingOps<P, R> {
    ops: HashMap<PendingWriteId, PendingOp<P, R>>,
    order: VecDeque<PendingWriteId>,
    next_op_id: u64,
    pub(crate) auto_complete: bool,
    pub(crate) delay_next: usize,
    pub(crate) fail_submit_remaining: usize,
    pub(crate) fail_commit_remaining: usize,
}

impl<P, R> Default for PendingOps<P, R> {
    fn default() -> Self {
        Self {
            ops: HashMap::new(),
            order: VecDeque::new(),
            next_op_id: 1,
            auto_complete: true,
            delay_next: 0,
            fail_submit_remaining: 0,
            fail_commit_remaining: 0,
        }
    }
}

impl<P, R> PendingOps<P, R> {
    /// Create with an explicit auto-complete mode.
    pub(crate) fn with_auto_complete(auto_complete: bool) -> Self {
        Self {
            auto_complete,
            ..Self::default()
        }
    }

    // -- Submission path --

    /// Check and decrement the submit-fault counter.
    pub(crate) fn check_submit_fault(
        &mut self,
        store: InMemoryStoreKind,
    ) -> Result<(), InMemoryPersistenceError> {
        if self.fail_submit_remaining > 0 {
            self.fail_submit_remaining -= 1;
            return Err(InMemoryPersistenceError::InjectedSubmissionFailure { store });
        }
        Ok(())
    }

    /// Allocate the next operation id.
    pub(crate) fn allocate_op_id(&mut self) -> PendingWriteId {
        let id = PendingWriteId::from_raw(self.next_op_id);
        self.next_op_id = self.next_op_id.saturating_add(1);
        id
    }

    /// Determine whether the current submission should be delayed.
    ///
    /// Returns `true` if `delay_next > 0` (decrementing the counter) or if
    /// `auto_complete` is disabled. The caller enqueues the op when this
    /// returns `true`, or applies it immediately when `false`.
    pub(crate) fn should_delay(&mut self) -> bool {
        if self.delay_next > 0 {
            self.delay_next -= 1;
            true
        } else {
            !self.auto_complete
        }
    }

    /// Check and decrement the commit-fault counter.
    pub(crate) fn check_commit_fault(
        &mut self,
        store: InMemoryStoreKind,
    ) -> Result<(), InMemoryPersistenceError> {
        if self.fail_commit_remaining > 0 {
            self.fail_commit_remaining -= 1;
            return Err(InMemoryPersistenceError::InjectedCommitFailure { store });
        }
        Ok(())
    }

    /// Enqueue a pending (delayed) operation into both the map and the
    /// insertion-order queue.
    pub(crate) fn enqueue_pending(&mut self, op_id: PendingWriteId, op: PendingOp<P, R>) {
        self.order.push_back(op_id);
        self.ops.insert(op_id, op);
    }

    /// Insert a finished (auto-completed) operation into the map only.
    pub(crate) fn insert_finished(&mut self, op_id: PendingWriteId, op: PendingOp<P, R>) {
        self.ops.insert(op_id, op);
    }

    // -- Release path --

    /// Pop the next still-pending operation id from the queue.
    ///
    /// Skips already-finished entries that accumulate when
    /// [`release_specific`](Self) is used out of queue order.
    pub(crate) fn find_next_pending(&mut self, order: CompletionOrder) -> Option<PendingWriteId> {
        loop {
            let maybe = match order {
                CompletionOrder::OldestFirst => self.order.pop_front(),
                CompletionOrder::NewestFirst => self.order.pop_back(),
            };
            let op_id = maybe?;
            if self.ops.get(&op_id).is_some_and(|op| op.state.is_pending()) {
                return Some(op_id);
            }
        }
    }

    /// Check whether a specific operation is still pending.
    pub(crate) fn is_pending(&self, op_id: PendingWriteId) -> bool {
        self.ops.get(&op_id).is_some_and(|op| op.state.is_pending())
    }

    /// Collect all currently pending operation ids in queue order.
    pub(crate) fn collect_pending_ordered(&self, order: CompletionOrder) -> Vec<PendingWriteId> {
        let mut ids: Vec<PendingWriteId> = self
            .order
            .iter()
            .copied()
            .filter(|op_id| self.ops.get(op_id).is_some_and(|op| op.state.is_pending()))
            .collect();
        if order == CompletionOrder::NewestFirst {
            ids.reverse();
        }
        ids
    }

    /// Remove an operation id from the insertion-order queue.
    pub(crate) fn remove_from_order(&mut self, op_id: PendingWriteId) {
        self.order.retain(|id| *id != op_id);
    }

    // -- Query --

    /// Number of operations still in `Pending` state.
    pub(crate) fn pending_count(&self) -> usize {
        self.ops.values().filter(|op| op.state.is_pending()).count()
    }

    /// Pending operation ids in their current queue order.
    pub(crate) fn pending_ids(&self) -> Vec<PendingWriteId> {
        self.order
            .iter()
            .copied()
            .filter(|op_id| self.ops.get(op_id).is_some_and(|op| op.state.is_pending()))
            .collect()
    }

    // -- Direct map access (used by CommitHandle::wait and finish_*_op) --

    /// Get a mutable reference to an operation by id.
    pub(crate) fn get_mut(&mut self, op_id: PendingWriteId) -> Option<&mut PendingOp<P, R>> {
        self.ops.get_mut(&op_id)
    }

    /// Remove an operation from the map, returning it if present.
    pub(crate) fn remove(&mut self, op_id: PendingWriteId) -> Option<PendingOp<P, R>> {
        self.ops.remove(&op_id)
    }

    /// Insert an operation into the map.
    pub(crate) fn insert(&mut self, op_id: PendingWriteId, op: PendingOp<P, R>) {
        self.ops.insert(op_id, op);
    }
}
