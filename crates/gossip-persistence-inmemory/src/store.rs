//! Generic in-memory store infrastructure shared by all persistence backends.
//!
//! [`InMemoryStoreCore`] captures the queue management, fault injection,
//! condvar coordination, and commit handle lifecycle that would otherwise be
//! duplicated in every backend module. Domain-specific behavior is injected
//! through the [`StoreBackend`] trait.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use crate::{
    error::{CompletionOrder, InMemoryPersistenceError, InMemoryStoreKind, PendingWriteId},
    pending::{PendingOp, PendingState},
};

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Domain-specific behavior that differs between persistence backends.
///
/// Implementors provide the payload type, receipt type, store kind tag, and
/// the function that applies a payload to the durable state.
pub(crate) trait StoreBackend: Send + 'static {
    /// The buffered write payload (e.g. a vec of records).
    type Payload: Send;

    /// The receipt returned to callers after a successful commit.
    type Receipt: Send;

    /// The mutable durable state that payloads are applied to.
    type Durable: Send + Default;

    /// Discriminator used in error variants.
    const STORE_KIND: InMemoryStoreKind;

    /// Apply `payload` to `durable`, consulting and mutating the fault
    /// injection counter `fail_commit_remaining`.
    ///
    /// Implementations must check `fail_commit_remaining` first and
    /// decrement it when injecting a commit failure.
    fn apply(
        durable: &mut Self::Durable,
        fail_commit_remaining: &mut usize,
        payload: &Self::Payload,
    ) -> Result<Self::Receipt, InMemoryPersistenceError>;
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Queue and fault-injection state shared by all in-memory backends.
pub(crate) struct StoreState<B: StoreBackend> {
    pub(crate) durable: B::Durable,
    ops: HashMap<PendingWriteId, PendingOp<B::Payload, B::Receipt>>,
    order: VecDeque<PendingWriteId>,
    next_op_id: u64,
    pub(crate) auto_complete: bool,
    delay_next: usize,
    fail_submit_remaining: usize,
    fail_commit_remaining: usize,
}

impl<B: StoreBackend> Default for StoreState<B> {
    fn default() -> Self {
        Self {
            durable: B::Durable::default(),
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

// ---------------------------------------------------------------------------
// Core (Mutex + Condvar wrapper)
// ---------------------------------------------------------------------------

/// Shared interior that wraps `StoreState<B>` with a mutex and condvar.
///
/// All public control methods (release, fault injection, pending queries) are
/// implemented here once. Domain wrappers hold `Arc<InMemoryStoreCore<B>>`
/// and delegate to these methods.
pub(crate) struct InMemoryStoreCore<B: StoreBackend> {
    pub(crate) state: Mutex<StoreState<B>>,
    pub(crate) cv: Condvar,
}

impl<B: StoreBackend> Default for InMemoryStoreCore<B> {
    fn default() -> Self {
        Self {
            state: Mutex::new(StoreState::default()),
            cv: Condvar::new(),
        }
    }
}

impl<B: StoreBackend> InMemoryStoreCore<B> {
    /// Create a core with an explicit auto-complete mode.
    pub(crate) fn with_auto_complete(auto_complete: bool) -> Self {
        Self {
            state: Mutex::new(StoreState {
                auto_complete,
                ..StoreState::default()
            }),
            cv: Condvar::new(),
        }
    }

    pub(crate) fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, StoreState<B>>, InMemoryPersistenceError> {
        self.state
            .lock()
            .map_err(|_| InMemoryPersistenceError::Poisoned {
                store: B::STORE_KIND,
            })
    }

    // -- Fault injection controls ------------------------------------------

    pub(crate) fn set_auto_complete(
        &self,
        auto_complete: bool,
    ) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.auto_complete = auto_complete;
        Ok(())
    }

    pub(crate) fn delay_next_writes(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.delay_next = guard.delay_next.saturating_add(count);
        Ok(())
    }

    pub(crate) fn fail_next_submissions(
        &self,
        count: usize,
    ) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.fail_submit_remaining = guard.fail_submit_remaining.saturating_add(count);
        Ok(())
    }

    pub(crate) fn fail_next_commits(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.fail_commit_remaining = guard.fail_commit_remaining.saturating_add(count);
        Ok(())
    }

    // -- Release controls --------------------------------------------------

    /// Release one delayed operation in the requested order.
    ///
    /// Returns `Ok(Some(id))` with the released operation's id, or `Ok(None)`
    /// if the pending queue is empty. Already-finished operations in the queue
    /// are silently skipped.
    pub(crate) fn release_next(
        &self,
        order: CompletionOrder,
    ) -> Result<Option<PendingWriteId>, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        let op_id = loop {
            let maybe = match order {
                CompletionOrder::OldestFirst => guard.order.pop_front(),
                CompletionOrder::NewestFirst => guard.order.pop_back(),
            };
            let Some(op_id) = maybe else {
                break None;
            };
            if guard
                .ops
                .get(&op_id)
                .is_some_and(|op| op.state.is_pending())
            {
                break Some(op_id);
            }
        };
        let Some(op_id) = op_id else {
            return Ok(None);
        };
        finish_op::<B>(&mut guard, op_id)?;
        self.cv.notify_all();
        Ok(Some(op_id))
    }

    /// Release a specific delayed operation by id.
    ///
    /// The released operation's entry is removed from the `order` queue to
    /// prevent stale IDs from accumulating.
    pub(crate) fn release_specific(
        &self,
        op_id: PendingWriteId,
    ) -> Result<bool, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        let is_pending = guard
            .ops
            .get(&op_id)
            .is_some_and(|op| op.state.is_pending());
        if !is_pending {
            return Ok(false);
        }
        finish_op::<B>(&mut guard, op_id)?;
        guard.order.retain(|id| *id != op_id);
        self.cv.notify_all();
        Ok(true)
    }

    /// Release every currently delayed operation under a single lock
    /// acquisition.
    ///
    /// Uses a `HashSet` for the drain filter to achieve O(n+m) complexity
    /// instead of the O(n*m) cost of linear search per retained element.
    pub(crate) fn release_all(
        &self,
        order: CompletionOrder,
    ) -> Result<usize, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;

        let mut pending: Vec<PendingWriteId> = guard
            .order
            .iter()
            .copied()
            .filter(|op_id| guard.ops.get(op_id).is_some_and(|op| op.state.is_pending()))
            .collect();
        if order == CompletionOrder::NewestFirst {
            pending.reverse();
        }

        let mut released = 0usize;
        for op_id in &pending {
            finish_op::<B>(&mut guard, *op_id)?;
            released += 1;
        }
        if released > 0 {
            let released_set: HashSet<PendingWriteId> = pending.iter().copied().collect();
            guard.order.retain(|id| !released_set.contains(id));
            self.cv.notify_all();
        }
        Ok(released)
    }

    // -- Query helpers -----------------------------------------------------

    /// Number of operations that are still pending durability.
    pub(crate) fn pending_count(&self) -> Result<usize, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard
            .ops
            .values()
            .filter(|op| op.state.is_pending())
            .count())
    }

    /// Pending operation ids in their current queue order.
    pub(crate) fn pending_ids(&self) -> Result<Vec<PendingWriteId>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard
            .order
            .iter()
            .copied()
            .filter(|op_id| guard.ops.get(op_id).is_some_and(|op| op.state.is_pending()))
            .collect())
    }

    // -- Submission --------------------------------------------------------

    /// Core submission logic: check fault injection, allocate an op id,
    /// decide delay vs auto-complete, and return the new handle.
    ///
    /// The caller must build the `payload` before calling this method.
    pub(crate) fn submit(
        self: &Arc<Self>,
        payload: B::Payload,
    ) -> Result<StoreHandle<B>, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;

        if guard.fail_submit_remaining > 0 {
            guard.fail_submit_remaining -= 1;
            return Err(InMemoryPersistenceError::InjectedSubmissionFailure {
                store: B::STORE_KIND,
            });
        }

        let op_id = PendingWriteId::from_raw(guard.next_op_id);
        guard.next_op_id = guard.next_op_id.checked_add(1).ok_or(
            InMemoryPersistenceError::InjectedSubmissionFailure {
                store: B::STORE_KIND,
            },
        )?;

        let mut op = PendingOp {
            payload,
            state: PendingState::Pending,
        };

        let should_delay = if guard.delay_next > 0 {
            guard.delay_next -= 1;
            true
        } else {
            !guard.auto_complete
        };

        if should_delay {
            guard.order.push_back(op_id);
            guard.ops.insert(op_id, op);
        } else {
            let state = &mut *guard;
            let result = B::apply(
                &mut state.durable,
                &mut state.fail_commit_remaining,
                &op.payload,
            );
            op.state = PendingState::Finished(Some(result));
            state.ops.insert(op_id, op);
            self.cv.notify_all();
        }

        Ok(StoreHandle {
            inner: Arc::clone(self),
            op_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Generic commit handle
// ---------------------------------------------------------------------------

/// Commit handle backed by the generic store core.
///
/// Calling [`wait`](CommitHandle::wait) blocks the current thread on the
/// shared condvar until the operation transitions to `Finished`.
pub(crate) struct StoreHandle<B: StoreBackend> {
    inner: Arc<InMemoryStoreCore<B>>,
    op_id: PendingWriteId,
}

impl<B: StoreBackend> StoreHandle<B> {
    /// Pending operation id associated with this handle.
    #[inline]
    pub(crate) const fn operation_id(&self) -> PendingWriteId {
        self.op_id
    }

    /// Block until this operation is durable (or fails).
    pub(crate) fn wait(self) -> Result<B::Receipt, InMemoryPersistenceError> {
        let mut guard =
            self.inner
                .state
                .lock()
                .map_err(|_| InMemoryPersistenceError::Poisoned {
                    store: B::STORE_KIND,
                })?;

        loop {
            let finished = match guard.ops.get_mut(&self.op_id) {
                Some(op) => match &mut op.state {
                    PendingState::Pending => None,
                    PendingState::Finished(result) => Some(result.take().ok_or(
                        InMemoryPersistenceError::UnknownOperation {
                            store: B::STORE_KIND,
                            op_id: self.op_id,
                        },
                    )),
                },
                None => {
                    return Err(InMemoryPersistenceError::UnknownOperation {
                        store: B::STORE_KIND,
                        op_id: self.op_id,
                    });
                }
            };

            if let Some(result) = finished {
                guard.ops.remove(&self.op_id);
                return result?;
            }

            guard = self
                .inner
                .cv
                .wait(guard)
                .map_err(|_| InMemoryPersistenceError::Poisoned {
                    store: B::STORE_KIND,
                })?;
        }
    }
}

// ---------------------------------------------------------------------------
// Internal finish helper
// ---------------------------------------------------------------------------

/// Transition a pending operation to `Finished` by applying its payload.
///
/// Removes the op from the map to avoid the split-borrow limitation (we need
/// `&op.payload` and `&mut state` simultaneously), applies the payload, then
/// re-inserts the finished op. Already-finished ops are a no-op.
fn finish_op<B: StoreBackend>(
    state: &mut StoreState<B>,
    op_id: PendingWriteId,
) -> Result<(), InMemoryPersistenceError> {
    let mut op = match state.ops.remove(&op_id) {
        Some(op) if op.state.is_pending() => op,
        Some(op) => {
            state.ops.insert(op_id, op);
            return Ok(());
        }
        None => {
            return Err(InMemoryPersistenceError::UnknownOperation {
                store: B::STORE_KIND,
                op_id,
            });
        }
    };

    let StoreState {
        ref mut durable,
        ref mut fail_commit_remaining,
        ..
    } = *state;
    let result = B::apply(durable, fail_commit_remaining, &op.payload);
    op.state = PendingState::Finished(Some(result));
    state.ops.insert(op_id, op);
    Ok(())
}
