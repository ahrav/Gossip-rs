//! Generic in-memory store infrastructure shared by all persistence backends.
//!
//! # Problem
//!
//! Both the done-ledger and findings backends need identical machinery for
//! pending-write queuing, condvar-based durability signaling, fault injection,
//! and commit-handle lifecycle management. Without a shared core, every backend
//! would duplicate this coordination logic — a maintenance and correctness
//! hazard.
//!
//! # Design
//!
//! [`InMemoryStoreCore`] is the generic interior that owns all of that shared
//! machinery. Domain-specific behavior — how a payload is applied to durable
//! state — is injected through the [`StoreBackend`] trait. Each public wrapper
//! (`InMemoryDoneLedger`, `InMemoryFindingsSink`) holds an
//! `Arc<InMemoryStoreCore<B>>` and delegates control/release/query methods.
//!
//! # Operation lifecycle
//!
//! ```text
//!   submit()
//!     │
//!     ├─ fail_submit_remaining > 0 ──► InjectedSubmissionFailure (no state change)
//!     │
//!     ├─ delay_next > 0 or !auto_complete
//!     │     └─► op inserted as Pending into `ops` + `order` queue
//!     │         └─► caller gets StoreHandle, wait() blocks on condvar
//!     │             └─► release_next / release_specific / release_all
//!     │                   └─► finish_op() applies payload ──► condvar.notify_all()
//!     │
//!     └─ auto_complete (default)
//!           └─► B::apply() runs immediately under the lock
//!               └─► op inserted as Finished ──► condvar.notify_all()
//!                   └─► wait() returns at once
//! ```
//!
//! # Invariants
//!
//! - **Op IDs are monotonically increasing**: `next_op_id` starts at 1 and is
//!   incremented with `checked_add`, preventing wrap-around.
//! - **`order` queue only tracks delayed ops**: auto-completed ops are never
//!   pushed to `order`, so the queue faithfully represents the pending backlog.
//! - **Single-consumer results**: each `Finished` result is wrapped in
//!   `Option` and consumed via `take()` by the first `wait()` call. A second
//!   `wait()` on the same op (impossible at compile time since `wait` consumes
//!   `self`) would see `None`.
//! - **Condvar wake is conservative**: `notify_all` is called after every
//!   state transition to `Finished`, even for auto-completed ops. This is
//!   correct but over-notifies — acceptable for a test/simulation backend.
//! - **Lock ordering**: there is exactly one mutex per `InMemoryStoreCore`
//!   instance. No code path acquires a second lock while holding this one,
//!   eliminating deadlock risk.

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
/// Each implementor defines five items:
///
/// 1. The **payload** type buffered by a pending write (e.g. a vec of records).
/// 2. The **receipt** returned to callers after a successful commit.
/// 3. The **durable state** that payloads are applied to.
/// 4. The **store kind** discriminator used in error variants.
/// 5. The **apply** function that performs the domain-specific mutation.
///
/// # Contract
///
/// `apply` is called under the `StoreState` mutex — it must not block on
/// external I/O or acquire other locks. The `fail_commit_remaining` counter
/// is passed by mutable reference so that each backend can check it at the
/// top of `apply` and decrement it to inject a commit failure *before*
/// mutating durable state. This keeps fault injection deterministic and
/// ensures partial mutations never occur on injected failures.
///
/// # Implementors
///
/// - `DoneLedgerBackend` — monotonic lattice merge for done-ledger records.
/// - `FindingsBackend` — referential integrity enforcement for findings,
///   occurrences, and observations.
pub(crate) trait StoreBackend: Send + 'static {
    /// The buffered write payload (e.g. a vec of records).
    type Payload: Send;

    /// The receipt returned to callers after a successful commit.
    type Receipt: Send;

    /// The mutable durable state that payloads are applied to.
    type Durable: Send + Default;

    /// Discriminator used in error variants to identify which backend
    /// produced the error without requiring downcasting.
    const STORE_KIND: InMemoryStoreKind;

    /// Apply `payload` to `durable`, producing a receipt on success.
    ///
    /// # Fault injection protocol
    ///
    /// Implementations **must** check `fail_commit_remaining` before any
    /// mutation. If the counter is non-zero, decrement it and return
    /// [`InjectedCommitFailure`](InMemoryPersistenceError::InjectedCommitFailure)
    /// without touching `durable`. This guarantees that injected failures
    /// leave durable state unchanged.
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
///
/// Operations live in two parallel structures:
///
/// - **`ops`** (`HashMap`): keyed by `PendingWriteId`, stores the payload and
///   lifecycle state (`Pending` or `Finished`). Both delayed and auto-completed
///   ops are inserted here so that `StoreHandle::wait` can look up results by
///   id regardless of completion mode.
/// - **`order`** (`VecDeque`): tracks submission order for delayed ops only.
///   Used by `release_next` to drain in FIFO/LIFO order. Auto-completed ops
///   are never pushed here.
///
/// # Fault injection counters
///
/// Three independent, monotonically decremented counters control failure
/// injection. They are checked in the order listed during each submission:
///
/// 1. `fail_submit_remaining` — rejects before handle creation (submission
///    failure).
/// 2. `delay_next` / `auto_complete` — determines whether the accepted write
///    is delayed or applied immediately.
/// 3. `fail_commit_remaining` — checked inside `B::apply()` at commit time.
///
/// All counters use `saturating_add` when incremented, preventing overflow
/// when tests configure multiple rounds of failures.
pub(crate) struct StoreState<B: StoreBackend> {
    /// Backend-specific durable state (e.g. the `HashMap` of records).
    pub(crate) durable: B::Durable,
    /// All operations indexed by id, both pending and recently finished.
    /// Finished entries are removed when `StoreHandle::wait` consumes them.
    ops: HashMap<PendingWriteId, PendingOp<B::Payload, B::Receipt>>,
    /// Submission-order queue of delayed operations awaiting manual release.
    /// Auto-completed operations are never added to this queue.
    order: VecDeque<PendingWriteId>,
    /// Monotonically increasing counter for the next operation id. Starts at 1
    /// so that id 0 is never issued (useful as a sentinel in tests).
    next_op_id: u64,
    /// When `true`, submissions are applied immediately rather than enqueued.
    pub(crate) auto_complete: bool,
    /// Number of upcoming submissions to force-delay regardless of
    /// `auto_complete`. Decremented on each delayed submission.
    delay_next: usize,
    /// Remaining submissions to reject with `InjectedSubmissionFailure`.
    fail_submit_remaining: usize,
    /// Remaining commits to fail with `InjectedCommitFailure`. Passed to
    /// `B::apply()` which is responsible for checking and decrementing it.
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

/// Shared interior that wraps [`StoreState`] with a mutex and condvar.
///
/// This is the single synchronization point for each backend. All public
/// control methods — fault injection, release, pending queries — are
/// implemented here once. Domain-specific wrappers (`InMemoryDoneLedger`,
/// `InMemoryFindingsSink`) hold `Arc<InMemoryStoreCore<B>>` and delegate to
/// these methods, adding only payload construction and trait-impl boilerplate.
///
/// # Condvar protocol
///
/// The condvar is signaled (`notify_all`) whenever any operation transitions
/// to `Finished`. Waiters (`StoreHandle::wait`) re-check their specific op id
/// after each wake, tolerating spurious wakes and wakes for other operations.
/// `notify_all` (rather than `notify_one`) is used because multiple handles
/// may be waiting on different operations simultaneously, and the condvar is
/// shared across all of them.
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
    ///
    /// Pass `false` to start in delayed mode, where all submissions are
    /// enqueued as pending and must be released explicitly.
    pub(crate) fn with_auto_complete(auto_complete: bool) -> Self {
        Self {
            state: Mutex::new(StoreState {
                auto_complete,
                ..StoreState::default()
            }),
            cv: Condvar::new(),
        }
    }

    /// Acquire the state mutex, converting a poisoned lock into the
    /// backend-specific `Poisoned` error variant.
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

    /// Toggle the auto-complete mode for all future submissions.
    ///
    /// When `auto_complete` is `true` (the default), submissions apply their
    /// payload immediately and the returned handle's `wait()` returns at once.
    /// When `false`, submissions are enqueued and block until explicitly
    /// released.
    pub(crate) fn set_auto_complete(
        &self,
        auto_complete: bool,
    ) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.auto_complete = auto_complete;
        Ok(())
    }

    /// Force the next `count` submissions to be delayed, regardless of
    /// `auto_complete`.
    ///
    /// The `delay_next` counter takes priority over `auto_complete`: even if
    /// auto-complete is on, the next `count` writes will be enqueued as
    /// pending. This allows mixed-mode operation within a single test
    /// without toggling `auto_complete` back and forth.
    ///
    /// Calls are additive — `delay_next_writes(2)` followed by
    /// `delay_next_writes(3)` delays 5 writes total (saturating addition).
    pub(crate) fn delay_next_writes(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.delay_next = guard.delay_next.saturating_add(count);
        Ok(())
    }

    /// Fail the next `count` submissions with `InjectedSubmissionFailure`.
    ///
    /// Submission failures are checked before any state mutation — no handle
    /// is created, no op id is allocated, and the durable state is untouched.
    /// This simulates backend unavailability at the request-acceptance layer.
    pub(crate) fn fail_next_submissions(
        &self,
        count: usize,
    ) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.fail_submit_remaining = guard.fail_submit_remaining.saturating_add(count);
        Ok(())
    }

    /// Fail the next `count` commits with `InjectedCommitFailure`.
    ///
    /// Unlike submission failures, commit failures occur at apply time — the
    /// caller receives a valid handle, but `wait()` returns the injected error.
    /// This simulates fsync/replication failures in real backends.
    pub(crate) fn fail_next_commits(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.fail_commit_remaining = guard.fail_commit_remaining.saturating_add(count);
        Ok(())
    }

    // -- Release controls --------------------------------------------------

    /// Release one delayed operation in the requested order.
    ///
    /// Pops entries from the `order` queue (front for `OldestFirst`, back for
    /// `NewestFirst`) until it finds one that is still `Pending`, then applies
    /// its payload via [`finish_op`]. Already-finished entries are silently
    /// discarded — this can happen when `release_specific` was used to
    /// complete an op out of queue order.
    ///
    /// Returns `Ok(Some(id))` with the released operation's id, or `Ok(None)`
    /// if no pending operations remain in the queue.
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
            // Stale entry (already finished via release_specific) — skip it.
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
    /// Returns `Ok(true)` if the operation was pending and has now been
    /// applied, or `Ok(false)` if the id is unknown or already finished.
    ///
    /// The released operation's entry is explicitly removed from the `order`
    /// queue via `retain` to prevent stale IDs from accumulating. This is
    /// O(n) in queue length, acceptable for a test backend.
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
    /// Only operations that are `Pending` at snapshot time are released.
    /// Operations submitted concurrently after the snapshot are not drained,
    /// preventing unbounded loops when writer threads are active.
    ///
    /// The `order` parameter controls the apply sequence: `OldestFirst`
    /// (FIFO) is the natural drain; `NewestFirst` (LIFO) lets tests exercise
    /// out-of-order durability.
    ///
    /// # Complexity
    ///
    /// Uses a `HashSet` for the queue cleanup pass to achieve O(n+m)
    /// (n = queue length, m = released count) instead of the O(n*m)
    /// cost of per-element linear search via `retain`.
    pub(crate) fn release_all(
        &self,
        order: CompletionOrder,
    ) -> Result<usize, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;

        // Snapshot pending ops before mutation so concurrent submitters
        // cannot extend the set we drain.
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

    /// Submit a payload for durability, returning a handle that can be
    /// waited on for the commit result.
    ///
    /// This is the primary entry point for all write operations. The caller
    /// (a domain wrapper) constructs the `payload` and passes it here; all
    /// queuing, fault injection, and completion logic is handled generically.
    ///
    /// # Execution order
    ///
    /// 1. Check `fail_submit_remaining` — if non-zero, reject immediately.
    /// 2. Allocate a monotonic op id.
    /// 3. Determine delay: `delay_next > 0` takes priority over
    ///    `auto_complete`. This lets callers force a specific number of
    ///    delayed writes without toggling the global mode.
    /// 4. If delayed: enqueue in `ops` + `order`, return a blocking handle.
    ///    If auto-complete: apply the payload now, store the `Finished`
    ///    result, notify waiters, return a handle that resolves immediately.
    ///
    /// # Errors
    ///
    /// - `InjectedSubmissionFailure` — the `fail_submit_remaining` counter
    ///   was non-zero (no state change occurs).
    /// - `InjectedSubmissionFailure` — op id counter overflow (should be
    ///   unreachable in practice with `u64`).
    ///
    /// Note: for auto-completed writes, errors from `B::apply()` do **not**
    /// cause `submit` to fail. Instead, the error is stored inside the
    /// operation's `Finished` state and surfaced when `StoreHandle::wait`
    /// is called.
    pub(crate) fn submit(
        self: &Arc<Self>,
        payload: B::Payload,
    ) -> Result<StoreHandle<B>, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;

        // Phase 1: Submission fault injection — reject before any state change.
        if guard.fail_submit_remaining > 0 {
            guard.fail_submit_remaining -= 1;
            return Err(InMemoryPersistenceError::InjectedSubmissionFailure {
                store: B::STORE_KIND,
            });
        }

        // Phase 2: Allocate a unique, monotonically increasing op id.
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

        // Phase 3: delay_next takes priority over auto_complete, allowing
        // per-submission delay overrides without toggling global mode.
        let should_delay = if guard.delay_next > 0 {
            guard.delay_next -= 1;
            true
        } else {
            !guard.auto_complete
        };

        // Phase 4: Enqueue or apply.
        if should_delay {
            guard.order.push_back(op_id);
            guard.ops.insert(op_id, op);
        } else {
            // Reborrow through a local to satisfy the borrow checker: we
            // need `&mut state.durable` and `&mut state.fail_commit_remaining`
            // simultaneously, which requires destructuring through `&mut *guard`.
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
/// Each handle is a lightweight `(Arc, PendingWriteId)` pair. Calling
/// [`wait`](StoreHandle::wait) blocks the current thread on the shared
/// condvar until the operation transitions to `Finished`, then extracts
/// the result and removes the operation entry from the map.
///
/// # Single-use consumption
///
/// `wait` takes `self` by value, so a handle can only be consumed once.
/// After `wait` returns, the operation's entry is removed from the `ops`
/// map. If the entry was somehow already consumed (should be impossible
/// at the type level), `UnknownOperation` is returned.
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

    /// Block until this operation is durable (or fails), consuming the handle.
    ///
    /// The wait loop re-acquires the mutex after each condvar wake and checks
    /// whether this specific operation has transitioned to `Finished`. Spurious
    /// wakes and wakes for other operations are handled by looping.
    ///
    /// On success, the `Finished` result is `take()`n out of the `Option`
    /// (consuming it) and the operation entry is removed from the `ops` map.
    /// This ensures no stale entries accumulate across the lifetime of the
    /// store.
    ///
    /// # Errors
    ///
    /// - `UnknownOperation` — the op id was not found in the map (indicates
    ///   a bug or double-wait, which the type system prevents).
    /// - `Poisoned` — the mutex was poisoned by a panic in another thread.
    /// - Any `InMemoryPersistenceError` produced by `B::apply()` during
    ///   commit (e.g. `InjectedCommitFailure`, referential integrity errors).
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
                // Clean up the finished entry to prevent unbounded map growth.
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
/// # Borrow-checker dance
///
/// We need `&op.payload` (immutable) and `&mut state.durable` (mutable)
/// simultaneously, but both live inside `state.ops` / `state`. Rust's
/// borrow checker cannot prove these do not alias through the `HashMap`.
/// The workaround is a **remove → apply → reinsert** sequence:
///
/// 1. Remove the op from `ops` (now we own it independently).
/// 2. Destructure `state` to get `&mut durable` and `&mut fail_commit_remaining`.
/// 3. Call `B::apply()` with the owned `op.payload` and the destructured refs.
/// 4. Store the result in `op.state` and reinsert.
///
/// Already-finished ops (e.g. from a concurrent `release_specific` call)
/// are silently reinserted without re-applying.
///
/// # Errors
///
/// Returns `UnknownOperation` if the op id is not in the map. Errors from
/// `B::apply()` (including injected commit failures) are stored in the
/// operation's `Finished` state and surfaced when the handle is waited on —
/// this function itself returns `Ok(())` in that case.
fn finish_op<B: StoreBackend>(
    state: &mut StoreState<B>,
    op_id: PendingWriteId,
) -> Result<(), InMemoryPersistenceError> {
    let mut op = match state.ops.remove(&op_id) {
        Some(op) if op.state.is_pending() => op,
        Some(op) => {
            // Already finished — reinsert without re-applying.
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
