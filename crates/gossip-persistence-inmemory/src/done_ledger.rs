//! In-memory reference implementation of [`DoneLedger`].
//!
//! See the [crate-level docs](crate) for architecture, completion modes, and
//! fault injection semantics.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use gossip_contracts::{
    identity::TenantId,
    persistence::{
        CommitHandle, DoneLedger, DoneLedgerCommitReceipt, DoneLedgerKey, DoneLedgerRecord,
        DoneLedgerStatus, OvidHash,
    },
};

use crate::{
    error::{CompletionOrder, InMemoryPersistenceError, InMemoryStoreKind, PendingWriteId},
    pending::{PendingOp, PendingState},
};

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct DoneLedgerPayload {
    records: Vec<DoneLedgerRecord>,
}

/// Mutable interior state of the in-memory done-ledger.
///
/// `durable` is the committed keyspace — the source of truth for
/// [`batch_get`](DoneLedger::batch_get) and [`snapshot`](InMemoryDoneLedger::snapshot).
///
/// `ops` + `order` form the pending-write queue. `ops` owns each operation's
/// payload and lifecycle state; `order` preserves insertion order so
/// [`release_next`](InMemoryDoneLedger::release_next) can drain FIFO or LIFO.
///
/// The three fault-injection counters (`fail_submit_remaining`,
/// `fail_commit_remaining`, `delay_next`) are decremented on use and operate
/// independently. See the [crate-level docs](crate) for evaluation order.
struct DoneLedgerState {
    durable: HashMap<DoneLedgerKey, DoneLedgerRecord>,
    ops: HashMap<PendingWriteId, PendingOp<DoneLedgerPayload, DoneLedgerCommitReceipt>>,
    order: VecDeque<PendingWriteId>,
    next_op_id: u64,
    auto_complete: bool,
    delay_next: usize,
    fail_submit_remaining: usize,
    fail_commit_remaining: usize,
}

impl Default for DoneLedgerState {
    fn default() -> Self {
        Self {
            durable: HashMap::new(),
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

struct DoneLedgerInner {
    state: Mutex<DoneLedgerState>,
    cv: Condvar,
}

impl Default for DoneLedgerInner {
    fn default() -> Self {
        Self {
            state: Mutex::new(DoneLedgerState::default()),
            cv: Condvar::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// In-memory reference implementation of [`DoneLedger`].
///
/// Cloning is cheap (`Arc` bump) and produces a handle to the **same** shared
/// state — this is intentional so that test harnesses can inject faults on one
/// handle while the system under test uses another.
///
/// All public methods acquire the internal mutex for the duration of the call.
/// Commit handles block on a [`Condvar`](std::sync::Condvar) until the
/// corresponding operation is released (delayed mode) or return immediately
/// (auto-complete mode).
#[derive(Clone, Default)]
pub struct InMemoryDoneLedger {
    inner: Arc<DoneLedgerInner>,
}

impl InMemoryDoneLedger {
    /// Create an empty done-ledger with auto-complete enabled.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty done-ledger with an explicit auto-complete mode.
    #[must_use]
    pub fn with_auto_complete(auto_complete: bool) -> Self {
        Self {
            inner: Arc::new(DoneLedgerInner {
                state: Mutex::new(DoneLedgerState {
                    auto_complete,
                    ..DoneLedgerState::default()
                }),
                cv: Condvar::new(),
            }),
        }
    }

    /// Toggle whether future submissions complete immediately.
    pub fn set_auto_complete(&self, auto_complete: bool) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.auto_complete = auto_complete;
        Ok(())
    }

    /// Delay the next `count` submissions. Delayed submissions remain pending
    /// until released explicitly.
    pub fn delay_next_writes(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.delay_next = guard.delay_next.saturating_add(count);
        Ok(())
    }

    /// Fail the next `count` submissions immediately.
    pub fn fail_next_submissions(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.fail_submit_remaining = guard.fail_submit_remaining.saturating_add(count);
        Ok(())
    }

    /// Fail the next `count` durable commits.
    pub fn fail_next_commits(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.fail_commit_remaining = guard.fail_commit_remaining.saturating_add(count);
        Ok(())
    }

    /// Release one delayed operation in the requested order.
    ///
    /// Returns `Ok(Some(id))` with the released operation's id, or `Ok(None)`
    /// if the pending queue is empty. Already-finished operations in the queue
    /// are silently skipped (this can happen if [`release_specific`](Self::release_specific)
    /// was called out-of-order).
    ///
    /// The released operation's payload is applied to the durable state under
    /// the same lock acquisition, and all waiting condvar threads are notified.
    pub fn release_next(
        &self,
        order: CompletionOrder,
    ) -> Result<Option<PendingWriteId>, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        // Walk the queue until we find a still-pending op or exhaust it.
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
        finish_done_ledger_op(&mut guard, op_id)?;
        self.inner.cv.notify_all();
        Ok(Some(op_id))
    }

    /// Release a specific delayed operation by id.
    ///
    /// The released operation's entry is removed from the `order` queue to
    /// prevent stale IDs from accumulating when `release_specific` is the
    /// primary release mechanism (instead of `release_next`).
    pub fn release_specific(
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
        finish_done_ledger_op(&mut guard, op_id)?;
        guard.order.retain(|id| *id != op_id);
        self.inner.cv.notify_all();
        Ok(true)
    }

    /// Release every currently delayed operation under a single lock
    /// acquisition.
    ///
    /// Only operations that are pending at the time of the call are released.
    /// Operations submitted concurrently *after* the call are not drained,
    /// preventing unbounded loops when writer threads are active.
    pub fn release_all(&self, order: CompletionOrder) -> Result<usize, InMemoryPersistenceError> {
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
        for op_id in pending {
            finish_done_ledger_op(&mut guard, op_id)?;
            guard.order.retain(|id| *id != op_id);
            released += 1;
        }
        if released > 0 {
            self.inner.cv.notify_all();
        }
        Ok(released)
    }

    /// Number of operations that are still pending durability.
    pub fn pending_count(&self) -> Result<usize, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard
            .ops
            .values()
            .filter(|op| op.state.is_pending())
            .count())
    }

    /// Pending operation ids in their current queue order.
    pub fn pending_ids(&self) -> Result<Vec<PendingWriteId>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard
            .order
            .iter()
            .copied()
            .filter(|op_id| guard.ops.get(op_id).is_some_and(|op| op.state.is_pending()))
            .collect())
    }

    /// Return the durable row for `key`, if present.
    pub fn get_record(
        &self,
        key: DoneLedgerKey,
    ) -> Result<Option<DoneLedgerRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard.durable.get(&key).cloned())
    }

    /// Return a sorted durable snapshot for assertions in downstream tests.
    ///
    /// Records are sorted by `(tenant_id, policy_hash, ovid_hash)` in
    /// byte-lexicographic order so that snapshot comparisons are deterministic
    /// regardless of `HashMap` iteration order.
    pub fn snapshot(&self) -> Result<Vec<DoneLedgerRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        let mut rows: Vec<_> = guard.durable.values().cloned().collect();
        rows.sort_by(|lhs, rhs| {
            lhs.key()
                .tenant_id()
                .as_bytes()
                .cmp(rhs.key().tenant_id().as_bytes())
                .then_with(|| {
                    lhs.key()
                        .policy_hash()
                        .as_bytes()
                        .cmp(rhs.key().policy_hash().as_bytes())
                })
                .then_with(|| {
                    lhs.key()
                        .ovid_hash()
                        .as_bytes()
                        .cmp(rhs.key().ovid_hash().as_bytes())
                })
        });
        Ok(rows)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, DoneLedgerState>, InMemoryPersistenceError> {
        self.inner
            .state
            .lock()
            .map_err(|_| InMemoryPersistenceError::Poisoned {
                store: InMemoryStoreKind::DoneLedger,
            })
    }
}

impl fmt::Debug for InMemoryDoneLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.lock_state() {
            Ok(guard) => f
                .debug_struct("InMemoryDoneLedger")
                .field("durable_rows", &guard.durable.len())
                .field(
                    "pending_ops",
                    &guard
                        .ops
                        .values()
                        .filter(|op| op.state.is_pending())
                        .count(),
                )
                .field("auto_complete", &guard.auto_complete)
                .finish(),
            Err(_) => f.write_str("InMemoryDoneLedger(<poisoned>)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Commit handle
// ---------------------------------------------------------------------------

/// Handle returned by [`InMemoryDoneLedger::batch_upsert`].
///
/// Calling [`wait`](CommitHandle::wait) blocks the current thread on the
/// shared condvar until the operation transitions to `Finished`. In
/// auto-complete mode the result is already available, so `wait` returns
/// immediately. In delayed mode, `wait` blocks until
/// [`release_next`](InMemoryDoneLedger::release_next) (or a similar release
/// method) applies the payload and notifies the condvar.
///
/// The handle is consumed by `wait` — attempting to wait twice is a
/// compile-time error. After `wait` returns, the operation entry is removed
/// from the internal map.
pub struct InMemoryDoneLedgerHandle {
    inner: Arc<DoneLedgerInner>,
    op_id: PendingWriteId,
}

impl InMemoryDoneLedgerHandle {
    /// Pending operation id associated with this handle.
    #[inline]
    #[must_use]
    pub const fn operation_id(&self) -> PendingWriteId {
        self.op_id
    }
}

impl fmt::Debug for InMemoryDoneLedgerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryDoneLedgerHandle")
            .field("op_id", &self.op_id)
            .finish()
    }
}

impl CommitHandle for InMemoryDoneLedgerHandle {
    type Receipt = DoneLedgerCommitReceipt;
    type Error = InMemoryPersistenceError;

    /// Block until this operation is durable (or fails).
    ///
    /// The wait loop re-acquires the mutex after each condvar wake-up and
    /// checks whether the operation has transitioned to `Finished`. On
    /// success the result is `take()`-n out of the `Option` (ensuring
    /// single-use semantics) and the operation entry is removed from the
    /// map so it cannot be observed by future `release_*` calls.
    fn wait(self) -> Result<Self::Receipt, Self::Error> {
        let mut guard =
            self.inner
                .state
                .lock()
                .map_err(|_| InMemoryPersistenceError::Poisoned {
                    store: InMemoryStoreKind::DoneLedger,
                })?;

        loop {
            let finished = match guard.ops.get_mut(&self.op_id) {
                Some(op) => match &mut op.state {
                    PendingState::Pending => None,
                    PendingState::Finished(result) => Some(result.take().ok_or(
                        InMemoryPersistenceError::UnknownOperation {
                            store: InMemoryStoreKind::DoneLedger,
                            op_id: self.op_id,
                        },
                    )),
                },
                None => {
                    return Err(InMemoryPersistenceError::UnknownOperation {
                        store: InMemoryStoreKind::DoneLedger,
                        op_id: self.op_id,
                    });
                }
            };

            if let Some(result) = finished {
                // Clean up: remove the entry so pending_count/pending_ids
                // no longer see this completed op.
                guard.ops.remove(&self.op_id);
                return result?;
            }

            guard = self
                .inner
                .cv
                .wait(guard)
                .map_err(|_| InMemoryPersistenceError::Poisoned {
                    store: InMemoryStoreKind::DoneLedger,
                })?;
        }
    }
}

// ---------------------------------------------------------------------------
// DoneLedger trait impl
// ---------------------------------------------------------------------------

impl DoneLedger for InMemoryDoneLedger {
    type Error = InMemoryPersistenceError;
    type CommitHandle = InMemoryDoneLedgerHandle;

    fn batch_get(
        &self,
        tenant_id: TenantId,
        policy_hash: gossip_contracts::identity::PolicyHash,
        ovid_hashes: &[OvidHash],
    ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
        let guard = self.lock_state()?;
        Ok(ovid_hashes
            .iter()
            .map(|ovid_hash| {
                let key = DoneLedgerKey::new(tenant_id, policy_hash, *ovid_hash);
                guard.durable.get(&key).cloned()
            })
            .collect())
    }

    fn batch_upsert(
        &self,
        records: &[DoneLedgerRecord],
    ) -> Result<Self::CommitHandle, Self::Error> {
        let mut guard = self.lock_state()?;

        if guard.fail_submit_remaining > 0 {
            guard.fail_submit_remaining -= 1;
            return Err(InMemoryPersistenceError::InjectedSubmissionFailure {
                store: InMemoryStoreKind::DoneLedger,
            });
        }

        let op_id = PendingWriteId::from_raw(guard.next_op_id);
        guard.next_op_id = guard.next_op_id.saturating_add(1);

        let mut op = PendingOp {
            payload: DoneLedgerPayload {
                records: records.to_vec(),
            },
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
            let result = apply_done_ledger_payload(&mut guard, &op.payload.records);
            op.state = PendingState::Finished(Some(result));
            guard.ops.insert(op_id, op);
            self.inner.cv.notify_all();
        }

        Ok(InMemoryDoneLedgerHandle {
            inner: Arc::clone(&self.inner),
            op_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal apply / finish / merge helpers
// ---------------------------------------------------------------------------

/// Apply a batch of done-ledger records to the durable state.
///
/// For each record, if the key already exists the incoming record is merged
/// with the existing one using [`merge_done_ledger_records`] (monotonic
/// lattice join). New keys are inserted directly.
///
/// The `fail_commit_remaining` counter is checked first — if positive the
/// entire batch is rejected without mutating `durable`.
fn apply_done_ledger_payload(
    state: &mut DoneLedgerState,
    records: &[DoneLedgerRecord],
) -> Result<DoneLedgerCommitReceipt, InMemoryPersistenceError> {
    if state.fail_commit_remaining > 0 {
        state.fail_commit_remaining -= 1;
        return Err(InMemoryPersistenceError::InjectedCommitFailure {
            store: InMemoryStoreKind::DoneLedger,
        });
    }

    for record in records {
        let key = record.key();
        match state.durable.get(&key) {
            Some(existing) => {
                let merged = merge_done_ledger_records(existing, record);
                state.durable.insert(key, merged);
            }
            None => {
                state.durable.insert(key, record.clone());
            }
        }
    }

    let receipt = DoneLedgerCommitReceipt::new(
        records.len() as u64,
        records
            .iter()
            .filter(|record| record.status().is_scanned())
            .count() as u64,
        records.iter().fold(0u64, |acc, record| {
            acc.saturating_add(record.findings_count() as u64)
        }),
    );
    Ok(receipt)
}

/// Transition a pending done-ledger operation to `Finished`.
///
/// Removes the op from the map to avoid the split-borrow limitation (we need
/// `&op.payload` and `&mut state` simultaneously), applies the payload, then
/// re-inserts the finished op. Already-finished ops are a no-op.
fn finish_done_ledger_op(
    state: &mut DoneLedgerState,
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
                store: InMemoryStoreKind::DoneLedger,
                op_id,
            });
        }
    };

    let result = apply_done_ledger_payload(state, &op.payload.records);
    op.state = PendingState::Finished(Some(result));
    state.ops.insert(op_id, op);
    Ok(())
}

/// Merge two done-ledger records for the same key, producing the dominant row.
///
/// # Merge algorithm
///
/// 1. **Status**: lattice join via [`DoneLedgerStatus::merge`] — the higher
///    rank wins, ensuring scanned states can never be downgraded.
/// 2. **Metrics**: `bytes_scanned` takes the max (monotonically increasing).
///    `findings_count` is status-aware: forced to 0 for `ScannedClean`,
///    forced to at least 1 for `ScannedWithFindings`, and max for other
///    statuses.
/// 3. **Provenance winner**: the record whose provenance is "freshest" is
///    chosen as the source of `provenance`, `error_code`, and display
///    metadata. Tie-breaking order:
///    - Higher status rank wins outright.
///    - Equal rank: later `finished_at` wins.
///    - Equal rank and `finished_at`: later `started_at` wins.
///    - Otherwise: keep `existing` (stable under no-op replays).
/// 4. **Error code**: cleared if the merged status is scanned (success
///    absorbs prior errors). Otherwise taken from the provenance winner,
///    falling back to the loser if the winner has none.
///
/// # Panics
///
/// Panics (via `expect`) if the merged fields violate `DoneLedgerRecord`
/// construction invariants. This should be unreachable because the lattice
/// join can only raise the status, never lower it, and `max()` on metrics
/// preserves consistency.
///
/// [`DoneLedgerStatus::merge`]: gossip_contracts::persistence::DoneLedgerStatus::merge
fn merge_done_ledger_records(
    existing: &DoneLedgerRecord,
    incoming: &DoneLedgerRecord,
) -> DoneLedgerRecord {
    let merged_status = existing.status().merge(incoming.status());
    let bytes_scanned = existing.bytes_scanned().max(incoming.bytes_scanned());
    let findings_count = match merged_status {
        DoneLedgerStatus::ScannedClean => 0,
        DoneLedgerStatus::ScannedWithFindings => existing
            .findings_count()
            .max(incoming.findings_count())
            .max(1),
        _ => existing.findings_count().max(incoming.findings_count()),
    };

    // Determine which record's provenance to trust for non-metric fields.
    let choose_incoming = incoming.status().rank() > existing.status().rank()
        || (incoming.status().rank() == existing.status().rank()
            && incoming.provenance().finished_at() > existing.provenance().finished_at())
        || (incoming.status().rank() == existing.status().rank()
            && incoming.provenance().finished_at() == existing.provenance().finished_at()
            && incoming.provenance().started_at() > existing.provenance().started_at());

    let chosen = if choose_incoming { incoming } else { existing };
    let fallback = if choose_incoming { existing } else { incoming };

    // Success absorbs prior error codes; otherwise prefer the winner's code.
    let error_code = if merged_status.is_scanned() {
        None
    } else {
        chosen
            .error_code()
            .cloned()
            .or_else(|| fallback.error_code().cloned())
    };

    DoneLedgerRecord::try_new(
        existing.key(),
        merged_status,
        bytes_scanned,
        findings_count,
        chosen.provenance(),
        error_code,
    )
    .expect("merged done-ledger record should preserve all record invariants")
}
