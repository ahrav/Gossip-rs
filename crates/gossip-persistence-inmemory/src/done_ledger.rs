//! In-memory reference implementation of [`DoneLedger`].
//!
//! See the [crate-level docs](crate) for architecture, completion modes, and
//! fault injection semantics.

use std::{collections::HashMap, fmt, sync::Arc};

use gossip_contracts::{
    identity::TenantId,
    persistence::{
        CommitHandle, DoneLedger, DoneLedgerCommitReceipt, DoneLedgerKey, DoneLedgerRecord,
        DoneLedgerStatus, OvidHash,
    },
};

use crate::{
    error::{CompletionOrder, InMemoryPersistenceError, InMemoryStoreKind, PendingWriteId},
    store::{InMemoryStoreCore, StoreBackend, StoreHandle},
};

// ---------------------------------------------------------------------------
// Backend definition
// ---------------------------------------------------------------------------

pub(crate) struct DoneLedgerPayload {
    records: Vec<DoneLedgerRecord>,
}

/// Durable state for the done-ledger backend.
#[derive(Default)]
pub(crate) struct DoneLedgerDurable {
    rows: HashMap<DoneLedgerKey, DoneLedgerRecord>,
}

pub(crate) struct DoneLedgerBackend;

impl StoreBackend for DoneLedgerBackend {
    type Payload = DoneLedgerPayload;
    type Receipt = DoneLedgerCommitReceipt;
    type Durable = DoneLedgerDurable;

    const STORE_KIND: InMemoryStoreKind = InMemoryStoreKind::DoneLedger;

    fn apply(
        durable: &mut DoneLedgerDurable,
        fail_commit_remaining: &mut usize,
        payload: &DoneLedgerPayload,
    ) -> Result<DoneLedgerCommitReceipt, InMemoryPersistenceError> {
        if *fail_commit_remaining > 0 {
            *fail_commit_remaining -= 1;
            return Err(InMemoryPersistenceError::InjectedCommitFailure {
                store: InMemoryStoreKind::DoneLedger,
            });
        }

        for record in &payload.records {
            let key = record.key();
            match durable.rows.get(&key) {
                Some(existing) => {
                    let merged = merge_done_ledger_records(existing, record)?;
                    durable.rows.insert(key, merged);
                }
                None => {
                    durable.rows.insert(key, record.clone());
                }
            }
        }

        let receipt = DoneLedgerCommitReceipt::new(
            payload.records.len() as u64,
            payload
                .records
                .iter()
                .filter(|record| record.status().is_scanned())
                .count() as u64,
            payload.records.iter().fold(0u64, |acc, record| {
                acc.saturating_add(record.findings_count() as u64)
            }),
        );
        Ok(receipt)
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
    core: Arc<InMemoryStoreCore<DoneLedgerBackend>>,
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
            core: Arc::new(InMemoryStoreCore::with_auto_complete(auto_complete)),
        }
    }

    /// Toggle whether future submissions complete immediately.
    pub fn set_auto_complete(&self, auto_complete: bool) -> Result<(), InMemoryPersistenceError> {
        self.core.set_auto_complete(auto_complete)
    }

    /// Delay the next `count` submissions. Delayed submissions remain pending
    /// until released explicitly.
    pub fn delay_next_writes(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        self.core.delay_next_writes(count)
    }

    /// Fail the next `count` submissions immediately.
    pub fn fail_next_submissions(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        self.core.fail_next_submissions(count)
    }

    /// Fail the next `count` durable commits.
    pub fn fail_next_commits(&self, count: usize) -> Result<(), InMemoryPersistenceError> {
        self.core.fail_next_commits(count)
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
        self.core.release_next(order)
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
        self.core.release_specific(op_id)
    }

    /// Release every currently delayed operation under a single lock
    /// acquisition.
    ///
    /// Only operations that are pending at the time of the call are released.
    /// Operations submitted concurrently *after* the call are not drained,
    /// preventing unbounded loops when writer threads are active.
    pub fn release_all(&self, order: CompletionOrder) -> Result<usize, InMemoryPersistenceError> {
        self.core.release_all(order)
    }

    /// Number of operations that are still pending durability.
    pub fn pending_count(&self) -> Result<usize, InMemoryPersistenceError> {
        self.core.pending_count()
    }

    /// Pending operation ids in their current queue order.
    pub fn pending_ids(&self) -> Result<Vec<PendingWriteId>, InMemoryPersistenceError> {
        self.core.pending_ids()
    }

    /// Return the durable row for `key`, if present.
    pub fn get_record(
        &self,
        key: DoneLedgerKey,
    ) -> Result<Option<DoneLedgerRecord>, InMemoryPersistenceError> {
        let guard = self.core.lock_state()?;
        Ok(guard.durable.rows.get(&key).cloned())
    }

    /// Return a sorted durable snapshot for assertions in downstream tests.
    ///
    /// Records are sorted by `(tenant_id, policy_hash, ovid_hash)` in
    /// byte-lexicographic order so that snapshot comparisons are deterministic
    /// regardless of `HashMap` iteration order.
    pub fn snapshot(&self) -> Result<Vec<DoneLedgerRecord>, InMemoryPersistenceError> {
        let guard = self.core.lock_state()?;
        let mut rows: Vec<_> = guard.durable.rows.values().cloned().collect();
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
}

impl fmt::Debug for InMemoryDoneLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.core.lock_state() {
            Ok(guard) => f
                .debug_struct("InMemoryDoneLedger")
                .field("durable_rows", &guard.durable.rows.len())
                .field("pending_ops", &self.core.pending_count().unwrap_or(0))
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
    handle: StoreHandle<DoneLedgerBackend>,
}

impl InMemoryDoneLedgerHandle {
    /// Pending operation id associated with this handle.
    #[inline]
    #[must_use]
    pub fn operation_id(&self) -> PendingWriteId {
        self.handle.operation_id()
    }
}

impl fmt::Debug for InMemoryDoneLedgerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryDoneLedgerHandle")
            .field("op_id", &self.handle.operation_id())
            .finish()
    }
}

impl CommitHandle for InMemoryDoneLedgerHandle {
    type Receipt = DoneLedgerCommitReceipt;
    type Error = InMemoryPersistenceError;

    fn wait(self) -> Result<Self::Receipt, Self::Error> {
        self.handle.wait()
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
        let guard = self.core.lock_state()?;
        Ok(ovid_hashes
            .iter()
            .map(|ovid_hash| {
                let key = DoneLedgerKey::new(tenant_id, policy_hash, *ovid_hash);
                guard.durable.rows.get(&key).cloned()
            })
            .collect())
    }

    fn batch_upsert(
        &self,
        records: &[DoneLedgerRecord],
    ) -> Result<Self::CommitHandle, Self::Error> {
        let payload = DoneLedgerPayload {
            records: records.to_vec(),
        };
        let handle = self.core.submit(payload)?;
        Ok(InMemoryDoneLedgerHandle { handle })
    }
}

// ---------------------------------------------------------------------------
// Merge helper
// ---------------------------------------------------------------------------

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
/// # Errors
///
/// Returns an error if the merged fields violate `DoneLedgerRecord`
/// construction invariants. This should be unreachable because the lattice
/// join can only raise the status, never lower it, and `max()` on metrics
/// preserves consistency.
///
/// [`DoneLedgerStatus::merge`]: gossip_contracts::persistence::DoneLedgerStatus::merge
fn merge_done_ledger_records(
    existing: &DoneLedgerRecord,
    incoming: &DoneLedgerRecord,
) -> Result<DoneLedgerRecord, InMemoryPersistenceError> {
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

    Ok(DoneLedgerRecord::try_new(
        existing.key(),
        merged_status,
        bytes_scanned,
        findings_count,
        chosen.provenance(),
        error_code,
    )?)
}
