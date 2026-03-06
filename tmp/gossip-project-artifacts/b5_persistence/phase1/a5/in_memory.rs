//! In-memory persistence backends for tests and deterministic simulation.
//!
//! These are **reference implementations**, not toy mocks:
//! - done-ledger writes use the same monotonic lattice semantics required of
//!   real backends
//! - findings writes are idempotent and enforce referential integrity between
//!   findings, occurrences, and observations
//! - durability acknowledgements remain explicit via `CommitHandle::wait()`
//!
//! The fault-injection controls are intentionally simple and deterministic:
//! callers can fail the next N submissions/commits, delay future commits, and
//! manually release pending handles in FIFO or LIFO order.

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use super::{
    conformance::{DurableFindingsCounts, FindingsConformanceProbe},
    CommitHandle, DoneLedger, DoneLedgerCommitReceipt, DoneLedgerKey, DoneLedgerRecord,
    FindingRecord, FindingsCommitReceipt, FindingsSink, FindingsUpsertBatch, ObservationRecord,
    OccurrenceRecord, PersistenceInputError,
};
use crate::identity::{FindingId, ObservationId, OccurrenceId, TenantId};

/// Ordering used when manually releasing delayed in-memory commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOrder {
    /// Release the oldest pending operation first.
    OldestFirst,
    /// Release the newest pending operation first.
    NewestFirst,
}

/// Store kind used in fault injection and error reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InMemoryStoreKind {
    /// Done-ledger reference store.
    DoneLedger,
    /// Findings/occurrences/observations reference store.
    Findings,
}

impl fmt::Display for InMemoryStoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoneLedger => f.write_str("done-ledger"),
            Self::Findings => f.write_str("findings"),
        }
    }
}

/// Identifier for a pending in-memory write operation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingWriteId(u64);

impl PendingWriteId {
    /// Zero sentinel value.
    pub const ZERO: Self = Self(0);

    /// Construct from a raw integer.
    #[inline]
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw integer value.
    #[inline]
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PendingWriteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PendingWriteId({})", self.0)
    }
}

impl fmt::Display for PendingWriteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Errors returned by the in-memory persistence reference backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InMemoryPersistenceError {
    /// The request was rejected before a handle was created.
    InjectedSubmissionFailure {
        /// Store that rejected the submission.
        store: InMemoryStoreKind,
    },
    /// The request was accepted, but the durable commit failed.
    InjectedCommitFailure {
        /// Store whose commit failed.
        store: InMemoryStoreKind,
    },
    /// The backend's mutex or condvar became poisoned.
    Poisoned {
        /// Store whose internal state was poisoned.
        store: InMemoryStoreKind,
    },
    /// A commit handle waited on an operation that no longer exists.
    UnknownOperation {
        /// Store that issued the handle.
        store: InMemoryStoreKind,
        /// Operation id carried by the handle.
        op_id: PendingWriteId,
    },
    /// An occurrence referenced a finding that was neither durable nor present
    /// in the same batch.
    MissingFinding {
        tenant_id: TenantId,
        finding_id: FindingId,
        occurrence_id: OccurrenceId,
    },
    /// An observation referenced an occurrence that was neither durable nor
    /// present in the same batch.
    MissingOccurrence {
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
        observation_id: ObservationId,
    },
    /// Two finding rows shared the same `(tenant_id, finding_id)` but had
    /// different immutable content.
    FindingConflict {
        tenant_id: TenantId,
        finding_id: FindingId,
    },
    /// Two occurrence rows shared the same `(tenant_id, occurrence_id)` but had
    /// different immutable content.
    OccurrenceConflict {
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    },
    /// Two observation rows shared the same `(tenant_id, observation_id)` but
    /// disagreed on immutable identity fields.
    ObservationConflict {
        tenant_id: TenantId,
        observation_id: ObservationId,
    },
    /// Local validation failed before submission.
    BatchValidation(PersistenceInputError),
}

impl fmt::Display for InMemoryPersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InjectedSubmissionFailure { store } => {
                write!(f, "in-memory {store} submission failed via fault injection")
            }
            Self::InjectedCommitFailure { store } => {
                write!(f, "in-memory {store} commit failed via fault injection")
            }
            Self::Poisoned { store } => write!(f, "in-memory {store} state lock poisoned"),
            Self::UnknownOperation { store, op_id } => {
                write!(f, "unknown in-memory {store} operation {op_id}")
            }
            Self::MissingFinding {
                tenant_id,
                finding_id,
                occurrence_id,
            } => write!(
                f,
                "occurrence {occurrence_id:?} for tenant {tenant_id:?} references missing finding {finding_id:?}"
            ),
            Self::MissingOccurrence {
                tenant_id,
                occurrence_id,
                observation_id,
            } => write!(
                f,
                "observation {observation_id:?} for tenant {tenant_id:?} references missing occurrence {occurrence_id:?}"
            ),
            Self::FindingConflict {
                tenant_id,
                finding_id,
            } => write!(
                f,
                "finding conflict for tenant {tenant_id:?}, finding {finding_id:?}"
            ),
            Self::OccurrenceConflict {
                tenant_id,
                occurrence_id,
            } => write!(
                f,
                "occurrence conflict for tenant {tenant_id:?}, occurrence {occurrence_id:?}"
            ),
            Self::ObservationConflict {
                tenant_id,
                observation_id,
            } => write!(
                f,
                "observation conflict for tenant {tenant_id:?}, observation {observation_id:?}"
            ),
            Self::BatchValidation(err) => err.fmt(f),
        }
    }
}

impl Error for InMemoryPersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BatchValidation(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PersistenceInputError> for InMemoryPersistenceError {
    #[inline]
    fn from(value: PersistenceInputError) -> Self {
        Self::BatchValidation(value)
    }
}

enum PendingState<R> {
    Pending,
    Finished(Option<Result<R, InMemoryPersistenceError>>),
}

impl<R> PendingState<R> {
    #[inline]
    fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

fn pop_next_pending_id<P, R>(
    queue: &mut VecDeque<PendingWriteId>,
    ops: &HashMap<PendingWriteId, PendingOp<P, R>>,
    order: CompletionOrder,
) -> Option<PendingWriteId> {
    loop {
        let maybe = match order {
            CompletionOrder::OldestFirst => queue.pop_front(),
            CompletionOrder::NewestFirst => queue.pop_back(),
        };
        let op_id = maybe?;
        if ops.get(&op_id).is_some_and(|op| op.state.is_pending()) {
            return Some(op_id);
        }
    }
}

struct PendingOp<P, R> {
    payload: P,
    state: PendingState<R>,
}

// ---------------------------------------------------------------------------
// Done-ledger reference backend
// ---------------------------------------------------------------------------

struct DoneLedgerPayload {
    records: Vec<DoneLedgerRecord>,
}

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

/// In-memory reference implementation of [`DoneLedger`].
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
        let this = Self::default();
        let _ = this.set_auto_complete(auto_complete);
        this
    }

    /// Toggle whether future submissions complete immediately.
    pub fn set_auto_complete(
        &self,
        auto_complete: bool,
    ) -> Result<(), InMemoryPersistenceError> {
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
    pub fn release_next(
        &self,
        order: CompletionOrder,
    ) -> Result<Option<PendingWriteId>, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        let Some(op_id) = pop_next_pending_id(&mut guard.order, &guard.ops, order) else {
            return Ok(None);
        };
        finish_done_ledger_op(&mut guard, op_id)?;
        self.inner.cv.notify_all();
        Ok(Some(op_id))
    }

    /// Release a specific delayed operation by id.
    pub fn release_specific(
        &self,
        op_id: PendingWriteId,
    ) -> Result<bool, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        let is_pending = guard.ops.get(&op_id).is_some_and(|op| op.state.is_pending());
        if !is_pending {
            return Ok(false);
        }
        finish_done_ledger_op(&mut guard, op_id)?;
        self.inner.cv.notify_all();
        Ok(true)
    }

    /// Release every currently delayed operation.
    pub fn release_all(&self, order: CompletionOrder) -> Result<usize, InMemoryPersistenceError> {
        let mut released = 0usize;
        while self.release_next(order)?.is_some() {
            released += 1;
        }
        Ok(released)
    }

    /// Number of operations that are still pending durability.
    pub fn pending_count(&self) -> Result<usize, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard.ops.values().filter(|op| op.state.is_pending()).count())
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
                    &guard.ops.values().filter(|op| op.state.is_pending()).count(),
                )
                .field("auto_complete", &guard.auto_complete)
                .finish(),
            Err(_) => f.write_str("InMemoryDoneLedger(<poisoned>)"),
        }
    }
}

/// Handle returned by [`InMemoryDoneLedger::batch_upsert`].
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

    fn wait(self) -> Result<Self::Receipt, Self::Error> {
        let mut guard = self
            .inner
            .state
            .lock()
            .map_err(|_| InMemoryPersistenceError::Poisoned {
                store: InMemoryStoreKind::DoneLedger,
            })?;

        loop {
            let finished = match guard.ops.get_mut(&self.op_id) {
                Some(op) => match &mut op.state {
                    PendingState::Pending => None,
                    PendingState::Finished(result) => Some(
                        result
                            .take()
                            .ok_or(InMemoryPersistenceError::UnknownOperation {
                                store: InMemoryStoreKind::DoneLedger,
                                op_id: self.op_id,
                            }),
                    ),
                },
                None => {
                    return Err(InMemoryPersistenceError::UnknownOperation {
                        store: InMemoryStoreKind::DoneLedger,
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
                    store: InMemoryStoreKind::DoneLedger,
                })?;
        }
    }
}

impl DoneLedger for InMemoryDoneLedger {
    type Error = InMemoryPersistenceError;
    type CommitHandle = InMemoryDoneLedgerHandle;

    fn batch_get(
        &self,
        tenant_id: TenantId,
        policy_hash: crate::identity::PolicyHash,
        ovid_hashes: &[super::OvidHash],
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

    fn batch_upsert(&self, records: &[DoneLedgerRecord]) -> Result<Self::CommitHandle, Self::Error> {
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
        records.iter().filter(|record| record.status().is_scanned()).count() as u64,
        records
            .iter()
            .fold(0u64, |acc, record| acc.saturating_add(record.findings_count() as u64)),
    );
    Ok(receipt)
}

fn finish_done_ledger_op(
    state: &mut DoneLedgerState,
    op_id: PendingWriteId,
) -> Result<(), InMemoryPersistenceError> {
    let records = match state.ops.get(&op_id) {
        Some(op) => match op.state {
            PendingState::Pending => op.payload.records.clone(),
            PendingState::Finished(_) => return Ok(()),
        },
        None => {
            return Err(InMemoryPersistenceError::UnknownOperation {
                store: InMemoryStoreKind::DoneLedger,
                op_id,
            });
        }
    };

    let result = apply_done_ledger_payload(state, &records);
    if let Some(op) = state.ops.get_mut(&op_id) {
        op.state = PendingState::Finished(Some(result));
    }
    Ok(())
}

fn merge_done_ledger_records(existing: &DoneLedgerRecord, incoming: &DoneLedgerRecord) -> DoneLedgerRecord {
    let merged_status = existing.status().merge(incoming.status());
    let bytes_scanned = existing.bytes_scanned().max(incoming.bytes_scanned());
    let findings_count = existing.findings_count().max(incoming.findings_count());

    let choose_incoming = incoming.status().rank() > existing.status().rank()
        || (incoming.status().rank() == existing.status().rank()
            && incoming.provenance().finished_at() > existing.provenance().finished_at())
        || (incoming.status().rank() == existing.status().rank()
            && incoming.provenance().finished_at() == existing.provenance().finished_at()
            && incoming.provenance().started_at() > existing.provenance().started_at());

    let chosen = if choose_incoming { incoming } else { existing };
    let fallback = if choose_incoming { existing } else { incoming };

    let error_code = if merged_status.is_scanned() {
        None
    } else {
        chosen
            .error_code()
            .cloned()
            .or_else(|| fallback.error_code().cloned())
    };

    DoneLedgerRecord::new(
        existing.key(),
        merged_status,
        bytes_scanned,
        findings_count,
        chosen.provenance(),
        error_code,
    )
}

// ---------------------------------------------------------------------------
// Findings reference backend
// ---------------------------------------------------------------------------

type FindingKey = (TenantId, FindingId);
type OccurrenceKey = (TenantId, OccurrenceId);
type ObservationKey = (TenantId, ObservationId);

struct FindingsPayload {
    findings: Vec<FindingRecord>,
    occurrences: Vec<OccurrenceRecord>,
    observations: Vec<ObservationRecord>,
}

struct FindingsState {
    durable_findings: HashMap<FindingKey, FindingRecord>,
    durable_occurrences: HashMap<OccurrenceKey, OccurrenceRecord>,
    durable_observations: HashMap<ObservationKey, ObservationRecord>,
    ops: HashMap<PendingWriteId, PendingOp<FindingsPayload, FindingsCommitReceipt>>,
    order: VecDeque<PendingWriteId>,
    next_op_id: u64,
    auto_complete: bool,
    delay_next: usize,
    fail_submit_remaining: usize,
    fail_commit_remaining: usize,
}

impl Default for FindingsState {
    fn default() -> Self {
        Self {
            durable_findings: HashMap::new(),
            durable_occurrences: HashMap::new(),
            durable_observations: HashMap::new(),
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

struct FindingsInner {
    state: Mutex<FindingsState>,
    cv: Condvar,
}

impl Default for FindingsInner {
    fn default() -> Self {
        Self {
            state: Mutex::new(FindingsState::default()),
            cv: Condvar::new(),
        }
    }
}

/// In-memory reference implementation of [`FindingsSink`].
#[derive(Clone, Default)]
pub struct InMemoryFindingsSink {
    inner: Arc<FindingsInner>,
}

impl InMemoryFindingsSink {
    /// Create an empty findings sink with auto-complete enabled.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty findings sink with an explicit auto-complete mode.
    #[must_use]
    pub fn with_auto_complete(auto_complete: bool) -> Self {
        let this = Self::default();
        let _ = this.set_auto_complete(auto_complete);
        this
    }

    /// Toggle whether future submissions complete immediately.
    pub fn set_auto_complete(
        &self,
        auto_complete: bool,
    ) -> Result<(), InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        guard.auto_complete = auto_complete;
        Ok(())
    }

    /// Delay the next `count` submissions until released explicitly.
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
    pub fn release_next(
        &self,
        order: CompletionOrder,
    ) -> Result<Option<PendingWriteId>, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        let Some(op_id) = pop_next_pending_id(&mut guard.order, &guard.ops, order) else {
            return Ok(None);
        };
        finish_findings_op(&mut guard, op_id)?;
        self.inner.cv.notify_all();
        Ok(Some(op_id))
    }

    /// Release a specific delayed operation by id.
    pub fn release_specific(
        &self,
        op_id: PendingWriteId,
    ) -> Result<bool, InMemoryPersistenceError> {
        let mut guard = self.lock_state()?;
        let is_pending = guard.ops.get(&op_id).is_some_and(|op| op.state.is_pending());
        if !is_pending {
            return Ok(false);
        }
        finish_findings_op(&mut guard, op_id)?;
        self.inner.cv.notify_all();
        Ok(true)
    }

    /// Release every currently delayed operation.
    pub fn release_all(&self, order: CompletionOrder) -> Result<usize, InMemoryPersistenceError> {
        let mut released = 0usize;
        while self.release_next(order)?.is_some() {
            released += 1;
        }
        Ok(released)
    }

    /// Number of operations still pending durability.
    pub fn pending_count(&self) -> Result<usize, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard.ops.values().filter(|op| op.state.is_pending()).count())
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

    /// Durable findings snapshot, sorted by `(tenant_id, finding_id)`.
    pub fn findings_snapshot(&self) -> Result<Vec<FindingRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        let mut rows: Vec<_> = guard.durable_findings.values().cloned().collect();
        rows.sort_by(|lhs, rhs| {
            lhs.tenant_id()
                .as_bytes()
                .cmp(rhs.tenant_id().as_bytes())
                .then_with(|| lhs.finding_id().as_bytes().cmp(rhs.finding_id().as_bytes()))
        });
        Ok(rows)
    }

    /// Durable occurrences snapshot, sorted by `(tenant_id, occurrence_id)`.
    pub fn occurrences_snapshot(&self) -> Result<Vec<OccurrenceRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        let mut rows: Vec<_> = guard.durable_occurrences.values().cloned().collect();
        rows.sort_by(|lhs, rhs| {
            lhs.tenant_id()
                .as_bytes()
                .cmp(rhs.tenant_id().as_bytes())
                .then_with(|| {
                    lhs.occurrence_id()
                        .as_bytes()
                        .cmp(rhs.occurrence_id().as_bytes())
                })
        });
        Ok(rows)
    }

    /// Durable observations snapshot, sorted by `(tenant_id, observation_id)`.
    pub fn observations_snapshot(
        &self,
    ) -> Result<Vec<ObservationRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        let mut rows: Vec<_> = guard.durable_observations.values().cloned().collect();
        rows.sort_by(|lhs, rhs| {
            lhs.tenant_id()
                .as_bytes()
                .cmp(rhs.tenant_id().as_bytes())
                .then_with(|| {
                    lhs.observation_id()
                        .as_bytes()
                        .cmp(rhs.observation_id().as_bytes())
                })
        });
        Ok(rows)
    }

    /// Return the durable finding for `(tenant_id, finding_id)`, if present.
    pub fn get_finding(
        &self,
        tenant_id: TenantId,
        finding_id: FindingId,
    ) -> Result<Option<FindingRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard.durable_findings.get(&(tenant_id, finding_id)).cloned())
    }

    /// Return the durable occurrence for `(tenant_id, occurrence_id)`, if present.
    pub fn get_occurrence(
        &self,
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    ) -> Result<Option<OccurrenceRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard
            .durable_occurrences
            .get(&(tenant_id, occurrence_id))
            .cloned())
    }

    /// Return the durable observation for `(tenant_id, observation_id)`, if present.
    pub fn get_observation(
        &self,
        tenant_id: TenantId,
        observation_id: ObservationId,
    ) -> Result<Option<ObservationRecord>, InMemoryPersistenceError> {
        let guard = self.lock_state()?;
        Ok(guard
            .durable_observations
            .get(&(tenant_id, observation_id))
            .cloned())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, FindingsState>, InMemoryPersistenceError> {
        self.inner
            .state
            .lock()
            .map_err(|_| InMemoryPersistenceError::Poisoned {
                store: InMemoryStoreKind::Findings,
            })
    }
}

impl fmt::Debug for InMemoryFindingsSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.lock_state() {
            Ok(guard) => f
                .debug_struct("InMemoryFindingsSink")
                .field("durable_findings", &guard.durable_findings.len())
                .field("durable_occurrences", &guard.durable_occurrences.len())
                .field("durable_observations", &guard.durable_observations.len())
                .field(
                    "pending_ops",
                    &guard.ops.values().filter(|op| op.state.is_pending()).count(),
                )
                .field("auto_complete", &guard.auto_complete)
                .finish(),
            Err(_) => f.write_str("InMemoryFindingsSink(<poisoned>)"),
        }
    }
}

/// Handle returned by [`InMemoryFindingsSink::upsert_batch`].
pub struct InMemoryFindingsHandle {
    inner: Arc<FindingsInner>,
    op_id: PendingWriteId,
}

impl InMemoryFindingsHandle {
    /// Pending operation id associated with this handle.
    #[inline]
    #[must_use]
    pub const fn operation_id(&self) -> PendingWriteId {
        self.op_id
    }
}

impl fmt::Debug for InMemoryFindingsHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryFindingsHandle")
            .field("op_id", &self.op_id)
            .finish()
    }
}

impl CommitHandle for InMemoryFindingsHandle {
    type Receipt = FindingsCommitReceipt;
    type Error = InMemoryPersistenceError;

    fn wait(self) -> Result<Self::Receipt, Self::Error> {
        let mut guard = self
            .inner
            .state
            .lock()
            .map_err(|_| InMemoryPersistenceError::Poisoned {
                store: InMemoryStoreKind::Findings,
            })?;

        loop {
            let finished = match guard.ops.get_mut(&self.op_id) {
                Some(op) => match &mut op.state {
                    PendingState::Pending => None,
                    PendingState::Finished(result) => Some(
                        result
                            .take()
                            .ok_or(InMemoryPersistenceError::UnknownOperation {
                                store: InMemoryStoreKind::Findings,
                                op_id: self.op_id,
                            }),
                    ),
                },
                None => {
                    return Err(InMemoryPersistenceError::UnknownOperation {
                        store: InMemoryStoreKind::Findings,
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
                    store: InMemoryStoreKind::Findings,
                })?;
        }
    }
}

impl FindingsSink for InMemoryFindingsSink {
    type Error = InMemoryPersistenceError;
    type CommitHandle = InMemoryFindingsHandle;

    fn upsert_batch(&self, batch: FindingsUpsertBatch<'_>) -> Result<Self::CommitHandle, Self::Error> {
        batch.validate()?;

        let mut guard = self.lock_state()?;

        if guard.fail_submit_remaining > 0 {
            guard.fail_submit_remaining -= 1;
            return Err(InMemoryPersistenceError::InjectedSubmissionFailure {
                store: InMemoryStoreKind::Findings,
            });
        }

        let op_id = PendingWriteId::from_raw(guard.next_op_id);
        guard.next_op_id = guard.next_op_id.saturating_add(1);

        let mut op = PendingOp {
            payload: FindingsPayload {
                findings: batch.findings().to_vec(),
                occurrences: batch.occurrences().to_vec(),
                observations: batch.observations().to_vec(),
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
            let payload = FindingsPayload {
                findings: op.payload.findings.clone(),
                occurrences: op.payload.occurrences.clone(),
                observations: op.payload.observations.clone(),
            };
            let result = apply_findings_payload(&mut guard, &payload);
            op.state = PendingState::Finished(Some(result));
            guard.ops.insert(op_id, op);
            self.inner.cv.notify_all();
        }

        Ok(InMemoryFindingsHandle {
            inner: Arc::clone(&self.inner),
            op_id,
        })
    }
}

fn finish_findings_op(
    state: &mut FindingsState,
    op_id: PendingWriteId,
) -> Result<(), InMemoryPersistenceError> {
    let payload = match state.ops.get(&op_id) {
        Some(op) => match op.state {
            PendingState::Pending => FindingsPayload {
                findings: op.payload.findings.clone(),
                occurrences: op.payload.occurrences.clone(),
                observations: op.payload.observations.clone(),
            },
            PendingState::Finished(_) => return Ok(()),
        },
        None => {
            return Err(InMemoryPersistenceError::UnknownOperation {
                store: InMemoryStoreKind::Findings,
                op_id,
            });
        }
    };

    let result = apply_findings_payload(state, &payload);
    if let Some(op) = state.ops.get_mut(&op_id) {
        op.state = PendingState::Finished(Some(result));
    }
    Ok(())
}

fn apply_findings_payload(
    state: &mut FindingsState,
    payload: &FindingsPayload,
) -> Result<FindingsCommitReceipt, InMemoryPersistenceError> {
    if state.fail_commit_remaining > 0 {
        state.fail_commit_remaining -= 1;
        return Err(InMemoryPersistenceError::InjectedCommitFailure {
            store: InMemoryStoreKind::Findings,
        });
    }

    let mut staged_findings = state.durable_findings.clone();
    let mut staged_occurrences = state.durable_occurrences.clone();
    let mut staged_observations = state.durable_observations.clone();

    // Findings are immutable once keyed by (tenant_id, finding_id).
    let mut batch_findings: HashMap<FindingKey, FindingRecord> = HashMap::new();
    for finding in &payload.findings {
        let key = (finding.tenant_id(), finding.finding_id());
        if let Some(existing) = batch_findings.get(&key) {
            if existing != finding {
                return Err(InMemoryPersistenceError::FindingConflict {
                    tenant_id: finding.tenant_id(),
                    finding_id: finding.finding_id(),
                });
            }
            continue;
        }
        if let Some(existing) = staged_findings.get(&key) {
            if existing != finding {
                return Err(InMemoryPersistenceError::FindingConflict {
                    tenant_id: finding.tenant_id(),
                    finding_id: finding.finding_id(),
                });
            }
        } else {
            staged_findings.insert(key, finding.clone());
        }
        batch_findings.insert(key, finding.clone());
    }

    // Occurrences are also immutable once keyed by (tenant_id, occurrence_id).
    let mut batch_occurrences: HashMap<OccurrenceKey, OccurrenceRecord> = HashMap::new();
    for occurrence in &payload.occurrences {
        let key = (occurrence.tenant_id(), occurrence.occurrence_id());
        let finding_key = (occurrence.tenant_id(), occurrence.finding_id());
        if !batch_findings.contains_key(&finding_key) && !staged_findings.contains_key(&finding_key) {
            return Err(InMemoryPersistenceError::MissingFinding {
                tenant_id: occurrence.tenant_id(),
                finding_id: occurrence.finding_id(),
                occurrence_id: occurrence.occurrence_id(),
            });
        }
        if let Some(existing) = batch_occurrences.get(&key) {
            if existing != occurrence {
                return Err(InMemoryPersistenceError::OccurrenceConflict {
                    tenant_id: occurrence.tenant_id(),
                    occurrence_id: occurrence.occurrence_id(),
                });
            }
            continue;
        }
        if let Some(existing) = staged_occurrences.get(&key) {
            if existing != occurrence {
                return Err(InMemoryPersistenceError::OccurrenceConflict {
                    tenant_id: occurrence.tenant_id(),
                    occurrence_id: occurrence.occurrence_id(),
                });
            }
        } else {
            staged_occurrences.insert(key, occurrence.clone());
        }
        batch_occurrences.insert(key, occurrence.clone());
    }

    // Observations are upserts keyed by (tenant_id, observation_id). Their
    // identity fields must agree, but last-seen provenance may legitimately
    // change across retries/reruns of the same occurrence under the same policy.
    let mut batch_observations: HashMap<ObservationKey, ObservationRecord> = HashMap::new();
    for observation in &payload.observations {
        observation.validate_identity()?;
        let key = (observation.tenant_id(), observation.observation_id());
        let occurrence_key = (observation.tenant_id(), observation.occurrence_id());
        if !batch_occurrences.contains_key(&occurrence_key)
            && !staged_occurrences.contains_key(&occurrence_key)
        {
            return Err(InMemoryPersistenceError::MissingOccurrence {
                tenant_id: observation.tenant_id(),
                occurrence_id: observation.occurrence_id(),
                observation_id: observation.observation_id(),
            });
        }

        if let Some(existing) = batch_observations.get(&key) {
            let merged = merge_observations(existing, observation)?;
            batch_observations.insert(key, merged.clone());
            staged_observations.insert(key, merged);
            continue;
        }

        if let Some(existing) = staged_observations.get(&key) {
            let merged = merge_observations(existing, observation)?;
            staged_observations.insert(key, merged.clone());
            batch_observations.insert(key, merged);
        } else {
            staged_observations.insert(key, observation.clone());
            batch_observations.insert(key, observation.clone());
        }
    }

    state.durable_findings = staged_findings;
    state.durable_occurrences = staged_occurrences;
    state.durable_observations = staged_observations;

    Ok(FindingsCommitReceipt::new(
        payload.findings.len() as u64,
        payload.occurrences.len() as u64,
        payload.observations.len() as u64,
    ))
}

fn merge_observations(
    existing: &ObservationRecord,
    incoming: &ObservationRecord,
) -> Result<ObservationRecord, InMemoryPersistenceError> {
    if existing.tenant_id() != incoming.tenant_id()
        || existing.observation_id() != incoming.observation_id()
        || existing.occurrence_id() != incoming.occurrence_id()
        || existing.policy_hash() != incoming.policy_hash()
        || existing.ovid_hash() != incoming.ovid_hash()
    {
        return Err(InMemoryPersistenceError::ObservationConflict {
            tenant_id: incoming.tenant_id(),
            observation_id: incoming.observation_id(),
        });
    }

    let (provenance_source, seen_at) = if incoming.seen_at() > existing.seen_at() {
        (incoming, incoming.seen_at())
    } else if incoming.seen_at() < existing.seen_at() {
        (existing, existing.seen_at())
    } else if existing.location().is_none() && incoming.location().is_some() {
        (incoming, incoming.seen_at())
    } else {
        (existing, existing.seen_at())
    };

    let mut merged = ObservationRecord::new(
        existing.tenant_id(),
        existing.occurrence_id(),
        existing.policy_hash(),
        existing.ovid_hash(),
        provenance_source.run_id(),
        provenance_source.shard_id(),
        provenance_source.fence_epoch(),
        seen_at,
    );

    if let Some(location) = provenance_source
        .location()
        .cloned()
        .or_else(|| existing.location().cloned())
        .or_else(|| incoming.location().cloned())
    {
        merged = merged.with_location(location);
    }

    Ok(merged)
}

impl FindingsConformanceProbe for InMemoryFindingsSink {
    type Error = InMemoryPersistenceError;

    fn durable_counts(&self) -> Result<DurableFindingsCounts, Self::Error> {
        let guard = self.lock_state()?;
        Ok(DurableFindingsCounts::new(
            guard.durable_findings.len() as u64,
            guard.durable_occurrences.len() as u64,
            guard.durable_observations.len() as u64,
        ))
    }
}
