//! In-memory reference implementation of [`FindingsSink`].
//!
//! See the [crate-level docs](crate) for architecture, completion modes, and
//! fault injection semantics.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use gossip_contracts::{
    identity::{FindingId, ObservationId, OccurrenceId, TenantId},
    persistence::{
        CommitHandle, FindingRecord, FindingsCommitReceipt, FindingsSink, FindingsUpsertBatch,
        ObservationRecord, OccurrenceRecord, PersistenceInputError,
    },
};

use crate::{
    error::{CompletionOrder, InMemoryPersistenceError, InMemoryStoreKind, PendingWriteId},
    pending::{PendingOp, PendingState},
};

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

// Composite keys for the three findings tables. Tenant is included in every
// key to enforce tenant isolation at the storage level, not just at the
// query level.
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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// In-memory reference implementation of [`FindingsSink`].
///
/// Enforces the same invariants a real persistence backend would:
///
/// - **Referential integrity**: every occurrence must reference a finding that
///   is either already durable or present in the same batch. Likewise,
///   observations must reference a durable or same-batch occurrence.
/// - **Immutability of findings and occurrences**: once a `(tenant_id,
///   finding_id)` or `(tenant_id, occurrence_id)` is durable, re-inserting
///   the same key with different content is a [`FindingConflict`] /
///   [`OccurrenceConflict`] error.
/// - **Observation upsert**: observations share the same key
///   `(tenant_id, observation_id)` but may be upserted with newer provenance.
///   Identity fields must match; `seen_at` and location may change across
///   retries or reruns.
/// - **Single-tenant batches**: all records in a batch must belong to the
///   same tenant ([`PersistenceInputError::InconsistentTenant`]).
///
/// Cloning and fault-injection semantics are identical to
/// [`InMemoryDoneLedger`](crate::InMemoryDoneLedger) — see its docs.
///
/// [`FindingConflict`]: InMemoryPersistenceError::FindingConflict
/// [`OccurrenceConflict`]: InMemoryPersistenceError::OccurrenceConflict
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
        Self {
            inner: Arc::new(FindingsInner {
                state: Mutex::new(FindingsState {
                    auto_complete,
                    ..FindingsState::default()
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
        finish_findings_op(&mut guard, op_id)?;
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
        finish_findings_op(&mut guard, op_id)?;
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
            finish_findings_op(&mut guard, op_id)?;
            guard.order.retain(|id| *id != op_id);
            released += 1;
        }
        if released > 0 {
            self.inner.cv.notify_all();
        }
        Ok(released)
    }

    /// Number of operations still pending durability.
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
        Ok(guard
            .durable_findings
            .get(&(tenant_id, finding_id))
            .cloned())
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
                    &guard
                        .ops
                        .values()
                        .filter(|op| op.state.is_pending())
                        .count(),
                )
                .field("auto_complete", &guard.auto_complete)
                .finish(),
            Err(_) => f.write_str("InMemoryFindingsSink(<poisoned>)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Commit handle
// ---------------------------------------------------------------------------

/// Handle returned by [`InMemoryFindingsSink::upsert_batch`].
///
/// Semantics mirror [`InMemoryDoneLedgerHandle`](crate::InMemoryDoneLedgerHandle)
/// — see its documentation for the condvar wait loop, single-use consumption,
/// and cleanup behavior.
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
        let mut guard =
            self.inner
                .state
                .lock()
                .map_err(|_| InMemoryPersistenceError::Poisoned {
                    store: InMemoryStoreKind::Findings,
                })?;

        loop {
            let finished = match guard.ops.get_mut(&self.op_id) {
                Some(op) => match &mut op.state {
                    PendingState::Pending => None,
                    PendingState::Finished(result) => Some(result.take().ok_or(
                        InMemoryPersistenceError::UnknownOperation {
                            store: InMemoryStoreKind::Findings,
                            op_id: self.op_id,
                        },
                    )),
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

// ---------------------------------------------------------------------------
// FindingsSink trait impl
// ---------------------------------------------------------------------------

impl FindingsSink for InMemoryFindingsSink {
    type Error = InMemoryPersistenceError;
    type CommitHandle = InMemoryFindingsHandle;

    fn upsert_batch(
        &self,
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<Self::CommitHandle, Self::Error> {
        // Validation is split into two phases:
        //
        // Phase 1 (here, before lock): batch-local invariants that do not
        // require access to durable state — observation identity consistency
        // and single-tenant enforcement.
        //
        // Phase 2 (inside `apply_findings_payload`, under lock): referential
        // integrity checks that need the union of durable and same-batch rows
        // to determine whether parent records exist.
        batch.validate_observation_identity()?;
        validate_batch_tenant_consistency(batch)?;

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
            // `op` is a local variable not yet inserted into any map, so
            // `&op.payload` can be passed directly — no clone needed.
            let result = apply_findings_payload(&mut guard, &op.payload);
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validate the single-tenant invariant: all records in the batch must share
/// the same `tenant_id`.
///
/// This check is intentionally separated from referential integrity validation
/// because it does not require durable state access — it can be performed
/// before acquiring the lock. Referential checks remain in
/// [`apply_findings_payload`], where the backend can consider both
/// already-durable parents and rows staged by the current batch.
fn validate_batch_tenant_consistency(
    batch: FindingsUpsertBatch<'_>,
) -> Result<(), PersistenceInputError> {
    let expected_tenant = batch
        .findings()
        .first()
        .map(FindingRecord::tenant_id)
        .or_else(|| batch.occurrences().first().map(OccurrenceRecord::tenant_id))
        .or_else(|| {
            batch
                .observations()
                .first()
                .map(ObservationRecord::tenant_id)
        });

    if let Some(expected_tenant) = expected_tenant
        && (batch
            .findings()
            .iter()
            .any(|finding| finding.tenant_id() != expected_tenant)
            || batch
                .occurrences()
                .iter()
                .any(|occurrence| occurrence.tenant_id() != expected_tenant)
            || batch
                .observations()
                .iter()
                .any(|observation| observation.tenant_id() != expected_tenant))
    {
        return Err(PersistenceInputError::InconsistentTenant);
    }

    Ok(())
}

/// Transition a pending findings operation to `Finished`.
///
/// Removes the op from the map to avoid the split-borrow limitation (we need
/// `&op.payload` and `&mut state` simultaneously), applies the payload, then
/// re-inserts the finished op. Already-finished ops are a no-op.
fn finish_findings_op(
    state: &mut FindingsState,
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
                store: InMemoryStoreKind::Findings,
                op_id,
            });
        }
    };

    let result = apply_findings_payload(state, &op.payload);
    op.state = PendingState::Finished(Some(result));
    state.ops.insert(op_id, op);
    Ok(())
}

/// Apply a findings payload to the durable state with full integrity checks.
///
/// # Validate-then-mutate approach
///
/// To ensure atomicity on failure the function builds temporary `batch_*` maps
/// from the payload and validates every invariant as read-only lookups against
/// the union of `batch_*` (same-batch rows) and `state.durable_*` (already-
/// durable rows). Only after the entire payload passes validation are the new
/// rows inserted into `state.durable_*`. A validation error at any point
/// aborts without mutating durable state.
///
/// # Processing order (findings -> occurrences -> observations)
///
/// The three layers are processed in parent-to-child order so that child
/// referential checks can look up parents in both the already-durable state
/// and the same-batch `batch_*` maps built during earlier iterations:
///
/// 1. **Findings**: immutable insert-or-check. Duplicate keys with identical
///    content are silently deduplicated; differing content is a conflict error.
/// 2. **Occurrences**: same immutability rule as findings, plus each
///    occurrence must reference a finding in `batch_findings` or
///    `state.durable_findings`.
/// 3. **Observations**: upsert semantics — identity fields must match, but
///    provenance (`seen_at`, `location`, `run_id`, etc.) may be updated via
///    [`merge_observations`].
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

    // --- Layer 1: Findings (immutable insert-or-check) ---
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
        if let Some(existing) = state.durable_findings.get(&key)
            && existing != finding
        {
            return Err(InMemoryPersistenceError::FindingConflict {
                tenant_id: finding.tenant_id(),
                finding_id: finding.finding_id(),
            });
        }
        batch_findings.insert(key, finding.clone());
    }

    // --- Layer 2: Occurrences (immutable insert-or-check, with parent ref check) ---
    let mut batch_occurrences: HashMap<OccurrenceKey, OccurrenceRecord> = HashMap::new();
    for occurrence in &payload.occurrences {
        let key = (occurrence.tenant_id(), occurrence.occurrence_id());
        let finding_key = (occurrence.tenant_id(), occurrence.finding_id());
        if !batch_findings.contains_key(&finding_key)
            && !state.durable_findings.contains_key(&finding_key)
        {
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
        if let Some(existing) = state.durable_occurrences.get(&key)
            && existing != occurrence
        {
            return Err(InMemoryPersistenceError::OccurrenceConflict {
                tenant_id: occurrence.tenant_id(),
                occurrence_id: occurrence.occurrence_id(),
            });
        }
        batch_occurrences.insert(key, occurrence.clone());
    }

    // --- Layer 3: Observations (upsert with identity check + parent ref check) ---
    // Identity fields must agree, but last-seen provenance may legitimately
    // change across retries/reruns of the same occurrence under the same policy.
    let mut batch_observations: HashMap<ObservationKey, ObservationRecord> = HashMap::new();
    for observation in &payload.observations {
        observation.validate_identity()?;
        let key = (observation.tenant_id(), observation.observation_id());
        let occurrence_key = (observation.tenant_id(), observation.occurrence_id());
        if !batch_occurrences.contains_key(&occurrence_key)
            && !state.durable_occurrences.contains_key(&occurrence_key)
        {
            return Err(InMemoryPersistenceError::MissingOccurrence {
                tenant_id: observation.tenant_id(),
                occurrence_id: observation.occurrence_id(),
                observation_id: observation.observation_id(),
            });
        }

        if let Some(existing) = batch_observations.get(&key) {
            let merged = merge_observations(existing, observation)?;
            batch_observations.insert(key, merged);
            continue;
        }

        if let Some(existing) = state.durable_observations.get(&key) {
            let merged = merge_observations(existing, observation)?;
            batch_observations.insert(key, merged);
        } else {
            batch_observations.insert(key, observation.clone());
        }
    }

    // Validation passed — commit new rows into durable state.
    for (key, record) in &batch_findings {
        state
            .durable_findings
            .entry(*key)
            .or_insert_with(|| record.clone());
    }
    for (key, record) in &batch_occurrences {
        state
            .durable_occurrences
            .entry(*key)
            .or_insert_with(|| record.clone());
    }
    // Observations use upsert semantics: always overwrite with the merged result.
    for (key, record) in batch_observations.iter() {
        state.durable_observations.insert(*key, record.clone());
    }

    // Use deduplicated batch map sizes rather than raw payload lengths.
    // Within-batch duplicates (same key, same content) are silently skipped
    // by the `continue` branches above, so `batch_*.len()` reflects the
    // number of distinct rows actually acknowledged by this commit.
    Ok(FindingsCommitReceipt::new(
        batch_findings.len() as u64,
        batch_occurrences.len() as u64,
        batch_observations.len() as u64,
    ))
}

/// Merge two observation records that share the same `(tenant_id, observation_id)`.
///
/// # Identity check
///
/// The five identity fields (`tenant_id`, `observation_id`, `occurrence_id`,
/// `policy_hash`, `ovid_hash`) must agree. A mismatch is an
/// [`ObservationConflict`](InMemoryPersistenceError::ObservationConflict) —
/// it means two different logical observations collided on the same key,
/// which indicates a derivation bug upstream.
///
/// # Provenance winner selection
///
/// Non-identity fields (provenance, location) are taken from whichever record
/// is "freshest", using the following tie-breaking cascade:
///
/// 1. Later `seen_at` wins — the most recent observation of the same secret
///    carries the most up-to-date run/shard/epoch context.
/// 2. Equal `seen_at`: if the existing record has no location but the
///    incoming one does, prefer incoming — this lets a retry attach location
///    metadata that was missing on the first pass.
/// 3. Otherwise keep existing (stable under idempotent replay).
///
/// # Location fallback
///
/// Location is taken from the provenance winner first, then falls back to
/// whichever record has one. This ensures location is never lost during a
/// merge even if the provenance winner happens to lack it.
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
        // Equal seen_at: prefer whichever carries location metadata.
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

    // Location fallback chain: winner -> existing -> incoming.
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
