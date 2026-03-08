//! etcd-backed coordination backend implementation.
//!
//! This module owns [`EtcdCoordinator`], the concrete [`CoordinationBackend`]
//! that persists run and shard lifecycle state in etcd. It implements:
//!
//! - **Run management** (`create_run`, `register_shards`, `get_run`,
//!   `get_run_progress`, `list_shards_into`, `collect_claim_candidates_into`)
//! - **Shard hot path** (`acquire_and_restore_into`, `renew`, `checkpoint`,
//!   `split_replace`, `split_residual`)
//! - **Shard claiming** (via [`default_claim_next_available`])
//!
//! # Concurrency model
//!
//! All mutating operations use optimistic compare-and-swap (CAS) transactions
//! against etcd. Each operation follows the same pattern:
//!
//! 1. **Read** — Load the current record (shard or run) and its `mod_revision`.
//! 2. **Validate** — Check preconditions locally (lease, status, fencing epoch).
//! 3. **CAS** — Submit an etcd `Txn` conditioned on `mod_revision` equality.
//! 4. **Retry** — On CAS failure, backoff with jitter and retry from step 1
//!    (up to `optimistic_txn_retries`).
//!
//! If retries exhaust without success, the operation re-reads and returns
//! whatever domain error is appropriate (stale fence, already leased, etc.)
//! or panics if the contention is unexplainable. This last-resort re-read
//! ensures the caller never silently loses work.
//!
//! # Shard ownership
//!
//! Each shard has a separate `/owner` key holding a `(WorkerId, FenceEpoch)`
//! binding, attached to an etcd lease. When the etcd lease expires (e.g.,
//! worker crash), the `/owner` key is automatically deleted by etcd's TTL
//! mechanism. The shard record itself persists the logical lease deadline
//! for coordinators to make availability decisions without watching etcd
//! lease events.
//!
//! This dual-key design means ownership depends on *two* conditions being
//! true simultaneously: (a) the `/owner` key exists and matches, and
//! (b) the shard record's logical deadline has not passed. CAS transactions
//! guard both.
//!
//! # Idempotency
//!
//! All mutating operations carry an `OpId` and a payload hash. If a retry
//! finds the operation already recorded in the shard's or run's op-log,
//! it returns [`IdempotentOutcome::Replayed`] with the previously computed
//! result. This makes every mutation safe to retry across network partitions.
//!
//! # Unimplemented operations
//!
//! Operations not yet persisted (`complete`, `park_shard`, `complete_run`,
//! `fail_run`, `cancel_run`, `unpark_shard`) panic with a descriptive
//! message. They will be persisted as the coordination surface is extended.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crate::codec::{
    EtcdCodecError, OwnerLeaseValue, decode_owner_value, decode_run_record, decode_shard_record,
    encode_owner_value, encode_run_record, encode_shard_record,
};
use crate::config::{DEFAULT_CONNECT_TIMEOUT, EtcdCoordinatorConfig};
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::EtcdKeyspace;
#[cfg(test)]
use etcd_client::DeleteOptions;
use etcd_client::{Compare, CompareOp, GetOptions, PutOptions, Txn, TxnOp};
use gossip_contracts::coordination::limits::{MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN};
use gossip_contracts::coordination::shard_spec::{
    ShardSpec, ShardSpecRef, SplitValidationError, validate_residual_split_bounds,
};
#[cfg(test)]
use gossip_contracts::test_util::TestSlab;
#[cfg(test)]
use gossip_coordination::FenceEpoch;
use gossip_coordination::validation::validate_cursor_update_pooled;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, ByteSlab, CapacityHint, CheckpointError,
    ClaimError, CompleteError, CoordinationBackend, CreateRunError, CursorUpdate, DerivedShardKind,
    GetRunError, IdempotentOutcome, InitialShardInput, Lease, LeaseHolder, LogicalTime, OpId,
    OpKind, OpLogEntry, OpResult, ParkError, ParkReason, RegisterShardsError, RenewError,
    RenewResult, RingBuffer, RunConfig, RunId, RunManagement, RunOpKind, RunOpLogEntry,
    RunOpResult, RunProgress, RunRecord, RunStatus, RunTransitionError, ShardClaiming, ShardFilter,
    ShardId, ShardKey, ShardRecord, ShardStatus, ShardSummary, SplitReplaceChild,
    SplitReplaceError, SplitReplacePlan, SplitReplaceResult, SplitResidualError, SplitResidualPlan,
    SplitResidualResult, TenantId, UnparkError, WorkerId, check_op_idempotency,
    default_claim_next_available, derive_split_shard_id, hash_checkpoint_payload,
    hash_register_shards_payload, hash_split_replace_payload, hash_split_residual_payload,
    validate_lease, validate_manifest,
};
use gossip_stdx::InlineVec;

/// Minimum slab capacity allocated for decoding a shard record blob.
///
/// Ensures small blobs (e.g. a shard with empty key range and no metadata)
/// still get a workable slab for pooled field allocation without
/// triggering immediate `SlabFull`.
const MIN_DECODE_SLAB_CAPACITY: usize = 4 * 1024;

/// Maximum slab capacity allocated for decoding a shard record blob.
///
/// Caps the 4× heuristic in [`EtcdCoordinator::make_decode_slab`] to
/// prevent a single oversized blob from causing a disproportionate
/// one-shot allocation.
const MAX_DECODE_SLAB_CAPACITY: usize = 256 * 1024;

/// Floor capacity for slabs built during shard registration encoding.
///
/// Prevents tiny slabs when a shard's combined spec + cursor content is
/// nearly empty.
const DEFAULT_BUILD_SLAB_FLOOR: usize = 1024;

/// Maximum shards per `register_shards` etcd transaction.
///
/// Derived from etcd's default `--max-txn-ops` limit of 128. Each shard
/// generates 2 ops (put-record, put-active-index) and 1 compare
/// (compare-absent). The run itself adds 3 fixed ops
/// (compare-run-revision, put-run-record, put-run-active-index), giving
/// `(128 - 3) / 3 = 41` as the maximum shard count per transaction.
const MAX_SHARDS_PER_ETCD_TXN: usize = 41;

type SplitChildIds = InlineVec<ShardId, { MAX_SPLIT_CHILDREN }>;

const _: () = assert!(MAX_SPLIT_CHILDREN <= u16::MAX as usize);

/// Compute a backoff delay for CAS retry loops.
///
/// Uses exponential backoff (5 ms base, 2× per attempt, capped at 200 ms)
/// with ±50% jitter to prevent thundering-herd contention when multiple
/// workers race on the same shard.
///
/// Jitter is derived from the current system time's sub-second nanoseconds
/// rather than an RNG. This avoids adding a CSPRNG or thread-local RNG
/// dependency for a best-effort delay that only needs approximate
/// decorrelation between independent callers.
fn cas_retry_delay(attempt: usize) -> Duration {
    let base_ms: u64 = 5;
    let max_ms: u64 = 200;
    let exp_ms = base_ms.saturating_mul(1u64 << attempt.min(6)).min(max_ms);

    let jitter_source = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .subsec_nanos();
    let jitter_frac = (jitter_source % 1000) as f64 / 1000.0;
    let jittered = (exp_ms as f64) * (0.5 + jitter_frac);

    Duration::from_micros((jittered * 1000.0) as u64)
}

/// A run record loaded from etcd, paired with its `mod_revision` for
/// compare-and-swap transaction guards.
///
/// `mod_revision` is the etcd key revision at the time of the read; the
/// subsequent CAS transaction conditions on this revision to detect
/// concurrent writes between the read and the write.
#[derive(Debug)]
struct PersistedRun {
    record: RunRecord,
    /// etcd key modification revision used as a CAS precondition.
    mod_revision: i64,
}

/// Decoded owner-key state for a single shard, including the etcd lease
/// ID that controls the key's TTL-based automatic deletion.
///
/// The `lease_id` is the etcd-level lease (distinct from the coordination
/// protocol's logical `Lease`). When etcd's TTL expires, it deletes the
/// owner key automatically, which the backend detects on the next read
/// as an absent owner.
#[derive(Clone, Debug)]
struct PersistedOwner {
    binding: OwnerLeaseValue,
    /// etcd lease ID attached to the owner key. Revocation of this lease
    /// causes etcd to delete the owner key, signaling ownership loss.
    lease_id: i64,
}

/// A shard record loaded from etcd with its associated slab, revision,
/// and optional owner binding.
///
/// This is the internal read model: every mutating operation loads one or
/// more `PersistedShard` values, validates preconditions against them,
/// then builds a CAS transaction conditioned on `mod_revision`. The slab
/// is co-located with the record because `ShardRecord` pools its
/// variable-length fields (spec, cursor, spawned) in a `ByteSlab`.
struct PersistedShard {
    record: ShardRecord,
    /// Slab backing the pooled fields in `record` (`spec`, `cursor`, `spawned`).
    slab: ByteSlab,
    /// etcd key modification revision used as a CAS precondition.
    mod_revision: i64,
    /// Decoded owner-key binding, present only if the shard has a live
    /// `/owner` key in etcd.
    owner: Option<PersistedOwner>,
}

impl PersistedShard {
    /// Returns `true` if the shard has a live owner whose logical lease
    /// has not yet expired at `now`.
    fn owner_is_live_at(&self, now: LogicalTime) -> bool {
        self.owner.is_some()
            && self
                .record
                .lease_deadline()
                .is_some_and(|deadline| now < deadline)
    }

    /// Re-encode the current owner binding for use as a CAS comparison
    /// value. Returns `None` if there is no owner.
    fn expected_owner_value(&self) -> Option<Vec<u8>> {
        self.owner
            .as_ref()
            .map(|owner| encode_owner_value(owner.binding.worker, owner.binding.fence))
    }

    /// Returns `true` if the persisted owner binding matches the
    /// presented lease's worker and fence epoch.
    fn owner_matches_lease(&self, lease: &Lease) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.binding.worker == lease.owner() && owner.binding.fence == lease.fence()
        })
    }
}

/// Start-sorted index mapping for a split-replace plan's children.
///
/// Split plans preserve caller order for canonical payload hashing, but
/// coverage validation and deterministic child-ID derivation require
/// children sorted by `key_range_start`. This type maintains an index
/// mapping from sorted position to original plan position, letting the
/// backend validate and execute in sorted order without reordering the
/// stored plan or allocating a separate sorted copy of the children.
#[derive(Clone, Copy)]
struct SplitChildOrder {
    len: usize,
    indices: [u16; MAX_SPLIT_CHILDREN],
}

impl SplitChildOrder {
    /// Build a start-sorted index mapping for `plan`.
    fn from_plan(plan: &SplitReplacePlan<'_>) -> Self {
        let len = plan.children().len();
        let mut indices = [0u16; MAX_SPLIT_CHILDREN];
        for (child_idx, slot) in indices.iter_mut().take(len).enumerate() {
            *slot = u16::try_from(child_idx).expect("split child index exceeds u16");
        }
        indices[..len].sort_by(|left, right| {
            plan.children()[usize::from(*left)]
                .spec()
                .key_range_start()
                .cmp(
                    plan.children()[usize::from(*right)]
                        .spec()
                        .key_range_start(),
                )
        });

        Self { len, indices }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn child<'a>(
        &self,
        plan: &'a SplitReplacePlan<'a>,
        sorted_idx: usize,
    ) -> &'a SplitReplaceChild<'a> {
        &plan.children()[usize::from(self.indices[sorted_idx])]
    }
}

/// Verify that sorted split-replace children exactly partition the parent.
///
/// Checks the same contiguity invariants as
/// [`validate_split_coverage_bounds`](gossip_contracts::coordination::shard_spec::validate_split_coverage_bounds)
/// but operates on sorted `SplitChildOrder` indices into the plan rather
/// than a standalone slice. This keeps validation allocation-free for
/// pooled parent records and guarantees the same sibling order used for
/// derived child IDs also satisfies the parent's `[start, end)` continuity
/// contract.
fn split_replace_validate_coverage_sorted(
    parent_start: &[u8],
    parent_end: &[u8],
    plan: &SplitReplacePlan<'_>,
    sorted: &SplitChildOrder,
) -> Result<(), SplitValidationError> {
    if sorted.len() == 0 {
        return Err(SplitValidationError::NoChildren);
    }
    if sorted.len() == 1 {
        return Err(SplitValidationError::SingleChild);
    }

    let first = sorted.child(plan, 0).spec();
    if first.key_range_start() != parent_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: parent_start.len(),
            first_child_start: first.key_range_start().len(),
        });
    }

    let last = sorted.child(plan, sorted.len() - 1).spec();
    if last.key_range_end() != parent_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: parent_end.len(),
            last_child_end: last.key_range_end().len(),
        });
    }

    for sorted_idx in 0..sorted.len() - 1 {
        let child = sorted.child(plan, sorted_idx).spec();
        let next = sorted.child(plan, sorted_idx + 1).spec();
        if child.key_range_end() != next.key_range_start() {
            return Err(SplitValidationError::BoundaryMismatch {
                child_index: sorted_idx,
                next_child_index: sorted_idx + 1,
                child_end: child.key_range_end().len(),
                next_child_start: next.key_range_start().len(),
            });
        }
        if child.key_range_end().is_empty() {
            return Err(SplitValidationError::OverlappingChild {
                child_index: sorted_idx,
                next_child_index: sorted_idx + 1,
            });
        }
    }

    for sorted_idx in 0..sorted.len() {
        let child = sorted.child(plan, sorted_idx).spec();
        if !child.key_range_start().is_empty()
            && !child.key_range_end().is_empty()
            && child.key_range_start() >= child.key_range_end()
        {
            return Err(SplitValidationError::InvertedChild {
                child_index: sorted_idx,
            });
        }
    }

    Ok(())
}

/// Validate all split-replace preconditions before any etcd writes.
///
/// Checks (in order): backend child-fanout cap, per-child spec validity,
/// coverage continuity against the parent's key range, and spawn-capacity
/// headroom. Returns the sorted child order on success so the caller can
/// derive child IDs in the same deterministic order.
fn split_replace_validate_preconditions<'a>(
    parent: &ShardRecord,
    plan: &'a SplitReplacePlan<'a>,
    slab: &ByteSlab,
    max_children_per_op: usize,
) -> Result<SplitChildOrder, SplitReplaceError> {
    let sorted = SplitChildOrder::from_plan(plan);

    if sorted.len() > max_children_per_op {
        return Err(SplitReplaceError::SplitInvalid(
            SplitValidationError::BackendChildLimitExceeded {
                requested: sorted.len(),
                backend_max: max_children_per_op,
            },
        ));
    }

    for sorted_idx in 0..sorted.len() {
        let child = sorted.child(plan, sorted_idx);
        if ShardSpec::validate_ref(child.spec()).is_err() {
            return Err(SplitReplaceError::SplitInvalid(
                SplitValidationError::InvalidChildSpec {
                    child_index: sorted_idx,
                },
            ));
        }
    }

    split_replace_validate_coverage_sorted(
        parent.spec.key_range_start(slab),
        parent.spec.key_range_end(slab),
        plan,
        &sorted,
    )
    .map_err(SplitReplaceError::SplitInvalid)?;

    if !parent.can_spawn(sorted.len()) {
        return Err(SplitReplaceError::SplitInvalid(
            SplitValidationError::SpawnLimitExceeded {
                current: parent.spawned.len(),
                additional: sorted.len(),
                max: MAX_SPAWNED_PER_SHARD,
            },
        ));
    }

    Ok(sorted)
}

/// Recover split-replace child IDs from the parent's spawned lineage tail.
///
/// `split_replace` makes the parent terminal (`Split` status), so once the
/// first execution commits, no later mutation can reorder or append
/// additional children. Replays therefore recover the previously published
/// child set directly from the last `plan_len` spawned entries.
///
/// # Panics
///
/// Panics if `parent.spawned.len() < plan_len`, indicating state corruption
/// (the spawned list is shorter than the plan that produced it).
fn split_replace_replay_child_ids(
    parent: &ShardRecord,
    slab: &ByteSlab,
    plan_len: usize,
) -> SplitChildIds {
    let base_index = parent
        .spawned
        .len()
        .checked_sub(plan_len)
        .expect("split_replace replay: parent.spawned shorter than plan; state corruption");

    let mut ids = SplitChildIds::new();
    for child_id in parent.spawned.iter(slab).skip(base_index) {
        ids.push(child_id);
    }

    debug_assert_eq!(ids.len(), plan_len);
    ids
}

/// Apply the parent-side mutation for `split_replace`.
///
/// The parent records the newly spawned children, transitions to terminal
/// `Split`, clears its lease, and logs the completed op before the record is
/// encoded into the enclosing etcd transaction.
fn split_replace_apply_parent(
    parent: &mut ShardRecord,
    child_ids: &[ShardId],
    op_id: OpId,
    payload_hash: u64,
    now: LogicalTime,
    slab: &mut ByteSlab,
) -> Result<(), SplitReplaceError> {
    assert!(!child_ids.is_empty(), "split_replace requires children");
    debug_assert!(parent.can_spawn(child_ids.len()));

    let (spawned_slot, spawned_len) = parent.spawned.allocate_appended_slot(child_ids, slab)?;
    parent.assert_transition_legal(ShardStatus::Split);
    parent.spawned.install_slot(spawned_slot, spawned_len, slab);
    parent.status = ShardStatus::Split;
    parent.lease = None;
    parent.op_log_push(OpLogEntry::new(
        op_id,
        OpKind::SplitReplace,
        OpResult::Completed,
        payload_hash,
        now,
    ));
    parent.assert_invariants(slab);
    Ok(())
}

/// Find a residual shard created by `split_residual(op_id)` in the parent's
/// permanent spawned lineage list.
///
/// Unlike the op-log, `spawned` entries are never evicted, so a residual
/// derived from `(run, parent, op_id, Residual, idx)` can still be found
/// even after many later operations have rotated the op-log.
fn find_replayed_residual(parent: &ShardRecord, slab: &ByteSlab, op_id: OpId) -> Option<ShardId> {
    for (idx, spawned_id) in parent.spawned.iter(slab).enumerate() {
        let derived = derive_split_shard_id(
            parent.run,
            parent.shard,
            op_id,
            DerivedShardKind::Residual,
            idx as u32,
        );
        if spawned_id == derived {
            return Some(derived);
        }
    }

    None
}

/// Detect an idempotent split-residual replay.
///
/// Residual splits leave the parent `Active`, so later checkpoints can
/// push the residual's op-log entry out of the fixed-capacity ring buffer.
/// Replays therefore probe in two stages:
///
/// 1. **Op-log** — checked first to preserve `OpIdConflict` semantics
///    (same op-id, different payload hash → conflict error).
/// 2. **Spawned lineage** — the permanent `parent.spawned` list is the
///    fallback. Unlike the op-log, spawned entries are never evicted, so
///    a residual derived from `(run, parent, op_id, Residual, idx)` can
///    always be found if it was ever committed.
fn split_residual_check_replay(
    parent: &ShardRecord,
    op_id: OpId,
    payload_hash: u64,
    slab: &ByteSlab,
) -> Result<Option<IdempotentOutcome<SplitResidualResult>>, SplitResidualError> {
    if check_op_idempotency(parent, op_id, payload_hash)?.is_some() {
        let residual = find_replayed_residual(parent, slab, op_id).expect(
            "split_residual replay hit in op-log without matching spawned residual; \
             state corruption",
        );
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual,
        })));
    }

    if let Some(residual) = find_replayed_residual(parent, slab, op_id) {
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual,
        })));
    }

    Ok(None)
}

/// Validate residual-split preconditions before any etcd writes.
fn split_residual_validate_preconditions(
    now: LogicalTime,
    tenant: TenantId,
    lease: &Lease,
    parent: &ShardRecord,
    plan: &SplitResidualPlan<'_>,
    slab: &ByteSlab,
) -> Result<(), SplitResidualError> {
    validate_lease(now, tenant, lease, parent)?;

    if ShardSpec::validate_ref(plan.parent_new_spec()).is_err() {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::InvalidChildSpec { child_index: 0 },
        ));
    }
    if ShardSpec::validate_ref(plan.residual_spec()).is_err() {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::InvalidChildSpec { child_index: 1 },
        ));
    }

    validate_residual_split_bounds(
        parent.spec.key_range_start(slab),
        parent.spec.key_range_end(slab),
        plan.parent_new_spec(),
        plan.residual_spec(),
    )
    .map_err(SplitResidualError::SplitInvalid)?;

    split_residual_validate_cursor_bounds(parent, slab, plan.parent_new_spec())?;

    if !parent.can_spawn(1) {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::SpawnLimitExceeded {
                current: parent.spawned.len(),
                additional: 1,
                max: MAX_SPAWNED_PER_SHARD,
            },
        ));
    }

    Ok(())
}

/// Ensure the parent's existing cursor stays inside its proposed new range.
fn split_residual_validate_cursor_bounds(
    parent: &ShardRecord,
    slab: &ByteSlab,
    new_parent_spec: ShardSpecRef<'_>,
) -> Result<(), SplitResidualError> {
    if let Some(last_key) = parent.cursor.last_key(slab)
        && !new_parent_spec.contains_key(last_key)
    {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::ParentCursorOutOfBounds {
                cursor: last_key.len(),
                new_parent_start: new_parent_spec.key_range_start().len(),
                new_parent_end: new_parent_spec.key_range_end().len(),
            },
        ));
    }

    Ok(())
}

/// Build the residual shard record for a fresh `split_residual`.
fn split_residual_build_record(
    parent: &ShardRecord,
    tenant: TenantId,
    residual_id: ShardId,
    plan: &SplitResidualPlan<'_>,
    slab: &mut ByteSlab,
) -> Result<ShardRecord, SplitResidualError> {
    ShardRecord::new_split_child(
        tenant,
        parent.run,
        residual_id,
        plan.residual_spec(),
        CursorUpdate::initial(),
        parent.cursor_semantics,
        parent.shard,
        slab,
    )
    .map_err(SplitResidualError::from)
}

/// Apply the parent-side mutation for `split_residual`.
///
/// The parent keeps its lease and active status, but records the new
/// residual in `spawned`, shrinks its spec, and logs the completed op.
/// If spec replacement fails after the spawned extension is staged, the
/// staged slot is explicitly deallocated before returning.
fn split_residual_apply_parent(
    parent: &mut ShardRecord,
    residual_id: ShardId,
    new_parent_spec: ShardSpecRef<'_>,
    op_id: OpId,
    payload_hash: u64,
    now: LogicalTime,
    slab: &mut ByteSlab,
) -> Result<(), SplitResidualError> {
    debug_assert!(parent.can_spawn(1));

    let (spawned_slot, spawned_len) = parent
        .spawned
        .allocate_appended_slot(core::slice::from_ref(&residual_id), slab)?;
    if let Err(err) = parent.spec.update_from_ref(new_parent_spec, slab) {
        slab.deallocate(spawned_slot);
        return Err(SplitResidualError::from(err));
    }

    parent.spawned.install_slot(spawned_slot, spawned_len, slab);
    parent.op_log_push(OpLogEntry::new(
        op_id,
        OpKind::SplitResidual,
        OpResult::Completed,
        payload_hash,
        now,
    ));
    parent.assert_invariants(slab);
    Ok(())
}

/// etcd-backed coordination backend.
///
/// Persists run creation, shard registration, read-side queries, and the
/// acquire/renew/checkpoint/split hot path directly in etcd. Remaining
/// mutating operations (complete, park, run transitions, unpark) panic
/// with a descriptive message until their persistence logic is implemented.
///
/// ## Threading model
///
/// Internally owns a single-threaded Tokio runtime and synchronizes via
/// `block_on`. Callers **must not** invoke methods from within an existing
/// Tokio runtime — `block_on` within `block_on` deadlocks. Debug-asserts
/// guard against this in `connect()` and `status()`.
///
/// ## Scratch allocation
///
/// `claim_candidates_scratch` is a reusable buffer for
/// [`default_claim_next_available`]. It is `mem::take`-ed at the start of
/// each claim and restored afterward, avoiding per-claim heap allocation
/// in the common case where the buffer capacity is already sufficient.
pub struct EtcdCoordinator {
    config: EtcdCoordinatorConfig,
    keyspace: EtcdKeyspace,
    runtime: tokio::runtime::Runtime,
    client: etcd_client::Client,
    /// Reusable buffer for shard-claim candidate collection, avoiding
    /// per-claim allocation.
    claim_candidates_scratch: Vec<ShardId>,
}

impl EtcdCoordinator {
    /// Connect to etcd, verify connectivity with `status`, and create the
    /// backend.
    ///
    /// # Panics
    ///
    /// Debug-asserts that no Tokio runtime is active on the current thread.
    /// The backend owns a single-threaded runtime internally and
    /// `block_on` within an existing runtime would deadlock.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError`] on config validation failure,
    /// Tokio runtime creation failure, connection failure, or if the
    /// initial `status` health check fails.
    pub fn connect(config: EtcdCoordinatorConfig) -> Result<Self, EtcdCoordinatorError> {
        config.validate()?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(EtcdCoordinatorError::RuntimeBuild)?;

        let endpoints = config.endpoints().to_vec();
        let mut connect_opts =
            etcd_client::ConnectOptions::new().with_connect_timeout(DEFAULT_CONNECT_TIMEOUT);
        if let Some((user, password)) = config.auth() {
            connect_opts = connect_opts.with_user(user, password);
        }
        #[cfg(feature = "tls")]
        if let Some(tls) = config.tls().cloned() {
            connect_opts = connect_opts.with_tls(tls);
        }

        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "connect() must not be called from within an active Tokio runtime"
        );

        let mut client = runtime
            .block_on(etcd_client::Client::connect(endpoints, Some(connect_opts)))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Connect,
                source,
            })?;

        runtime
            .block_on(client.status())
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })?;

        let keyspace = EtcdKeyspace::new(config.namespace_prefix())?;

        Ok(Self {
            config,
            keyspace,
            runtime,
            client,
            claim_candidates_scratch: Vec::new(),
        })
    }

    /// The validated configuration used to construct this backend.
    #[must_use]
    pub fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    /// The keyspace builder used for all etcd key construction.
    #[must_use]
    pub fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
    }

    /// Round-trip a maintenance `status` request against etcd.
    pub fn status(&self) -> Result<etcd_client::StatusResponse, EtcdCoordinatorError> {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "status() must not be called from within an active Tokio runtime"
        );

        let mut client = self.client.clone();
        self.runtime
            .block_on(client.status())
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })
    }

    /// Panics with a message identifying the unimplemented operation.
    ///
    /// Used as a placeholder for coordination operations whose etcd
    /// persistence logic has not been implemented. Callers should not
    /// catch this panic — it indicates a code path that must not be
    /// reached until the operation is persisted.
    fn fail_unimplemented<T>(&self, operation: &'static str) -> T {
        panic!(
            "EtcdCoordinator::{operation} is not yet persisted to etcd; \
             this operation must be implemented before it is callable"
        );
    }

    /// Panics on an unrecoverable storage error.
    ///
    /// Called when an etcd operation fails in a context where there is no
    /// meaningful recovery (e.g., encoding a shard record that was just
    /// successfully decoded). The panic message includes `context` for
    /// diagnosis.
    fn fatal_storage_error<T>(&self, context: &'static str, err: impl fmt::Display) -> T {
        panic!("etcd coordination backend {context} failed: {err}");
    }

    /// Create a decode slab sized as a multiple of the blob length,
    /// clamped to `[MIN_DECODE_SLAB_CAPACITY, MAX_DECODE_SLAB_CAPACITY]`.
    ///
    /// The 4× heuristic accounts for pooled field overhead (slab headers,
    /// alignment) relative to the raw wire bytes.
    fn make_decode_slab(blob_len: usize) -> ByteSlab {
        let cap = blob_len
            .saturating_mul(4)
            .clamp(MIN_DECODE_SLAB_CAPACITY, MAX_DECODE_SLAB_CAPACITY);
        ByteSlab::with_capacity(cap)
    }

    /// Estimate the slab capacity needed to encode one shard's pooled
    /// fields (spec + cursor + padding). Returns at least
    /// `DEFAULT_BUILD_SLAB_FLOOR`.
    fn build_slab_capacity_for_spec_and_cursor(
        spec: ShardSpecRef<'_>,
        cursor: CursorUpdate<'_>,
    ) -> usize {
        let cursor_last = cursor.last_key().map_or(0, |key| key.len());
        let cursor_token = cursor.token().map_or(0, |token| token.len());
        let needed = spec.key_range_start().len()
            + spec.key_range_end().len()
            + spec.metadata().len()
            + cursor_last
            + cursor_token
            + 256;
        needed.max(DEFAULT_BUILD_SLAB_FLOOR)
    }

    /// Estimate the slab capacity needed to encode one initial shard's
    /// pooled fields (spec + cursor + padding). Returns at least
    /// `DEFAULT_BUILD_SLAB_FLOOR`.
    fn build_slab_capacity_for_initial_shard(input: &InitialShardInput<'_>) -> usize {
        Self::build_slab_capacity_for_spec_and_cursor(input.spec(), input.cursor())
    }

    /// Execute a `get` RPC on the internal single-threaded Tokio runtime.
    fn etcd_get(
        &self,
        key: Vec<u8>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.get(key, options))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Get,
                source,
            })
    }

    /// Execute a `txn` (compare-and-swap) RPC on the internal runtime.
    fn etcd_txn(&self, txn: Txn) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.txn(txn))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Txn,
                source,
            })
    }

    /// Grant an etcd lease with the given TTL in seconds.
    fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.lease_grant(ttl, None))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseGrant,
                source,
            })
    }

    /// Send a single keep-alive ping for an existing etcd lease and
    /// consume the server ACK to confirm the renewal succeeded.
    fn etcd_lease_keep_alive_once(&self, lease_id: i64) -> Result<(), EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move {
                let (mut keeper, mut stream) = client.lease_keep_alive(lease_id).await?;
                keeper.keep_alive().await?;
                // The keep_alive() call only sends the request; the server
                // ACK (or error) arrives on the response stream. Read it to
                // confirm the lease was actually renewed.
                match stream.message().await? {
                    Some(resp) if resp.ttl() > 0 => Ok(()),
                    _ => Err(etcd_client::Error::LeaseKeepAliveError(
                        "lease expired or keep-alive rejected by server".into(),
                    )),
                }
            })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseKeepAlive,
                source,
            })
    }

    /// Immediately revoke an etcd lease, causing all keys attached to it
    /// to be deleted.
    fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.lease_revoke(lease_id))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseRevoke,
                source,
            })
    }

    #[cfg(test)]
    fn etcd_delete(
        &self,
        key: Vec<u8>,
        options: Option<DeleteOptions>,
    ) -> Result<etcd_client::DeleteResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.delete(key, options))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Delete,
                source,
            })
    }

    /// Load a single run record by exact key. Returns `None` if the key
    /// does not exist in etcd.
    fn load_run_record(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<PersistedRun>, EtcdCoordinatorError> {
        let key = self.keyspace.run_record_key(tenant, run).into_bytes();
        let response = self.etcd_get(key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };

        let record =
            decode_run_record(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            })?;

        Ok(Some(PersistedRun {
            record,
            mod_revision: kv.mod_revision(),
        }))
    }

    /// Decode an owner-key blob, wrapping codec errors with the given
    /// operation context.
    fn decode_owner_binding(
        &self,
        operation: EtcdOperation,
        bytes: &[u8],
    ) -> Result<OwnerLeaseValue, EtcdCoordinatorError> {
        decode_owner_value(bytes)
            .map_err(|source| EtcdCoordinatorError::Codec { operation, source })
    }

    /// Decode an owner-key KV pair, validating the non-zero lease invariant.
    ///
    /// Combines codec decoding with the structural check that every owner
    /// key must be attached to a real etcd lease (lease ID > 0).
    fn decode_owner_kv(
        &self,
        kv: &etcd_client::KeyValue,
    ) -> Result<PersistedOwner, EtcdCoordinatorError> {
        let binding = self.decode_owner_binding(EtcdOperation::Get, kv.value())?;
        if kv.lease() == 0 {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "OwnerKey",
                    detail: "owner key must be attached to a non-zero etcd lease",
                },
            });
        }
        Ok(PersistedOwner {
            binding,
            lease_id: kv.lease(),
        })
    }

    /// Verify that a persisted owner binding is consistent with the shard
    /// record's lease holder and fence epoch.
    ///
    /// Returns an invariant-violation error if the owner key exists but the
    /// shard record has no lease, or if the worker/fence fields disagree.
    fn validate_owner_consistency(
        owner: &PersistedOwner,
        record: &ShardRecord,
    ) -> Result<(), EtcdCoordinatorError> {
        let Some(holder) = record.lease() else {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "owner key exists but shard record lease is None",
                },
            });
        };
        if holder.owner() != owner.binding.worker || record.fence_epoch != owner.binding.fence {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "owner key binding disagrees with shard record lease or fence",
                },
            });
        }
        Ok(())
    }

    /// Load a single shard record and its owner binding by exact key.
    ///
    /// Uses a single prefix-range GET on the shard record key. Because
    /// shard IDs are fixed-width 16-char hex and the only child key is
    /// `/owner`, the prefix scan returns exactly the record KV and
    /// (optionally) the owner KV — no false matches against other shard
    /// IDs. Cross-validates the owner binding against the shard record's
    /// lease fields. Returns `None` if the shard record key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError::Codec`] with an invariant violation
    /// if the owner key exists but disagrees with the shard record's
    /// lease holder or fence epoch.
    fn load_shard_record(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<PersistedShard>, EtcdCoordinatorError> {
        let shard_record_key = self
            .keyspace
            .shard_record_key(tenant, key.run(), key.shard());

        // Single prefix-range scan fetches both the shard record and its
        // `/owner` child key in one etcd RPC.
        let response = self.etcd_get(
            shard_record_key.clone().into_bytes(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut record_kv: Option<&etcd_client::KeyValue> = None;
        let mut owner_kv: Option<&etcd_client::KeyValue> = None;

        for kv in response.kvs() {
            if kv.key() == shard_record_key.as_bytes() {
                record_kv = Some(kv);
            } else if kv.key().ends_with(b"/owner") {
                owner_kv = Some(kv);
            }
        }

        let Some(kv) = record_kv else {
            return Ok(None);
        };

        let mut slab = Self::make_decode_slab(kv.value().len());
        let record = decode_shard_record(kv.value(), &mut slab).map_err(|source| {
            EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            }
        })?;
        let mod_revision = kv.mod_revision();

        let owner = match owner_kv {
            None => None,
            Some(okv) => Some(self.decode_owner_kv(okv)?),
        };

        if let Some(owner) = &owner {
            Self::validate_owner_consistency(owner, &record)?;
        }

        Ok(Some(PersistedShard {
            record,
            slab,
            mod_revision,
            owner,
        }))
    }

    /// Prefix-scan all shard records (and their `/owner` keys) under a run.
    ///
    /// Issues a single etcd prefix-range `get` on the `shards/` subtree,
    /// then partitions the response into record KVs and owner KVs.
    /// Owner bindings are matched to their parent shard record by
    /// key suffix convention (`{shard_key}/owner`).
    ///
    /// Cross-validates every owner binding against its shard record and
    /// rejects orphaned owner keys (owner with no matching shard record).
    fn scan_run_shards(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Vec<PersistedShard>, EtcdCoordinatorError> {
        let prefix = self
            .keyspace
            .shard_records_scan_prefix(tenant, run)
            .into_bytes();
        let response = self.etcd_get(prefix, Some(GetOptions::new().with_prefix()))?;

        let mut owner_map = HashMap::<Vec<u8>, PersistedOwner>::new();
        let mut record_kvs = Vec::<(Vec<u8>, Vec<u8>, i64)>::new();

        for kv in response.kvs() {
            if kv.key().ends_with(b"/owner") {
                let owner = self.decode_owner_kv(kv)?;
                owner_map.insert(kv.key().to_vec(), owner);
            } else {
                record_kvs.push((kv.key().to_vec(), kv.value().to_vec(), kv.mod_revision()));
            }
        }

        let mut out = Vec::with_capacity(record_kvs.len());
        for (record_key, value, mod_revision) in record_kvs {
            let mut slab = Self::make_decode_slab(value.len());
            let record = decode_shard_record(&value, &mut slab).map_err(|source| {
                EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                }
            })?;

            let mut owner_key = record_key.clone();
            owner_key.extend_from_slice(b"/owner");
            let owner = owner_map.remove(&owner_key);

            if let Some(owner) = &owner {
                Self::validate_owner_consistency(owner, &record)?;
            }

            out.push(PersistedShard {
                record,
                slab,
                mod_revision,
                owner,
            });
        }

        if !owner_map.is_empty() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "OwnerKey",
                    detail: "owner key exists without a corresponding shard record",
                },
            });
        }

        Ok(out)
    }

    /// Determine the effective observation time for a shard's status.
    ///
    /// If the shard has a live owner at `now`, uses `now` directly. Otherwise,
    /// falls back to the shard's persisted lease deadline (the last known
    /// expiration). This ensures expired leases are visible as expired in
    /// `ShardFilter` evaluations even when `now` predates the deadline
    /// (e.g., when `LogicalTime` is not wall-clock-aligned).
    fn visible_now(persisted: &PersistedShard, now: LogicalTime) -> LogicalTime {
        if persisted.owner_is_live_at(now) {
            now
        } else {
            persisted.record.lease_deadline().unwrap_or(now)
        }
    }

    /// Lightweight capacity hint using count-only and keys-only RPCs.
    ///
    /// Returns the number of active shards without an owner key. Uses two
    /// etcd RPCs with minimal data transfer (no shard record values decoded):
    ///
    /// 1. `count_only` on the `shards_active/` prefix → total active shards.
    /// 2. `keys_only` on the `shards/` prefix, counting `/owner` suffixes →
    ///    owned shard count.
    ///
    /// `earliest_deadline` is always `None` because computing it would require
    /// decoding shard record values, defeating the purpose. The facade's claim
    /// path computes deadlines separately via `collect_claim_candidates_into`.
    fn count_available_lightweight(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<CapacityHint, EtcdCoordinatorError> {
        let active_prefix = self.keyspace.shards_active_prefix(tenant, run).into_bytes();
        let active_response = self.etcd_get(
            active_prefix,
            Some(GetOptions::new().with_prefix().with_count_only()),
        )?;
        let total_active = active_response.count() as u32;

        let shards_prefix = self
            .keyspace
            .shard_records_scan_prefix(tenant, run)
            .into_bytes();
        let keys_response = self.etcd_get(
            shards_prefix,
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        let owned_count = keys_response
            .kvs()
            .iter()
            .filter(|kv| kv.key().ends_with(b"/owner"))
            .count() as u32;

        Ok(CapacityHint {
            available_count: total_active.saturating_sub(owned_count),
            earliest_deadline: None,
        })
    }

    // -----------------------------------------------------------------------
    // etcd CAS guard helpers
    // -----------------------------------------------------------------------
    //
    // Each helper builds one or more `Compare` clauses for an etcd
    // transaction. The transaction succeeds only if all comparisons pass;
    // failure means a concurrent writer modified the guarded key(s).

    /// CAS guard: shard record key has not been modified since `mod_revision`.
    fn compare_shard_revision(shard_record_key: String, mod_revision: i64) -> Compare {
        Compare::mod_revision(shard_record_key, CompareOp::Equal, mod_revision)
    }

    /// CAS guard: run record key has not been modified since `mod_revision`.
    fn compare_run_revision(run_record_key: String, mod_revision: i64) -> Compare {
        Compare::mod_revision(run_record_key, CompareOp::Equal, mod_revision)
    }

    /// CAS guard: the key must not exist (etcd version == 0).
    ///
    /// Used to ensure a shard or run record is being created for the first
    /// time, preventing double-registration.
    fn compare_absent(key: String) -> Compare {
        Compare::version(key, CompareOp::Equal, 0)
    }

    /// CAS guard: owner key must exist (version > 0) with the given value
    /// and be attached to the expected etcd lease.
    ///
    /// Returns three `Compare` clauses: existence, value equality, and
    /// lease identity. The lease check prevents a stale worker from
    /// passing the value guard after another worker reuses the same
    /// worker ID + fence epoch with a different etcd lease.
    fn compare_owner_present(
        owner_key: String,
        owner_value: Vec<u8>,
        lease_id: i64,
    ) -> Vec<Compare> {
        vec![
            Compare::version(owner_key.clone(), CompareOp::Greater, 0),
            Compare::value(owner_key.clone(), CompareOp::Equal, owner_value),
            Compare::lease(owner_key, CompareOp::Equal, lease_id),
        ]
    }

    /// Attempt to revoke an etcd lease, ignoring errors.
    ///
    /// Used for cleanup after a CAS failure when the lease is no longer
    /// needed. If the revocation fails (e.g., network error), the lease
    /// will eventually expire via etcd's TTL mechanism.
    fn best_effort_revoke_lease(&self, lease_id: i64) {
        if lease_id <= 0 {
            return;
        }
        let _ = self.etcd_lease_revoke(lease_id);
    }

    /// Load a run record, panicking if the key is missing or unreadable.
    ///
    /// Used in paths where the run is expected to exist (e.g., after
    /// a successful `create_run`).
    fn load_run_or_panic(&self, tenant: TenantId, run: RunId) -> PersistedRun {
        match self.load_run_record(tenant, run) {
            Ok(Some(run_record)) => run_record,
            Ok(None) => self.fatal_storage_error("load run", format!("run {run:?} missing")),
            Err(err) => self.fatal_storage_error("load run", err),
        }
    }

    /// Load a shard record, panicking if the key is missing or unreadable.
    fn load_shard_or_panic(&self, tenant: TenantId, key: ShardKey) -> PersistedShard {
        match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => shard,
            Ok(None) => self.fatal_storage_error("load shard", format!("shard {key:?} missing")),
            Err(err) => self.fatal_storage_error("load shard", err),
        }
    }

    /// Construct a new `ShardRecord` from registration input and encode it
    /// into a binary blob ready for etcd storage.
    fn build_root_shard_blob(
        &self,
        tenant: TenantId,
        run: RunId,
        cursor_semantics: gossip_coordination::CursorSemantics,
        input: &InitialShardInput<'_>,
    ) -> Result<Vec<u8>, RegisterShardsError> {
        let mut slab = ByteSlab::with_capacity(Self::build_slab_capacity_for_initial_shard(input));
        let record = ShardRecord::new_active_with_cursor(
            tenant,
            run,
            input.shard(),
            input.spec(),
            input.cursor(),
            cursor_semantics,
            &mut slab,
        )
        .map_err(|_| RegisterShardsError::ResourceExhausted {
            resource: "shard_slab",
        })?;

        Ok(encode_shard_record(&record, &slab)
            .unwrap_or_else(|err| self.fatal_storage_error("register_shards.encode_shard", err)))
    }

    #[cfg(test)]
    pub(crate) fn test_clear_namespace(&self) -> Result<(), EtcdCoordinatorError> {
        self.etcd_delete(
            self.keyspace.prefix().as_bytes().to_vec(),
            Some(DeleteOptions::new().with_prefix()),
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_load_owner_binding(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(WorkerId, FenceEpoch, i64)>, EtcdCoordinatorError> {
        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        let response = self.etcd_get(owner_key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        let binding = self.decode_owner_binding(EtcdOperation::Get, kv.value())?;
        Ok(Some((binding.worker, binding.fence, kv.lease())))
    }

    #[cfg(test)]
    pub(crate) fn test_load_shard_snapshot(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(ShardRecord, TestSlab)>, EtcdCoordinatorError> {
        match self.load_shard_record(tenant, key)? {
            None => Ok(None),
            Some(persisted) => Ok(Some((
                persisted.record,
                TestSlab::from_slab(persisted.slab),
            ))),
        }
    }
}

impl fmt::Debug for EtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdCoordinator")
            .field("endpoint_count", &self.config.endpoints().len())
            .field("namespace_prefix", &self.keyspace.prefix())
            .field(
                "coordination_storage_mode",
                &"persisted acquire/renew/checkpoint/split + run registration in etcd",
            )
            .finish()
    }
}

impl CoordinationBackend for EtcdCoordinator {
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        for attempt in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(AcquireError::ShardNotFound { shard: key }),
                Err(err) => {
                    return Err(AcquireError::BackendError {
                        message: format!("acquire.load_shard: {err}"),
                    });
                }
            };

            if persisted.record.tenant != tenant {
                return Err(AcquireError::TenantMismatch { expected: tenant });
            }
            if persisted.record.status != ShardStatus::Active {
                return Err(AcquireError::ShardTerminal {
                    shard: key,
                    status: persisted.record.status,
                });
            }
            if persisted.owner_is_live_at(now) {
                return Err(AcquireError::AlreadyLeased {
                    current_owner: persisted
                        .record
                        .lease_owner()
                        .expect("live owner key must match shard record lease"),
                    lease_deadline: persisted
                        .record
                        .lease_deadline()
                        .expect("live owner key must match shard record deadline"),
                });
            }

            let run_record = self.load_run_or_panic(tenant, key.run());
            let lease_duration = run_record.record.config.lease_duration();
            let new_deadline = now
                .checked_add(lease_duration)
                .unwrap_or(LogicalTime::from_raw(u64::MAX));
            let grant = match self.etcd_lease_grant(self.config.owner_lease_ttl_secs()) {
                Ok(g) => g,
                Err(err) => {
                    return Err(AcquireError::BackendError {
                        message: format!("acquire.lease_grant: {err}"),
                    });
                }
            };
            let new_lease_id = grant.id();
            let prior_lease_id = persisted.owner.as_ref().map(|owner| owner.lease_id);

            let mut persisted = persisted;
            let new_fence = persisted.record.advance_fence();
            persisted.record.lease = Some(LeaseHolder::new(worker, new_deadline));
            persisted.record.assert_invariants(&persisted.slab);
            let shard_blob = encode_shard_record(&persisted.record, &persisted.slab)
                .unwrap_or_else(|err| self.fatal_storage_error("acquire.encode_shard", err));
            let owner_blob = encode_owner_value(worker, new_fence);

            let shard_record_key = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            if let Some(expected_owner) = persisted.expected_owner_value() {
                let prior_etcd_lease =
                    prior_lease_id.expect("owner value present implies owner lease_id is known");
                compares.extend(Self::compare_owner_present(
                    owner_key.clone(),
                    expected_owner,
                    prior_etcd_lease,
                ));
            } else {
                compares.push(Self::compare_absent(owner_key.clone()));
            }

            let txn = Txn::new().when(compares).and_then(vec![
                TxnOp::put(shard_record_key.into_bytes(), shard_blob, None),
                TxnOp::put(
                    owner_key.into_bytes(),
                    owner_blob,
                    Some(PutOptions::new().with_lease(new_lease_id)),
                ),
            ]);
            let response = match self.etcd_txn(txn) {
                Ok(r) => r,
                Err(err) => {
                    self.best_effort_revoke_lease(new_lease_id);
                    return Err(AcquireError::BackendError {
                        message: format!("acquire.txn: {err}"),
                    });
                }
            };
            if !response.succeeded() {
                self.best_effort_revoke_lease(new_lease_id);
                std::thread::sleep(cas_retry_delay(attempt));
                continue;
            }

            if let Some(old_lease_id) = prior_lease_id {
                self.best_effort_revoke_lease(old_lease_id);
            }

            // Best-effort: read capacity after the CAS succeeds. If the
            // hint read fails (transport blip, leader election), degrade
            // to a conservative zero-available hint rather than returning
            // an error — the shard record and owner key are already
            // committed, so reporting failure would lie about ownership
            // and can strand the shard behind the new lease.
            let capacity = self
                .count_available_lightweight(tenant, key.run())
                .unwrap_or(CapacityHint::ZERO);

            let lease = Lease::new(
                tenant,
                key.run(),
                key.shard(),
                worker,
                new_fence,
                new_deadline,
            );
            out.reset();
            out.write_spec(
                persisted.record.spec.key_range_start(&persisted.slab),
                persisted.record.spec.key_range_end(&persisted.slab),
                persisted.record.spec.metadata(&persisted.slab),
            );
            out.write_cursor(
                persisted.record.cursor.last_key(&persisted.slab),
                persisted.record.cursor.token(&persisted.slab),
            );
            out.write_spawned_iter(persisted.record.spawned.iter(&persisted.slab));
            let snapshot = out.view(
                persisted.record.status,
                persisted.record.cursor_semantics,
                persisted.record.parent,
            );

            return Ok(AcquireResultView {
                lease,
                snapshot,
                capacity,
            });
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if persisted.record.tenant != tenant {
            return Err(AcquireError::TenantMismatch { expected: tenant });
        }
        if persisted.record.status != ShardStatus::Active {
            return Err(AcquireError::ShardTerminal {
                shard: key,
                status: persisted.record.status,
            });
        }
        if persisted.owner_is_live_at(now) {
            return Err(AcquireError::AlreadyLeased {
                current_owner: persisted
                    .record
                    .lease_owner()
                    .expect("live owner key must match record owner"),
                lease_deadline: persisted
                    .record
                    .lease_deadline()
                    .expect("live owner key must match record deadline"),
            });
        }

        self.fatal_storage_error(
            "acquire.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = lease.shard_key();

        for attempt in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(RenewError::ShardNotFound { shard: key }),
                Err(err) => {
                    return Err(RenewError::BackendError {
                        message: format!("renew.load_shard: {err}"),
                    });
                }
            };

            validate_lease(now, tenant, lease, &persisted.record)?;
            if !persisted.owner_matches_lease(lease) {
                return Err(RenewError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }

            let run_record = self.load_run_or_panic(tenant, key.run());
            let lease_duration = run_record.record.config.lease_duration();
            let new_deadline = now
                .checked_add(lease_duration)
                .unwrap_or(LogicalTime::from_raw(u64::MAX));

            let old_lease_id = persisted
                .owner
                .as_ref()
                .map(|owner| owner.lease_id)
                .expect("validated owner must exist");

            let mut persisted = persisted;
            persisted.record.lease = Some(LeaseHolder::new(lease.owner(), new_deadline));
            persisted.record.assert_invariants(&persisted.slab);
            let shard_blob = encode_shard_record(&persisted.record, &persisted.slab)
                .unwrap_or_else(|err| self.fatal_storage_error("renew.encode_shard", err));
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce owner value");

            let shard_record_key = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(
                owner_key,
                owner_blob,
                old_lease_id,
            ));

            let txn = Txn::new().when(compares).and_then(vec![TxnOp::put(
                shard_record_key.into_bytes(),
                shard_blob,
                None,
            )]);
            let response = match self.etcd_txn(txn) {
                Ok(r) => r,
                Err(err) => {
                    return Err(RenewError::BackendError {
                        message: format!("renew.txn: {err}"),
                    });
                }
            };
            if response.succeeded() {
                // Best-effort: extend the etcd lease TTL after the CAS
                // succeeds. If the keep-alive fails (transport blip or the
                // lease expired in the tiny window between CAS and this
                // call), the CAS already committed the new deadline to the
                // shard record. The next renew cycle will detect ownership
                // loss via `owner_matches_lease` if the owner key was
                // deleted. Returning an error here would lie about the
                // outcome — the shard record IS updated.
                let _ = self.etcd_lease_keep_alive_once(old_lease_id);
                // Best-effort: read capacity after the CAS succeeds. If
                // the hint read fails, degrade to a conservative
                // zero-available hint — the new deadline is already
                // persisted, so returning an error would misreport the
                // outcome and cause callers to drop work.
                let capacity = self
                    .count_available_lightweight(tenant, key.run())
                    .unwrap_or(CapacityHint::ZERO);
                return Ok(RenewResult {
                    new_deadline,
                    capacity,
                });
            }
            std::thread::sleep(cas_retry_delay(attempt));
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        validate_lease(now, tenant, lease, &persisted.record)?;
        if !persisted.owner_matches_lease(lease) {
            return Err(RenewError::StaleFence {
                presented: lease.fence(),
                current: persisted.record.fence_epoch,
            });
        }

        self.fatal_storage_error(
            "renew.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let key = lease.shard_key();
        let payload_hash = hash_checkpoint_payload(new_cursor);

        for attempt in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(CheckpointError::ShardNotFound { shard: key }),
                Err(err) => {
                    return Err(CheckpointError::BackendError {
                        message: format!("checkpoint.load_shard: {err}"),
                    });
                }
            };

            if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                return Ok(IdempotentOutcome::Replayed(()));
            }
            validate_lease(now, tenant, lease, &persisted.record)?;
            if !persisted.owner_matches_lease(lease) {
                return Err(CheckpointError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }
            validate_cursor_update_pooled(
                new_cursor,
                persisted.record.cursor.last_key(&persisted.slab),
                persisted.record.spec.key_range_start(&persisted.slab),
                persisted.record.spec.key_range_end(&persisted.slab),
            )?;

            let mut persisted = persisted;
            persisted
                .record
                .cursor
                .update_from_ref(new_cursor, &mut persisted.slab)?;
            persisted.record.op_log_push(OpLogEntry::new(
                op_id,
                OpKind::Checkpoint,
                OpResult::Completed,
                payload_hash,
                now,
            ));
            persisted.record.assert_invariants(&persisted.slab);
            let shard_blob = encode_shard_record(&persisted.record, &persisted.slab)
                .unwrap_or_else(|err| self.fatal_storage_error("checkpoint.encode_shard", err));
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce owner value");
            let owner_lease_id = persisted
                .owner
                .as_ref()
                .expect("validated owner must have lease_id")
                .lease_id;

            let shard_record_key = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(
                owner_key,
                owner_blob,
                owner_lease_id,
            ));

            let txn = Txn::new().when(compares).and_then(vec![TxnOp::put(
                shard_record_key.into_bytes(),
                shard_blob,
                None,
            )]);
            let response = match self.etcd_txn(txn) {
                Ok(r) => r,
                Err(err) => {
                    return Err(CheckpointError::BackendError {
                        message: format!("checkpoint.txn: {err}"),
                    });
                }
            };
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(()));
            }
            std::thread::sleep(cas_retry_delay(attempt));
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }
        validate_lease(now, tenant, lease, &persisted.record)?;
        if !persisted.owner_matches_lease(lease) {
            return Err(CheckpointError::StaleFence {
                presented: lease.fence(),
                current: persisted.record.fence_epoch,
            });
        }

        self.fatal_storage_error(
            "checkpoint.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    fn complete(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _final_cursor: &CursorUpdate<'_>,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.fail_unimplemented("complete")
    }

    fn park_shard(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _reason: ParkReason,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.fail_unimplemented("park_shard")
    }

    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_replace_payload(&plan);

        for attempt in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(SplitReplaceError::ShardNotFound { shard: key }),
                Err(err) => {
                    return Err(SplitReplaceError::BackendError {
                        message: format!("split_replace.load_shard: {err}"),
                    });
                }
            };

            if persisted.record.tenant != tenant {
                return Err(SplitReplaceError::TenantMismatch { expected: tenant });
            }
            if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                let children = split_replace_replay_child_ids(
                    &persisted.record,
                    &persisted.slab,
                    plan.children().len(),
                );
                return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
            }
            if persisted.record.status != ShardStatus::Active {
                return Err(SplitReplaceError::ShardTerminal {
                    shard: key,
                    status: persisted.record.status,
                });
            }
            validate_lease(now, tenant, lease, &persisted.record)?;
            if !persisted.owner_matches_lease(lease) {
                return Err(SplitReplaceError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }

            let sorted = split_replace_validate_preconditions(
                &persisted.record,
                &plan,
                &persisted.slab,
                self.config.max_children_per_op(),
            )?;

            let mut child_ids = SplitChildIds::new();
            let mut child_puts = Vec::with_capacity(sorted.len());
            let mut child_index_ops = Vec::with_capacity(sorted.len());
            let mut child_absent_compares = Vec::with_capacity(sorted.len());

            for sorted_index in 0..sorted.len() {
                let child = sorted.child(&plan, sorted_index);
                let child_id = derive_split_shard_id(
                    persisted.record.run,
                    persisted.record.shard,
                    op_id,
                    DerivedShardKind::Child,
                    u32::try_from(persisted.record.spawned.len() + sorted_index)
                        .expect("child index exceeds u32"),
                );
                let child_key = ShardKey::new(persisted.record.run, child_id);

                match self.load_shard_record(tenant, child_key) {
                    Ok(Some(_)) => {
                        return Err(SplitReplaceError::SplitInvalid(
                            SplitValidationError::DerivedIdCollision {
                                derived_id: child_id,
                            },
                        ));
                    }
                    Ok(None) => {}
                    Err(err) => {
                        return Err(SplitReplaceError::BackendError {
                            message: format!("split_replace.preflight_child_absence: {err}"),
                        });
                    }
                }

                let mut child_slab = ByteSlab::with_capacity(
                    Self::build_slab_capacity_for_spec_and_cursor(child.spec(), child.cursor()),
                );
                let child_record = ShardRecord::new_split_child(
                    tenant,
                    persisted.record.run,
                    child_id,
                    child.spec(),
                    child.cursor(),
                    persisted.record.cursor_semantics,
                    persisted.record.shard,
                    &mut child_slab,
                )?;
                child_record.assert_invariants(&child_slab);

                let child_record_key =
                    self.keyspace
                        .shard_record_key(tenant, persisted.record.run, child_id);
                child_absent_compares.push(Self::compare_absent(child_record_key.clone()));
                child_puts.push(TxnOp::put(
                    child_record_key.into_bytes(),
                    encode_shard_record(&child_record, &child_slab).unwrap_or_else(|err| {
                        self.fatal_storage_error("split_replace.encode_child", err)
                    }),
                    None,
                ));
                child_index_ops.push(TxnOp::put(
                    self.keyspace
                        .shard_active_index_key(tenant, persisted.record.run, child_id)
                        .into_bytes(),
                    Vec::new(),
                    None,
                ));
                child_ids.push(child_id);
            }

            let mut persisted = persisted;
            split_replace_apply_parent(
                &mut persisted.record,
                child_ids.as_slice(),
                op_id,
                payload_hash,
                now,
                &mut persisted.slab,
            )?;
            let parent_blob = encode_shard_record(&persisted.record, &persisted.slab)
                .unwrap_or_else(|err| self.fatal_storage_error("split_replace.encode_parent", err));
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce an owner value");
            let owner_lease_id = persisted
                .owner
                .as_ref()
                .expect("validated owner must carry an etcd lease id")
                .lease_id;

            let shard_record_key = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(
                owner_key.clone(),
                owner_blob,
                owner_lease_id,
            ));
            compares.extend(child_absent_compares);

            let mut ops = Vec::with_capacity(3 + child_puts.len() + child_index_ops.len());
            ops.push(TxnOp::put(shard_record_key.into_bytes(), parent_blob, None));
            ops.push(TxnOp::delete(owner_key.into_bytes(), None));
            ops.push(TxnOp::delete(
                self.keyspace
                    .shard_active_index_key(tenant, key.run(), key.shard())
                    .into_bytes(),
                None,
            ));
            ops.extend(child_puts);
            ops.extend(child_index_ops);

            let txn = Txn::new().when(compares).and_then(ops);
            let response = match self.etcd_txn(txn) {
                Ok(r) => r,
                Err(err) => {
                    return Err(SplitReplaceError::BackendError {
                        message: format!("split_replace.txn: {err}"),
                    });
                }
            };
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(SplitReplaceResult {
                    children: child_ids,
                }));
            }
            std::thread::sleep(cas_retry_delay(attempt));
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
            let children = split_replace_replay_child_ids(
                &persisted.record,
                &persisted.slab,
                plan.children().len(),
            );
            return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
        }
        if persisted.record.status != ShardStatus::Active {
            return Err(SplitReplaceError::ShardTerminal {
                shard: key,
                status: persisted.record.status,
            });
        }
        validate_lease(now, tenant, lease, &persisted.record)?;
        if !persisted.owner_matches_lease(lease) {
            return Err(SplitReplaceError::StaleFence {
                presented: lease.fence(),
                current: persisted.record.fence_epoch,
            });
        }

        self.fatal_storage_error(
            "split_replace.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_residual_payload(&plan);

        for attempt in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(SplitResidualError::ShardNotFound { shard: key }),
                Err(err) => {
                    return Err(SplitResidualError::BackendError {
                        message: format!("split_residual.load_shard: {err}"),
                    });
                }
            };

            if persisted.record.tenant != tenant {
                return Err(SplitResidualError::TenantMismatch { expected: tenant });
            }
            if let Some(replay) = split_residual_check_replay(
                &persisted.record,
                op_id,
                payload_hash,
                &persisted.slab,
            )? {
                return Ok(replay);
            }
            if persisted.record.status != ShardStatus::Active {
                return Err(SplitResidualError::ShardTerminal {
                    shard: key,
                    status: persisted.record.status,
                });
            }
            split_residual_validate_preconditions(
                now,
                tenant,
                lease,
                &persisted.record,
                &plan,
                &persisted.slab,
            )?;
            if !persisted.owner_matches_lease(lease) {
                return Err(SplitResidualError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }

            let residual_id = derive_split_shard_id(
                persisted.record.run,
                persisted.record.shard,
                op_id,
                DerivedShardKind::Residual,
                u32::try_from(persisted.record.spawned.len()).expect("spawned index exceeds u32"),
            );
            let residual_key = ShardKey::new(persisted.record.run, residual_id);
            match self.load_shard_record(tenant, residual_key) {
                Ok(Some(_)) => {
                    return Err(SplitResidualError::SplitInvalid(
                        SplitValidationError::DerivedIdCollision {
                            derived_id: residual_id,
                        },
                    ));
                }
                Ok(None) => {}
                Err(err) => {
                    return Err(SplitResidualError::BackendError {
                        message: format!("split_residual.preflight_child_absence: {err}"),
                    });
                }
            }

            let mut residual_slab =
                ByteSlab::with_capacity(Self::build_slab_capacity_for_spec_and_cursor(
                    plan.residual_spec(),
                    CursorUpdate::initial(),
                ));
            let residual_record = split_residual_build_record(
                &persisted.record,
                tenant,
                residual_id,
                &plan,
                &mut residual_slab,
            )?;
            residual_record.assert_invariants(&residual_slab);

            let residual_record_key =
                self.keyspace
                    .shard_record_key(tenant, persisted.record.run, residual_id);

            let mut persisted = persisted;
            split_residual_apply_parent(
                &mut persisted.record,
                residual_id,
                plan.parent_new_spec(),
                op_id,
                payload_hash,
                now,
                &mut persisted.slab,
            )?;
            let parent_blob = encode_shard_record(&persisted.record, &persisted.slab)
                .unwrap_or_else(|err| {
                    self.fatal_storage_error("split_residual.encode_parent", err)
                });
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce an owner value");
            let owner_lease_id = persisted
                .owner
                .as_ref()
                .expect("validated owner must carry an etcd lease id")
                .lease_id;

            let shard_record_key = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(
                owner_key,
                owner_blob,
                owner_lease_id,
            ));
            compares.push(Self::compare_absent(residual_record_key.clone()));

            let ops = vec![
                TxnOp::put(shard_record_key.into_bytes(), parent_blob, None),
                TxnOp::put(
                    residual_record_key.into_bytes(),
                    encode_shard_record(&residual_record, &residual_slab).unwrap_or_else(|err| {
                        self.fatal_storage_error("split_residual.encode_residual", err)
                    }),
                    None,
                ),
                TxnOp::put(
                    self.keyspace
                        .shard_active_index_key(tenant, persisted.record.run, residual_id)
                        .into_bytes(),
                    Vec::new(),
                    None,
                ),
            ];

            let txn = Txn::new().when(compares).and_then(ops);
            let response = match self.etcd_txn(txn) {
                Ok(r) => r,
                Err(err) => {
                    return Err(SplitResidualError::BackendError {
                        message: format!("split_residual.txn: {err}"),
                    });
                }
            };
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(SplitResidualResult {
                    residual: residual_id,
                }));
            }
            std::thread::sleep(cas_retry_delay(attempt));
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if let Some(replay) =
            split_residual_check_replay(&persisted.record, op_id, payload_hash, &persisted.slab)?
        {
            return Ok(replay);
        }
        if persisted.record.status != ShardStatus::Active {
            return Err(SplitResidualError::ShardTerminal {
                shard: key,
                status: persisted.record.status,
            });
        }
        validate_lease(now, tenant, lease, &persisted.record)?;
        if !persisted.owner_matches_lease(lease) {
            return Err(SplitResidualError::StaleFence {
                presented: lease.fence(),
                current: persisted.record.fence_epoch,
            });
        }

        self.fatal_storage_error(
            "split_residual.compare_retry_budget",
            "compare contention did not converge",
        )
    }
}

impl RunManagement for EtcdCoordinator {
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        config.assert_valid();

        let record = RunRecord {
            tenant,
            run,
            config,
            status: RunStatus::Initializing,
            created_at: now,
            completed_at: None,
            root_shards: Vec::new(),
            op_log: RingBuffer::new(),
        };
        record.assert_invariants();

        let key = self.keyspace.run_record_key(tenant, run);
        let blob = encode_run_record(&record);
        let txn = Txn::new()
            .when(vec![Self::compare_absent(key.clone())])
            .and_then(vec![TxnOp::put(key.into_bytes(), blob, None)]);
        let response = match self.etcd_txn(txn) {
            Ok(r) => r,
            Err(err) => {
                return Err(CreateRunError::BackendError {
                    message: format!("create_run.txn: {err}"),
                });
            }
        };
        if response.succeeded() {
            return Ok(record);
        }

        Err(CreateRunError::RunAlreadyExists { run })
    }

    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        if shards.len() > MAX_SHARDS_PER_ETCD_TXN {
            return Err(RegisterShardsError::ResourceExhausted {
                resource: "etcd_txn_ops",
            });
        }

        let payload_hash = hash_register_shards_payload(shards);

        for attempt in 0..self.config.optimistic_txn_retries() {
            let persisted_run = match self.load_run_record(tenant, run) {
                Ok(Some(run_record)) => run_record,
                Ok(None) => return Err(RegisterShardsError::RunNotFound),
                Err(err) => {
                    return Err(RegisterShardsError::BackendError {
                        message: format!("register_shards.load_run: {err}"),
                    });
                }
            };
            let mut run_record = persisted_run.record;

            if run_record.tenant != tenant {
                return Err(RegisterShardsError::TenantMismatch { expected: tenant });
            }
            if let Some(entry) = run_record.check_op_idempotency(op_id, payload_hash)? {
                assert_eq!(
                    entry.kind(),
                    RunOpKind::RegisterShards,
                    "idempotent replay kind mismatch: expected RegisterShards, got {:?}",
                    entry.kind()
                );
                match entry.result() {
                    RunOpResult::RegisteredShards { shard_ids } => {
                        return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                    }
                    RunOpResult::Ack => {
                        panic!(
                            "Run {run:?}: RegisterShards op-log entry has Ack result \
                             (expected RegisteredShards) — data corruption"
                        );
                    }
                }
            }
            if run_record.status != RunStatus::Initializing {
                return Err(RegisterShardsError::WrongStatus {
                    status: run_record.status,
                });
            }

            validate_manifest(shards).map_err(RegisterShardsError::ManifestInvalid)?;

            let cursor_semantics = run_record.config.cursor_semantics();
            let shard_ids: Vec<ShardId> = shards.iter().map(InitialShardInput::shard).collect();

            let mut txn_ops = Vec::with_capacity(1 + (shards.len() * 2) + 1);
            let mut compares = Vec::with_capacity(1 + shards.len());
            let run_key = self.keyspace.run_record_key(tenant, run);
            compares.push(Self::compare_run_revision(
                run_key.clone(),
                persisted_run.mod_revision,
            ));

            for shard in shards {
                let shard_key = self.keyspace.shard_record_key(tenant, run, shard.shard());
                compares.push(Self::compare_absent(shard_key.clone()));
                let shard_blob =
                    self.build_root_shard_blob(tenant, run, cursor_semantics, shard)?;
                txn_ops.push(TxnOp::put(shard_key.into_bytes(), shard_blob, None));

                let active_index = self
                    .keyspace
                    .shard_active_index_key(tenant, run, shard.shard());
                txn_ops.push(TxnOp::put(
                    active_index.into_bytes(),
                    Vec::<u8>::new(),
                    None,
                ));
            }

            run_record.assert_transition_legal(RunStatus::Active);
            run_record.status = RunStatus::Active;
            run_record.root_shards = shard_ids.clone();
            run_record.op_log_push(RunOpLogEntry::new(
                op_id,
                RunOpKind::RegisterShards,
                payload_hash,
                now,
                RunOpResult::RegisteredShards {
                    shard_ids: shard_ids.clone().into_boxed_slice(),
                },
            ));
            run_record.assert_invariants();
            let run_blob = encode_run_record(&run_record);

            txn_ops.insert(0, TxnOp::put(run_key.into_bytes(), run_blob, None));
            let run_active_key = self.keyspace.run_active_index_key(tenant, run);
            txn_ops.push(TxnOp::put(
                run_active_key.into_bytes(),
                Vec::<u8>::new(),
                None,
            ));

            let txn = Txn::new().when(compares).and_then(txn_ops);
            let response = match self.etcd_txn(txn) {
                Ok(r) => r,
                Err(err) => {
                    return Err(RegisterShardsError::BackendError {
                        message: format!("register_shards.txn: {err}"),
                    });
                }
            };
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(shard_ids));
            }
            std::thread::sleep(cas_retry_delay(attempt));
        }

        let persisted_run = self.load_run_or_panic(tenant, run);
        if let Some(entry) = persisted_run
            .record
            .check_op_idempotency(op_id, payload_hash)?
        {
            match entry.result() {
                RunOpResult::RegisteredShards { shard_ids } => {
                    return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                }
                RunOpResult::Ack => {
                    panic!(
                        "Run {run:?}: RegisterShards op-log entry has Ack result \
                         (expected RegisteredShards) — data corruption"
                    );
                }
            }
        }
        if persisted_run.record.status != RunStatus::Initializing {
            return Err(RegisterShardsError::WrongStatus {
                status: persisted_run.record.status,
            });
        }

        self.fatal_storage_error(
            "register_shards.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        match self.load_run_record(tenant, run) {
            Ok(Some(persisted)) => {
                if persisted.record.tenant != tenant {
                    Err(GetRunError::TenantMismatch { expected: tenant })
                } else {
                    Ok(persisted.record)
                }
            }
            Ok(None) => Err(GetRunError::RunNotFound),
            Err(err) => Err(GetRunError::BackendError {
                message: format!("get_run.load: {err}"),
            }),
        }
    }

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards =
            self.scan_run_shards(tenant, run)
                .map_err(|err| GetRunError::BackendError {
                    message: format!("get_run_progress.scan: {err}"),
                })?;

        let mut progress = RunProgress::default();
        for persisted in &shards {
            progress.observe_shard(
                persisted.record.status,
                persisted.owner_is_live_at(now),
                persisted.record.cursor.last_key(&persisted.slab),
            );
        }
        Ok(progress)
    }

    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards =
            self.scan_run_shards(tenant, run)
                .map_err(|err| GetRunError::BackendError {
                    message: format!("list_shards_into.scan: {err}"),
                })?;

        out.clear();
        for persisted in &shards {
            let visible_now = Self::visible_now(persisted, now);
            if !filter.matches_record(&persisted.record, visible_now) {
                continue;
            }
            out.push(ShardSummary::from_record(
                &persisted.record,
                visible_now,
                &persisted.slab,
            ));
        }

        out.sort_by(|a, b| {
            a.key_range_start()
                .cmp(b.key_range_start())
                .then_with(|| a.shard().cmp(&b.shard()))
        });
        Ok(())
    }

    fn collect_claim_candidates_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards =
            self.scan_run_shards(tenant, run)
                .map_err(|err| GetRunError::BackendError {
                    message: format!("collect_claim_candidates.scan: {err}"),
                })?;

        candidates.clear();
        let mut earliest_deadline: Option<LogicalTime> = None;
        for persisted in &shards {
            if persisted.record.status != ShardStatus::Active {
                continue;
            }
            if persisted.owner_is_live_at(now) {
                if let Some(deadline) = persisted.record.lease_deadline() {
                    earliest_deadline = Some(match earliest_deadline {
                        Some(prev) => core::cmp::min(prev, deadline),
                        None => deadline,
                    });
                }
                continue;
            }
            candidates.push(persisted.record.shard);
        }

        candidates.sort_unstable();
        Ok(earliest_deadline)
    }

    fn complete_run(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _run: RunId,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.fail_unimplemented("complete_run")
    }

    fn fail_run(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _run: RunId,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.fail_unimplemented("fail_run")
    }

    fn cancel_run(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _run: RunId,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.fail_unimplemented("cancel_run")
    }

    fn unpark_shard(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _key: ShardKey,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        self.fail_unimplemented("unpark_shard")
    }
}

impl ShardClaiming for EtcdCoordinator {
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, ClaimError> {
        let mut candidates = std::mem::take(&mut self.claim_candidates_scratch);
        let result =
            default_claim_next_available(self, now, tenant, run, worker, out, &mut candidates);
        self.claim_candidates_scratch = candidates;
        result
    }
}
