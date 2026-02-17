//! In-memory reference implementation of the [`CoordinationBackend`] trait.
//!
//! # Purpose
//!
//! This backend is the **executable specification** for the shard coordination
//! protocol. Every protocol rule (fencing, leases, idempotency, cursor
//! monotonicity, split coverage) is enforced here first; production backends
//! (Postgres, DynamoDB, etc.) must produce identical observable behavior.
//!
//! # Design choices
//!
//! - **Single-threaded** — `&mut self` serializes all operations, eliminating
//!   concurrency concerns so invariants can be verified in-line.
//! - **Purely in-memory** — `HashMap<(TenantId, ShardKey), ShardRecord>`.
//!   No I/O, no transactions, no retries.
//! - **Tiger-style invariant enforcement** — every mutation path calls
//!   [`ShardRecord::assert_invariants()`] before returning. A violated
//!   invariant panics immediately (crash-to-prevent-corruption).
//!
//! # Protocol foundations
//!
//! - **Fencing tokens** (Kleppmann 2016): each `acquire_and_restore` bumps a
//!   monotonic `fence_epoch`. Stale workers are rejected by epoch comparison.
//! - **Leases** (Gray & Cheriton 1989): time-bounded ownership via
//!   `LeaseHolder(worker, deadline)`. Expiry makes shards re-acquirable.
//! - **Bounded idempotency** (Stripe pattern): a 16-entry FIFO op-log caches
//!   operation fingerprints including `(OpId, payload_hash)` for replay
//!   detection. Replays return cached results; hash mismatches yield
//!   `OpIdConflict`.
//!
//! # Shard state machine
//!
//! ```text
//!        ┌──────────────┐
//!        │    Active     │
//!        └──┬───┬────┬──┘
//!           │   │    │
//!  complete │   │    │ park_shard
//!    ┌──────┘   │    └───────┐
//!    ▼    split_replace      ▼
//! ┌──────┐      │       ┌────────┐
//! │ Done │      ▼       │ Parked │
//! └──────┘  ┌───────┐   └────────┘
//!           │ Split  │
//!           └───────┘
//! ```
//!
//! All transitions originate from `Active`. Terminal states (`Done`, `Split`,
//! `Parked`) reject further mutations. `split_residual` is special: it shrinks
//! the parent's range and spawns a residual child, but the parent stays
//! `Active`.
//!
//! # Split operation memory-safety pattern
//!
//! Both split operations temporarily **remove** the parent record from the map,
//! mutate it inside a closure, then **restore** it unconditionally. This avoids
//! holding a `&mut ShardRecord` (from `get_mut`) while also inserting new child
//! entries into the same `HashMap`. If the closure panics (invariant violation),
//! the parent is intentionally *not* restored — an invariant panic indicates
//! irrecoverable corruption.
//!
//! # Performance note
//!
//! A future `claim_next_available` would scan all shards — O(S) for a linear
//! pass, or O(S log S) if sorted by priority. Acceptable here; production
//! backends need a secondary available-shards index.

use std::collections::HashMap;

use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, AcquireResult, CheckpointError, CompleteError, IdempotentOutcome, ParkError,
    RenewError, RenewResult, SplitReplaceError, SplitResidualError,
};
use crate::coordination::lease::{Lease, LeaseHolder, OpKind, OpLogEntry, OpResult};
use crate::coordination::record::{ParkReason, ShardRecord, ShardStatus};
use crate::coordination::shard_spec::{validate_residual_split, validate_split_coverage};
use crate::coordination::split::{
    DerivedShardKind, SplitReplaceChild, SplitReplacePlan, SplitReplaceResult, SplitResidualPlan,
    SplitResidualResult, derive_split_shard_id, hash_checkpoint_payload, hash_complete_payload,
    hash_park_payload, hash_split_replace_payload, hash_split_residual_payload,
};
use crate::coordination::traits::CoordinationBackend;
use crate::coordination::validation::{
    check_op_idempotency, validate_cursor_update, validate_lease,
};
use crate::identity::{LogicalTime, OpId, ShardId, ShardKey, TenantId, WorkerId};

/// In-memory coordinator for shard-level operations.
///
/// # Keying strategy
///
/// Records are stored in a `HashMap<(TenantId, ShardKey), ShardRecord>`.
/// The composite key `(TenantId, ShardKey)` enforces tenant isolation at
/// the data-structure level: a lookup with the wrong tenant simply misses,
/// preventing cross-tenant data leakage even if higher-level checks have bugs.
///
/// # Lease duration
///
/// `default_lease_duration` is stored on the coordinator (not per-record)
/// because lease length is an operational parameter of the deployment, not
/// an intrinsic property of a shard. All shards served by this coordinator
/// share the same duration.
///
/// # Scope
///
/// Currently covers shard-level operations only. Run-level operations
/// (create, register, complete runs) will be added in a future task.
#[derive(Debug)]
pub struct InMemoryCoordinator {
    shards: HashMap<(TenantId, ShardKey), ShardRecord>,
    default_lease_duration: u64,
}

impl InMemoryCoordinator {
    /// Create a new coordinator with the given default lease duration.
    ///
    /// # Panics
    ///
    /// Panics if `default_lease_duration` is 0.
    pub fn new(default_lease_duration: u64) -> Self {
        assert!(default_lease_duration > 0, "lease duration must be > 0");
        Self {
            shards: HashMap::new(),
            default_lease_duration,
        }
    }

    /// Seed a shard record directly (test/fixture helper).
    ///
    /// # Panics
    ///
    /// Panics if `record` violates any of the 10 `ShardRecord` invariants.
    /// This catches malformed test fixtures early rather than letting them
    /// propagate to confusing failures later.
    ///
    /// In production paths, shards are created through split operations
    /// which derive records with correct invariants by construction.
    pub fn seed_shard(&mut self, record: ShardRecord) {
        record.assert_invariants();
        let key = ShardKey::new(record.run, record.shard);
        self.shards.insert((record.tenant, key), record);
    }
}

// ============================================================================
// Shard-level protocol (CoordinationBackend)
// ============================================================================

impl CoordinationBackend for InMemoryCoordinator {
    fn acquire_and_restore(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
    ) -> Result<AcquireResult, AcquireError> {
        let lease_duration = self.default_lease_duration;
        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(AcquireError::ShardNotFound { shard: key })?;

        // 1) Tenant isolation (SEC-1): checked first so that a wrong-tenant
        //    request never leaks status, lease, or fence information.
        if record.tenant != tenant {
            return Err(AcquireError::TenantMismatch { expected: tenant });
        }

        // 2) Terminal shards are permanently done — no new work can be assigned.
        if record.status != ShardStatus::Active {
            return Err(AcquireError::ShardTerminal {
                shard: key,
                status: record.status,
            });
        }

        // 3) Active lease means another worker holds the shard. We must wait
        //    for expiry rather than preempt — preemption would violate the
        //    at-most-once processing guarantee within a lease window.
        if record.is_leased_at(now) {
            let (owner, deadline) = record
                .lease
                .as_ref()
                .map(|h| (h.owner(), h.deadline()))
                .unwrap_or((worker, LogicalTime::ZERO));
            return Err(AcquireError::AlreadyLeased {
                current_owner: owner,
                lease_deadline: deadline,
            });
        }

        // 4) Bump fence epoch — this is the Kleppmann fencing token. Any
        //    worker still holding a lease from a previous epoch will be
        //    rejected on its next mutation attempt (stale fence check).
        let new_fence = record.advance_fence();

        // 5) Grant a new lease with a fresh deadline.
        let deadline = now
            .checked_add(lease_duration)
            .expect("lease deadline overflow — LogicalTime near max");
        record.lease = Some(LeaseHolder::new(worker, deadline));

        // 6) Return the fencing lease + a read-only snapshot of shard state
        //    so the worker can resume from the last checkpointed cursor.
        let lease = Lease::new(tenant, key.run(), key.shard(), worker, new_fence, deadline);
        let snapshot = record.snapshot();

        // TODO(events): emit ShardAcquired
        record.assert_invariants();
        Ok(AcquireResult { lease, snapshot })
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = lease.shard_key();
        let lease_duration = self.default_lease_duration;
        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(RenewError::ShardNotFound { shard: key })?;

        validate_lease(now, tenant, lease, record)?;

        let deadline = now
            .checked_add(lease_duration)
            .expect("lease deadline overflow — LogicalTime near max");
        record.lease = Some(LeaseHolder::new(lease.owner(), deadline));

        record.assert_invariants();
        Ok(RenewResult {
            new_deadline: deadline,
        })
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let key = lease.shard_key();
        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(CheckpointError::ShardNotFound { shard: key })?;

        // Idempotency checked before lease so replays succeed even after
        // the shard becomes terminal or the lease is released.
        let payload_hash = hash_checkpoint_payload(&new_cursor);
        if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        validate_lease(now, tenant, lease, record)?;
        validate_cursor_update(&new_cursor, record)?;

        record.cursor = new_cursor;
        record.op_log_push(OpLogEntry::new(
            op_id,
            OpKind::Checkpoint,
            OpResult::Completed,
            payload_hash,
            now,
        ));

        // TODO(events): emit ShardCheckpointed
        record.assert_invariants();
        Ok(IdempotentOutcome::Executed(()))
    }

    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        let key = lease.shard_key();
        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(CompleteError::ShardNotFound { shard: key })?;

        let payload_hash = hash_complete_payload(&final_cursor);
        if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        validate_lease(now, tenant, lease, record)?;
        validate_cursor_update(&final_cursor, record)?;

        record.cursor = final_cursor;
        record.status = ShardStatus::Done;
        record.lease = None;
        record.op_log_push(OpLogEntry::new(
            op_id,
            OpKind::Complete,
            OpResult::Completed,
            payload_hash,
            now,
        ));

        // TODO(events): emit ShardCompleted
        record.assert_invariants();
        Ok(IdempotentOutcome::Executed(()))
    }

    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        let key = lease.shard_key();
        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(ParkError::ShardNotFound { shard: key })?;

        let payload_hash = hash_park_payload(reason);
        if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        validate_lease(now, tenant, lease, record)?;

        record.status = ShardStatus::Parked;
        record.park_reason = Some(reason);
        record.lease = None;
        record.op_log_push(OpLogEntry::new(
            op_id,
            OpKind::Park,
            OpResult::Completed,
            payload_hash,
            now,
        ));

        // TODO(events): emit ShardParked
        record.assert_invariants();
        Ok(IdempotentOutcome::Executed(()))
    }

    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        let key = lease.shard_key();
        let map_key = (tenant, key);

        // Remove-mutate-restore pattern: we need `&mut parent` for mutation
        // AND `&mut self.shards` for child insertion, which Rust's borrow
        // checker forbids simultaneously via `get_mut`. Removing the parent
        // resolves this. See module-level docs for the panic-safety rationale.
        let mut parent = self
            .shards
            .remove(&map_key)
            .ok_or(SplitReplaceError::ShardNotFound { shard: key })?;

        let result = (|| {
            // Phase 1: Validate preconditions (idempotency, lease, coverage).
            let payload_hash = hash_split_replace_payload(&plan);
            if check_op_idempotency(&parent, op_id, payload_hash)?.is_some() {
                // NOTE(safety): Op-log eviction cannot affect split_replace replays.
                // After split_replace, parent status becomes Split (terminal). No further
                // ops can push entries, so the split_replace op_log entry is never evicted.
                // check_op_idempotency() will always detect the replay.
                let children = split_replace_replay_child_ids(&parent, &plan, op_id);
                return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
            }

            validate_lease(now, tenant, lease, &parent)?;

            let sorted = split_replace_sort_children(&plan);
            let child_specs: Vec<&_> = sorted.iter().map(|c| c.spec()).collect();
            validate_split_coverage(&parent.spec, &child_specs)
                .map_err(|e| SplitReplaceError::SplitInvalid(Box::new(e)))?;

            // Phase 2: Compute new state (pure — no side effects).
            let (child_ids, children_to_insert) =
                split_replace_build_children(&parent, &sorted, tenant, op_id);

            // Phase 3: Apply mutations. Collision check is defense-in-depth:
            // derive_split_shard_id uses BLAKE3 with domain separation, so
            // collisions indicate a logic bug, not a hash weakness.
            for (k, _) in &children_to_insert {
                assert!(
                    !self.shards.contains_key(k),
                    "derived child shard id collision: {k:?}",
                );
            }

            split_replace_apply_parent(&mut parent, &child_ids, op_id, payload_hash, now);

            for (k, v) in children_to_insert {
                self.shards.insert(k, v);
            }

            // TODO(events): emit ShardSplit
            Ok(IdempotentOutcome::Executed(SplitReplaceResult {
                children: child_ids,
            }))
        })();

        // Always restore the parent record (mutated or not).
        self.shards.insert(map_key, parent);
        result
    }

    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        let key = lease.shard_key();
        let map_key = (tenant, key);

        let mut parent = self
            .shards
            .remove(&map_key)
            .ok_or(SplitResidualError::ShardNotFound { shard: key })?;

        let result = (|| {
            // Phase 1: Validate preconditions.
            let payload_hash = hash_split_residual_payload(&plan);

            // Derive the residual ID for a fresh execution (index = current
            // spawned.len(), before any push).
            let residual_id = derive_split_shard_id(
                parent.run,
                parent.shard,
                op_id,
                DerivedShardKind::Residual,
                parent.spawned.len() as u32,
            );

            if let Some(replay) =
                split_residual_check_replay(&parent, op_id, payload_hash, residual_id)?
            {
                return Ok(replay);
            }
            split_residual_validate_preconditions(now, tenant, lease, &parent, &plan)?;

            // Phase 2: Build residual record (pure).
            let residual_record = split_residual_build_record(&parent, &plan, tenant, residual_id);

            // Phase 3: Apply mutations.
            let residual_key = ShardKey::new(parent.run, residual_id);
            assert!(
                !self.shards.contains_key(&(tenant, residual_key)),
                "derived residual shard id collision: {residual_key:?}",
            );

            split_residual_apply_parent(
                &mut parent,
                plan.parent_new_spec().clone(),
                residual_id,
                op_id,
                payload_hash,
                now,
            );

            self.shards.insert((tenant, residual_key), residual_record);

            // TODO(events): emit ShardResidualCreated
            Ok(IdempotentOutcome::Executed(SplitResidualResult {
                residual: residual_id,
            }))
        })();

        self.shards.insert(map_key, parent);
        result
    }
}

// ============================================================================
// split_replace helpers (free functions — Tiger Style decomposition)
// ============================================================================

/// Sort plan children by `key_range_start` for deterministic ordering.
///
/// Callers may submit children in any order. Sorting ensures that the
/// derived child IDs (which depend on index) are stable regardless of
/// submission order, and that `validate_split_coverage` sees children in
/// the contiguous sequence it expects.
fn split_replace_sort_children(plan: &SplitReplacePlan) -> Vec<&SplitReplaceChild> {
    let mut sorted: Vec<&SplitReplaceChild> = plan.children().iter().collect();
    sorted.sort_by(|a, b| a.spec().key_range_start().cmp(b.spec().key_range_start()));
    debug_assert!(sorted.len() >= 2, "split_replace requires >= 2 children");
    sorted
}

/// Recompute child IDs for an idempotent replay.
///
/// On replay, the op_log entry exists but the children are already in
/// `parent.spawned`. Since `split_replace` transitions the parent to
/// terminal `Split` status, no further operations can modify `spawned`.
/// The original base index was `spawned.len() - children_count`.
fn split_replace_replay_child_ids(
    parent: &ShardRecord,
    plan: &SplitReplacePlan,
    op_id: OpId,
) -> Vec<ShardId> {
    let sorted = split_replace_sort_children(plan);
    let n = sorted.len();
    // Parent is terminal (Split) after first execution, so spawned is
    // frozen. The children were the last N entries appended.
    let base_index = parent.spawned.len() - n;
    sorted
        .iter()
        .enumerate()
        .map(|(i, _)| {
            derive_split_shard_id(
                parent.run,
                parent.shard,
                op_id,
                DerivedShardKind::Child,
                (base_index + i) as u32,
            )
        })
        .collect()
}

/// A shard map entry: the HashMap key and the record to insert.
type ShardMapEntry = ((TenantId, ShardKey), ShardRecord);

/// Derive child IDs and build child `ShardRecord`s (pure — no map mutation).
///
/// Each child ID is derived via BLAKE3 from `(run, parent_shard, op_id,
/// kind=Child, index)`. The index starts at `parent.spawned.len()` so IDs
/// are unique across successive splits of the same parent.
///
/// Returns `(child_ids, entries)` where `entries` are ready for insertion
/// into the shard map.
fn split_replace_build_children(
    parent: &ShardRecord,
    sorted: &[&SplitReplaceChild],
    tenant: TenantId,
    op_id: OpId,
) -> (Vec<ShardId>, Vec<ShardMapEntry>) {
    let mut child_ids = Vec::with_capacity(sorted.len());
    let mut to_insert = Vec::with_capacity(sorted.len());

    for (i, child) in sorted.iter().enumerate() {
        let idx = (parent.spawned.len() + i) as u32;
        let child_id = derive_split_shard_id(
            parent.run,
            parent.shard,
            op_id,
            DerivedShardKind::Child,
            idx,
        );
        debug_assert!(child_id.is_derived(), "derived child must have bit 63 set");

        let child_key = ShardKey::new(parent.run, child_id);
        let record = ShardRecord::new_split_child(
            tenant,
            parent.run,
            child_id,
            child.spec().clone(),
            child.cursor().clone(),
            parent.cursor_semantics,
            parent.shard,
        );

        child_ids.push(child_id);
        to_insert.push(((tenant, child_key), record));
    }

    debug_assert_eq!(
        child_ids.len(),
        sorted.len(),
        "child count mismatch after build",
    );
    (child_ids, to_insert)
}

/// Transition parent to terminal `Split` status.
///
/// The parent's lease is released (no worker owns a terminal shard) and
/// child IDs are recorded in `spawned` for lineage tracking. Once in
/// `Split` status, no further operations can push op-log entries, so the
/// split_replace entry is **never evicted** — guaranteeing idempotent
/// replay detection.
fn split_replace_apply_parent(
    parent: &mut ShardRecord,
    child_ids: &[ShardId],
    op_id: OpId,
    payload_hash: u64,
    now: LogicalTime,
) {
    debug_assert!(!child_ids.is_empty(), "split_replace requires children");

    parent.status = ShardStatus::Split;
    parent.spawned.extend_from_slice(child_ids);
    parent.lease = None;
    parent.op_log_push(OpLogEntry::new(
        op_id,
        OpKind::SplitReplace,
        OpResult::Completed,
        payload_hash,
        now,
    ));
    parent.assert_invariants();
}

// ============================================================================
// split_residual helpers (free functions — Tiger Style decomposition)
// ============================================================================

/// Search `parent.spawned` for a residual derived from the given `op_id`.
///
/// On replay, the residual's original creation index is unknown because
/// `spawned` may have grown since the first execution. We brute-force all
/// possible indices `0..spawned.len()`, re-deriving the BLAKE3-based ID
/// for each and checking membership.
///
/// Complexity: O(S² + S·D) where S = `spawned.len()` and D = BLAKE3 hash
/// cost (constant). The `contains()` call performs a linear scan of
/// `spawned` for each candidate. At the bound of `MAX_SPAWNED_PER_SHARD`
/// (1024), worst case is ~1024 hashes + ~1M `ShardId` comparisons — still
/// acceptable for correctness-critical replay detection.
///
/// Returns `None` if no match, meaning this is genuinely a new operation.
fn find_replayed_residual(parent: &ShardRecord, op_id: OpId) -> Option<ShardId> {
    for idx in 0..parent.spawned.len() as u32 {
        let candidate = derive_split_shard_id(
            parent.run,
            parent.shard,
            op_id,
            DerivedShardKind::Residual,
            idx,
        );
        if parent.spawned.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Two-tier replay detection for `split_residual`.
///
/// Unlike `split_replace` (which makes the parent terminal, freezing its
/// op-log), `split_residual` keeps the parent `Active`. Subsequent
/// checkpoints can evict the split_residual op-log entry. To handle this:
///
/// 1. **Op-log check** (primary): if the entry is still present and the
///    payload hash matches, return `Replayed`. If the hash differs, return
///    `OpIdConflict`.
/// 2. **Spawned probe** (defense-in-depth): if the op-log entry was evicted,
///    scan `parent.spawned` for a residual derived from this `op_id`. The
///    `spawned` vec is permanent (never evicted, bounded by
///    `MAX_SPAWNED_PER_SHARD`).
///
/// The spawned check comes *after* the op-log check so that `OpIdConflict`
/// (same op_id, different payload) is not masked.
///
/// Returns `Some(Replayed(..))` if replay detected, `None` to proceed.
fn split_residual_check_replay(
    parent: &ShardRecord,
    op_id: OpId,
    payload_hash: u64,
    fresh_residual_id: ShardId,
) -> Result<Option<IdempotentOutcome<SplitResidualResult>>, SplitResidualError> {
    if check_op_idempotency(parent, op_id, payload_hash)?.is_some() {
        // Op-log hit. The residual is already in spawned; find it.
        let replayed = find_replayed_residual(parent, op_id).unwrap_or(fresh_residual_id);
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual: replayed,
        })));
    }

    // Defense-in-depth: if op_log entry was evicted but residual was
    // already created, detect via parent.spawned (permanent, never
    // evicted). This check comes AFTER op-log miss to avoid masking
    // OpIdConflict. MAX_SPAWNED_PER_SHARD bounds the search.
    if let Some(existing) = find_replayed_residual(parent, op_id) {
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual: existing,
        })));
    }

    Ok(None)
}

/// Validate all preconditions for a fresh `split_residual` execution.
///
/// Checks, in order: lease validity (tenant, fence, expiry), split
/// coverage (new parent + residual must partition old parent's range),
/// and cursor bounds (parent's cursor must remain within the shrunk range).
fn split_residual_validate_preconditions(
    now: LogicalTime,
    tenant: TenantId,
    lease: &Lease,
    parent: &ShardRecord,
    plan: &SplitResidualPlan,
) -> Result<(), SplitResidualError> {
    validate_lease(now, tenant, lease, parent)?;
    validate_residual_split(&parent.spec, plan.parent_new_spec(), plan.residual_spec())
        .map_err(|e| SplitResidualError::SplitInvalid(Box::new(e)))?;
    // Safety: shrinking the parent must not strand its existing cursor.
    split_residual_validate_cursor_bounds(parent, plan)
}

/// Verify the parent's cursor remains within the shrunk key range.
///
/// After a residual split, the parent keeps the lower portion of the
/// keyspace. If the cursor's `last_key` falls outside the new range,
/// the parent would violate cursor-bounds invariants (INV: `last_key ∈
/// [spec.start, spec.end)`). This would strand progress — the worker
/// could never advance past a key that's no longer in its range.
fn split_residual_validate_cursor_bounds(
    parent: &ShardRecord,
    plan: &SplitResidualPlan,
) -> Result<(), SplitResidualError> {
    if let Some(k) = parent.cursor.last_key()
        && !plan.parent_new_spec().contains_key(k)
    {
        return Err(SplitResidualError::SplitInvalid(Box::new(
            crate::coordination::shard_spec::SplitValidationError::ParentCursorOutOfBounds {
                cursor: k.to_vec().into_boxed_slice(),
                new_parent_start: plan.parent_new_spec().key_range_start().to_vec(),
                new_parent_end: plan.parent_new_spec().key_range_end().to_vec(),
            },
        )));
    }
    Ok(())
}

/// Build the residual shard record (pure — no map mutation).
///
/// The residual starts with `Cursor::initial()` because no work has been
/// done in the residual's key range yet. It inherits `cursor_semantics`
/// from the parent (run-level property) and records `parent.shard` as its
/// lineage parent.
fn split_residual_build_record(
    parent: &ShardRecord,
    plan: &SplitResidualPlan,
    tenant: TenantId,
    residual_id: ShardId,
) -> ShardRecord {
    debug_assert!(residual_id.is_derived(), "residual must be derived");
    ShardRecord::new_split_child(
        tenant,
        parent.run,
        residual_id,
        plan.residual_spec().clone(),
        Cursor::initial(),
        parent.cursor_semantics,
        parent.shard,
    )
}

/// Shrink parent's key range and record the residual in `spawned`.
///
/// Unlike `split_replace_apply_parent`, the parent **keeps its lease** —
/// the worker continues processing the (now smaller) parent shard. The
/// parent stays `Active`, which means subsequent ops can evict this
/// op-log entry. That's acceptable because `find_replayed_residual`
/// provides a secondary replay detection path via `spawned`.
fn split_residual_apply_parent(
    parent: &mut ShardRecord,
    new_spec: crate::coordination::shard_spec::ShardSpec,
    residual_id: ShardId,
    op_id: OpId,
    payload_hash: u64,
    now: LogicalTime,
) {
    debug_assert!(residual_id.is_derived(), "residual must be derived");

    parent.spec = new_spec;
    parent.spawned.push(residual_id);
    parent.op_log_push(OpLogEntry::new(
        op_id,
        OpKind::SplitResidual,
        OpResult::Completed,
        payload_hash,
        now,
    ));
    parent.assert_invariants();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
    use crate::identity::{FenceEpoch, RunId};

    // -- Test fixtures ---------------------------------------------------

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_shard() -> ShardId {
        ShardId::from_raw(10)
    }

    fn test_spec() -> ShardSpec {
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())
    }

    fn test_worker(id: u64) -> WorkerId {
        WorkerId::from_raw(id)
    }

    fn now(t: u64) -> LogicalTime {
        LogicalTime::from_raw(t)
    }

    const LEASE_DURATION: u64 = 100;

    fn seeded_coordinator() -> InMemoryCoordinator {
        let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
        let record = ShardRecord::new_active(
            test_tenant(),
            test_run(),
            test_shard(),
            test_spec(),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record);
        coord
    }

    fn acquire_shard(coord: &mut InMemoryCoordinator, t: u64, worker_id: u64) -> Lease {
        let result = coord
            .acquire_and_restore(now(t), test_tenant(), test_key(), test_worker(worker_id))
            .expect("acquire should succeed");
        result.lease
    }

    fn test_key() -> ShardKey {
        ShardKey::new(test_run(), test_shard())
    }

    fn test_cursor(key: &[u8]) -> Cursor {
        Cursor::with_last_key(key.to_vec())
    }

    // -- acquire_and_restore tests ----------------------------------------

    #[test]
    fn acquire_basic() {
        let mut coord = seeded_coordinator();
        let result = coord
            .acquire_and_restore(now(1), test_tenant(), test_key(), test_worker(1))
            .unwrap();

        assert_eq!(result.lease.owner(), test_worker(1));
        assert_eq!(result.lease.fence(), FenceEpoch::INITIAL.increment());
        assert_eq!(
            result.lease.deadline(),
            now(1).checked_add(LEASE_DURATION).unwrap(),
        );
        assert_eq!(result.snapshot.status(), ShardStatus::Active);
    }

    #[test]
    fn acquire_not_found() {
        let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
        let err = coord
            .acquire_and_restore(now(1), test_tenant(), test_key(), test_worker(1))
            .unwrap_err();
        assert!(matches!(err, AcquireError::ShardNotFound { .. }));
    }

    #[test]
    fn acquire_already_leased() {
        let mut coord = seeded_coordinator();
        let _lease = acquire_shard(&mut coord, 1, 1);

        let err = coord
            .acquire_and_restore(now(2), test_tenant(), test_key(), test_worker(2))
            .unwrap_err();
        assert!(matches!(err, AcquireError::AlreadyLeased { .. }));
    }

    #[test]
    fn acquire_after_lease_expiry() {
        let mut coord = seeded_coordinator();
        let _lease = acquire_shard(&mut coord, 1, 1);

        // Advance past lease deadline.
        let result = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 2),
                test_tenant(),
                test_key(),
                test_worker(2),
            )
            .unwrap();
        assert_eq!(result.lease.owner(), test_worker(2));
    }

    #[test]
    fn acquire_terminal_rejected() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        // Complete the shard (terminal).
        let cursor = test_cursor(b"m");
        let _ = coord
            .complete(now(2), test_tenant(), &lease, cursor, OpId::from_raw(1))
            .unwrap();

        let err = coord
            .acquire_and_restore(now(3), test_tenant(), test_key(), test_worker(2))
            .unwrap_err();
        assert!(matches!(err, AcquireError::ShardTerminal { .. }));
    }

    // -- renew tests -------------------------------------------------------

    #[test]
    fn renew_basic() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let result = coord.renew(now(50), test_tenant(), &lease).unwrap();
        assert_eq!(
            result.new_deadline,
            now(50).checked_add(LEASE_DURATION).unwrap(),
        );
    }

    #[test]
    fn renew_stale_fence() {
        let mut coord = seeded_coordinator();
        let old_lease = acquire_shard(&mut coord, 1, 1);

        // Another worker acquires, bumping the fence.
        let _new_lease = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 2),
                test_tenant(),
                test_key(),
                test_worker(2),
            )
            .unwrap();

        let err = coord
            .renew(now(LEASE_DURATION + 3), test_tenant(), &old_lease)
            .unwrap_err();
        assert!(matches!(err, RenewError::StaleFence { .. }));
    }

    // -- checkpoint tests --------------------------------------------------

    #[test]
    fn checkpoint_basic() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let cursor = test_cursor(b"b");
        let result = coord
            .checkpoint(now(2), test_tenant(), &lease, cursor, OpId::from_raw(1))
            .unwrap();
        assert!(result.is_executed());
    }

    #[test]
    fn checkpoint_op_id_conflict() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let op = OpId::from_raw(1);
        let _ = coord
            .checkpoint(now(2), test_tenant(), &lease, test_cursor(b"b"), op)
            .unwrap();

        // Same op_id, different payload -> OpIdConflict.
        let err = coord
            .checkpoint(now(3), test_tenant(), &lease, test_cursor(b"c"), op)
            .unwrap_err();
        assert!(matches!(err, CheckpointError::OpIdConflict { .. }));
    }

    // -- complete tests ----------------------------------------------------

    #[test]
    fn complete_basic() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let cursor = test_cursor(b"m");
        let result = coord
            .complete(now(2), test_tenant(), &lease, cursor, OpId::from_raw(1))
            .unwrap();
        assert!(result.is_executed());

        // Shard is now terminal.
        let err = coord
            .acquire_and_restore(now(3), test_tenant(), test_key(), test_worker(2))
            .unwrap_err();
        assert!(matches!(err, AcquireError::ShardTerminal { .. }));
    }

    // -- park tests --------------------------------------------------------

    #[test]
    fn park_basic() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let result = coord
            .park_shard(
                now(2),
                test_tenant(),
                &lease,
                ParkReason::TooManyErrors,
                OpId::from_raw(1),
            )
            .unwrap();
        assert!(result.is_executed());
    }

    // -- split_replace tests -----------------------------------------------

    #[test]
    fn split_replace_basic() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let child_a_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let child_b_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());

        let plan = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(child_a_spec, Cursor::initial()),
            SplitReplaceChild::new(child_b_spec, Cursor::initial()),
        ])
        .unwrap();

        let result = coord
            .split_replace(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap();
        assert!(result.is_executed());
        assert_eq!(result.as_ref().children.len(), 2);

        // All children should be derived (bit 63 set).
        for id in &result.as_ref().children {
            assert!(id.is_derived());
        }

        // Parent should be terminal.
        let err = coord
            .acquire_and_restore(now(3), test_tenant(), test_key(), test_worker(2))
            .unwrap_err();
        assert!(matches!(err, AcquireError::ShardTerminal { .. }));
    }

    #[test]
    fn split_replace_replay() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let child_a_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let child_b_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());

        let plan = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(child_a_spec.clone(), Cursor::initial()),
            SplitReplaceChild::new(child_b_spec.clone(), Cursor::initial()),
        ])
        .unwrap();

        let op = OpId::from_raw(1);
        let first = coord
            .split_replace(now(2), test_tenant(), &lease, plan.clone(), op)
            .unwrap();
        assert!(first.is_executed());

        // Replay with same OpId + payload.
        let second = coord
            .split_replace(now(3), test_tenant(), &lease, plan, op)
            .unwrap();
        assert!(second.is_replay());
        assert_eq!(first.as_ref().children, second.as_ref().children);
    }

    #[test]
    fn split_replace_child_id_determinism() {
        // Same inputs produce same child IDs.
        let mut coord1 = seeded_coordinator();
        let lease1 = acquire_shard(&mut coord1, 1, 1);

        let mut coord2 = seeded_coordinator();
        let lease2 = acquire_shard(&mut coord2, 1, 1);

        let make_plan = || {
            let a = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
            let b = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
            SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(a, Cursor::initial()),
                SplitReplaceChild::new(b, Cursor::initial()),
            ])
            .unwrap()
        };

        let op = OpId::from_raw(42);
        let r1 = coord1
            .split_replace(now(2), test_tenant(), &lease1, make_plan(), op)
            .unwrap();
        let r2 = coord2
            .split_replace(now(2), test_tenant(), &lease2, make_plan(), op)
            .unwrap();
        assert_eq!(r1.into_inner().children, r2.into_inner().children);
    }

    // -- split_residual tests ----------------------------------------------

    #[test]
    fn split_residual_basic() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        // Checkpoint to set a cursor within the new parent range.
        let _ = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease,
                test_cursor(b"f"),
                OpId::from_raw(10),
            )
            .unwrap();

        let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

        let result = coord
            .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap();
        assert!(result.is_executed());
        assert!(result.as_ref().residual.is_derived());

        // Parent should still be acquirable (not terminal).
        // But current lease is still active, so we must wait for expiry.
        let new_result = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 4),
                test_tenant(),
                test_key(),
                test_worker(2),
            )
            .unwrap();
        assert_eq!(new_result.snapshot.status(), ShardStatus::Active);
    }

    #[test]
    fn split_residual_cursor_out_of_bounds() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        // Checkpoint to "r" — outside the new parent range [a, m).
        let _ = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease,
                test_cursor(b"r"),
                OpId::from_raw(10),
            )
            .unwrap();

        let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

        let err = coord
            .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap_err();
        assert!(matches!(err, SplitResidualError::SplitInvalid(_)));
    }

    // -- Op-log eviction edge case ----------------------------------------

    #[test]
    fn op_log_eviction_treats_old_op_as_new() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        // Push 17 ops (cap is 16) to evict the first one.
        let mut cursor_key = b"b".to_vec();
        for i in 1..=17u64 {
            let cursor = Cursor::with_last_key(cursor_key.clone());
            let _ = coord
                .checkpoint(now(i + 1), test_tenant(), &lease, cursor, OpId::from_raw(i))
                .unwrap();
            cursor_key[0] = b'b' + (i as u8).min(23); // advance within range
        }

        // Retry the first op — it was evicted, so it's treated as a new op
        // rather than a replay. It will fail because its cursor (b"b") would
        // regress from the current position.
        let old_cursor = Cursor::with_last_key(b"b".to_vec());
        let err = coord
            .checkpoint(
                now(20),
                test_tenant(),
                &lease,
                old_cursor,
                OpId::from_raw(1),
            )
            .unwrap_err();
        // After eviction, it's treated as new — cursor regression check fails.
        assert!(matches!(err, CheckpointError::CursorRegression { .. }));
    }

    // -- Fencing mutual exclusion -----------------------------------------

    #[test]
    fn only_latest_fence_holder_can_mutate() {
        let mut coord = seeded_coordinator();
        let old_lease = acquire_shard(&mut coord, 1, 1);

        // New worker acquires.
        let new_lease = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 2),
                test_tenant(),
                test_key(),
                test_worker(2),
            )
            .unwrap()
            .lease;

        // Old lease: all mutations rejected.
        assert!(
            coord
                .checkpoint(
                    now(LEASE_DURATION + 3),
                    test_tenant(),
                    &old_lease,
                    test_cursor(b"b"),
                    OpId::from_raw(1),
                )
                .is_err()
        );
        assert!(
            coord
                .complete(
                    now(LEASE_DURATION + 3),
                    test_tenant(),
                    &old_lease,
                    test_cursor(b"b"),
                    OpId::from_raw(2),
                )
                .is_err()
        );
        assert!(
            coord
                .park_shard(
                    now(LEASE_DURATION + 3),
                    test_tenant(),
                    &old_lease,
                    ParkReason::TooManyErrors,
                    OpId::from_raw(3),
                )
                .is_err()
        );

        // New lease: mutation succeeds.
        let result = coord
            .checkpoint(
                now(LEASE_DURATION + 3),
                test_tenant(),
                &new_lease,
                test_cursor(b"b"),
                OpId::from_raw(4),
            )
            .unwrap();
        assert!(result.is_executed());
    }

    // -- split_residual replay via spawned.contains() ---------------------

    #[test]
    fn split_residual_replay_via_spawned_after_eviction() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        // Checkpoint to set cursor within new parent range.
        let _ = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease,
                test_cursor(b"d"),
                OpId::from_raw(100),
            )
            .unwrap();

        // Split residual.
        let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();
        let split_op = OpId::from_raw(200);

        let first = coord
            .split_residual(now(3), test_tenant(), &lease, plan.clone(), split_op)
            .unwrap();
        assert!(first.is_executed());

        // Push 16+ checkpoint ops to evict the split_residual op_log entry.
        let mut key_byte = b'e';
        for i in 1..=17u64 {
            let cursor = Cursor::with_last_key(vec![key_byte]);
            let _ = coord
                .checkpoint(
                    now(10 + i),
                    test_tenant(),
                    &lease,
                    cursor,
                    OpId::from_raw(300 + i),
                )
                .unwrap();
            if key_byte < b'l' {
                key_byte += 1;
            }
        }

        // Retry split_residual — op_log entry is evicted, but spawned.contains()
        // detects the replay.
        let second = coord
            .split_residual(now(30), test_tenant(), &lease, plan, split_op)
            .unwrap();
        assert!(second.is_replay());
        assert_eq!(first.as_ref().residual, second.as_ref().residual);
    }
}

// ============================================================================
// Property tests
// ============================================================================

#[cfg(test)]
mod prop_tests {
    use super::*;
    use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
    use crate::identity::{FenceEpoch, RunId};
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_shard() -> ShardId {
        ShardId::from_raw(10)
    }

    fn test_key() -> ShardKey {
        ShardKey::new(test_run(), test_shard())
    }

    const LEASE_DURATION: u64 = 100;

    fn seeded_coordinator() -> InMemoryCoordinator {
        let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
        let spec = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let record = ShardRecord::new_active(
            test_tenant(),
            test_run(),
            test_shard(),
            spec,
            CursorSemantics::Completed,
        );
        coord.seed_shard(record);
        coord
    }

    /// Operations that can be applied to the coordinator.
    #[derive(Debug, Clone)]
    enum Op {
        Acquire { worker: u8 },
        Checkpoint { cursor_key: u8 },
        Complete { cursor_key: u8 },
        Park,
        Renew,
        TimeAdvance { ticks: u64 },
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..4).prop_map(|w| Op::Acquire { worker: w }),
            (b'a'..b'y').prop_map(|k| Op::Checkpoint { cursor_key: k }),
            (b'a'..b'y').prop_map(|k| Op::Complete { cursor_key: k }),
            Just(Op::Park),
            Just(Op::Renew),
            (1u64..200).prop_map(|t| Op::TimeAdvance { ticks: t }),
        ]
    }

    /// Apply a single `Op` to the coordinator, returning `(time, op_counter)`.
    fn apply_op(
        coord: &mut InMemoryCoordinator,
        op: &Op,
        time: u64,
        oc: u64,
        last_lease: &mut Option<Lease>,
    ) -> (u64, u64) {
        let now = LogicalTime::from_raw(time);
        let ten = test_tenant();
        match op {
            Op::Acquire { worker } => {
                if let Ok(r) = coord.acquire_and_restore(
                    now,
                    ten,
                    test_key(),
                    WorkerId::from_raw(*worker as u64),
                ) {
                    *last_lease = Some(r.lease);
                }
                (time, oc)
            }
            Op::Checkpoint { cursor_key } => {
                if let Some(lease) = last_lease.as_ref()
                    && let Ok(c) = Cursor::try_with_last_key(vec![*cursor_key])
                {
                    let _ = coord.checkpoint(now, ten, lease, c, OpId::from_raw(oc));
                    return (time, oc + 1);
                }
                (time, oc)
            }
            Op::Complete { cursor_key } => {
                if let Some(lease) = last_lease.as_ref()
                    && let Ok(c) = Cursor::try_with_last_key(vec![*cursor_key])
                {
                    let _ = coord.complete(now, ten, lease, c, OpId::from_raw(oc));
                    return (time, oc + 1);
                }
                (time, oc)
            }
            Op::Park => {
                if let Some(lease) = last_lease.as_ref() {
                    let _ = coord.park_shard(
                        now,
                        ten,
                        lease,
                        ParkReason::TooManyErrors,
                        OpId::from_raw(oc),
                    );
                    return (time, oc + 1);
                }
                (time, oc)
            }
            Op::Renew => {
                if let Some(lease) = last_lease.as_ref() {
                    let _ = coord.renew(now, ten, lease);
                }
                (time, oc)
            }
            Op::TimeAdvance { ticks } => (time.saturating_add(*ticks), oc),
        }
    }

    proptest! {
        #![proptest_config(miri_proptest_config())]

        /// Random operation sequences preserve all invariants.
        ///
        /// After every operation (success or failure), all shard records
        /// in the coordinator satisfy `assert_invariants()`.
        #[test]
        fn random_ops_preserve_invariants(ops in proptest::collection::vec(arb_op(), 1..100)) {
            let mut coord = seeded_coordinator();
            let mut time = 1u64;
            let mut op_counter = 1u64;
            let mut last_lease: Option<Lease> = None;

            for op in ops {
                (time, op_counter) = apply_op(&mut coord, &op, time, op_counter, &mut last_lease);

                // After every op, all records must satisfy invariants.
                for record in coord.shards.values() {
                    record.assert_invariants();
                }
            }
        }

        /// Fence epoch never decreases across acquisitions.
        #[test]
        fn fence_monotonicity_property(
            worker_ids in proptest::collection::vec(0u8..4, 2..20),
        ) {
            let mut coord = seeded_coordinator();
            let mut time = 1u64;
            let mut max_fence = FenceEpoch::INITIAL;

            for worker in worker_ids {
                time += LEASE_DURATION + 1; // ensure lease expired
                if let Ok(result) = coord.acquire_and_restore(
                    LogicalTime::from_raw(time),
                    test_tenant(),
                    test_key(),
                    WorkerId::from_raw(worker as u64),
                ) {
                    let fence = result.lease.fence();
                    prop_assert!(
                        fence > max_fence,
                        "fence must strictly increase: {fence:?} <= {max_fence:?}",
                    );
                    max_fence = fence;
                }
            }
        }

        /// Any idempotent operation (checkpoint, complete, park), when
        /// replayed with the same op_id and identical payload, returns
        /// `Replayed`.
        #[test]
        fn idempotent_replay_across_operations(
            cursor_key in b'b'..b'y',
            op_raw in 1u64..1000,
            op_kind in 0u8..3,
        ) {
            let mut coord = seeded_coordinator();
            let ten = test_tenant();
            let lease = coord
                .acquire_and_restore(
                    LogicalTime::from_raw(1),
                    ten,
                    test_key(),
                    WorkerId::from_raw(1),
                )
                .unwrap()
                .lease;
            let op = OpId::from_raw(op_raw);
            let cursor = Cursor::with_last_key(vec![cursor_key]);

            match op_kind {
                0 => {
                    let first = coord
                        .checkpoint(LogicalTime::from_raw(2), ten, &lease, cursor.clone(), op)
                        .unwrap();
                    prop_assert!(first.is_executed());
                    let second = coord
                        .checkpoint(LogicalTime::from_raw(3), ten, &lease, cursor, op)
                        .unwrap();
                    prop_assert!(second.is_replay());
                }
                1 => {
                    let first = coord
                        .complete(LogicalTime::from_raw(2), ten, &lease, cursor.clone(), op)
                        .unwrap();
                    prop_assert!(first.is_executed());
                    let second = coord
                        .complete(LogicalTime::from_raw(3), ten, &lease, cursor, op)
                        .unwrap();
                    prop_assert!(second.is_replay());
                }
                _ => {
                    let first = coord
                        .park_shard(
                            LogicalTime::from_raw(2),
                            ten,
                            &lease,
                            ParkReason::TooManyErrors,
                            op,
                        )
                        .unwrap();
                    prop_assert!(first.is_executed());
                    let second = coord
                        .park_shard(
                            LogicalTime::from_raw(3),
                            ten,
                            &lease,
                            ParkReason::TooManyErrors,
                            op,
                        )
                        .unwrap();
                    prop_assert!(second.is_replay());
                }
            }
        }

        /// Cursor monotonicity: cursor.last_key never regresses within
        /// the same lease epoch.
        #[test]
        fn cursor_monotonicity_property(
            keys in proptest::collection::vec(b'a'..b'y', 2..20),
        ) {
            let mut coord = seeded_coordinator();
            let lease = coord
                .acquire_and_restore(
                    LogicalTime::from_raw(1),
                    test_tenant(),
                    test_key(),
                    WorkerId::from_raw(1),
                )
                .unwrap()
                .lease;

            let mut max_key: Option<u8> = None;
            let mut op_counter = 1u64;

            for &key_byte in &keys {
                let cursor = Cursor::with_last_key(vec![key_byte]);
                let result = coord.checkpoint(
                    LogicalTime::from_raw(op_counter + 1),
                    test_tenant(),
                    &lease,
                    cursor,
                    OpId::from_raw(op_counter),
                );
                op_counter += 1;

                match result {
                    Ok(_) => {
                        // Checkpoint succeeded — key must be >= max_key.
                        if let Some(prev) = max_key {
                            prop_assert!(key_byte >= prev);
                        }
                        max_key = Some(key_byte);
                    }
                    Err(CheckpointError::CursorRegression { .. }) => {
                        // Expected: key_byte < max_key, regression rejected.
                        if let Some(prev) = max_key {
                            prop_assert!(key_byte < prev);
                        }
                    }
                    Err(other) => {
                        prop_assert!(
                            false,
                            "unexpected checkpoint error: {other:?}",
                        );
                    }
                }
            }
        }
    }
}
