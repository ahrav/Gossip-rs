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

use std::collections::{HashMap, HashSet};

use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, AcquireResult, CheckpointError, CompleteError, IdempotentOutcome, ParkError,
    RenewError, RenewResult, SplitReplaceError, SplitResidualError,
};
use crate::coordination::lease::{Lease, LeaseHolder, OpKind, OpLogEntry, OpResult};
use crate::coordination::record::{ParkReason, ShardRecord, ShardStatus};
use crate::coordination::shard_spec::{
    ShardLimitScope, SplitValidationError, validate_residual_split, validate_split_coverage,
};
use crate::coordination::split::{
    DerivedShardKind, MAX_SPAWNED_PER_SHARD, SplitReplaceChild, SplitReplacePlan,
    SplitReplaceResult, SplitResidualPlan, SplitResidualResult, derive_split_shard_id,
    hash_checkpoint_payload, hash_complete_payload, hash_park_payload, hash_split_replace_payload,
    hash_split_residual_payload,
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
    max_shards_per_tenant: usize,
    max_total_shards: usize,
}

impl InMemoryCoordinator {
    /// Create a new coordinator with the given default lease duration
    /// and generous default shard limits.
    ///
    /// # Panics
    ///
    /// Panics if `default_lease_duration` is 0.
    pub fn new(default_lease_duration: u64) -> Self {
        Self::with_limits(default_lease_duration, 100_000, 1_000_000)
    }

    /// Create a coordinator with explicit shard count limits.
    ///
    /// # Panics
    ///
    /// Panics if `default_lease_duration` is 0 or if either limit is 0.
    pub fn with_limits(
        default_lease_duration: u64,
        max_shards_per_tenant: usize,
        max_total_shards: usize,
    ) -> Self {
        assert!(default_lease_duration > 0, "lease duration must be > 0");
        assert!(
            max_shards_per_tenant > 0,
            "max_shards_per_tenant must be > 0"
        );
        assert!(max_total_shards > 0, "max_total_shards must be > 0");
        Self {
            shards: HashMap::new(),
            default_lease_duration,
            max_shards_per_tenant,
            max_total_shards,
        }
    }

    /// Seed a shard record directly (test/fixture helper).
    ///
    /// Does not enforce shard count limits — this is a test helper for
    /// constructing specific states.
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

    /// Check that adding `additional` shards for `tenant` stays within limits.
    ///
    /// `temporarily_removed` accounts for records that have been removed
    /// from the map for the remove-mutate-restore pattern (split ops) but
    /// will be restored. These must be counted toward both per-tenant and
    /// global totals.
    fn check_shard_limits(
        &self,
        tenant: TenantId,
        additional: usize,
        temporarily_removed: usize,
    ) -> Result<(), SplitValidationError> {
        // Per-tenant limit (restored parent(s) are for this tenant).
        let tenant_count =
            self.shards.keys().filter(|(t, _)| *t == tenant).count() + temporarily_removed;
        if tenant_count + additional > self.max_shards_per_tenant {
            return Err(SplitValidationError::ShardLimitExceeded {
                current: tenant_count,
                additional,
                max: self.max_shards_per_tenant,
                scope: ShardLimitScope::PerTenant,
            });
        }

        // Global limit.
        let total_count = self.shards.len() + temporarily_removed;
        if total_count + additional > self.max_total_shards {
            return Err(SplitValidationError::ShardLimitExceeded {
                current: total_count,
                additional,
                max: self.max_total_shards,
                scope: ShardLimitScope::Global,
            });
        }

        Ok(())
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
                .expect("lease must exist when is_leased_at returns true");
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
        // snapshot() calls assert_invariants() internally.
        let snapshot = record.snapshot();

        // TODO(events): emit ShardAcquired
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
        record.assert_transition_legal(ShardStatus::Done);
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

        record.assert_transition_legal(ShardStatus::Parked);
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

            // Spawn-cap guard: check BEFORE mutating parent.spawned.
            if !parent.can_spawn(sorted.len()) {
                return Err(SplitReplaceError::SplitInvalid(Box::new(
                    SplitValidationError::SpawnLimitExceeded {
                        current: parent.spawned.len(),
                        additional: sorted.len(),
                        max: MAX_SPAWNED_PER_SHARD,
                    },
                )));
            }

            // Shard count limit guard: prevents split-flooding (CWE-400).
            // Parent was temporarily removed from the map (remove-mutate-restore
            // pattern), so pass temporarily_removed=1 for correct counting.
            self.check_shard_limits(tenant, sorted.len(), 1)
                .map_err(|e| SplitReplaceError::SplitInvalid(Box::new(e)))?;

            // Phase 2: Compute new state (pure — no side effects).
            let (child_ids, children_to_insert) =
                split_replace_build_children(&parent, &sorted, tenant, op_id);

            // Phase 3: Apply mutations. Collision check is defense-in-depth:
            // derive_split_shard_id uses BLAKE3 with domain separation, so
            // collisions indicate a logic bug, not a hash weakness.
            for (k, _) in &children_to_insert {
                if self.shards.contains_key(k) {
                    return Err(SplitReplaceError::SplitInvalid(Box::new(
                        SplitValidationError::DerivedIdCollision {
                            derived_id: k.1.shard(),
                        },
                    )));
                }
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

            if let Some(replay) = split_residual_check_replay(&parent, op_id, payload_hash)? {
                return Ok(replay);
            }
            split_residual_validate_preconditions(now, tenant, lease, &parent, &plan)?;

            // Spawn-cap guard: check BEFORE mutating parent.spawned.
            if !parent.can_spawn(1) {
                return Err(SplitResidualError::SplitInvalid(Box::new(
                    SplitValidationError::SpawnLimitExceeded {
                        current: parent.spawned.len(),
                        additional: 1,
                        max: MAX_SPAWNED_PER_SHARD,
                    },
                )));
            }

            // Shard count limit guard: prevents split-flooding (CWE-400).
            // Parent was temporarily removed from the map (remove-mutate-restore
            // pattern), so pass temporarily_removed=1 for correct counting.
            self.check_shard_limits(tenant, 1, 1)
                .map_err(|e| SplitResidualError::SplitInvalid(Box::new(e)))?;

            // Phase 2: Build residual record (pure).
            let residual_record = split_residual_build_record(&parent, &plan, tenant, residual_id);

            // Phase 3: Apply mutations.
            let residual_key = ShardKey::new(parent.run, residual_id);
            if self.shards.contains_key(&(tenant, residual_key)) {
                return Err(SplitResidualError::SplitInvalid(Box::new(
                    SplitValidationError::DerivedIdCollision {
                        derived_id: residual_id,
                    },
                )));
            }

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
// split_replace helpers
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
    let base_index = parent
        .spawned
        .len()
        .checked_sub(n)
        .expect("split_replace replay: parent.spawned.len() < child count; state corruption");
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

    parent.assert_transition_legal(ShardStatus::Split);
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
// split_residual helpers
// ============================================================================

/// Search `parent.spawned` for a residual derived from the given `op_id`.
///
/// On replay, the residual's original creation index is unknown because
/// `spawned` may have grown since the first execution. We brute-force all
/// possible indices `0..spawned.len()`, re-deriving the BLAKE3-based ID
/// for each and checking membership in a `HashSet`.
///
/// Complexity: O(S·D) where S = `spawned.len()` and D = BLAKE3 hash cost
/// (constant). The `HashSet` construction is O(S) and each lookup is O(1)
/// amortized. At `MAX_SPAWNED_PER_SHARD` (1024), worst case is ~1024
/// hashes + ~1024 set lookups.
///
/// Returns `None` if no match, meaning this is genuinely a new operation.
fn find_replayed_residual(parent: &ShardRecord, op_id: OpId) -> Option<ShardId> {
    assert!(
        parent.spawned.len() <= MAX_SPAWNED_PER_SHARD,
        "spawned count {} exceeds bound {}",
        parent.spawned.len(),
        MAX_SPAWNED_PER_SHARD,
    );
    let spawned_set: HashSet<&ShardId> = parent.spawned.iter().collect();
    for idx in 0..parent.spawned.len() as u32 {
        let candidate = derive_split_shard_id(
            parent.run,
            parent.shard,
            op_id,
            DerivedShardKind::Residual,
            idx,
        );
        if spawned_set.contains(&candidate) {
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
) -> Result<Option<IdempotentOutcome<SplitResidualResult>>, SplitResidualError> {
    if check_op_idempotency(parent, op_id, payload_hash)?.is_some() {
        // Op-log hit. The residual is already in spawned; find it.
        // An op-log hit means `split_residual_apply_parent` completed — the
        // residual was pushed to `parent.spawned` before the op-log entry was
        // written. If `find_replayed_residual` fails here, it indicates a
        // logic bug (spawned was mutated without recording the residual).
        let replayed = find_replayed_residual(parent, op_id).expect(
            "op-log hit for split_residual implies residual exists in parent.spawned; \
             missing entry indicates a coordinator bug",
        );
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual: replayed,
        })));
    }

    // Defense-in-depth: if op_log entry was evicted but residual was
    // already created, detect via parent.spawned (permanent, never
    // evicted). This check comes AFTER op-log miss to avoid masking
    // OpIdConflict. MAX_SPAWNED_PER_SHARD bounds the search.
    //
    // NOTE(limitation): The spawned-probe tier cannot verify payload hash
    // after op-log eviction. If a client replays op_id=X with a *different*
    // plan after the op-log entry is evicted, this path returns Replayed
    // (matching the original residual) instead of OpIdConflict. This is
    // acceptable because: (1) eviction requires 16+ intervening ops,
    // meaning the original execution is far in the past, (2) op_ids are
    // CSPRNG-generated so accidental reuse is astronomically unlikely,
    // (3) this is a reference implementation — production backends with
    // durable op-logs don't have this window.
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
                new_parent_start: plan
                    .parent_new_spec()
                    .key_range_start()
                    .to_vec()
                    .into_boxed_slice(),
                new_parent_end: plan
                    .parent_new_spec()
                    .key_range_end()
                    .to_vec()
                    .into_boxed_slice(),
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

    // -- spawn-cap guard tests -----------------------------------------------

    /// Helper to create a derived ShardId (bit 63 set).
    fn derived_shard_id(base: u64) -> ShardId {
        ShardId::from_raw(base | (1u64 << 63))
    }

    /// Build a coordinator with a shard that already has `spawned_count`
    /// derived entries in `spawned`. The shard is Active with spec [a, z)
    /// and cursor at "d" (within the [a, m) split range).
    fn coordinator_with_spawned_count(spawned_count: usize) -> InMemoryCoordinator {
        let spawned: Vec<ShardId> = (0..spawned_count as u64)
            .map(|i| derived_shard_id(i + 1))
            .collect();
        let record = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            test_shard(),
            ShardStatus::Active,
            None,
            test_spec(), // [a, z)
            test_cursor(b"d"),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            spawned,
            Vec::new(),
        );
        let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
        coord.seed_shard(record);
        coord
    }

    #[test]
    fn split_residual_at_spawn_cap_returns_error() {
        let mut coord = coordinator_with_spawned_count(MAX_SPAWNED_PER_SHARD);
        let lease = acquire_shard(&mut coord, 1, 1);

        let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

        let err = coord
            .split_residual(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap_err();
        assert!(
            matches!(err, SplitResidualError::SplitInvalid(_)),
            "expected SplitInvalid for spawn cap exceeded, got: {err:?}",
        );
    }

    #[test]
    fn split_replace_at_spawn_cap_returns_error() {
        let mut coord = coordinator_with_spawned_count(MAX_SPAWNED_PER_SHARD);
        let lease = acquire_shard(&mut coord, 1, 1);

        let child_a = SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        );
        let child_b = SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        );
        let plan = SplitReplacePlan::try_new(vec![child_a, child_b]).unwrap();

        let err = coord
            .split_replace(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap_err();
        assert!(
            matches!(err, SplitReplaceError::SplitInvalid(_)),
            "expected SplitInvalid for spawn cap exceeded, got: {err:?}",
        );
    }

    #[test]
    fn split_residual_below_cap_succeeds() {
        // One below the cap — should succeed.
        let mut coord = coordinator_with_spawned_count(MAX_SPAWNED_PER_SHARD - 1);
        let lease = acquire_shard(&mut coord, 1, 1);

        let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

        let result = coord
            .split_residual(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap();
        assert!(result.is_executed());
    }

    // -- Idempotent replay after terminal state --------------------------------

    #[test]
    fn complete_replay_after_terminal() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let cursor = test_cursor(b"m");
        let op = OpId::from_raw(1);
        let first = coord
            .complete(now(2), test_tenant(), &lease, cursor.clone(), op)
            .unwrap();
        assert!(first.is_executed());

        // Replay same op_id + payload after shard is terminal (Done).
        let second = coord
            .complete(now(3), test_tenant(), &lease, cursor, op)
            .unwrap();
        assert!(
            second.is_replay(),
            "replay of complete after terminal should return Replayed, not ShardTerminal",
        );
    }

    #[test]
    fn park_replay_after_terminal() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let op = OpId::from_raw(1);
        let first = coord
            .park_shard(now(2), test_tenant(), &lease, ParkReason::TooManyErrors, op)
            .unwrap();
        assert!(first.is_executed());

        // Replay same op_id + payload after shard is terminal (Parked).
        let second = coord
            .park_shard(now(3), test_tenant(), &lease, ParkReason::TooManyErrors, op)
            .unwrap();
        assert!(
            second.is_replay(),
            "replay of park after terminal should return Replayed, not ShardTerminal",
        );
    }

    // -- OpIdConflict tests for split operations --------------------------------

    #[test]
    fn split_replace_op_id_conflict() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let plan_a = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(
                ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                Cursor::initial(),
            ),
            SplitReplaceChild::new(
                ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                Cursor::initial(),
            ),
        ])
        .unwrap();

        let op = OpId::from_raw(1);
        let _ = coord
            .split_replace(now(2), test_tenant(), &lease, plan_a, op)
            .unwrap();

        // Same op_id, different plan (different split point).
        let plan_b = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(
                ShardSpec::with_range(b"a".to_vec(), b"p".to_vec()),
                Cursor::initial(),
            ),
            SplitReplaceChild::new(
                ShardSpec::with_range(b"p".to_vec(), b"z".to_vec()),
                Cursor::initial(),
            ),
        ])
        .unwrap();

        let err = coord
            .split_replace(now(3), test_tenant(), &lease, plan_b, op)
            .unwrap_err();
        assert!(
            matches!(err, SplitReplaceError::OpIdConflict { .. }),
            "expected OpIdConflict, got: {err:?}",
        );
    }

    #[test]
    fn split_residual_op_id_conflict() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        // Checkpoint to set cursor within the new parent range.
        let _ = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease,
                test_cursor(b"f"),
                OpId::from_raw(100),
            )
            .unwrap();

        let plan_a = SplitResidualPlan::try_new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        )
        .unwrap();

        let op = OpId::from_raw(1);
        let _ = coord
            .split_residual(now(3), test_tenant(), &lease, plan_a, op)
            .unwrap();

        // Same op_id, different plan (different split point).
        let plan_b = SplitResidualPlan::try_new(
            ShardSpec::with_range(b"a".to_vec(), b"p".to_vec()),
            ShardSpec::with_range(b"p".to_vec(), b"z".to_vec()),
        )
        .unwrap();

        let err = coord
            .split_residual(now(4), test_tenant(), &lease, plan_b, op)
            .unwrap_err();
        assert!(
            matches!(err, SplitResidualError::OpIdConflict { .. }),
            "expected OpIdConflict, got: {err:?}",
        );
    }

    // -- Lease deadline overflow -----------------------------------------------

    #[test]
    #[should_panic(expected = "lease deadline overflow")]
    fn acquire_panics_on_lease_deadline_overflow() {
        let mut coord = seeded_coordinator();
        // Using u64::MAX as `now` will cause checked_add to return None,
        // triggering the expect("lease deadline overflow") panic.
        let _ = coord.acquire_and_restore(
            LogicalTime::from_raw(u64::MAX),
            test_tenant(),
            test_key(),
            test_worker(1),
        );
    }

    // -- Shard count limit tests -----------------------------------------------

    fn other_tenant() -> TenantId {
        TenantId::from_bytes([0x02; 32])
    }

    #[test]
    fn split_replace_exceeds_per_tenant_limit() {
        let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 3, 100);

        // Seed the target shard.
        let record = ShardRecord::new_active(
            test_tenant(),
            test_run(),
            test_shard(),
            test_spec(),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record);

        // Seed two additional shards to fill tenant to limit.
        let record2 = ShardRecord::new_active(
            test_tenant(),
            test_run(),
            ShardId::from_raw(20),
            ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record2);
        let record3 = ShardRecord::new_active(
            test_tenant(),
            test_run(),
            ShardId::from_raw(30),
            ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record3);

        let lease = acquire_shard(&mut coord, 1, 1);

        let plan = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(
                ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                Cursor::initial(),
            ),
            SplitReplaceChild::new(
                ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                Cursor::initial(),
            ),
        ])
        .unwrap();

        let err = coord
            .split_replace(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap_err();
        assert!(
            matches!(err, SplitReplaceError::SplitInvalid(ref e)
                if matches!(e.as_ref(),
                    SplitValidationError::ShardLimitExceeded { scope: ShardLimitScope::PerTenant, .. })),
            "expected ShardLimitExceeded(PerTenant), got: {err:?}",
        );
    }

    #[test]
    fn split_residual_exceeds_global_limit() {
        // Global limit of 2: seed 2 shards, then split_residual wants to add 1 more.
        let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 100, 2);

        let record = ShardRecord::new_active(
            test_tenant(),
            test_run(),
            test_shard(),
            test_spec(),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record);

        // Seed a second shard (different tenant) to fill global limit.
        let record2 = ShardRecord::new_active(
            other_tenant(),
            test_run(),
            ShardId::from_raw(20),
            ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record2);

        let lease = acquire_shard(&mut coord, 1, 1);

        // Checkpoint to set cursor within the new parent range.
        let _ = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease,
                test_cursor(b"f"),
                OpId::from_raw(100),
            )
            .unwrap();

        let plan = SplitResidualPlan::try_new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        )
        .unwrap();

        let err = coord
            .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap_err();
        assert!(
            matches!(err, SplitResidualError::SplitInvalid(ref e)
                if matches!(e.as_ref(),
                    SplitValidationError::ShardLimitExceeded { scope: ShardLimitScope::Global, .. })),
            "expected ShardLimitExceeded(Global), got: {err:?}",
        );
    }

    // -- Tenant isolation tests -----------------------------------------------
    //
    // The coordinator uses a composite key `(TenantId, ShardKey)` for the
    // shard map. A wrong tenant simply doesn't find the record, returning
    // `ShardNotFound`. This is the correct security behavior: the wrong
    // tenant never learns the shard exists. The `TenantMismatch` variant
    // in `validate_lease` is a defense-in-depth check for internal
    // corruption, not the primary isolation mechanism.

    #[test]
    fn acquire_wrong_tenant_returns_not_found() {
        let mut coord = seeded_coordinator();
        let err = coord
            .acquire_and_restore(now(1), other_tenant(), test_key(), test_worker(1))
            .unwrap_err();
        assert!(
            matches!(err, AcquireError::ShardNotFound { .. }),
            "wrong tenant should see ShardNotFound, got: {err:?}",
        );
    }

    #[test]
    fn checkpoint_wrong_tenant_returns_not_found() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let err = coord
            .checkpoint(
                now(2),
                other_tenant(),
                &lease,
                test_cursor(b"f"),
                OpId::from_raw(1),
            )
            .unwrap_err();
        assert!(
            matches!(err, CheckpointError::ShardNotFound { .. }),
            "wrong tenant should see ShardNotFound, got: {err:?}",
        );
    }

    #[test]
    fn complete_wrong_tenant_returns_not_found() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let err = coord
            .complete(
                now(2),
                other_tenant(),
                &lease,
                test_cursor(b"m"),
                OpId::from_raw(1),
            )
            .unwrap_err();
        assert!(
            matches!(err, CompleteError::ShardNotFound { .. }),
            "wrong tenant should see ShardNotFound, got: {err:?}",
        );
    }

    #[test]
    fn split_replace_wrong_tenant_returns_not_found() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        let plan = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(
                ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                Cursor::initial(),
            ),
            SplitReplaceChild::new(
                ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                Cursor::initial(),
            ),
        ])
        .unwrap();

        let err = coord
            .split_replace(now(2), other_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap_err();
        assert!(
            matches!(err, SplitReplaceError::ShardNotFound { .. }),
            "wrong tenant should see ShardNotFound, got: {err:?}",
        );
    }

    #[test]
    fn split_residual_wrong_tenant_returns_not_found() {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 1, 1);

        // Checkpoint to set cursor within the new parent range.
        let _ = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease,
                test_cursor(b"f"),
                OpId::from_raw(100),
            )
            .unwrap();

        let plan = SplitResidualPlan::try_new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        )
        .unwrap();

        let err = coord
            .split_residual(now(3), other_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap_err();
        assert!(
            matches!(err, SplitResidualError::ShardNotFound { .. }),
            "wrong tenant should see ShardNotFound, got: {err:?}",
        );
    }

    // -- Lifecycle integration tests -----------------------------------------------

    #[test]
    fn full_lifecycle_acquire_checkpoint_split_residual_complete() {
        let mut coord = seeded_coordinator(); // [a, z)

        // Step 1: Acquire shard (worker 1, t=1).
        let lease_w1 = acquire_shard(&mut coord, 1, 1);

        // Step 2: Checkpoint to "f" (t=2, op_id=10).
        let cp_result = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease_w1,
                test_cursor(b"f"),
                OpId::from_raw(10),
            )
            .unwrap();
        assert!(cp_result.is_executed());

        // Step 3: Split residual [a,m) + [m,z) (t=3, op_id=20).
        let plan = SplitResidualPlan::try_new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        )
        .unwrap();
        let split_result = coord
            .split_residual(now(3), test_tenant(), &lease_w1, plan, OpId::from_raw(20))
            .unwrap();
        assert!(split_result.is_executed());
        let residual_id = split_result.into_inner().residual;

        // Step 4: Parent still Active — re-acquire after lease expiry (worker 2).
        let lease_w2 = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 4),
                test_tenant(),
                test_key(),
                test_worker(2),
            )
            .unwrap()
            .lease;

        // Step 5: Complete parent (t=LEASE_DURATION+5, op_id=30).
        let complete_result = coord
            .complete(
                now(LEASE_DURATION + 5),
                test_tenant(),
                &lease_w2,
                test_cursor(b"l"), // within [a, m)
                OpId::from_raw(30),
            )
            .unwrap();
        assert!(complete_result.is_executed());

        // Step 6: Acquire residual child (worker 3).
        let residual_key = ShardKey::new(test_run(), residual_id);
        let child_result = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 6),
                test_tenant(),
                residual_key,
                test_worker(3),
            )
            .unwrap();
        // Verify snapshot has the residual range [m, z).
        assert_eq!(
            child_result.snapshot.spec().key_range_start(),
            b"m".as_slice(),
        );
        assert_eq!(
            child_result.snapshot.spec().key_range_end(),
            b"z".as_slice(),
        );
        let child_lease = child_result.lease;

        // Step 7: Checkpoint residual child to "p".
        let _ = coord
            .checkpoint(
                now(LEASE_DURATION + 7),
                test_tenant(),
                &child_lease,
                test_cursor(b"p"),
                OpId::from_raw(40),
            )
            .unwrap();

        // Step 8: Complete residual child.
        let child_complete = coord
            .complete(
                now(LEASE_DURATION + 8),
                test_tenant(),
                &child_lease,
                test_cursor(b"y"), // within [m, z)
                OpId::from_raw(50),
            )
            .unwrap();
        assert!(child_complete.is_executed());

        // Step 9: Verify both parent and child are terminal.
        let parent_err = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 9),
                test_tenant(),
                test_key(),
                test_worker(4),
            )
            .unwrap_err();
        assert!(
            matches!(parent_err, AcquireError::ShardTerminal { .. }),
            "parent should be terminal, got: {parent_err:?}",
        );

        let child_err = coord
            .acquire_and_restore(
                now(LEASE_DURATION + 10),
                test_tenant(),
                residual_key,
                test_worker(4),
            )
            .unwrap_err();
        assert!(
            matches!(child_err, AcquireError::ShardTerminal { .. }),
            "child should be terminal, got: {child_err:?}",
        );
    }

    #[test]
    fn lifecycle_split_residual_twice_then_complete_children() {
        let mut coord = seeded_coordinator(); // [a, z)

        // Step 1: Acquire, checkpoint to "d".
        let lease = acquire_shard(&mut coord, 1, 1);
        let _ = coord
            .checkpoint(
                now(2),
                test_tenant(),
                &lease,
                test_cursor(b"d"),
                OpId::from_raw(10),
            )
            .unwrap();

        // Step 2: split_residual [a,m) + [m,z) — capture residual_1.
        let plan1 = SplitResidualPlan::try_new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        )
        .unwrap();
        let r1 = coord
            .split_residual(now(3), test_tenant(), &lease, plan1, OpId::from_raw(20))
            .unwrap();
        let residual_1 = r1.into_inner().residual;

        // Step 3: Checkpoint parent further to "g" (within [a, m)).
        let _ = coord
            .checkpoint(
                now(4),
                test_tenant(),
                &lease,
                test_cursor(b"g"),
                OpId::from_raw(30),
            )
            .unwrap();

        // Step 4: split_residual again [a,j) + [j,m) — capture residual_2.
        let plan2 = SplitResidualPlan::try_new(
            ShardSpec::with_range(b"a".to_vec(), b"j".to_vec()),
            ShardSpec::with_range(b"j".to_vec(), b"m".to_vec()),
        )
        .unwrap();
        let r2 = coord
            .split_residual(now(5), test_tenant(), &lease, plan2, OpId::from_raw(40))
            .unwrap();
        let residual_2 = r2.into_inner().residual;

        // Step 5: Complete parent [a, j).
        let _ = coord
            .complete(
                now(6),
                test_tenant(),
                &lease,
                test_cursor(b"i"), // within [a, j)
                OpId::from_raw(50),
            )
            .unwrap();

        // Step 6: Acquire + complete residual_1 [m, z).
        let r1_key = ShardKey::new(test_run(), residual_1);
        let r1_acq = coord
            .acquire_and_restore(now(7), test_tenant(), r1_key, test_worker(2))
            .unwrap();
        assert_eq!(r1_acq.snapshot.spec().key_range_start(), b"m".as_slice());
        assert_eq!(r1_acq.snapshot.spec().key_range_end(), b"z".as_slice());
        let _ = coord
            .complete(
                now(8),
                test_tenant(),
                &r1_acq.lease,
                test_cursor(b"y"),
                OpId::from_raw(60),
            )
            .unwrap();

        // Step 7: Acquire + complete residual_2 [j, m).
        let r2_key = ShardKey::new(test_run(), residual_2);
        let r2_acq = coord
            .acquire_and_restore(now(9), test_tenant(), r2_key, test_worker(3))
            .unwrap();
        assert_eq!(r2_acq.snapshot.spec().key_range_start(), b"j".as_slice());
        assert_eq!(r2_acq.snapshot.spec().key_range_end(), b"m".as_slice());
        let _ = coord
            .complete(
                now(10),
                test_tenant(),
                &r2_acq.lease,
                test_cursor(b"l"),
                OpId::from_raw(70),
            )
            .unwrap();

        // Step 8: All three are terminal.
        let parent_err = coord
            .acquire_and_restore(now(11), test_tenant(), test_key(), test_worker(4))
            .unwrap_err();
        assert!(matches!(parent_err, AcquireError::ShardTerminal { .. }));

        let r1_err = coord
            .acquire_and_restore(now(12), test_tenant(), r1_key, test_worker(4))
            .unwrap_err();
        assert!(matches!(r1_err, AcquireError::ShardTerminal { .. }));

        let r2_err = coord
            .acquire_and_restore(now(13), test_tenant(), r2_key, test_worker(4))
            .unwrap_err();
        assert!(matches!(r2_err, AcquireError::ShardTerminal { .. }));
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
        SplitReplace,
        SplitResidual,
        TimeAdvance { ticks: u64 },
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0u8..4).prop_map(|w| Op::Acquire { worker: w }),
            4 => (b'a'..b'y').prop_map(|k| Op::Checkpoint { cursor_key: k }),
            2 => (b'a'..b'y').prop_map(|k| Op::Complete { cursor_key: k }),
            1 => Just(Op::Park),
            2 => Just(Op::Renew),
            1 => Just(Op::SplitReplace),
            1 => Just(Op::SplitResidual),
            2 => (1u64..200).prop_map(|t| Op::TimeAdvance { ticks: t }),
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
            Op::SplitReplace => {
                if let Some(lease) = last_lease.as_ref() {
                    let child_a = SplitReplaceChild::new(
                        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                        Cursor::initial(),
                    );
                    let child_b = SplitReplaceChild::new(
                        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                        Cursor::initial(),
                    );
                    if let Ok(plan) = SplitReplacePlan::try_new(vec![child_a, child_b]) {
                        let _ = coord.split_replace(now, ten, lease, plan, OpId::from_raw(oc));
                        return (time, oc + 1);
                    }
                }
                (time, oc)
            }
            Op::SplitResidual => {
                if let Some(lease) = last_lease.as_ref() {
                    let new_parent = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
                    let residual = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
                    if let Ok(plan) = SplitResidualPlan::try_new(new_parent, residual) {
                        let _ = coord.split_residual(now, ten, lease, plan, OpId::from_raw(oc));
                        return (time, oc + 1);
                    }
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
