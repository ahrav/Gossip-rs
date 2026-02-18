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
//! All transitions originate from `Active`. `Done` and `Split` are permanently
//! terminal. `Parked` has one escape: `unpark_shard` ([`RunManagement`], not
//! [`CoordinationBackend`]) transitions Parked → Active, bumping the fence
//! epoch. All other terminal-state mutations are rejected.
//!
//! `split_residual` is special: it shrinks the parent's range and spawns a
//! residual child, but the parent stays `Active`.
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
use crate::coordination::run::{
    InitialShard, RunConfig, RunManagement, RunOpKind, RunOpLogEntry, RunOpResult, RunProgress,
    RunRecord, RunStatus, ShardFilter, ShardSummary, hash_cancel_run_payload,
    hash_complete_run_payload, hash_fail_run_payload, hash_register_shards_payload,
    hash_unpark_payload, validate_manifest,
};
use crate::coordination::run_errors::{
    CancelRunError, CompleteRunError, CreateRunError, FailRunError, GetRunError,
    RegisterShardsError, UnparkError,
};
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
use crate::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};

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
#[derive(Debug)]
pub struct InMemoryCoordinator {
    shards: HashMap<(TenantId, ShardKey), ShardRecord>,
    runs: HashMap<(TenantId, RunId), RunRecord>,
    /// Secondary index: run → shard IDs (root + split children).
    ///
    /// Avoids a full `shards` map scan when computing run progress or
    /// listing shards for a single run. Updated by `register_shards`
    /// and split operations (`split_replace`, `split_residual`).
    run_shards: HashMap<(TenantId, RunId), Vec<ShardId>>,
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
            runs: HashMap::new(),
            run_shards: HashMap::new(),
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
    /// In production paths, shards are created through `register_shards`
    /// (root shards) or split operations (derived children), both of
    /// which construct records with correct invariants by construction.
    pub fn seed_shard(&mut self, record: ShardRecord) {
        record.assert_invariants();
        let key = ShardKey::new(record.run, record.shard);
        self.shards.insert((record.tenant, key), record);
    }

    /// Seed a shard record **without** calling `assert_invariants()`.
    ///
    /// Only available in test builds — allows inserting intentionally
    /// invalid records for testing external invariant checkers.
    #[cfg(test)]
    pub fn seed_shard_unchecked(&mut self, record: ShardRecord) {
        let key = ShardKey::new(record.run, record.shard);
        self.shards.insert((record.tenant, key), record);
    }

    /// Read-only access to the shard map for external invariant checking.
    ///
    /// Gated behind `test-support` or `#[cfg(test)]` -- not part of the
    /// production API surface.
    #[cfg(any(test, feature = "test-support"))]
    pub fn shards(&self) -> &HashMap<(TenantId, ShardKey), ShardRecord> {
        &self.shards
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

        // 2) Non-Active shards cannot be acquired (terminal within the
        //    protocol; admin unpark is handled separately via RunManagement).
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
            let sorted = split_replace_validate_preconditions(&parent, &plan)?;

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
                let child_shard = v.shard;
                self.shards.insert(k, v);
                self.index_shard(tenant, parent.run, child_shard);
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
            self.index_shard(tenant, parent.run, residual_id);

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

/// Validate split_replace preconditions: coverage and spawn-cap.
///
/// Sorts children, validates that they partition the parent's range, and
/// checks the spawn-cap limit. Returns the sorted children on success.
fn split_replace_validate_preconditions<'a>(
    parent: &ShardRecord,
    plan: &'a SplitReplacePlan,
) -> Result<Vec<&'a SplitReplaceChild>, SplitReplaceError> {
    let sorted = split_replace_sort_children(plan);
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
    Ok(sorted)
}

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
/// cursor bounds (parent's cursor must remain within the shrunk range),
/// and spawn-cap (parent has not exceeded [`MAX_SPAWNED_PER_SHARD`]).
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
    split_residual_validate_cursor_bounds(parent, plan)?;
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
    Ok(())
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
// Run-level helpers
// ============================================================================

impl InMemoryCoordinator {
    /// Register a shard in the run→shards index.
    fn index_shard(&mut self, tenant: TenantId, run: RunId, shard: ShardId) {
        let entry = self.run_shards.entry((tenant, run)).or_default();
        if !entry.contains(&shard) {
            entry.push(shard);
        }
    }

    /// Look up a run record, checking tenant isolation.
    fn lookup_run(&self, tenant: TenantId, run: RunId) -> Result<&RunRecord, GetRunError> {
        let record = self
            .runs
            .get(&(tenant, run))
            .ok_or(GetRunError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(GetRunError::TenantMismatch { expected: tenant });
        }
        Ok(record)
    }
}

// ============================================================================
// RunManagement implementation
// ============================================================================

impl RunManagement for InMemoryCoordinator {
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        config.assert_valid();

        if self.runs.contains_key(&(tenant, run)) {
            return Err(CreateRunError::RunAlreadyExists { run });
        }

        let record = RunRecord {
            tenant,
            run,
            config,
            status: RunStatus::Initializing,
            created_at: now,
            completed_at: None,
            root_shards: Vec::new(),
            op_log: Vec::with_capacity(RunRecord::OP_LOG_CAP),
        };
        record.assert_invariants();

        self.runs.insert((tenant, run), record.clone());
        Ok(record)
    }

    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShard],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        let payload_hash = hash_register_shards_payload(shards);

        // 1. Lookup + tenant check.
        let record = self
            .runs
            .get(&(tenant, run))
            .ok_or(RegisterShardsError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(RegisterShardsError::TenantMismatch { expected: tenant });
        }

        // 2. Idempotency check FIRST (before status).
        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            debug_assert_eq!(
                entry.kind(),
                RunOpKind::RegisterShards,
                "idempotent replay kind mismatch: expected RegisterShards, got {:?}",
                entry.kind(),
            );
            match entry.result() {
                RunOpResult::RegisteredShards { shard_ids } => {
                    return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                }
                RunOpResult::Ack => {
                    panic!(
                        "Run {:?}: RegisterShards op-log entry has Ack result \
                         (expected RegisteredShards) — data corruption",
                        run,
                    );
                }
            }
        }

        // 3. Status check.
        if record.status != RunStatus::Initializing {
            return Err(RegisterShardsError::WrongStatus {
                status: record.status,
            });
        }

        // 4. Validate manifest.
        validate_manifest(shards).map_err(RegisterShardsError::ManifestInvalid)?;

        // 5. Shard count limit check (F3: register_shards must respect limits).
        self.check_shard_limits(tenant, shards.len(), 0)
            .map_err(|e| match e {
                SplitValidationError::ShardLimitExceeded {
                    current,
                    additional,
                    max,
                    scope,
                } => RegisterShardsError::ShardLimitExceeded {
                    current,
                    additional,
                    max,
                    scope,
                },
                _ => unreachable!("check_shard_limits only returns ShardLimitExceeded"),
            })?;

        // 6. Build and insert shard records in a single pass.
        let cursor_semantics = record.config.cursor_semantics();
        let shard_ids: Vec<ShardId> = shards.iter().map(|s| s.shard()).collect();

        for s in shards {
            let key = ShardKey::new(run, s.shard());
            let mut sr =
                ShardRecord::new_active(tenant, run, s.shard(), s.spec().clone(), cursor_semantics);
            if !s.cursor().is_initial() {
                sr.cursor = s.cursor().clone();
            }
            sr.assert_invariants();
            self.shards.insert((tenant, key), sr);
        }

        // Batch-insert into run→shards index (validate_manifest guarantees uniqueness).
        self.run_shards
            .entry((tenant, run))
            .or_default()
            .extend_from_slice(&shard_ids);

        // 7. Update RunRecord: status → Active, root_shards, op-log.
        let record = self.runs.get_mut(&(tenant, run)).unwrap();
        record.status = RunStatus::Active;
        record.root_shards = shard_ids.clone();
        record.op_log_push(RunOpLogEntry::new(
            op_id,
            RunOpKind::RegisterShards,
            payload_hash,
            now,
            RunOpResult::RegisteredShards {
                shard_ids: shard_ids.clone().into_boxed_slice(),
            },
        ));
        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(shard_ids))
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        self.lookup_run(tenant, run).cloned()
    }

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        // Validate run exists and tenant matches.
        let _ = self.lookup_run(tenant, run)?;

        let mut progress = RunProgress::default();
        if let Some(shard_ids) = self.run_shards.get(&(tenant, run)) {
            // Order-independent: iterate shard_ids, look up each record.
            for &shard_id in shard_ids {
                let key = ShardKey::new(run, shard_id);
                if let Some(record) = self.shards.get(&(tenant, key)) {
                    let is_leased = record.is_leased_at(now);
                    progress.count_shard(record.status, is_leased);
                }
            }
        }
        Ok(progress)
    }

    fn list_shards(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
    ) -> Result<Vec<ShardSummary>, GetRunError> {
        let _ = self.lookup_run(tenant, run)?;

        let mut summaries = Vec::new();
        if let Some(shard_ids) = self.run_shards.get(&(tenant, run)) {
            for &shard_id in shard_ids {
                let key = ShardKey::new(run, shard_id);
                if let Some(record) = self.shards.get(&(tenant, key)) {
                    let summary = ShardSummary::from_record(record, now);
                    if filter.matches(&summary) {
                        summaries.push(summary);
                    }
                }
            }
        }

        // Sort by key_range_start for deterministic output.
        summaries.sort_by(|a, b| a.key_range_start().cmp(b.key_range_start()));
        Ok(summaries)
    }

    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError> {
        let payload_hash = hash_complete_run_payload();

        let record = self
            .runs
            .get_mut(&(tenant, run))
            .ok_or(CompleteRunError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(CompleteRunError::TenantMismatch { expected: tenant });
        }

        // Idempotency check FIRST.
        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            debug_assert_eq!(
                entry.kind(),
                RunOpKind::CompleteRun,
                "idempotent replay kind mismatch: expected CompleteRun, got {:?}",
                entry.kind(),
            );
            return Ok(IdempotentOutcome::Replayed(()));
        }

        // Terminal check.
        if record.status.is_terminal() {
            return Err(CompleteRunError::RunTerminal {
                status: record.status,
            });
        }

        // Must be Active.
        if record.status != RunStatus::Active {
            return Err(CompleteRunError::WrongStatus {
                status: record.status,
            });
        }

        record.status = RunStatus::Done;
        record.completed_at = Some(now);
        record.op_log_push(RunOpLogEntry::new(
            op_id,
            RunOpKind::CompleteRun,
            payload_hash,
            now,
            RunOpResult::Ack,
        ));
        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(()))
    }

    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, FailRunError> {
        let payload_hash = hash_fail_run_payload();

        let record = self
            .runs
            .get_mut(&(tenant, run))
            .ok_or(FailRunError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(FailRunError::TenantMismatch { expected: tenant });
        }

        // Idempotency check FIRST.
        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            debug_assert_eq!(
                entry.kind(),
                RunOpKind::FailRun,
                "idempotent replay kind mismatch: expected FailRun, got {:?}",
                entry.kind(),
            );
            return Ok(IdempotentOutcome::Replayed(()));
        }

        // Terminal check.
        if record.status.is_terminal() {
            return Err(FailRunError::RunTerminal {
                status: record.status,
            });
        }

        // Must be Active (PD-2: not Initializing).
        if record.status != RunStatus::Active {
            return Err(FailRunError::WrongStatus {
                status: record.status,
            });
        }

        record.status = RunStatus::Failed;
        record.completed_at = Some(now);
        record.op_log_push(RunOpLogEntry::new(
            op_id,
            RunOpKind::FailRun,
            payload_hash,
            now,
            RunOpResult::Ack,
        ));
        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(()))
    }

    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CancelRunError> {
        let payload_hash = hash_cancel_run_payload();

        let record = self
            .runs
            .get_mut(&(tenant, run))
            .ok_or(CancelRunError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(CancelRunError::TenantMismatch { expected: tenant });
        }

        // Idempotency check FIRST.
        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            debug_assert_eq!(
                entry.kind(),
                RunOpKind::CancelRun,
                "idempotent replay kind mismatch: expected CancelRun, got {:?}",
                entry.kind(),
            );
            return Ok(IdempotentOutcome::Replayed(()));
        }

        // Terminal check.
        if record.status.is_terminal() {
            return Err(CancelRunError::RunTerminal {
                status: record.status,
            });
        }

        // Accepts both Initializing and Active (unlike fail_run).

        record.status = RunStatus::Cancelled;
        record.completed_at = Some(now);
        record.op_log_push(RunOpLogEntry::new(
            op_id,
            RunOpKind::CancelRun,
            payload_hash,
            now,
            RunOpResult::Ack,
        ));
        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(()))
    }

    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        let payload_hash = hash_unpark_payload(&key);

        let record = self
            .shards
            .get(&(tenant, key))
            .ok_or(UnparkError::ShardNotFound)?;
        if record.tenant != tenant {
            return Err(UnparkError::TenantMismatch { expected: tenant });
        }

        // NOTE(limitation): Unlike split_residual, unpark has no permanent marker
        // for defense-in-depth replay detection after op-log eviction. After 16+
        // shard-level operations, a stale unpark retry is treated as new. This is
        // acceptable because: (1) op_ids are CSPRNG-generated, (2) the shard must
        // be re-parked before a stale unpark could succeed, requiring a pathological
        // park→16ops→re-park→stale-retry sequence.

        // Idempotency via SHARD op-log (not run op-log).
        if check_op_idempotency(record, op_id, payload_hash)
            .map_err(|e| match e {
                crate::coordination::error::CoordError::OpIdConflict {
                    op_id,
                    expected_hash,
                    actual_hash,
                } => UnparkError::OpIdConflict(crate::coordination::run::RunOpIdConflict {
                    op_id,
                    expected_hash,
                    actual_hash,
                }),
                other => unreachable!("unexpected CoordError: {other:?}"),
            })?
            .is_some()
        {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        // Must be Parked.
        if record.status != ShardStatus::Parked {
            return Err(UnparkError::NotParked {
                status: record.status,
            });
        }

        let record = self.shards.get_mut(&(tenant, key)).unwrap();

        // Bump fence FIRST (fence any zombie workers from the prior lease).
        record.fence_epoch = record.fence_epoch.increment();

        // Clear park state, restore Active.
        record.park_reason = None;
        record.status = ShardStatus::Active;
        record.lease = None;

        // Record in shard op-log.
        record.op_log_push(OpLogEntry::new(
            op_id,
            OpKind::Unpark,
            OpResult::Completed,
            payload_hash,
            now,
        ));
        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(()))
    }
}

#[cfg(test)]
#[path = "in_memory_tests.rs"]
mod tests;
