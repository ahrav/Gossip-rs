//! In-memory reference implementation of the Boundary 2 coordination backend.
//!
//! This backend is intentionally:
//! - Single-threaded (`&mut self` serializes all operations)
//! - Purely in-memory (HashMaps)
//! - Strict about invariants (Tiger-style `assert_invariants()` after mutations)
//!
//! It serves as the executable reference for the normative spec:
//! - fencing tokens (Kleppmann 2016)
//! - leases (Gray & Cheriton 1989)
//! - bounded idempotency caches (Stripe idempotency pattern)

use std::collections::HashMap;

use crate::coordination::cursor::Cursor;
use crate::coordination::error::{
    AcquireError, AcquireResult, CheckpointError, CompleteError, IdempotentOutcome, ParkError,
    RenewError, RenewResult, SplitReplaceError, SplitResidualError,
};
use crate::coordination::lease::{Lease, OpKind, OpLogEntry, OpResult};
use crate::coordination::record::{ParkReason, ShardRecord, ShardStatus};
use crate::coordination::run::{
    validate_manifest, CancelRunError, CompleteRunError, CreateRunError, GetRunError, InitialShard,
    RegisterShardsError, RunConfig, RunManagement, RunProgress, RunRecord, RunStatus, ShardFilter,
    ShardSummary, UnparkError,
};
use crate::coordination::shard_spec::{validate_residual_split, validate_split_coverage, SplitValidationError};
use crate::coordination::split::{
    derive_split_shard_id, hash_checkpoint_payload, hash_complete_payload, hash_park_payload,
    hash_split_replace_payload, hash_split_residual_payload, DerivedShardKind, SplitReplacePlan,
    SplitReplaceResult, SplitResidualPlan, SplitResidualResult,
};
use crate::coordination::traits::CoordinationBackend;
use crate::coordination::validation::{check_op_idempotency, validate_cursor_update, validate_lease};
use crate::identity::{FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};

/// A minimal in-memory coordinator.
#[derive(Debug, Default)]
pub struct InMemoryCoordinator {
    shards: HashMap<(TenantId, ShardKey), ShardRecord>,
    runs: HashMap<(TenantId, RunId), RunRecord>,

    /// Fast-path index to avoid scanning `self.shards` for run-level queries.
    ///
    /// Invariant: for any `(tenant, run)` present, the vec contains every shard id that belongs
    /// to that run (roots + derived). Duplicates are tolerated but avoided.
    run_shards: HashMap<(TenantId, RunId), Vec<ShardId>>,

    /// Fallback lease duration used if a run record isn't present.
    default_lease_duration: u64,
}

impl InMemoryCoordinator {
    pub fn new(default_lease_duration: u64) -> Self {
        assert!(default_lease_duration > 0, "lease duration must be > 0");
        Self {
            shards: HashMap::new(),
            runs: HashMap::new(),
            run_shards: HashMap::new(),
            default_lease_duration,
        }
    }

    /// Test/fixture helper: seed a shard directly.
    ///
    /// Prefer creating shards through `register_shards` and the split operations.
    pub fn seed_shard(&mut self, record: ShardRecord) {
        let tenant = record.tenant;
        let run = record.run;
        let shard = record.shard;

        let key = (tenant, ShardKey { run, shard });
        self.shards.insert(key, record);
        self.index_shard(tenant, run, shard);
    }

    fn index_shard(&mut self, tenant: TenantId, run: RunId, shard: ShardId) {
        let entry = self.run_shards.entry((tenant, run)).or_default();
        if !entry.contains(&shard) {
            entry.push(shard);
        }
    }

    #[inline]
    fn lease_duration_for(&self, tenant: TenantId, run: RunId) -> u64 {
        self.runs
            .get(&(tenant, run))
            .map(|r| r.config.lease_duration)
            .unwrap_or(self.default_lease_duration)
    }

    #[inline]
    fn lease_deadline(now: LogicalTime, lease_duration: u64) -> LogicalTime {
        // `LogicalTime` is an input; we still keep arithmetic explicit.
        LogicalTime(now.0.saturating_add(lease_duration))
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
        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(AcquireError::ShardNotFound { shard: key })?;

        // 1) Tenant isolation (INV-S01).
        if record.tenant != tenant {
            return Err(AcquireError::TenantMismatch {
                expected: tenant,
                actual: record.tenant,
            });
        }

        // 2) Must be protocol-active.
        if record.status != ShardStatus::Active {
            return Err(AcquireError::ShardTerminal {
                shard: key,
                status: record.status,
            });
        }

        // 3) No active lease.
        if record.is_leased_at(now) {
            return Err(AcquireError::AlreadyLeased {
                shard: key,
                current_owner: record.lease_owner.unwrap_or(worker),
                deadline: record.lease_deadline.unwrap_or(LogicalTime::ZERO),
            });
        }

        // 4) Ownership transfer: bump fence epoch (INV-S02).
        record.fence_epoch = FenceEpoch(record.fence_epoch.0.saturating_add(1));

        // 5) Grant lease.
        let lease_duration = self.lease_duration_for(tenant, key.run);
        let deadline = Self::lease_deadline(now, lease_duration);
        record.lease_owner = Some(worker);
        record.lease_deadline = Some(deadline);

        // 6) Return the lease + snapshot.
        let lease = Lease {
            tenant,
            run: key.run,
            shard: key.shard,
            owner: worker,
            fence: record.fence_epoch,
            deadline,
        };

        let snapshot = record.snapshot();

        record.assert_invariants();

        Ok(AcquireResult { lease, snapshot })
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = ShardKey {
            run: lease.run,
            shard: lease.shard,
        };

        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(RenewError::ShardNotFound { shard: key })?;

        validate_lease(now, tenant, lease, record)?;

        let lease_duration = self.lease_duration_for(tenant, lease.run);
        let deadline = Self::lease_deadline(now, lease_duration);
        record.lease_deadline = Some(deadline);

        record.assert_invariants();

        Ok(RenewResult { new_deadline: deadline })
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let key = ShardKey {
            run: lease.run,
            shard: lease.shard,
        };

        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(CheckpointError::ShardNotFound { shard: key })?;

        // Idempotency is checked before lease validation so replays succeed even
        // after the shard becomes terminal or the lease is released.
        let payload_hash = hash_checkpoint_payload(&new_cursor);
        if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        validate_lease(now, tenant, lease, record)?;
        validate_cursor_update(&new_cursor, record)?;

        record.cursor = new_cursor;
        record.op_log_push(OpLogEntry {
            op_id,
            kind: OpKind::Checkpoint,
            result: OpResult::Completed,
            payload_hash,
            executed_at: now,
        });

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
        let key = ShardKey {
            run: lease.run,
            shard: lease.shard,
        };

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
        record.lease_owner = None;
        record.lease_deadline = None;

        record.op_log_push(OpLogEntry {
            op_id,
            kind: OpKind::Complete,
            result: OpResult::Completed,
            payload_hash,
            executed_at: now,
        });

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
        let key = ShardKey {
            run: lease.run,
            shard: lease.shard,
        };

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
        record.lease_owner = None;
        record.lease_deadline = None;

        record.op_log_push(OpLogEntry {
            op_id,
            kind: OpKind::Park,
            result: OpResult::Completed,
            payload_hash,
            executed_at: now,
        });

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
        let key = ShardKey {
            run: lease.run,
            shard: lease.shard,
        };
        let map_key = (tenant, key);

        // Take ownership of the parent record so we can insert children without
        // fighting the borrow checker, while still keeping error paths atomic.
        let mut parent = self
            .shards
            .remove(&map_key)
            .ok_or(SplitReplaceError::ShardNotFound { shard: key })?;

        // Ensure we always put it back on every return path.
        let result = (|| {
            if parent.tenant != tenant {
                return Err(SplitReplaceError::TenantMismatch {
                    expected: tenant,
                    actual: parent.tenant,
                });
            }

            let payload_hash = hash_split_replace_payload(&plan);
            if check_op_idempotency(&parent, op_id, payload_hash)?.is_some() {
                let child_ids = plan
                    .children
                    .iter()
                    .collect::<Vec<_>>();
                let mut ordered = child_ids;
                ordered.sort_by(|a, b| a.spec.key_range_start.cmp(&b.spec.key_range_start));

                let children = ordered
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        derive_split_shard_id(parent.shard, DerivedShardKind::Child, i as u32)
                    })
                    .collect::<Vec<_>>();

                return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
            }

            validate_lease(now, tenant, lease, &parent)?;

            let mut ordered = plan.children.iter().collect::<Vec<_>>();
            ordered.sort_by(|a, b| a.spec.key_range_start.cmp(&b.spec.key_range_start));
            let child_specs = ordered.iter().map(|c| c.spec.clone()).collect::<Vec<_>>();
            validate_split_coverage(&parent.spec, &child_specs)
                .map_err(SplitReplaceError::SplitInvalid)?;

            let mut children_to_insert: Vec<((TenantId, ShardKey), ShardRecord)> = Vec::new();
            let mut child_ids: Vec<ShardId> = Vec::with_capacity(ordered.len());

            for (i, child) in ordered.iter().enumerate() {
                let child_id = derive_split_shard_id(parent.shard, DerivedShardKind::Child, i as u32);
                let child_key = ShardKey {
                    run: parent.run,
                    shard: child_id,
                };
                if self.shards.contains_key(&(tenant, child_key)) {
                    // This should be impossible in the spec's atomic model.
                    panic!("derived child shard id collision: {child_key:?}");
                }

                let record = ShardRecord {
                    tenant: parent.tenant,
                    run: parent.run,
                    shard: child_id,
                    status: ShardStatus::Active,
                    park_reason: None,
                    spec: child.spec.clone(),
                    cursor: child.cursor.clone(),
                    cursor_semantics: parent.cursor_semantics,
                    lease_owner: None,
                    lease_deadline: None,
                    fence_epoch: FenceEpoch::INITIAL,
                    parent: Some(parent.shard),
                    spawned: Vec::new(),
                    op_log: Vec::new(),
                };

                children_to_insert.push(((tenant, child_key), record));
                child_ids.push(child_id);
            }

            // Mutate the parent last.
            parent.status = ShardStatus::Split;
            parent.spawned.extend(child_ids.iter().copied());
            parent.lease_owner = None;
            parent.lease_deadline = None;
            parent.op_log_push(OpLogEntry {
                op_id,
                kind: OpKind::SplitReplace,
                result: OpResult::Completed,
                payload_hash,
                executed_at: now,
            });
            parent.assert_invariants();

            // Commit: insert children and reinsert parent.
            for (k, v) in children_to_insert {
                self.index_shard(k.0, k.1.run, k.1.shard);
                self.shards.insert(k, v);
            }

            Ok(IdempotentOutcome::Executed(SplitReplaceResult { children: child_ids }))
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
        let key = ShardKey {
            run: lease.run,
            shard: lease.shard,
        };
        let map_key = (tenant, key);

        let mut parent = self
            .shards
            .remove(&map_key)
            .ok_or(SplitResidualError::ShardNotFound { shard: key })?;

        let result = (|| {
            if parent.tenant != tenant {
                return Err(SplitResidualError::TenantMismatch {
                    expected: tenant,
                    actual: parent.tenant,
                });
            }

            let payload_hash = hash_split_residual_payload(&plan);
            if check_op_idempotency(&parent, op_id, payload_hash)?.is_some() {
                let residual =
                    derive_split_shard_id(parent.shard, DerivedShardKind::Residual, 0);
                return Ok(IdempotentOutcome::Replayed(SplitResidualResult { residual }));
            }

            validate_lease(now, tenant, lease, &parent)?;

            validate_residual_split(&parent.spec, &plan.parent_new_spec, &plan.residual_spec)
                .map_err(SplitResidualError::SplitInvalid)?;

            // Safety: shrinking the parent must not strand its existing cursor.
            if let Some(k) = parent.cursor.last_key.as_deref() {
                if !plan.parent_new_spec.contains_key(k) {
                    return Err(SplitResidualError::SplitInvalid(
                        SplitValidationError::ParentCursorOutOfBounds {
                            cursor: k.to_vec().into_boxed_slice(),
                            new_parent_start: plan.parent_new_spec.key_range_start.clone(),
                            new_parent_end: plan.parent_new_spec.key_range_end.clone(),
                        },
                    ));
                }
            }

            let residual_id = derive_split_shard_id(parent.shard, DerivedShardKind::Residual, 0);
            let residual_key = ShardKey {
                run: parent.run,
                shard: residual_id,
            };

            if self.shards.contains_key(&(tenant, residual_key)) {
                panic!("derived residual shard id collision: {residual_key:?}");
            }

            let residual = ShardRecord {
                tenant: parent.tenant,
                run: parent.run,
                shard: residual_id,
                status: ShardStatus::Active,
                park_reason: None,
                spec: plan.residual_spec.clone(),
                cursor: Cursor::initial(),
                cursor_semantics: parent.cursor_semantics,
                lease_owner: None,
                lease_deadline: None,
                fence_epoch: FenceEpoch::INITIAL,
                parent: Some(parent.shard),
                spawned: Vec::new(),
                op_log: Vec::new(),
            };

            // Shrink parent; it keeps its lease.
            parent.spec = plan.parent_new_spec;
            parent.spawned.push(residual_id);
            parent.op_log_push(OpLogEntry {
                op_id,
                kind: OpKind::SplitResidual,
                result: OpResult::Completed,
                payload_hash,
                executed_at: now,
            });
            parent.assert_invariants();

            self.index_shard(tenant, parent.run, residual_id);
            self.shards.insert((tenant, residual_key), residual);

            Ok(IdempotentOutcome::Executed(SplitResidualResult {
                residual: residual_id,
            }))
        })();

        self.shards.insert(map_key, parent);
        result
    }
}

// ============================================================================
// Run-level management (RunManagement)
// ============================================================================

impl RunManagement for InMemoryCoordinator {
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        config.assert_valid().map_err(CreateRunError::InvalidConfig)?;

        let key = (tenant, run);
        if self.runs.contains_key(&key) {
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
            op_log: Vec::new(),
        };
        record.assert_invariants();

        self.runs.insert(key, record.clone());
        self.run_shards.entry((tenant, run)).or_default();
        Ok(record)
    }

    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: Vec<InitialShard>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        let run_key = (tenant, run);
        let record = self
            .runs
            .get_mut(&run_key)
            .ok_or(RegisterShardsError::RunNotFound { run })?;

        if record.tenant != tenant {
            return Err(RegisterShardsError::TenantMismatch {
                expected: tenant,
                actual: record.tenant,
            });
        }

        // Idempotency first: if this already succeeded, replay should work even
        // after status changed to Active.
        let payload_hash = crate::coordination::run::hash_register_shards_payload(&shards);
        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            match &entry.result {
                crate::coordination::run::RunOpResult::RegisteredShards { shard_ids } => {
                    return Ok(IdempotentOutcome::Replayed(shard_ids.clone()));
                }
                _ => {
                    // A logic bug: op_id matched but kind/result mismatch.
                    panic!("replayed register_shards but cached result was not RegisteredShards");
                }
            }
        }

        if record.status != RunStatus::Initializing {
            return Err(RegisterShardsError::WrongStatus {
                expected: RunStatus::Initializing,
                actual: record.status,
            });
        }

        validate_manifest(&shards).map_err(RegisterShardsError::ManifestInvalid)?;

        // Canonicalize shard order for deterministic results and idempotency.
        let mut ordered = shards;
        ordered.sort_by_key(|s| s.shard_id.0);

        let shard_ids = ordered.iter().map(|s| s.shard_id).collect::<Vec<_>>();

        // Create shard records.
        for s in &ordered {
            let shard_key = ShardKey { run, shard: s.shard_id };
            let map_key = (tenant, shard_key);
            if self.shards.contains_key(&map_key) {
                panic!("register_shards attempted to overwrite existing shard: {shard_key:?}");
            }

            let shard_record = ShardRecord {
                tenant,
                run,
                shard: s.shard_id,
                status: ShardStatus::Active,
                park_reason: None,
                spec: s.spec.clone(),
                cursor: s.cursor.clone(),
                cursor_semantics: record.config.cursor_semantics,
                lease_owner: None,
                lease_deadline: None,
                fence_epoch: FenceEpoch::INITIAL,
                parent: None,
                spawned: Vec::new(),
                op_log: Vec::new(),
            };
            shard_record.assert_invariants();

            self.shards.insert(map_key, shard_record);
            self.index_shard(tenant, run, s.shard_id);
        }

        record.root_shards = shard_ids.clone();
        record.status = RunStatus::Active;
        record.op_log_push(crate::coordination::run::RunOpLogEntry {
            op_id,
            kind: crate::coordination::run::RunOpKind::RegisterShards,
            payload_hash,
            result: crate::coordination::run::RunOpResult::RegisteredShards {
                shard_ids: shard_ids.clone(),
            },
        });

        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(shard_ids))
    }

    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError> {
        let run_key = (tenant, run);
        let record = self
            .runs
            .get_mut(&run_key)
            .ok_or(CompleteRunError::RunNotFound { run })?;

        if record.tenant != tenant {
            return Err(CompleteRunError::TenantMismatch {
                expected: tenant,
                actual: record.tenant,
            });
        }

        let payload_hash = crate::coordination::run::hash_complete_run_payload();
        if record
            .check_op_idempotency(op_id, payload_hash)?
            .is_some()
        {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status.is_terminal() {
            return Err(CompleteRunError::RunTerminal {
                run,
                status: record.status,
            });
        }
        if record.status != RunStatus::Active {
            return Err(CompleteRunError::WrongStatus {
                expected: RunStatus::Active,
                actual: record.status,
            });
        }

        record.status = RunStatus::Done;
        record.completed_at = Some(now);
        record.op_log_push(crate::coordination::run::RunOpLogEntry {
            op_id,
            kind: crate::coordination::run::RunOpKind::CompleteRun,
            payload_hash,
            result: crate::coordination::run::RunOpResult::Ack,
        });
        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(()))
    }

    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteRunError> {
        let run_key = (tenant, run);
        let record = self
            .runs
            .get_mut(&run_key)
            .ok_or(CompleteRunError::RunNotFound { run })?;

        if record.tenant != tenant {
            return Err(CompleteRunError::TenantMismatch {
                expected: tenant,
                actual: record.tenant,
            });
        }

        let payload_hash = crate::coordination::run::hash_fail_run_payload();
        if record
            .check_op_idempotency(op_id, payload_hash)?
            .is_some()
        {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status.is_terminal() {
            return Err(CompleteRunError::RunTerminal {
                run,
                status: record.status,
            });
        }
        if record.status != RunStatus::Active {
            return Err(CompleteRunError::WrongStatus {
                expected: RunStatus::Active,
                actual: record.status,
            });
        }

        record.status = RunStatus::Failed;
        record.completed_at = Some(now);
        record.op_log_push(crate::coordination::run::RunOpLogEntry {
            op_id,
            kind: crate::coordination::run::RunOpKind::FailRun,
            payload_hash,
            result: crate::coordination::run::RunOpResult::Ack,
        });
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
        let run_key = (tenant, run);
        let record = self
            .runs
            .get_mut(&run_key)
            .ok_or(CancelRunError::RunNotFound { run })?;

        if record.tenant != tenant {
            return Err(CancelRunError::TenantMismatch {
                expected: tenant,
                actual: record.tenant,
            });
        }

        let payload_hash = crate::coordination::run::hash_cancel_run_payload();
        if record
            .check_op_idempotency(op_id, payload_hash)?
            .is_some()
        {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status.is_terminal() {
            return Err(CancelRunError::RunTerminal {
                run,
                status: record.status,
            });
        }

        // Cancel is allowed from Initializing or Active.
        match record.status {
            RunStatus::Initializing | RunStatus::Active => {}
            other => {
                return Err(CancelRunError::WrongStatus {
                    expected: RunStatus::Active,
                    actual: other,
                });
            }
        }

        record.status = RunStatus::Failed;
        record.completed_at = Some(now);
        record.op_log_push(crate::coordination::run::RunOpLogEntry {
            op_id,
            kind: crate::coordination::run::RunOpKind::CancelRun,
            payload_hash,
            result: crate::coordination::run::RunOpResult::Ack,
        });
        record.assert_invariants();

        Ok(IdempotentOutcome::Executed(()))
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        let record = self
            .runs
            .get(&(tenant, run))
            .ok_or(GetRunError::RunNotFound { run })?;
        if record.tenant != tenant {
            return Err(GetRunError::TenantMismatch {
                expected: tenant,
                actual: record.tenant,
            });
        }
        Ok(record.clone())
    }

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        // Ensure run exists and tenant matches.
        let record = self.get_run(tenant, run)?;

        let mut progress = RunProgress::default();

        if let Some(ids) = self.run_shards.get(&(tenant, run)) {
            for shard_id in ids {
                let key = (tenant, ShardKey { run, shard: *shard_id });
                if let Some(shard_record) = self.shards.get(&key) {
                    progress.count_shard(shard_record.status, shard_record.is_leased_at(now));
                }
            }
        } else {
            // Fallback: scan the whole store (should be rare).
            for ((t, key), shard_record) in &self.shards {
                if *t == tenant && key.run == run {
                    progress.count_shard(shard_record.status, shard_record.is_leased_at(now));
                }
            }
        }

        // Keep the computed total consistent with the index, but do not attempt
        // to auto-transition run terminal status (spec: terminal evaluation is external).
        let _ = record;
        Ok(progress)
    }

    fn list_shards(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
    ) -> Result<Vec<ShardSummary>, GetRunError> {
        // Ensure run exists and tenant matches.
        let _ = self.get_run(tenant, run)?;

        let mut out: Vec<ShardSummary> = Vec::new();

        if let Some(ids) = self.run_shards.get(&(tenant, run)) {
            out.reserve(ids.len());
            for shard_id in ids {
                let key = (tenant, ShardKey { run, shard: *shard_id });
                if let Some(record) = self.shards.get(&key) {
                    let summary = ShardSummary::from_record(record, now);
                    if filter.matches(&summary) {
                        out.push(summary);
                    }
                }
            }
        } else {
            for ((t, key), record) in &self.shards {
                if *t == tenant && key.run == run {
                    let summary = ShardSummary::from_record(record, now);
                    if filter.matches(&summary) {
                        out.push(summary);
                    }
                }
            }
        }

        // Stable, deterministic ordering helps testing and claiming loops.
        out.sort_by(|a, b| a.key_range_start.cmp(&b.key_range_start));
        Ok(out)
    }

    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        let record = self
            .shards
            .get_mut(&(tenant, key))
            .ok_or(UnparkError::ShardNotFound { shard: key })?;

        if record.tenant != tenant {
            return Err(UnparkError::TenantMismatch {
                expected: tenant,
                actual: record.tenant,
            });
        }

        let payload_hash = crate::coordination::run::hash_unpark_payload(&key);
        if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status != ShardStatus::Parked {
            return Err(UnparkError::NotParked {
                shard: key,
                status: record.status,
            });
        }

        record.status = ShardStatus::Active;
        record.park_reason = None;
        record.fence_epoch = FenceEpoch(record.fence_epoch.0.saturating_add(1));
        record.lease_owner = None;
        record.lease_deadline = None;

        record.op_log_push(OpLogEntry {
            op_id,
            kind: OpKind::Unpark,
            result: OpResult::Completed,
            payload_hash,
            executed_at: now,
        });

        record.assert_invariants();
        Ok(IdempotentOutcome::Executed(()))
    }
}

// ============================================================================
// Tests (kept as stubs; conformance tests live in the harness)
// ============================================================================

#[cfg(test)]
mod tests {
    // TODO: add property tests for fencing + idempotency.
}
