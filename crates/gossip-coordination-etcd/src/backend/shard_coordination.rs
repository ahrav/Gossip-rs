//! [`CoordinationBackend`] and [`AsyncCoordinationBackend`] trait impls for
//! the etcd backend — shard coordination and lifecycle operations.
//!
//! # Warm path operations
//!
//! Latency-sensitive but each CAS retry includes an etcd network round-trip,
//! so these are WARM paths under the project allocation policy:
//!
//! - **`acquire_and_restore_into`** — take ownership by granting an etcd
//!   lease, bumping the fence epoch, and writing both the shard record and
//!   `/owner` key in a single CAS. Restores the shard's persisted spec,
//!   cursor, and spawned lineage into the caller's [`AcquireScratch`].
//! - **`renew`** — extend the logical lease deadline without changing
//!   ownership or fence epoch. Sends a keep-alive to the etcd lease
//!   best-effort after the CAS commits.
//! - **`checkpoint`** — persist a new cursor position. Validates cursor
//!   monotonicity and bounds, then CAS-updates with an op-log entry.
//!
//! # Lifecycle operations
//!
//! - **`split_replace`** — atomically replace an owned shard with N child
//!   shards. The parent becomes terminal (`Split` status), its owner key
//!   and active-index entry are deleted. Children are created as unowned
//!   `Active` shards with deterministic BLAKE3-derived IDs.
//! - **`split_residual`** — shrink an owned shard's key range and spawn
//!   a single residual shard for the removed range. The parent stays
//!   `Active` and retains its owner.
//! - **`complete`** / **`park_shard`** — not yet implemented; panic
//!   fail-closed.
//!
//! # CAS guard patterns
//!
//! All lease-gated operations (everything except `acquire`) verify:
//! 1. Shard record `mod_revision` (no concurrent mutation).
//! 2. Owner key exists with the expected (worker, fence) value.
//! 3. Owner key is attached to the expected etcd lease ID.
//!
//! `acquire` additionally handles the absent-owner case (first acquire
//! or expired TTL) by guarding key absence instead.
//!
//! # Idempotency
//!
//! `checkpoint`, `split_replace`, and `split_residual` use op-log entries
//! keyed by `OpId` + payload hash. `acquire` and `renew` rely on CAS
//! fencing instead.

use etcd_client::{Compare, PutOptions, TxnOp};
use gossip_contracts::coordination::shard_spec::SplitValidationError;
use gossip_coordination::validation::validate_cursor_update_pooled;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, AsyncCoordinationBackend, ByteSlab,
    CapacityHint, CheckpointError, CompleteError, CoordinationBackend, CursorUpdate,
    DerivedShardKind, IdempotentOutcome, InfraError, Lease, LeaseHolder, LogicalTime, OpId, OpKind,
    OpLogEntry, OpResult, ParkError, ParkReason, RenewError, RenewResult, ShardKey, ShardRecord,
    ShardStatus, SplitChildIds, SplitReplaceError, SplitReplacePlan, SplitReplaceResult,
    SplitResidualError, SplitResidualPlan, SplitResidualResult, TenantId, WorkerId,
    check_op_idempotency, derive_split_shard_id, hash_checkpoint_payload,
    hash_split_replace_payload, hash_split_residual_payload, shard_limit_violation,
    split_replace_apply_parent, split_replace_validate_preconditions, split_residual_apply_parent,
    split_residual_build_record, split_residual_check_replay,
    split_residual_validate_preconditions,
};

use crate::codec::{encode_owner_value_into, encode_shard_record, encode_shard_record_into};

use super::coordinator::{AsyncEtcdCoordinator, EtcdCoordinator};
use super::{
    CasOutcome, PersistedShard, TxnBuilder, build_shard_owner_cas, cas_retry_delay,
    split_replace_replay_child_ids, validate_loaded_shard_lease,
};

/// Project a persisted shard record into the caller's [`AcquireScratch`]
/// buffer and build the [`AcquireResultView`].
///
/// Copies the shard's spec (key range, metadata), cursor (last key, token),
/// and spawned lineage from the slab-backed record into the flat scratch
/// buffer. The resulting view borrows from `out` and is returned to the
/// caller alongside the freshly minted lease and capacity hint.
///
/// Shared by both sync and async `acquire_and_restore_into` to keep the
/// snapshot projection logic in a single place.
fn build_acquire_result<'a>(
    out: &'a mut AcquireScratch,
    persisted: &PersistedShard,
    lease: Lease,
    capacity: CapacityHint,
) -> AcquireResultView<'a> {
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
    AcquireResultView {
        lease,
        snapshot,
        capacity,
    }
}

impl CoordinationBackend for EtcdCoordinator {
    /// Atomically take ownership of a shard, restoring its persisted state
    /// into `out`.
    ///
    /// Grants a new etcd lease, bumps the fence epoch, and commits both the
    /// updated shard record and a new `/owner` key in a single CAS
    /// transaction. On CAS failure (concurrent writer), retries with
    /// exponential backoff up to `optimistic_txn_retries`.
    ///
    /// The previous owner's etcd lease (if any) is revoked best-effort after
    /// a successful CAS. If the revocation fails, the old lease expires via
    /// etcd's TTL mechanism.
    ///
    /// # Errors
    ///
    /// - [`AcquireError::ShardNotFound`] — shard key does not exist in etcd.
    /// - [`AcquireError::ShardTerminal`] — shard is in a terminal status.
    /// - [`AcquireError::AlreadyLeased`] — another owner's lease is still
    ///   live at `now`.
    /// - [`AcquireError::TenantMismatch`] — persisted tenant differs from
    ///   the requested tenant.
    /// - [`AcquireError::BackendError`] — etcd RPC failure, local encode
    ///   error, or corruption detected by internal validation (e.g., codec
    ///   or keyspace invariant violation).
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);

        // The closure returns intermediate owned data to avoid lifetime
        // conflicts between the closure's capture of `out` and the
        // returned `AcquireResultView` which borrows from `out`.
        let (persisted, lease, capacity) = self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(AcquireError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(AcquireError::BackendError(super::map_etcd_err(
                            "acquire.load_shard",
                            err,
                        )));
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

                let run_record = this.load_run_or_panic(tenant, key.run());
                let lease_duration = run_record.record.config.lease_duration();
                let new_deadline = now
                    .checked_add(lease_duration)
                    .unwrap_or(LogicalTime::from_raw(u64::MAX));
                let grant = match this.etcd_lease_grant(this.config.owner_lease_ttl_secs()) {
                    Ok(g) => g,
                    Err(err) => {
                        return Err(AcquireError::BackendError(super::map_etcd_err(
                            "acquire.lease_grant",
                            err,
                        )));
                    }
                };
                let new_lease_id = grant.id();
                let prior_lease_id = persisted.owner.as_ref().map(|owner| owner.lease_id);

                let mut persisted = persisted;
                let new_fence = persisted.record.advance_fence();
                persisted.record.lease = Some(LeaseHolder::new(worker, new_deadline));
                persisted.record.assert_invariants(&persisted.slab);
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| {
                        this.best_effort_revoke_lease(new_lease_id);
                        AcquireError::BackendError(InfraError::corruption(
                            "acquire.encode_shard",
                            err,
                        ))
                    })?;
                encode_owner_value_into(worker, new_fence, &mut owner_buf);

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = vec![super::compare_shard_revision(
                    shard_record_key.clone(),
                    persisted.mod_revision,
                )];
                if let Some(expected_owner) = persisted.expected_owner_value() {
                    let prior_etcd_lease = prior_lease_id
                        .expect("owner value present implies owner lease_id is known");
                    compares.extend(super::compare_owner_present(
                        owner_key.clone(),
                        expected_owner,
                        prior_etcd_lease,
                    ));
                } else {
                    compares.push(super::compare_absent(owner_key.clone()));
                }

                let mut txn = TxnBuilder::from_compares(compares);
                txn.put(shard_record_key.into_bytes(), shard_buf.clone())
                    .put_with_options(
                        owner_key.into_bytes(),
                        owner_buf.clone(),
                        PutOptions::new().with_lease(new_lease_id),
                    );
                let outcome = txn.execute(this, ()).map_err(|err| {
                    this.best_effort_revoke_lease(new_lease_id);
                    AcquireError::BackendError(super::map_etcd_err("acquire.txn", err))
                })?;
                if matches!(outcome, CasOutcome::RetryNeeded) {
                    this.best_effort_revoke_lease(new_lease_id);
                    return Ok(CasOutcome::RetryNeeded);
                }

                if let Some(old_lease_id) = prior_lease_id {
                    this.best_effort_revoke_lease(old_lease_id);
                }
                let capacity = this
                    .count_available_lightweight(tenant, key.run())
                    .unwrap_or_else(|err| {
                        tracing::warn!(%err, "capacity hint unavailable; defaulting to zero");
                        CapacityHint::ZERO
                    });
                let lease = Lease::new(
                    tenant,
                    key.run(),
                    key.shard(),
                    worker,
                    new_fence,
                    new_deadline,
                );

                Ok(CasOutcome::Committed((persisted, lease, capacity)))
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
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

                super::fatal_storage_error(
                    "acquire.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )?;

        Ok(build_acquire_result(out, &persisted, lease, capacity))
    }

    /// Extend a shard's logical lease deadline without changing ownership.
    ///
    /// Validates the presented lease (worker, fence epoch, deadline), then
    /// CAS-updates the shard record with a new deadline computed from the
    /// run's `lease_duration`. The etcd lease TTL is extended best-effort
    /// via `keep_alive` after the CAS succeeds.
    ///
    /// Unlike `acquire_and_restore_into`, renew does **not** bump the fence
    /// epoch or grant a new etcd lease — it reuses the existing owner binding.
    ///
    /// # Errors
    ///
    /// - [`RenewError::StaleFence`] — the persisted owner binding does not
    ///   match the presented lease's worker/fence.
    /// - [`RenewError::ShardNotFound`] — shard does not exist in etcd.
    /// - [`RenewError::BackendError`] — etcd RPC failure, local encode
    ///   error, or corruption detected by internal validation.
    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = lease.shard_key();
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);

        self.cas_retry(
            |this, _attempt| {
                let persisted = this.load_shard_and_validate_lease(
                    now,
                    tenant,
                    lease,
                    |shard| RenewError::ShardNotFound { shard },
                    |err| RenewError::BackendError(super::map_etcd_err("renew.load_shard", err)),
                    |presented, current| RenewError::StaleFence { presented, current },
                )?;

                let run_record = this.load_run_or_panic(tenant, key.run());
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
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| {
                        RenewError::BackendError(InfraError::corruption("renew.encode_shard", err))
                    })?;
                let owner = persisted
                    .owner
                    .as_ref()
                    .expect("validated owner must have binding");
                encode_owner_value_into(owner.binding.worker, owner.binding.fence, &mut owner_buf);

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let compares = build_shard_owner_cas(
                    shard_record_key.clone(),
                    owner_key,
                    &persisted,
                    owner_buf.clone(),
                );

                let mut txn = TxnBuilder::from_compares(compares);
                txn.put(shard_record_key.into_bytes(), shard_buf.clone());
                let outcome = txn.execute(this, ()).map_err(|err| {
                    RenewError::BackendError(super::map_etcd_err("renew.txn", err))
                })?;
                if matches!(outcome, CasOutcome::RetryNeeded) {
                    return Ok(CasOutcome::RetryNeeded);
                }

                // Best-effort: extend the etcd lease TTL after the CAS
                // succeeds. If the keep-alive fails, the CAS already
                // committed the new deadline to the shard record.
                if let Err(err) = this.etcd_lease_keep_alive_once(old_lease_id) {
                    tracing::warn!(
                        lease_id = old_lease_id,
                        %err,
                        "renew: failed to extend etcd lease TTL; \
                         logical deadline was committed but etcd lease may expire early",
                    );
                }
                let capacity = this
                    .count_available_lightweight(tenant, key.run())
                    .unwrap_or_else(|err| {
                        tracing::warn!(%err, "capacity hint unavailable; defaulting to zero");
                        CapacityHint::ZERO
                    });
                Ok(CasOutcome::Committed(RenewResult {
                    new_deadline,
                    capacity,
                }))
            },
            |this| {
                let _persisted = this.load_shard_and_validate_lease(
                    now,
                    tenant,
                    lease,
                    |shard| RenewError::ShardNotFound { shard },
                    |err| {
                        RenewError::BackendError(super::map_etcd_err(
                            "renew.exhaust.load_shard",
                            err,
                        ))
                    },
                    |presented, current| RenewError::StaleFence { presented, current },
                )?;

                super::fatal_storage_error(
                    "renew.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }

    /// Persist a new cursor position for an owned shard.
    ///
    /// Validates the lease, checks cursor monotonicity and bounds, then
    /// CAS-updates the shard record with the new cursor and an op-log
    /// entry. The owner key and its etcd lease are included as CAS
    /// preconditions but are not modified.
    ///
    /// Idempotent: replays with the same `op_id` and matching payload hash
    /// return [`IdempotentOutcome::Replayed`] without re-applying the
    /// cursor update.
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
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(CheckpointError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(CheckpointError::BackendError(super::map_etcd_err(
                            "checkpoint.load_shard",
                            err,
                        )));
                    }
                };

                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                }
                validate_loaded_shard_lease(
                    now,
                    tenant,
                    lease,
                    &persisted,
                    |presented, current| CheckpointError::StaleFence { presented, current },
                )?;
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
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| {
                        CheckpointError::BackendError(InfraError::corruption(
                            "checkpoint.encode_shard",
                            err,
                        ))
                    })?;
                let owner = persisted
                    .owner
                    .as_ref()
                    .expect("validated owner must have binding");
                encode_owner_value_into(owner.binding.worker, owner.binding.fence, &mut owner_buf);

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let compares = build_shard_owner_cas(
                    shard_record_key.clone(),
                    owner_key,
                    &persisted,
                    owner_buf.clone(),
                );

                let mut txn = TxnBuilder::from_compares(compares);
                txn.put(shard_record_key.into_bytes(), shard_buf.clone());
                txn.execute(this, IdempotentOutcome::Executed(()))
                    .map_err(|err| {
                        CheckpointError::BackendError(super::map_etcd_err("checkpoint.txn", err))
                    })
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(IdempotentOutcome::Replayed(()));
                }
                validate_loaded_shard_lease(
                    now,
                    tenant,
                    lease,
                    &persisted,
                    |presented, current| CheckpointError::StaleFence { presented, current },
                )?;

                super::fatal_storage_error(
                    "checkpoint.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }

    /// Mark a shard as completed with a final cursor position.
    ///
    /// **Not yet implemented** — panics unconditionally. Remains fail-closed
    /// until the etcd transaction semantics for shard completion are defined.
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

    /// Park a shard (temporarily suspend processing) for the given reason.
    ///
    /// **Not yet implemented** — panics unconditionally. Remains fail-closed
    /// until the etcd transaction semantics for shard parking are defined.
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

    /// Replace an owned shard with N child shards in a single atomic
    /// transaction.
    ///
    /// The parent transitions to `ShardStatus::Split` (terminal), its owner
    /// key and active-index entry are deleted, and each child is created as
    /// an unowned `Active` shard with its own active-index entry. The child
    /// IDs are deterministically derived from the parent identity, op_id,
    /// and spawned index via BLAKE3.
    ///
    /// The CAS transaction guards:
    /// - Parent shard record `mod_revision` (no concurrent mutation).
    /// - Owner key presence, value, and etcd lease ID (ownership proof).
    /// - Each child key absent (prevents double-creation and collision).
    ///
    /// On replay with the same `op_id`, recovers child IDs from the
    /// parent's permanent `spawned` lineage list.
    ///
    /// If CAS retries exhaust and all preconditions still hold, probes
    /// each derived child key for an existing record and returns
    /// `DerivedIdCollision` if found.
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

        // Pre-allocate Vecs outside the retry loop; cleared per iteration.
        let cap = self.config.max_children_per_op();
        let mut child_puts: Vec<TxnOp> = Vec::with_capacity(cap);
        let mut child_index_ops: Vec<TxnOp> = Vec::with_capacity(cap);
        let mut child_absent_compares: Vec<Compare> = Vec::with_capacity(cap);

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(SplitReplaceError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(SplitReplaceError::BackendError(super::map_etcd_err(
                            "split_replace.load_shard",
                            err,
                        )));
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
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(
                        SplitReplaceResult { children },
                    )));
                }
                if persisted.record.status != ShardStatus::Active {
                    return Err(SplitReplaceError::ShardTerminal {
                        shard: key,
                        status: persisted.record.status,
                    });
                }
                validate_loaded_shard_lease(
                    now,
                    tenant,
                    lease,
                    &persisted,
                    |presented, current| SplitReplaceError::StaleFence { presented, current },
                )?;

                // Backend-specific fanout cap: reject before shared validation.
                let child_count = plan.children().len();
                if child_count > this.config.max_children_per_op() {
                    return Err(SplitReplaceError::SplitInvalid(
                        SplitValidationError::BackendChildLimitExceeded {
                            requested: child_count,
                            backend_max: this.config.max_children_per_op(),
                        },
                    ));
                }

                let sorted = split_replace_validate_preconditions(
                    &persisted.record,
                    &plan,
                    &persisted.slab,
                )?;
                let counts = this.current_shard_counts(tenant).map_err(|err| {
                    SplitReplaceError::BackendError(super::map_etcd_err(
                        "split_replace.count_shards",
                        err,
                    ))
                })?;
                // The persisted count includes the parent shard (still in etcd).
                // After split the parent becomes terminal (Split status) and
                // stays in storage while N children are created, so the total
                // stored record count grows by N. Use N (child count) as
                // `additional`, matching the in-memory backend's accounting.
                if let Some(limit) = shard_limit_violation(
                    counts,
                    sorted.len(),
                    this.config.max_shards_per_tenant(),
                    this.config.max_total_shards(),
                ) {
                    return Err(SplitReplaceError::SplitInvalid(
                        SplitValidationError::ShardLimitExceeded {
                            current: limit.current,
                            additional: limit.additional,
                            max: limit.max,
                            scope: limit.scope,
                        },
                    ));
                }

                let mut child_ids = SplitChildIds::new();
                child_puts.clear();
                child_index_ops.clear();
                child_absent_compares.clear();

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
                    let mut child_slab =
                        ByteSlab::with_capacity(super::build_slab_capacity_for_spec_and_cursor(
                            child.spec(),
                            child.cursor(),
                        ));
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
                        this.keyspace
                            .shard_record_key(tenant, persisted.record.run, child_id);
                    child_absent_compares.push(super::compare_absent(child_record_key.clone()));
                    child_puts.push(TxnOp::put(
                        child_record_key.into_bytes(),
                        encode_shard_record(&child_record, &child_slab).unwrap_or_else(|err| {
                            super::fatal_storage_error("split_replace.encode_child", err)
                        }),
                        None,
                    ));
                    child_index_ops.push(TxnOp::put(
                        this.keyspace
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
                    .unwrap_or_else(|err| {
                        super::fatal_storage_error("split_replace.encode_parent", err)
                    });
                let owner_blob = persisted
                    .expected_owner_value()
                    .expect("validated owner must produce an owner value");

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = build_shard_owner_cas(
                    shard_record_key.clone(),
                    owner_key.clone(),
                    &persisted,
                    owner_blob,
                );
                compares.append(&mut child_absent_compares);

                // Atomically: update parent to Split status, delete its owner
                // and active-index keys, then create all child records and their
                // active-index entries.
                this.inject_split_replace_fault_if_armed(tenant, key);

                let mut txn = TxnBuilder::from_compares(compares);
                txn.put(shard_record_key.into_bytes(), parent_blob)
                    .delete(owner_key.into_bytes())
                    .delete(
                        this.keyspace
                            .shard_active_index_key(tenant, key.run(), key.shard())
                            .into_bytes(),
                    )
                    .ops(child_puts.drain(..))
                    .ops(child_index_ops.drain(..));

                txn.execute(
                    this,
                    IdempotentOutcome::Executed(SplitReplaceResult {
                        children: child_ids,
                    }),
                )
                .map_err(|err| {
                    SplitReplaceError::BackendError(super::map_etcd_err("split_replace.txn", err))
                })
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
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
                validate_loaded_shard_lease(
                    now,
                    tenant,
                    lease,
                    &persisted,
                    |presented, current| SplitReplaceError::StaleFence { presented, current },
                )?;

                // All standard preconditions still hold, yet the CAS failed
                // every attempt. The most likely non-transient cause is a
                // derived child key that already exists (hash collision). Probe
                // each derived child key and surface DerivedIdCollision if found.
                let sorted = split_replace_validate_preconditions(
                    &persisted.record,
                    &plan,
                    &persisted.slab,
                )?;
                for sorted_index in 0..sorted.len() {
                    let child_id = derive_split_shard_id(
                        persisted.record.run,
                        persisted.record.shard,
                        op_id,
                        DerivedShardKind::Child,
                        u32::try_from(persisted.record.spawned.len() + sorted_index)
                            .expect("child index exceeds u32"),
                    );
                    let child_key = ShardKey::new(persisted.record.run, child_id);
                    match this.load_shard_record(tenant, child_key) {
                        Ok(Some(_)) => {
                            return Err(SplitReplaceError::SplitInvalid(
                                SplitValidationError::DerivedIdCollision {
                                    derived_id: child_id,
                                },
                            ));
                        }
                        Ok(None) => {}
                        Err(err) => {
                            return Err(SplitReplaceError::BackendError(super::map_etcd_err(
                                "split_replace.collision_probe",
                                err,
                            )));
                        }
                    }
                }

                super::fatal_storage_error(
                    "split_replace.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }

    /// Shrink an owned shard's key range and spawn a residual shard
    /// covering the removed range.
    ///
    /// Unlike `split_replace`, the parent remains `Active` and retains its
    /// owner binding. Only the parent's spec (key range) is narrowed and
    /// a single new residual shard is created. The residual starts unowned
    /// with an empty cursor.
    ///
    /// The CAS transaction guards:
    /// - Parent shard record `mod_revision`.
    /// - Owner key presence, value, and etcd lease ID.
    /// - Residual key absent (prevents double-creation).
    ///
    /// On replay, the residual ID is recovered from the parent's `spawned`
    /// lineage list (permanent, not bounded by the op-log). This means
    /// replays succeed even after the op-log entry has been evicted by
    /// subsequent operations.
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

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(SplitResidualError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(SplitResidualError::BackendError(super::map_etcd_err(
                            "split_residual.load_shard",
                            err,
                        )));
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
                    return Ok(CasOutcome::Committed(replay));
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
                let counts = this.current_shard_counts(tenant).map_err(|err| {
                    SplitResidualError::BackendError(super::map_etcd_err(
                        "split_residual.count_shards",
                        err,
                    ))
                })?;
                // The parent stays Active (not terminal), so the persisted count
                // already includes it. Only the new residual shard is net growth.
                if let Some(limit) = shard_limit_violation(
                    counts,
                    1,
                    this.config.max_shards_per_tenant(),
                    this.config.max_total_shards(),
                ) {
                    return Err(SplitResidualError::SplitInvalid(
                        SplitValidationError::ShardLimitExceeded {
                            current: limit.current,
                            additional: limit.additional,
                            max: limit.max,
                            scope: limit.scope,
                        },
                    ));
                }
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
                    u32::try_from(persisted.record.spawned.len())
                        .expect("spawned index exceeds u32"),
                );
                let mut residual_slab =
                    ByteSlab::with_capacity(super::build_slab_capacity_for_spec_and_cursor(
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
                    this.keyspace
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
                        super::fatal_storage_error("split_residual.encode_parent", err)
                    });
                let owner_blob = persisted
                    .expected_owner_value()
                    .expect("validated owner must produce an owner value");

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = build_shard_owner_cas(
                    shard_record_key.clone(),
                    owner_key,
                    &persisted,
                    owner_blob,
                );
                compares.push(super::compare_absent(residual_record_key.clone()));

                this.inject_split_residual_fault_if_armed(tenant, key);

                let mut txn = TxnBuilder::from_compares(compares);
                txn.put(shard_record_key.into_bytes(), parent_blob)
                    .put(
                        residual_record_key.into_bytes(),
                        encode_shard_record(&residual_record, &residual_slab).unwrap_or_else(
                            |err| super::fatal_storage_error("split_residual.encode_residual", err),
                        ),
                    )
                    .put(
                        this.keyspace
                            .shard_active_index_key(tenant, persisted.record.run, residual_id)
                            .into_bytes(),
                        Vec::new(),
                    );

                txn.execute(
                    this,
                    IdempotentOutcome::Executed(SplitResidualResult {
                        residual: residual_id,
                    }),
                )
                .map_err(|err| {
                    SplitResidualError::BackendError(super::map_etcd_err("split_residual.txn", err))
                })
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
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
                validate_loaded_shard_lease(
                    now,
                    tenant,
                    lease,
                    &persisted,
                    |presented, current| SplitResidualError::StaleFence { presented, current },
                )?;

                // All standard preconditions still hold, yet the CAS failed
                // every attempt. Check if the derived residual key already
                // exists (hash collision) and surface DerivedIdCollision if so.
                let residual_id = derive_split_shard_id(
                    persisted.record.run,
                    persisted.record.shard,
                    op_id,
                    DerivedShardKind::Residual,
                    u32::try_from(persisted.record.spawned.len())
                        .expect("spawned index exceeds u32"),
                );
                let residual_key = ShardKey::new(persisted.record.run, residual_id);
                match this.load_shard_record(tenant, residual_key) {
                    Ok(Some(_)) => {
                        return Err(SplitResidualError::SplitInvalid(
                            SplitValidationError::DerivedIdCollision {
                                derived_id: residual_id,
                            },
                        ));
                    }
                    Ok(None) => {}
                    Err(err) => {
                        return Err(SplitResidualError::BackendError(super::map_etcd_err(
                            "split_residual.collision_probe",
                            err,
                        )));
                    }
                }

                super::fatal_storage_error(
                    "split_residual.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }
}

impl AsyncCoordinationBackend for AsyncEtcdCoordinator {
    async fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        let (persisted, lease, capacity) = self
            .cas_retry(
                |this, _attempt| {
                    Box::pin(async move {
                        // Buffers are allocated per-retry because `Box::pin(async move {...})`
                        // requires ownership — buffer reuse across retries would need wrapper
                        // types. CAS retries are rare (0-2 under contention) and these are
                        // small (2 KB + 32 B), dwarfed by etcd round-trip cost.
                        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
                        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);
                        let persisted = match this.load_shard_record(tenant, key).await {
                            Ok(Some(s)) => s,
                            Ok(None) => return Err(AcquireError::ShardNotFound { shard: key }),
                            Err(e) => {
                                return Err(AcquireError::BackendError(super::map_etcd_err(
                                    "acquire.load_shard",
                                    e,
                                )));
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
                                current_owner: persisted.record.lease_owner().expect("live owner"),
                                lease_deadline: persisted
                                    .record
                                    .lease_deadline()
                                    .expect("live deadline"),
                            });
                        }
                        let run_record = this.load_run_or_panic(tenant, key.run()).await;
                        let lease_duration = run_record.record.config.lease_duration();
                        let new_deadline = now
                            .checked_add(lease_duration)
                            .unwrap_or(LogicalTime::from_raw(u64::MAX));
                        let grant = match this
                            .etcd_lease_grant(this.config.owner_lease_ttl_secs())
                            .await
                        {
                            Ok(g) => g,
                            Err(e) => {
                                return Err(AcquireError::BackendError(super::map_etcd_err(
                                    "acquire.lease_grant",
                                    e,
                                )));
                            }
                        };
                        let new_lease_id = grant.id();
                        let prior_lease_id = persisted.owner.as_ref().map(|o| o.lease_id);
                        let mut persisted = persisted;
                        let new_fence = persisted.record.advance_fence();
                        persisted.record.lease = Some(LeaseHolder::new(worker, new_deadline));
                        persisted.record.assert_invariants(&persisted.slab);
                        if let Err(e) = encode_shard_record_into(
                            &persisted.record,
                            &persisted.slab,
                            &mut shard_buf,
                        ) {
                            this.best_effort_revoke_lease(new_lease_id).await;
                            return Err(AcquireError::BackendError(InfraError::corruption(
                                "acquire.encode_shard",
                                e,
                            )));
                        }
                        encode_owner_value_into(worker, new_fence, &mut owner_buf);
                        let srk = this
                            .keyspace
                            .shard_record_key(tenant, key.run(), key.shard());
                        let ok = this
                            .keyspace
                            .shard_owner_key(tenant, key.run(), key.shard());
                        let mut compares = vec![super::compare_shard_revision(
                            srk.clone(),
                            persisted.mod_revision,
                        )];
                        if let Some(ev) = persisted.expected_owner_value() {
                            let pl = prior_lease_id.expect("owner value implies lease_id");
                            compares.extend(super::compare_owner_present(ok.clone(), ev, pl));
                        } else {
                            compares.push(super::compare_absent(ok.clone()));
                        }
                        let mut txn = TxnBuilder::from_compares(compares);
                        txn.put(srk.into_bytes(), shard_buf).put_with_options(
                            ok.into_bytes(),
                            owner_buf,
                            PutOptions::new().with_lease(new_lease_id),
                        );
                        let outcome = match txn.execute_async(this, ()).await {
                            Ok(outcome) => outcome,
                            Err(err) => {
                                this.best_effort_revoke_lease(new_lease_id).await;
                                return Err(AcquireError::BackendError(super::map_etcd_err(
                                    "acquire.txn",
                                    err,
                                )));
                            }
                        };
                        if matches!(outcome, CasOutcome::RetryNeeded) {
                            this.best_effort_revoke_lease(new_lease_id).await;
                            return Ok(CasOutcome::RetryNeeded);
                        }
                        if let Some(old) = prior_lease_id {
                            this.best_effort_revoke_lease(old).await;
                        }
                        let capacity = this
                            .count_available_lightweight(tenant, key.run())
                            .await
                            .unwrap_or_else(|e| {
                                tracing::warn!(%e, "capacity hint unavailable");
                                CapacityHint::ZERO
                            });
                        let lease = Lease::new(
                            tenant,
                            key.run(),
                            key.shard(),
                            worker,
                            new_fence,
                            new_deadline,
                        );
                        Ok(CasOutcome::Committed((persisted, lease, capacity)))
                    })
                },
                |this| {
                    Box::pin(async move {
                        let persisted = this.load_shard_or_panic(tenant, key).await;
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
                                current_owner: persisted.record.lease_owner().expect("live owner"),
                                lease_deadline: persisted
                                    .record
                                    .lease_deadline()
                                    .expect("live deadline"),
                            });
                        }
                        super::fatal_storage_error(
                            "acquire.compare_retry_budget",
                            "compare contention did not converge",
                        )
                    })
                },
            )
            .await?;
        Ok(build_acquire_result(out, &persisted, lease, capacity))
    }

    async fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = lease.shard_key();
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);
        let max_retries = self.config.optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            shard_buf.clear();
            owner_buf.clear();
            let persisted = self
                .load_shard_and_validate_lease(
                    now,
                    tenant,
                    lease,
                    |shard| RenewError::ShardNotFound { shard },
                    |err| RenewError::BackendError(super::map_etcd_err("renew.load_shard", err)),
                    |presented, current| RenewError::StaleFence { presented, current },
                )
                .await?;
            let run_record = self.load_run_or_panic(tenant, key.run()).await;
            let new_deadline = now
                .checked_add(run_record.record.config.lease_duration())
                .unwrap_or(LogicalTime::from_raw(u64::MAX));
            let old_lease_id = persisted
                .owner
                .as_ref()
                .map(|o| o.lease_id)
                .expect("validated owner must exist");
            let mut persisted = persisted;
            persisted.record.lease = Some(LeaseHolder::new(lease.owner(), new_deadline));
            persisted.record.assert_invariants(&persisted.slab);
            encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf).map_err(
                |e| RenewError::BackendError(InfraError::corruption("renew.encode_shard", e)),
            )?;
            let owner = persisted.owner.as_ref().expect("validated owner");
            encode_owner_value_into(owner.binding.worker, owner.binding.fence, &mut owner_buf);
            let srk = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let ok = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let compares = build_shard_owner_cas(srk.clone(), ok, &persisted, owner_buf.clone());
            let mut txn = TxnBuilder::from_compares(compares);
            txn.put(srk.into_bytes(), shard_buf.clone());
            let outcome = txn
                .execute_async(self, ())
                .await
                .map_err(|err| RenewError::BackendError(super::map_etcd_err("renew.txn", err)))?;
            if matches!(outcome, CasOutcome::Committed(())) {
                if let Err(e) = self.etcd_lease_keep_alive_once(old_lease_id).await {
                    tracing::warn!(lease_id = old_lease_id, %e, "renew: keep-alive failed");
                }
                let capacity = self
                    .count_available_lightweight(tenant, key.run())
                    .await
                    .unwrap_or_else(|e| {
                        tracing::warn!(%e, "capacity hint unavailable");
                        CapacityHint::ZERO
                    });
                return Ok(RenewResult {
                    new_deadline,
                    capacity,
                });
            }
            if attempt_num + 1 < max_retries {
                tokio::time::sleep(cas_retry_delay(attempt_num)).await;
            }
        }
        // Exhaustion.
        let persisted = self.load_shard_or_panic(tenant, key).await;
        validate_loaded_shard_lease(now, tenant, lease, &persisted, |presented, current| {
            RenewError::StaleFence { presented, current }
        })?;
        super::fatal_storage_error(
            "renew.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    async fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let key = lease.shard_key();
        let payload_hash = hash_checkpoint_payload(new_cursor);
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);
        let max_retries = self.config.optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            shard_buf.clear();
            owner_buf.clear();
            let persisted = match self.load_shard_record(tenant, key).await {
                Ok(Some(s)) => s,
                Ok(None) => return Err(CheckpointError::ShardNotFound { shard: key }),
                Err(e) => {
                    return Err(CheckpointError::BackendError(super::map_etcd_err(
                        "checkpoint.load_shard",
                        e,
                    )));
                }
            };
            if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                return Ok(IdempotentOutcome::Replayed(()));
            }
            validate_loaded_shard_lease(now, tenant, lease, &persisted, |presented, current| {
                CheckpointError::StaleFence { presented, current }
            })?;
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
            encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf).map_err(
                |e| {
                    CheckpointError::BackendError(InfraError::corruption(
                        "checkpoint.encode_shard",
                        e,
                    ))
                },
            )?;
            let owner = persisted.owner.as_ref().expect("validated owner");
            encode_owner_value_into(owner.binding.worker, owner.binding.fence, &mut owner_buf);
            let srk = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let ok = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let compares = build_shard_owner_cas(srk.clone(), ok, &persisted, owner_buf.clone());
            let mut txn = TxnBuilder::from_compares(compares);
            txn.put(srk.into_bytes(), shard_buf.clone());
            let outcome = txn
                .execute_async(self, IdempotentOutcome::Executed(()))
                .await
                .map_err(|err| {
                    CheckpointError::BackendError(super::map_etcd_err("checkpoint.txn", err))
                })?;
            if let CasOutcome::Committed(result) = outcome {
                return Ok(result);
            }
            if attempt_num + 1 < max_retries {
                tokio::time::sleep(cas_retry_delay(attempt_num)).await;
            }
        }
        // Exhaustion.
        let persisted = self.load_shard_or_panic(tenant, key).await;
        if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }
        validate_loaded_shard_lease(now, tenant, lease, &persisted, |presented, current| {
            CheckpointError::StaleFence { presented, current }
        })?;
        super::fatal_storage_error(
            "checkpoint.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    async fn complete(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _final_cursor: &CursorUpdate<'_>,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.fail_unimplemented("complete")
    }

    async fn park_shard(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _reason: ParkReason,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.fail_unimplemented("park_shard")
    }

    async fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_replace_payload(&plan);
        let plan_children_len = plan.children().len();
        let cap = self.config.max_children_per_op();
        let mut child_puts: Vec<TxnOp> = Vec::with_capacity(cap);
        let mut child_index_ops: Vec<TxnOp> = Vec::with_capacity(cap);
        let mut child_absent_compares: Vec<Compare> = Vec::with_capacity(cap);
        let max_retries = self.config.optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            child_puts.clear();
            child_index_ops.clear();
            child_absent_compares.clear();
            let persisted = match self.load_shard_record(tenant, key).await {
                Ok(Some(s)) => s,
                Ok(None) => return Err(SplitReplaceError::ShardNotFound { shard: key }),
                Err(e) => {
                    return Err(SplitReplaceError::BackendError(super::map_etcd_err(
                        "split_replace.load_shard",
                        e,
                    )));
                }
            };
            if persisted.record.tenant != tenant {
                return Err(SplitReplaceError::TenantMismatch { expected: tenant });
            }
            if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                let children = split_replace_replay_child_ids(
                    &persisted.record,
                    &persisted.slab,
                    plan_children_len,
                );
                return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
            }
            if persisted.record.status != ShardStatus::Active {
                return Err(SplitReplaceError::ShardTerminal {
                    shard: key,
                    status: persisted.record.status,
                });
            }
            validate_loaded_shard_lease(now, tenant, lease, &persisted, |presented, current| {
                SplitReplaceError::StaleFence { presented, current }
            })?;
            let child_count = plan.children().len();
            if child_count > self.config.max_children_per_op() {
                return Err(SplitReplaceError::SplitInvalid(
                    SplitValidationError::BackendChildLimitExceeded {
                        requested: child_count,
                        backend_max: self.config.max_children_per_op(),
                    },
                ));
            }
            let sorted =
                split_replace_validate_preconditions(&persisted.record, &plan, &persisted.slab)?;
            let counts = self.current_shard_counts(tenant).await.map_err(|e| {
                SplitReplaceError::BackendError(super::map_etcd_err(
                    "split_replace.count_shards",
                    e,
                ))
            })?;
            if let Some(limit) = shard_limit_violation(
                counts,
                sorted.len(),
                self.config.max_shards_per_tenant(),
                self.config.max_total_shards(),
            ) {
                return Err(SplitReplaceError::SplitInvalid(
                    SplitValidationError::ShardLimitExceeded {
                        current: limit.current,
                        additional: limit.additional,
                        max: limit.max,
                        scope: limit.scope,
                    },
                ));
            }
            let mut child_ids = SplitChildIds::new();
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
                let mut child_slab = ByteSlab::with_capacity(
                    super::build_slab_capacity_for_spec_and_cursor(child.spec(), child.cursor()),
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
                let crk = self
                    .keyspace
                    .shard_record_key(tenant, persisted.record.run, child_id);
                child_absent_compares.push(super::compare_absent(crk.clone()));
                child_puts.push(TxnOp::put(
                    crk.into_bytes(),
                    encode_shard_record(&child_record, &child_slab).unwrap_or_else(|e| {
                        super::fatal_storage_error("split_replace.encode_child", e)
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
                .unwrap_or_else(|e| super::fatal_storage_error("split_replace.encode_parent", e));
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner value");
            let srk = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let ok = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let mut compares =
                build_shard_owner_cas(srk.clone(), ok.clone(), &persisted, owner_blob);
            compares.append(&mut child_absent_compares);
            self.inject_split_replace_fault_if_armed(tenant, key).await;
            let mut txn = TxnBuilder::from_compares(compares);
            txn.put(srk.into_bytes(), parent_blob)
                .delete(ok.into_bytes())
                .delete(
                    self.keyspace
                        .shard_active_index_key(tenant, key.run(), key.shard())
                        .into_bytes(),
                )
                .ops(child_puts.drain(..))
                .ops(child_index_ops.drain(..));
            let outcome = txn
                .execute_async(
                    self,
                    IdempotentOutcome::Executed(SplitReplaceResult {
                        children: child_ids,
                    }),
                )
                .await
                .map_err(|err| {
                    SplitReplaceError::BackendError(super::map_etcd_err("split_replace.txn", err))
                })?;
            if let CasOutcome::Committed(result) = outcome {
                return Ok(result);
            }
            if attempt_num + 1 < max_retries {
                tokio::time::sleep(cas_retry_delay(attempt_num)).await;
            }
        }
        // Exhaustion: re-read and diagnose.
        let persisted = self.load_shard_or_panic(tenant, key).await;
        if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
            let children = split_replace_replay_child_ids(
                &persisted.record,
                &persisted.slab,
                plan_children_len,
            );
            return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
        }
        if persisted.record.status != ShardStatus::Active {
            return Err(SplitReplaceError::ShardTerminal {
                shard: key,
                status: persisted.record.status,
            });
        }
        validate_loaded_shard_lease(now, tenant, lease, &persisted, |presented, current| {
            SplitReplaceError::StaleFence { presented, current }
        })?;
        let sorted =
            split_replace_validate_preconditions(&persisted.record, &plan, &persisted.slab)?;
        for sorted_index in 0..sorted.len() {
            let child_id = derive_split_shard_id(
                persisted.record.run,
                persisted.record.shard,
                op_id,
                DerivedShardKind::Child,
                u32::try_from(persisted.record.spawned.len() + sorted_index)
                    .expect("child index exceeds u32"),
            );
            let child_key = ShardKey::new(persisted.record.run, child_id);
            match self.load_shard_record(tenant, child_key).await {
                Ok(Some(_)) => {
                    return Err(SplitReplaceError::SplitInvalid(
                        SplitValidationError::DerivedIdCollision {
                            derived_id: child_id,
                        },
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(SplitReplaceError::BackendError(super::map_etcd_err(
                        "split_replace.collision_probe",
                        e,
                    )));
                }
            }
        }
        super::fatal_storage_error(
            "split_replace.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    async fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_residual_payload(&plan);
        let max_retries = self.config.optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            let persisted = match self.load_shard_record(tenant, key).await {
                Ok(Some(s)) => s,
                Ok(None) => return Err(SplitResidualError::ShardNotFound { shard: key }),
                Err(e) => {
                    return Err(SplitResidualError::BackendError(super::map_etcd_err(
                        "split_residual.load_shard",
                        e,
                    )));
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
            let counts = self.current_shard_counts(tenant).await.map_err(|e| {
                SplitResidualError::BackendError(super::map_etcd_err(
                    "split_residual.count_shards",
                    e,
                ))
            })?;
            // The parent stays Active (not terminal), so the persisted count
            // already includes it. Only the new residual shard is net growth.
            if let Some(limit) = shard_limit_violation(
                counts,
                1,
                self.config.max_shards_per_tenant(),
                self.config.max_total_shards(),
            ) {
                return Err(SplitResidualError::SplitInvalid(
                    SplitValidationError::ShardLimitExceeded {
                        current: limit.current,
                        additional: limit.additional,
                        max: limit.max,
                        scope: limit.scope,
                    },
                ));
            }
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
            let mut residual_slab =
                ByteSlab::with_capacity(super::build_slab_capacity_for_spec_and_cursor(
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
            let rrk = self
                .keyspace
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
                .unwrap_or_else(|e| super::fatal_storage_error("split_residual.encode_parent", e));
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner value");
            let srk = self
                .keyspace
                .shard_record_key(tenant, key.run(), key.shard());
            let ok = self
                .keyspace
                .shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = build_shard_owner_cas(srk.clone(), ok, &persisted, owner_blob);
            compares.push(super::compare_absent(rrk.clone()));
            self.inject_split_residual_fault_if_armed(tenant, key).await;
            let mut txn = TxnBuilder::from_compares(compares);
            txn.put(srk.into_bytes(), parent_blob)
                .put(
                    rrk.into_bytes(),
                    encode_shard_record(&residual_record, &residual_slab).unwrap_or_else(|e| {
                        super::fatal_storage_error("split_residual.encode_residual", e)
                    }),
                )
                .put(
                    self.keyspace
                        .shard_active_index_key(tenant, persisted.record.run, residual_id)
                        .into_bytes(),
                    Vec::new(),
                );
            let outcome = txn
                .execute_async(
                    self,
                    IdempotentOutcome::Executed(SplitResidualResult {
                        residual: residual_id,
                    }),
                )
                .await
                .map_err(|err| {
                    SplitResidualError::BackendError(super::map_etcd_err("split_residual.txn", err))
                })?;
            if let CasOutcome::Committed(result) = outcome {
                return Ok(result);
            }
            if attempt_num + 1 < max_retries {
                tokio::time::sleep(cas_retry_delay(attempt_num)).await;
            }
        }
        // Exhaustion: re-read and diagnose.
        let persisted = self.load_shard_or_panic(tenant, key).await;
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
        validate_loaded_shard_lease(now, tenant, lease, &persisted, |presented, current| {
            SplitResidualError::StaleFence { presented, current }
        })?;
        let residual_id = derive_split_shard_id(
            persisted.record.run,
            persisted.record.shard,
            op_id,
            DerivedShardKind::Residual,
            u32::try_from(persisted.record.spawned.len()).expect("spawned index exceeds u32"),
        );
        let residual_key = ShardKey::new(persisted.record.run, residual_id);
        match self.load_shard_record(tenant, residual_key).await {
            Ok(Some(_)) => {
                return Err(SplitResidualError::SplitInvalid(
                    SplitValidationError::DerivedIdCollision {
                        derived_id: residual_id,
                    },
                ));
            }
            Ok(None) => {}
            Err(e) => {
                return Err(SplitResidualError::BackendError(super::map_etcd_err(
                    "split_residual.collision_probe",
                    e,
                )));
            }
        }
        super::fatal_storage_error(
            "split_residual.compare_retry_budget",
            "compare contention did not converge",
        )
    }
}
