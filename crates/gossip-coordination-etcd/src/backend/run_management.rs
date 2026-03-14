//! [`RunManagement`] and [`AsyncRunManagement`] trait impls for the etcd backend.
//!
//! These impls persist the full run lifecycle to etcd:
//!
//! ```text
//!    create_run          register_shards        complete_run / fail_run
//! ──────────────> Initializing ──────────────> Active ──────────────> Done / Failed
//!                      │                          │
//!                      └── cancel_run ────────────┴── cancel_run ──> Cancelled
//! ```
//!
//! **Visibility rule**: a run becomes visible to workers only after
//! `register_shards` publishes the active-run index entry. Before that,
//! the run exists in etcd but is invisible to `list_active_runs_into`
//! and `collect_claim_candidates_into`.
//!
//! # Shard claiming
//!
//! The [`ShardClaiming`] impl delegates to [`default_claim_next_available`],
//! which iterates the candidate list produced by
//! `collect_claim_candidates_into` and calls `acquire_and_restore_into` on
//! each until one succeeds. The candidate buffer is reused across calls
//! to avoid per-claim allocation.
//!
//! # Unpark
//!
//! `unpark_shard` transitions a `Parked` shard back to `Active` and
//! publishes a new active-shard index entry. The CAS transaction guards
//! both the shard and the run (run must still be `Active`) to prevent
//! unparking into a terminated run.

use std::collections::HashSet;

use etcd_client::{GetOptions, TxnOp};
use gossip_coordination::{
    AcquireResultView, AcquireScratch, AsyncRunManagement, ClaimError, CreateRunError, GetRunError,
    IdempotentOutcome, InfraError, InitialShardInput, LogicalTime, OpId, OpKind, OpLogEntry,
    OpResult, RegisterShardsError, RingBuffer, RunConfig, RunId, RunManagement, RunOpKind,
    RunOpLogEntry, RunOpResult, RunProgress, RunRecord, RunStatus, RunTransitionError,
    ShardClaiming, ShardCountSnapshot, ShardFilter, ShardId, ShardKey, ShardStatus, ShardSummary,
    TenantId, UnparkError, WorkerId, check_op_idempotency, default_claim_next_available,
    hash_register_shards_payload, hash_unpark_payload, shard_limit_violation, validate_manifest,
};

use super::coordinator::{AsyncEtcdCoordinator, EtcdCoordinator, SyncEtcdLike};
use super::{CasOutcome, MAX_SHARDS_PER_ETCD_TXN, TxnBuilder, cas_retry_delay};
use crate::codec::{encode_run_record, encode_shard_record_into};
use crate::keyspace::{ShardActiveIndexKey, ShardOwnerKey};
#[cfg(any(test, feature = "test-support"))]
use crate::sim_coordinator::SimEtcdCoordinator;

macro_rules! impl_sync_run_management {
    ($coord:ty) => {
        impl RunManagement for $coord {
    /// Create a new run in `Initializing` status.
    ///
    /// Uses a single CAS transaction guarded by key absence to prevent
    /// double-creation. No active-run index entry is published at this
    /// stage — the run becomes visible to workers only after
    /// `register_shards` transitions it to `Active`.
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        self.sync_logical_time(now);
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
        let mut txn = TxnBuilder::new();
        txn.compare(super::compare_absent(key.clone()))
            .put(key.into_bytes(), blob);
        let outcome = txn.execute(self, record).map_err(|err| {
            CreateRunError::BackendError(super::map_etcd_err("create_run.txn", err))
        })?;
        if let CasOutcome::Committed(created) = outcome {
            self.best_effort_refresh_cached_run_state(tenant, run);
            return Ok(created);
        }
        Err(CreateRunError::RunAlreadyExists { run })
    }

    /// Atomically register root shards and activate the run.
    ///
    /// Performs all of the following in a single CAS transaction:
    /// 1. Validates the run is `Initializing` and the manifest is valid.
    /// 2. Checks shard-count limits (per-tenant and global).
    /// 3. Creates each shard record and its active-index entry.
    /// 4. Transitions the run to `Active`, records `root_shards`, and
    ///    publishes the active-run index entry.
    ///
    /// The batch size is capped at `MAX_SHARDS_PER_ETCD_TXN` (41) due
    /// to etcd's default `--max-txn-ops` limit of 128. Each shard
    /// contributes 3 operations (compare-absent, put-record,
    /// put-active-index). Fixed overhead is 5 operations:
    /// run compare+put+active-index plus tenant-counter compare+put.
    ///
    /// Idempotent: replays return the shard IDs from the op-log.
    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        self.sync_logical_time(now);
        if shards.len() > MAX_SHARDS_PER_ETCD_TXN {
            return Err(RegisterShardsError::ResourceExhausted {
                resource: "etcd_txn_ops",
            });
        }

        let payload_hash = hash_register_shards_payload(shards);

        let result = self.cas_retry(
            |this, _attempt| {
                let persisted_run = match this.load_run_record(tenant, run) {
                    Ok(Some(run_record)) => run_record,
                    Ok(None) => return Err(RegisterShardsError::RunNotFound),
                    Err(err) => {
                        return Err(RegisterShardsError::BackendError(super::map_etcd_err(
                            "register_shards.load_run",
                            err,
                        )));
                    }
                };
                let mut run_record = persisted_run.record;

                if run_record.tenant != tenant {
                    return Err(RegisterShardsError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = run_record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != RunOpKind::RegisterShards {
                        return Err(RegisterShardsError::BackendError(InfraError::corruption(
                            "register_shards.idempotent_replay",
                            format!(
                                "kind mismatch: expected RegisterShards, got {:?}",
                                entry.kind()
                            ),
                        )));
                    }
                    match entry.result() {
                        RunOpResult::RegisteredShards { shard_ids } => {
                            return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(
                                shard_ids.to_vec(),
                            )));
                        }
                        RunOpResult::Ack => {
                            return Err(RegisterShardsError::BackendError(InfraError::corruption(
                                "register_shards.idempotent_replay",
                                format!(
                                    "run {run:?}: RegisterShards op-log entry has Ack result \
                                         (expected RegisteredShards)"
                                ),
                            )));
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
                let tenant_counter = this
                    .prepare_tenant_shard_count_mutation(tenant, shard_ids.len())
                    .map_err(|err| {
                        RegisterShardsError::BackendError(super::map_etcd_err(
                            "register_shards.load_tenant_counter",
                            err,
                        ))
                    })?;
                // Per-tenant limit is CAS-enforced: `tenant_counter.compare`
                // guards against concurrent same-tenant mutations.  The global
                // limit is best-effort preflight only — `total_count` is a
                // point-in-time scan with no CAS guard, so concurrent
                // cross-tenant shard creation can overshoot `max_total_shards`.
                // A global sentinel key would serialize all shard-creating
                // transactions across every tenant; the preflight catches the
                // common case (approaching capacity) without that contention.
                let total_count = this
                    .count_persisted_shards_under_prefix(this.keyspace.tenants_prefix())
                    .map_err(|err| {
                        RegisterShardsError::BackendError(super::map_etcd_err(
                            "register_shards.count_total_shards",
                            err,
                        ))
                    })?;
                let counts = ShardCountSnapshot {
                    tenant: tenant_counter.current_count,
                    total: total_count,
                };
                if let Some(limit) = shard_limit_violation(
                    counts,
                    shard_ids.len(),
                    this.config.max_shards_per_tenant(),
                    this.config.max_total_shards(),
                ) {
                    return Err(RegisterShardsError::ShardLimitExceeded {
                        current: limit.current,
                        additional: limit.additional,
                        max: limit.max,
                        scope: limit.scope,
                    });
                }

                let mut txn_ops = Vec::with_capacity(1 + (shards.len() * 2) + 1);
                let mut compares = Vec::with_capacity(2 + shards.len());
                let run_key = this.keyspace.run_record_key(tenant, run);
                compares.push(super::compare_run_revision(
                    run_key.clone(),
                    persisted_run.mod_revision,
                ));
                compares.push(tenant_counter.compare);

                for shard in shards {
                    let shard_key = this.keyspace.shard_record_key(tenant, run, shard.shard());
                    compares.push(super::compare_absent(shard_key.clone()));
                    let shard_blob =
                        super::build_root_shard_blob(tenant, run, cursor_semantics, shard)?;
                    txn_ops.push(TxnOp::put(shard_key.into_bytes(), shard_blob, None));

                    let active_index =
                        this.keyspace
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

                let run_active_key = this.keyspace.run_active_index_key(tenant, run);
                let mut txn = TxnBuilder::from_compares(compares);
                txn.put(run_key.into_bytes(), run_blob)
                    .ops(txn_ops)
                    .put(run_active_key.into_bytes(), Vec::<u8>::new())
                    .put(
                        tenant_counter.key.into_bytes(),
                        super::encode_tenant_shard_count(tenant_counter.next_count),
                    );
                txn.execute(this, IdempotentOutcome::Executed(shard_ids))
                    .map_err(|err| {
                        RegisterShardsError::BackendError(super::map_etcd_err(
                            "register_shards.txn",
                            err,
                        ))
                    })
            },
            |this| {
                // Use load_run_record directly: register_shards operates on
                // Initializing runs, which gc_stale_initializing_runs_into
                // can legitimately delete during the CAS retry window.
                let persisted_run = match this.load_run_record(tenant, run) {
                    Ok(Some(r)) => r,
                    Ok(None) => return Err(RegisterShardsError::RunNotFound),
                    Err(err) => {
                        return Err(RegisterShardsError::BackendError(super::map_etcd_err(
                            "register_shards.exhaust.load_run",
                            err,
                        )));
                    }
                };
                if let Some(entry) = persisted_run
                    .record
                    .check_op_idempotency(op_id, payload_hash)?
                {
                    match entry.result() {
                        RunOpResult::RegisteredShards { shard_ids } => {
                            return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                        }
                        RunOpResult::Ack => {
                            return Err(RegisterShardsError::BackendError(InfraError::corruption(
                                "register_shards",
                                format!(
                                    "Run {run:?}: RegisterShards op-log entry has Ack result \
                                         (expected RegisteredShards)"
                                ),
                            )));
                        }
                    }
                }
                if persisted_run.record.status != RunStatus::Initializing {
                    return Err(RegisterShardsError::WrongStatus {
                        status: persisted_run.record.status,
                    });
                }

                Err(RegisterShardsError::BackendError(InfraError::transient(
                    "register_shards",
                    "CAS retry budget exhausted",
                )))
            },
        )?;
        self.best_effort_refresh_cached_run_state(tenant, run);
        Ok(result)
    }

    /// Load a run record by exact key. Returns `GetRunError::RunNotFound` if
    /// the key does not exist. Validates tenant consistency.
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
            Err(err) => Err(GetRunError::BackendError(super::map_etcd_err(
                "get_run.load",
                err,
            ))),
        }
    }

    /// Compute aggregate progress across all shards in a run.
    ///
    /// Performs a full prefix scan of all shard records under the run,
    /// observing each shard's status, ownership liveness, and cursor
    /// position. This is an O(shards) read operation.
    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        self.sync_logical_time(now);
        let _ = self.get_run(tenant, run)?;
        let shards = self.scan_run_shards(tenant, run).map_err(|err| {
            GetRunError::BackendError(super::map_etcd_err("get_run_progress.scan", err))
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

    /// List shard summaries matching `filter`, sorted by key range start
    /// then shard ID.
    ///
    /// Performs a full prefix scan, decodes all shard records, applies the
    /// filter using `visible_now` for expired-lease visibility, and
    /// collects matching summaries into `out`.
    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        self.sync_logical_time(now);
        let _ = self.get_run(tenant, run)?;
        let shards = self.scan_run_shards(tenant, run).map_err(|err| {
            GetRunError::BackendError(super::map_etcd_err("list_shards_into.scan", err))
        })?;

        out.clear();
        for persisted in &shards {
            let visible_now = super::visible_now(persisted, now);
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

    /// Collect shard IDs eligible for claiming (active and unowned).
    ///
    /// Uses two keys-only prefix scans instead of loading full shard
    /// record blobs:
    ///
    /// 1. **Active-index scan** — entries in `shards_active/` exist only
    ///    for `Active` shards, skipping terminal records entirely.
    /// 2. **Owner-key scan** — owner keys (`shards/{hex}/owner`) indicate
    ///    a live etcd-level owner binding. Their presence means the shard
    ///    is owned; absence means it is available for claiming.
    ///
    /// Active shards without an owner key are candidates. The earliest
    /// lease deadline among owned shards is not computed (would require
    /// loading full record blobs); `None` is returned instead. The
    /// caller ([`default_claim_next_available`]) handles `None`
    /// gracefully — per-shard acquire attempts refine the deadline as
    /// `AlreadyLeased` errors are encountered.
    ///
    /// The candidate list is sorted by shard ID for deterministic claim
    /// ordering.
    fn collect_claim_candidates_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        self.sync_logical_time(now);
        let _ = self.get_run(tenant, run)?;

        // Keys-only scan of the active-shard index to find unleased candidates.
        let mut active_prefix = self.keyspace.shards_active_prefix(tenant, run);
        active_prefix.push('/');
        let active_resp = self
            .etcd_get(
                active_prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .map_err(|err| {
                GetRunError::BackendError(super::map_etcd_err(
                    "collect_claim_candidates.active_scan",
                    err,
                ))
            })?;

        let active_ids: Vec<ShardId> = active_resp
            .kvs()
            .iter()
            .filter_map(|kv| ShardActiveIndexKey::parse_direct_shard_id(&active_prefix, kv.key()))
            .collect();

        if active_ids.is_empty() {
            candidates.clear();
            return Ok(None);
        }

        // Keys-only scan of the shard record prefix to discover
        // which active shards have a live `/owner` key.
        let shards_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
        let keys_resp = self
            .etcd_get(
                shards_prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .map_err(|err| {
                GetRunError::BackendError(super::map_etcd_err(
                    "collect_claim_candidates.keys_scan",
                    err,
                ))
            })?;

        let owned_ids: HashSet<ShardId> = keys_resp
            .kvs()
            .iter()
            .filter_map(|kv| ShardOwnerKey::parse_owned_shard(shards_prefix.as_bytes(), kv.key()))
            .collect();

        candidates.clear();
        for shard_id in &active_ids {
            if !owned_ids.contains(shard_id) {
                candidates.push(*shard_id);
            }
        }
        candidates.sort_unstable();

        Ok(None)
    }

    /// Transition an `Active` run to `Done`. Requires the active-run index
    /// entry to exist.
    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.sync_logical_time(now);
        let result =
            self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::CompleteRun)?;
        self.best_effort_refresh_cached_run_state(tenant, run);
        Ok(result)
    }

    /// Transition an `Active` run to `Failed`. Requires the active-run
    /// index entry to exist.
    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.sync_logical_time(now);
        let result = self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::FailRun)?;
        self.best_effort_refresh_cached_run_state(tenant, run);
        Ok(result)
    }

    /// Transition an `Initializing` or `Active` run to `Cancelled`.
    ///
    /// Unlike `complete_run` and `fail_run`, this accepts `Initializing`
    /// runs (which have no active-run index entry) as well as `Active`
    /// runs. The CAS transaction adapts its index-key guard accordingly.
    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.sync_logical_time(now);
        let result =
            self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::CancelRun)?;
        self.best_effort_refresh_cached_run_state(tenant, run);
        Ok(result)
    }

    /// Re-activate a parked shard, making it available for claiming.
    ///
    /// Transitions the shard from `Parked` to `Active`, clears the park
    /// reason, bumps the fence epoch, and publishes a new active-shard
    /// index entry. No owner binding is created — the shard must be
    /// explicitly acquired after unparking.
    ///
    /// The CAS transaction guards:
    /// - Shard record `mod_revision` (no concurrent mutation).
    /// - Run record `mod_revision` and active-run index presence (run
    ///   must still be `Active`).
    /// - Owner key absent (parked shards must not have an owner).
    ///
    /// Idempotent via op-log replay.
    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        self.sync_logical_time(now);
        let payload_hash = hash_unpark_payload(&key);
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);

        let result = self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(UnparkError::ShardNotFound),
                    Err(err) => {
                        return Err(UnparkError::BackendError(super::map_etcd_err(
                            "unpark.load_shard",
                            err,
                        )));
                    }
                };

                if persisted.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }

                let persisted_run = match this.load_run_record(tenant, key.run()) {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        return Err(UnparkError::BackendError(InfraError::corruption(
                            "unpark",
                            format!("run {:?} missing", key.run()),
                        )));
                    }
                    Err(err) => {
                        return Err(UnparkError::BackendError(super::map_etcd_err(
                            "unpark.load_run",
                            err,
                        )));
                    }
                };
                if persisted_run.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }
                if persisted_run.record.status.is_terminal() {
                    return Err(UnparkError::RunTerminal {
                        status: persisted_run.record.status,
                    });
                }
                if persisted_run.record.status != RunStatus::Active {
                    return Err(UnparkError::BackendError(InfraError::corruption(
                        "unpark",
                        format!(
                            "shard {key:?} belongs to non-active run (status: {:?})",
                            persisted_run.record.status
                        ),
                    )));
                }

                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                }

                if persisted.record.status != ShardStatus::Parked {
                    return Err(UnparkError::NotParked {
                        status: persisted.record.status,
                    });
                }

                let mut persisted = persisted;
                persisted.record.advance_fence();
                persisted.record.park_reason = None;
                persisted.record.status = ShardStatus::Active;
                persisted.record.lease = None;
                persisted.record.op_log_push(OpLogEntry::new(
                    op_id,
                    OpKind::Unpark,
                    OpResult::Completed,
                    payload_hash,
                    now,
                ));
                persisted.record.assert_invariants(&persisted.slab);
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| {
                        UnparkError::BackendError(InfraError::corruption(
                            "unpark.encode_shard",
                            err,
                        ))
                    })?;

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let run_key = this.keyspace.run_record_key(tenant, key.run());
                let run_active_key = this.keyspace.run_active_index_key(tenant, key.run());
                let active_shard_key =
                    this.keyspace
                        .shard_active_index_key(tenant, key.run(), key.shard());

                let mut txn = TxnBuilder::new();
                txn.compare(super::compare_shard_revision(
                    shard_record_key.clone(),
                    persisted.mod_revision,
                ))
                .compare(super::compare_run_revision(
                    run_key,
                    persisted_run.mod_revision,
                ))
                .compare(super::compare_present(run_active_key))
                .compare(super::compare_absent(owner_key))
                .put(shard_record_key.into_bytes(), shard_buf.clone())
                .put(active_shard_key.into_bytes(), Vec::<u8>::new());
                txn.execute(this, IdempotentOutcome::Executed(()))
                    .map_err(|err| {
                        UnparkError::BackendError(super::map_etcd_err("unpark.txn", err))
                    })
            },
            |this| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(s)) => s,
                    Ok(None) => return Err(UnparkError::ShardNotFound),
                    Err(err) => {
                        return Err(UnparkError::BackendError(super::map_etcd_err(
                            "unpark.exhaust.load_shard",
                            err,
                        )));
                    }
                };
                if persisted.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }
                let persisted_run = match this.load_run_record(tenant, key.run()) {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        return Err(UnparkError::BackendError(InfraError::corruption(
                            "unpark.exhaust",
                            format!("run {:?} missing", key.run()),
                        )));
                    }
                    Err(err) => {
                        return Err(UnparkError::BackendError(super::map_etcd_err(
                            "unpark.exhaust.load_run",
                            err,
                        )));
                    }
                };
                if persisted_run.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }
                if persisted_run.record.status.is_terminal() {
                    return Err(UnparkError::RunTerminal {
                        status: persisted_run.record.status,
                    });
                }
                if persisted_run.record.status != RunStatus::Active {
                    return Err(UnparkError::BackendError(InfraError::corruption(
                        "unpark.exhaust",
                        format!(
                            "shard {key:?} belongs to non-active run (status: {:?})",
                            persisted_run.record.status
                        ),
                    )));
                }

                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(IdempotentOutcome::Replayed(()));
                }
                if persisted.record.status != ShardStatus::Parked {
                    return Err(UnparkError::NotParked {
                        status: persisted.record.status,
                    });
                }

                Err(UnparkError::BackendError(InfraError::transient(
                    "unpark",
                    "CAS retry budget exhausted",
                )))
            },
        )?;
        self.best_effort_refresh_cached_run_state(tenant, key.run());
        Ok(result)
    }
        }

        impl ShardClaiming for $coord {
    /// Claim the next available shard using the default round-robin
    /// strategy.
    ///
    /// Delegates to [`default_claim_next_available`], passing a reusable
    /// candidate buffer (`claim_candidates_scratch`) that is `mem::take`-ed
    /// before the call and restored afterward. This avoids per-claim heap
    /// allocation when the buffer capacity is already sufficient from a
    /// prior call.
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
        // Shrink if capacity grew disproportionate to actual usage,
        // preventing unbounded growth from transient shard-count spikes.
        if candidates.capacity() > 1024 && candidates.len() < candidates.capacity() / 4 {
            candidates.shrink_to(candidates.len().max(256));
        }
        self.claim_candidates_scratch = candidates;
        result
    }
        }
    };
}

impl_sync_run_management!(EtcdCoordinator);
#[cfg(any(test, feature = "test-support"))]
impl_sync_run_management!(SimEtcdCoordinator);

impl AsyncRunManagement for AsyncEtcdCoordinator {
    async fn create_run(
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
        let mut txn = TxnBuilder::new();
        txn.compare(super::compare_absent(key.clone()))
            .put(key.into_bytes(), blob);
        let outcome = txn.execute_async(self, record).await.map_err(|err| {
            CreateRunError::BackendError(super::map_etcd_err("create_run.txn", err))
        })?;
        if let CasOutcome::Committed(created) = outcome {
            return Ok(created);
        }
        Err(CreateRunError::RunAlreadyExists { run })
    }

    async fn register_shards(
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
        for attempt_num in 0..self.config.optimistic_txn_retries() {
            let persisted_run = match self.load_run_record(tenant, run).await {
                Ok(Some(r)) => r,
                Ok(None) => return Err(RegisterShardsError::RunNotFound),
                Err(e) => {
                    return Err(RegisterShardsError::BackendError(super::map_etcd_err(
                        "register_shards.load_run",
                        e,
                    )));
                }
            };
            let mut run_record = persisted_run.record;
            if run_record.tenant != tenant {
                return Err(RegisterShardsError::TenantMismatch { expected: tenant });
            }
            if let Some(entry) = run_record.check_op_idempotency(op_id, payload_hash)? {
                if entry.kind() != RunOpKind::RegisterShards {
                    return Err(RegisterShardsError::BackendError(InfraError::corruption(
                        "register_shards.idempotent_replay",
                        format!(
                            "kind mismatch: expected RegisterShards, got {:?}",
                            entry.kind()
                        ),
                    )));
                }
                match entry.result() {
                    RunOpResult::RegisteredShards { shard_ids } => {
                        return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                    }
                    RunOpResult::Ack => {
                        return Err(RegisterShardsError::BackendError(InfraError::corruption(
                            "register_shards.idempotent_replay",
                            format!("run {run:?}: Ack result (expected RegisteredShards)"),
                        )));
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
            let tenant_counter = self
                .prepare_tenant_shard_count_mutation(tenant, shard_ids.len())
                .await
                .map_err(|err| {
                    RegisterShardsError::BackendError(super::map_etcd_err(
                        "register_shards.load_tenant_counter",
                        err,
                    ))
                })?;
            let total_count = self
                .count_persisted_shards_under_prefix(self.keyspace.tenants_prefix())
                .await
                .map_err(|err| {
                    RegisterShardsError::BackendError(super::map_etcd_err(
                        "register_shards.count_total_shards",
                        err,
                    ))
                })?;
            let counts = ShardCountSnapshot {
                tenant: tenant_counter.current_count,
                total: total_count,
            };
            if let Some(limit) = shard_limit_violation(
                counts,
                shard_ids.len(),
                self.config.max_shards_per_tenant(),
                self.config.max_total_shards(),
            ) {
                return Err(RegisterShardsError::ShardLimitExceeded {
                    current: limit.current,
                    additional: limit.additional,
                    max: limit.max,
                    scope: limit.scope,
                });
            }
            let mut txn_ops = Vec::with_capacity(1 + (shards.len() * 2) + 1);
            let mut compares = Vec::with_capacity(2 + shards.len());
            let run_key = self.keyspace.run_record_key(tenant, run);
            compares.push(super::compare_run_revision(
                run_key.clone(),
                persisted_run.mod_revision,
            ));
            compares.push(tenant_counter.compare);
            for shard in shards {
                let sk = self.keyspace.shard_record_key(tenant, run, shard.shard());
                compares.push(super::compare_absent(sk.clone()));
                let shard_blob =
                    super::build_root_shard_blob(tenant, run, cursor_semantics, shard)?;
                txn_ops.push(TxnOp::put(sk.into_bytes(), shard_blob, None));
                let ai = self
                    .keyspace
                    .shard_active_index_key(tenant, run, shard.shard());
                txn_ops.push(TxnOp::put(ai.into_bytes(), Vec::<u8>::new(), None));
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
            let rak = self.keyspace.run_active_index_key(tenant, run);
            let mut txn = TxnBuilder::from_compares(compares);
            txn.put(run_key.into_bytes(), run_blob)
                .ops(txn_ops)
                .put(rak.into_bytes(), Vec::<u8>::new())
                .put(
                    tenant_counter.key.into_bytes(),
                    super::encode_tenant_shard_count(tenant_counter.next_count),
                );
            let outcome = txn
                .execute_async(self, IdempotentOutcome::Executed(shard_ids))
                .await
                .map_err(|err| {
                    RegisterShardsError::BackendError(super::map_etcd_err(
                        "register_shards.txn",
                        err,
                    ))
                })?;
            if let CasOutcome::Committed(result) = outcome {
                return Ok(result);
            }
            tokio::time::sleep(cas_retry_delay(attempt_num)).await;
        }
        // Exhaustion.
        let persisted_run = match self.load_run_record(tenant, run).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err(RegisterShardsError::RunNotFound),
            Err(err) => {
                return Err(RegisterShardsError::BackendError(super::map_etcd_err(
                    "register_shards.exhaust.load_run",
                    err,
                )));
            }
        };
        if let Some(entry) = persisted_run
            .record
            .check_op_idempotency(op_id, payload_hash)?
        {
            match entry.result() {
                RunOpResult::RegisteredShards { shard_ids } => {
                    return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                }
                RunOpResult::Ack => {
                    return Err(RegisterShardsError::BackendError(InfraError::corruption(
                        "register_shards",
                        format!(
                            "Run {run:?}: RegisterShards op-log entry has Ack result \
                                 (expected RegisteredShards)"
                        ),
                    )));
                }
            }
        }
        if persisted_run.record.status != RunStatus::Initializing {
            return Err(RegisterShardsError::WrongStatus {
                status: persisted_run.record.status,
            });
        }
        Err(RegisterShardsError::BackendError(InfraError::transient(
            "register_shards",
            "CAS retry budget exhausted",
        )))
    }

    async fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        match self.load_run_record(tenant, run).await {
            Ok(Some(p)) => {
                if p.record.tenant != tenant {
                    Err(GetRunError::TenantMismatch { expected: tenant })
                } else {
                    Ok(p.record)
                }
            }
            Ok(None) => Err(GetRunError::RunNotFound),
            Err(e) => Err(GetRunError::BackendError(super::map_etcd_err(
                "get_run.load",
                e,
            ))),
        }
    }

    async fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        let _ = self.get_run(tenant, run).await?;
        let shards = self.scan_run_shards(tenant, run).await.map_err(|e| {
            GetRunError::BackendError(super::map_etcd_err("get_run_progress.scan", e))
        })?;
        let mut progress = RunProgress::default();
        for p in &shards {
            progress.observe_shard(
                p.record.status,
                p.owner_is_live_at(now),
                p.record.cursor.last_key(&p.slab),
            );
        }
        Ok(progress)
    }

    async fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        let _ = self.get_run(tenant, run).await?;
        let shards = self.scan_run_shards(tenant, run).await.map_err(|e| {
            GetRunError::BackendError(super::map_etcd_err("list_shards_into.scan", e))
        })?;
        out.clear();
        for p in &shards {
            let vn = super::visible_now(p, now);
            if !filter.matches_record(&p.record, vn) {
                continue;
            }
            out.push(ShardSummary::from_record(&p.record, vn, &p.slab));
        }
        out.sort_by(|a, b| {
            a.key_range_start()
                .cmp(b.key_range_start())
                .then_with(|| a.shard().cmp(&b.shard()))
        });
        Ok(())
    }

    async fn collect_claim_candidates_into(
        &self,
        _now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        let _ = self.get_run(tenant, run).await?;
        let mut active_prefix = self.keyspace.shards_active_prefix(tenant, run);
        active_prefix.push('/');
        let active_resp = self
            .etcd_get(
                active_prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .await
            .map_err(|e| {
                GetRunError::BackendError(super::map_etcd_err(
                    "collect_claim_candidates.active_scan",
                    e,
                ))
            })?;
        let active_ids: Vec<ShardId> = active_resp
            .kvs()
            .iter()
            .filter_map(|kv| ShardActiveIndexKey::parse_direct_shard_id(&active_prefix, kv.key()))
            .collect();
        if active_ids.is_empty() {
            candidates.clear();
            return Ok(None);
        }
        let shards_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
        let keys_resp = self
            .etcd_get(
                shards_prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .await
            .map_err(|e| {
                GetRunError::BackendError(super::map_etcd_err(
                    "collect_claim_candidates.keys_scan",
                    e,
                ))
            })?;
        let owned_ids: HashSet<ShardId> = keys_resp
            .kvs()
            .iter()
            .filter_map(|kv| ShardOwnerKey::parse_owned_shard(shards_prefix.as_bytes(), kv.key()))
            .collect();
        candidates.clear();
        for id in &active_ids {
            if !owned_ids.contains(id) {
                candidates.push(*id);
            }
        }
        candidates.sort_unstable();
        Ok(None)
    }

    async fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::CompleteRun)
            .await
    }

    async fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::FailRun)
            .await
    }

    async fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::CancelRun)
            .await
    }

    async fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        let payload_hash = hash_unpark_payload(&key);
        self.cas_retry(
            |this, _attempt| {
                Box::pin(async move {
                    let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
                    let persisted = match this.load_shard_record(tenant, key).await {
                        Ok(Some(s)) => s,
                        Ok(None) => return Err(UnparkError::ShardNotFound),
                        Err(e) => {
                            return Err(UnparkError::BackendError(super::map_etcd_err(
                                "unpark.load_shard",
                                e,
                            )));
                        }
                    };
                    if persisted.record.tenant != tenant {
                        return Err(UnparkError::TenantMismatch { expected: tenant });
                    }
                    let persisted_run = match this.load_run_record(tenant, key.run()).await {
                        Ok(Some(r)) => r,
                        Ok(None) => {
                            return Err(UnparkError::BackendError(InfraError::corruption(
                                "unpark.load_run",
                                format!("run {:?} missing", key.run()),
                            )));
                        }
                        Err(e) => {
                            return Err(UnparkError::BackendError(super::map_etcd_err(
                                "unpark.load_run",
                                e,
                            )));
                        }
                    };
                    if persisted_run.record.tenant != tenant {
                        return Err(UnparkError::TenantMismatch { expected: tenant });
                    }
                    if persisted_run.record.status.is_terminal() {
                        return Err(UnparkError::RunTerminal {
                            status: persisted_run.record.status,
                        });
                    }
                    if persisted_run.record.status != RunStatus::Active {
                        return Err(UnparkError::BackendError(InfraError::corruption(
                            "unpark",
                            format!(
                                "shard {key:?} belongs to non-active run (status: {:?})",
                                persisted_run.record.status
                            ),
                        )));
                    }
                    if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                        return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                    }
                    if persisted.record.status != ShardStatus::Parked {
                        return Err(UnparkError::NotParked {
                            status: persisted.record.status,
                        });
                    }
                    let mut persisted = persisted;
                    persisted.record.advance_fence();
                    persisted.record.park_reason = None;
                    persisted.record.status = ShardStatus::Active;
                    persisted.record.lease = None;
                    persisted.record.op_log_push(OpLogEntry::new(
                        op_id,
                        OpKind::Unpark,
                        OpResult::Completed,
                        payload_hash,
                        now,
                    ));
                    persisted.record.assert_invariants(&persisted.slab);
                    encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                        .map_err(|e| {
                            UnparkError::BackendError(InfraError::corruption(
                                "unpark.encode_shard",
                                e,
                            ))
                        })?;
                    let srk = this
                        .keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                    let ok = this
                        .keyspace
                        .shard_owner_key(tenant, key.run(), key.shard());
                    let rk = this.keyspace.run_record_key(tenant, key.run());
                    let rak = this.keyspace.run_active_index_key(tenant, key.run());
                    let ask = this
                        .keyspace
                        .shard_active_index_key(tenant, key.run(), key.shard());
                    let mut txn = TxnBuilder::new();
                    txn.compare(super::compare_shard_revision(
                        srk.clone(),
                        persisted.mod_revision,
                    ))
                    .compare(super::compare_run_revision(rk, persisted_run.mod_revision))
                    .compare(super::compare_present(rak))
                    .compare(super::compare_absent(ok))
                    .put(srk.into_bytes(), shard_buf)
                    .put(ask.into_bytes(), Vec::<u8>::new());
                    txn.execute_async(this, IdempotentOutcome::Executed(()))
                        .await
                        .map_err(|e| {
                            UnparkError::BackendError(super::map_etcd_err("unpark.txn", e))
                        })
                })
            },
            |this| {
                Box::pin(async move {
                    let persisted = match this.load_shard_record(tenant, key).await {
                        Ok(Some(s)) => s,
                        Ok(None) => return Err(UnparkError::ShardNotFound),
                        Err(e) => {
                            return Err(UnparkError::BackendError(super::map_etcd_err(
                                "unpark.exhaust.load_shard",
                                e,
                            )));
                        }
                    };
                    if persisted.record.tenant != tenant {
                        return Err(UnparkError::TenantMismatch { expected: tenant });
                    }
                    let persisted_run = match this.load_run_record(tenant, key.run()).await {
                        Ok(Some(r)) => r,
                        Ok(None) => {
                            return Err(UnparkError::BackendError(InfraError::corruption(
                                "unpark.exhaust.load_run",
                                format!("run {:?} missing", key.run()),
                            )));
                        }
                        Err(e) => {
                            return Err(UnparkError::BackendError(super::map_etcd_err(
                                "unpark.exhaust.load_run",
                                e,
                            )));
                        }
                    };
                    if persisted_run.record.tenant != tenant {
                        return Err(UnparkError::TenantMismatch { expected: tenant });
                    }
                    if persisted_run.record.status.is_terminal() {
                        return Err(UnparkError::RunTerminal {
                            status: persisted_run.record.status,
                        });
                    }
                    if persisted_run.record.status != RunStatus::Active {
                        return Err(UnparkError::BackendError(InfraError::corruption(
                            "unpark.exhaust",
                            format!(
                                "shard {key:?} belongs to non-active run (status: {:?})",
                                persisted_run.record.status
                            ),
                        )));
                    }
                    if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                        return Ok(IdempotentOutcome::Replayed(()));
                    }
                    if persisted.record.status != ShardStatus::Parked {
                        return Err(UnparkError::NotParked {
                            status: persisted.record.status,
                        });
                    }
                    Err(UnparkError::BackendError(InfraError::transient(
                        "unpark",
                        "CAS retry budget exhausted",
                    )))
                })
            },
        )
        .await
    }
}
