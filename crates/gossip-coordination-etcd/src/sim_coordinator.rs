//! Deterministic simulation coordinator backed by [`SimulatedEtcdKV`].
//!
//! This adapter executes the same sync etcd coordination logic as
//! [`crate::EtcdCoordinator`] while persisting state into the in-memory etcd
//! model. A decoded cache of run and shard records powers
//! [`gossip_coordination::sim::SimIntrospection`] without changing the raw KV
//! layout exercised by the mutation path.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use etcd_client::{Compare, CompareOp, DeleteOptions, GetOptions, PutOptions, Txn, TxnOp};
use gossip_contracts::coordination::pooled::PooledSpawnedIter;
use gossip_coordination::{
    CapacityHint, IdempotentOutcome, InfraError, Lease, LogicalTime, OpId, RunId, RunOpKind,
    RunRecord, RunStatus, RunTransitionError, ShardId, ShardKey, ShardRecord, TenantId,
};

use crate::backend::coordinator::SyncEtcdLike;
use crate::backend::{
    CasOutcome, PersistedRun, PersistedShard, PersistedTenantShardCount, TenantShardCountMutation,
    TxnBuilder, apply_terminal_run_transition, compare_absent, compare_present,
    compare_run_revision, compare_tenant_shard_count_revision, decode_owner_kv,
    decode_tenant_shard_count_kv, encode_tenant_shard_count, make_decode_slab, map_etcd_err,
    u64_to_usize_saturating, usize_to_u64_saturating, validate_owner_consistency,
};
use crate::codec::{EtcdCodecError, decode_run_record, decode_shard_record, encode_run_record};
use crate::config::EtcdCoordinatorConfig;
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::{
    EtcdKeyspace, PersistedShardSubtreeKey, RunActiveIndexKey, RunRecordKey, ShardOwnerKey,
    ShardRecordKey,
};
use crate::sim_etcd_kv::{LeaseInfo, SimEtcdFaultConfig, SimulatedEtcdKV};

#[derive(Default)]
struct SimEtcdTestFaultState {
    rewrite_before_next_txn: Option<Vec<u8>>,
}

pub struct SimEtcdCoordinator {
    pub(crate) config: EtcdCoordinatorConfig,
    pub(crate) keyspace: EtcdKeyspace,
    kv: RefCell<SimulatedEtcdKV>,
    pub(crate) claim_candidates_scratch: Vec<ShardId>,
    shard_cache: HashMap<(TenantId, ShardKey), PersistedShard>,
    run_cache: HashMap<(TenantId, RunId), PersistedRun>,
    test_faults: RefCell<SimEtcdTestFaultState>,
}

impl SimEtcdCoordinator {
    pub fn new(config: EtcdCoordinatorConfig, seed: u64) -> Result<Self, EtcdCoordinatorError> {
        Self::with_kv(config, SimulatedEtcdKV::new(seed))
    }

    pub fn with_fault_config(
        config: EtcdCoordinatorConfig,
        seed: u64,
        fault_config: SimEtcdFaultConfig,
    ) -> Result<Self, EtcdCoordinatorError> {
        Self::with_kv(
            config,
            SimulatedEtcdKV::with_fault_config(seed, fault_config),
        )
    }

    pub fn with_kv(
        config: EtcdCoordinatorConfig,
        kv: SimulatedEtcdKV,
    ) -> Result<Self, EtcdCoordinatorError> {
        config.validate()?;
        let keyspace = EtcdKeyspace::new(config.namespace_prefix())?;
        Ok(Self {
            config,
            keyspace,
            kv: RefCell::new(kv),
            claim_candidates_scratch: Vec::new(),
            shard_cache: HashMap::new(),
            run_cache: HashMap::new(),
            test_faults: RefCell::new(SimEtcdTestFaultState::default()),
        })
    }

    #[must_use]
    pub fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    #[must_use]
    pub fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
    }

    pub fn set_fault_config(&self, config: SimEtcdFaultConfig) {
        self.kv.borrow_mut().set_fault_config(config);
    }

    #[must_use]
    pub fn kv_revision(&self) -> i64 {
        self.kv.borrow().revision()
    }

    #[must_use]
    pub fn kv_time(&self) -> u64 {
        self.kv.borrow().now()
    }

    #[must_use]
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.kv.borrow().contains_key(key)
    }

    #[must_use]
    pub fn lease_info(&self, lease_id: i64) -> Option<LeaseInfo> {
        self.kv.borrow().lease_info(lease_id)
    }

    pub fn list_active_runs_into(
        &self,
        tenant: TenantId,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut prefix = self.keyspace.runs_active_prefix(tenant);
        prefix.push('/');
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        out.clear();
        for kv in response.kvs() {
            if let Some(run) = RunActiveIndexKey::parse_direct_run_id(&prefix, kv.key()) {
                out.push(run);
            }
        }
        out.sort_unstable_by_key(|run| run.as_raw());
        Ok(())
    }

    pub fn gc_stale_initializing_runs_into(
        &mut self,
        tenant: TenantId,
        cutoff: LogicalTime,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut candidates = self.scan_tenant_runs(tenant)?;
        candidates.retain(|persisted| {
            persisted.record.status == RunStatus::Initializing
                && persisted.record.created_at < cutoff
        });
        candidates.sort_by(|left, right| {
            left.record
                .created_at
                .cmp(&right.record.created_at)
                .then_with(|| left.record.run.as_raw().cmp(&right.record.run.as_raw()))
        });

        out.clear();
        for persisted in candidates {
            let run = persisted.record.run;
            let run_key = self.keyspace.run_record_key(tenant, run);
            let active_key = self.keyspace.run_active_index_key(tenant, run);
            let shard_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
            let mut active_shard_prefix = self.keyspace.shards_active_prefix(tenant, run);
            active_shard_prefix.push('/');
            let removed_shard_count =
                self.count_persisted_shards_under_prefix(shard_prefix.clone())?;

            let counter_key = self.keyspace.tenant_shard_count_key(tenant);
            let (counter_compare, next_count) = if let Some(counter) =
                self.load_tenant_shard_count(tenant)?
            {
                let removed = usize_to_u64_saturating(removed_shard_count);
                let next = match counter.count.checked_sub(removed) {
                    Some(n) => n,
                    None => {
                        let scanned = self.count_persisted_shards_under_prefix(
                            self.keyspace.tenant_prefix(tenant),
                        )?;
                        usize_to_u64_saturating(scanned).saturating_sub(removed)
                    }
                };
                (
                    compare_tenant_shard_count_revision(counter_key.clone(), counter.mod_revision),
                    next,
                )
            } else {
                let scanned =
                    self.count_persisted_shards_under_prefix(self.keyspace.tenant_prefix(tenant))?;
                let next = usize_to_u64_saturating(scanned)
                    .saturating_sub(usize_to_u64_saturating(removed_shard_count));
                (compare_absent(counter_key.clone()), next)
            };

            let mut txn = TxnBuilder::new();
            txn.compare(compare_run_revision(
                run_key.clone(),
                persisted.mod_revision,
            ))
            .compare(compare_absent(active_key.clone()))
            .delete(run_key.into_bytes())
            .delete(active_key.into_bytes())
            .ops([
                TxnOp::delete(
                    shard_prefix.into_bytes(),
                    Some(DeleteOptions::new().with_prefix()),
                ),
                TxnOp::delete(
                    active_shard_prefix.into_bytes(),
                    Some(DeleteOptions::new().with_prefix()),
                ),
            ]);
            txn.compare(counter_compare).put(
                counter_key.into_bytes(),
                encode_tenant_shard_count(next_count),
            );

            let response = self.etcd_txn(txn.build())?;
            if response.succeeded() {
                self.drop_cached_run_state_inner(tenant, run);
                out.push(run);
            }
        }
        Ok(())
    }

    pub fn test_arm_run_revision_bump(&self, tenant: TenantId, run: RunId) {
        self.test_faults.borrow_mut().rewrite_before_next_txn =
            Some(self.keyspace.run_record_key(tenant, run).into_bytes());
    }

    fn sync_logical_time_inner(&self, now: LogicalTime) {
        let target = now.as_raw();
        let current = self.kv.borrow().now();
        if target <= current {
            return;
        }
        let mut kv = self.kv.borrow_mut();
        kv.set_time(target);
        kv.expire_due_leases();
    }

    fn refresh_cached_run_state_inner(
        &mut self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<(), EtcdCoordinatorError> {
        match <Self as SyncEtcdLike>::load_run_record(self, tenant, run)? {
            Some(persisted) => {
                self.run_cache.insert((tenant, run), persisted);
            }
            None => {
                self.run_cache.remove(&(tenant, run));
            }
        }

        self.shard_cache.retain(|(cached_tenant, cached_key), _| {
            *cached_tenant != tenant || cached_key.run() != run
        });
        for persisted in <Self as SyncEtcdLike>::scan_run_shards(self, tenant, run)? {
            let cache_key = ShardKey::new(run, persisted.record.shard);
            self.shard_cache.insert((tenant, cache_key), persisted);
        }
        Ok(())
    }

    fn drop_cached_run_state_inner(&mut self, tenant: TenantId, run: RunId) {
        self.run_cache.remove(&(tenant, run));
        self.shard_cache.retain(|(cached_tenant, cached_key), _| {
            *cached_tenant != tenant || cached_key.run() != run
        });
    }

    fn cached_shard_for_record(&self, record: &ShardRecord) -> Option<&PersistedShard> {
        self.shard_cache
            .get(&(record.tenant, ShardKey::new(record.run, record.shard)))
    }

    fn scan_tenant_runs(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<PersistedRun>, EtcdCoordinatorError> {
        let prefix = self.keyspace.run_records_scan_prefix(tenant);
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut out = Vec::new();
        for kv in response.kvs() {
            let Some(run_from_key) = RunRecordKey::parse_direct_run_id(&prefix, kv.key()) else {
                continue;
            };
            let record =
                decode_run_record(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                })?;
            if record.tenant != tenant {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "run record tenant disagrees with keyspace tenant",
                    },
                });
            }
            if record.run != run_from_key {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "run record run id disagrees with key suffix",
                    },
                });
            }
            out.push(PersistedRun {
                record,
                mod_revision: kv.mod_revision(),
            });
        }
        out.sort_unstable_by_key(|persisted| persisted.record.run.as_raw());
        Ok(out)
    }

    fn maybe_rewrite_key_before_txn(&self) -> Result<(), EtcdCoordinatorError> {
        let Some(key) = self.test_faults.borrow_mut().rewrite_before_next_txn.take() else {
            return Ok(());
        };

        let mut kv = self.kv.borrow_mut();
        let response =
            kv.get(key.clone(), None)
                .map_err(|source| EtcdCoordinatorError::Simulated {
                    operation: EtcdOperation::Get,
                    source,
                })?;
        let Some(current) = response.kvs().first() else {
            return Ok(());
        };
        let put = if current.lease() == 0 {
            TxnOp::put(key.clone(), current.value().to_vec(), None)
        } else {
            TxnOp::put(
                key.clone(),
                current.value().to_vec(),
                Some(PutOptions::new().with_lease(current.lease())),
            )
        };
        let txn = Txn::new()
            .when(vec![Compare::mod_revision(
                key,
                CompareOp::Equal,
                current.mod_revision(),
            )])
            .and_then(vec![put]);
        let response = kv
            .txn(txn)
            .map_err(|source| EtcdCoordinatorError::Simulated {
                operation: EtcdOperation::Txn,
                source,
            })?;
        debug_assert!(response.succeeded());
        Ok(())
    }
}

impl SyncEtcdLike for SimEtcdCoordinator {
    fn fail_unimplemented<T>(&self, operation: &'static str) -> T {
        panic!(
            "SimEtcdCoordinator::{operation} is not yet persisted to the simulated etcd backend; \
             this operation must be implemented before it is callable"
        );
    }

    fn sync_logical_time(&self, now: LogicalTime) {
        self.sync_logical_time_inner(now);
    }

    fn refresh_cached_run_state(
        &mut self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<(), EtcdCoordinatorError> {
        self.refresh_cached_run_state_inner(tenant, run)
    }

    fn cas_retry<T, E>(
        &mut self,
        mut attempt: impl FnMut(&mut Self, usize) -> Result<CasOutcome<T>, E>,
        on_exhaustion: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let max_retries = self.config.optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            match attempt(self, attempt_num)? {
                CasOutcome::Committed(val) => return Ok(val),
                CasOutcome::RetryNeeded => {
                    if attempt_num + 1 < max_retries {
                        std::thread::sleep(crate::backend::cas_retry_delay(attempt_num));
                    }
                }
            }
        }
        on_exhaustion(self)
    }

    fn load_shard_and_validate_lease<E>(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        map_not_found: impl FnOnce(ShardKey) -> E,
        map_load_error: impl FnOnce(EtcdCoordinatorError) -> E,
        map_stale_fence: impl FnOnce(
            gossip_coordination::FenceEpoch,
            gossip_coordination::FenceEpoch,
        ) -> E,
    ) -> Result<PersistedShard, E>
    where
        E: From<gossip_coordination::CoordError>,
    {
        let key = lease.shard_key();
        let persisted = match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => shard,
            Ok(None) => return Err(map_not_found(key)),
            Err(err) => return Err(map_load_error(err)),
        };
        gossip_coordination::validate_lease(now, tenant, lease, &persisted.record)?;
        if !persisted.owner_matches_lease(lease) {
            return Err(map_stale_fence(lease.fence(), persisted.record.fence_epoch));
        }
        Ok(persisted)
    }

    fn etcd_get(
        &self,
        key: Vec<u8>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError> {
        self.kv
            .borrow_mut()
            .get(key, options)
            .map_err(|source| EtcdCoordinatorError::Simulated {
                operation: EtcdOperation::Get,
                source,
            })
    }

    fn etcd_txn(&self, txn: Txn) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError> {
        self.maybe_rewrite_key_before_txn()?;
        self.kv
            .borrow_mut()
            .txn(txn)
            .map_err(|source| EtcdCoordinatorError::Simulated {
                operation: EtcdOperation::Txn,
                source,
            })
    }

    fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError> {
        self.kv
            .borrow_mut()
            .lease_grant(ttl)
            .map_err(|source| EtcdCoordinatorError::Simulated {
                operation: EtcdOperation::LeaseGrant,
                source,
            })
    }

    fn etcd_lease_keep_alive_once(&self, lease_id: i64) -> Result<(), EtcdCoordinatorError> {
        self.kv
            .borrow_mut()
            .lease_keep_alive_once(lease_id)
            .map_err(|source| EtcdCoordinatorError::Simulated {
                operation: EtcdOperation::LeaseKeepAlive,
                source,
            })
    }

    fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError> {
        self.kv
            .borrow_mut()
            .lease_revoke(lease_id)
            .map_err(|source| EtcdCoordinatorError::Simulated {
                operation: EtcdOperation::LeaseRevoke,
                source,
            })
    }

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
        if record.tenant != tenant {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "run record tenant disagrees with key-path tenant",
                },
            });
        }
        if record.run != run {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "run record run id disagrees with key-path run id",
                },
            });
        }

        Ok(Some(PersistedRun {
            record,
            mod_revision: kv.mod_revision(),
        }))
    }

    fn load_tenant_shard_count(
        &self,
        tenant: TenantId,
    ) -> Result<Option<PersistedTenantShardCount>, EtcdCoordinatorError> {
        let key = self.keyspace.tenant_shard_count_key(tenant).into_bytes();
        let response = self.etcd_get(key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        Ok(Some(decode_tenant_shard_count_kv(kv)?))
    }

    fn prepare_tenant_shard_count_mutation(
        &self,
        tenant: TenantId,
        additional: usize,
    ) -> Result<TenantShardCountMutation, EtcdCoordinatorError> {
        let counter_key = self.keyspace.tenant_shard_count_key(tenant);
        let delta = usize_to_u64_saturating(additional);
        if let Some(counter) = self.load_tenant_shard_count(tenant)? {
            return Ok(TenantShardCountMutation {
                key: counter_key.clone(),
                current_count: u64_to_usize_saturating(counter.count),
                next_count: counter.count.saturating_add(delta),
                compare: compare_tenant_shard_count_revision(counter_key, counter.mod_revision),
            });
        }

        let scanned =
            self.count_persisted_shards_under_prefix(self.keyspace.tenant_prefix(tenant))?;
        Ok(TenantShardCountMutation {
            key: counter_key.clone(),
            current_count: scanned,
            next_count: usize_to_u64_saturating(scanned).saturating_add(delta),
            compare: compare_absent(counter_key),
        })
    }

    fn load_shard_record(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<PersistedShard>, EtcdCoordinatorError> {
        let shard_record_key = self
            .keyspace
            .shard_record_key(tenant, key.run(), key.shard());
        let owner_key = shard_record_key.owner_key();
        let response = self.etcd_get(
            shard_record_key.clone().into_bytes(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut record_kv: Option<&etcd_client::KeyValue> = None;
        let mut owner_kv: Option<&etcd_client::KeyValue> = None;
        for kv in response.kvs() {
            if kv.key() == shard_record_key.as_bytes() {
                record_kv = Some(kv);
            } else if kv.key() == owner_key.as_bytes() {
                owner_kv = Some(kv);
            }
        }

        let Some(kv) = record_kv else {
            return Ok(None);
        };

        let mut slab = make_decode_slab(kv.value().len());
        let record = decode_shard_record(kv.value(), &mut slab).map_err(|source| {
            EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            }
        })?;
        if record.tenant != tenant {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record tenant disagrees with key-path tenant",
                },
            });
        }
        if record.run != key.run() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record run id disagrees with key-path run id",
                },
            });
        }
        if record.shard != key.shard() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record shard id disagrees with key-path shard id",
                },
            });
        }

        let owner = match owner_kv {
            None => None,
            Some(okv) => Some(decode_owner_kv(okv)?),
        };
        if let Some(owner) = &owner {
            validate_owner_consistency(owner, &record)?;
        }

        Ok(Some(PersistedShard {
            record,
            slab,
            mod_revision: kv.mod_revision(),
            owner,
        }))
    }

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

        let mut owner_map = HashMap::<ShardOwnerKey, crate::backend::PersistedOwner>::new();
        let mut record_kvs = Vec::<(ShardRecordKey, Vec<u8>, i64)>::new();
        for kv in response.kvs() {
            match PersistedShardSubtreeKey::classify(kv.key()) {
                Some(PersistedShardSubtreeKey::Owner) => {
                    let owner_key = ShardOwnerKey::from_encoded_key(kv.key()).ok_or_else(|| {
                        EtcdCoordinatorError::Codec {
                            operation: EtcdOperation::Get,
                            source: EtcdCodecError::InvariantViolation {
                                kind: "OwnerKey",
                                detail: "owner key under shard scan prefix is malformed",
                            },
                        }
                    })?;
                    owner_map.insert(owner_key, decode_owner_kv(kv)?);
                }
                Some(PersistedShardSubtreeKey::Record) => {
                    let record_key =
                        ShardRecordKey::from_encoded_key(kv.key()).ok_or_else(|| {
                            EtcdCoordinatorError::Codec {
                                operation: EtcdOperation::Get,
                                source: EtcdCodecError::InvariantViolation {
                                    kind: "ShardRecord",
                                    detail: "shard record key under scan prefix is malformed",
                                },
                            }
                        })?;
                    record_kvs.push((record_key, kv.value().to_vec(), kv.mod_revision()));
                }
                None => {
                    return Err(EtcdCoordinatorError::Codec {
                        operation: EtcdOperation::Get,
                        source: EtcdCodecError::InvariantViolation {
                            kind: "ShardKey",
                            detail: "unexpected key found under shard scan prefix",
                        },
                    });
                }
            }
        }

        let mut out = Vec::with_capacity(record_kvs.len());
        for (record_key, value, mod_revision) in record_kvs {
            let mut slab = make_decode_slab(value.len());
            let record = decode_shard_record(&value, &mut slab).map_err(|source| {
                EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                }
            })?;
            if record.tenant != tenant || record.run != run {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "shard record identity disagrees with scan prefix",
                    },
                });
            }
            let expected_key = self.keyspace.shard_record_key(tenant, run, record.shard);
            if record_key != expected_key {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "shard record shard id disagrees with key path",
                    },
                });
            }
            let owner = owner_map.remove(&record_key.owner_key());
            if let Some(owner) = &owner {
                validate_owner_consistency(owner, &record)?;
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
        let total_active = u32::try_from(active_response.count()).unwrap_or(u32::MAX);

        let shards_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
        let keys_response = self.etcd_get(
            shards_prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        let owned_count = u32::try_from(
            keys_response
                .kvs()
                .iter()
                .filter(|kv| {
                    ShardOwnerKey::parse_owned_shard(shards_prefix.as_bytes(), kv.key()).is_some()
                })
                .count(),
        )
        .unwrap_or(u32::MAX);

        Ok(CapacityHint {
            available_count: total_active.saturating_sub(owned_count),
            earliest_deadline: None,
        })
    }

    fn count_persisted_shards_under_prefix(
        &self,
        prefix: String,
    ) -> Result<usize, EtcdCoordinatorError> {
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        Ok(response
            .kvs()
            .iter()
            .filter(|kv| {
                PersistedShardSubtreeKey::classify(kv.key())
                    == Some(PersistedShardSubtreeKey::Record)
            })
            .count())
    }

    fn transition_run_terminal(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
        op_kind: RunOpKind,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let (target_status, payload_hash, require_active) = match op_kind {
            RunOpKind::CompleteRun => (
                RunStatus::Done,
                gossip_coordination::hash_complete_run_payload(),
                true,
            ),
            RunOpKind::FailRun => (
                RunStatus::Failed,
                gossip_coordination::hash_fail_run_payload(),
                true,
            ),
            RunOpKind::CancelRun => (
                RunStatus::Cancelled,
                gossip_coordination::hash_cancel_run_payload(),
                false,
            ),
            RunOpKind::RegisterShards => {
                unreachable!("transition_run_terminal does not handle RegisterShards")
            }
        };

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_run_record(tenant, run) {
                    Ok(Some(run_record)) => run_record,
                    Ok(None) => return Err(RunTransitionError::RunNotFound),
                    Err(err) => {
                        return Err(RunTransitionError::BackendError(map_etcd_err(
                            "run_terminal.load_run",
                            err,
                        )));
                    }
                };
                let prior_status = persisted.record.status;
                let mut record = persisted.record;

                if record.tenant != tenant {
                    return Err(RunTransitionError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != op_kind {
                        return Err(RunTransitionError::BackendError(InfraError::corruption(
                            "run_terminal.idempotent_replay",
                            format!(
                                "kind mismatch: expected {op_kind:?}, got {:?}",
                                entry.kind()
                            ),
                        )));
                    }
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                }
                if record.status.is_terminal() {
                    return Err(RunTransitionError::RunTerminal {
                        status: record.status,
                    });
                }
                if require_active && record.status != RunStatus::Active {
                    return Err(RunTransitionError::WrongStatus {
                        status: record.status,
                        target: target_status,
                    });
                }

                apply_terminal_run_transition(
                    &mut record,
                    now,
                    target_status,
                    op_id,
                    op_kind,
                    payload_hash,
                );
                let run_blob = encode_run_record(&record);
                let run_key = this.keyspace.run_record_key(tenant, run);
                let active_key = this.keyspace.run_active_index_key(tenant, run);
                let mut compares = vec![compare_run_revision(
                    run_key.clone(),
                    persisted.mod_revision,
                )];
                match prior_status {
                    RunStatus::Active => compares.push(compare_present(active_key.clone())),
                    RunStatus::Initializing => compares.push(compare_absent(active_key.clone())),
                    RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled => {
                        unreachable!("terminal statuses return early")
                    }
                }

                let mut txn = TxnBuilder::new();
                txn.compare_all(compares)
                    .put(run_key.into_bytes(), run_blob)
                    .delete(active_key.into_bytes());
                txn.execute(this, IdempotentOutcome::Executed(()))
                    .map_err(|err| {
                        RunTransitionError::BackendError(map_etcd_err("run_terminal.txn", err))
                    })
            },
            |this| {
                let persisted = match this.load_run_record(tenant, run) {
                    Ok(Some(r)) => r,
                    Ok(None) if !require_active => return Err(RunTransitionError::RunNotFound),
                    Ok(None) => {
                        return Err(RunTransitionError::BackendError(InfraError::corruption(
                            "run_terminal.exhaust.load_run",
                            format!("run {run:?} missing (expected Active)"),
                        )));
                    }
                    Err(err) => {
                        return Err(RunTransitionError::BackendError(map_etcd_err(
                            "run_terminal.exhaust.load_run",
                            err,
                        )));
                    }
                };
                if persisted.record.tenant != tenant {
                    return Err(RunTransitionError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = persisted.record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != op_kind {
                        return Err(RunTransitionError::BackendError(InfraError::corruption(
                            "run_terminal.idempotent_replay",
                            format!(
                                "kind mismatch: expected {op_kind:?}, got {:?}",
                                entry.kind()
                            ),
                        )));
                    }
                    return Ok(IdempotentOutcome::Replayed(()));
                }
                if persisted.record.status.is_terminal() {
                    return Err(RunTransitionError::RunTerminal {
                        status: persisted.record.status,
                    });
                }
                if require_active && persisted.record.status != RunStatus::Active {
                    return Err(RunTransitionError::WrongStatus {
                        status: persisted.record.status,
                        target: target_status,
                    });
                }

                Err(RunTransitionError::BackendError(InfraError::transient(
                    "run_terminal",
                    "CAS retry budget exhausted",
                )))
            },
        )
    }

    fn best_effort_revoke_lease(&self, lease_id: i64) {
        if lease_id <= 0 {
            return;
        }
        if let Err(err) = self.etcd_lease_revoke(lease_id) {
            tracing::warn!(
                lease_id,
                %err,
                ttl_secs = self.config.owner_lease_ttl_secs(),
                "failed to revoke simulated etcd lease; will expire via TTL",
            );
        }
    }

    fn load_run_checked(
        &self,
        context: &'static str,
        tenant: TenantId,
        run: RunId,
    ) -> Result<PersistedRun, InfraError> {
        match self.load_run_record(tenant, run) {
            Ok(Some(run_record)) => Ok(run_record),
            Ok(None) => Err(InfraError::corruption(
                context,
                format!("run {run:?} missing"),
            )),
            Err(err) => Err(map_etcd_err(context, err)),
        }
    }

    fn load_shard_checked(
        &self,
        context: &'static str,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<PersistedShard, InfraError> {
        match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => Ok(shard),
            Ok(None) => Err(InfraError::corruption(
                context,
                format!("shard {key:?} missing"),
            )),
            Err(err) => Err(map_etcd_err(context, err)),
        }
    }
}

pub struct SimEtcdShardIter<'a> {
    inner: std::collections::hash_map::Iter<'a, (TenantId, ShardKey), PersistedShard>,
}

impl<'a> Iterator for SimEtcdShardIter<'a> {
    type Item = ((TenantId, ShardKey), &'a ShardRecord);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(&(tenant, key), persisted)| ((tenant, key), &persisted.record))
    }
}

pub struct SimEtcdRunIter<'a> {
    inner: std::collections::hash_map::Iter<'a, (TenantId, RunId), PersistedRun>,
}

impl<'a> Iterator for SimEtcdRunIter<'a> {
    type Item = ((TenantId, RunId), &'a RunRecord);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(&(tenant, run), persisted)| ((tenant, run), &persisted.record))
    }
}

pub struct SimEtcdSpawnedIter<'a> {
    inner: PooledSpawnedIter<'a>,
}

impl<'a> Iterator for SimEtcdSpawnedIter<'a> {
    type Item = ShardId;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl gossip_coordination::sim::backend::SimIntrospection for SimEtcdCoordinator {
    type ShardIter<'a>
        = SimEtcdShardIter<'a>
    where
        Self: 'a;
    type RunIter<'a>
        = SimEtcdRunIter<'a>
    where
        Self: 'a;
    type SpawnedIter<'a>
        = SimEtcdSpawnedIter<'a>
    where
        Self: 'a;

    fn shards(&self) -> Self::ShardIter<'_> {
        SimEtcdShardIter {
            inner: self.shard_cache.iter(),
        }
    }

    fn runs(&self) -> Self::RunIter<'_> {
        SimEtcdRunIter {
            inner: self.run_cache.iter(),
        }
    }

    fn shard_count(&self) -> usize {
        self.shard_cache.len()
    }

    fn shard_lookup(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord> {
        self.shard_cache
            .get(&(*tenant, *key))
            .map(|persisted| &persisted.record)
    }

    fn cursor_last_key<'a>(&'a self, record: &'a ShardRecord) -> Option<&'a [u8]> {
        let cached = self
            .cached_shard_for_record(record)
            .expect("SimEtcdCoordinator introspection record missing from cache");
        record.cursor.last_key(&cached.slab)
    }

    fn spec_bounds<'a>(&'a self, record: &'a ShardRecord) -> (&'a [u8], &'a [u8]) {
        let cached = self
            .cached_shard_for_record(record)
            .expect("SimEtcdCoordinator introspection record missing from cache");
        (
            record.spec.key_range_start(&cached.slab),
            record.spec.key_range_end(&cached.slab),
        )
    }

    fn validate_record_invariants(&self, record: &ShardRecord) -> Result<(), String> {
        let cached = self
            .cached_shard_for_record(record)
            .expect("SimEtcdCoordinator introspection record missing from cache");
        record.validate_invariants(&cached.slab)
    }

    fn spawned_children<'a>(&'a self, record: &'a ShardRecord) -> Self::SpawnedIter<'a> {
        let cached = self
            .cached_shard_for_record(record)
            .expect("SimEtcdCoordinator introspection record missing from cache");
        SimEtcdSpawnedIter {
            inner: record.spawned.iter(&cached.slab),
        }
    }

    fn release_record_fields(&mut self, _record: &mut ShardRecord) {}
}

impl fmt::Debug for SimEtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimEtcdCoordinator")
            .field("namespace_prefix", &self.keyspace.prefix())
            .field("kv_revision", &self.kv_revision())
            .field("cached_runs", &self.run_cache.len())
            .field("cached_shards", &self.shard_cache.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::SimEtcdCoordinator;
    use crate::{EtcdCoordinatorConfig, decode_owner_value};
    use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, ShardSpecRef};
    use gossip_contracts::identity::{
        LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
    };
    use gossip_coordination::sim::{
        CoordinationSim, FaultLevel, SimEvent, SimIntrospection, SimOp,
    };
    use gossip_coordination::{
        AcquireScratch, CoordinationBackend, IdempotentOutcome, InitialShardInput, RunConfig,
        RunManagement, RunStatus,
    };

    fn test_backend(seed: u64) -> SimEtcdCoordinator {
        let config =
            EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/sim-etcd-tests")
                .expect("hard-coded sim config must be valid");
        SimEtcdCoordinator::new(config, seed).expect("sim coordinator should construct")
    }

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_shard() -> ShardId {
        ShardId::from_raw(1)
    }

    fn test_worker(raw: u64) -> WorkerId {
        WorkerId::from_raw(raw)
    }

    fn now(raw: u64) -> LogicalTime {
        LogicalTime::from_raw(raw)
    }

    fn seed_single_shard_run(backend: &mut SimEtcdCoordinator) -> ShardKey {
        let tenant = test_tenant();
        let run = test_run();
        let shard = test_shard();
        let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5))
            .expect("test run config must be valid");
        backend
            .create_run(now(1), tenant, run, config)
            .expect("create_run should succeed");

        let manifest = [InitialShardInput::new(
            shard,
            ShardSpecRef::new(b"a", b"z", b"meta"),
            CursorUpdate::initial(),
        )];
        let outcome = backend
            .register_shards(now(2), tenant, run, &manifest, OpId::from_raw(11))
            .expect("register_shards should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(_)));

        ShardKey::new(run, shard)
    }

    #[test]
    fn acquire_persists_owner_key_with_simulated_lease() {
        let mut backend = test_backend(7);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(9), &mut scratch)
            .expect("acquire should succeed");

        let owner_key = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let response = backend
            .kv
            .borrow_mut()
            .get(owner_key, None)
            .expect("owner lookup should succeed");
        let kv = response
            .kvs()
            .first()
            .expect("owner key must exist after acquire");
        let owner = decode_owner_value(kv.value()).expect("owner blob must decode");

        assert_eq!(owner.worker, test_worker(9));
        assert_eq!(owner.fence, acquire.lease.fence());
        assert!(
            kv.lease() > 0,
            "owner key must be attached to a simulated lease"
        );

        let lease = backend
            .lease_info(kv.lease())
            .expect("simulated lease must still exist");
        assert_eq!(lease.attached_key_count, 1);
        assert_eq!(lease.expires_at, backend.kv_time() + lease.ttl);
    }

    #[test]
    fn sim_introspection_round_trips_cached_records() {
        let mut backend = test_backend(11);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let lease = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(5), &mut scratch)
            .expect("acquire should succeed")
            .lease;
        let _ = backend
            .checkpoint(
                now(4),
                test_tenant(),
                &lease,
                &CursorUpdate::new(b"m"),
                OpId::from_raw(12),
            )
            .expect("checkpoint should succeed");

        let record = backend
            .shard_lookup(&test_tenant(), &key)
            .expect("cached shard record must be present");
        let cached = backend
            .cached_shard_for_record(record)
            .expect("cached shard state must back introspection");
        let (start, end) = backend.spec_bounds(record);
        let runs: Vec<_> = backend
            .runs()
            .map(|((tenant, run), record)| (tenant, run, record.status, record.root_shards.clone()))
            .collect();

        assert_eq!(backend.shard_count(), 1);
        assert_eq!(start, b"a");
        assert_eq!(end, b"z");
        assert_eq!(backend.cursor_last_key(record), Some(b"m".as_slice()));
        assert_eq!(record.spec.metadata(&cached.slab), b"meta");
        assert!(backend.validate_record_invariants(record).is_ok());
        assert_eq!(backend.spawned_children(record).count(), 0);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].0, test_tenant());
        assert_eq!(runs[0].1, test_run());
        assert_eq!(runs[0].2, RunStatus::Active);
        assert_eq!(runs[0].3, vec![test_shard()]);
    }

    #[test]
    fn simulation_harness_steps_pass_invariants_with_sim_etcd_backend() {
        let mut backend = test_backend(23);
        let key = seed_single_shard_run(&mut backend);
        let worker = test_worker(1);

        let mut sim = CoordinationSim::with_backend(23, FaultLevel::SunnyDay, backend);
        sim.add_worker(worker);

        let (event, violations) = sim.step(SimOp::AdvanceTime { ticks: 3 });
        assert!(matches!(event, SimEvent::TimeAdvanced { .. }));
        assert!(
            violations.is_empty(),
            "advance must preserve all invariants"
        );

        let (event, violations) = sim.step(SimOp::Acquire { worker, key });
        assert!(matches!(event, SimEvent::AcquireOk { .. }));
        assert!(
            violations.is_empty(),
            "acquire must preserve all invariants"
        );

        let (event, violations) = sim.step(SimOp::Checkpoint { worker, key });
        assert!(matches!(event, SimEvent::CheckpointOk));
        assert!(
            violations.is_empty(),
            "checkpoint must preserve all invariants"
        );
    }

    #[test]
    fn register_shards_retries_after_forced_run_revision_bump() {
        let mut backend = test_backend(31);
        let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5))
            .expect("test run config must be valid");
        backend
            .create_run(now(1), test_tenant(), test_run(), config)
            .expect("create_run should succeed");

        backend.test_arm_run_revision_bump(test_tenant(), test_run());
        let manifest = [InitialShardInput::new(
            test_shard(),
            ShardSpecRef::new(b"a", b"z", b"meta"),
            CursorUpdate::initial(),
        )];
        let outcome = backend
            .register_shards(
                now(2),
                test_tenant(),
                test_run(),
                &manifest,
                OpId::from_raw(13),
            )
            .expect("register_shards should retry and succeed");
        let mut active_runs = Vec::new();
        backend
            .list_active_runs_into(test_tenant(), &mut active_runs)
            .expect("active run scan should succeed");

        assert!(matches!(outcome, IdempotentOutcome::Executed(_)));
        assert_eq!(
            backend.kv_revision(),
            3,
            "forced rewrite should consume one revision before the successful register_shards CAS"
        );
        assert_eq!(active_runs, vec![test_run()]);
    }
}
