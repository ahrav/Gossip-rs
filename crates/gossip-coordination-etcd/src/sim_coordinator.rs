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

use etcd_client::{Compare, CompareOp, GetOptions, PutOptions, Txn, TxnOp};
use gossip_contracts::coordination::pooled::PooledSpawnedIter;
use gossip_coordination::{
    LogicalTime, RunId, RunRecord, ShardId, ShardKey, ShardRecord, TenantId,
};

use crate::backend::coordinator::SyncEtcdLike;
use crate::backend::{PersistedRun, PersistedShard};
use crate::config::EtcdCoordinatorConfig;
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::EtcdKeyspace;
use crate::sim_etcd_kv::{LeaseInfo, SimEtcdFaultConfig, SimulatedEtcdKV};

#[derive(Default)]
struct SimEtcdTestFaultState {
    rewrite_before_next_txn: Option<Vec<u8>>,
}

/// Deterministic simulation coordinator backed by [`SimulatedEtcdKV`].
///
/// # Thread Safety
///
/// This coordinator uses `RefCell` for interior mutability and is
/// `!Send + !Sync`. All method calls must be non-reentrant — nested
/// `SyncEtcdLike` calls through the same reference will panic at runtime.
pub struct SimEtcdCoordinator {
    pub(crate) config: EtcdCoordinatorConfig,
    pub(crate) keyspace: EtcdKeyspace,
    kv: RefCell<SimulatedEtcdKV>,
    pub(crate) claim_candidates_scratch: Vec<ShardId>,
    shard_cache: HashMap<(TenantId, ShardKey), PersistedShard>,
    /// Reverse index: (tenant, run) → set of ShardKeys in shard_cache.
    /// Enables O(1) run-scoped invalidation instead of O(N) HashMap scan.
    shard_run_index: HashMap<(TenantId, RunId), Vec<ShardKey>>,
    run_cache: HashMap<(TenantId, RunId), PersistedRun>,
    /// Lease IDs expired by `sync_logical_time_inner` that haven't been
    /// flushed to the shard cache yet. Deferred because `sync_logical_time`
    /// is `&self` (called from read-only trait methods) while shard_cache
    /// mutation requires `&mut self`.
    expired_lease_buffer: RefCell<Vec<i64>>,
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
            shard_run_index: HashMap::new(),
            run_cache: HashMap::new(),
            expired_lease_buffer: RefCell::new(Vec::new()),
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
        // Expire any due leases before scanning active runs.
        // Buffer expired IDs for deferred cache invalidation — identical
        // to the buffering in sync_logical_time_inner.
        let expired_ids = self.kv.borrow_mut().expire_due_leases();
        if !expired_ids.is_empty() {
            self.expired_lease_buffer.borrow_mut().extend(expired_ids);
        }
        <Self as SyncEtcdLike>::list_active_runs_into(self, tenant, out)
    }

    pub fn gc_stale_initializing_runs_into(
        &mut self,
        tenant: TenantId,
        cutoff: LogicalTime,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        self.sync_logical_time_inner(cutoff);
        self.flush_expired_lease_cache();
        <Self as SyncEtcdLike>::gc_stale_initializing_runs_into(self, tenant, cutoff, out)
    }

    pub fn test_arm_run_revision_bump(&self, tenant: TenantId, run: RunId) {
        self.test_faults.borrow_mut().rewrite_before_next_txn =
            Some(self.keyspace.run_record_key(tenant, run).into_bytes());
    }

    /// Advance simulation time and expire due leases.
    ///
    /// Expired lease IDs are buffered for deferred cache invalidation in
    /// the next `&mut self` method (see [`flush_expired_lease_cache`]).
    /// This keeps `sync_logical_time` callable from `&self` trait methods.
    ///
    /// Returns `true` if any leases expired (keys may have been deleted).
    fn sync_logical_time_inner(&self, now: LogicalTime) -> bool {
        let target = now.as_raw();
        let mut kv = self.kv.borrow_mut();
        if target <= kv.now() {
            return false;
        }
        kv.set_time(target);
        let expired_ids = kv.expire_due_leases();
        if !expired_ids.is_empty() {
            self.expired_lease_buffer.borrow_mut().extend(expired_ids);
            return true;
        }
        false
    }

    /// Drain buffered expired lease IDs and clear cached owner bindings
    /// for any shards whose etcd lease was revoked by TTL expiry.
    fn flush_expired_lease_cache(&mut self) {
        let expired = self.expired_lease_buffer.get_mut();
        if expired.is_empty() {
            return;
        }
        let expired_set: std::collections::HashSet<i64> = expired.iter().copied().collect();
        for persisted in self.shard_cache.values_mut() {
            if let Some(ref owner) = persisted.owner
                && expired_set.contains(&owner.lease_id)
            {
                persisted.owner = None;
            }
        }
        expired.clear();
    }

    fn refresh_cached_run_state_inner(
        &mut self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<(), EtcdCoordinatorError> {
        self.flush_expired_lease_cache();

        // Perform both reads before committing any cache mutations so a
        // failure in the second read doesn't leave caches half-updated.
        let run_entry = <Self as SyncEtcdLike>::load_run_record(self, tenant, run)?;
        let shard_entries = <Self as SyncEtcdLike>::scan_run_shards(self, tenant, run)?;

        // Both reads succeeded — commit atomically to caches.
        match run_entry {
            Some(persisted) => {
                self.run_cache.insert((tenant, run), persisted);
            }
            None => {
                self.run_cache.remove(&(tenant, run));
            }
        }
        if let Some(old_keys) = self.shard_run_index.remove(&(tenant, run)) {
            for key in old_keys {
                self.shard_cache.remove(&(tenant, key));
            }
        }
        let mut index_keys = Vec::with_capacity(shard_entries.len());
        for persisted in shard_entries {
            let cache_key = ShardKey::new(run, persisted.record.shard);
            index_keys.push(cache_key);
            self.shard_cache.insert((tenant, cache_key), persisted);
        }
        self.shard_run_index.insert((tenant, run), index_keys);
        Ok(())
    }

    fn drop_cached_run_state_inner(&mut self, tenant: TenantId, run: RunId) {
        self.run_cache.remove(&(tenant, run));
        if let Some(keys) = self.shard_run_index.remove(&(tenant, run)) {
            for key in keys {
                self.shard_cache.remove(&(tenant, key));
            }
        }
    }

    fn cached_shard_for_record(&self, record: &ShardRecord) -> Option<&PersistedShard> {
        self.shard_cache
            .get(&(record.tenant, ShardKey::new(record.run, record.shard)))
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
    fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
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

    /// Deterministic simulation: no real contention, skip wall-clock sleep.
    fn cas_retry_backoff(&self, _attempt: usize) {}

    fn on_gc_run(&mut self, tenant: TenantId, run: RunId) {
        self.drop_cached_run_state_inner(tenant, run);
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
        let cached = self.cached_shard_for_record(record)?;
        record.cursor.last_key(&cached.slab)
    }

    fn spec_bounds<'a>(&'a self, record: &'a ShardRecord) -> (&'a [u8], &'a [u8]) {
        let Some(cached) = self.cached_shard_for_record(record) else {
            tracing::warn!(
                tenant = %record.tenant,
                run = ?record.run,
                shard = ?record.shard,
                cache_size = self.shard_cache.len(),
                "SimIntrospection::spec_bounds: shard missing from cache",
            );
            return (&[], &[]);
        };
        (
            record.spec.key_range_start(&cached.slab),
            record.spec.key_range_end(&cached.slab),
        )
    }

    fn validate_record_invariants(&self, record: &ShardRecord) -> Result<(), String> {
        let Some(cached) = self.cached_shard_for_record(record) else {
            return Err(format!(
                "shard ({}, {}, {}) missing from cache (cache size: {})",
                record.tenant,
                record.run,
                record.shard,
                self.shard_cache.len(),
            ));
        };
        record.validate_invariants(&cached.slab)
    }

    fn spawned_children<'a>(&'a self, record: &'a ShardRecord) -> Self::SpawnedIter<'a> {
        let Some(cached) = self.cached_shard_for_record(record) else {
            // Empty spawned lists need no slab access — return a zero-item
            // iterator. Non-empty lists require the slab for decoding, so
            // that case remains a hard failure.
            if record.spawned.is_empty() {
                tracing::warn!(
                    tenant = %record.tenant,
                    run = ?record.run,
                    shard = ?record.shard,
                    cache_size = self.shard_cache.len(),
                    "SimIntrospection::spawned_children: shard missing from cache (empty spawned)",
                );
                return SimEtcdSpawnedIter {
                    inner: PooledSpawnedIter::empty(),
                };
            }
            panic!(
                "SimIntrospection::spawned_children: shard ({}, {}, {}) with {} children \
                 missing from cache (cache size: {})",
                record.tenant,
                record.run,
                record.shard,
                record.spawned.len(),
                self.shard_cache.len(),
            );
        };
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
    use crate::sim_etcd_kv::SimEtcdFaultConfig;
    use crate::{EtcdCoordinatorConfig, decode_owner_value};
    use gossip_contracts::coordination::{
        CursorSemantics, CursorUpdate, ShardSpecRef, SplitReplaceChild, SplitReplacePlan,
        plan_split_residual_at_point,
    };
    use gossip_contracts::identity::{
        LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
    };
    use gossip_coordination::sim::{
        CoordinationSim, FaultLevel, SimEvent, SimIntrospection, SimOp,
    };
    use gossip_coordination::{
        AcquireScratch, CheckpointError, CoordinationBackend, IdempotentOutcome, InitialShardInput,
        ParkReason, RunConfig, RunManagement, RunStatus, ShardClaiming, ShardFilter, ShardStatus,
        ShardSummary,
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

    fn seed_multi_shard_run(backend: &mut SimEtcdCoordinator) -> Vec<ShardKey> {
        let tenant = test_tenant();
        let run = test_run();
        let shard1 = ShardId::from_raw(1);
        let shard2 = ShardId::from_raw(2);
        let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5))
            .expect("test run config must be valid");
        backend
            .create_run(now(1), tenant, run, config)
            .expect("create_run should succeed");

        let manifest = [
            InitialShardInput::new(
                shard1,
                ShardSpecRef::new(b"a", b"m", b"meta1"),
                CursorUpdate::initial(),
            ),
            InitialShardInput::new(
                shard2,
                ShardSpecRef::new(b"m", b"z", b"meta2"),
                CursorUpdate::initial(),
            ),
        ];
        let outcome = backend
            .register_shards(now(2), tenant, run, &manifest, OpId::from_raw(11))
            .expect("register_shards should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(_)));

        vec![ShardKey::new(run, shard1), ShardKey::new(run, shard2)]
    }

    // ---- Run lifecycle tests ----

    #[test]
    fn complete_run_transitions_active_to_done() {
        let mut backend = test_backend(40);
        seed_single_shard_run(&mut backend);

        let outcome = backend
            .complete_run(now(10), test_tenant(), test_run(), OpId::from_raw(20))
            .expect("complete_run should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(())));

        let record = backend
            .get_run(test_tenant(), test_run())
            .expect("get_run should succeed after completion");
        assert_eq!(record.status, RunStatus::Done);
    }

    #[test]
    fn fail_run_transitions_active_to_failed() {
        let mut backend = test_backend(41);
        seed_single_shard_run(&mut backend);

        let outcome = backend
            .fail_run(now(10), test_tenant(), test_run(), OpId::from_raw(21))
            .expect("fail_run should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(())));

        let record = backend
            .get_run(test_tenant(), test_run())
            .expect("get_run should succeed after failure");
        assert_eq!(record.status, RunStatus::Failed);
    }

    #[test]
    fn cancel_run_transitions_initializing_to_cancelled() {
        let mut backend = test_backend(42);
        let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5))
            .expect("test run config must be valid");
        backend
            .create_run(now(1), test_tenant(), test_run(), config)
            .expect("create_run should succeed");

        let outcome = backend
            .cancel_run(now(5), test_tenant(), test_run(), OpId::from_raw(22))
            .expect("cancel_run should succeed for initializing run");
        assert!(matches!(outcome, IdempotentOutcome::Executed(())));

        let record = backend
            .get_run(test_tenant(), test_run())
            .expect("get_run should succeed after cancellation");
        assert_eq!(record.status, RunStatus::Cancelled);
    }

    #[test]
    fn get_run_returns_created_run_record() {
        let mut backend = test_backend(43);
        seed_single_shard_run(&mut backend);

        let record = backend
            .get_run(test_tenant(), test_run())
            .expect("get_run should succeed");
        assert_eq!(record.tenant, test_tenant());
        assert_eq!(record.run, test_run());
        assert_eq!(record.status, RunStatus::Active);
        assert_eq!(record.root_shards, vec![test_shard()]);
    }

    #[test]
    fn get_run_progress_returns_shard_counts() {
        let mut backend = test_backend(44);
        seed_single_shard_run(&mut backend);

        let progress = backend
            .get_run_progress(now(5), test_tenant(), test_run())
            .expect("get_run_progress should succeed");
        assert_eq!(progress.total, 1);
        assert_eq!(progress.active, 1);
        assert_eq!(progress.leased, 0, "no shard is acquired yet");
    }

    // ---- Shard operation tests ----

    #[test]
    fn renew_extends_lease_and_preserves_fence() {
        let mut backend = test_backend(45);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let lease = acquire.lease;
        let fence = lease.fence();

        let _renew = backend
            .renew(now(10), test_tenant(), &lease)
            .expect("renew should succeed");

        let record = backend
            .shard_lookup(&test_tenant(), &key)
            .expect("shard record must be in cache after renew");
        assert_eq!(
            record.fence_epoch, fence,
            "fence must be preserved across renew"
        );
    }

    #[test]
    fn list_shards_into_returns_registered_shards() {
        let mut backend = test_backend(46);
        seed_multi_shard_run(&mut backend);

        let mut out: Vec<ShardSummary> = Vec::new();
        backend
            .list_shards_into(
                now(5),
                test_tenant(),
                test_run(),
                ShardFilter::all(),
                &mut out,
            )
            .expect("list_shards_into should succeed");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn collect_claim_candidates_into_finds_unowned_shards() {
        let mut backend = test_backend(47);
        seed_multi_shard_run(&mut backend);

        let mut candidates = Vec::new();
        backend
            .collect_claim_candidates_into(now(5), test_tenant(), test_run(), &mut candidates)
            .expect("collect_claim_candidates should succeed");
        assert_eq!(
            candidates.len(),
            2,
            "both unowned shards should be candidates"
        );
    }

    #[test]
    fn claim_next_available_acquires_unowned_shard() {
        let mut backend = test_backend(48);
        seed_multi_shard_run(&mut backend);

        let mut scratch = AcquireScratch::new();
        let result = backend
            .claim_next_available(
                now(5),
                test_tenant(),
                test_run(),
                test_worker(1),
                &mut scratch,
            )
            .expect("claim_next_available should succeed");
        assert!(
            result.lease.fence().as_raw() > 0,
            "claimed shard should have a valid fence"
        );
    }

    // ---- Shard splitting tests ----

    #[test]
    fn split_replace_creates_children_and_terminates_parent() {
        let mut backend = test_backend(49);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let lease = acquire.lease;

        let plan = SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(ShardSpecRef::new(b"a", b"m", b""), CursorUpdate::initial()),
            SplitReplaceChild::new(ShardSpecRef::new(b"m", b"z", b""), CursorUpdate::initial()),
        ])
        .expect("plan must be valid");

        let outcome = backend
            .split_replace(now(5), test_tenant(), &lease, plan, OpId::from_raw(30))
            .expect("split_replace should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(_)));

        // Parent + 2 children should now be cached.
        assert!(
            backend.shard_count() >= 3,
            "expected at least 3 cached shards (parent + 2 children), got {}",
            backend.shard_count(),
        );
    }

    #[test]
    fn split_residual_preserves_original_with_narrowed_spec() {
        let mut backend = test_backend(50);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let lease = acquire.lease;

        let plan = plan_split_residual_at_point(ShardSpecRef::new(b"a", b"z", b"meta"), b"m")
            .expect("residual plan must be valid");

        let outcome = backend
            .split_residual(now(5), test_tenant(), &lease, plan, OpId::from_raw(31))
            .expect("split_residual should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(_)));

        // Original stays Active with narrowed spec, plus a new residual shard.
        assert!(
            backend.shard_count() >= 2,
            "expected at least 2 cached shards (original + residual), got {}",
            backend.shard_count(),
        );
    }

    // ---- Lease expiry tests (C2) ----

    #[test]
    fn lease_expiry_allows_reacquire_by_different_worker() {
        let mut backend = test_backend(51);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();

        // Worker 1 acquires.
        let acquire1 = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("first acquire should succeed");
        let fence1 = acquire1.lease.fence();

        // Find the etcd lease expiry time from the owner key.
        let owner_key = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key, None)
            .expect("owner lookup should succeed");
        let lease_id = resp.kvs().first().expect("owner must exist").lease();
        let info = backend.lease_info(lease_id).expect("lease must exist");
        let expiry_time = info.expires_at + 1;

        // Worker 2 acquires after lease expires.
        let mut scratch2 = AcquireScratch::new();
        let acquire2 = backend
            .acquire_and_restore_into(
                now(expiry_time),
                test_tenant(),
                key,
                test_worker(2),
                &mut scratch2,
            )
            .expect("reacquire after lease expiry should succeed");
        let fence2 = acquire2.lease.fence();

        assert!(fence2 > fence1, "fence epoch must increase on reacquire");
    }

    #[test]
    fn introspection_reflects_state_after_lease_expiry_and_reacquire() {
        let mut backend = test_backend(52);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();

        // Worker 1 acquires and checkpoints.
        let acquire1 = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let fence1 = acquire1.lease.fence();
        let _ = backend
            .checkpoint(
                now(4),
                test_tenant(),
                &acquire1.lease,
                &CursorUpdate::new(b"g"),
                OpId::from_raw(40),
            )
            .expect("checkpoint should succeed");

        // Determine the expiry time of worker 1's lease.
        let owner_key = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key, None)
            .expect("owner lookup should succeed");
        let lease_id = resp.kvs().first().expect("owner must exist").lease();
        let info = backend.lease_info(lease_id).expect("lease must exist");
        let expiry_time = info.expires_at + 1;

        // Worker 2 reacquires after expiry.
        let mut scratch2 = AcquireScratch::new();
        let _acquire2 = backend
            .acquire_and_restore_into(
                now(expiry_time),
                test_tenant(),
                key,
                test_worker(2),
                &mut scratch2,
            )
            .expect("reacquire should succeed");

        // Introspection should show updated state.
        let record = backend
            .shard_lookup(&test_tenant(), &key)
            .expect("shard must be in cache after reacquire");
        let last_key = backend.cursor_last_key(record);
        assert_eq!(
            last_key,
            Some(b"g".as_slice()),
            "cursor must retain checkpointed value across reacquire"
        );
        assert!(
            record.fence_epoch > fence1,
            "fence epoch must advance on reacquire"
        );
    }

    // ---- GC tests ----

    #[test]
    fn gc_stale_initializing_runs_removes_old_unregistered_runs() {
        let mut backend = test_backend(55);
        let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5))
            .expect("test run config must be valid");
        backend
            .create_run(now(1), test_tenant(), test_run(), config)
            .expect("create_run should succeed");
        // Do not register shards — run stays Initializing.

        let mut removed = Vec::new();
        backend
            .gc_stale_initializing_runs_into(test_tenant(), now(100), &mut removed)
            .expect("gc should succeed");
        assert_eq!(
            removed,
            vec![test_run()],
            "stale initializing run should be GC'd"
        );
    }

    #[test]
    fn gc_preserves_active_runs() {
        let mut backend = test_backend(56);
        seed_single_shard_run(&mut backend);

        let mut removed = Vec::new();
        backend
            .gc_stale_initializing_runs_into(test_tenant(), now(100), &mut removed)
            .expect("gc should succeed");
        assert!(removed.is_empty(), "active runs must not be GC'd");
    }

    // ---- Cache refresh does not mask committed operations ----

    #[test]
    fn create_run_succeeds_when_cache_refresh_fails() {
        // With 100% GET failure, refresh_cached_run_state will fail.
        // create_run's CAS uses only TXN (no GET), so the CAS itself
        // succeeds. The caller must see success, not a masked BackendError.
        let fault_config = SimEtcdFaultConfig::default().with_get_failure_ppm(1_000_000);
        let config =
            EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/sim-cache-test")
                .expect("hard-coded sim config must be valid");
        let mut backend = SimEtcdCoordinator::with_fault_config(config, 71, fault_config.clone())
            .expect("sim coordinator should construct");
        let run_config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5))
            .expect("test run config must be valid");

        let result = backend.create_run(now(1), test_tenant(), test_run(), run_config);

        // The CAS committed the run — the caller must receive the RunRecord.
        assert!(
            result.is_ok(),
            "create_run committed; cache refresh failure must not mask success: {result:?}"
        );
    }

    // ---- Complete / Park tests ----

    #[test]
    fn full_lifecycle_create_to_complete() {
        let mut backend = test_backend(60);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let lease = acquire.lease;

        let _ = backend
            .checkpoint(
                now(4),
                test_tenant(),
                &lease,
                &CursorUpdate::new(b"m"),
                OpId::from_raw(100),
            )
            .expect("checkpoint should succeed");

        let _ = backend
            .renew(now(5), test_tenant(), &lease)
            .expect("renew should succeed");

        let outcome = backend
            .complete(
                now(6),
                test_tenant(),
                &lease,
                &CursorUpdate::new(b"y"),
                OpId::from_raw(101),
            )
            .expect("complete should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(())));

        let record = backend
            .shard_lookup(&test_tenant(), &key)
            .expect("shard must remain in cache after completion");
        assert_eq!(record.status, ShardStatus::Done);
        assert!(
            record.lease.is_none(),
            "lease must be cleared after complete"
        );

        // Owner key must be deleted from KV.
        let owner_key = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key, None)
            .expect("KV lookup should succeed");
        assert!(
            resp.kvs().is_empty(),
            "owner key must be deleted after complete"
        );

        // Active-index entry must be deleted.
        let index_key = backend
            .keyspace
            .shard_active_index_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(index_key, None)
            .expect("KV lookup should succeed");
        assert!(
            resp.kvs().is_empty(),
            "active-index entry must be deleted after complete"
        );

        // Terminal run transition should succeed.
        let outcome = backend
            .complete_run(now(10), test_tenant(), test_run(), OpId::from_raw(102))
            .expect("complete_run should succeed after shard completion");
        assert!(matches!(outcome, IdempotentOutcome::Executed(())));
    }

    #[test]
    fn park_shard_transitions_and_clears_owner() {
        let mut backend = test_backend(61);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let lease = acquire.lease;

        let outcome = backend
            .park_shard(
                now(5),
                test_tenant(),
                &lease,
                ParkReason::Poisoned,
                OpId::from_raw(110),
            )
            .expect("park_shard should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(())));

        let record = backend
            .shard_lookup(&test_tenant(), &key)
            .expect("shard must remain in cache after parking");
        assert_eq!(record.status, ShardStatus::Parked);
        assert_eq!(record.park_reason, Some(ParkReason::Poisoned));
        assert!(record.lease.is_none(), "lease must be cleared after park");

        // Owner key must be deleted from KV.
        let owner_key = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key, None)
            .expect("KV lookup should succeed");
        assert!(
            resp.kvs().is_empty(),
            "owner key must be deleted after park"
        );
    }

    // ---- Lease expiry correctness (F4) ----

    #[test]
    fn lease_expiry_rejects_checkpoint() {
        let mut backend = test_backend(62);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let lease = acquire.lease;

        // Find the etcd lease expiry time.
        let owner_key = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key, None)
            .expect("owner lookup should succeed");
        let etcd_lease_id = resp.kvs().first().expect("owner must exist").lease();
        let info = backend.lease_info(etcd_lease_id).expect("lease must exist");
        let expiry_time = info.expires_at + 1;

        // Checkpoint after lease expired must fail.
        let result = backend.checkpoint(
            now(expiry_time),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"m"),
            OpId::from_raw(120),
        );
        assert!(
            matches!(
                result,
                Err(CheckpointError::StaleFence { .. } | CheckpointError::LeaseExpired { .. })
            ),
            "checkpoint after lease expiry must fail, got: {result:?}"
        );
    }

    #[test]
    fn lease_expiry_invalidates_cached_owner() {
        let mut backend = test_backend(63);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let _acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");

        // Verify owner is cached.
        let cached = backend.shard_cache.get(&(test_tenant(), key)).unwrap();
        assert!(cached.owner.is_some(), "owner must be cached after acquire");

        // Find the etcd lease expiry time.
        let owner_key = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key.clone(), None)
            .expect("owner lookup should succeed");
        let etcd_lease_id = resp.kvs().first().expect("owner must exist").lease();
        let info = backend.lease_info(etcd_lease_id).expect("lease must exist");
        let expiry_time = info.expires_at + 1;

        // Advance time past TTL via gc (triggers sync + flush).
        let mut removed = Vec::new();
        backend
            .gc_stale_initializing_runs_into(test_tenant(), now(expiry_time), &mut removed)
            .expect("gc should succeed");

        // Owner key must be deleted from KV.
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key, None)
            .expect("KV lookup should succeed");
        assert!(
            resp.kvs().is_empty(),
            "owner key must be deleted after lease expiry"
        );

        // Cached owner must be invalidated.
        let cached = backend.shard_cache.get(&(test_tenant(), key)).unwrap();
        assert!(
            cached.owner.is_none(),
            "cached owner must be cleared after lease expiry flush"
        );
    }

    // ---- Complete idempotency ----

    #[test]
    fn complete_idempotent_replay() {
        let mut backend = test_backend(64);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");
        let lease = acquire.lease;
        let op_id = OpId::from_raw(130);
        let cursor = CursorUpdate::new(b"y");

        let outcome = backend
            .complete(now(5), test_tenant(), &lease, &cursor, op_id)
            .expect("first complete should succeed");
        assert!(matches!(outcome, IdempotentOutcome::Executed(())));

        // Replay with same op_id returns Replayed, not a duplicate mutation.
        let outcome = backend
            .complete(now(6), test_tenant(), &lease, &cursor, op_id)
            .expect("replay complete should succeed");
        assert!(
            matches!(outcome, IdempotentOutcome::Replayed(())),
            "second complete with same op_id must return Replayed"
        );
    }

    // ---- Lease expiry via list_active_runs_into ----

    #[test]
    fn list_active_runs_buffers_expired_lease_ids_for_cache_flush() {
        let mut backend = test_backend(70);
        let key = seed_single_shard_run(&mut backend);
        let mut scratch = AcquireScratch::new();
        let _acquire = backend
            .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
            .expect("acquire should succeed");

        // Owner must be cached after acquire.
        assert!(
            backend
                .shard_cache
                .get(&(test_tenant(), key))
                .unwrap()
                .owner
                .is_some(),
            "owner must be cached after acquire"
        );

        // Find the etcd lease expiry time.
        let owner_key_bytes = backend
            .keyspace()
            .shard_owner_key(test_tenant(), key.run(), key.shard())
            .into_bytes();
        let resp = backend
            .kv
            .borrow_mut()
            .get(owner_key_bytes, None)
            .expect("owner lookup should succeed");
        let etcd_lease_id = resp.kvs().first().expect("owner must exist").lease();
        let info = backend.lease_info(etcd_lease_id).expect("lease must exist");
        let expiry_time = info.expires_at + 1;

        // Advance sim clock past TTL, then expire leases via
        // list_active_runs_into (which calls expire_due_leases internally).
        backend.kv.borrow_mut().set_time(expiry_time);
        let mut active_runs = Vec::new();
        backend
            .list_active_runs_into(test_tenant(), &mut active_runs)
            .expect("list_active_runs should succeed");

        // The expired IDs must be buffered so flush_expired_lease_cache
        // can clear stale owner bindings. Trigger the flush via a &mut self
        // method. gc_stale_initializing_runs_into calls flush_expired_lease_cache
        // but won't re-expire leases (clock already at expiry_time).
        let mut removed = Vec::new();
        backend
            .gc_stale_initializing_runs_into(test_tenant(), now(expiry_time), &mut removed)
            .expect("gc should succeed");

        // Cached owner must be invalidated.
        assert!(
            backend
                .shard_cache
                .get(&(test_tenant(), key))
                .unwrap()
                .owner
                .is_none(),
            "cached owner must be cleared after lease expiry via list_active_runs_into"
        );
    }

    // ---- Simulation harness smoke test ----

    #[test]
    fn simulation_harness_50_steps_sunny_day() {
        let mut backend = test_backend(65);
        let _key = seed_single_shard_run(&mut backend);
        let worker_a = test_worker(1);
        let worker_b = test_worker(2);

        let mut sim = CoordinationSim::with_backend(65, FaultLevel::SunnyDay, backend);
        sim.add_worker(worker_a);
        sim.add_worker(worker_b);

        let report = sim.run(25, 25);
        assert!(
            report.violations.is_empty(),
            "50-step SunnyDay simulation must produce zero invariant violations, \
             got {} violations: {:?}",
            report.violations.len(),
            report.violations,
        );
    }
}
