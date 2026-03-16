//! Shared live-etcd observation helpers for integration tests.
//!
//! `ObservedEtcdCoordinator` wraps a real `EtcdCoordinator` with a cache backed
//! by the test-only snapshot loaders. Tests use it when they need the real
//! backend's mutation semantics together with `SimIntrospection` for invariant
//! checking or state comparison.

use std::collections::{BTreeMap, BTreeSet};

use gossip_coordination::sim::SimIntrospection;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, CheckpointError, ClaimError, CompleteError,
    CoordinationBackend, CreateRunError, GetRunError, IdempotentOutcome, InitialShardInput, Lease,
    LogicalTime, OpId, ParkError, RegisterShardsError, RenewError, RenewResult, RunId,
    RunManagement, RunRecord, ShardClaiming, ShardFilter, ShardId, ShardKey, ShardRecord,
    ShardSummary, SplitReplaceError, SplitReplacePlan, SplitReplaceResult, SplitResidualError,
    SplitResidualPlan, SplitResidualResult, TenantId, UnparkError, WorkerId,
};
use gossip_coordination_etcd::{EtcdCoordinator, EtcdTestShardSnapshot};

/// Composite key for the `ObservedEtcdCoordinator` shard cache.
///
/// `ShardKey` intentionally omits `Ord`, so this struct unpacks its components
/// into `Ord`-capable fields for use in `BTreeMap`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShardCacheKey {
    tenant: TenantId,
    run: RunId,
    shard: ShardId,
}

impl ShardCacheKey {
    pub fn from_parts(tenant: TenantId, key: ShardKey) -> Self {
        Self {
            tenant,
            run: key.run(),
            shard: key.shard(),
        }
    }

    fn shard_key(self) -> ShardKey {
        ShardKey::new(self.run, self.shard)
    }
}

/// Adapter that pairs a real [`EtcdCoordinator`] with a local cache so tests
/// can observe shard and run state through [`SimIntrospection`].
///
/// Delegates all mutations to the inner `EtcdCoordinator`, then eagerly
/// refreshes a local `BTreeMap` cache by calling the test-only
/// `test_load_run_snapshot` / `test_load_shard_snapshot` helpers. The cache
/// satisfies the `SimIntrospection` contract with data that is current as
/// of the most recent successful mutation (refresh is synchronous).
///
/// # Cache consistency model
///
/// The `known_shards` index tracks which `ShardId`s exist per `(tenant, run)`.
/// It grows when mutations introduce new shards (register, split) and shrinks
/// when a snapshot load returns `None` (shard deleted or absent). This avoids
/// full etcd range scans while still detecting shard removal.
///
/// Refresh is triggered on *successful* mutations only ([`Self::refresh_if_ok`]).
/// Failed mutations cannot change etcd state, so skipping refresh is safe.
pub struct ObservedEtcdCoordinator {
    inner: EtcdCoordinator,
    /// Cached run records, keyed by `(tenant, run)`.
    runs: BTreeMap<(TenantId, RunId), RunRecord>,
    /// Cached shard snapshots, keyed by `(tenant, run, shard)`.
    shards: BTreeMap<ShardCacheKey, EtcdTestShardSnapshot>,
    /// Known shard IDs per `(tenant, run)`. Drives the per-shard refresh loop
    /// in [`Self::refresh_run_state`] — only IDs present here are re-fetched
    /// from etcd.
    known_shards: BTreeMap<(TenantId, RunId), BTreeSet<ShardId>>,
}

/// Iterator adapter for [`SimIntrospection::shards`] on the observation cache.
pub struct ObservedEtcdShardIter<'a> {
    inner: std::collections::btree_map::Iter<'a, ShardCacheKey, EtcdTestShardSnapshot>,
}

/// Iterator adapter for [`SimIntrospection::runs`] on the observation cache.
pub struct ObservedEtcdRunIter<'a> {
    inner: std::collections::btree_map::Iter<'a, (TenantId, RunId), RunRecord>,
}

impl ObservedEtcdCoordinator {
    pub fn new(inner: EtcdCoordinator) -> Self {
        Self {
            inner,
            runs: BTreeMap::new(),
            shards: BTreeMap::new(),
            known_shards: BTreeMap::new(),
        }
    }

    /// Register a run so future refreshes know which shard IDs to load.
    pub fn note_run(&mut self, tenant: TenantId, run: RunId) {
        self.known_shards.entry((tenant, run)).or_default();
    }

    /// Register shard IDs produced or discovered by the harness.
    pub fn note_shards<I>(&mut self, tenant: TenantId, run: RunId, shard_ids: I)
    where
        I: IntoIterator<Item = ShardId>,
    {
        let known = self.known_shards.entry((tenant, run)).or_default();
        for shard_id in shard_ids {
            known.insert(shard_id);
        }
    }

    /// Re-read the run record and all known shards from etcd into the local
    /// cache. Handles three cases:
    ///
    /// - **Run still exists**: update the cached run record, then re-fetch
    ///   each known shard. Shards that return `None` are pruned from both
    ///   the cache and the known-set.
    /// - **Run deleted**: purge all cached state for the `(tenant, run)`.
    /// - **Read error**: panic — test infrastructure failures are not recoverable.
    ///
    /// # Panics
    ///
    /// Panics if the etcd read for the run record or any known shard fails.
    /// A read failure during invariant checking indicates a broken test
    /// environment, not a recoverable condition. Callers in the contention
    /// harness catch these panics via `std::panic::catch_unwind` in the
    /// worker loop.
    pub fn refresh_run_state(&mut self, tenant: TenantId, run: RunId, context: &'static str) {
        let run_key = (tenant, run);
        match self.inner.test_load_run_snapshot(tenant, run) {
            Ok(Some(record)) => {
                self.runs.insert(run_key, record);
            }
            Ok(None) => {
                self.runs.remove(&run_key);
                self.known_shards.remove(&run_key);
                self.shards
                    .retain(|key, _| (key.tenant, key.run) != run_key);
                return;
            }
            Err(err) => panic!("{context}: failed to refresh run snapshot for {run:?}: {err}"),
        }

        let known_ids: Vec<ShardId> = self
            .known_shards
            .get(&run_key)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        let mut missing = Vec::new();

        for shard_id in known_ids {
            let key = ShardKey::new(run, shard_id);
            match self.inner.test_load_shard_snapshot(tenant, key) {
                Ok(Some(snapshot)) => {
                    self.shards
                        .insert(ShardCacheKey::from_parts(tenant, key), snapshot);
                }
                Ok(None) => {
                    self.shards.remove(&ShardCacheKey::from_parts(tenant, key));
                    missing.push(shard_id);
                }
                Err(err) => {
                    panic!("{context}: failed to refresh shard snapshot for {key:?}: {err}")
                }
            }
        }

        if let Some(known) = self.known_shards.get_mut(&run_key) {
            for shard_id in missing {
                known.remove(&shard_id);
            }
        }
    }

    /// Refresh the local cache if `result` is `Ok`, then pass it through.
    ///
    /// Every `CoordinationBackend` and `RunManagement` method delegates to the
    /// inner coordinator, then calls this to keep the observation cache
    /// consistent on success. The `context` label is included in panic messages
    /// for debuggability.
    fn refresh_if_ok<T, E>(
        &mut self,
        tenant: TenantId,
        run: RunId,
        result: Result<T, E>,
        context: &'static str,
    ) -> Result<T, E> {
        if result.is_ok() {
            self.refresh_run_state(tenant, run, context);
        }
        result
    }

    /// Look up the [`EtcdTestShardSnapshot`] backing a `ShardRecord`.
    ///
    /// The snapshot provides the `ByteSlab` required by pooled-field accessors
    /// (`cursor.last_key`, `spec.key_range_start`, etc.). Panics if the record
    /// is not in the cache — this would indicate a harness bug where the cache
    /// drifted from the iteration set.
    fn snapshot_for_record<'a>(&'a self, record: &ShardRecord) -> &'a EtcdTestShardSnapshot {
        let key = ShardCacheKey {
            tenant: record.tenant,
            run: record.run,
            shard: record.shard,
        };
        self.shards
            .get(&key)
            .expect("observed etcd cache must contain any record yielded by shards()")
    }
}

impl<'a> Iterator for ObservedEtcdShardIter<'a> {
    type Item = ((TenantId, ShardKey), &'a ShardRecord);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(key, snapshot)| ((key.tenant, key.shard_key()), &**snapshot))
    }
}

impl<'a> Iterator for ObservedEtcdRunIter<'a> {
    type Item = ((TenantId, RunId), &'a RunRecord);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, record)| (*key, record))
    }
}

impl SimIntrospection for ObservedEtcdCoordinator {
    type ShardIter<'a>
        = ObservedEtcdShardIter<'a>
    where
        Self: 'a;
    type RunIter<'a>
        = ObservedEtcdRunIter<'a>
    where
        Self: 'a;
    type SpawnedIter<'a>
        = std::vec::IntoIter<ShardId>
    where
        Self: 'a;

    fn shards(&self) -> Self::ShardIter<'_> {
        ObservedEtcdShardIter {
            inner: self.shards.iter(),
        }
    }

    fn runs(&self) -> Self::RunIter<'_> {
        ObservedEtcdRunIter {
            inner: self.runs.iter(),
        }
    }

    fn shard_count(&self) -> usize {
        self.shards.len()
    }

    fn shard_lookup(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord> {
        self.shards
            .get(&ShardCacheKey::from_parts(*tenant, *key))
            .map(|snapshot| &**snapshot)
    }

    fn cursor_last_key<'a>(&'a self, record: &'a ShardRecord) -> Option<&'a [u8]> {
        let snapshot = self.snapshot_for_record(record);
        record.cursor.last_key(snapshot.slab())
    }

    fn spec_bounds<'a>(&'a self, record: &'a ShardRecord) -> (&'a [u8], &'a [u8]) {
        let snapshot = self.snapshot_for_record(record);
        (
            record.spec.key_range_start(snapshot.slab()),
            record.spec.key_range_end(snapshot.slab()),
        )
    }

    fn validate_record_invariants(&self, record: &ShardRecord) -> Result<(), String> {
        let snapshot = self.snapshot_for_record(record);
        record.validate_invariants(snapshot.slab())
    }

    fn spawned_children<'a>(&'a self, record: &'a ShardRecord) -> Self::SpawnedIter<'a> {
        let snapshot = self.snapshot_for_record(record);
        record
            .spawned
            .iter(snapshot.slab())
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn release_record_fields(&mut self, _record: &mut ShardRecord) {}
}

impl CoordinationBackend for ObservedEtcdCoordinator {
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        let result = self
            .inner
            .acquire_and_restore_into(now, tenant, key, worker, out);
        self.refresh_if_ok(tenant, key.run(), result, "acquire")
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let result = self.inner.renew(now, tenant, lease);
        self.refresh_if_ok(tenant, lease.run(), result, "renew")
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &gossip_coordination::CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let result = self.inner.checkpoint(now, tenant, lease, new_cursor, op_id);
        self.refresh_if_ok(tenant, lease.run(), result, "checkpoint")
    }

    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: &gossip_coordination::CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        let result = self.inner.complete(now, tenant, lease, final_cursor, op_id);
        self.refresh_if_ok(tenant, lease.run(), result, "complete")
    }

    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: gossip_coordination::ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        let result = self.inner.park_shard(now, tenant, lease, reason, op_id);
        self.refresh_if_ok(tenant, lease.run(), result, "park_shard")
    }

    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        let result = self.inner.split_replace(now, tenant, lease, plan, op_id);
        if let Ok(outcome) = result.as_ref() {
            self.note_shards(
                tenant,
                lease.run(),
                outcome.as_ref().children.iter().copied(),
            );
        }
        self.refresh_if_ok(tenant, lease.run(), result, "split_replace")
    }

    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        let result = self.inner.split_residual(now, tenant, lease, plan, op_id);
        if let Ok(outcome) = result.as_ref() {
            self.note_shards(tenant, lease.run(), [outcome.as_ref().residual]);
        }
        self.refresh_if_ok(tenant, lease.run(), result, "split_residual")
    }
}

impl RunManagement for ObservedEtcdCoordinator {
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: gossip_coordination::RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        let result = self.inner.create_run(now, tenant, run, config);
        if result.is_ok() {
            self.note_run(tenant, run);
        }
        self.refresh_if_ok(tenant, run, result, "create_run")
    }

    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        let result = self.inner.register_shards(now, tenant, run, shards, op_id);
        if let Ok(outcome) = result.as_ref() {
            self.note_shards(tenant, run, outcome.as_ref().iter().copied());
        }
        self.refresh_if_ok(tenant, run, result, "register_shards")
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        self.inner.get_run(tenant, run)
    }

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<gossip_coordination::RunProgress, GetRunError> {
        self.inner.get_run_progress(now, tenant, run)
    }

    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        self.inner.list_shards_into(now, tenant, run, filter, out)
    }

    fn collect_claim_candidates_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        self.inner
            .collect_claim_candidates_into(now, tenant, run, candidates)
    }

    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, gossip_coordination::RunTransitionError> {
        let result = self.inner.complete_run(now, tenant, run, op_id);
        self.refresh_if_ok(tenant, run, result, "complete_run")
    }

    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, gossip_coordination::RunTransitionError> {
        let result = self.inner.fail_run(now, tenant, run, op_id);
        self.refresh_if_ok(tenant, run, result, "fail_run")
    }

    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, gossip_coordination::RunTransitionError> {
        let result = self.inner.cancel_run(now, tenant, run, op_id);
        self.refresh_if_ok(tenant, run, result, "cancel_run")
    }

    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        let result = self.inner.unpark_shard(now, tenant, key, op_id);
        self.refresh_if_ok(tenant, key.run(), result, "unpark_shard")
    }
}

impl ShardClaiming for ObservedEtcdCoordinator {
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, ClaimError> {
        let result = self
            .inner
            .claim_next_available(now, tenant, run, worker, out);
        self.refresh_if_ok(tenant, run, result, "claim_next_available")
    }
}
