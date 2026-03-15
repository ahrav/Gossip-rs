#![cfg(feature = "test-support")]
//! Differential oracle: deterministic in-memory etcd model vs. live etcd.
//!
//! # Problem
//!
//! [`SimEtcdCoordinator`] is a pure-logic model of how the etcd coordination
//! backend *should* behave — deterministic, fast, and safe to embed in
//! proptest/simulation harnesses. But bugs can hide in the gap between the
//! model's assumptions and real etcd's transaction semantics, revision
//! arithmetic, and TTL behavior.
//!
//! This module closes that gap by running identical [`SimOp`] sequences through
//! two [`CoordinationSim`] harnesses and asserting equivalence at every step:
//!
//! | Harness | Backend | Storage |
//! |---------|---------|---------|
//! | `sim` | [`SimEtcdCoordinator`] | In-memory `SimulatedEtcdKV` |
//! | `etcd` | [`ObservedEtcdCoordinator`] | Real etcd via testcontainers |
//!
//! # What is compared
//!
//! Comparison stays at the coordination boundary on purpose:
//!
//! - **Events**: the [`SimEvent`] emitted by each harness after every step.
//! - **State**: full shard and run records read via [`SimIntrospection`].
//! - **Invariants**: both harnesses run the invariant checker; any violation
//!   from either side is a test failure.
//!
//! Implementation-specific details (etcd revision numbers, raw lease IDs,
//! internal slab addresses) are **stripped** before comparison via the
//! `Comparable*` wrapper types.
//!
//! # Architecture
//!
//! The real [`EtcdCoordinator`] already implements mutation traits
//! ([`CoordinationBackend`], [`RunManagement`], [`ShardClaiming`]) but has no
//! [`SimIntrospection`] impl because its storage is remote and opaque.
//! [`ObservedEtcdCoordinator`] bridges this gap by maintaining a local cache
//! that is refreshed after every successful mutation via `test_load_*_snapshot`
//! helpers, providing the read-only observation surface the simulation harness
//! requires.
//!
//! # Namespace isolation
//!
//! Each proptest case gets a unique etcd namespace (`/test/{pid}/{seq}`)
//! so parallel test processes and cases never collide, even against a
//! shared etcd instance.
//!
//! # Running
//!
//! The test is `#[ignore]`d by default because it requires a live etcd.
//! Either start testcontainers or set `ETCD_ENDPOINTS` to point at an
//! existing cluster:
//!
//! ```sh
//! # testcontainers (Docker required):
//! cargo test --features test-support -- --ignored no_model_drift
//!
//! # External etcd:
//! ETCD_ENDPOINTS=http://localhost:2379 cargo test --features test-support -- --ignored no_model_drift
//! ```

use std::collections::{BTreeMap, BTreeSet};

use gossip_contracts::test_util::miri_proptest_config;
use gossip_coordination::sim::test_util::arb_sim_op;
use gossip_coordination::sim::{CoordinationSim, FaultLevel, SimIntrospection, SimOp};
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, CheckpointError, ClaimError, CompleteError,
    CoordinationBackend, CreateRunError, GetRunError, IdempotentOutcome, InitialShardInput, Lease,
    LogicalTime, OpId, OpKind, ParkError, RegisterShardsError, RenewError, RenewResult, RunConfig,
    RunId, RunManagement, RunOpKind, RunOpResult, RunRecord, RunStatus, RunTransitionError,
    ShardClaiming, ShardFilter, ShardId, ShardKey, ShardRecord, ShardStatus, ShardSummary,
    SplitReplaceError, SplitReplacePlan, SplitReplaceResult, SplitResidualError, SplitResidualPlan,
    SplitResidualResult, TenantId, UnparkError, WorkerId,
};
use gossip_coordination_etcd::test_etcd::test_coordinator_with_ttl;
use gossip_coordination_etcd::{
    EtcdCoordinator, EtcdCoordinatorConfig, EtcdTestShardSnapshot, SimEtcdCoordinator,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Simulation topology constants
// ---------------------------------------------------------------------------

const N_WORKERS: u64 = 4;
const N_SHARDS: u64 = 8;

/// Long TTL avoids time-of-day expiry interfering with the oracle's
/// coordination-level comparisons. The oracle runs at `FaultLevel::SunnyDay`
/// (no synthetic time-jumps), so leases expire only if the test clock
/// advances far enough — 300 s of logical time is well beyond the
/// `AdvanceTime` range in `arb_sim_op`.
const OWNER_LEASE_TTL_SECS: i64 = 300;

const OPTIMISTIC_TXN_RETRIES: usize = 8;
const MAX_CHILDREN_PER_OP: usize = 8;

// ---------------------------------------------------------------------------
// Shard cache key for the observation adapter
// ---------------------------------------------------------------------------

/// Composite key for the `ObservedEtcdCoordinator` shard cache.
///
/// `ShardKey` intentionally omits `Ord` (it is an opaque identity, not an
/// ordered quantity), so this struct unpacks its components into `Ord`-capable
/// fields to serve as a `BTreeMap` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ShardCacheKey {
    tenant: TenantId,
    run: RunId,
    shard: ShardId,
}

impl ShardCacheKey {
    fn from_parts(tenant: TenantId, key: ShardKey) -> Self {
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

// ---------------------------------------------------------------------------
// ObservedEtcdCoordinator — live-etcd observation adapter
// ---------------------------------------------------------------------------

/// Adapter that pairs a real [`EtcdCoordinator`] with a local cache so the
/// [`CoordinationSim`] harness can observe shard and run state through
/// [`SimIntrospection`].
///
/// # Why this exists
///
/// `CoordinationSim` requires its backend to implement both the mutation traits
/// (`CoordinationBackend`, `RunManagement`, `ShardClaiming`) *and* the
/// read-only [`SimIntrospection`] trait. The real `EtcdCoordinator` provides
/// mutations but has no `SimIntrospection` impl — its storage is remote.
///
/// This wrapper delegates all mutations to the inner `EtcdCoordinator`, then
/// eagerly refreshes a local `BTreeMap` cache by calling the test-only
/// `test_load_run_snapshot` / `test_load_shard_snapshot` helpers. The cache
/// satisfies the `SimIntrospection` contract with data that is current as
/// of the most recent successful mutation (refresh is synchronous).
///
/// # Cache consistency model
///
/// The `known_shards` index tracks which `ShardId`s exist per `(tenant, run)`.
/// It grows when mutations introduce new shards (register, split) and shrinks
/// when a snapshot load returns `None` (shard deleted or absent). This
/// avoids full etcd range scans while still detecting shard removal.
///
/// Refresh is triggered on *successful* mutations only (`refresh_if_ok`).
/// Failed mutations cannot change etcd state, so skipping refresh is safe.
struct ObservedEtcdCoordinator {
    inner: EtcdCoordinator,
    /// Cached run records, keyed by `(tenant, run)`.
    runs: BTreeMap<(TenantId, RunId), RunRecord>,
    /// Cached shard snapshots, keyed by `(tenant, run, shard)`.
    shards: BTreeMap<ShardCacheKey, EtcdTestShardSnapshot>,
    /// Known shard IDs per `(tenant, run)`. Drives the per-shard refresh loop
    /// in `refresh_run_state` — only IDs present here are re-fetched from etcd.
    known_shards: BTreeMap<(TenantId, RunId), BTreeSet<ShardId>>,
}

/// Iterator adapter for [`SimIntrospection::shards`] on the observation cache.
struct ObservedEtcdShardIter<'a> {
    inner: std::collections::btree_map::Iter<'a, ShardCacheKey, EtcdTestShardSnapshot>,
}

/// Iterator adapter for [`SimIntrospection::runs`] on the observation cache.
struct ObservedEtcdRunIter<'a> {
    inner: std::collections::btree_map::Iter<'a, (TenantId, RunId), RunRecord>,
}

// ---------------------------------------------------------------------------
// Comparable* wrappers — implementation-detail-free comparison types
// ---------------------------------------------------------------------------
//
// These types mirror their production counterparts but omit fields that
// differ between the simulated and real etcd backends (etcd revision numbers,
// raw lease IDs, slab addresses). Comparing `Comparable*` values is the
// mechanism by which the oracle detects behavioral drift without being
// sensitive to implementation-level noise.

/// Lease stripped of its etcd-internal lease ID. Only the worker identity
/// and logical deadline are semantically meaningful at the coordination
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableLease {
    owner: WorkerId,
    deadline: LogicalTime,
}

/// Shard op-log entry with etcd-internal details removed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableShardOpLogEntry {
    op_id: OpId,
    kind: OpKind,
    result: gossip_coordination::OpResult,
    payload_hash: u64,
    executed_at: LogicalTime,
}

/// Run op-log entry with etcd-internal details removed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableRunOpLogEntry {
    op_id: OpId,
    kind: RunOpKind,
    payload_hash: u64,
    executed_at: LogicalTime,
    result: RunOpResult,
}

/// Full shard state snapshot for cross-backend comparison.
///
/// Includes all coordination-visible fields: status, cursor, spec bounds,
/// lease (as [`ComparableLease`]), fence epoch, split lineage, and op log.
/// Variable-length byte fields (`spec_start`, `spec_end`, `cursor_last_key`)
/// are materialized into owned `Vec<u8>` so comparison is slab-independent.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableShardState {
    status: ShardStatus,
    park_reason: Option<gossip_coordination::ParkReason>,
    spec_start: Vec<u8>,
    spec_end: Vec<u8>,
    cursor_last_key: Option<Vec<u8>>,
    cursor_semantics: gossip_coordination::CursorSemantics,
    lease: Option<ComparableLease>,
    fence_epoch: gossip_coordination::FenceEpoch,
    parent: Option<ShardId>,
    spawned: Vec<ShardId>,
    op_log: Vec<ComparableShardOpLogEntry>,
}

/// Full run state snapshot for cross-backend comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableRunState {
    config: RunConfig,
    status: RunStatus,
    created_at: LogicalTime,
    completed_at: Option<LogicalTime>,
    root_shards: Vec<ShardId>,
    op_log: Vec<ComparableRunOpLogEntry>,
}

/// Aggregate backend state: all runs and all shards, comparable across
/// implementations. Used as the "after each step" snapshot for state drift
/// detection in [`DifferentialOracle::run_sequence`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableBackendState {
    runs: BTreeMap<(TenantId, RunId), ComparableRunState>,
    shards: BTreeMap<ShardCacheKey, ComparableShardState>,
}

// ---------------------------------------------------------------------------
// Differential oracle — the core test driver
// ---------------------------------------------------------------------------

/// Pairs two `CoordinationSim` instances (simulated and live-etcd) and
/// drives them with identical operation sequences, panicking on any
/// divergence in events, state, or invariant violations.
struct DifferentialOracle {
    sim: CoordinationSim<SimEtcdCoordinator>,
    etcd: CoordinationSim<ObservedEtcdCoordinator>,
}

/// Debug payload carried into [`panic_drift`] for rich failure messages.
/// Pre-formatted as strings to avoid lifetime tangles in the panic path.
struct DriftComparison {
    sim_event: String,
    etcd_event: String,
    sim_detail: String,
    etcd_detail: String,
}

impl ObservedEtcdCoordinator {
    fn new(inner: EtcdCoordinator) -> Self {
        Self {
            inner,
            runs: BTreeMap::new(),
            shards: BTreeMap::new(),
            known_shards: BTreeMap::new(),
        }
    }

    /// Register a run in the `known_shards` index so future `refresh_run_state`
    /// calls will look up its shards.
    fn note_run(&mut self, tenant: TenantId, run: RunId) {
        self.known_shards.entry((tenant, run)).or_default();
    }

    /// Register shard IDs produced by a mutation (register_shards, split)
    /// so they are included in the next cache refresh.
    fn note_shards<I>(&mut self, tenant: TenantId, run: RunId, shard_ids: I)
    where
        I: IntoIterator<Item = ShardId>,
    {
        let known = self.known_shards.entry((tenant, run)).or_default();
        for shard_id in shard_ids {
            known.insert(shard_id);
        }
    }

    /// Refresh the local cache if `result` is `Ok`, then pass it through.
    ///
    /// This is the central integration point: every `CoordinationBackend` and
    /// `RunManagement` method delegates to the inner coordinator, then calls
    /// this to keep the observation cache consistent on success. The `context`
    /// label is included in panic messages for debuggability.
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

    /// Re-read the run record and all known shards from etcd into the local
    /// cache. Handles three cases:
    ///
    /// - **Run still exists**: update the cached run record, then re-fetch
    ///   each known shard. Shards that return `None` are pruned from both
    ///   the cache and the known-set.
    /// - **Run deleted**: purge all cached state for the `(tenant, run)`.
    /// - **Read error**: panic — test infrastructure failures are not recoverable.
    fn refresh_run_state(&mut self, tenant: TenantId, run: RunId, context: &'static str) {
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

    // No-op: each snapshot owns its own `ByteSlab`, so pooled fields are
    // freed automatically when the snapshot drops.
    fn release_record_fields(&mut self, _record: &mut ShardRecord) {}
}

// All CoordinationBackend, RunManagement, and ShardClaiming methods follow
// the same pattern: delegate to `self.inner`, then call `refresh_if_ok` to
// update the observation cache on success. Split operations additionally
// register newly created shard IDs via `note_shards` *before* refresh, so
// the refresh loop knows to fetch them.

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
        config: RunConfig,
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
        if result.is_ok() {
            self.note_shards(tenant, run, shards.iter().map(InitialShardInput::shard));
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
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let result = self.inner.complete_run(now, tenant, run, op_id);
        self.refresh_if_ok(tenant, run, result, "complete_run")
    }

    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let result = self.inner.fail_run(now, tenant, run, op_id);
        self.refresh_if_ok(tenant, run, result, "fail_run")
    }

    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
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

impl DifferentialOracle {
    /// Construct both harnesses with identical topology and verify their
    /// initial states match before any operations are applied.
    ///
    /// Both harnesses use `FaultLevel::SunnyDay` (no synthetic faults) because
    /// the oracle tests *behavioral equivalence between backends*, not fault
    /// tolerance. Fault injection would introduce non-determinism between the
    /// simulated and real backends (e.g., different retry timing), making
    /// comparison meaningless.
    fn new(seed: u64) -> Self {
        let sim_backend =
            SimEtcdCoordinator::new(sim_config(&format!("/gossip/diff/{seed}")), seed)
                .expect("simulated etcd backend must construct");
        let etcd_backend =
            ObservedEtcdCoordinator::new(test_coordinator_with_ttl(OWNER_LEASE_TTL_SECS));

        let sim = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, sim_backend)
            .with_workers_and_shards(N_WORKERS, N_SHARDS);
        let etcd = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, etcd_backend)
            .with_workers_and_shards(N_WORKERS, N_SHARDS);

        let oracle = Self { sim, etcd };
        let sim_state = comparable_state(oracle.sim.backend());
        let etcd_state = comparable_state(oracle.etcd.backend());
        if sim_state != etcd_state {
            panic!(
                "initial state drift detected\nseed={seed}\nsim_state={sim_state:#?}\netcd_state={etcd_state:#?}"
            );
        }
        oracle
    }

    /// Feed each operation to both harnesses and check three equivalence
    /// properties after every step:
    ///
    /// 1. **No invariant violations** — either harness reporting a violation
    ///    is a failure, regardless of whether the other agrees.
    /// 2. **Event equivalence** — both harnesses must emit the same
    ///    [`ComparableEvent`] for the same input.
    /// 3. **State equivalence** — full [`ComparableBackendState`] snapshots
    ///    must match after every step.
    ///
    /// On any divergence, the panic includes the seed, step index, failing
    /// operation, and the full operation sequence so the failure is
    /// deterministically reproducible.
    fn run_sequence(&mut self, seed: u64, ops: &[SimOp]) {
        for (step, op) in ops.iter().enumerate() {
            let (sim_event, sim_violations) = self.sim.step(op.clone());
            let (etcd_event, etcd_violations) = self.etcd.step(op.clone());

            if !sim_violations.is_empty() || !etcd_violations.is_empty() {
                panic_drift(
                    seed,
                    step,
                    op,
                    ops,
                    "invariant violation",
                    DriftComparison {
                        sim_event: format!("{sim_event:#?}"),
                        etcd_event: format!("{etcd_event:#?}"),
                        sim_detail: format!("{sim_violations:#?}"),
                        etcd_detail: format!("{etcd_violations:#?}"),
                    },
                );
            }

            // SimEvent derives PartialEq — compare directly.
            if sim_event != etcd_event {
                panic_drift(
                    seed,
                    step,
                    op,
                    ops,
                    "event drift",
                    DriftComparison {
                        sim_event: format!("{sim_event:#?}"),
                        etcd_event: format!("{etcd_event:#?}"),
                        sim_detail: String::new(),
                        etcd_detail: String::new(),
                    },
                );
            }

            let sim_state = comparable_state(self.sim.backend());
            let etcd_state = comparable_state(self.etcd.backend());
            if sim_state != etcd_state {
                panic_drift(
                    seed,
                    step,
                    op,
                    ops,
                    "state drift",
                    DriftComparison {
                        sim_event: format!("{sim_event:#?}"),
                        etcd_event: format!("{etcd_event:#?}"),
                        sim_detail: format!("{sim_state:#?}"),
                        etcd_detail: format!("{etcd_state:#?}"),
                    },
                );
            }
        }
    }
}

/// Emit a rich panic with enough context to reproduce the failure
/// deterministically: the seed, step index, triggering operation, the events
/// and states from both backends, and the full operation sequence.
fn panic_drift(
    seed: u64,
    step: usize,
    op: &SimOp,
    ops: &[SimOp],
    reason: &str,
    comparison: DriftComparison,
) -> ! {
    panic!(
        "differential oracle drift detected\n\
         seed={seed}\n\
         step={step}\n\
         op={op:#?}\n\
         reason={reason}\n\
         sim_event={}\n\
         etcd_event={}\n\
         sim_detail={}\n\
         etcd_detail={}\n\
         full_sequence={ops:#?}",
        comparison.sim_event, comparison.etcd_event, comparison.sim_detail, comparison.etcd_detail,
    );
}

/// Builds an owned, normalized snapshot of all backend state for equality comparison.
///
/// Every semantically meaningful field from `ShardRecord` and `RunRecord` must
/// be captured here. If you add a field to either record type, update this
/// function — the oracle will silently pass despite real divergence otherwise.
///
/// Iterates all runs and shards via [`SimIntrospection`], materializing
/// variable-length fields (spec bounds, cursor, spawned children) into owned
/// collections and stripping backend-specific lease internals. Also validates
/// structural invariants on each shard record (via `validate_record_invariants`)
/// as a side-effect — a failing invariant is a hard panic, not a comparison
/// mismatch.
///
/// Ends with an assertion that `shard_count()` agrees with the iteration
/// length, catching `SimIntrospection` implementations where the counter
/// and iterator diverge.
fn comparable_state<B: SimIntrospection>(backend: &B) -> ComparableBackendState {
    let mut runs = BTreeMap::new();
    let mut shards = BTreeMap::new();

    for ((tenant, run), record) in backend.runs() {
        runs.insert(
            (tenant, run),
            ComparableRunState {
                config: record.config,
                status: record.status,
                created_at: record.created_at,
                completed_at: record.completed_at,
                root_shards: record.root_shards.clone(),
                op_log: record
                    .op_log
                    .iter()
                    .map(|entry| ComparableRunOpLogEntry {
                        op_id: entry.op_id(),
                        kind: entry.kind(),
                        payload_hash: entry.payload_hash(),
                        executed_at: entry.executed_at(),
                        result: entry.result().clone(),
                    })
                    .collect(),
            },
        );
    }

    for ((tenant, key), record) in backend.shards() {
        backend
            .validate_record_invariants(record)
            .unwrap_or_else(|err| panic!("invalid record in comparable_state for {key:?}: {err}"));
        let (start, end) = backend.spec_bounds(record);
        let lease = record.lease().map(|lease| ComparableLease {
            owner: lease.owner(),
            deadline: lease.deadline(),
        });
        let op_log = record
            .op_log
            .iter()
            .map(|entry| ComparableShardOpLogEntry {
                op_id: entry.op_id(),
                kind: entry.kind(),
                result: entry.result(),
                payload_hash: entry.payload_hash(),
                executed_at: entry.executed_at(),
            })
            .collect();

        shards.insert(
            ShardCacheKey::from_parts(tenant, key),
            ComparableShardState {
                status: record.status,
                park_reason: record.park_reason,
                spec_start: start.to_vec(),
                spec_end: end.to_vec(),
                cursor_last_key: backend.cursor_last_key(record).map(|key| key.to_vec()),
                cursor_semantics: record.cursor_semantics,
                lease,
                fence_epoch: record.fence_epoch,
                parent: record.parent,
                spawned: backend.spawned_children(record).collect(),
                op_log,
            },
        );
    }

    assert_eq!(
        backend.shard_count(),
        shards.len(),
        "SimIntrospection::shard_count disagrees with shard iteration",
    );

    ComparableBackendState { runs, shards }
}

/// Build an `EtcdCoordinatorConfig` for the simulated (in-memory) backend.
///
/// The endpoint URL is irrelevant — `SimEtcdCoordinator` never opens a
/// connection — but the namespace and tuning parameters must match the
/// live-etcd backend's config to ensure identical protocol behavior.
fn sim_config(namespace: &str) -> EtcdCoordinatorConfig {
    EtcdCoordinatorConfig::new_with_tuning(
        ["http://127.0.0.1:2379"],
        namespace,
        OWNER_LEASE_TTL_SECS,
        OPTIMISTIC_TXN_RETRIES,
        MAX_CHILDREN_PER_OP,
    )
    .expect("sim differential-oracle config must be valid")
}

// ---------------------------------------------------------------------------
// Proptest harness
// ---------------------------------------------------------------------------
//
// Generates 50 random operation sequences (5–50 ops each) and feeds each
// through the differential oracle. `#[ignore]` keeps CI fast by default;
// run with `--ignored` when a live etcd is available.

proptest! {
    #![proptest_config({
        let mut config = miri_proptest_config();
        config.cases = 50;
        config
    })]

    #[test]
    #[ignore]
    fn no_model_drift_against_real_etcd(
        seed in any::<u64>(),
        ops in proptest::collection::vec(arb_sim_op(N_WORKERS, N_SHARDS), 5..50),
    ) {
        let mut oracle = DifferentialOracle::new(seed);
        oracle.run_sequence(seed, &ops);
    }
}
