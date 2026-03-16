#![cfg(feature = "test-support")]
//! Multi-threaded CAS contention harness against a live etcd backend.
//!
//! The harness has three phases per seed:
//!
//! - Seed one shared namespace with a single run and four root shards.
//! - Run four synchronized acquire races so every root shard proves the
//!   single-winner CAS behavior before mixed traffic begins.
//! - Continue with seeded mixed operations (`acquire`, `checkpoint`, `renew`,
//!   `complete`, `park`, `unpark`, `split_replace`, `split_residual`) across
//!   per-thread coordinators, then verify the quiescent state with
//!   `InvariantChecker` plus a direct shard-counter conservation check.
//!
//! The test is ignored by default because it requires a live etcd endpoint or
//! Docker-backed testcontainers.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use gossip_coordination::sim::{InvariantChecker, SimIntrospection};
use gossip_coordination::test_fixtures::{now, short_lease_run_config, test_tenant, test_worker};
use gossip_coordination::{
    AcquireError, AcquireScratch, CheckpointError, CompleteError, CoordinationBackend,
    InitialShardInput, Lease, LogicalTime, OpId, ParkError, ParkReason, RenewError, RunId,
    RunManagement, ShardFilter, ShardId, ShardKey, SplitReplaceError, SplitReplaceResult,
    SplitResidualError, SplitResidualResult, UnparkError,
    plan_split_replace_at_points_initial_cursor, plan_split_residual_at_point,
};
use gossip_coordination_etcd::test_support::{contention_namespace, test_coordinator_in_namespace};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use support::ObservedEtcdCoordinator;

const N_WORKERS: usize = 4;
const ROOT_RACE_ROUNDS: usize = 4;
const MIXED_ROUNDS: usize = 24;
const TOTAL_ROUNDS: usize = ROOT_RACE_ROUNDS + MIXED_ROUNDS;
const DEFAULT_SEED_COUNT: usize = 4;
const VERIFY_COOLDOWN_INTERVAL: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlannedOp {
    Acquire(ShardKey),
    Checkpoint(ShardKey),
    Renew(ShardKey),
    Complete(ShardKey),
    Park(ShardKey),
    Unpark(ShardKey),
    SplitReplace(ShardKey),
    SplitResidual(ShardKey),
}

impl PlannedOp {
    fn label(self) -> &'static str {
        match self {
            Self::Acquire(_) => "acquire",
            Self::Checkpoint(_) => "checkpoint",
            Self::Renew(_) => "renew",
            Self::Complete(_) => "complete",
            Self::Park(_) => "park",
            Self::Unpark(_) => "unpark",
            Self::SplitReplace(_) => "split_replace",
            Self::SplitResidual(_) => "split_residual",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcquireRaceOutcome {
    Won,
    LostContention,
}

#[derive(Clone, Debug)]
struct HeldLease {
    lease: Lease,
    range_start: Vec<u8>,
    range_end: Vec<u8>,
    last_cursor: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct ThreadReport {
    attempts: BTreeMap<&'static str, usize>,
    successes: BTreeMap<&'static str, usize>,
    discovered_shards: BTreeSet<ShardId>,
    acquire_races: BTreeMap<ShardId, AcquireRaceOutcome>,
}

impl ThreadReport {
    fn record_attempt(&mut self, label: &'static str) {
        *self.attempts.entry(label).or_default() += 1;
    }

    fn record_success(&mut self, label: &'static str) {
        *self.successes.entry(label).or_default() += 1;
    }

    fn merge(&mut self, other: &ThreadReport) {
        for (&label, &count) in &other.attempts {
            *self.attempts.entry(label).or_default() += count;
        }
        for (&label, &count) in &other.successes {
            *self.successes.entry(label).or_default() += count;
        }
    }

    fn success_count(&self, label: &'static str) -> usize {
        self.successes.get(label).copied().unwrap_or(0)
    }
}

struct WorkerHarness {
    worker_index: usize,
    worker: gossip_coordination::WorkerId,
    coord: gossip_coordination_etcd::EtcdCoordinator,
    rng: ChaCha8Rng,
    leases: BTreeMap<ShardKey, HeldLease>,
    known_shards: BTreeSet<ShardId>,
    parked_hints: BTreeSet<ShardId>,
    report: ThreadReport,
}

impl WorkerHarness {
    fn new(worker_index: usize, namespace: &str, seed: u64) -> Self {
        let known_shards: BTreeSet<ShardId> =
            root_shards().into_iter().map(|(id, _, _)| id).collect();
        let report = ThreadReport {
            discovered_shards: known_shards.clone(),
            ..ThreadReport::default()
        };
        Self {
            worker_index,
            worker: test_worker((worker_index + 1) as u64),
            coord: test_coordinator_in_namespace(namespace),
            rng: ChaCha8Rng::seed_from_u64(seed),
            leases: BTreeMap::new(),
            known_shards,
            parked_hints: BTreeSet::new(),
            report,
        }
    }

    fn backend_err(&self, op: &str, key: ShardKey, err: impl fmt::Display) -> String {
        format!(
            "worker {} {op} {key:?} failed with backend error: {err}",
            self.worker_index + 1
        )
    }

    fn unexpected_err(&self, op: &str, key: ShardKey, err: impl fmt::Debug) -> String {
        format!(
            "worker {} {op} {key:?} returned unexpected error: {err:?}",
            self.worker_index + 1
        )
    }

    fn plan_for_round(&mut self, round: usize) -> PlannedOp {
        if round < ROOT_RACE_ROUNDS {
            return PlannedOp::Acquire(root_key_for_round(round));
        }

        if self.leases.is_empty() {
            if !self.parked_hints.is_empty() && self.rng.random_bool(0.35) {
                return PlannedOp::Unpark(self.random_parked_key());
            }
            return PlannedOp::Acquire(self.random_acquire_key());
        }

        match self.rng.random_range(0..100) {
            0..18 => PlannedOp::Acquire(self.random_acquire_key()),
            18..36 => PlannedOp::Checkpoint(self.random_held_key()),
            36..50 => PlannedOp::Renew(self.random_held_key()),
            50..62 => PlannedOp::Complete(self.random_held_key()),
            62..74 => PlannedOp::Park(self.random_held_key()),
            74..87 => self.random_split_op(),
            _ => {
                if !self.parked_hints.is_empty() {
                    PlannedOp::Unpark(self.random_parked_key())
                } else {
                    PlannedOp::Acquire(self.random_acquire_key())
                }
            }
        }
    }

    fn run_round(&mut self, round: usize, logical_now: LogicalTime) -> Result<(), String> {
        let op = self.plan_for_round(round);
        self.report.record_attempt(op.label());
        match op {
            PlannedOp::Acquire(key) => {
                self.exec_acquire(key, logical_now, round < ROOT_RACE_ROUNDS)
            }
            PlannedOp::Checkpoint(key) => self.exec_checkpoint(key, logical_now, round),
            PlannedOp::Renew(key) => self.exec_renew(key, logical_now),
            PlannedOp::Complete(key) => self.exec_complete(key, logical_now, round),
            PlannedOp::Park(key) => self.exec_park(key, logical_now, round),
            PlannedOp::Unpark(key) => self.exec_unpark(key, logical_now, round),
            PlannedOp::SplitReplace(key) => self.exec_split_replace(key, logical_now, round),
            PlannedOp::SplitResidual(key) => self.exec_split_residual(key, logical_now, round),
        }
    }

    fn exec_acquire(
        &mut self,
        key: ShardKey,
        logical_now: LogicalTime,
        strict_race: bool,
    ) -> Result<(), String> {
        let mut scratch = AcquireScratch::new();
        match self.coord.acquire_and_restore_into(
            logical_now,
            test_tenant(),
            key,
            self.worker,
            &mut scratch,
        ) {
            Ok(view) => {
                let spec = view.snapshot.spec();
                let held = HeldLease {
                    lease: view.lease,
                    range_start: spec.key_range_start().to_vec(),
                    range_end: spec.key_range_end().to_vec(),
                    last_cursor: view.snapshot.cursor().last_key().map(|k| k.to_vec()),
                };
                self.leases.insert(key, held);
                self.parked_hints.remove(&key.shard());
                self.known_shards.insert(key.shard());
                self.report.discovered_shards.insert(key.shard());
                self.report.record_success("acquire");
                if strict_race {
                    self.report
                        .acquire_races
                        .insert(key.shard(), AcquireRaceOutcome::Won);
                }
                Ok(())
            }
            Err(AcquireError::AlreadyLeased { .. }) => {
                if strict_race {
                    self.report
                        .acquire_races
                        .insert(key.shard(), AcquireRaceOutcome::LostContention);
                }
                Ok(())
            }
            Err(
                err @ (AcquireError::ShardTerminal { .. } | AcquireError::ShardNotFound { .. }),
            ) if strict_race => Err(format!(
                "worker {} acquire {:?} in root-race phase hit non-contention error \
                 (expected only Won/AlreadyLeased): {err:?}",
                self.worker_index + 1,
                key,
            )),
            Err(AcquireError::ShardTerminal { .. } | AcquireError::ShardNotFound { .. }) => Ok(()),
            Err(AcquireError::BackendError(err)) => Err(self.backend_err("acquire", key, err)),
            Err(err) => Err(self.unexpected_err("acquire", key, err)),
        }
    }

    fn exec_renew(&mut self, key: ShardKey, logical_now: LogicalTime) -> Result<(), String> {
        let Some(current) = self.leases.get(&key).cloned() else {
            return Ok(());
        };
        match self.coord.renew(logical_now, test_tenant(), &current.lease) {
            Ok(result) => {
                if let Some(held) = self.leases.get_mut(&key) {
                    held.lease = Lease::new(
                        current.lease.tenant(),
                        current.lease.run(),
                        current.lease.shard(),
                        current.lease.owner(),
                        current.lease.fence(),
                        result.new_deadline,
                    );
                }
                self.report.record_success("renew");
                Ok(())
            }
            Err(
                RenewError::StaleFence { .. }
                | RenewError::LeaseExpired { .. }
                | RenewError::ShardTerminal { .. }
                | RenewError::ShardNotFound { .. },
            ) => {
                self.leases.remove(&key);
                Ok(())
            }
            Err(RenewError::BackendError(err)) => Err(self.backend_err("renew", key, err)),
            Err(err) => Err(self.unexpected_err("renew", key, err)),
        }
    }

    fn exec_checkpoint(
        &mut self,
        key: ShardKey,
        logical_now: LogicalTime,
        round: usize,
    ) -> Result<(), String> {
        let Some(current) = self.leases.get(&key).cloned() else {
            return Ok(());
        };
        let Some(next_cursor) = next_checkpoint_cursor(&current) else {
            return Ok(());
        };
        let op_id = op_id_for_round(round, self.worker_index);
        match self.coord.checkpoint(
            logical_now,
            test_tenant(),
            &current.lease,
            &gossip_coordination::CursorUpdate::new(&next_cursor),
            op_id,
        ) {
            Ok(_) => {
                if let Some(held) = self.leases.get_mut(&key) {
                    held.last_cursor = Some(next_cursor);
                }
                self.report.record_success("checkpoint");
                Ok(())
            }
            Err(
                CheckpointError::StaleFence { .. }
                | CheckpointError::LeaseExpired { .. }
                | CheckpointError::ShardTerminal { .. }
                | CheckpointError::ShardNotFound { .. },
            ) => {
                self.leases.remove(&key);
                Ok(())
            }
            Err(CheckpointError::BackendError(err)) => {
                Err(self.backend_err("checkpoint", key, err))
            }
            Err(err) => Err(self.unexpected_err("checkpoint", key, err)),
        }
    }

    fn exec_complete(
        &mut self,
        key: ShardKey,
        logical_now: LogicalTime,
        round: usize,
    ) -> Result<(), String> {
        let Some(current) = self.leases.get(&key).cloned() else {
            return Ok(());
        };
        let Some(final_cursor) = terminal_cursor(&current) else {
            return Ok(());
        };
        let op_id = op_id_for_round(round, self.worker_index);
        match self.coord.complete(
            logical_now,
            test_tenant(),
            &current.lease,
            &gossip_coordination::CursorUpdate::new(&final_cursor),
            op_id,
        ) {
            Ok(_) => {
                self.leases.remove(&key);
                self.parked_hints.remove(&key.shard());
                self.report.record_success("complete");
                Ok(())
            }
            Err(
                CompleteError::StaleFence { .. }
                | CompleteError::LeaseExpired { .. }
                | CompleteError::ShardTerminal { .. }
                | CompleteError::ShardNotFound { .. },
            ) => {
                self.leases.remove(&key);
                Ok(())
            }
            Err(CompleteError::BackendError(err)) => Err(self.backend_err("complete", key, err)),
            Err(err) => Err(self.unexpected_err("complete", key, err)),
        }
    }

    fn exec_park(
        &mut self,
        key: ShardKey,
        logical_now: LogicalTime,
        round: usize,
    ) -> Result<(), String> {
        let Some(current) = self.leases.get(&key).cloned() else {
            return Ok(());
        };
        let op_id = op_id_for_round(round, self.worker_index);
        match self.coord.park_shard(
            logical_now,
            test_tenant(),
            &current.lease,
            ParkReason::TooManyErrors,
            op_id,
        ) {
            Ok(_) => {
                self.leases.remove(&key);
                self.parked_hints.insert(key.shard());
                self.report.record_success("park");
                Ok(())
            }
            Err(
                ParkError::StaleFence { .. }
                | ParkError::LeaseExpired { .. }
                | ParkError::ShardTerminal { .. }
                | ParkError::ShardNotFound { .. },
            ) => {
                self.leases.remove(&key);
                Ok(())
            }
            Err(ParkError::BackendError(err)) => Err(self.backend_err("park", key, err)),
            Err(err) => Err(self.unexpected_err("park", key, err)),
        }
    }

    fn exec_unpark(
        &mut self,
        key: ShardKey,
        logical_now: LogicalTime,
        round: usize,
    ) -> Result<(), String> {
        let op_id = op_id_for_round(round, self.worker_index);
        match self
            .coord
            .unpark_shard(logical_now, test_tenant(), key, op_id)
        {
            Ok(_) => {
                self.parked_hints.remove(&key.shard());
                self.report.record_success("unpark");
                Ok(())
            }
            Err(
                UnparkError::NotParked { .. }
                | UnparkError::RunTerminal { .. }
                | UnparkError::ShardNotFound,
            ) => {
                // Shard is not actually parked (or no longer exists); clear
                // the stale hint so future rounds don't retry unpark on it.
                self.parked_hints.remove(&key.shard());
                Ok(())
            }
            Err(UnparkError::BackendError(err)) => Err(self.backend_err("unpark", key, err)),
            Err(err) => Err(self.unexpected_err("unpark", key, err)),
        }
    }

    fn exec_split_replace(
        &mut self,
        key: ShardKey,
        logical_now: LogicalTime,
        round: usize,
    ) -> Result<(), String> {
        let Some(current) = self.leases.get(&key).cloned() else {
            return Ok(());
        };
        let Some(mid) = split_replace_midpoint(&current, &mut self.rng) else {
            return Ok(());
        };
        let plan = plan_split_replace_at_points_initial_cursor(
            gossip_coordination::ShardSpecRef::with_range(&current.range_start, &current.range_end),
            [mid.as_slice()],
        )
        .map_err(|err| {
            format!(
                "worker {} split_replace plan build failed: {err:?}",
                self.worker_index + 1
            )
        })?;
        let op_id = op_id_for_round(round, self.worker_index);
        match self
            .coord
            .split_replace(logical_now, test_tenant(), &current.lease, plan, op_id)
        {
            Ok(outcome) => {
                let SplitReplaceResult { children } = outcome.into_inner();
                self.leases.remove(&key);
                self.parked_hints.remove(&key.shard());
                // The parent shard is now terminal; remove it from acquire
                // candidates. It stays in `discovered_shards` for S7 verification.
                self.known_shards.remove(&key.shard());
                for &child in &children {
                    self.known_shards.insert(child);
                    self.report.discovered_shards.insert(child);
                }
                self.report.record_success("split_replace");
                Ok(())
            }
            Err(
                SplitReplaceError::StaleFence { .. }
                | SplitReplaceError::LeaseExpired { .. }
                | SplitReplaceError::ShardTerminal { .. }
                | SplitReplaceError::ShardNotFound { .. },
            ) => {
                self.leases.remove(&key);
                Ok(())
            }
            Err(SplitReplaceError::BackendError(err)) => {
                Err(self.backend_err("split_replace", key, err))
            }
            Err(err) => Err(self.unexpected_err("split_replace", key, err)),
        }
    }

    fn exec_split_residual(
        &mut self,
        key: ShardKey,
        logical_now: LogicalTime,
        round: usize,
    ) -> Result<(), String> {
        let Some(current) = self.leases.get(&key).cloned() else {
            return Ok(());
        };
        let Some(mid) = split_residual_midpoint(&current, &mut self.rng) else {
            return Ok(());
        };
        let plan = plan_split_residual_at_point(
            gossip_coordination::ShardSpecRef::with_range(&current.range_start, &current.range_end),
            &mid,
        )
        .map_err(|err| {
            format!(
                "worker {} split_residual plan build failed: {err:?}",
                self.worker_index + 1
            )
        })?;
        let op_id = op_id_for_round(round, self.worker_index);
        match self
            .coord
            .split_residual(logical_now, test_tenant(), &current.lease, plan, op_id)
        {
            Ok(outcome) => {
                let SplitResidualResult { residual } = outcome.into_inner();
                if let Some(held) = self.leases.get_mut(&key) {
                    held.range_end = mid.clone();
                }
                self.known_shards.insert(residual);
                self.report.discovered_shards.insert(residual);
                self.report.record_success("split_residual");
                Ok(())
            }
            Err(
                SplitResidualError::StaleFence { .. }
                | SplitResidualError::LeaseExpired { .. }
                | SplitResidualError::ShardTerminal { .. }
                | SplitResidualError::ShardNotFound { .. },
            ) => {
                self.leases.remove(&key);
                Ok(())
            }
            Err(SplitResidualError::BackendError(err)) => {
                Err(self.backend_err("split_residual", key, err))
            }
            Err(err) => Err(self.unexpected_err("split_residual", key, err)),
        }
    }

    fn random_acquire_key(&mut self) -> ShardKey {
        let mut candidates: Vec<ShardId> = self
            .known_shards
            .iter()
            .copied()
            .filter(|shard_id| {
                !self
                    .leases
                    .contains_key(&ShardKey::new(run_id(), *shard_id))
            })
            .collect();
        if candidates.is_empty() {
            candidates.extend(self.known_shards.iter().copied());
        }
        let shard = candidates[self.rng.random_range(0..candidates.len())];
        ShardKey::new(run_id(), shard)
    }

    fn random_held_key(&mut self) -> ShardKey {
        let keys: Vec<ShardKey> = self.leases.keys().copied().collect();
        keys[self.rng.random_range(0..keys.len())]
    }

    fn random_parked_key(&mut self) -> ShardKey {
        let parked: Vec<ShardId> = self.parked_hints.iter().copied().collect();
        ShardKey::new(run_id(), parked[self.rng.random_range(0..parked.len())])
    }

    fn random_split_op(&mut self) -> PlannedOp {
        let keys: Vec<ShardKey> = self.leases.keys().copied().collect();
        let mut replace_candidates = Vec::new();
        let mut residual_candidates = Vec::new();
        for key in &keys {
            let Some(held) = self.leases.get(key) else {
                continue;
            };
            if can_split_replace(held) {
                replace_candidates.push(*key);
            }
            if can_split_residual(held) {
                residual_candidates.push(*key);
            }
        }

        if !residual_candidates.is_empty() && self.rng.random_bool(0.5) {
            let key = residual_candidates[self.rng.random_range(0..residual_candidates.len())];
            return PlannedOp::SplitResidual(key);
        }
        if !replace_candidates.is_empty() {
            let key = replace_candidates[self.rng.random_range(0..replace_candidates.len())];
            return PlannedOp::SplitReplace(key);
        }
        PlannedOp::Checkpoint(self.random_held_key())
    }
}

#[test]
#[ignore = "requires a live etcd endpoint or Docker-backed testcontainers"]
fn concurrent_cas_contention_preserves_invariants() {
    let seeds = selected_seeds(DEFAULT_SEED_COUNT);
    let mut aggregate = ThreadReport::default();
    let mut failures = Vec::new();

    for seed in &seeds {
        match run_seed(*seed) {
            Ok(stats) => aggregate.merge(&stats),
            Err(err) => failures.push((*seed, err)),
        }
    }

    assert!(
        failures.is_empty(),
        "contention harness failed for {}/{} seed(s):\n{}",
        failures.len(),
        seeds.len(),
        failures
            .iter()
            .map(|(seed, err)| format!(
                "  seed {seed}: {err}\n  Reproduce: {}",
                repro_command(*seed)
            ))
            .collect::<Vec<_>>()
            .join("\n\n")
    );

    for label in [
        "acquire",
        "checkpoint",
        "renew",
        "complete",
        "park",
        "unpark",
    ] {
        assert!(
            aggregate.success_count(label) > 0,
            "expected at least one successful {label} across {} seed(s); successes={:?}",
            seeds.len(),
            aggregate.successes
        );
    }
    assert!(
        aggregate.success_count("split_replace") + aggregate.success_count("split_residual") > 0,
        "expected at least one successful split across {} seed(s); successes={:?}",
        seeds.len(),
        aggregate.successes
    );
}

fn run_seed(seed: u64) -> Result<ThreadReport, String> {
    let namespace = contention_namespace();
    seed_shared_namespace(&namespace)?;

    let barrier_start = Arc::new(Barrier::new(N_WORKERS));
    let barrier_end = Arc::new(Barrier::new(N_WORKERS));
    let stop = Arc::new(AtomicBool::new(false));
    let hard_errors = Arc::new(Mutex::new(Vec::new()));

    let reports: Vec<ThreadReport> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..N_WORKERS)
            .map(|worker_index| {
                let namespace = namespace.clone();
                let barrier_start = Arc::clone(&barrier_start);
                let barrier_end = Arc::clone(&barrier_end);
                let stop = Arc::clone(&stop);
                let hard_errors = Arc::clone(&hard_errors);
                scope.spawn(move || {
                    let mut harness = match std::panic::catch_unwind(AssertUnwindSafe(|| {
                        WorkerHarness::new(
                            worker_index,
                            &namespace,
                            seed ^ ((worker_index as u64 + 1) << 32),
                        )
                    })) {
                        Ok(h) => h,
                        Err(panic_payload) => {
                            stop.store(true, Ordering::Release);
                            let msg = match panic_payload.downcast_ref::<&str>() {
                                Some(s) => (*s).to_string(),
                                None => panic_payload
                                    .downcast_ref::<String>()
                                    .cloned()
                                    .unwrap_or_else(|| "unknown panic".to_string()),
                            };
                            hard_errors
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(format!(
                                    "worker {} panicked during construction: {msg}",
                                    worker_index + 1
                                ));
                            // Drain barriers so other threads are not stuck waiting.
                            for _ in 0..TOTAL_ROUNDS {
                                barrier_start.wait();
                                barrier_end.wait();
                            }
                            return ThreadReport::default();
                        }
                    };
                    for round in 0..TOTAL_ROUNDS {
                        barrier_start.wait();
                        if !stop.load(Ordering::Acquire) {
                            let round_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                // Advance time 3x faster in mixed rounds so
                                // leases acquired early expire mid-test
                                // (lease duration = 30 ticks).
                                let base_ticks = if round < ROOT_RACE_ROUNDS {
                                    (round + 10) as u64
                                } else {
                                    ((round - ROOT_RACE_ROUNDS) * 3 + ROOT_RACE_ROUNDS + 10) as u64
                                };
                                // Per-worker offset so different workers
                                // present slightly different clocks.
                                let logical_now = now(base_ticks + worker_index as u64);
                                harness.run_round(round, logical_now)
                            }));
                            match round_result {
                                Ok(Ok(())) => {}
                                Ok(Err(err)) => {
                                    stop.store(true, Ordering::Release);
                                    hard_errors
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .push(err);
                                }
                                Err(panic_payload) => {
                                    stop.store(true, Ordering::Release);
                                    let msg = match panic_payload.downcast_ref::<&str>() {
                                        Some(s) => (*s).to_string(),
                                        None => panic_payload
                                            .downcast_ref::<String>()
                                            .cloned()
                                            .unwrap_or_else(|| "unknown panic".to_string()),
                                    };
                                    hard_errors.lock().unwrap_or_else(|e| e.into_inner()).push(
                                        format!(
                                            "worker {} panicked in round {round}: \
                                             {msg}",
                                            worker_index + 1
                                        ),
                                    );
                                }
                            }
                        }
                        barrier_end.wait();
                    }
                    harness.report
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });

    let hard_errors = hard_errors.lock().unwrap_or_else(|e| e.into_inner());
    if !hard_errors.is_empty() {
        return Err(hard_errors.join("\n---\n"));
    }

    let mut aggregate = ThreadReport::default();
    for report in &reports {
        aggregate.merge(report);
        aggregate
            .discovered_shards
            .extend(report.discovered_shards.iter().copied());
    }

    // Split success depends on CAS contention outcomes and scheduling;
    // individual seeds may not produce splits. The suite-level aggregate
    // assertion enforces overall split coverage across all seeds.
    if aggregate.discovered_shards.len() <= ROOT_RACE_ROUNDS {
        eprintln!(
            "note: seed did not observe splits beyond the {ROOT_RACE_ROUNDS} roots \
             (discovered {} total shard IDs); suite-level check will enforce coverage",
            aggregate.discovered_shards.len()
        );
    }

    assert_single_winner_per_race(&reports)?;
    verify_quiescent_state(&namespace, &aggregate.discovered_shards)?;

    Ok(aggregate)
}

fn seed_shared_namespace(namespace: &str) -> Result<(), String> {
    let mut setup = test_coordinator_in_namespace(namespace);
    setup
        .create_run(now(1), test_tenant(), run_id(), short_lease_run_config())
        .map_err(|err| format!("create_run failed during setup: {err}"))?;
    let manifest = root_manifest();
    let outcome = setup
        .register_shards(
            now(2),
            test_tenant(),
            run_id(),
            &manifest,
            OpId::from_raw(1),
        )
        .map_err(|err| format!("register_shards failed during setup: {err}"))?;
    assert!(
        matches!(outcome, gossip_coordination::IdempotentOutcome::Executed(_)),
        "expected fresh registration in unique namespace, got replayed outcome"
    );
    Ok(())
}

/// Verify structural invariants at quiescence.
///
/// The `InvariantChecker` runs once after all workers have finished, so it
/// can only verify structural invariants (S4 record validity, S6 cursor bounds,
/// S7 split coverage), static state (S1 mutual exclusion, S8 run-terminal
/// irreversibility), and counter conservation. Temporal invariants (S2, S3, S5) require
/// per-step checking, which the differential oracle test provides.
fn verify_quiescent_state(
    namespace: &str,
    discovered_shards: &BTreeSet<ShardId>,
) -> Result<(), String> {
    // Mirror the worker time formula: the last mixed round (TOTAL_ROUNDS - 1)
    // produces base_ticks = (MIXED_ROUNDS - 1) * 3 + ROOT_RACE_ROUNDS + 10,
    // plus the maximum per-worker offset (N_WORKERS - 1). Add a margin past
    // the lease duration so the checker observes a truly quiescent post-expiry
    // state.
    let max_worker_tick = ((MIXED_ROUNDS - 1) * 3 + ROOT_RACE_ROUNDS + 10 + (N_WORKERS - 1)) as u64;
    let final_now = now(max_worker_tick + 50);
    let mut observed = ObservedEtcdCoordinator::new(test_coordinator_in_namespace(namespace));
    observed.note_run(test_tenant(), run_id());
    observed.note_shards(test_tenant(), run_id(), discovered_shards.iter().copied());
    observed.refresh_run_state(test_tenant(), run_id(), "contention verifier");

    let mut checker = InvariantChecker::with_cooldown_interval(VERIFY_COOLDOWN_INTERVAL);
    let violations = checker.check_all(&observed, test_tenant(), final_now);
    if !violations.is_empty() {
        return Err(format!(
            "invariant violations after contention: {violations:#?}"
        ));
    }

    let counter_reader = test_coordinator_in_namespace(namespace);
    let counter = counter_reader
        .test_load_tenant_shard_count(test_tenant())
        .map_err(|err| format!("failed to load tenant shard counter: {err}"))?
        .ok_or_else(|| "tenant shard counter was absent after contention".to_string())?;

    let mut summaries = Vec::new();
    counter_reader
        .list_shards_into(
            final_now,
            test_tenant(),
            run_id(),
            ShardFilter::all(),
            &mut summaries,
        )
        .map_err(|err| format!("failed to list shards for conservation check: {err}"))?;

    let actual_count = summaries.len() as u64;
    if counter != actual_count {
        return Err(format!(
            "tenant shard counter drifted from persisted shard count: counter={counter}, actual={actual_count}"
        ));
    }

    if observed.shard_count() != summaries.len() {
        return Err(format!(
            "observed cache did not cover all persisted shards: cache={}, list_shards_into={}",
            observed.shard_count(),
            summaries.len()
        ));
    }

    Ok(())
}

fn assert_single_winner_per_race(reports: &[ThreadReport]) -> Result<(), String> {
    for (root_id, _, _) in root_shards() {
        let winners = reports
            .iter()
            .filter_map(|report| report.acquire_races.get(&root_id))
            .filter(|outcome| matches!(outcome, AcquireRaceOutcome::Won))
            .count();
        let losers = reports
            .iter()
            .filter_map(|report| report.acquire_races.get(&root_id))
            .filter(|outcome| matches!(outcome, AcquireRaceOutcome::LostContention))
            .count();
        let total = winners + losers;
        if total != N_WORKERS {
            return Err(format!(
                "acquire race on {root_id:?}: only {total}/{N_WORKERS} workers recorded \
                 an outcome (winners={winners}, losers={losers}); {} workers did not participate",
                N_WORKERS - total
            ));
        }
        if winners != 1 {
            return Err(format!(
                "expected exactly one winner for acquire race on {root_id:?}, \
                 got winners={winners}, losers={losers}",
            ));
        }
    }
    Ok(())
}

fn root_manifest() -> [InitialShardInput<'static>; ROOT_RACE_ROUNDS] {
    root_shards().map(|(shard, start, end)| {
        InitialShardInput::new(
            shard,
            gossip_coordination::ShardSpecRef::new(start, end, b""),
            gossip_coordination::CursorUpdate::initial(),
        )
    })
}

fn root_shards() -> [(ShardId, &'static [u8], &'static [u8]); ROOT_RACE_ROUNDS] {
    // Wide single-byte ranges (~64 values each) allow multiple levels of
    // binary splits before the range becomes too narrow.
    [
        (ShardId::from_raw(0x9020_1401), &[0x00], &[0x40]),
        (ShardId::from_raw(0x9020_1402), &[0x40], &[0x80]),
        (ShardId::from_raw(0x9020_1403), &[0x80], &[0xC0]),
        (ShardId::from_raw(0x9020_1404), &[0xC0], &[0xFF]),
    ]
}

fn root_key_for_round(round: usize) -> ShardKey {
    let (shard, _, _) = root_shards()[round];
    ShardKey::new(run_id(), shard)
}

fn run_id() -> RunId {
    RunId::from_raw(0x9020_1400)
}

fn next_checkpoint_cursor(held: &HeldLease) -> Option<Vec<u8>> {
    let low = *held.range_start.first()?;
    let high = held.range_end.first().copied()?.checked_sub(1)?;
    let next = match held
        .last_cursor
        .as_ref()
        .and_then(|cursor| cursor.first().copied())
    {
        Some(current) if current < high => current + 1,
        Some(current) => current,
        None => low,
    };
    Some(vec![next])
}

fn terminal_cursor(held: &HeldLease) -> Option<Vec<u8>> {
    let final_byte = held.range_end.first().copied()?.checked_sub(1)?;
    Some(vec![final_byte])
}

fn split_replace_midpoint(held: &HeldLease, rng: &mut ChaCha8Rng) -> Option<Vec<u8>> {
    let start = *held.range_start.first()?;
    let end = *held.range_end.first()?;
    if end <= start.saturating_add(1) {
        return None;
    }
    Some(vec![rng.random_range(start.saturating_add(1)..end)])
}

/// Predicate form of [`split_replace_midpoint`] that avoids consuming RNG state.
///
/// Candidate discovery in [`WorkerHarness::random_split_op`] must not advance
/// the RNG — doing so would make the operation sequence seed-dependent on which
/// shards happen to be held, breaking reproducibility.
fn can_split_replace(held: &HeldLease) -> bool {
    held.range_start
        .first()
        .zip(held.range_end.first())
        .is_some_and(|(&start, &end)| end > start.saturating_add(1))
}

fn split_residual_midpoint(held: &HeldLease, rng: &mut ChaCha8Rng) -> Option<Vec<u8>> {
    let start = *held.range_start.first()?;
    let end = *held.range_end.first()?;
    if end <= start.saturating_add(1) {
        return None;
    }
    let cursor = held
        .last_cursor
        .as_ref()
        .and_then(|cursor| cursor.first().copied())
        .unwrap_or(start);
    let low = cursor.saturating_add(1).max(start.saturating_add(1));
    if low >= end {
        return None;
    }
    Some(vec![rng.random_range(low..end)])
}

/// Predicate form of [`split_residual_midpoint`] that avoids consuming RNG state.
///
/// See [`can_split_replace`] for rationale.
fn can_split_residual(held: &HeldLease) -> bool {
    let Some(&start) = held.range_start.first() else {
        return false;
    };
    let Some(&end) = held.range_end.first() else {
        return false;
    };
    if end <= start.saturating_add(1) {
        return false;
    }
    let cursor = held
        .last_cursor
        .as_ref()
        .and_then(|cursor| cursor.first().copied())
        .unwrap_or(start);
    cursor.saturating_add(1).max(start.saturating_add(1)) < end
}

fn op_id_for_round(round: usize, worker_index: usize) -> OpId {
    OpId::from_raw(((round as u64 + 1) << 8) | (worker_index as u64 + 1))
}

fn parse_seed_count(default: usize) -> usize {
    match std::env::var("GOSSIP_CAS_SEEDS") {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|err| panic!("GOSSIP_CAS_SEEDS={value:?} is not a valid usize: {err}")),
        Err(_) => default,
    }
}

fn parse_single_seed() -> Option<u64> {
    std::env::var("GOSSIP_CAS_SEED").ok().map(|value| {
        value
            .parse()
            .unwrap_or_else(|err| panic!("GOSSIP_CAS_SEED={value:?} is not a valid u64: {err}"))
    })
}

fn selected_seeds(default_count: usize) -> Vec<u64> {
    if let Some(seed) = parse_single_seed() {
        vec![seed]
    } else {
        (0..parse_seed_count(default_count) as u64).collect()
    }
}

fn repro_command(seed: u64) -> String {
    format!(
        "GOSSIP_CAS_SEED={seed} cargo test -p gossip-coordination-etcd --features test-support \
         --test concurrent_cas_contention concurrent_cas_contention_preserves_invariants \
         -- --ignored --exact --nocapture"
    )
}
