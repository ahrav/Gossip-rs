//! Shared differential-oracle helpers for coordination integration tests.
//!
//! The oracle compares two simulation backends at the coordination boundary:
//! emitted events, full shard/run state, and invariant-check results. Backend-
//! specific storage details such as slab addresses or etcd lease identifiers
//! are normalized away before comparison.

use std::collections::BTreeMap;

use gossip_contracts::coordination::{PooledCursor, PooledShardSpec, PooledSpawned};
use gossip_coordination::sim::test_util::arb_sim_op;
use gossip_coordination::sim::{CoordinationSim, SimIntrospection, SimOp, SimulationBackend};
use gossip_coordination::{
    LogicalTime, OpId, OpKind, RunConfig, RunId, RunOpKind, RunOpResult, RunRecord, RunStatus,
    ShardId, ShardKey, ShardRecord, ShardStatus, TenantId, WorkerId,
};
use gossip_coordination_etcd::EtcdCoordinatorConfig;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, TestRng, TestRunner};

/// Pairs two simulation harnesses and panics on any behavioral drift.
pub(crate) struct DifferentialOracle<L: SimulationBackend, R: SimulationBackend> {
    left: CoordinationSim<L>,
    right: CoordinationSim<R>,
    left_label: &'static str,
    right_label: &'static str,
    reproduce: String,
    seed: u64,
}

/// Debug payload emitted on drift so failures show both backends' views.
struct DriftComparison {
    left_event: String,
    right_event: String,
    left_detail: String,
    right_detail: String,
}

/// Lease fields that are semantically visible at the coordination boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableLease {
    owner: WorkerId,
    deadline: LogicalTime,
}

/// Shard op-log entry with backend-specific storage details removed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableShardOpLogEntry {
    op_id: OpId,
    kind: OpKind,
    result: gossip_coordination::OpResult,
    payload_hash: u64,
    executed_at: LogicalTime,
}

/// Run op-log entry with backend-specific storage details removed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableRunOpLogEntry {
    op_id: OpId,
    kind: RunOpKind,
    payload_hash: u64,
    executed_at: LogicalTime,
    result: RunOpResult,
}

/// Full shard state snapshot normalized for cross-backend comparison.
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

/// Full run state snapshot normalized for cross-backend comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableRunState {
    config: RunConfig,
    status: RunStatus,
    created_at: LogicalTime,
    completed_at: Option<LogicalTime>,
    root_shards: Vec<ShardId>,
    op_log: Vec<ComparableRunOpLogEntry>,
}

/// Aggregate normalized backend state after a simulation step.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComparableBackendState {
    runs: BTreeMap<(TenantId, RunId), ComparableRunState>,
    shards: BTreeMap<(TenantId, ShardKey), ComparableShardState>,
}

// ShardRecord fields compared (via ComparableShardState):
//   status, park_reason, spec (via spec_bounds -> spec_start/spec_end),
//   cursor (via cursor_last_key), cursor_semantics, lease (via ComparableLease:
//   owner + deadline), fence_epoch, parent, spawned (via spawned_children), op_log
//
// ShardRecord fields excluded (map keys, not state):
//   tenant, run, shard
//
// RunRecord fields compared (via ComparableRunState):
//   config, status, created_at, completed_at, root_shards, op_log
//
// RunRecord fields excluded (map keys):
//   tenant, run

// Tripwire: if the record layouts change, audit `comparable_state` so newly
// added fields are either compared or explicitly documented as excluded.
//
// The pooled-type assertions guard against field additions to the slab-backed
// wrappers that would bypass the record-level tripwire (a new ByteSlot field
// in PooledShardSpec wouldn't change ShardRecord's size because the slab
// stores the bytes externally).
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<ShardRecord>() == 728);
    assert!(std::mem::size_of::<RunRecord>() == 512);
    assert!(std::mem::size_of::<PooledShardSpec>() == 48);
    assert!(std::mem::size_of::<PooledCursor>() == 40);
    assert!(std::mem::size_of::<PooledSpawned>() == 20);
};

impl<L: SimulationBackend, R: SimulationBackend> DifferentialOracle<L, R> {
    /// Construct an oracle and verify both harnesses start from the same state.
    pub(crate) fn new(
        left: CoordinationSim<L>,
        left_label: &'static str,
        right: CoordinationSim<R>,
        right_label: &'static str,
        seed: u64,
        reproduce: impl Into<String>,
    ) -> Self {
        let oracle = Self {
            left,
            right,
            left_label,
            right_label,
            reproduce: reproduce.into(),
            seed,
        };

        let left_state = comparable_state(oracle.left.backend()).unwrap_or_else(|err| {
            panic!(
                "initial differential-oracle state load failed\n\
                 seed={}\n\
                 side={}\n\
                 reproduce={}\n\
                 error={err}",
                oracle.seed, oracle.left_label, oracle.reproduce,
            )
        });
        let right_state = comparable_state(oracle.right.backend()).unwrap_or_else(|err| {
            panic!(
                "initial differential-oracle state load failed\n\
                 seed={}\n\
                 side={}\n\
                 reproduce={}\n\
                 error={err}",
                oracle.seed, oracle.right_label, oracle.reproduce,
            )
        });

        if left_state != right_state {
            panic!(
                "initial differential-oracle state drift detected\n\
                 seed={}\n\
                 left_label={}\n\
                 right_label={}\n\
                 reproduce={}\n\
                 left_state={left_state:#?}\n\
                 right_state={right_state:#?}",
                oracle.seed, oracle.left_label, oracle.right_label, oracle.reproduce,
            );
        }

        oracle
    }

    /// Drive both harnesses with the same operation sequence and compare every step.
    pub(crate) fn run_sequence(&mut self, ops: &[SimOp]) {
        for (step, op) in ops.iter().enumerate() {
            let (left_event, left_violations) = self.left.step(op.clone());
            let (right_event, right_violations) = self.right.step(op.clone());

            if !left_violations.is_empty() || !right_violations.is_empty() {
                panic_drift(
                    self,
                    step,
                    op,
                    ops,
                    "invariant violation",
                    DriftComparison {
                        left_event: format!("{left_event:#?}"),
                        right_event: format!("{right_event:#?}"),
                        left_detail: format!("{left_violations:#?}"),
                        right_detail: format!("{right_violations:#?}"),
                    },
                );
            }

            if left_event != right_event {
                panic_drift(
                    self,
                    step,
                    op,
                    ops,
                    "event drift",
                    DriftComparison {
                        left_event: format!("{left_event:#?}"),
                        right_event: format!("{right_event:#?}"),
                        left_detail: String::new(),
                        right_detail: String::new(),
                    },
                );
            }

            let left_state = comparable_state(self.left.backend()).unwrap_or_else(|err| {
                panic_drift(
                    self,
                    step,
                    op,
                    ops,
                    "left comparable_state failed",
                    DriftComparison {
                        left_event: format!("{left_event:#?}"),
                        right_event: format!("{right_event:#?}"),
                        left_detail: err,
                        right_detail: String::new(),
                    },
                );
            });
            let right_state = comparable_state(self.right.backend()).unwrap_or_else(|err| {
                panic_drift(
                    self,
                    step,
                    op,
                    ops,
                    "right comparable_state failed",
                    DriftComparison {
                        left_event: format!("{left_event:#?}"),
                        right_event: format!("{right_event:#?}"),
                        left_detail: String::new(),
                        right_detail: err,
                    },
                );
            });

            if left_state != right_state {
                panic_drift(
                    self,
                    step,
                    op,
                    ops,
                    "state drift",
                    DriftComparison {
                        left_event: format!("{left_event:#?}"),
                        right_event: format!("{right_event:#?}"),
                        left_detail: format!("{left_state:#?}"),
                        right_detail: format!("{right_state:#?}"),
                    },
                );
            }
        }
    }
}

fn panic_drift<L: SimulationBackend, R: SimulationBackend>(
    oracle: &DifferentialOracle<L, R>,
    step: usize,
    op: &SimOp,
    ops: &[SimOp],
    reason: &str,
    comparison: DriftComparison,
) -> ! {
    panic!(
        "differential oracle drift detected\n\
         seed={}\n\
         step={step}\n\
         op={op:#?}\n\
         reason={reason}\n\
         left_label={}\n\
         right_label={}\n\
         reproduce={}\n\
         left_event={}\n\
         right_event={}\n\
         left_detail={}\n\
         right_detail={}\n\
         full_sequence={ops:#?}",
        oracle.seed,
        oracle.left_label,
        oracle.right_label,
        oracle.reproduce,
        comparison.left_event,
        comparison.right_event,
        comparison.left_detail,
        comparison.right_detail,
    );
}

fn comparable_state<B: SimIntrospection>(backend: &B) -> Result<ComparableBackendState, String> {
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
                root_shards: {
                    let mut shards = record.root_shards.clone();
                    shards.sort_unstable();
                    shards
                },
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
            .map_err(|err| format!("invalid record for {key:?}: {err}"))?;
        let (start, end) = backend.spec_bounds(record);
        let lease = record.lease().map(|lease| ComparableLease {
            owner: lease.owner(),
            deadline: lease.deadline(),
        });

        shards.insert(
            (tenant, key),
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
                spawned: {
                    let mut spawned: Vec<_> = backend.spawned_children(record).collect();
                    spawned.sort_unstable();
                    spawned
                },
                op_log: record
                    .op_log
                    .iter()
                    .map(|entry| ComparableShardOpLogEntry {
                        op_id: entry.op_id(),
                        kind: entry.kind(),
                        result: entry.result(),
                        payload_hash: entry.payload_hash(),
                        executed_at: entry.executed_at(),
                    })
                    .collect(),
            },
        );
    }

    let count = backend.shard_count();
    if count != shards.len() {
        return Err(format!(
            "SimIntrospection::shard_count ({count}) disagrees with shard iteration ({})",
            shards.len(),
        ));
    }

    Ok(ComparableBackendState { runs, shards })
}

pub(crate) const N_WORKERS: u64 = 4;
pub(crate) const N_SHARDS: u64 = 8;
pub(crate) const OWNER_LEASE_TTL_SECS: i64 = 300;
pub(crate) const OPTIMISTIC_TXN_RETRIES: usize = 8;
pub(crate) const MAX_CHILDREN_PER_OP: usize = 8;

pub(crate) fn proptest_seed(seed: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes
}

pub(crate) fn generated_ops(seed: u64) -> Vec<SimOp> {
    let strategy = proptest::collection::vec(arb_sim_op(N_WORKERS, N_SHARDS), 15..50);
    let mut runner = TestRunner::new_with_rng(
        ProptestConfig {
            failure_persistence: None,
            ..ProptestConfig::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &proptest_seed(seed)),
    );

    strategy
        .new_tree(&mut runner)
        .expect("SimOp strategy must generate a sequence")
        .current()
}

pub(crate) fn etcd_sim_config(namespace: &str) -> EtcdCoordinatorConfig {
    EtcdCoordinatorConfig::new_with_tuning(
        ["http://127.0.0.1:2379"],
        namespace,
        OWNER_LEASE_TTL_SECS,
        OPTIMISTIC_TXN_RETRIES,
        MAX_CHILDREN_PER_OP,
    )
    .expect("differential oracle config must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossip_coordination::InMemoryCoordinator;
    use gossip_coordination::sim::{CoordinationSim, FaultLevel, SimOp};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Verify the oracle detects genuine state drift between two backends
    /// with different lease duration configurations. The mismatch in
    /// `default_lease_duration` causes divergent lease deadlines on acquire,
    /// which the per-step state comparison must catch.
    #[test]
    fn oracle_detects_deliberate_drift() {
        let seed = 42;

        let fast = InMemoryCoordinator::new(100);
        let slow = InMemoryCoordinator::new(50);

        let left = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, fast)
            .with_workers_and_shards(2, 4);
        let right = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, slow)
            .with_workers_and_shards(2, 4);

        let mut oracle =
            DifferentialOracle::new(left, "fast_lease", right, "slow_lease", seed, "meta-test");

        // Acquire a shard — different lease durations produce different deadlines.
        let ops = vec![SimOp::Acquire {
            worker: WorkerId::from_raw(1),
            key: ShardKey::new(RunId::from_raw(1), ShardId::from_raw(1)),
        }];

        let result = catch_unwind(AssertUnwindSafe(|| oracle.run_sequence(&ops)));
        let err = result.expect_err("oracle must panic on deliberate lease-deadline drift");
        let msg = err
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .unwrap_or("");
        assert!(
            msg.contains("drift"),
            "panic message must mention drift, got: {msg}"
        );
    }
}
