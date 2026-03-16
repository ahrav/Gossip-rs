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
//! internal slab addresses) are **stripped** before comparison. Events are
//! compared directly as [`SimEvent`] values (which derive `PartialEq`);
//! state snapshots are compared via the `Comparable*` wrapper types that
//! normalize away backend-specific fields.
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
//! cargo test -p gossip-coordination-etcd --features test-support -- --ignored no_model_drift
//!
//! # External etcd:
//! ETCD_ENDPOINTS=http://localhost:2379 cargo test -p gossip-coordination-etcd --features test-support -- --ignored no_model_drift
//! ```

mod support;

use std::collections::BTreeMap;

use gossip_contracts::test_util::miri_proptest_config;
use gossip_coordination::sim::test_util::arb_sim_op;
use gossip_coordination::sim::{CoordinationSim, FaultLevel, SimIntrospection, SimOp};
use gossip_coordination::{
    LogicalTime, OpId, OpKind, RunConfig, RunId, RunOpKind, RunOpResult, RunRecord, RunStatus,
    ShardId, ShardRecord, ShardStatus, TenantId, WorkerId,
};
use gossip_coordination_etcd::test_support::test_coordinator_with_tuning;
use gossip_coordination_etcd::{EtcdCoordinatorConfig, SimEtcdCoordinator};
use proptest::prelude::*;
use support::{ObservedEtcdCoordinator, ShardCacheKey};

// ---------------------------------------------------------------------------
// Simulation topology constants
// ---------------------------------------------------------------------------

const N_WORKERS: u64 = 4;
const N_SHARDS: u64 = 8;

/// Dual-purpose TTL applied to etcd owner leases in both backends.
///
/// **Wall-clock dimension (real etcd):** 300 real seconds prevents the
/// real etcd backend's lease from expiring during a fast-running test.
///
/// **Logical-time dimension (SimEtcdCoordinator):** The simulated KV store
/// expires leases when `logical_now >= grant_time + TTL`. No single
/// `AdvanceTime` step in `arb_sim_op` exceeds 150 ticks, so 300 provides
/// a 2x per-step safety margin. Cumulative advances across a full 50-op
/// sequence can theoretically exceed 300, but coordination-level behavior
/// remains identical: the per-shard logical deadline (`now + lease_duration`,
/// where `lease_duration = 100`) expires well before the etcd-level TTL,
/// so both backends observe the same lease-expired state at the
/// coordination boundary.
const OWNER_LEASE_TTL_SECS: i64 = 300;

const OPTIMISTIC_TXN_RETRIES: usize = 8;
const MAX_CHILDREN_PER_OP: usize = 8;

// ---------------------------------------------------------------------------
// Comparable* wrappers — implementation-detail-free comparison types
// ---------------------------------------------------------------------------
//
// These types mirror their production counterparts but omit fields that
// differ between the simulated and real etcd backends (etcd revision numbers,
// raw lease IDs, slab addresses). Comparing `Comparable*` values is the
// mechanism by which the oracle detects behavioral drift without being
// sensitive to implementation-level noise.

/// Lease fields for cross-backend comparison. Only the worker identity
/// and logical deadline are semantically meaningful at the coordination
/// boundary; backend-specific identifiers (etcd lease ID, slab slot) are
/// excluded.
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
///
/// `cursor_token` is intentionally omitted: the sim harness never exercises
/// token-based cursors, so the field is always `None` on both sides.
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

// Tripwire: if ShardRecord or RunRecord layout changes, audit `comparable_state`
// to ensure the new fields are captured (or intentionally excluded).
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<ShardRecord>() == 728);
    assert!(std::mem::size_of::<RunRecord>() == 512);
};

// ---------------------------------------------------------------------------
// Differential oracle — the core test driver
// ---------------------------------------------------------------------------

/// Pairs two `CoordinationSim` instances (simulated and live-etcd) and
/// drives them with identical operation sequences, panicking on any
/// divergence in events, state, or invariant violations.
struct DifferentialOracle {
    sim: CoordinationSim<SimEtcdCoordinator>,
    etcd: CoordinationSim<ObservedEtcdCoordinator>,
    seed: u64,
}

/// Debug payload carried into [`panic_drift`] for rich failure messages.
/// Pre-formatted as strings to avoid lifetime tangles in the panic path.
struct DriftComparison {
    sim_event: String,
    etcd_event: String,
    sim_detail: String,
    etcd_detail: String,
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
        let etcd_backend = ObservedEtcdCoordinator::new(test_coordinator_with_tuning(
            OWNER_LEASE_TTL_SECS,
            OPTIMISTIC_TXN_RETRIES,
            MAX_CHILDREN_PER_OP,
        ));

        let sim = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, sim_backend)
            .with_workers_and_shards(N_WORKERS, N_SHARDS);
        let etcd = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, etcd_backend)
            .with_workers_and_shards(N_WORKERS, N_SHARDS);

        let oracle = Self { sim, etcd, seed };
        let sim_state = comparable_state(oracle.sim.backend())
            .expect("sim comparable_state failed during initial check");
        let etcd_state = comparable_state(oracle.etcd.backend())
            .expect("etcd comparable_state failed during initial check");
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
    ///    [`SimEvent`] for the same input.
    /// 3. **State equivalence** — full [`ComparableBackendState`] snapshots
    ///    must match after every step.
    ///
    /// On any divergence, the panic includes the seed, step index, failing
    /// operation, and the full operation sequence so the failure is
    /// deterministically reproducible.
    fn run_sequence(&mut self, ops: &[SimOp]) {
        let seed = self.seed;
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

            let sim_state = comparable_state(self.sim.backend()).unwrap_or_else(|err| {
                panic_drift(
                    seed,
                    step,
                    op,
                    ops,
                    "sim comparable_state failed",
                    DriftComparison {
                        sim_event: format!("{sim_event:#?}"),
                        etcd_event: format!("{etcd_event:#?}"),
                        sim_detail: err,
                        etcd_detail: String::new(),
                    },
                );
            });
            let etcd_state = comparable_state(self.etcd.backend()).unwrap_or_else(|err| {
                panic_drift(
                    seed,
                    step,
                    op,
                    ops,
                    "etcd comparable_state failed",
                    DriftComparison {
                        sim_event: format!("{sim_event:#?}"),
                        etcd_event: format!("{etcd_event:#?}"),
                        sim_detail: String::new(),
                        etcd_detail: err,
                    },
                );
            });
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
/// — returning an error rather than panicking so the caller can include oracle
/// context (seed, step, operation sequence) in the failure message.
///
/// Ends with a check that `shard_count()` agrees with the iteration length,
/// catching `SimIntrospection` implementations where the counter and iterator
/// diverge.
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
                    let mut v = record.root_shards.clone();
                    v.sort_unstable();
                    v
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
                spawned: {
                    let mut v: Vec<ShardId> = backend.spawned_children(record).collect();
                    v.sort_unstable();
                    v
                },
                op_log,
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
// Generates 50 random operation sequences (15–50 ops each) and feeds each
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
        ops in proptest::collection::vec(arb_sim_op(N_WORKERS, N_SHARDS), 15..50),
    ) {
        let mut oracle = DifferentialOracle::new(seed);
        oracle.run_sequence(&ops);
    }
}
