# Implementation Plan: Orchestrator / Control Plane Layer

## Executive Summary

The orchestrator is a **library crate** (`gossip-orchestrator`) that sits between
source-specific partitioning logic and the coordination layer. It automates the
manual workflow currently performed by `dev-seed` + `run-worker`: given a source
description, it partitions it into shards, creates a run, registers the manifest,
monitors progress, and handles dynamic splitting and straggler management.

The plan is structured as seven incremental steps, each independently testable
and shippable. Steps 1-4 produce the core library. Step 5 wires the CLI
one-shot path. Step 6 adds the production service integration. Step 7 adds
observability and straggler defense.

---

## Step 1: Crate scaffold and `SourcePartitioner` trait

### What

Create `crates/gossip-orchestrator/` with:

```rust
// crates/gossip-orchestrator/src/lib.rs
pub mod partition;
pub mod lifecycle;
pub mod policy;
pub mod error;

// crates/gossip-orchestrator/src/partition.rs

/// A single shard-to-be, produced by a partitioner before registration.
///
/// Carries the key range, connector-opaque metadata bytes (e.g., filesystem
/// root path), and the hint type for traceability. This is the partitioner's
/// output; the orchestrator converts it to `InitialShardInput` via
/// `PreallocShardBuilder`.
pub struct PlannedShard {
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub connector_extra: Vec<u8>,
}

/// Output of a partitioning operation.
pub struct PartitionPlan {
    pub shards: Vec<PlannedShard>,
    /// Estimated total bytes across all shards (best-effort).
    pub estimated_total_bytes: Option<u64>,
}

/// Source-agnostic partitioning contract.
///
/// Given a source description, produce a shard manifest. The trait is
/// deliberately synchronous: filesystem pre-walks are I/O but not
/// async (readdir is blocking), and the in-memory path needs no runtime.
pub trait SourcePartitioner {
    type Config;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Produce a partition plan from the given configuration.
    ///
    /// Implementations perform lightweight pre-enumeration (e.g., a
    /// shallow directory walk) to discover natural shard boundaries.
    fn partition(&self, config: &Self::Config) -> Result<PartitionPlan, Self::Error>;
}
```

**Filesystem implementation** (`FsPartitioner`):

```rust
// crates/gossip-orchestrator/src/partition/filesystem.rs

pub struct FsPartitionConfig {
    /// Filesystem target to scan. May be a regular file or a directory.
    pub path: PathBuf,
    /// Target bytes per shard (default: 256 MB).
    pub target_shard_bytes: u64,
    /// Maximum depth for the pre-walk (0 = root only, 1 = immediate children).
    pub pre_walk_depth: u32,
    /// Minimum shards to produce regardless of size estimate.
    pub min_shards: usize,
    /// Maximum shards to produce (bounded by MAX_INITIAL_SHARDS).
    pub max_shards: usize,
}

pub struct FsPartitioner;
```

The `FsPartitioner::partition` implementation:
1. Canonicalize the target path.
2. If the target is a regular file, emit a single full-range shard `[\x00, \xFF)` with `connector_extra` set to the canonical file path bytes, then stop. This preserves the current `scan fs` behavior for single-file scans.
3. If the target is a directory, walk directories up to `pre_walk_depth` levels, collecting `(prefix, estimated_bytes)` pairs. Byte estimation uses `fs::metadata().len()` for files and recursive `readdir` + `stat` for directories (bounded by depth).
4. Sort prefixes lexicographically.
5. Bin-pack prefixes into shards targeting `target_shard_bytes`, using a greedy next-fit algorithm. Each shard gets `[prefix_start, prefix_successor(prefix_end))` as its key range.
6. If the directory pre-walk produces fewer entries than `min_shards`, fall back to a single full-range shard `[\x00, \xFF)`.
7. Clamp shard count to `max_shards` and `MAX_INITIAL_SHARDS`.
8. Set `connector_extra` to the canonical target path bytes.

### Why

- **F54 (ES:4), F2 (ES:4):** Hybrid static + dynamic partitioning requires a coarse static phase. The pre-walk produces the static partition.
- **F19 (ES:5):** Hadoop `FileInputFormat` uses `goalSize = totalSize / numSplits`. The bin-packing approach is a refinement of this.
- **F21 (ES:5):** Spark's `openCostInBytes` motivates per-file overhead awareness. The depth-bounded pre-walk avoids the O(n) stat storm of a full walk while still getting reasonable size estimates.
- **F10 (ES:4):** Power-law directory sizes mean most directories are small but some are enormous. Depth-bounded pre-walk avoids getting stuck in million-entry directories.
- The current runtime accepts either a regular file or a directory for `scan fs`, so the orchestrated path must preserve that surface rather than narrowing it to directories only.

### Files

| Action | Path |
|--------|------|
| Create | `crates/gossip-orchestrator/Cargo.toml` |
| Create | `crates/gossip-orchestrator/src/lib.rs` |
| Create | `crates/gossip-orchestrator/src/partition.rs` (trait + `PlannedShard`) |
| Create | `crates/gossip-orchestrator/src/partition/filesystem.rs` |
| Create | `crates/gossip-orchestrator/src/error.rs` |
| Modify | `Cargo.toml` (add workspace member) |

### Risks

| Risk | Mitigation |
|------|-----------|
| **G1 (shard size tuning):** No empirical data on optimal filesystem shard size. | `target_shard_bytes` is configurable with a conservative default (256 MB). Adjust via benchmarks. |
| **R5 (NFS readdir stall):** Pre-walk readdir on NFS could block. | Bound pre-walk depth. Add per-directory timeout in a follow-up (Step 7). |
| **R6 (walk memory):** Deep pre-walk could consume excessive memory. | `pre_walk_depth` caps the traversal. Default depth=1 limits to immediate subdirectories of root. |

### Acceptance Criteria

1. `FsPartitioner::partition` on a regular file path produces exactly one full-range shard with `connector_extra` set to the canonical file path.
2. `FsPartitioner::partition` on a test directory tree produces non-overlapping, contiguous shard ranges covering `[\x00, \xFF)`.
3. Shard count respects `min_shards` and `max_shards` bounds for directory targets.
4. Each shard's `connector_extra` is the canonical target path.
5. `cargo test -p gossip-orchestrator` passes.
6. `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings` clean.

---

## Step 2: Run lifecycle manager

### What

```rust
// crates/gossip-orchestrator/src/lifecycle.rs

/// Orchestrates the full run lifecycle: create, register, monitor, complete.
///
/// Generic over the coordination backend so it works with both
/// `InMemoryCoordinator` (CLI/test) and `EtcdCoordinator` (production).
pub struct RunLifecycleManager<C> {
    coordinator: C,
    tenant: TenantId,
    run_id: RunId,
}

/// Configuration for a new run.
pub struct OrchestratorRunConfig {
    pub cursor_semantics: CursorSemantics,
    pub lease_duration_ms: u64,
    pub max_shard_retries: Option<u32>,
}

/// Outcome of `setup_run`: the registered run record and shard IDs.
pub struct RunSetupOutcome {
    pub run_record: RunRecord,
    pub shard_ids: Vec<ShardId>,
}

impl<C: CoordinationFacade> RunLifecycleManager<C> {
    pub fn new(coordinator: C, tenant: TenantId, run_id: RunId) -> Self;

    /// Create a run from a partition plan: builds the shard manifest via
    /// `PreallocShardBuilder`, calls `create_run_with_shards`.
    ///
    /// This is the automated equivalent of what `dev-seed` does manually.
    pub fn setup_run(
        &mut self,
        plan: &PartitionPlan,
        config: OrchestratorRunConfig,
    ) -> Result<RunSetupOutcome, OrchestratorError>;

    /// Poll run progress until all shards reach a terminal state.
    /// Returns the final `RunProgress` snapshot.
    ///
    /// `poll_interval` controls how frequently progress is checked.
    /// Calls `complete_run` when all active shards are done, or
    /// `fail_run` when parked shards exist and no active shards remain.
    pub fn await_completion(
        &mut self,
        poll_interval: Duration,
    ) -> Result<RunProgress, OrchestratorError>;

    /// Cancel a run (any state).
    pub fn cancel(&mut self) -> Result<(), OrchestratorError>;

    /// Access the coordinator for direct worker-loop integration.
    pub fn coordinator_mut(&mut self) -> &mut C;
}
```

`setup_run` implementation:
1. Allocate a `ShardArena` and `PreallocShardBuilder` with `plan.shards.len()` capacity.
2. For each `PlannedShard`, call `builder.add_range(start, end, connector_extra)`.
3. Call `builder.build_inputs()` to validate the manifest.
4. Generate a `LogicalTime::from_raw(wall_clock_millis)` and `OpId`.
5. Call `self.coordinator.create_run_with_shards(now, tenant, run_id, config, inputs, op_id)`.
6. Return the `RunRecord` and shard IDs.

`await_completion` implementation:
1. Loop: call `get_run_progress(now, tenant, run_id)`.
2. If `progress.active() == 0 && progress.parked() == 0`: call `complete_run`, return.
3. If `progress.active() == 0 && progress.parked() > 0`: call `fail_run`, return.
4. Sleep `poll_interval`.

### Why

- This automates the exact workflow that `dev-seed` (`cmd_seed`) performs manually (lines 119-193 of `tools/dev-seed/src/main.rs`).
- The `create_run_with_shards` convenience method handles idempotent retry, matching the research consensus on crash-recovery semantics.
- `await_completion` implements the monitoring loop that the research (F13, F52) identifies as the control-plane's core responsibility.

### Files

| Action | Path |
|--------|------|
| Create | `crates/gossip-orchestrator/src/lifecycle.rs` |
| Modify | `crates/gossip-orchestrator/src/error.rs` (add `OrchestratorError`) |
| Modify | `crates/gossip-orchestrator/src/lib.rs` (add module) |

### Risks

| Risk | Mitigation |
|------|-----------|
| **R1 (etcd ceiling):** Large partition plans could register thousands of shards. | `MAX_INITIAL_SHARDS = 10_000` is already enforced by `validate_manifest`. `FsPartitioner` clamps to `max_shards`. |
| `create_run_with_shards` default is not atomic for etcd. | Acceptable while a single caller owns run bootstrap. etcd backend can override with transactional implementation. Idempotent retry via `op_id` covers crash between create and register. |

### Acceptance Criteria

1. `setup_run` with `InMemoryCoordinator` creates a run in `Active` status with the correct shard count.
2. After manually completing all shards, `await_completion` calls `complete_run` and returns `Done` progress.
3. After parking a shard with no active shards remaining, `await_completion` calls `fail_run`.
4. `setup_run` with an already-existing run + same `op_id` returns idempotent success.

---

## Step 3: Split policy engine

### What

```rust
// crates/gossip-orchestrator/src/policy.rs

/// Configuration for the split policy engine.
pub struct SplitPolicyConfig {
    /// Byte threshold above which a shard is eligible for split.
    /// Default: 512 MB. Uses progressive thresholds per F18/F57.
    pub max_shard_bytes: u64,
    /// Minimum bytes before a shard is split-eligible.
    /// Default: 50 MB. Prevents splitting tiny shards.
    pub min_shard_bytes: u64,
    /// Maximum number of pending splits that can be in-flight
    /// cluster-wide. Defends against R2 (split storm).
    pub max_concurrent_splits: u32,
    /// Cooldown period after a split before the same parent lineage
    /// can split again. Defends against R3 (zombie shard loop).
    pub split_cooldown: Duration,
}

/// Split decision for a single shard.
pub enum SplitDecision {
    /// Shard is within bounds; no action needed.
    NoSplit,
    /// Shard should be split-replaced at the given byte-weighted midpoint.
    SplitReplace { split_key: Vec<u8> },
    /// Shard should shed its unscanned tail via split-residual.
    SplitResidual { residual_start: Vec<u8> },
}

/// Evaluates split eligibility for shards within a run.
pub struct SplitPolicyEngine {
    config: SplitPolicyConfig,
    /// In-flight split count for rate limiting (R2 defense).
    in_flight_splits: u32,
}

impl SplitPolicyEngine {
    pub fn new(config: SplitPolicyConfig) -> Self;

    /// Evaluate a shard for split eligibility.
    ///
    /// Inputs:
    /// - `shard_bytes_scanned`: bytes processed by the shard so far.
    /// - `shard_bytes_remaining_estimate`: estimated unscanned bytes.
    /// - `split_key_hint`: byte-weighted midpoint from the connector's
    ///   `StreamingSplitEstimator`, if available.
    /// - `cursor_position`: current cursor key for residual split boundary.
    /// - `shard_generation`: number of ancestors in the split lineage.
    ///
    /// Uses progressive threshold from F18/F57:
    /// `threshold = min(generation^2 * min_shard_bytes, max_shard_bytes)`
    pub fn evaluate(
        &self,
        shard_bytes_scanned: u64,
        shard_bytes_remaining_estimate: u64,
        split_key_hint: Option<&[u8]>,
        cursor_position: Option<&[u8]>,
        shard_generation: u32,
    ) -> SplitDecision;

    /// Record that a split was initiated (increments in-flight counter).
    pub fn record_split_initiated(&mut self);

    /// Record that a split completed (decrements in-flight counter).
    pub fn record_split_completed(&mut self);
}
```

Progressive threshold (HBase/YugabyteDB pattern):
```
effective_threshold = min(generation^2 * min_shard_bytes, max_shard_bytes)
```

Where `generation` is the depth in the split tree (root = 0). This ensures:
- Root shards split aggressively (threshold = `min_shard_bytes`).
- Children split less aggressively (threshold = `4 * min_shard_bytes`).
- Deep descendants rarely split (threshold approaches `max_shard_bytes`).

### Why

- **F18 (ES:5), F57 (ES:3):** Progressive thresholds are the consensus approach. HBase uses `min(R^2 * flushSize, maxFileSize)`.
- **F17 (ES:5), F51 (ES:5):** CockroachDB dual trigger. This draft uses size-only triggering; load triggering remains a later extension.
- **R2 (split storm):** `max_concurrent_splits` rate-limits cluster-wide.
- **R3 (zombie shard loop):** `split_cooldown` + `MAX_SPAWNED_PER_SHARD` prevents runaway splitting.
- **F24 (ES:4), F58 (ES:3):** `SplitResidual` decision uses cursor position, matching the DRQS "send half your queue" pattern.

### Files

| Action | Path |
|--------|------|
| Create | `crates/gossip-orchestrator/src/policy.rs` |
| Modify | `crates/gossip-orchestrator/src/lib.rs` (add module) |

### Risks

| Risk | Mitigation |
|------|-----------|
| **G1 (tuning):** Progressive threshold parameters lack filesystem-specific empirical data. | All thresholds are configurable. Default values are conservative. |
| **R2 (split storm):** Rate limiting is in-process, not cluster-wide for multi-orchestrator deployments. | Acceptable while a single orchestrator owns split decisions. Cluster-wide rate limiting requires shared state (etcd counter) in a follow-up. |

### Acceptance Criteria

1. Root shard (generation=0) with bytes > `min_shard_bytes` and a split hint produces `SplitReplace`.
2. Root shard with a cursor but no split hint produces `SplitResidual` when bytes > threshold.
3. Deep shard (generation=4) requires `16 * min_shard_bytes` before splitting.
4. Shard below `min_shard_bytes` always returns `NoSplit`.
5. When `in_flight_splits >= max_concurrent_splits`, always returns `NoSplit`.
6. Property test: threshold is monotonically non-decreasing with generation.

---

## Step 4: Straggler detection

### What

```rust
// crates/gossip-orchestrator/src/policy/straggler.rs

/// Configuration for straggler detection.
pub struct StragglerConfig {
    /// Duration after which a shard with no cursor progress is flagged.
    /// Default: 10 minutes.
    pub no_progress_timeout: Duration,
    /// If a shard's elapsed time exceeds this multiple of the median
    /// completed shard time, it is flagged.
    /// Default: 3.0x.
    pub median_multiple_threshold: f64,
    /// Maximum number of times a shard can be parked and unparked
    /// before being permanently parked.
    /// Default: 3.
    pub max_unpark_attempts: u32,
}

/// Control-plane recommendation for a straggler shard.
///
/// The detector does not mutate coordinator state directly. It classifies a
/// shard so the control plane can log, surface, or route the recommendation to
/// the current lease-holder. Direct controller-initiated parking would require a
/// new admin API beyond the current `RunManagement` surface.
pub enum StragglerAction {
    /// No action; shard is making progress.
    None,
    /// The current lease-holder should consider parking the shard.
    RecommendWorkerPark { reason: ParkReason },
    /// The controller should record or surface that the shard is stuck, but no
    /// automatic mutation is available yet.
    FlagForIntervention { reason: &'static str },
    /// The shard is a candidate for residual splitting.
    RecommendSplitResidual,
}

pub struct StragglerDetector {
    config: StragglerConfig,
    /// Per-shard tracking: last observed cursor position and logical time.
    shard_progress: HashMap<ShardId, ShardProgressRecord>,
    /// Completed shard durations in logical-time ticks for median calculation.
    completed_durations: Vec<u64>,
}

struct ShardProgressRecord {
    last_cursor: Option<Vec<u8>>,
    last_progress_at: LogicalTime,
    acquire_count: u32,
}

impl StragglerDetector {
    pub fn new(config: StragglerConfig) -> Self;

    /// Update tracking state from a progress poll.
    pub fn observe_progress(
        &mut self,
        now: LogicalTime,
        shard_id: ShardId,
        cursor: Option<&[u8]>,
        acquire_count: u32,
    );

    /// Record a shard completion for median tracking.
    pub fn record_completion(&mut self, elapsed_ticks: u64);

    /// Evaluate whether a shard is a straggler at logical time `now`.
    pub fn evaluate(
        &self,
        now: LogicalTime,
        shard_id: ShardId,
        elapsed_ticks: u64,
    ) -> StragglerAction;
}
```

### Why

- **R4 (HIGHEST RISK):** Single-object straggler is near-certain at PB scale (F29, ES:5). No defense currently exists.
- **F29 (ES:5):** 8x slower shards, 47% duration increase. Detection is the minimum viable first step; automatic controller-side parking requires either worker cooperation or a new admin API.
- **F13 (ES:5), F52 (ES:4):** Slicer control plane actively monitors and rebalances. This is the monitoring component.
- The coordination subsystem uses caller-supplied `LogicalTime`, so the detector should use the same time model rather than `Instant` to stay deterministic in simulation and tests.

### Files

| Action | Path |
|--------|------|
| Create | `crates/gossip-orchestrator/src/policy/straggler.rs` |
| Modify | `crates/gossip-orchestrator/src/policy.rs` (re-export module) |

### Risks

| Risk | Mitigation |
|------|-----------|
| **R4 residual:** Flagging or worker-side parking a straggler does not actually solve the giant-file problem; it just defers it. | The detector makes the condition visible and retryable. Future work: intra-file parallelism or a true admin park API. |
| False positives on legitimately slow shards (e.g., scanning a directory of large binaries). | `median_multiple_threshold` adapts to actual workload. Conservative default (3x median). |

### Acceptance Criteria

1. Shard with no cursor change for > `no_progress_timeout` evaluates to `RecommendWorkerPark` or `FlagForIntervention`.
2. Shard elapsed > `median_multiple_threshold * median_duration` evaluates to `RecommendWorkerPark` or `RecommendSplitResidual`.
3. Shard within bounds evaluates to `None`.
4. Shard with `acquire_count > max_unpark_attempts` evaluates to a non-`None` intervention recommendation.

---

## Step 5: CLI one-shot mode integration

### What

Add a new subcommand to `scanner-rs` (or a top-level flag) that performs the full
orchestrated flow:

```
scanner-rs orchestrate fs --path /data/target [OPTIONS]
```

Implementation path:

```rust
// crates/gossip-scanner-runtime/src/orchestrate.rs

/// One-shot orchestrated scan: partition, create run, run workers, report.
///
/// Uses `InMemoryCoordinator` for zero-infrastructure local execution.
/// This is the CLI equivalent of `just scan PATH` but without requiring
/// etcd or PostgreSQL.
pub fn orchestrate_fs_scan(
    config: &OrchestrateFsConfig,
) -> Result<OrchestrateReport, OrchestrateError> {
    // 1. Partition the source.
    let partitioner = FsPartitioner;
    let plan = partitioner.partition(&config.partition)?;

    // 2. Create coordinator and lifecycle manager.
    let mut coordinator = InMemoryCoordinator::new(config.lease_duration_ms);
    let tenant = TenantId::from_bytes([0x01; 32]);
    let run_id = RunId::from_raw(wall_clock_millis());
    let mut manager = RunLifecycleManager::new(coordinator, tenant, run_id);

    // 3. Setup run with partition plan.
    let setup = manager.setup_run(&plan, config.run_config())?;

    // 4. Run worker(s) against the in-memory coordinator.
    //    This draft runs workers sequentially. Parallel local execution is a
    //    follow-up because `run_worker` currently takes `&mut coordinator`.
    let report = run_worker(
        manager.coordinator_mut(),
        identity,
        persistence,
        runtime_config,
    )?;

    // 5. Await completion (should be immediate since workers ran inline).
    let progress = manager.await_completion(Duration::from_millis(100))?;

    Ok(OrchestrateReport { scan_report: report, progress })
}
```

Key integration points:
- `InMemoryCoordinator` already implements `CoordinationFacade`.
- `run_worker` already works against any `CoordinationFacade`.
- Persistence backends use `InMemoryDoneLedger` + `InMemoryFindingsSink` for CLI mode (no PostgreSQL required).
- The CLI module (`gossip-scanner-runtime/src/cli.rs`) gets a new `orchestrate` subcommand.

### Why

- This replaces the manual `dev-seed seed PATH && run-worker PATH` workflow with a single command for local one-shot scans.
- CLI users get multi-shard orchestration without any infrastructure setup. Parallel local execution can be added once coordinator sharing is designed explicitly.
- The in-memory coordinator makes this testable without Docker/etcd.

### Files

| Action | Path |
|--------|------|
| Create | `crates/gossip-scanner-runtime/src/orchestrate.rs` |
| Modify | `crates/gossip-scanner-runtime/src/cli.rs` (add `orchestrate` subcommand) |
| Modify | `crates/gossip-scanner-runtime/src/lib.rs` (add `orchestrate` module) |

### Risks

| Risk | Mitigation |
|------|-----------|
| Thread contention with `InMemoryCoordinator` under parallel workers. | `InMemoryCoordinator` uses `&mut self` for mutations, requiring external synchronization. Use `Mutex` wrapper or keep the local one-shot path sequential until coordinator sharing is designed explicitly. |
| CLI user confusion about `scan fs` vs `orchestrate fs`. | `scan fs` remains the simple single-shard path. `orchestrate fs` is explicitly multi-shard. Document the distinction. |

### Acceptance Criteria

1. `scanner-rs orchestrate fs --path /tmp/test_dir` partitions, scans, and reports without external services.
2. `scanner-rs orchestrate fs --path /tmp/single-file.txt` completes via the single-file fast path.
3. Scanning a multi-directory tree produces >1 shard (verified via report output).
4. All existing `scanner-rs scan fs` tests continue to pass unchanged.
5. Integration test: create a test directory with 5 subdirectories, orchestrate, verify all files are scanned.

---

## Step 6: Production service integration

### What

Extend the production path with two complementary responsibilities:

1. **Bootstrap / operator path:** create and publish a run against etcd and
   PostgreSQL, then optionally execute an inline worker for single-node smoke
   testing.
2. **Worker-fleet assignment path:** add a production worker mode that no
   longer requires an operator-supplied `RunId`. Fleet workers discover active
   runs from the coordinator's active-run index, bind themselves to one run,
   and then enter the existing shard-claim loop for that run.

The current run-pinned worker configuration remains useful for tests and manual
targeting, but it is not sufficient by itself for a real control-plane/data-
plane handoff.

Illustrative bootstrap entrypoint:

```rust
// crates/gossip-worker/src/orchestrate.rs

/// Production orchestrated scan against real backends.
///
/// 1. Connect to etcd and PostgreSQL.
/// 2. Partition the source via `FsPartitioner`.
/// 3. Create run via `RunLifecycleManager` against etcd.
/// 4. For local bootstrap, optionally launch one inline `run_worker`
///    against the etcd coordinator.
/// 5. Publish the run so fleet workers can discover it.
/// 6. Monitor progress via `await_completion`.
/// 7. Report results.
pub fn run_production_orchestration(
    config: &ProductionOrchestrateConfig,
) -> Result<OrchestrateReport, ProductionOrchestrateError>;
```

Fleet-assignment addition:

```rust
// crates/gossip-worker/src/assignment.rs

/// Long-lived production worker that discovers active runs and then executes
/// the existing shard-claim loop for the selected run.
pub fn run_assigned_worker(
    config: &AssignedWorkerConfig,
) -> Result<AssignedWorkerReport, AssignedWorkerError>;
```

This replaces the manual `just seed PATH && just run-worker PATH` workflow in
two layers: bootstrap no longer requires a separate seed command, and fleet
workers no longer require manually wiring `GOSSIP_RUN_ID` for each new run.

Add a Justfile recipe:
```
# Full orchestrated scan against local backends (etcd + postgres)
orchestrate PATH:
    GOSSIP_WORKER_MODE=orchestrate \
    ... \
    cargo run -p gossip-worker -- orchestrate fs "{{PATH}}"
```

### Why

- **F13 (ES:5), F52 (ES:4):** The Slicer model separates control plane (orchestrator) from data plane (workers). Production rollout therefore needs both run creation and a worker-assignment handoff.
- Replaces the fragile `dev-seed` + manual worker launch workflow.

### Files

| Action | Path |
|--------|------|
| Create | `crates/gossip-worker/src/orchestrate.rs` |
| Create | `crates/gossip-worker/src/assignment.rs` |
| Modify | `crates/gossip-worker/src/config.rs` (add `Orchestrate` mode) |
| Modify | `crates/gossip-worker/src/main.rs` (add dispatch) |
| Modify | `Justfile` (add `orchestrate` recipe) |

### Risks

| Risk | Mitigation |
|------|-----------|
| **R1 (etcd ceiling):** Large partitions could stress etcd. | `FsPartitioner` clamps to `max_shards`. Monitor etcd size in Step 7. |
| Single orchestrator is a SPOF. | Acceptable while one orchestrator instance owns run supervision. The coordination layer's idempotent operations allow a restarted orchestrator to resume from the last known state. |
| Existing distributed workers require an explicit `RunId`, so publishing a run does not automatically recruit the worker fleet. | Add a fleet-assignment mode that discovers active runs from the coordinator instead of requiring the operator to preconfigure `RunId`. |

### Acceptance Criteria

1. `just orchestrate /tmp/test_dir` completes a distributed bootstrap scan against local etcd + PostgreSQL.
2. A fleet worker can discover an orchestrator-created active run without an operator-supplied `RunId`.
3. `just inspect` shows non-zero rows in findings and done-ledger tables.
4. Running `just orchestrate` twice with the same path is idempotent at the run-creation layer (second run detects the existing run via `create_run_with_shards` retry path or a deterministic run-identity policy).
5. Integration test with testcontainers (etcd + postgres) verifies end-to-end flow.

---

## Step 7: Observability and runtime monitoring

### What

Add runtime instrumentation to the orchestrator:

1. **etcd utilization monitoring (R1 defense):**
   ```rust
   // Poll etcd's maintenance status endpoint for DB size.
   // Emit warning when DB size exceeds 80% of configured quota.
   fn check_etcd_utilization(client: &EtcdClient) -> EtcdHealth;
   ```

2. **Split rate telemetry (R2 defense):**
   ```rust
   // Track splits/second over a sliding window.
   // If rate exceeds threshold, the policy engine pauses split decisions.
   struct SplitRateMonitor { ... }
   ```

3. **Per-shard progress logging:**
   - Periodic progress snapshots via `get_run_progress`.
   - Log shard-level watermark advancement rate.
   - Flag shards stuck at the same cursor for extended periods.

4. **Straggler integration:**
   - Wire `StragglerDetector` into the `await_completion` poll loop.
   - When a straggler is detected, do **not** call `coordinator.park_shard()` directly from the controller. `park_shard` is lease-gated today. The controller records the recommendation, logs it, and optionally routes it to the current lease-holder; a future follow-up can add an admin park API if direct controller action is required.

### Why

- **R1, R2, R4:** The three highest-priority risks all require runtime monitoring that does not exist today.
- **F13 (ES:5):** Slicer's 30-180% load imbalance was detected and corrected via active monitoring.

### Files

| Action | Path |
|--------|------|
| Create | `crates/gossip-orchestrator/src/monitor.rs` |
| Modify | `crates/gossip-orchestrator/src/lifecycle.rs` (integrate monitors into poll loop) |

### Acceptance Criteria

1. `tracing` log output includes periodic progress snapshots during `await_completion`.
2. etcd utilization check emits a warning log when a mock returns >80% full.
3. Split rate monitor correctly pauses split decisions when rate exceeds threshold.
4. Straggler detector records a non-`None` intervention recommendation for a shard that makes no progress for > timeout.

---

## Evidence Trail

| Plan Step | Research Finding(s) | Evidence Strength | Confidence |
|-----------|--------------------|--------------------|------------|
| Step 1: `SourcePartitioner` | F54 (hybrid static+dynamic), F19 (Hadoop FileInputFormat), F21 (Spark bin-packing), F10 (directory power-law) | 4-5 across findings | High |
| Step 1: Depth-bounded pre-walk | F12 (full walk cost), F33 (NFS readdir stall), F34 (walk memory) | 3-5 across findings | Medium-High |
| Step 2: Run lifecycle | F13 (Slicer control/data separation), F52 (Slicer efficiency) | 4-5 | High |
| Step 2: `create_run_with_shards` | Existing codebase pattern (run.rs:1613-1658) | N/A (code evidence) | Very High |
| Step 3: Progressive split threshold | F18 (HBase), F57 (YugabyteDB) | 3-5 | High |
| Step 3: Split rate limiting | F30 (split storm), R2 risk register | 4 | High |
| Step 3: Size-only trigger | F17 (CockroachDB dual), F1 (Bigtable) | 5 | High (load trigger deferred) |
| Step 4: Straggler detection | F29 (single-object straggler), R4 risk register | 5 | Very High (R4 = highest risk) |
| Step 5: CLI one-shot | F42 (ripgrep architecture), existing `scan_fs` flow | 5 + code evidence | Very High |
| Step 6: Production integration | F13 (Slicer), F64 (Uber coordinator) | 2-5 | Medium-High |
| Step 7: etcd monitoring | F38 (etcd ceiling), R1 risk register | 5 | High |

---

## Alternative Approaches

### A1: Single full-range shard vs pre-walk partitioning

**Current plan:** Single-file fast path for regular files, plus depth-bounded directory pre-walk for directory targets.

**Alternative:** Always start with a single `[\x00, \xFF)` shard and rely entirely on dynamic `split_residual` to subdivide during scanning.

**Trade-offs:**
- Single-shard start is simpler (no pre-walk) but has slow ramp-up (only 1 worker until first split).
- Directory pre-walk adds latency before scanning starts but enables immediate parallelism.
- Regular-file targets still take the single-shard path because there is no directory structure to partition.
- At PB scale with thousands of workers, single-shard start means minutes of idle workers.

**Switch condition:** If pre-walk latency on large NFS mounts exceeds 30 seconds, consider the single-shard fallback with aggressive early splitting.

### A2: `PreallocShardBuilder` vs direct `InitialShardInput` construction

**Current plan:** Use `PreallocShardBuilder` to stage and validate the manifest before registration.

**Alternative:** Construct `InitialShardInput` directly (as `dev-seed` does) without the builder.

**Trade-offs:**
- Builder provides manifest validation, arena management, and overflow protection.
- Direct construction is simpler but skips validation.
- Builder pattern is the codebase convention (see `builder.rs`).

**Decision:** Use `PreallocShardBuilder`. It exists, is well-tested, and provides the validation layer the orchestrator needs.

### A3: Synchronous vs async orchestrator

**Current plan:** Synchronous orchestrator for the in-memory/test path, with the option to add an async production-facing variant if the controller must manage many runs concurrently.

**Alternative:** Async orchestrator using `AsyncRunManagement` and `AsyncCoordinationBackend`.

**Trade-offs:**
- Sync is simpler, matches `InMemoryCoordinator` and the existing test infrastructure.
- Production etcd already has both a sync wrapper and async core; the initial plan can use the sync wrapper, but a long-lived controller service may want `AsyncRunManagement` / `AsyncCoordinationBackend`.
- The orchestrator's I/O pattern (infrequent progress polls, rare splits) does not benefit from async concurrency until it manages multiple runs or joins an async service framework.

**Switch condition:** If the orchestrator needs to manage multiple runs concurrently or integrate with an async service framework, add an async variant. The sync trait can be wrapped in `tokio::task::spawn_blocking`.

### A4: In-process split execution vs orchestrator-driven splits

**Current plan:** Split policy engine evaluates splits and records when they should happen. Coordination already supports split execution, but the production worker/runtime does not yet have an automatic trigger wired in.

**Alternative:** Workers self-split by calling `split_residual` directly on the coordinator during scanning.

**Trade-offs:**
- Worker self-split is supported by existing coordination primitives, but no automatic runtime trigger is wired today.
- Orchestrator-driven evaluation adds centralized rate limiting and straggler awareness.
- Both models can coexist once the runtime wiring exists: workers can self-split for "I'm overwhelmed" cases, while the orchestrator supplies global supervision and rate limits.

**Decision:** Support both. The orchestrator adds a supervision layer that decides when splits should occur, and a later runtime hook can let either the lease-holder or a dedicated control-plane path execute the decision.

---

## Validation Strategy

### Unit Tests

- **Step 1:** Property tests for `FsPartitioner`:
  - Regular-file input produces a single full-range shard.
  - Generated directory trees with power-law depth/breadth.
  - Assert: shard ranges are contiguous, non-overlapping, cover `[\x00, \xFF)`.
  - Assert: shard count within `[min_shards, max_shards]`.
  - Assert: each shard's estimated bytes is within 2x of `target_shard_bytes` (relaxed for tail shards).

- **Step 2:** Lifecycle manager tests with `InMemoryCoordinator`:
  - Happy path: setup -> workers complete all shards -> `await_completion` returns Done.
  - Failure path: setup -> park a shard -> `await_completion` returns Failed.
  - Idempotency: call `setup_run` twice with same `op_id` -> success.

- **Step 3:** Split policy tests:
  - Progressive threshold monotonicity across generations.
  - Rate-limiting behavior at boundary.
  - Decision accuracy for known shard states.

- **Step 4:** Straggler detector tests:
  - Timeout detection with mock logical-time progress observations.
  - Median-based detection with synthetic completion distributions.

### Integration Tests

- **Step 5:** End-to-end CLI test:
  - Create temp directory with known file content.
  - Run `orchestrate_fs_scan` with `InMemoryCoordinator` + `InMemoryDoneLedger` + `InMemoryFindingsSink`.
  - Verify scan report covers all files.
  - Add a single-file test case to confirm the orchestrated path preserves the current `scan fs` surface.

- **Step 6:** Testcontainer integration test:
  - Spin up etcd + postgres via testcontainers.
  - Run `run_production_orchestration`.
  - Verify etcd state and postgres rows.
  - Run a fleet worker in assignment mode and verify it can discover the newly created run without a preconfigured `RunId`.

### Benchmarks

- **Shard sizing calibration (G1):**
  - Benchmark `FsPartitioner::partition` on synthetic trees of 10K, 100K, 1M files.
  - Measure pre-walk latency vs shard count vs scan throughput.
  - Use results to tune `target_shard_bytes` default.

- **Split policy calibration:**
  - Benchmark progressive threshold with the simulation harness (existing `sim/` module).
  - Measure: total scan time, split count, shard count at completion.

### Simulation

The existing deterministic simulation harness (`crates/gossip-coordination/src/sim/`)
can be extended to test the orchestrator under simulated clock progression. Add a
simulation scenario that:
1. Creates a run with `FsPartitioner`-generated shards.
2. Simulates workers claiming and completing shards at variable speeds.
3. Triggers the split policy engine when shard size exceeds thresholds.
4. Triggers the straggler detector when simulated workers stall.
5. Asserts invariants S1-S9 hold throughout.

---

## Dependency Graph

```
Step 1 (SourcePartitioner) ──┐
                             ├──► Step 2 (RunLifecycleManager) ──┐
Step 3 (SplitPolicyEngine) ──┘                                  │
                                                                 ├──► Step 5 (CLI one-shot)
Step 4 (StragglerDetector) ──────────────────────────────────────┤
                                                                 ├──► Step 6 (Production)
                                                                 │
                                                                 └──► Step 7 (Observability)
```

Steps 1 and 3 can be developed in parallel. Step 4 depends only on Step 3's
types. Steps 5, 6, and 7 all depend on Steps 1-4 but are independent of each other.

---

## References

1. Chang, F., et al. "Bigtable: A Distributed Storage System for Structured Data." OSDI 2006.
2. Taft, R., et al. "CockroachDB: The Resilient Geo-Distributed SQL Database." SIGMOD 2020.
3. LaFreniere, K., et al. "DRQS: Distributed Random Queue Scheduler." SC 2012.
4. Corbett, J., et al. "Spanner: Google's Globally-Distributed Database." OSDI 2012.
5. Zhou, J., et al. "Foundationdb: A Distributed Unbundled Transactional Key Value Store." SIGMOD 2021.
6. Azar, Y., et al. "Balanced Allocations (Power of Two Choices)." STOC 1994.
7. Kleppmann, M. "How to Do Distributed Locking." 2016.
8. Gray, C. and Cheriton, D. "Leases: An Efficient Fault-Tolerant Mechanism for Distributed File Cache Consistency." SOSP 1989.
9. Dageville, B., et al. "The Snowflake Elastic Data Warehouse." SIGMOD 2016.
10. HBase Reference Guide: "Region Splitting." Apache HBase documentation.
11. Spark Documentation: "Performance Tuning — openCostInBytes." Apache Spark.
12. Blumofe, R. and Leiserson, C. "Scheduling Multithreaded Computations by Work Stealing." FOCS 1994.
