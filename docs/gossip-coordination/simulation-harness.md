# Simulation Harness

Deterministic simulation infrastructure for the coordination subsystem,
inspired by FoundationDB's simulation framework, TigerBeetle's VOPR, and
sled's simulation harness.

Execution integration note: the runtime now has a dedicated scan-driver seam
(`crates/gossip-scan-driver`) for translating shard assignments into
source-specific execution backends. The simulation harness remains focused on
coordination correctness and intentionally does not depend on scanner-engine
or scheduler internals.

## Architecture

The simulation is built in five layers, each composing the one below it:

### Layer 1: SimContext (`sim/mod.rs`)

Owns the single `ChaCha8Rng` PRNG and a monotonic `LogicalTime` clock.
Everything random in a simulation run flows through this one RNG instance.

### Layer 2: SimWorker (`sim/worker.rs`)

Per-worker bookkeeping that tracks:

- **Lease claims** -- which shards the worker believes it holds (may diverge
  from coordinator truth after silent lease expiry).
- **Op-ID generation** -- partitioned by worker ID (`worker_id * 1_000_000`)
  to guarantee cross-worker uniqueness without coordination.
- **Pause state** -- models GC pauses, network partitions, or VM migrations.
- **Cursor progress** -- last checkpoint cursor per `(RunId, ShardId)` for
  forward-only cursor generation.

### Layer 3: InvariantChecker (`sim/invariants.rs`)

An external observer that verifies nine safety properties against coordinator
ground truth at every simulation step. It never trusts worker-side bookkeeping.
See the invariant table below.

### Layer 4: Overload Scenarios (`sim/overload.rs`)

Deterministic scripted stress workloads that exercise cooldown and capacity
behavior. Defines scenario descriptors (`OverloadKind`, `OverloadScenario`),
lightweight telemetry (`GoodputTracker`, `D1Observation`, `OverloadReport`),
and operation burst generators consumed by `CoordinationSim::run_overload`.

### Layer 5: CoordinationSim (`sim/harness.rs`)

The top-level driver. Runs a three-stage simulation (zombie preamble, safety,
then liveness) with weighted random op generation, fault injection, and full
invariant checking after every step.

For split-replace operations, the harness uses the contracts-owned planner
helper (`gossip_contracts::coordination::split::plan_split_replace_at_points_initial_cursor`)
so simulation planning behavior stays aligned across boundary consumers.

## Determinism Model

All randomness flows through a single `ChaCha8Rng` seeded from a `u64`.

**Why ChaCha8Rng?** `ChaCha8Rng` is algorithm-specified and value-stable
across patch releases, unlike `StdRng` which is explicitly non-portable.
`Cargo.lock` provides sufficient pinning for cross-platform reproducibility.

**PRNG call ordering matters.** The RNG is a single sequential stream. Any
change to the order or number of `rng()` calls changes all subsequent random
decisions for a given seed. When adding new randomized logic, append calls
rather than inserting them between existing ones.

**Integer PPM fault rates.** Fault probabilities use integer parts-per-million
(PPM) instead of `f64` to eliminate IEEE 754 rounding variance across
platforms and prevent invalid probability construction.

## Invariant Table

| Label | Name                       | Rule                                                                                                            |
| ----- | -------------------------- | --------------------------------------------------------------------------------------------------------------- |
| S1    | MutualExclusion            | At most one worker holds a non-expired lease per shard.                                                         |
| S2    | FenceMonotonicity          | `fence_epoch` never decreases for a given `(RunId, ShardId)`.                                                   |
| S3    | TerminalIrreversibility    | Terminal states (Done, Split, Parked) never revert, except Parked->Active (unpark) which requires a fence bump. |
| S4    | RecordInvariant            | `ShardRecord::validate_invariants()` returns `Ok`.                                                              |
| S5    | CursorMonotonicity         | `cursor.last_key()` never decreases per shard.                                                                  |
| S6    | CursorBounds               | Non-initial cursors remain within shard spec key range.                                                         |
| S7    | SplitCoverage              | Split-parent's spawned children exist and reference the correct parent.                                         |
| S8    | RunTerminalIrreversibility | Terminal run states (Done, Failed, Cancelled) never revert.                                                     |
| S9    | CooldownViolation          | A worker must not successfully claim twice within the configured cooldown.                                      |

All nine invariants are checked after
every operation (both successful and rejected).

**S9 push-style pattern:** Unlike S1–S8 which are validated during
`InvariantChecker::check_all()`'s pass over coordinator state, S9 uses a
push-style check. The harness calls `record_claim_success(worker, now)`
when `ClaimNext` succeeds, and violations are buffered internally. The
buffered violations are then drained and appended to the result vector at
the end of `check_all`, keeping all invariant reporting in one place.

## Three-Stage Run Model

`CoordinationSim::run(safety_ops, liveness_ops)` executes three stages:

### Stage 0: Zombie Preamble

Before the main safety phase, the harness seeds initial leases and then
immediately expires them, creating "zombie" workers that hold stale lease
references. This exercises the fence-based rejection paths from the very
first operation of the run, ensuring that stale-lease handling is tested
even before normal operation begins.

### Stage 1: Safety

Runs `safety_ops` random operations under fault injection. The first few
operations (warmup) suppress faults to let the system reach a healthy
baseline. After warmup, time jumps, worker pauses, lease expiry, split
operations, OpId replays, zombie checkpoints, and run-terminal transitions
(complete/fail/cancel) are all exercised at weighted probabilities.

**Goal:** Verify that no invariant (S1-S9) is ever violated regardless of
operation ordering, timing, or fault injection.

### Stage 2: Liveness

Runs `liveness_ops` operations biased toward acquire and complete. No faults
are injected.

**Goal:** Verify that the system converges -- all shards reach a terminal
state (Done, Split, or Parked).

## Overload Scenarios

`CoordinationSim::run_overload(warmup_ops, scenario, recovery_ops)` provides a
targeted stress path for cooldown/capacity behavior.

The run has three phases:

1. Warmup random operations to establish baseline leases.
2. Scripted overload rounds (`OverloadScenario`):
   - `BurstClaim`: all workers issue `ClaimNext`.
   - `CapacityDrop`: pause half the workers, then force a time jump.
   - `BurstShards`: issue `SplitReplace` on all currently held shards.
3. Recovery with periodic `ClaimNext` injection and liveness-biased ops.

The overload report includes:

- Standard simulation fields (`ops_executed`, `violations`, `event_counts`,
  `seed`, `end_time`).
- `overload_goodput` (completion ratio during overload rounds).
- D1 diagnostics (`d1_observations`) comparing reported
  `count_available_for_run` values with coordinator-derived ground truth.
  D1 samples are captured after each overload round. A mismatch between
  `reported` and `ground_truth` indicates the coordinator's fast-path
  availability counter drifted from the full-scan result — a bug in the
  bookkeeping optimization, not in the protocol itself.
- L1 liveness sentinel (`l1_any_completed`).

## Fault Injection Levels

| Level       | Lease Expiry | Worker Pause | Time Jump | Use Case                |
| ----------- | ------------ | ------------ | --------- | ----------------------- |
| SunnyDay    | 0%           | 0%           | 0%        | Happy-path correctness  |
| Stormy      | 10%          | 5%           | 10%       | Moderate fault coverage |
| Radioactive | 20%          | 10%          | 20%       | Stress/edge-case search |

Pause durations and time-jump magnitudes scale with the level. See
`FaultConfig::for_level` for exact PPM values.

## Zombie Checkpoint Coverage

The harness exercises two distinct zombie-rejection paths:

1. **B1 bookkeeping cleanup** -- When Worker B acquires a shard previously
   held by Worker A (whose lease expired), Worker A's local bookkeeping is
   cleared. A subsequent checkpoint attempt by Worker A is rejected with
   `NotLeased` before reaching the coordinator.

2. **Coordinator fence-based StaleFence** -- Stale leases are saved when
   bookkeeping cleanup supersedes them. `ZombieCheckpoint` ops use these
   saved stale leases to bypass B1 cleanup entirely, exercising the
   coordinator's `StaleFence` error path directly.

## Reproducing a Failing Seed

Every `SimReport` includes the `seed` field. To reproduce:

```rust
let report = CoordinationSim::new(FAILING_SEED, FaultLevel::Stormy)
    .with_workers_and_shards(3, 5)
    .run(500, 200);
assert!(report.violations.is_empty());
```

The simulation is fully deterministic: same seed, same fault level, same
worker/shard counts, same op counts produce identical results on any
platform.

## Adding a New Invariant

1. **Define the violation variant** in `InvariantViolation` (in
   `sim/invariants.rs`).

2. **Add the check** inside `InvariantChecker::check_all()`. Follow the
   single-pass pattern: accumulate state during the shard iteration, then
   validate after the loop if needed (like S1's post-pass duplicate check).

   **Alternative: push-style checks.** If the invariant depends on
   information not available in coordinator state (e.g., S9 depends on
   knowing *when* a claim succeeded, which is transient), use the
   push-style pattern: add a public method that the harness calls at the
   relevant event, buffer violations internally, and drain them in
   `check_all`. See `record_claim_success` (S9) as a reference.

3. **Add a negative test** in `invariants::tests` that constructs a
   coordinator state violating the new invariant and asserts the checker
   detects it. Use `seed_shard_unchecked` for states that `seed_shard`
   would reject.

4. **Update the invariant table** in this document and in the module doc
   comment at the top of `sim/mod.rs`.

5. **Run the full simulation** across multiple seeds to verify the new check
   does not produce false positives:

   ```bash
   cargo test --all-features -p gossip-coordination -- sim
   ```
