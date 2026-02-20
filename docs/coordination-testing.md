# Coordination Testing Strategy

Testing strategy for the shard coordination protocol and its simulation
infrastructure. Four tiers target distinct quality dimensions: isolation,
invariant interaction, workflow correctness, and large-scale randomized
validation.

For protocol details see [boundary-2-coordination.md](boundary-2-coordination.md).
For simulation architecture see [simulation-harness.md](simulation-harness.md).

---

## 1. Testing Pyramid

```text
                    ┌──────────────┐
                    │  Simulation  │  Tier 4: randomized seed sweep
                    │  (sim/)      │  across 100+ seeds, 12K ops each
                    ├──────────────┤
                    │  Scenario    │  Tier 3: multi-step user stories
                    │              │  (8 end-to-end workflows)
                ┌───┴──────────────┴───┐
                │    Conformance       │  Tier 2: invariant interactions
                │                      │  (3 groups, ~15 tests)
            ┌───┴──────────────────────┴───┐
            │         Unit Tests           │  Tier 1: single-operation
            │                              │  isolation (~90 tests)
            └──────────────────────────────┘
```

Each tier builds on the one below it. Unit tests validate individual
operations against the `InMemoryCoordinator`. Conformance tests compose
two or more invariants and verify they hold simultaneously. Scenario tests
chain operations into realistic workflows. Simulation tests sweep hundreds
of random seeds under fault injection, validating all seven safety
invariants at every step.

---

## 2. Tier 1 — Unit Tests

**File:** `coordination/in_memory_tests.rs`
**Declared in:** `coordination/in_memory.rs` (`#[cfg(test)]` submodule)

Single-operation isolation tests against `InMemoryCoordinator`. Each test
exercises one backend operation or one edge case, with deterministic
logical time advanced via `now(t)`.

### Coverage areas

| Area | Example tests |
|------|---------------|
| Acquire | `acquire_basic`, `acquire_not_found`, `acquire_already_leased`, `acquire_after_lease_expiry`, `acquire_terminal_rejected` |
| Renew | `renew_basic`, `renew_stale_fence` |
| Checkpoint | `checkpoint_basic`, `checkpoint_op_id_conflict` |
| Complete | `complete_basic`, `complete_replay_after_terminal` |
| Park | `park_basic`, `park_replay_after_terminal` |
| Split (replace) | `split_replace_basic`, `split_replace_replay`, `split_replace_child_id_determinism` |
| Split (residual) | `split_residual_basic`, `split_residual_cursor_out_of_bounds`, `split_residual_replay_via_spawned_after_eviction` |
| Fencing | `only_latest_fence_holder_can_mutate` |
| Op-log eviction | `op_log_eviction_treats_old_op_as_new` |
| Tenant isolation | `acquire_wrong_tenant_returns_not_found`, `checkpoint_wrong_tenant_returns_not_found`, etc. |
| Shard count limits | `split_replace_exceeds_per_tenant_limit`, `split_residual_exceeds_global_limit`, `register_shards_exceeds_per_tenant_limit` |
| Run lifecycle | `complete_run_happy_path`, `fail_run_happy_path`, `cancel_run_from_initializing`, `terminal_ops_set_completed_at` |
| Unpark | `unpark_shard_happy_path`, `unpark_shard_fence_epoch_bumped`, `unpark_shard_cursor_preserved`, `unpark_shard_rejected_when_run_cancelled` |
| List shards | `list_shards_filter_active`, `list_shards_filter_available`, `list_shards_filter_parked`, `list_shards_filter_root_only` |
| Integration | `full_lifecycle_acquire_checkpoint_split_residual_complete`, `full_run_lifecycle_create_register_process_complete` |

The module also includes **property-based tests** (proptest) that fuzz
random operation sequences against the coordinator and assert structural
invariants (record consistency, fence monotonicity, cursor monotonicity,
idempotent replay) after every step.

All tests use shared fixtures from `test_fixtures.rs` (see Section 5).

---

## 3. Tier 2 — Conformance Tests

**File:** `coordination/conformance_tests.rs`
**Declared in:** `coordination/mod.rs` (`#[cfg(test)]`)

Invariant-interaction tests. Each test composes two or more of the
protocol's safety invariants and verifies they hold simultaneously. The
focus is on invariant *combinations* — these are the tests most likely to
catch regressions where a fix for one invariant violates another.

### Group A: Cross-Cutting Invariant Interactions

| Test | Invariants composed |
|------|-------------------|
| `fence_monotonicity_across_full_lifecycle` | Fence monotonicity + lease expiry enables re-acquisition + checkpoint/complete do not mutate fence |
| `cursor_monotonicity_combined_with_split_residual` | Cursor bounds + split-residual spec narrowing + cursor preservation across splits |
| `idempotency_before_lease_validation` | OpId idempotency + terminal irreversibility + their priority ordering |
| `owner_divergence_with_matching_fence` | Lease validation (fence + owner identity) + tenant isolation |
| `terminal_clears_lease` | Terminal transitions clear leases + correct terminal status per operation (complete, park, split_replace) |

### Group B: Gap-Filling Tests

Edge cases with zero or minimal coverage elsewhere.

| Test | Gap filled |
|------|-----------|
| `cursor_semantics_dispatched_through_coordinator` | `CursorSemantics::Dispatched` propagation through acquire, checkpoint, complete |
| `lease_deadline_at_exact_boundary` | Half-open lease interval: `now < deadline` active, `now == deadline` expired |
| `split_coverage_key_range_partition` | Split-replace children's key ranges form a contiguous, gap-free partition |
| `oplog_eviction_then_replay` | Op-log eviction interaction with idempotency on terminal shards |
| `unpark_lifecycle_fence_and_cursor_preserved` | Full park/unpark round-trip preserves cursor, bumps fence, allows re-acquire |
| `same_worker_reacquire_bumps_fence` | Same-worker reacquire bumps fence, old lease rejected with `StaleFence` |

### Group C: Run-Level Conformance

Run lifecycle state machine tests.

| Test | Property |
|------|----------|
| `run_terminal_irreversibility` | Done run rejects complete_run, fail_run, and cancel_run |
| `register_shards_on_non_initializing_rejected` | Registration requires Initializing status |
| `run_completed_at_consistency` | `completed_at` is `Some` iff run is terminal |
| `unpark_after_run_terminal_rejected` | Terminal run blocks shard-level unpark (`RunTerminal`) |

### Compile-time guards

```rust
const _: () = assert!(ShardRecord::OP_LOG_CAP == 16);
const _: () = assert!(MAX_SPAWNED_PER_SHARD == 1024);
const _: () = assert!(LEASE_DURATION == 100);
```

These prevent silent constant changes from invalidating test assumptions.
If `OP_LOG_CAP`, `MAX_SPAWNED_PER_SHARD`, or `LEASE_DURATION` change, the
conformance tests fail at compile time.

---

## 4. Tier 3 — Scenario Tests

**File:** `coordination/scenario_tests.rs`
**Declared in:** `coordination/mod.rs` (`#[cfg(test)]`)

Multi-step workflow tests that exercise realistic end-to-end stories.
Each scenario chains operations in production-realistic order, including
state restoration across ownership transfers.

| ID | Scenario | Core property |
|----|----------|---------------|
| S1 | Full run lifecycle | Baseline happy path: create_run → register → acquire → checkpoint×3 → complete (shard) → complete_run |
| S2 | Lease expiry + reacquire | Cursor restoration across ownership transfer; stale writer fenced with `StaleFence` |
| S3 | Split-replace + children | Parent becomes `Split`; children are independently acquirable and completable by different workers |
| S4 | Double residual split chain | Iterative parent narrowing `[a,z)→[a,m)→[a,j)` with spawned list tracking; all three pieces complete |
| S5 | Op-log eviction boundary | Evicted `OpId` treated as new (`Executed`); surviving `OpId` with wrong payload returns `OpIdConflict` |
| S6 | Cancel from Initializing | Early run termination blocks registration; idempotent replay; terminal irreversibility |
| S7 | Worker self-recovery | Same worker recovers from own lease expiry with cursor restoration and fence bump |
| S8 | Claim contention | 3 workers contend for 2 shards via `claim_next_available`; exactly 2 succeed, 1 gets `NoneAvailable` |

---

## 5. Test Infrastructure

### Test Fixtures (`coordination/test_fixtures.rs`)

Shared factory functions consumed by all three coordination test modules.

| Function | Returns |
|----------|---------|
| `test_tenant()` | `TenantId` from fixed bytes |
| `test_run()` | `RunId::from_raw(1)` |
| `test_shard()` | `ShardId::from_raw(10)` |
| `test_spec()` | `ShardSpec` with range `[a, z)` |
| `test_worker(id)` | `WorkerId::from_raw(id)` |
| `now(t)` | `LogicalTime::from_raw(t)` |
| `test_key()` | `ShardKey::new(test_run(), test_shard())` |
| `test_cursor(key)` | `Cursor::with_last_key(key.to_vec())` |
| `seeded_coordinator()` | `InMemoryCoordinator` with one run containing one shard `[a, z)`, `CursorSemantics::Completed`, already in Active status |
| `seeded_coordinator_with_semantics(s)` | Same as above but with the specified `CursorSemantics` |
| `test_split_replace_plan()` | Canonical `[a,m) + [m,z)` `SplitReplacePlan` |
| `test_split_residual_plan()` | Canonical `[a,m)` parent + `[m,z)` residual `SplitResidualPlan` |
| `acquire_shard(coord, t, worker_id)` | Shorthand for `acquire_and_restore`; returns the `Lease` |
| `checkpoint_ok(coord, t, lease, cursor_key, op_id)` | Fire-and-forget `checkpoint` using `test_tenant()` |
| `complete_ok(coord, t, lease, cursor_key, op_id)` | Fire-and-forget `complete` using `test_tenant()` |
| `park_ok(coord, t, lease, reason, op_id)` | Fire-and-forget `park_shard` using `test_tenant()` |
| `LEASE_DURATION` | `100` logical time ticks |

`seeded_coordinator()` calls `create_run` and `register_shards` during
construction, so the run is Active and the shard is ready for acquire.
The register-shards op uses `OpId::MAX` to avoid collisions with test ops.

### Tiger Style Assertions

Every conformance test asserts both the expected outcome *and* the absence
of unexpected side effects. This pattern is called "Tiger Style" (after
TigerBeetle's testing philosophy).

Example from `fence_monotonicity_across_full_lifecycle`:

```rust
// After checkpoint: verify cursor advanced AND fence did not change.
let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
assert_eq!(rec.fence_epoch, f1, "checkpoint must not change fence");
assert_eq!(rec.status, ShardStatus::Active);
```

The positive assertion (`fence_epoch == f1`) proves the expected behavior.
The status check proves no unexpected side effect (e.g., an accidental
terminal transition). This catches regressions where satisfying one
invariant accidentally violates another.

---

## 6. Tier 4 — Simulation Tests

**Files:** `sim/sim_behavioral_tests.rs`, `sim/mega_sim_tests.rs`
**Declared in:** `sim/mod.rs` (`#[cfg(test)]`)

Two sub-tiers exercise the full simulation harness.

### Behavioral Regression Tests (`sim_behavioral_tests.rs`)

Fixed-seed behavioral tests that pin safety properties without depending
on exact PRNG-stream counts. A legitimate harness change that reorders
random calls shifts counts but must not break behavioral assertions.

| Test | Config | Assertions |
|------|--------|------------|
| `behavioral_seed_42_stormy` | seed=42, Stormy, 3 workers, 5 shards, 700 ops | No violations, converged, event coverage |
| `behavioral_seed_99_sunny` | seed=99, SunnyDay, 2 workers, 3 shards, 300 ops | No violations, converged, event coverage |
| `behavioral_seed_7_radioactive` | seed=7, Radioactive, 4 workers, 8 shards, 1500 ops | No violations (convergence not asserted under aggressive faults) |
| `deterministic_replay_cross_config` | Runs each config twice | Field-identical reports (`event_counts`, `ops_executed`, `end_time`) |

A compile-time `const` match block provides exhaustiveness enforcement:
if a variant is added to `SimEventKind` without updating the match, the
build fails. This replaces the former `all_event_kinds_enumerated`
runtime test, which was strictly weaker.

Event coverage checks are fault-level-dependent: under `SunnyDay` with a
small op budget, `WorkerPaused`/`WorkerResumed` may or may not appear
depending on the PRNG sequence, so those are only required under
`Stormy`/`Radioactive` where higher op counts make them reliable.

### Mega Simulation Tests (`mega_sim_tests.rs`)

Thread-parallel seed sweep and proptest-based sweeper. Both are `#[ignore]`
because they are too slow for the default `cargo test` cycle.

**`mega_sim_10k_steps`** — Divides seeds across `available_parallelism()`
OS threads. Each seed runs 4 workers contending over 15 shards through
10K safety ops + 2K liveness ops. Assertions: zero invariant violations
across all seeds; aggregate event-kind coverage includes the five core
kinds. Failures include reproduction commands.

**`proptest_mega_sim`** — Delegates seed generation to proptest (100 cases
by default), gaining automatic shrinking and `.proptest-regressions` file
persistence. Same simulation config as `mega_sim_10k_steps`.

For simulation architecture, the invariant table (S1–S7), determinism
model, fault injection levels, and two-phase run model, see
[simulation-harness.md](simulation-harness.md).

---

## 7. Running Tests

### Quick test cycles

```bash
# All coordination tests (unit + conformance + scenario)
cargo test -p gossip-contracts --lib coordination

# Individual tiers
cargo test -p gossip-contracts --lib in_memory_tests
cargo test -p gossip-contracts --lib conformance_tests
cargo test -p gossip-contracts --lib scenario_tests
```

### Simulation tests

```bash
# Behavioral regression tests (fast, runs in default cargo test)
cargo test --all-features -p gossip-contracts -- sim

# Mega simulation (slow, #[ignore])
cargo test -p gossip-contracts mega_sim -- --ignored --nocapture
```

### Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `GOSSIP_SIM_SEEDS` | Number of seeds in the parallel sweep | 100 |
| `GOSSIP_SIM_SEED` | Single seed for failure reproduction (bypasses sweep) | — |
| `GOSSIP_SIM_FAULT` | Fault level: `sunny`, `stormy`, `radioactive` | `stormy` |

### Reproducing failures

The mega sim prints reproduction commands for every failing seed:

```bash
GOSSIP_SIM_SEED=<seed> cargo test -p gossip-contracts mega_sim -- --ignored --nocapture
```

Or programmatically:

```rust
let report = CoordinationSim::new(FAILING_SEED, FaultLevel::Stormy)
    .with_workers_and_shards(4, 15)
    .run(10_000, 2_000);
assert!(report.violations.is_empty());
```

The simulation is fully deterministic: same seed, same fault level, same
worker/shard counts, same op counts produce identical results on any
platform.

---

## 8. Choosing the Right Tier

| Signal | Tier |
|--------|------|
| Testing a single backend operation in isolation | Tier 1 — Unit |
| Two or more invariants interact and must hold simultaneously | Tier 2 — Conformance |
| Multi-step workflow or end-to-end user story | Tier 3 — Scenario |
| Randomized large-scale validation or fault injection | Tier 4 — Simulation |

When adding a new protocol feature:

1. Start with Tier 1 tests for each new operation or error path.
2. If the feature interacts with existing invariants, add Tier 2 tests
   that compose the relevant invariants.
3. If the feature changes user-visible workflow behavior, add a Tier 3
   scenario.
4. Run the existing simulation suite to verify no regressions. If the
   feature adds new randomized behavior (e.g., a new fault type), update
   the simulation harness and add behavioral assertions.

---

## 9. Invariants Under Test

The simulation validates seven safety properties at every step. Unit,
conformance, and scenario tests exercise these implicitly via
`ShardRecord::assert_invariants()` (called on every mutation path), while
the simulation validates them explicitly via `InvariantChecker::check_all()`.

| Label | Name | Rule |
|-------|------|------|
| S1 | MutualExclusion | At most one worker holds a non-expired lease per shard |
| S2 | FenceMonotonicity | `fence_epoch` never decreases for a given `(RunId, ShardId)` |
| S3 | TerminalIrreversibility | Terminal states (Done, Split, Parked) never revert to non-terminal |
| S4 | RecordInvariant | `ShardRecord::assert_invariants()` does not panic |
| S5 | CursorMonotonicity | `cursor.last_key()` never decreases per shard |
| S6 | CursorBounds | Non-initial cursors remain within shard spec key range |
| S7 | SplitCoverage | Split-parent's spawned children exist and reference the correct parent |

Full invariant definitions and the checker implementation are in
[simulation-harness.md](simulation-harness.md).

---

## 10. Source Files

| File | Role |
|------|------|
| `coordination/in_memory_tests.rs` | Tier 1: unit tests + proptest property tests |
| `coordination/conformance_tests.rs` | Tier 2: invariant-interaction tests (Groups A, B, C) |
| `coordination/scenario_tests.rs` | Tier 3: multi-step end-to-end workflows (S1–S8) |
| `coordination/test_fixtures.rs` | Shared factory functions and seeded coordinator setup |
| `sim/sim_behavioral_tests.rs` | Tier 4a: fixed-seed behavioral regression + deterministic replay |
| `sim/mega_sim_tests.rs` | Tier 4b: thread-parallel seed sweep + proptest sweeper |
| `sim/harness.rs` | Simulation driver (CoordinationSim, two-phase run model) |
| `sim/invariants.rs` | External invariant checker (S1–S7) |
| `sim/worker.rs` | Simulated worker bookkeeping |
| `sim/mod.rs` | SimContext (PRNG + clock), FaultConfig, FaultLevel |
