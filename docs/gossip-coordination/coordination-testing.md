# Coordination Testing Strategy

Testing strategy for the shard coordination protocol and its simulation
infrastructure. Four tiers target distinct quality dimensions: isolation,
invariant interaction, workflow correctness, and large-scale randomized
validation.

Split-replace planner construction (`SplitReplacePlan`, `plan_split_replace*`)
is contracts-owned in `gossip-contracts::coordination::split`; coordination
tests validate backend execution semantics using those shared planner surfaces.

For protocol details see [boundary-2-coordination.md](boundary-2-coordination.md).
For simulation architecture see [simulation-harness.md](simulation-harness.md).

A family-oriented execution seam in `crates/gossip-scanner-runtime/` and
`gossip_contracts::connector` bridges coordination and scan execution.
Coordination tests continue to validate protocol invariants independently of
scan execution internals, while runtime integration tests exercise the same
family entrypoints used by the CLI and worker binaries.

The etcd scaffold in `crates/gossip-coordination-etcd/` adds backend-specific
tests alongside the shared protocol suite: configuration/keyspace/codec tests
stay local and deterministic, while ignored local-etcd integration coverage
auto-provisions `quay.io/coreos/etcd:v3.5.15` via testcontainers (or reuses
`ETCD_ENDPOINTS`) and verifies `EtcdCoordinator::connect()` /
`AsyncEtcdCoordinator::connect()` + `status()`, persisted run
creation/registration, acquire/checkpoint/renew, terminal shard transitions
(`complete`, `park_shard`), unpark, split round trips, shard-limit rejection
paths, derived-ID collision handling, and deterministic split-atomicity aborts
via test-only owner-drop fault injection. A separate `#[ignore]` test
(`lease_ttl_expiry_full_cycle`) exercises wall-clock lease TTL expiry against
live etcd: it verifies that the owner binding is auto-deleted while the shard
record survives, that a second worker can reacquire with an advanced fence, and
that the original worker's stale lease is rejected for both `renew` and
`checkpoint`. The binary codec (`codec.rs`) has
dedicated round-trip fuzz targets and proptest coverage for `ShardRecord`
serialization in `codec_tests.rs`. Deterministic simulator tests cover the
in-process etcd path via `SimulatedEtcdKV` and `SimEtcdCoordinator`, including
compare-miss contention, uncertain commits, lease-expiry races, and
retry-exhaustion bursts. The ignored local-etcd tests remain the coverage layer
for live gRPC transport and real-member integration. A dedicated
`behavioral_conformance.rs` module mirrors the shared coordination conformance
scenarios against the real `EtcdCoordinator`, using only public
`CoordinationBackend` / `RunManagement` operations plus persisted read-back
helpers (`test_load_shard_snapshot`, `test_load_run_snapshot`) instead of
simulation-only introspection.

## Allocation Policy Scope (Tiered)

Coordination follows a HOT/WARM/COLD allocation policy:

- **HOT** paths keep allocation-silent behavior where practical
  (`acquire_and_restore_into`, `checkpoint`, `complete`, claim internals).
- **WARM** query/admin paths prioritize simpler contracts and may grow
  caller buffers (`list_shards_into`, `collect_claim_candidates_into`).
- **COLD** lifecycle/setup paths optimize for clarity and atomicity over
  preallocation plumbing (`register_shards` preflight + staged rollback).

Simulation/test-support code (`crates/gossip-coordination/src/sim/`) remains free to allocate for
readability, workload generation, and diagnostics.

Feature-aware enforcement remains in place for production-facing signatures:

- `#[cfg(not(feature = "test-support"))]` compile-time guards in
  `crates/gossip-coordination/src/conformance_tests.rs` preserve borrowed/scratch hot-path
  forms.
- The same guards are intentionally absent with `test-support` enabled, so
  simulation infrastructure can evolve without hot-path false positives.

---

## 1. Testing Pyramid

```text
                                                ┌─────────────────────┐
                    ┌──────────────┐            │  TLA+ Model Check   │
                    │  Simulation  │  Tier 4    │  (specs/)           │
                    │  (sim/)      │            │                     │
                    ├──────────────┤            │  Exhaustive design  │
                    │  Scenario    │  Tier 3    │  verification of    │
                    │              │            │  protocol safety    │
                ┌───┴──────────────┴───┐       │  and liveness       │
                │    Conformance       │ T2    │  properties.        │
                │                      │       │                     │
            ┌───┴──────────────────────┴───┐   │  Parallel layer,    │
            │         Unit Tests           │ T1│  not a pyramid tier │
            │                              │   │  (verifies design,  │
            └──────────────────────────────┘   │  not Rust code).    │
                                                └─────────────────────┘
```

Each tier builds on the one below it. Unit tests validate individual
operations against the `InMemoryCoordinator`. Conformance tests compose
two or more invariants and verify they hold simultaneously. Scenario tests
chain operations into realistic workflows. Simulation tests sweep hundreds
of random seeds under fault injection, validating all nine safety
invariants at every step. TLA+ model checking (Section 11) operates as a
parallel verification layer that exhaustively verifies the protocol design.

---

## 2. Tier 1 — Unit Tests

**File:** `crates/gossip-coordination/src/in_memory_tests.rs`
**Declared in:** `crates/gossip-coordination/src/in_memory.rs` (via `#[path = "in_memory_tests.rs"]` attribute)

Single-operation isolation tests against `InMemoryCoordinator`. Each test
exercises one backend operation or one edge case, with deterministic
logical time advanced via `now(t)`.

### Coverage areas

| Area               | Example tests                                                                                                                             |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Acquire            | `acquire_basic`, `acquire_not_found`, `acquire_already_leased`, `acquire_after_lease_expiry`, `acquire_terminal_rejected`                 |
| Renew              | `renew_basic`, `renew_stale_fence`                                                                                                        |
| Checkpoint         | `checkpoint_basic`, `checkpoint_op_id_conflict`                                                                                           |
| Complete           | `complete_basic`, `complete_replay_after_terminal`                                                                                        |
| Park               | `park_basic`, `park_replay_after_terminal`                                                                                                |
| Split (replace)    | `split_replace_basic`, `split_replace_replay`, `split_replace_child_id_determinism`                                                       |
| Split (residual)   | `split_residual_basic`, `split_residual_cursor_out_of_bounds`, `split_residual_replay_via_spawned_after_eviction`                         |
| Fencing            | `only_latest_fence_holder_can_mutate`                                                                                                     |
| Op-log eviction    | `op_log_eviction_treats_old_op_as_new`                                                                                                    |
| Tenant isolation   | `acquire_wrong_tenant_returns_not_found`, `checkpoint_wrong_tenant_returns_not_found`, etc.                                               |
| Shard count limits | `split_replace_exceeds_per_tenant_limit`, `split_residual_exceeds_global_limit`, `register_shards_exceeds_per_tenant_limit`               |
| Run lifecycle      | `terminal_op_happy_path`, `cancel_run_from_initializing`, `terminal_op_idempotent_replay`, `complete_run_not_found`                       |
| Unpark             | `unpark_shard_happy_path`, `unpark_shard_fence_epoch_bumped`, `unpark_shard_cursor_preserved`, `unpark_shard_rejected_when_run_terminal` |
| List shards        | `list_shards_filter_active`, `list_shards_filter_available`, `list_shards_filter_parked`, `list_shards_filter_root_only`                  |
| Integration        | `full_lifecycle_acquire_checkpoint_split_residual_complete`, `full_run_lifecycle_create_register_process_complete`                        |

The module also includes **property-based tests** (proptest) that fuzz
random operation sequences against the coordinator and assert structural
invariants (record consistency, fence monotonicity, cursor monotonicity,
idempotent replay) after every step.

All tests use shared fixtures from `test_fixtures.rs` (see Section 5).

---

## 3. Tier 2 — Conformance Tests

**Harness:** `crates/gossip-coordination/src/conformance.rs`
**In-memory binding:** `crates/gossip-coordination/src/conformance_tests.rs`
**Declared in:** `lib.rs` (`#[cfg(any(test, feature = "test-support"))] pub mod conformance;`, `#[cfg(test)] mod conformance_tests;`)

Invariant-interaction tests. Each test composes two or more of the
protocol's safety invariants and verifies they hold simultaneously. The
focus is on invariant *combinations* — these are the tests most likely to
catch regressions where a fix for one invariant violates another.
`conformance.rs` owns the reusable backend-agnostic harness, while
`conformance_tests.rs` keeps the in-memory backend entrypoint and the
production-only compile-time API guards.

### Group A: Cross-Cutting Invariant Interactions

| Test                                               | Invariants composed                                                                                       |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `fence_monotonicity_across_full_lifecycle`         | Fence monotonicity + lease expiry enables re-acquisition + checkpoint/complete do not mutate fence        |
| `cursor_monotonicity_combined_with_split_residual` | Cursor bounds + split-residual spec narrowing + cursor preservation across splits                         |
| `idempotency_before_terminal_state_rejection`      | OpId idempotency + terminal irreversibility + their priority ordering                                     |
| `owner_divergence_with_matching_fence`             | Lease validation (fence + owner identity) + tenant isolation                                              |
| `terminal_clears_lease`                            | Terminal transitions clear leases + correct terminal status per operation (complete, park, split_replace) |

### Group B: Supplementary Coverage Tests

Edge cases with zero or minimal coverage elsewhere.

| Test                                              | Gap filled                                                                      |
| ------------------------------------------------- | ------------------------------------------------------------------------------- |
| `cursor_semantics_dispatched_through_coordinator` | `CursorSemantics::Dispatched` propagation through acquire, checkpoint, complete |
| `lease_deadline_at_exact_boundary`                | Half-open lease interval: `now < deadline` active, `now == deadline` expired    |
| `split_coverage_key_range_partition`              | Split-replace children's key ranges form a contiguous, gap-free partition       |
| `oplog_eviction_then_replay`                      | Op-log eviction interaction with idempotency on terminal shards                 |
| `unpark_lifecycle_fence_and_cursor_preserved`     | Full park/unpark round-trip preserves cursor, bumps fence, allows re-acquire    |
| `same_worker_reacquire_bumps_fence`               | Same-worker reacquire bumps fence, old lease rejected with `StaleFence`         |

### Group C: Run-Level Conformance

Run lifecycle state machine tests.

| Test                                           | Property                                                |
| ---------------------------------------------- | ------------------------------------------------------- |
| `run_terminal_irreversibility`                 | Done run rejects complete_run, fail_run, and cancel_run |
| `register_shards_on_non_initializing_rejected` | Registration requires Initializing status               |
| `run_completed_at_consistency`                 | `completed_at` is `Some` iff run is terminal            |
| `unpark_after_run_terminal_rejected`           | Terminal run blocks shard-level unpark (`RunTerminal`)  |

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

**File:** `crates/gossip-coordination/src/scenario_tests.rs`
**Declared in:** `lib.rs` (`#[cfg(test)]`)

Multi-step workflow tests that exercise realistic end-to-end stories.
Each scenario chains operations in production-realistic order, including
state restoration across ownership transfers.

| ID  | Scenario                    | Core property                                                                                          |
| --- | --------------------------- | ------------------------------------------------------------------------------------------------------ |
| S1  | Full run lifecycle          | Baseline happy path: create_run → register → acquire → checkpoint×3 → complete (shard) → complete_run  |
| S2  | Lease expiry + reacquire    | Cursor restoration across ownership transfer; stale writer fenced with `StaleFence`                    |
| S3  | Split-replace + children    | Parent becomes `Split`; children are independently acquirable and completable by different workers     |
| S4  | Double residual split chain | Iterative parent narrowing `[a,z)→[a,m)→[a,j)` with spawned list tracking; all three pieces complete   |
| S5  | Op-log eviction boundary    | Evicted `OpId` treated as new (`Executed`); surviving `OpId` with wrong payload returns `OpIdConflict` |
| S6  | Cancel from Initializing    | Early run termination blocks registration; idempotent replay; terminal irreversibility                 |
| S7  | Worker self-recovery        | Same worker recovers from own lease expiry with cursor restoration and fence bump                      |
| S8  | Claim contention            | 3 workers contend for 2 shards via `claim_next_available`; exactly 2 succeed, 1 gets `NoneAvailable`   |

---

## 5. Test Infrastructure

### Test Fixtures (`crates/gossip-coordination/src/test_fixtures.rs`)

Shared factory functions consumed by all three coordination test modules.

| Function                                            | Returns                                                                                                                  |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `test_tenant()`                                     | `TenantId` from fixed bytes                                                                                              |
| `test_run()`                                        | `RunId::from_raw(1)`                                                                                                     |
| `test_shard()`                                      | `ShardId::from_raw(10)`                                                                                                  |
| `test_spec()`                                       | `ShardSpec` with range `[a, z)`                                                                                          |
| `test_worker(id)`                                   | `WorkerId::from_raw(id)`                                                                                                 |
| `now(t)`                                            | `LogicalTime::from_raw(t)`                                                                                               |
| `test_key()`                                        | `ShardKey::new(test_run(), test_shard())`                                                                                |
| `test_cursor(key)`                                  | `CursorUpdate::new(key)`                                                                                                 |
| `seeded_coordinator()`                              | `InMemoryCoordinator` with one run containing one shard `[a, z)`, `CursorSemantics::Completed`, already in Active status |
| `seeded_coordinator_with_semantics(s)`              | Same as above but with the specified `CursorSemantics`                                                                   |
| `test_split_replace_plan()`                         | Canonical `[a,m) + [m,z)` `SplitReplacePlan`                                                                             |
| `test_split_residual_plan()`                        | Canonical `[a,m)` parent + `[m,z)` residual `SplitResidualPlan`                                                          |
| `acquire_shard(coord, t, worker_id)`                | Shorthand for `acquire_and_restore`; returns the `Lease`                                                                 |
| `checkpoint_ok(coord, t, lease, cursor_key, op_id)` | Fire-and-forget `checkpoint` using `test_tenant()`                                                                       |
| `complete_ok(coord, t, lease, cursor_key, op_id)`   | Fire-and-forget `complete` using `test_tenant()`                                                                         |
| `park_ok(coord, t, lease, reason, op_id)`           | Fire-and-forget `park_shard` using `test_tenant()`                                                                       |
| `LEASE_DURATION`                                    | `100` logical time ticks                                                                                                 |

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

**Primary files:** `crates/gossip-coordination/src/sim/sim_behavioral_tests.rs`, `crates/gossip-coordination/src/sim/mega_sim_tests.rs`, `crates/gossip-coordination/src/sim/overload_tests.rs`, `crates/gossip-coordination/src/sim/proptest_state_machine_tests.rs`, `crates/gossip-coordination/src/sim/composition_tests.rs`
**Declared in:** `crates/gossip-coordination/src/sim/mod.rs` (`#[cfg(test)]`)

Eight sub-tiers exercise the full simulation harness.

Test-support builds also include a composition harness for the coordination +
done-ledger boundary. It reuses the same `SimContext` determinism model but
adds a synthetic scan driver and cross-component provenance log on top of the
core coordination harness.

### Overload Scenario Tests (`crates/gossip-coordination/src/sim/overload_tests.rs`)

Targeted tests for the scripted overload path (`run_overload`). Fixed-seed
tests cover each `OverloadKind` under different fault levels, a deterministic
replay test verifies seed stability, a D1 accuracy test validates availability
reporting, and a proptest sweeps random seeds/kinds/rounds for safety.

| Test                                                   | Config                         | Assertions                    |
| ------------------------------------------------------ | ------------------------------ | ----------------------------- |
| `test_overload_burst_claim_sunny`                      | seed=42, SunnyDay, 10 rounds   | No violations, L1 liveness    |
| `test_overload_capacity_drop_stormy`                   | seed=77, Stormy, 8 rounds      | No violations                 |
| `test_overload_burst_shards_radioactive` (`#[ignore]`) | seed=9, Radioactive, 12 rounds | No violations                 |
| `test_overload_deterministic_replay`                   | seed=123, Stormy, 12 rounds    | Field-identical reports       |
| `test_d1_accuracy_sunny`                               | seed=7, SunnyDay, 10 rounds    | D1 reported == ground truth   |
| `test_overload_zero_rounds_warmup_recovery_only`       | seed=1, SunnyDay, 0 rounds     | No violations, goodput == 0.0 |
| `proptest_overload_safety`                             | 50 cases, Stormy, 0-6 rounds   | No violations                 |

### Behavioral Regression Tests (`sim_behavioral_tests.rs`)

Fixed-seed behavioral tests that pin safety properties without depending
on exact PRNG-stream counts. A legitimate harness change that reorders
random calls shifts counts but must not break behavioral assertions.

| Test                                         | Config                                                         | Assertions                                                           |
| -------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------- |
| `behavioral_seed_42_stormy`                  | seed=42, Stormy, 3 workers, 5 shards, 700 ops                  | No violations, converged, event coverage                             |
| `behavioral_seed_99_sunny`                   | seed=99, SunnyDay, 2 workers, 3 shards, 300 ops                | No violations, converged, event coverage                             |
| `behavioral_seed_7_radioactive`              | seed=7, Radioactive, 4 workers, 8 shards, 1500 ops             | No violations (convergence not asserted under aggressive faults)     |
| `deterministic_replay_cross_config`          | Runs each config twice                                         | Field-identical reports (`event_counts`, `ops_executed`, `end_time`) |
| `behavioral_cooldown_fires_under_simulation` | seed=42, SunnyDay, 8 workers, 20 shards, cooldown=99, 2000 ops | Cooldown throttling fires, `ClaimThrottled` event present            |

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

### Stress Tests (`mega_sim_tests.rs`)

Scale-sensitive tests that push configurations well beyond the normal
test suite. Both are `#[ignore]`.

**`stress_200_shards_stormy`** — 8 workers, 200 shards, Stormy, 5 seeds,
5K safety + 2K liveness ops. At ~13x the shard count of the mega sweep,
this test exercises two scale-sensitive paths: `InvariantChecker` pruning
overhead as many shards reach terminal states, and worker contention with
8 workers competing for 200 shards.

**`stress_split_cascade`** — 4 workers, 20 shards, Radioactive, 10 seeds,
3K safety + 1K liveness ops. Radioactive mode's aggressive time-jumps and
high lease-expiry rate create conditions for multi-level split cascades.
Asserts at least one `SplitReplaceOk` event fires across all seeds,
catching regressions in op-generation weights or split-plan construction.
Invariants S1–S9 are validated even as the shard set grows dynamically
from splits.

### Convergence Proptests (`mega_sim_tests.rs`)

Bounded-liveness tests that complement the mega sweep's safety focus.
The Alpern-Schneider decomposition (1985) states that every correctness
property is the intersection of a safety property and a liveness property.
The mega sweep covers safety (S1–S9); these tests cover the complementary
liveness half — that every shard eventually reaches a terminal state.
Both are `#[ignore]`.

**`proptest_convergence_sunny`** — SunnyDay, 200 cases, 50 safety + 2000
liveness ops. Asserts both safety (no violations) and liveness (all shards
terminal). Zero faults, but splits during the safety phase grow the shard
count from the initial 15 to ~20-25, requiring proportionally more
liveness ops for reliable acquire→complete cycles.

**`proptest_convergence_stormy`** — Stormy, 200 cases, 500 safety + 15000
liveness ops. Same dual assertion under ~10% fault pressure. Faults cause
lease expiry mid-operation, forcing re-acquisition cycles that consume
extra ops. The ~7.5× raw budget over SunnyDay compensates for the ~10%
rejection rate and larger active shard set from the longer safety phase.

### Multi-Tenant Isolation (`mega_sim_tests.rs`)

**`multi_tenant_isolation`** — Two tenants sharing one
`InMemoryCoordinator` instance. This is the only test that exercises the
cross-tenant rejection path (tenant-scoped lookup returning `ShardNotFound`)
and tenant-scoped checker history.
Runs in the default `cargo test` cycle (not `#[ignore]`).

The test verifies three properties:

1. **Cross-tenant rejection**: tenant B cannot acquire tenant A's shards
   (tenant-scoped lookup returns `ShardNotFound`).
2. **Independent lifecycles**: each tenant's shards progress through
   acquire → checkpoint → terminal independently, exercising both
   terminal paths (`Complete` for tenant A, `Park` for tenant B).
3. **Checker isolation**: the `InvariantChecker` uses
   `(TenantId, RunId, ShardId)` history keys, so tenant A's fence epoch
   history does not contaminate tenant B's S2 checks.

### Regression Guard

**`zero_seed_count_does_not_panic`** — Protects against a `chunks(0)`
panic when `GOSSIP_SIM_SEEDS=0`. The mega sweep's `div_ceil` and
`chunks()` calls would panic unconditionally without the early-return
guard; this test mirrors the arithmetic path to verify the guard remains
effective.

### Proptest State Machine Tests (`proptest_state_machine_tests.rs`)

Proptest-driven operation sequence tests that generate `Vec<SimOp>` via
stateless strategies and feed them through `CoordinationSim::step()`.
Unlike the mega-sim tests (which shrink only the seed), these tests shrink
the operation sequence itself — when a bug is found, proptest minimizes to
the smallest failing sequence of coordinator operations.

Operations are generated without state tracking. The harness handles
rejected/skipped ops gracefully, and the invariant checker (S1–S9) runs
after every step regardless of outcome. Expected rejection rate is ~45-55%
for held-shard ops; rejections verify the coordinator's rejection path
preserves safety.

| Test                                            | Config                           | Assertions              |
| ----------------------------------------------- | -------------------------------- | ----------------------- |
| `prop_short_sequences_preserve_invariants`      | SunnyDay, 256 cases, 5-50 ops    | No violations (CI gate) |
| `prop_safety_under_random_ops` (`#[ignore]`)    | Stormy, 200 cases, 5-200 ops     | No violations           |
| `prop_safety_across_fault_levels` (`#[ignore]`) | All levels, 100 cases, 5-200 ops | No violations           |

```bash
# CI-friendly (not ignored)
cargo test -p gossip-coordination prop_short_sequences_preserve_invariants

# Deep tests (ignored)
cargo test -p gossip-coordination proptest_state_machine -- --ignored --nocapture
```

For simulation architecture, the invariant table (S1–S9), determinism
model, fault injection levels, and three-stage run model, see
[simulation-harness.md](simulation-harness.md).

---

## 7. Running Tests

### Quick test cycles

```bash
# All coordination protocol tests (unit + conformance + scenario)
cargo test -p gossip-coordination

# Data model tests (shard_spec, cursor, pooled)
cargo test -p gossip-contracts --lib coordination

# Individual tiers (module pattern matching)
cargo test -p gossip-coordination in_memory_tests
cargo test -p gossip-coordination conformance_tests
cargo test -p gossip-coordination scenario_tests
```

### Overload tests

```bash
# Overload scenario tests (fast, runs in default cargo test)
cargo test -p gossip-coordination overload

# Including the slow radioactive test
cargo test -p gossip-coordination overload -- --ignored --nocapture
```

### Simulation tests

```bash
# Behavioral regression tests (fast, runs in default cargo test)
cargo test --all-features -p gossip-coordination -- sim

# Mega simulation (slow, #[ignore])
cargo test -p gossip-coordination mega_sim -- --ignored --nocapture

# Convergence proptests (slow, #[ignore])
cargo test -p gossip-coordination proptest_convergence -- --ignored --nocapture

# Stress tests (slow, #[ignore])
cargo test -p gossip-coordination stress_ -- --ignored --nocapture

# Multi-tenant isolation (fast, runs in default cargo test)
cargo test -p gossip-coordination multi_tenant -- --nocapture
```

### Environment variables

| Variable           | Purpose                                               | Default  |
| ------------------ | ----------------------------------------------------- | -------- |
| `GOSSIP_SIM_SEEDS` | Number of seeds in the parallel sweep                 | 100      |
| `GOSSIP_SIM_SEED`  | Single seed for failure reproduction (bypasses sweep) | —        |
| `GOSSIP_SIM_FAULT` | Fault level: `sunny`, `stormy`, `radioactive`         | `stormy` |

### Reproducing failures

The mega sim prints reproduction commands for every failing seed:

```bash
GOSSIP_SIM_SEED=<seed> cargo test -p gossip-coordination mega_sim -- --ignored --nocapture
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

| Signal                                                       | Tier                 |
| ------------------------------------------------------------ | -------------------- |
| Testing a single backend operation in isolation              | Tier 1 — Unit        |
| Two or more invariants interact and must hold simultaneously | Tier 2 — Conformance |
| Multi-step workflow or end-to-end user story                 | Tier 3 — Scenario    |
| Randomized large-scale validation or fault injection         | Tier 4 — Simulation  |

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

The simulation validates nine safety properties at every step. Unit,
conformance, and scenario tests exercise these implicitly via
`ShardRecord::assert_invariants()` (called on every mutation path), while
the simulation validates them explicitly via `InvariantChecker::check_all()`.

| Label | Name                       | Rule                                                                   |
| ----- | -------------------------- | ---------------------------------------------------------------------- |
| S1    | MutualExclusion            | At most one worker holds a non-expired lease per shard                 |
| S2    | FenceMonotonicity          | `fence_epoch` never decreases for a given `(RunId, ShardId)`           |
| S3    | TerminalIrreversibility    | Terminal states (Done, Split, Parked) never revert to non-terminal     |
| S4    | RecordInvariant            | `ShardRecord::assert_invariants()` does not panic                      |
| S5    | CursorMonotonicity         | `cursor.last_key()` never decreases per shard                          |
| S6    | CursorBounds               | Non-initial cursors remain within shard spec key range                 |
| S7    | SplitCoverage              | Split-parent's spawned children exist and reference the correct parent |
| S8    | RunTerminalIrreversibility | Terminal run states never revert                                       |
| S9    | CooldownViolation          | A worker must not claim twice within cooldown interval                 |

Full invariant definitions and the checker implementation are in
[simulation-harness.md](simulation-harness.md).

---

## 10. Source Files

| File                                                                 | Role                                                                   |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `crates/gossip-coordination/src/in_memory_tests.rs`                  | Tier 1: unit tests + proptest property tests                           |
| `crates/gossip-coordination/src/error_tests.rs`                      | Tier 1: error type Display/source/Debug coverage                       |
| `crates/gossip-coordination/src/record_tests.rs`                     | Tier 1: `ShardRecord`, `ShardStatus`, `ParkReason`, `OpLogEntry` tests |
| `crates/gossip-coordination/src/run_tests.rs`                        | Tier 1: run lifecycle types, validation, and state machine tests       |
| `crates/gossip-coordination/src/facade_tests.rs`                     | Tier 1: `CoordinationFacade`, `ShardClaiming`, claim algorithm tests   |
| `crates/gossip-coordination/src/session_tests.rs`                    | Tier 1: `WorkerSession` RAII handle and delegation tests               |
| `crates/gossip-coordination/src/in_memory_filter_tests.rs`           | Tier 1: `ShardFilter` predicates for `list_shards_into`                |
| `crates/gossip-coordination/src/in_memory_run_tests.rs`              | Tier 1: `RunManagement` trait implementation tests                     |
| `crates/gossip-coordination/src/conformance.rs`                      | Tier 2: backend-agnostic invariant-interaction harness (Groups A, B, C) |
| `crates/gossip-coordination/src/conformance_tests.rs`                | Tier 2: InMemoryCoordinator binding + compile-time API guards          |
| `crates/gossip-coordination/src/scenario_tests.rs`                   | Tier 3: multi-step end-to-end workflows (S1–S9)                        |
| `crates/gossip-coordination/src/test_fixtures.rs`                    | Shared factory functions and seeded coordinator setup                  |
| `crates/gossip-coordination/src/sim/sim_behavioral_tests.rs`         | Tier 4a: fixed-seed behavioral regression + deterministic replay       |
| `crates/gossip-coordination/src/sim/mega_sim_tests.rs`               | Tier 4b: thread-parallel seed sweep + proptest sweeper                 |
| `crates/gossip-coordination/src/sim/proptest_state_machine_tests.rs` | Tier 4c: proptest state machine tests with per-op shrinking            |
| `crates/gossip-coordination/src/sim/harness.rs`                      | Simulation driver (`run` + `run_overload`)                             |
| `crates/gossip-coordination/src/sim/harness_tests.rs`                | Harness unit and property tests for bookkeeping and op generation      |
| `crates/gossip-coordination/src/sim/invariants.rs`                   | External invariant checker (S1–S9)                                     |
| `crates/gossip-coordination/src/sim/invariants_tests.rs`             | Targeted unit tests for `InvariantChecker` edge cases                  |
| `crates/gossip-coordination/src/sim/overload.rs`                     | Overload scenario/reports and scripted op generators                   |
| `crates/gossip-coordination/src/sim/overload_tests.rs`               | Overload scenario tests: per-kind, replay, D1 accuracy, proptest       |
| `crates/gossip-coordination/src/sim/composition.rs`                  | Test-support composition harness coupling coordinator and done-ledger  |
| `crates/gossip-coordination/src/sim/composition_invariants.rs`       | Cross-component invariant checker for coordinator ↔ done-ledger provenance (C1–C4) |
| `crates/gossip-coordination/src/sim/composition_invariants_tests.rs` | Targeted unit tests for `CompositionInvariantChecker` and C1–C4 violations |
| `crates/gossip-coordination/src/sim/composition_tests.rs`            | Four-tier composition test suite for the coordinator ↔ done-ledger boundary |
| `crates/gossip-coordination/src/sim/scan_driver_sim.rs`              | Deterministic synthetic scan-outcome generator for composition runs    |
| `crates/gossip-coordination/src/sim/shared.rs`                       | Internal helper aliases and utility functions shared by both harnesses |
| `crates/gossip-coordination/src/sim/backend.rs`                      | `SimIntrospection` and `SimulationBackend` trait definitions           |
| `crates/gossip-coordination/src/sim/fault_injector.rs`               | Fault-injecting introspector for invariant checker validation          |
| `crates/gossip-coordination/src/sim/worker.rs`                       | Simulated worker bookkeeping                                           |
| `crates/gossip-coordination/src/sim/test_util.rs`                    | Shared test helpers: record builder, proptest strategies               |
| `crates/gossip-coordination/src/sim/mod.rs`                          | SimContext (PRNG + clock), FaultConfig, FaultLevel                     |

---

## 11. Formal Verification (TLA+)

Tiers 1-4 verify the **Rust implementation** of the coordination protocol.
TLA+ model checking verifies the **protocol design** -- an abstract model
that exhaustively explores all reachable states to prove safety and liveness
properties hold regardless of timing, interleaving, or worker behavior.

### Invariant correspondence

| TLA+ invariant                  | Sim label | Property                                           |
| ------------------------------- | --------- | -------------------------------------------------- |
| `MutualExclusion`               | S1        | At most one valid lease per shard                  |
| `AlwaysFenceMonotonicity`       | S2        | Fence epoch never decreases                        |
| `AlwaysTerminalIrreversibility` | S3        | Done and Split never revert                        |
| `TerminalUnleased`              | S4        | Terminal shards hold no lease                      |
| `CursorMonotonicity`            | S5        | Cursor never decreases                             |
| `AlwaysCursorNonRegression`     | S5        | Cursor never decreases (action property)           |
| --                              | S6        | CursorBounds (byte-key ranges not modeled in TLA+) |
| `SplitAtomicity`                | S7        | Split parent has non-empty spawned set             |
| `ChildImpliesParentSplit`       | S7        | Child non-NotCreated implies parent Split          |
| `ZombieRejection`               | --        | Stale-epoch worker cannot hold valid lease         |
| `Liveness` (INV-L01)            | --        | Active unleased shard eventually leased            |

Gaps are intentional: S6 (CursorBounds) depends on byte-key ranges not
present in the abstract model; ZombieRejection and Liveness have no
simulation label because they were introduced by the TLA+ spec.

### Running the model checker

See [specs/coordination/README.md](../../specs/coordination/README.md) for
prerequisites, TLC commands, and mutation tests.

### Source files

| File                                           | Purpose                           |
| ---------------------------------------------- | --------------------------------- |
| `specs/coordination/ShardFencing.tla`          | TLA+ specification                |
| `specs/coordination/ShardFencing.cfg`          | Production safety config          |
| `specs/coordination/ShardFencing_liveness.cfg` | Liveness config                   |
| `specs/coordination/run_mutations.sh`          | Mutation test suite (14 mutations) |
