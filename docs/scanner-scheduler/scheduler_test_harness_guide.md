# Scheduler Test Harness User Guide

This guide explains how to use the deterministic scheduler simulation harness to test the executor's work-stealing policy.

## Overview

The scheduler test harness validates the **executor's work distribution policy** - not scanning logic. It simulates multi-worker scheduling without OS threads, enabling reproducible bug discovery and systematic interleaving exploration.

**What it tests:**
- Local LIFO queue semantics (cache locality)
- Global FIFO injector behavior
- Work-stealing with randomized victim selection
- Gate/count correctness (no lost tasks after `join()`)
- Park/unpark semantics (no deadlocks while work exists)
- Resource accounting (bounded permits)

**Why deterministic simulation:**
- **Reproducible bugs**: Any failure produces an artifact that replays identically
- **Systematic exploration**: Enumerate interleavings that would require millions of runs to hit randomly
- **Shared policy code**: `executor_core.rs` runs identically in production and simulation

## Quick Start

```bash
# Run corpus regression tests
cargo test --features scheduler-sim scheduler_sim_replay_corpus

# Run stress tests with random case generation
cargo test --features scheduler-sim scheduler_sim_stress_smoke

# Scale stress runs via environment variables
SCHEDULER_SIM_STRESS_SEEDS=100 cargo test --features scheduler-sim scheduler_sim_stress_smoke
```

**Key paths:**
- **Corpus**: `tests/simulation/corpus/*.json` - regression tests replayed on every run
- **Failures**: `tests/failures/*.json` - where stress failures are written

## SimCase DSL Reference

A `SimCase` defines a complete simulation scenario in JSON. The harness loads the case, initializes the executor, and steps through actions until completion or failure.

### Top-Level Structure

```json
{
  "schema_version": 1,
  "seed": 42,
  "case": {
    "exec_cfg": { ... },
    "resources": [ ... ],
    "programs": [ ... ],
    "tasks": [ ... ],
    "initial_runnable": [ ... ],
    "external_events": [ ... ],
    "max_steps": 100
  },
  "driver_choices": [ ... ],
  "expected_trace_hash": 12345678901234567890,
  "failure": { ... }
}
```

### exec_cfg - Executor Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `workers` | usize | required | Number of simulated worker threads |
| `steal_tries` | u32 | 4 | Steal attempts before parking |
| `seed` | u64 | required | RNG seed for deterministic victim selection |
| `wake_on_hoard_threshold` | u32 | 32 | Local spawns before waking a sibling worker |

```json
"exec_cfg": {
  "workers": 2,
  "steal_tries": 2,
  "seed": 178,
  "wake_on_hoard_threshold": 32
}
```

### resources - Bounded Permits

Models semaphores, byte budgets, or other bounded resources. Tasks can acquire and release units; the harness checks for overflow/underflow.

```json
"resources": [
  { "id": 0, "total": 4 },
  { "id": 1, "total": 1 }
]
```

### programs - Task Definitions

Each program is a sequence of bytecode instructions. Multiple tasks can share a program (like a function definition).

```json
"programs": [
  {
    "name": "worker",
    "code": [
      { "Yield": { "placement": "Local" } },
      "Complete"
    ]
  }
]
```

### tasks - Task Instances

Logical task states. Each task references a program and starts at a program counter (pc).

```json
"tasks": [
  { "tid": 0, "program": 0, "pc": 0 },
  { "tid": 1, "program": 1, "pc": 0 }
]
```

### initial_runnable - Starting Queue

Task IDs to enqueue at simulation start. A task ID can appear multiple times to model multiple run-tokens.

```json
"initial_runnable": [0, 1, 0]
```

### external_events - Scheduled I/O and Gate Operations

Events delivered by the driver at specific steps. These model external I/O completions and the `join()` call that closes the accepting gate.

```json
"external_events": [
  { "at_step": 5, "event": { "IoComplete": { "token": 7 } } },
  { "at_step": 10, "event": "CloseGateJoin" }
]
```

### max_steps - Safety Limit

Hard cap on simulation steps to prevent infinite runs. Reaching this limit without invariant violation means the test passed.

### driver_choices - Replay Interleaving

Each choice is an index into the enabled action list at that step. Empty means use the default policy (first enabled action).

```json
"driver_choices": [
  { "idx": 0 },
  { "idx": 1 }
]
```

### expected_trace_hash - Determinism Check

A 64-bit hash of the trace events. Replay must produce this exact hash, validating determinism.

### failure - Artifact Metadata

`failure` records the outcome captured when the artifact was created.
Replay currently asserts `expected_trace_hash`; this field is metadata.

```json
"failure": {
  "kind": "Timeout",
  "step": 11,
  "message": "corpus artifact"
}
```

`"Timeout"` with `"corpus artifact"` is the common convention for non-violation corpus cases.
Some corpus artifacts intentionally use other kinds (for example `"Panic"`).

## Bytecode Instruction Reference

Each instruction executes atomically. After execution, the task either continues (new PC), blocks, or completes.

| Instruction | Scanner Equivalent | JSON Syntax |
|-------------|-------------------|-------------|
| `Yield` | Async yield / reschedule self | `{ "Yield": { "placement": "Local" } }` |
| `Spawn` | `ctx.spawn_local()` / `spawn_global()` | `{ "Spawn": { "program": 1, "placement": "Local" } }` |
| `Sleep` | Timer-based wait / backoff | `{ "Sleep": { "ticks": 5 } }` |
| `WaitIo` | Waiting for network/disk I/O | `{ "WaitIo": { "token": 7 } }` |
| `TryAcquire` | ByteBudget / permit check | `{ "TryAcquire": { "res": 0, "units": 1, "ok": 2, "fail": 3 } }` |
| `Release` | Return budget / permit | `{ "Release": { "res": 0, "units": 1 } }` |
| `Jump` | Control flow (goto PC) | `{ "Jump": { "target": 0 } }` |
| `Complete` | Task finishes normally | `"Complete"` |
| `Panic` | Intentional crash (error path testing) | `"Panic"` |

### Placement Options

Used by `Yield` and `Spawn` to control where run-tokens are enqueued:

| Placement | Queue | Semantics |
|-----------|-------|-----------|
| `Local` | Worker's local LIFO queue | Cache locality, same worker likely executes |
| `Global` | Global FIFO injector | Fairness, any worker can pick up |
| `External` | Global injector (gated) | Respects accepting gate; fails after `join()` |

### Instruction Details

**Yield**: Re-enqueues the current task as a new run-token. The task continues at PC+1 when next executed.

```json
{ "Yield": { "placement": "Local" } }
```

**Spawn**: Creates a new task from the specified program and enqueues it. Parent continues at PC+1.

```json
{ "Spawn": { "program": 1, "placement": "Global" } }
```

**Sleep**: Blocks until `ticks` time units pass. The driver's `AdvanceTimeTo` action wakes sleepers.

```json
{ "Sleep": { "ticks": 3 } }
```

**WaitIo**: Blocks until the matching `IoComplete` event is delivered.

```json
{ "WaitIo": { "token": 42 } }
```

**TryAcquire**: Attempts to acquire `units` from resource `res`. Jumps to `ok` on success, `fail` on insufficient availability.

```json
{
  "TryAcquire": {
    "res": 0,
    "units": 1,
    "ok": 1,
    "fail": 3
  }
}
```

**Release**: Returns `units` to resource `res`. Panics on over-release.

```json
{ "Release": { "res": 0, "units": 1 } }
```

**Jump**: Unconditional jump to target PC.

```json
{ "Jump": { "target": 0 } }
```

**Complete**: Task finishes. No more instructions execute.

```json
"Complete"
```

**Panic**: Triggers a panic for testing error handling paths.

```json
"Panic"
```

## Common Scenarios

### Scenario 1: Basic Yield and Complete

Tests that a single task can yield and complete.

```json
{
  "exec_cfg": { "workers": 1, "steal_tries": 2, "seed": 161, "wake_on_hoard_threshold": 32 },
  "resources": [],
  "programs": [
    {
      "name": "basic",
      "code": [
        { "Yield": { "placement": "Local" } },
        "Complete"
      ]
    }
  ],
  "tasks": [{ "tid": 0, "program": 0, "pc": 0 }],
  "initial_runnable": [0],
  "external_events": [{ "at_step": 3, "event": "CloseGateJoin" }],
  "max_steps": 50
}
```

### Scenario 2: Work-Stealing

Tests that tasks spawned locally can be stolen by idle workers.

```json
{
  "exec_cfg": { "workers": 2, "steal_tries": 2, "seed": 178, "wake_on_hoard_threshold": 32 },
  "resources": [],
  "programs": [
    {
      "name": "root",
      "code": [
        { "Spawn": { "program": 1, "placement": "Local" } },
        "Complete"
      ]
    },
    {
      "name": "child",
      "code": ["Complete"]
    }
  ],
  "tasks": [{ "tid": 0, "program": 0, "pc": 0 }],
  "initial_runnable": [0],
  "external_events": [],
  "max_steps": 20
}
```

Worker 0 spawns a child locally. Worker 1 can steal the child from worker 0's queue (FIFO steal = oldest first).

### Scenario 3: I/O and Sleep Blocking

Tests that tasks block on I/O until completion events arrive, and that sleepers wake after time advances.

```json
{
  "exec_cfg": { "workers": 1, "steal_tries": 2, "seed": 195, "wake_on_hoard_threshold": 32 },
  "resources": [],
  "programs": [
    {
      "name": "io_sleep",
      "code": [
        { "WaitIo": { "token": 7 } },
        { "Sleep": { "ticks": 2 } },
        "Complete"
      ]
    }
  ],
  "tasks": [{ "tid": 0, "program": 0, "pc": 0 }],
  "initial_runnable": [0],
  "external_events": [
    { "at_step": 1, "event": { "IoComplete": { "token": 7 } } },
    { "at_step": 5, "event": "CloseGateJoin" }
  ],
  "max_steps": 40
}
```

### Scenario 4: Resource Contention

Tests that bounded resources are correctly accounted and that TryAcquire branches correctly.

```json
{
  "exec_cfg": { "workers": 1, "steal_tries": 2, "seed": 212, "wake_on_hoard_threshold": 32 },
  "resources": [{ "id": 0, "total": 1 }],
  "programs": [
    {
      "name": "resource_release",
      "code": [
        { "TryAcquire": { "res": 0, "units": 1, "ok": 1, "fail": 3 } },
        { "Release": { "res": 0, "units": 1 } },
        "Complete",
        "Complete"
      ]
    },
    {
      "name": "resource_fail",
      "code": [
        { "TryAcquire": { "res": 0, "units": 1, "ok": 1, "fail": 2 } },
        "Complete",
        "Complete"
      ]
    }
  ],
  "tasks": [
    { "tid": 0, "program": 0, "pc": 0 },
    { "tid": 1, "program": 1, "pc": 0 }
  ],
  "initial_runnable": [0, 1, 0],
  "external_events": [],
  "max_steps": 20
}
```

With only 1 unit available, one task acquires while the other fails and takes the `fail` branch.

## Workflow Guide

### When to Create New Test Cases

- **After finding a concurrency bug**: Create a regression test from the failure artifact
- **Before major executor changes**: Add stress coverage for the changed behavior
- **When adding new executor features**: Write specification tests that exercise the feature

### Adding a Test to the Corpus

1. Create a JSON file in `tests/simulation/corpus/` following the schema above
2. Run `cargo test --features scheduler-sim scheduler_sim_replay_corpus`
3. The test will fail with `trace hash mismatch` and print the actual hash
4. Copy the printed hash into your JSON as `expected_trace_hash`
5. Re-run to verify the test passes

Example workflow:
```bash
# Create your test case
vim tests/simulation/corpus/my_test.json

# Run to get the trace hash (will fail first time)
cargo test --features scheduler-sim scheduler_sim_replay_corpus

# Update expected_trace_hash with the printed value
# Re-run to verify
cargo test --features scheduler-sim scheduler_sim_replay_corpus
```

### Interpreting Failure Artifacts

When stress tests find a violation, they write an artifact to `tests/failures/`:

```json
{
  "failure": {
    "kind": { "Violation": "RunnableStarvation" },
    "step": 47,
    "message": "task 3 runnable since step 12 (backlog 5)"
  }
}
```

Key fields:
- **`failure.kind`**: The violation type (see Invariants below)
- **`failure.step`**: Step number where the violation occurred
- **`driver_choices`**: Exact interleaving to reproduce the bug
- **`expected_trace_hash`**: Hash for determinism verification

### Running Stress Tests

```bash
# Default: 16 seeds, small bounds, fast
cargo test --features scheduler-sim scheduler_sim_stress_smoke

# Scale up for deeper testing
SCHEDULER_SIM_STRESS_SEEDS=1000 \
SCHEDULER_SIM_STRESS_MAX_STEPS=200 \
cargo test --features scheduler-sim scheduler_sim_stress_smoke

# Reproduce a specific failure
SCHEDULER_SIM_STRESS_SEEDS=1 \
SCHEDULER_SIM_STRESS_SEED_BASE=3735928559 \
cargo test --features scheduler-sim scheduler_sim_stress_smoke
```

Environment variables:
| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_SIM_STRESS_SEEDS` | 16 | Number of random cases to generate |
| `SCHEDULER_SIM_STRESS_MAX_STEPS` | 80 | Maximum steps per case |
| `SCHEDULER_SIM_STRESS_MAX_PROGRAMS` | 4 | Maximum programs per case |
| `SCHEDULER_SIM_STRESS_MAX_TASKS` | 4 | Maximum initial tasks per case |
| `SCHEDULER_SIM_STRESS_SEED_BASE` | 3490561775 (0xD00D_BEEF) | Base seed for RNG (env value is parsed as decimal) |

## Invariants Checked

The harness validates these invariants on every step:

| Invariant | Violation Kind | Meaning |
|-----------|---------------|---------|
| Resource bounds | `ResourceOverflow` | Released more units than acquired |
| Gate consistency | `GateViolation` | Gate closed with zero in-flight but `done` not set |
| Bounded starvation | `RunnableStarvation` | Runnable task not executed within bound |

Other `ViolationKind` variants exist in the enum (`InFlightMismatch`, `LostWakeup`, `IllegalUnblock`, etc.), but they are not emitted by the current oracle checks.

### Starvation Bound

The starvation check uses a dynamic bound: `K = workers * (steal_tries + 2) * 4 + backlog`. A runnable task must execute within K steps of becoming runnable, where `backlog` is the in-flight count when it became runnable. This accounts for legitimate queuing delays in busy systems.

## FAQ

**Q: Do I need to write tests for my scanning logic?**

A: No. This harness tests the executor (work distribution), not scanning. Use regular unit tests for scanning logic, rule validation, and transform correctness.

**Q: How do I model waiting for a file read?**

A: Use `WaitIo { token: N }` in the program, then schedule `IoComplete { token: N }` in `external_events`. The task blocks until the event is delivered.

**Q: Why does the corpus use "Timeout" as the failure kind?**

A: In corpus artifacts, `"Timeout"` is the common metadata convention for a non-violation case (`"corpus artifact"`). Replay correctness is enforced by `expected_trace_hash`.

**Q: How do I debug a failing stress test?**

A:
1. Find the artifact in `tests/failures/`
2. Set `SCHEDULER_SIM_STRESS_SEEDS=1` and `SCHEDULER_SIM_STRESS_SEED_BASE=<seed-as-decimal>` to reproduce
3. Add the artifact to `tests/simulation/corpus/` to make it a permanent regression test

**Q: Can I test the actual crossbeam queues?**

A: No. The simulation uses deterministic `VecDeque` models. The production crossbeam queues require real parallelism to test (consider loom for that). The harness tests the scheduling *policy*, not the queue *implementation*.

**Q: How do driver_choices work?**

A: At each step, the harness computes a list of enabled actions in a stable order. The `driver_choices[i].idx` selects the action at that index. Empty choices means use the default (index 0). This enables exact replay of any execution.
