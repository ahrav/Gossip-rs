# Scheduler Simulation Corpus

This directory contains deterministic test cases for the scheduler simulation harness. Each JSON file is a `ReproArtifact` that is replayed on every test run to ensure regression coverage.

## Corpus Files

| File | Workers | What It Tests |
|------|---------|---------------|
| `basic.json` | 1 | Single worker yield and complete cycle |
| `steal.json` | 2 | Work-stealing between workers (local spawn, FIFO steal) |
| `io_sleep.json` | 1 | I/O blocking with `WaitIo` and timer blocking with `Sleep` |
| `resources.json` | 1 | Resource acquisition/release and contention paths |
| `global_spawn.json` | 2 | Global injector spawning behavior |
| `external_spawn.json` | 1 | External spawn with gate semantics |
| `jump.json` | 1 | Control flow with `Jump` instruction |
| `panic.json` | 1 | Task panic handling via `Panic` instruction |

## Coverage Requirements

The corpus must collectively exercise:

**Instructions:**
- `Yield` with all placement types (Local, Global, External)
- `Spawn` with all placement types
- `Sleep` and `WaitIo`
- `TryAcquire` and `Release`
- `Jump` and `Complete`
- `Panic` (verifies panic handling and `ExitPanicked` result)

**Scheduler Behavior:**
- Multi-worker execution
- Local queue pop (LIFO)
- Injector pop (FIFO)
- Steal from victim (FIFO)
- Time advancement for sleepers
- External events (IoComplete, CloseGateJoin)

The `scheduler_sim_replay_corpus` test asserts coverage completeness.

## Adding a New Test Case

1. **Create the JSON file** following the schema in [scheduler_test_harness_guide.md](../../../docs/scheduler_test_harness_guide.md)

2. **Run the corpus test** (it will fail with a hash mismatch):
   ```bash
   cargo test --features scheduler-sim scheduler_sim_replay_corpus
   ```

3. **Copy the actual hash** from the error message into your JSON as `expected_trace_hash`

4. **Re-run to verify**:
   ```bash
   cargo test --features scheduler-sim scheduler_sim_replay_corpus
   ```

## Trace Hash Workflow

The `expected_trace_hash` is a 64-bit SHA-256 prefix of the trace events. It validates that replay is deterministic:
- Same case + same driver_choices = same trace = same hash

If you modify the harness in a way that changes trace output (adding new trace events, changing event format), you'll need to update all corpus hashes.

## Promoting Stress Failures

When `scheduler_sim_stress_smoke` finds a violation, it writes an artifact to `tests/failures/`. To add it to the corpus:

1. Copy the file to this directory
2. Update `expected_trace_hash` if needed (stress artifacts may have a stale hash)
3. Change `failure.kind` to `"Timeout"` and `failure.message` to `"corpus artifact"`
4. Run the replay test to verify

This ensures the bug stays fixed.
