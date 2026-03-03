# Git Simulation Harness Guide

This guide describes the deterministic Git simulation harness used to exercise
Git scanning stages without relying on OS scheduling, wall-clock time, or a real
repository layout.

## Purpose

- Provide deterministic stage execution under `SimExecutor`.
- Capture bounded trace events for replay and debugging.
- Enforce stability across schedule seeds.
- Validate correctness and gating invariants with structured oracles.

## Runner Lifecycle

The Git simulation runner models the Git scan pipeline as a sequence of stage
tasks. Each stage runs to completion in a single deterministic step, and the
scheduler decides which task to run next via a seed-driven RNG.

Stages:
1. Repo open (build simulated start set, commit graph, tree source)
2. Commit walk (plan commits)
3. Tree diff (emit candidates)
4. Pack exec (uses in-memory artifacts when present; falls back to semantic scan)
5. Finalize (determine complete vs partial outcome)

Stage boundaries emit trace events so failures can be replayed and minimized.
Each step also records the scheduler decision so trace hashes capture the
deterministic interleaving.

## Invariants

- Determinism: identical inputs and seeds yield identical trace + outputs.
- Stability: changing only the schedule seed yields identical normalized output.
- Watermark gating: any skipped candidate yields `Partial` and suppresses
  watermark advancement.
- Ordering: refs are processed in lexicographic order by raw refname bytes.
- Output sets: scanned and skipped OIDs are sorted, unique, and disjoint.

## Oracles

- Termination: runs complete within `max_steps` or return `FailureKind::Hang`.
- Determinism: identical `{scenario, seed}` yields identical trace hash.
- Stability: multiple schedule seeds compare normalized outputs and outcome.
- Gating: `FinalizeOutcome::Complete` requires zero skips;
  `FinalizeOutcome::Partial { skipped_count }` requires non-zero skips.

## Fault Plan

Faults are keyed by logical resources and per-read index so injected failures
are deterministic and schedule-independent.

Resources:
- `CommitGraph`
- `Midx`
- `Pack { pack_id }`
- `Persist`
- `Other(String)` for non-core resources

Faults:
- `ErrKind { kind }` (simulated I/O error)
- `PartialRead { max_len }` (short read)
- `EIntrOnce` (interrupted read)

Corruption:
- `TruncateTo { new_len }`
- `FlipBit { offset, mask }`
- `Overwrite { offset, bytes }`

Each fault is consumed in read-index order (`0`, `1`, …). When a fault or
corruption is applied, the runner emits a `FaultInjected` trace event that
captures the resource id, read index, and fault kind.

## Persistence Safety

The simulation persistence store (`SimPersistStore`) logs operations in the
order they are issued and enforces the two-phase contract:

- Data ops are always written first.
- Watermark ops are written only for `FinalizeOutcome::Complete`.
- Faults injected on the persistence resource abort the phase and prevent
  watermark writes, preserving partial-run gating.

## Failure Taxonomy

- `Panic`: unexpected panic in runner logic.
- `Hang`: no runnable tasks or exceeded `max_steps`.
- `InvariantViolation`: ordering or structural invariants failed.
- `OracleMismatch`: correctness oracle failed (gating, overlap, mismatch).
- `StabilityMismatch`: output differed across schedule seeds.

## Running Tests

The Git simulation tests are wired behind the `sim-harness` feature alongside
scanner simulation tests. Primary entry points:

```bash
# Random Git simulation runs (bounded)
cargo test --features sim-harness --test simulation git_scan_random

# Replay Git simulation corpus
cargo test --features sim-harness --test simulation git_scan_corpus
```

Corpus cases live in `tests/corpus/git_scan/*.case.json`. Replay failures emit
artifacts to `tests/failures/` for triage and minimization.

Optional knobs for random runs:

- `SIM_GIT_SCAN_DEEP=1` (larger scenarios)
- `SIM_GIT_SCAN_SEED_START` / `SIM_GIT_SCAN_SEED_COUNT`
- `SIM_GIT_SCENARIO_COMMITS`, `SIM_GIT_SCENARIO_REFS`, `SIM_GIT_SCENARIO_BLOBS_PER_TREE`
- `SIM_GIT_RUN_WORKERS`, `SIM_GIT_RUN_WORKERS_MIN`, `SIM_GIT_RUN_WORKERS_MAX`
- `SIM_GIT_RUN_MAX_STEPS`, `SIM_GIT_RUN_STABILITY_RUNS`, `SIM_GIT_RUN_TRACE_CAP`
- `GIT_SIM_WRITE_FAIL=1` (write failing artifacts to `tests/failures/`)

## CI Expectations

The Git simulation tests are included in the `sim-harness` suite. CI should
run at least:

```bash
cargo test --features sim-harness --test simulation
```

Soak or nightly tiers can increase `SIM_GIT_SCAN_SEED_COUNT` or enable
`SIM_GIT_SCAN_DEEP=1` for broader coverage.

## Minimization

The Git minimizer (`minimize_git_case`) applies conservative shrink passes:

- Drop unused fault plan entries and trailing read faults.
- Remove extra refs when failures reproduce with fewer start points.
- Prune unreachable commits/trees/blobs outside the ref-reachable subgraph.
- Drop optional artifact bundles when failures reproduce without pack bytes.

Minimization is driven by a reproduction predicate; only candidates that still
trigger the failure are retained. Use the replay harness to validate minimized
cases before adding them to the corpus.

## Related Docs

- `docs/architecture-overview.md`
- `docs/scanner_test_harness_guide.md`
