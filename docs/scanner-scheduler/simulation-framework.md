# Scanner Simulation Framework

Deterministic simulation framework for the scanner-scheduler: virtual clock, fault injection, seeded RNG, mutation-based testing, counterexample minimization, and oracle verification.

## Overview

The scanner simulation framework is a TigerBeetle-style VOPR (Verification by Overloaded, Parallel Replay) approach to testing the scanning pipeline. It replaces all sources of non-determinism — wall-clock time, OS scheduling, filesystem I/O, and randomness — with deterministic substitutes so that any test scenario can be reproduced, minimized, and replayed from a single seed.

**Design principles:**
- **Deterministic**: Same seed always produces byte-identical output. No wall-clock, no OS threads, no real filesystem.
- **Reproducible**: Every failure produces a self-contained `ReproArtifact` that replays identically.
- **Minimizable**: Failing cases are shrunk automatically via greedy deterministic passes.
- **Oracle-verified**: Multiple correctness oracles (ground-truth, differential, stability, archive, mutation) cross-check results.

**What it tests:**
- Chunked scanning with overlap deduplication
- Multi-worker discover + scan scheduling (single-threaded simulation)
- Fault injection (I/O errors, partial reads, corruption, cancellation, latency)
- Archive scanning (zip, tar, gzip, bzip2, tar.gz, tar.bz2) with virtual path mapping
- Mutation-based near-miss counterexample generation (token families, encoding layers)
- Secret detection correctness across encoding representations (raw, base64, percent, UTF-16)

## Architecture

The simulation framework is organized in three layers:

```
┌──────────────────────────────────────────────────────────────┐
│                    Test Harness Layer                         │
│  sim_scanner/runner_tests.rs    integration tests             │
│  Corpus replay · Random-seed stress · Mutation stress         │
├──────────────────────────────────────────────────────────────┤
│                  Execution Layer                              │
│  sim_scanner/runner.rs ── ScannerSimRunner                    │
│  sim_scanner/replay.rs ── replay_artifact()                   │
│  sim_scanner/generator.rs ── generate_scenario()              │
│  sim/mutation/adapter.rs ── build_mutation_scenario()          │
│  sim_scanner/vpath_table.rs ── VirtualPathTable               │
├──────────────────────────────────────────────────────────────┤
│                  Primitives Layer                             │
│  sim/clock.rs ── SimClock       sim/rng.rs ── SimRng          │
│  sim/fs.rs ── SimFs             sim/fault.rs ── FaultInjector │
│  sim/executor.rs ── SimExecutor sim/trace.rs ── TraceRing     │
│  sim/artifact.rs ── ReproArtifact                             │
│  sim/minimize.rs ── minimize_scanner_case()                   │
│  sim/mutation/ ── MutOp, TokenFamily, MutationPlan, encode    │
└──────────────────────────────────────────────────────────────┘
```

**Primitives** provide deterministic replacements for OS services. **Execution** wires them into a full scan simulation with oracles. **Test harness** drives execution from corpus artifacts, random seeds, and mutation plans.

## Key Types

### SimClock — Virtual Time

A monotonic tick-based clock with no wall-clock dependency. Time advances only through explicit `advance_to(t)` or `advance_by(dt)` calls. Ticks are unitless; callers assign meaning (e.g., 1 tick = simulated I/O latency).

**Invariant**: `now_ticks()` never decreases. `advance_to` debug-asserts monotonicity; `advance_by` saturates at `u64::MAX`.

```rust
pub struct SimClock { now: u64 }
// SimClock::new() starts at tick 0
// advance_to(t) — absolute jump
// advance_by(dt) — relative advance (saturating)
// now_ticks() — current time
```

Source: `crates/scanner-scheduler/src/sim/clock.rs`

### SimRng — Deterministic RNG

Uses xorshift64* for speed and cross-platform stability. A zero seed is remapped to `0x9E3779B97F4A7C15` to avoid the xorshift lockup state. Not cryptographically secure.

```rust
pub struct SimRng { state: u64 }
// SimRng::new(seed) — create with seed (zero remapped)
// next_u64() — xorshift64*
// gen_range(lo, hi_exclusive) — uniform u32 in [lo, hi)
// gen_bool(numerator, denominator) — weighted coin flip
```

Source: `crates/scanner-scheduler/src/sim/rng.rs`

### SimFs — In-Memory Filesystem

Deterministic in-memory filesystem. Stores files and directories as `BTreeMap`s keyed by raw byte paths. Directory listings are sorted lexicographically. Missing paths return `io::ErrorKind::NotFound`. Reads past EOF return empty slices.

```rust
pub struct SimFs {
    files: BTreeMap<Vec<u8>, Vec<u8>>,
    dirs: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
}
```

Built from a `SimFsSpec` containing `SimNodeSpec::File` and `SimNodeSpec::Dir` nodes. Files carry optional `discovery_len_hint` (for max-size filtering) and `type_hint` (`File`, `NotFile`, `Unknown`) modeling `DirEntry::file_type()` behavior.

Source: `crates/scanner-scheduler/src/sim/fs.rs`

### FaultPlan / FaultInjector — Fault Injection

Faults are declared in a `FaultPlan` keyed by file path bytes, then applied at runtime by a `FaultInjector` that tracks per-file read indices.

**FaultPlan** — declarative fault schedule:
```rust
pub struct FaultPlan {
    pub per_file: BTreeMap<Vec<u8>, FileFaultPlan>,
}

pub struct FileFaultPlan {
    pub open: Option<IoFault>,           // Fault on open
    pub reads: Vec<ReadFault>,           // Per-read faults (0-indexed)
    pub cancel_after_reads: Option<u32>, // Cancel after N reads
}
```

**IoFault** variants:
| Variant | Effect |
|---------|--------|
| `ErrKind { kind }` | Permanent I/O error; file is skipped |
| `PartialRead { max_len }` | Return at most `max_len` bytes |
| `EIntrOnce` | Single EINTR-style interruption (retry) |

**ReadFault** adds per-read latency and optional corruption:
```rust
pub struct ReadFault {
    pub fault: Option<IoFault>,
    pub latency_ticks: u64,
    pub corruption: Option<Corruption>,
}
```

**Corruption** variants: `TruncateTo { new_len }`, `FlipBit { offset, mask }`, `Overwrite { offset, bytes }`.

Serialization encodes path bytes as lowercase hex strings for JSON compatibility. Deserialization accepts both hex (`"666f6f"`) and raw UTF-8 (`"foo"`).

Source: `crates/scanner-scheduler/src/sim/fault.rs`

### SimExecutor — Deterministic Work-Stealing Executor

Models a multi-worker work-stealing scheduler in a single OS thread. Each `step()` call selects a worker uniformly at random via the seeded RNG, then that worker pops from its local queue (LIFO), falls back to the global queue (FIFO), or steals from a random victim (FIFO steal from front).

```rust
pub struct SimExecutor {
    workers: u32,
    local_queues: Vec<VecDeque<SimTaskId>>,
    global_queue: VecDeque<SimTaskId>,
    rng: SimRng,
    // ...
}
```

Task states: `Runnable`, `Blocked`, `Completed`. The executor does not interpret task kind — that is handled by the runner callback.

**What this does NOT model**: real-time scheduling, cache effects, CAS failures, thread wake/sleep.

Source: `crates/scanner-scheduler/src/sim/executor.rs`

### TraceRing — Bounded Event Buffer

Fixed-capacity ring buffer of `TraceEvent`s. When full, oldest events are evicted (FIFO). Used for failure forensics and replay debugging.

`TraceEvent` variants include: `StepChoose`, `TaskSpawn`, `TaskPoll`, `IoSubmit`, `IoComplete`, `FaultInjected`, `FindingEmit`, `ArchiveStart`, `ArchiveEntryStart`, `ArchiveEntryEnd`, `ArchiveEnd`, `InvariantFail`.

The runner uses a `TraceCollector` that writes to both the ring buffer (always, capacity 2048) and an optional full trace (when `SIM_TRACE_FULL` is set).

Source: `crates/scanner-scheduler/src/sim/trace.rs`

### ReproArtifact — Failure Reproduction

Self-contained JSON artifact that captures everything needed to replay a failure:

```rust
pub struct ReproArtifact {
    pub schema_version: u32,
    pub scanner_pkg_version: String,
    pub git_commit: Option<String>,
    pub scenario_seed: u64,
    pub schedule_seed: u64,
    pub run_config: RunConfig,
    pub scenario: Scenario,
    pub fault_plan: FaultPlan,
    pub failure: FailureReport,
    pub trace: TraceDump,
}
```

`TraceDump` contains the ring-buffer snapshot (`ring`) and an optional full trace (`full`).

Source: `crates/scanner-scheduler/src/sim/artifact.rs`

### VirtualPathTable — Archive Path Registry

Byte-budgeted, append-only mapping between raw path bytes and `FileId`s. Root files get low IDs (0, 1, 2, ...), archive entries get high-bit IDs (`0x8000_0000+`). Duplicate paths reuse existing IDs. Insertions fail when the byte budget is exhausted.

Source: `crates/scanner-scheduler/src/sim_scanner/vpath_table.rs`

## Scenario Generation

Scenarios are created through two pipelines depending on the test mode.

### Standard Generation (`generate_scenario`)

The standard generator creates filesystem contents with known secrets and matching rules:

1. **Build rule suite** — generates `N` synthetic rules, each with a deterministic prefix (`SIM0_`, `SIM1_`, ...) and a regex matching `prefix + [A-Z0-9]{token_len}`.
2. **Generate files** — for each file, inserts `secrets_per_file` secrets separated by noise bytes (`x` filler to avoid false prefix matches). Each secret picks a random rule and encoding representation (`Raw`, `Base64`, `UrlPercent`, `Utf16Le`, `Utf16Be`).
3. **Generate archives** — if `archive_count > 0`, materializes archive files (tar, zip, gzip, bzip2, tar.gz, tar.bz2) with embedded secrets. Gzip/bzip2 get exactly one entry (matching the scanner's single-stream model).
4. **Record expected secrets** — each inserted secret is recorded with its path, rule ID, encoded byte span, representation, and disposition (`MustFind` or `MayMiss`).

Configuration is via `ScenarioGenConfig`:

| Field | Default | Description |
|-------|---------|-------------|
| `rule_count` | 2 | Number of synthetic detection rules |
| `file_count` | 2 | Number of plain files |
| `secrets_per_file` | 3 | Secrets inserted per file/entry |
| `token_len` | 12 | Random token tail length |
| `min_noise_len` | 8 | Minimum noise bytes between secrets |
| `max_noise_len` | 32 | Maximum noise bytes between secrets |
| `archive_count` | 0 | Number of archive files |
| `archive_entries` | 2 | Entries per archive |
| `representations` | Raw, Base64, UrlPercent, Utf16Le, Utf16Be | Allowed encodings |

Source: `crates/scanner-scheduler/src/sim_scanner/generator.rs`

### Mutation Generation (`build_mutation_scenario`)

The mutation adapter translates `MutationPlan`s into a `Scenario` for the runner. Each plan becomes a separate file (`mutation_0.txt`, `mutation_1.txt`, ...) with the layout:

```
[noise_len bytes of '\n'] [wrapped token bytes] [noise_len bytes of '\n']
```

The noise padding separates tokens from file boundaries and provides leading context for the engine's overlap requirements.

Expected secrets use `MayMiss` point-span sentinels (1-byte spans every 8 bytes through the token region, for every rule ID). The real correctness check happens post-scan via `check_mutation_expectations`.

Source: `crates/scanner-scheduler/src/sim/mutation/adapter.rs`

## Runner

`ScannerSimRunner` executes a scenario deterministically in a single thread. The run loop:

1. **Initialize**: Build `SimFs`, discover file paths (lexicographic order, type-hint aware), create `SimExecutor` with schedule seed, spawn discovery task.
2. **Step loop**: On each step:
   - Deliver due I/O completions based on simulated clock
   - If no tasks queued but work incomplete, advance clock to next I/O tick (or fail with hang)
   - Call `executor.step()` to select a worker and task
   - Execute one quantum: discovery emits file-scan tasks (backpressure-limited by `max_in_flight_objects`), file-scan tasks perform open/read/scan steps
3. **Termination**: When all tasks complete, run oracles and return findings.

**File scanning** progresses through: open → read chunk → scan chunk → emit findings → advance tail overlap → repeat until EOF. Reads may block on simulated latency (via `FaultInjector`), at which point the task is marked `Blocked` and an I/O waiter is registered. The clock advances to wake blocked tasks.

**Archive scanning** loads the entire file into memory, dispatches to the appropriate format scanner (zip, tar, gzip, etc.), and processes entries through a `SimArchiveSink` that assigns virtual `FileId`s and collects per-entry summaries.

**Stability mode**: When `run_config.stability_runs > 1`, the runner replays the same scenario under additional schedule seeds and compares normalized finding sets. A mismatch produces a `StabilityMismatch` failure.

Source: `crates/scanner-scheduler/src/sim_scanner/runner.rs`

### Failure Kinds

| Kind | Meaning |
|------|---------|
| `Panic` | A panic escaped from engine or harness logic |
| `Hang` | Simulation failed to terminate within step budget |
| `InvariantViolation { code }` | Ordering, offset, dedupe, or budget invariant violated |
| `OracleMismatch` | Ground-truth, differential, or archive oracle failed |
| `StabilityMismatch` | Different schedules produced different finding sets |

Source: `crates/scanner-scheduler/src/sim_scanner/runner.rs`

### Oracles

The runner applies these correctness checks after a successful run:

**Ground-truth oracle** — verifies that every `MustFind` expected secret was detected and no unexpected findings appeared. Uses representation-aware span matching (strict containment for raw/percent, bounded slack for base64/UTF-16). Files with data-affecting faults are excluded.

**Differential oracle** — re-scans each file's observed byte stream in a single chunk (no overlap boundaries) and compares the findings set against the chunked results. Root findings must match exactly; non-root findings use relaxed comparison (only checked when `SCANNER_SIM_STRICT_NON_ROOT=1`).

**Archive oracle** — validates that archive scanning respected configured budgets (per-entry byte cap, per-root total cap, max entries), stats counters are consistent with outcomes, and skip/partial reasons are properly recorded.

**Stability oracle** — runs the same scenario under multiple schedule seeds (when `stability_runs > 1`) and asserts the normalized finding sets are identical.

**Mutation oracle** (`check_mutation_expectations`) — post-scan check for mutation test cases. For each case, computes the expected token span and checks whether any finding from the same file with the correct rule_id intersects that span. `MustMatch` not found is a violation (false negative). `MustNotMatch` but found is silently tolerated (context wrappers can extend regex matches).

Source: `crates/scanner-scheduler/src/sim_scanner/runner.rs` (dispatch + oracle impls), `crates/scanner-scheduler/src/sim/mutation/adapter.rs` (mutation oracle)

### Invariant Codes

The runner checks numbered invariants. Key codes:

| Code | Check |
|------|-------|
| 1 | `workers > 0` |
| 2 | `chunk_size > 0` |
| 3 | Scheduled task must be `Runnable` |
| 10 | `overlap >= engine.required_overlap()` |
| 11 | `chunk_size > 0` (per-file) |
| 15 | I/O completion before ready time |
| 16 | I/O completion offset mismatch |
| 18 | `tail_len` exceeds overlap |
| 20 | Duplicate finding emitted |
| 22 | Prefix boundary mismatch |
| 23 | Prefix dedupe failure |
| 30-33 | In-flight object budget accounting |
| 40-42 | Archive open/read invariants |
| 50-54 | Archive entry lifecycle invariants |
| 60 | Virtual path budget exceeded for root |

Source: `crates/scanner-scheduler/src/sim_scanner/runner.rs`

## Mutation Engine

The mutation subsystem generates near-miss counterexamples by perturbing valid tokens and predicting the expected detection outcome.

### Token Families

Each `TokenFamily` variant models one class of real-world credential:

| Family | Format | Length | Checksum |
|--------|--------|--------|----------|
| `AwsAccessKey` | `AKIA` + 16 base-32 chars | 20 | None (prefix + charset + length) |
| `GithubFinegrainedPat` | `github_pat_` + 76 base-62 + 6 CRC | 93 | CRC-32 over first 87 bytes (prefix included) |
| `GithubClassicPat` | `ghp_` + 30 base-62 + 6 CRC | 40 | CRC-32 over payload only (prefix excluded) |
| `JwtLike` | `eyJ...` header `.` payload `.` signature | Variable | None (structural: dot-separated base64url) |
| `Base64Blob` | `base64(24-48 random bytes)` | 32-68 | None (opaque) |
| `UrlEncodedBlob` | `%XX` encoding of 16-32 bytes | 48-96 | None (opaque) |

Each family provides:
- `gen_valid(rng)` — generate a structurally valid token (deterministic)
- `allowed_ops()` — which mutation operator kinds are meaningful
- `expectation(canonical, ops)` — predict detection outcome after mutations
- `param_bound()` — conservative upper bound for numeric parameters
- `rule_id()` — positional index in `TokenFamily::ALL` (single source of truth)

Source: `crates/scanner-scheduler/src/sim/mutation/family.rs`

### Mutation Operators (MutOp)

Composable perturbations applied left-to-right via `apply_ops`. Order-dependent. Out-of-range parameters are clamped (never panic).

| Operator | Effect | Gate Tested |
|----------|--------|-------------|
| `Truncate { len }` | Cut token to `len` bytes | Minimum-length |
| `CharsetViolate { positions, replacement }` | Replace bytes at positions | Charset validation |
| `PrefixMangle { replacement }` | Overwrite leading bytes | Structural prefix |
| `ChecksumCorrupt` | XOR last byte with `0xFF` | CRC/checksum |
| `EntropyReduce { repeat_byte, count }` | Fill first N bytes with repeat | Entropy threshold |
| `Encode { repr }` | Wrap in encoding layer | Encoding detection |
| `Extend { suffix }` | Append trailing bytes | Boundary detection |

Safety: pipeline halts if output exceeds `MAX_OUTPUT_BYTES` (1 MiB). `ApplyResult` reports how many operators actually ran, which the oracle uses to avoid predicting based on unapplied operators.

Source: `crates/scanner-scheduler/src/sim/mutation/op.rs`

### Expectation Oracle

`TokenFamily::expectation(canonical, ops)` returns a three-valued `Outcome`:

| Outcome | Meaning | Test action |
|---------|---------|-------------|
| `MustMatch` | No mutation alters a checked property | Miss = false negative bug |
| `MustNotMatch` | Hard constraint broken (length/charset/prefix/checksum) | Hit = tolerated (context effects) |
| `MayMatch` | Soft heuristic affected (entropy/encoding/trailing bytes) | Either outcome accepted |

The oracle evaluates operators left-to-right, tracking running token length. A `MustNotMatch` from any operator immediately dominates. Soft effects accumulate but can be overridden by later hard breakers.

Source: `crates/scanner-scheduler/src/sim/mutation/family.rs`

### Encoding Layer

Self-contained encoders that produce bit-identical output for any given input. No external crate dependencies for output stability.

| Representation | Function | Description |
|----------------|----------|-------------|
| `Raw` | identity | No encoding |
| `Base64` | `base64_encode_std` | RFC 4648 §4 with `=` padding |
| `UrlPercent` | `percent_encode_all` | Every byte as `%XX` (uppercase) |
| `Utf16Le` | `encode_utf16(_, false)` | Zero-extended to 16-bit LE |
| `Utf16Be` | `encode_utf16(_, true)` | Zero-extended to 16-bit BE |
| `Nested { depth }` | `encode_nested` | Alternating base64/percent, clamped to depth 4 |

Source: `crates/scanner-scheduler/src/sim/mutation/encode.rs`

### Context Wrappers

Mutated tokens are embedded in surrounding context via `ContextWrap`:

| Wrapper | Format |
|---------|--------|
| `Raw` | Token bytes only |
| `EnvAssignment` | `SECRET_KEY=<token>\n` |
| `JsonField` | `{"token":"<token>"}` |
| `YamlValue` | `token: <token>\n` |
| `SingleLineComment` | `// <token>\n` |
| `MultiLineString` | `"""\n<token>\n"""` |

No escaping is applied — the test exercises raw byte scanning, not format-aware parsing.

Source: `crates/scanner-scheduler/src/sim/mutation/plan.rs`

### Plan Execution Pipeline

A `MutationPlan` is a serializable recipe for one test case. `execute_plan` materializes it through a four-stage pipeline:

1. **Generate** — produce valid canonical token from family + seed
2. **Mutate** — apply operators left-to-right
3. **Predict** — query family oracle for expected outcome (only for operators that actually ran)
4. **Wrap** — embed in context, record token offset

The function is pure and deterministic: same plan always produces byte-identical output.

Source: `crates/scanner-scheduler/src/sim/mutation/plan.rs`

### Plan Generation

`random_mutation_plan(rng, case_id)` generates a single plan by drawing from the RNG in fixed order: family → base_seed → op_count (0-4) → operators → context wrapper. The strict consumption order is load-bearing: reordering any draw changes all downstream plans.

`random_mutation_plans_all_families(rng, plans_per_family)` generates plans for every family, grouped by family in `TokenFamily::ALL` order.

Source: `crates/scanner-scheduler/src/sim/mutation/plan_gen.rs`

## Minimization

`minimize_scanner_case(failing, cfg, reproduce)` shrinks a failing `ReproArtifact` through deterministic greedy passes. No randomness is used. Each candidate reduction is replayed via the `reproduce` predicate.

**Shrink passes** (applied in order, iterated until no pass makes progress or `max_iterations` reached):

1. **Reduce workers** — try fewer workers (down to 1)
2. **Reduce faults** — for each file in the fault plan:
   - Drop entire file fault entry
   - Remove open fault
   - Remove cancellation
   - Truncate read faults from tail
3. **Reduce files** — remove files from the scenario one at a time (also removes from fault plan and expected secrets)
4. **Reduce archives** — for each archive:
   - Remove entries (rematerializes archive bytes and remaps expected paths)
   - Truncate entry payloads (halve, then zero)
   - Shorten entry names
   - Reduce corruption parameters

The minimizer re-materializes archive bytes after each modification to keep the filesystem node consistent with the archive spec.

**Configuration**: `MinimizerCfg { max_iterations: 8 }` (default).

Source: `crates/scanner-scheduler/src/sim/minimize.rs`

## Replay

`replay_artifact(artifact)` rebuilds the engine from the artifact's rule suite and run config, then re-executes the simulation with the original schedule seed and fault plan:

```rust
pub fn replay_artifact(artifact: &ReproArtifact) -> RunOutcome {
    let engine = build_engine_from_suite(&artifact.scenario.rule_suite, &artifact.run_config)?;
    let runner = ScannerSimRunner::new(artifact.run_config.clone(), artifact.schedule_seed);
    runner.run(&artifact.scenario, &engine, &artifact.fault_plan)
}
```

Because all inputs are captured in the artifact (scenario, fault plan, seeds, run config), replay is fully deterministic.

Source: `crates/scanner-scheduler/src/sim_scanner/replay.rs`

## Oracle Verification

The framework uses five oracles to verify scan correctness. See [Oracles](#oracles) for details.

Summary of oracle coverage:

| Oracle | Checks | Failure Kind |
|--------|--------|--------------|
| Ground-truth | Expected secrets found, no unexpected findings | `OracleMismatch` |
| Differential | Chunked results match single-chunk reference scan | `OracleMismatch` |
| Archive | Budget enforcement, stats consistency | `OracleMismatch` |
| Stability | Same findings across different schedule seeds | `StabilityMismatch` |
| Mutation | Token family expectations vs. actual detection | `MutationCheckResult` (external) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIM_TRACE_FULL` | unset | When set, capture full trace (not just ring buffer) |
| `SCANNER_SIM_DUP_DEBUG` | unset | Print diagnostic details on duplicate finding detection |
| `SCANNER_SIM_STRICT_NON_ROOT` | unset | Enable strict non-root finding comparison in differential oracle |

The scheduler simulation harness (separate from the scanner simulation) uses additional variables documented in `docs/scanner-scheduler/scheduler_test_harness_guide.md`.

## Source of Truth

| Component | File |
|-----------|------|
| Sim module root | `crates/scanner-scheduler/src/sim/mod.rs` |
| SimClock | `crates/scanner-scheduler/src/sim/clock.rs` |
| SimRng | `crates/scanner-scheduler/src/sim/rng.rs` |
| SimFs, SimFsSpec, SimNodeSpec | `crates/scanner-scheduler/src/sim/fs.rs` |
| FaultPlan, FaultInjector, IoFault | `crates/scanner-scheduler/src/sim/fault.rs` |
| SimExecutor, SimTask, StepResult | `crates/scanner-scheduler/src/sim/executor.rs` |
| TraceEvent, TraceRing | `crates/scanner-scheduler/src/sim/trace.rs` |
| ReproArtifact, TraceDump | `crates/scanner-scheduler/src/sim/artifact.rs` |
| minimize_scanner_case, MinimizerCfg | `crates/scanner-scheduler/src/sim/minimize.rs` |
| MutOp, MutOpKind, apply_ops | `crates/scanner-scheduler/src/sim/mutation/op.rs` |
| TokenFamily, Outcome | `crates/scanner-scheduler/src/sim/mutation/family.rs` |
| SecretRepr, encode_secret | `crates/scanner-scheduler/src/sim/mutation/encode.rs` |
| MutationPlan, execute_plan, ContextWrap | `crates/scanner-scheduler/src/sim/mutation/plan.rs` |
| random_mutation_plan, random_mutation_plans_all_families | `crates/scanner-scheduler/src/sim/mutation/plan_gen.rs` |
| build_mutation_scenario, check_mutation_expectations | `crates/scanner-scheduler/src/sim/mutation/adapter.rs` |
| Scenario, RunConfig, ExpectedSecret | `crates/scanner-scheduler/src/sim_scanner/scenario.rs` |
| generate_scenario, ScenarioGenConfig | `crates/scanner-scheduler/src/sim_scanner/generator.rs` |
| ScannerSimRunner, RunOutcome, FailureKind | `crates/scanner-scheduler/src/sim_scanner/runner.rs` |
| replay_artifact | `crates/scanner-scheduler/src/sim_scanner/replay.rs` |
| VirtualPathTable | `crates/scanner-scheduler/src/sim_scanner/vpath_table.rs` |
