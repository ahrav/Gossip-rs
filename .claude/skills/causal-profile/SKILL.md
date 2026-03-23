---
name: causal-profile
description: Use when flamegraph/perf profiling identified hot functions but you are unsure which are on the critical path, when optimizing a hot function yields no measurable improvement, when concurrent code has hidden contention or pipeline imbalance, or when you need to prioritize optimization effort across multiple hot spots. Linux-only, synchronous code paths only (not async/Tokio).
user-invocable: true
---

# Causal Profiling — Find Code That Actually Counts

**Philosophy: Traditional profilers show where time is spent. Causal profiling
shows what to optimize.**

A function consuming 40% of runtime may yield 0% speedup when optimized (it is
off the critical path). A function consuming 0.15% of runtime may yield 25%
speedup when optimized (it serializes everything else). Causal profiling
distinguishes these cases. Traditional profiling cannot.

The technique was introduced by Curtsinger & Berger (SOSP 2015, Best Paper) and
works by *virtually speeding up* a target line — inserting delays into all other
threads to simulate the effect of making that line faster — then measuring the
impact on application-level progress. The result is a **speedup curve** for each
line: a direct answer to "if I made this line N% faster, how much faster would
the whole program get?"

## When to Use

- After flamegraph/perf profiling identified hot functions but you are unsure
  which ones are *on the critical path* and worth optimizing
- Concurrent/multi-threaded code where lock contention, pipeline stalls, or
  thread imbalance may hide the real bottleneck
- When traditional profiling says "optimize function X" but doing so yields no
  measurable improvement — causal profiling explains why
- When you need to *prioritize* optimization effort across multiple hot functions
- To detect contention (negative speedup curves) that is invisible to sampling profilers

## When NOT to Use

- **Async / Tokio code paths** — coz is fundamentally incompatible with M:N
  async runtimes. The virtual speedup mechanism operates on OS threads; Tokio
  multiplexes tasks across a thread pool, so delays applied to a thread affect
  unrelated tasks. Results will be misleading. Use `/linux-perf-profile` or
  `/perf-topdown` for async code.
- **macOS** — coz requires `LD_PRELOAD` and `perf_event_open()`, both
  Linux-only. Profile on a Linux machine or inside Docker.
- **Short-lived processes** (<2 seconds) — coz needs enough runtime to
  accumulate statistically significant experiments. Wrap the workload in a loop.
- **Code where you already know the bottleneck** — go straight to `/asm-forge`
  or `/perf-topdown` instead.
- **When co-running with other SIGPROF profilers** — coz uses SIGPROF for
  sampling. Cannot share with perf-based profilers simultaneously.

---

## Prerequisites

### Platform

Causal profiling requires Linux. Two paths:

**Native Linux**: Install coz from your package manager or build from source.

```bash
# Debian/Ubuntu
sudo apt-get install coz-profiler

# From source (recommended — gets latest fixes)
git clone https://github.com/plasma-umass/coz.git
cd coz && mkdir build && cd build && cmake .. && make -j$(nproc)
sudo make install
```

**Docker on macOS** (for local development):

```dockerfile
FROM rust:1.93-bookworm

# Install coz dependencies
RUN apt-get update && apt-get install -y \
    libelfin-dev \
    nodejs \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Build coz from source
RUN git clone https://github.com/plasma-umass/coz.git /opt/coz \
    && cd /opt/coz && mkdir build && cd build \
    && cmake .. && make -j$(nproc) && make install

# Docker capability requirement: CAP_PERFMON or CAP_SYS_ADMIN
# Run with: docker run --cap-add SYS_PTRACE --cap-add SYS_ADMIN ...
# Or on kernel 5.8+: docker run --cap-add CAP_PERFMON --cap-add SYS_PTRACE ...
```

Run container with required capabilities:

```bash
# Kernel 5.8+ (preferred — minimal privileges)
docker run --cap-add CAP_PERFMON --cap-add SYS_PTRACE \
  -v $(pwd):/workspace -w /workspace <image>

# Older kernels
docker run --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  -v $(pwd):/workspace -w /workspace <image>
```

### Rust Crate: Use Git Master, NOT crates.io

The published `coz` crate v0.1.3 on crates.io has a critical bug: the
`_coz_add_delays()` function is missing from the generated delay injection code.
This causes coz to report "0 experiments" — the profiler runs but collects no
data. **You must use the git master branch.**

```toml
# In the target crate's Cargo.toml
[dependencies]
coz = { git = "https://github.com/plasma-umass/coz.git", optional = true }

[features]
causal-profiling = ["dep:coz"]
```

### Build Profile: Debug Info Required

coz maps samples to source lines via DWARF debug info. Without it, profiles
are empty.

Add to the **workspace** `Cargo.toml`:

```toml
# Dedicated profile for causal profiling.
# Full optimization + debug info for source-line mapping.
[profile.causal]
inherits = "release"
debug = 1          # Line tables only — minimal binary size overhead
# debug = 2        # Full debug info — use if line attribution is poor
```

Build with:

```bash
cargo build --profile causal --features causal-profiling
```

The binary lands in `target/causal/`.

---

## Workflow Overview

```
/causal-profile <target-binary-or-bench> "what are you measuring"
    |
    +-- Phase 0: Pre-Flight Checks
    |   +-- Linux? Debug info? No async on target path?
    |   +-- coz installed? Using git master crate?
    |
    +-- Phase 1: Instrument
    |   +-- Add progress points (throughput or latency)
    |   +-- Add thread_init() to all spawned threads
    |   +-- Feature-gate behind causal-profiling
    |
    +-- Phase 2: Build & Validate
    |   +-- cargo build --profile causal --features causal-profiling
    |   +-- Verify debug info present (objdump / readelf)
    |   +-- Dry run: confirm progress point is hit
    |
    +-- Phase 3: Run Experiments
    |   +-- coz run --- ./target/causal/<binary>
    |   +-- Multiple runs for statistical confidence
    |
    +-- Phase 4: Interpret Results
    |   +-- Parse profile.coz
    |   +-- Classify speedup curves
    |   +-- Identify optimization targets
    |
    +-- Phase 5: Act on Findings
    |   +-- Apply fix to highest-impact line
    |   +-- Re-profile to confirm causal effect changed
    |   +-- Validate with Criterion benchmark
    |
    +-- Phase 6: Report
```

---

## Phase 0: Pre-Flight Checks

Run the bundled pre-flight script or verify manually:

```bash
bash .claude/skills/causal-profile/scripts/causal_preflight.sh ./target/causal/<binary>
```

Manual checklist:

| Check | Command | Expected |
|-------|---------|----------|
| Linux | `uname -s` | `Linux` |
| coz installed | `coz run --help` | Usage text |
| Debug info present | `readelf -S <binary> \| grep debug_line` | Non-empty `.debug_line` section |
| Feature enabled | `grep 'causal-profiling' Cargo.toml` | Feature exists |
| No async on target path | Code review | No `.await`, no tokio spawn on measured path |
| perf_event access | `cat /proc/sys/kernel/perf_event_paranoid` | `<= 1` (or run as root) |

If `perf_event_paranoid` is too restrictive:

```bash
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
# Or for Docker: ensure CAP_PERFMON / CAP_SYS_ADMIN capability
```

---

## Phase 1: Instrument

### The coz API

coz provides four macros. All are no-ops when the `coz` crate is not enabled,
so feature-gating makes instrumentation zero-cost in normal builds.

#### `coz::progress!("name")` — Throughput Progress Point

Marks completion of one unit of work. coz measures throughput as completions per
second. Place at the boundary where one logical work unit finishes.

```rust
fn process_batch(items: &[Item]) -> Result<()> {
    for item in items {
        process_single(item)?;
    }
    #[cfg(feature = "causal-profiling")]
    coz::progress!("batch_complete");
    Ok(())
}
```

**Placement rules:**
- At work-unit completion boundaries, NOT inside tight inner loops
- One progress point per profiling run (multiple points confuse the analysis)
- The point must be reached frequently enough for statistical significance
  (minimum ~5 visits per experiment, ideally hundreds)

#### `coz::begin!("name")` / `coz::end!("name")` — Latency Progress Points

Measures the wall-clock time between begin and end. Use for latency-sensitive
paths where you care about per-request time, not throughput.

```rust
fn handle_request(req: &Request) -> Response {
    #[cfg(feature = "causal-profiling")]
    coz::begin!("request_latency");

    let result = do_work(req);

    #[cfg(feature = "causal-profiling")]
    coz::end!("request_latency");

    result
}
```

**Warning:** `begin!` and `end!` must execute on the same thread. Do not
begin on one thread and end on another.

#### `coz::scope!("name")` — Scoped Latency (Preferred in Rust)

Drop-guard version of begin/end. Automatically calls end when the scope exits.
Handles early returns, `?` operator, and panics correctly.

```rust
fn handle_request(req: &Request) -> Result<Response> {
    #[cfg(feature = "causal-profiling")]
    coz::scope!("request_latency");

    let parsed = parse(req)?;        // early return handled
    let validated = validate(parsed)?; // early return handled
    Ok(process(validated))
    // end! called automatically on drop
}
```

**Prefer `scope!` over `begin!/end!`** in Rust code — it is immune to
early-return bugs that would leave a latency measurement dangling.

#### `coz::thread_init!()` — Thread Registration

**CRITICAL: Every thread that executes instrumented code MUST call
`coz::thread_init!()` before any coz macro.** Failure to do so causes a
sigaltstack crash — coz installs a SIGPROF handler that requires per-thread
signal stack setup.

```rust
fn spawn_workers(count: usize) -> Vec<JoinHandle<()>> {
    (0..count)
        .map(|_| {
            std::thread::spawn(|| {
                #[cfg(feature = "causal-profiling")]
                coz::thread_init!();

                // ... worker loop with progress points ...
            })
        })
        .collect()
}
```

The main thread is initialized automatically. Only explicitly spawned threads
need this call. **Rayon, crossbeam, and other thread-pool crates require
special handling** — see the Risk Mitigation section.

### Throughput vs Latency: Choosing the Right Mode

| Scenario | Mode | Macro |
|----------|------|-------|
| "How many items/sec can we process?" | Throughput | `coz::progress!()` |
| "How long does one request take?" | Latency | `coz::scope!()` |
| Pipeline with stages | Throughput on slowest stage | `coz::progress!()` at stage exit |
| Request handler | Latency | `coz::scope!()` around handler |

**Do not mix throughput and latency points in one run.** coz interprets them
differently and mixing produces inconsistent results.

### Feature-Gating Pattern

All instrumentation must be behind `#[cfg(feature = "causal-profiling")]` so
it compiles to nothing in normal builds:

```rust
// In lib.rs or the relevant module
#[cfg(feature = "causal-profiling")]
use coz;

pub fn critical_path() {
    #[cfg(feature = "causal-profiling")]
    coz::scope!("critical_path_latency");

    // ... actual work ...
}
```

For thread init in thread pool wrappers:

```rust
pub fn init_worker_thread() {
    #[cfg(feature = "causal-profiling")]
    coz::thread_init!();
}
```

---

## Phase 2: Build & Validate

### Build

```bash
cargo build --profile causal --features causal-profiling
```

### Verify Debug Info

```bash
# Must show .debug_line section
readelf -S ./target/causal/<binary> | grep debug_line

# Verify source mapping works for your target file
objdump -d -l ./target/causal/<binary> | grep '<source_file>.rs' | head -5
```

If `.debug_line` is absent, the profile will be empty. Double-check the
`[profile.causal]` section has `debug = 1` or `debug = 2`.

### Dry Run (Confirm Progress Points Fire)

Run the binary briefly without coz to verify it reaches the progress point:

```bash
# If you added a log/eprintln near the progress point for debugging:
timeout 5 ./target/causal/<binary> 2>&1 | grep -c "progress"

# Or just verify the binary runs without crash:
timeout 5 ./target/causal/<binary>
```

---

## Phase 3: Run Experiments

### Basic Run

```bash
coz run --- ./target/causal/<binary> [args...]
```

This produces `profile.coz` in the current directory. coz selects random lines
and random virtual speedups (0-100% in 5% increments), running many short
experiments. The 0% speedup is selected 50% of the time to build a strong
baseline.

### Scoped Run (Recommended for Large Binaries)

Limit coz to only experiment on lines within specific source files. This
dramatically reduces experiment count and improves statistical significance on
the code you care about:

```bash
# Single source file
coz run -s 'crates/scanner-engine/src/pipeline.rs%' \
    --- ./target/causal/<binary>

# Multiple source files
coz run -s 'crates/scanner-engine/src/pipeline.rs%' \
         -s 'crates/scanner-engine/src/matcher.rs%' \
    --- ./target/causal/<binary>

# Entire crate
coz run -s 'crates/scanner-engine/src/%' \
    --- ./target/causal/<binary>
```

The `%` wildcard at the end matches any suffix. Use source-relative paths as
they appear in DWARF debug info.

### Fixed-Line Experiment

Force coz to only experiment on a specific line (useful for hypothesis testing):

```bash
coz run -f 'crates/scanner-engine/src/pipeline.rs:142' \
    --- ./target/causal/<binary>
```

### Multiple Runs for Statistical Confidence

Single runs may have noisy data. Run 3-5 times and merge:

```bash
for i in $(seq 1 5); do
    coz run -o "profile-$i.coz" \
        -s 'crates/scanner-engine/src/%' \
        --- ./target/causal/<binary>
done

# Concatenate profiles (coz format is append-friendly)
cat profile-*.coz > profile-merged.coz
```

### Minimum Runtime

Each experiment needs the progress point to fire at least ~5 times. coz samples
at 1ms intervals and batches experiments every 10ms. For reliable results:

- **Throughput mode**: Progress point should fire hundreds of times per second
- **Latency mode**: Each begin-to-end span should be long enough to contain
  multiple sample points (>10ms ideal)
- **Total runtime**: At least 30 seconds, ideally 1-2 minutes, to accumulate
  enough experiments across different lines and speedup levels

### Runtime Overhead

Average overhead is ~17.6% (measured in the SOSP 2015 paper across PARSEC
benchmarks). The overhead comes from `nanosleep()` calls for virtual delays
and `perf_event_open()` sampling at ~1ms intervals.

---

## Phase 4: Interpret Results

### Viewing Results

**Browser viewer** (recommended):

```bash
# coz includes a web viewer
coz plot
# Or manually: open profile.coz at https://plasma-umass.org/coz/
```

**Text parsing** (for automated analysis):

The `profile.coz` format is line-oriented text:

```
startup	time=<ns>	end_time=<ns>
runtime	time=<ns>	end_time=<ns>
throughput-point	name=<name>	delta=<count>
latency-point	name=<name>	begin-delta=<count>	end-delta=<count>
experiment	selected=<file>:<line>	speedup=<0.00-1.00>	duration=<ns>	selected-samples=<n>	throughput-point	name=<name>	delta=<count>
```

Use the bundled parsing script:

```bash
bash .claude/skills/causal-profile/scripts/parse_coz_profile.sh profile.coz
```

### Speedup Curve Interpretation

Each profiled line gets a speedup curve: X-axis is "virtual speedup of this
line" (0-100%), Y-axis is "resulting program speedup."

#### Curve Shape Decision Table

| Curve Shape | Meaning | Action |
|-------------|---------|--------|
| **Steep positive slope** | High causal impact — speeding up this line speeds up the program proportionally | This is your optimization target. Focus effort here. |
| **Moderate positive slope** | Some causal impact — this line is partially on the critical path | Worth optimizing if the top targets are already fast |
| **Flat (near zero)** | No causal impact — this line is NOT on the critical path | Do NOT optimize. Time spent here is hidden by parallelism or is off the critical path. |
| **Negative slope** | Contention indicator — speeding up this line makes the program SLOWER | This line is involved in contention (lock, barrier, false sharing). Making it faster increases contention. Fix the contention pattern instead of optimizing the line. |
| **Noisy / inconsistent** | Insufficient data or non-deterministic behavior | Re-run with longer duration or scope to fewer files |

#### Interpreting Negative Slopes (Contention Detection)

Negative speedup curves are coz's unique contribution — no other profiler
reveals contention this directly. When speeding up line L makes the program
slower, it means:

1. L is inside a critical section or contention point
2. Making L faster means threads arrive at the contention point faster
3. The contention itself becomes the bottleneck
4. The fix is to reduce contention (finer-grained locks, lock-free data
   structures, batching), NOT to make L faster

**Real-world examples from SOSP 2015:**
- `fluidanimate`: Barrier wait showed negative slope — threads finishing faster
  just waited longer at the barrier. Fix: remove unnecessary barrier (37.5% speedup)
- `streamcluster`: Same barrier contention pattern (68.4% speedup after fix)
- `memcached`: Lock acquisition showed negative slope — unnecessary lock scope.
  Fix: reduce critical section (9% speedup)

#### Reading the Numbers

A speedup curve showing the line at `pipeline.rs:142` yields:

```
speedup=0.00  program_speedup=0.00   (baseline)
speedup=0.10  program_speedup=0.08   (10% line speedup -> 8% program speedup)
speedup=0.50  program_speedup=0.35   (50% line speedup -> 35% program speedup)
speedup=1.00  program_speedup=0.55   (100% line speedup -> 55% program speedup)
```

This means: if you could make line 142 infinitely fast (100% speedup), the
entire program would be 55% faster. That is an extremely high-impact line.

**Relationship to Amdahl's Law:** The maximum program speedup from optimizing
a line is bounded by the fraction of serial execution that line represents.
coz measures this empirically rather than requiring you to estimate it.

---

## Phase 5: Act on Findings

### Optimization Priority

Rank lines by the slope of their speedup curve at the origin (0% speedup point).
The steepest positive slopes are the highest-priority optimization targets.

### Workflow per Finding

1. **Identify the line** in the source code. Note: due to compiler optimizations,
   the attributed line may be slightly off — check the surrounding context.
   (Known issue: Rust optimized builds can shift line attribution. See Risk R4.)

2. **Understand why the line is on the critical path.** Is it:
   - Compute-bound? Use `/asm-forge` to optimize the generated code
   - Memory-bound? Use `/perf-topdown` to classify and fix cache behavior
   - Contention-bound (negative slope)? Restructure synchronization

3. **Apply the fix.** Make one change at a time.

4. **Re-run causal profiling.** The speedup curve for the fixed line should
   flatten (the line is no longer a bottleneck). Other lines may now show
   steeper slopes — the critical path shifted.

5. **Validate with Criterion.** Causal profiling predicts the *relative* impact.
   Confirm the *absolute* improvement with a proper benchmark:

   ```bash
   # Baseline
   cargo bench --bench <relevant> -- --save-baseline before-fix
   # After fix
   cargo bench --bench <relevant> -- --baseline before-fix
   ```

### When the Critical Path Shifts

After optimizing the top bottleneck, re-profile. The previous #2 bottleneck
may now be #1, or an entirely different line may appear. This is expected —
optimization is iterative. Stop when:

- All remaining lines have flat or near-flat speedup curves
- The Criterion benchmark meets your performance target
- The only remaining lines with steep slopes are in external libraries

---

## Phase 6: Report

```markdown
## Causal Profile: [target / scenario]

### Environment
- Platform: Linux [version] (or Docker image)
- CPU: [model]
- Build: `cargo build --profile causal --features causal-profiling`
- Progress point: [throughput/latency] at [location]
- Scope: [which source files were included]
- Runs: [N] merged profiles

### Top Optimization Targets

| Rank | File:Line | Slope at Origin | Max Program Speedup | Category |
|------|-----------|-----------------|---------------------|----------|
| 1 | pipeline.rs:142 | 0.70 | 55% | Compute-bound |
| 2 | matcher.rs:89 | 0.35 | 22% | Memory-bound |
| 3 | lock.rs:201 | -0.15 | N/A (contention) | Contention |

### Contention Findings

[Lines with negative slopes, explanation of contention pattern, recommended fix]

### Flat Lines (Not Worth Optimizing)

[Lines that traditional profiling flagged as hot but causal profiling shows
are NOT on the critical path. This is the key insight — effort saved.]

### Actions Taken

| # | Target Line | Fix Applied | Speedup Curve Change | Criterion Delta |
|---|-------------|-------------|----------------------|-----------------|
| 1 | pipeline.rs:142 | [description] | Slope 0.70 -> 0.10 | -18% latency |

### Remaining Opportunities

[Lines still showing positive slopes after fixes applied]
```

---

## Risk Mitigation

### R1: Sigaltstack Crash (CRITICAL)

**Symptom:** Segfault or "sigaltstack failed" immediately on coz run.

**Cause:** A thread executed a coz macro without calling `coz::thread_init!()`.
coz installs a SIGPROF handler that requires per-thread signal stack setup.

**Fix:** Ensure every spawned thread calls `coz::thread_init!()`. For thread
pools (rayon, crossbeam), install the init call in the pool's thread builder:

```rust
// Rayon
rayon::ThreadPoolBuilder::new()
    .start_handler(|_| {
        #[cfg(feature = "causal-profiling")]
        coz::thread_init!();
    })
    .build_global()
    .unwrap();

// std::thread::Builder
std::thread::Builder::new()
    .name("worker".into())
    .spawn(|| {
        #[cfg(feature = "causal-profiling")]
        coz::thread_init!();
        // ... work ...
    })?;
```

### R2: "0 Experiments" from crates.io v0.1.3 Bug (CRITICAL)

**Symptom:** coz runs to completion but `profile.coz` contains zero experiment
lines. The profiler attached but never collected data.

**Cause:** Published crate v0.1.3 is missing `_coz_add_delays()` in the
generated delay injection. Without delays, coz cannot create virtual speedups.

**Fix:** Use git master:
```toml
coz = { git = "https://github.com/plasma-umass/coz.git", optional = true }
```

### R3: Empty Profile from Missing Debug Info (HIGH)

**Symptom:** `profile.coz` is empty or has experiments with `selected-samples=0`.

**Cause:** Binary was built without debug info. coz cannot map instruction
addresses to source lines.

**Fix:** Verify debug info:
```bash
readelf -S ./target/causal/<binary> | grep debug_line
```
If missing, ensure `[profile.causal]` has `debug = 1` (or `debug = 2`).

### R4: Wrong Line Attribution in Optimized Rust (MEDIUM)

**Symptom:** Speedup curves point to lines that don't make semantic sense
(e.g., a closing brace, a `let` binding with no computation).

**Cause:** LLVM optimizations (inlining, loop unrolling, instruction
reordering) can shift debug line attribution. This is a known issue
(coz GitHub issue #197, unresolved).

**Mitigation:**
- Use `debug = 2` instead of `debug = 1` for richer debug info
- Interpret results at the function/block level, not individual lines
- Cross-reference with the surrounding code context
- Use `-f` flag to test a specific line hypothesis when attribution is suspect

### R5: Misleading Results on Async/Tokio Paths (HIGH)

**Symptom:** Speedup curves are flat for code you know is a bottleneck, or
curves make no sense.

**Cause:** coz operates on OS threads. Tokio's M:N scheduler multiplexes
many tasks onto few threads. Delaying a thread delays all tasks on it, not
just the one at the profiled line.

**Fix:** Do not use coz on async code paths. For async bottleneck analysis:
- Use `tokio-console` for task-level analysis
- Use `/linux-perf-profile` for thread-level PMU analysis
- Use `/perf-topdown` for microarchitectural classification
- If possible, extract the hot synchronous inner loop and profile that in
  isolation with coz

### R6: jemalloc Deadlock (MEDIUM)

**Symptom:** Process hangs under coz, especially on multi-threaded allocation.

**Cause:** coz's `nanosleep()` delays can interact poorly with jemalloc's
internal locking when a delay fires inside an allocation path.

**Fix:** Use the system allocator for causal profiling runs:
```rust
#[cfg(feature = "causal-profiling")]
#[global_allocator]
static ALLOC: std::alloc::System = std::alloc::System;
```

Or simply don't set jemalloc as the global allocator when the
`causal-profiling` feature is enabled.

### R7: Docker CAP Requirements

**Symptom:** `coz run` fails with permission errors about `perf_event_open`.

**Fix:** Run with `--cap-add CAP_PERFMON --cap-add SYS_PTRACE` (kernel 5.8+)
or `--cap-add SYS_ADMIN --cap-add SYS_PTRACE` (older kernels).

---

## Production Case Studies (SOSP 2015)

These results demonstrate causal profiling's ability to find non-obvious
bottlenecks that traditional profiling misses:

| Application | Speedup Achieved | Lines Changed | Key Finding |
|-------------|------------------|---------------|-------------|
| SQLite | 25.6% | <10 | A function consuming 0.15% of runtime was the true bottleneck — it serialized journal writes |
| Memcached | 9% | <10 | Unnecessary lock scope — reducing critical section removed contention |
| fluidanimate | 37.5% | <10 | Barrier contention (detected via negative speedup curve) — removed unnecessary synchronization |
| streamcluster | 68.4% | <10 | Same barrier contention pattern |
| ferret | 21.3% | <10 | Pipeline stage imbalance — one stage was the throughput bottleneck |
| dedup | 7.2% | <10 | Hidden serialization in hash computation |

Key takeaway: In every case, the bottleneck was a small number of lines, and
traditional profiling would have directed effort to the wrong places.

---

## How coz Works (Implementation)

Understanding the mechanism helps interpret unusual results.

1. **Sampling**: coz uses `perf_event_open()` to deliver SIGPROF at ~1ms
   intervals to all threads. Each sample captures the current instruction
   pointer.

2. **Experiment selection**: For each experiment, coz randomly selects one
   source line and one virtual speedup level (0%, 5%, 10%, ..., 100%).
   The 0% level is chosen 50% of the time to build a strong baseline.

3. **Virtual speedup**: When a thread is sampled at the selected line, coz
   records it. To simulate speeding up that line by X%, coz inserts
   `nanosleep()` delays into all *other* threads proportional to the time
   the selected line would have saved.

4. **Delay formula**: `effective_reduction = delay / sampling_period`.
   With a 1ms sampling period and 5% speedup selected, each sample at the
   target line causes ~50us of delay in other threads.

5. **Progress measurement**: coz measures the progress point's rate (throughput)
   or span (latency) during each experiment and compares to baseline.

6. **Batching**: Experiments are batched every ~10ms. Global and per-thread
   delay counters track accumulated virtual time adjustments.

7. **Output**: The speedup curve is the aggregate of many experiments at
   different speedup levels for each line.

---

## Comparison with Alternative Approaches

### When to Use Which Tool

| Question | Tool | Skill |
|----------|------|-------|
| Where is time spent? | `perf record` + flamegraph | `/linux-perf-profile` |
| WHY is it slow? (uarch) | `perf stat --topdown` | `/perf-topdown` |
| WHAT should I optimize? | `coz` | `/causal-profile` (this skill) |
| How does the ASM look? | `cargo-show-asm` | `/asm-forge` |
| Did my fix work? (benchmark) | `cargo bench` (Criterion) | `/bench-compare` |
| Can I optimize the binary layout? | PGO + BOLT | `/pgo-bolt` |

### Typical Workflow Chain

```
1. /linux-perf-profile  (flamegraph: where is time spent?)
          |
2. /causal-profile      (which hot spots are worth optimizing?)
          |
3. /perf-topdown        (why is the target line slow? uarch classification)
          |
4. /asm-forge           (what codegen issue? apply source-level fix)
          |
5. /bench-compare       (did the fix actually help? measure absolute impact)
```

Flamegraph first for orientation, causal profiling second for prioritization,
microarchitectural analysis third for diagnosis, assembly audit fourth for
the fix.

### Academic Successors

For awareness — these are research tools, not production-ready:

- **BCOZ** (OSDI 2024): Extends causal profiling to off-CPU time (blocked on
  I/O, locks, page faults). Useful when the bottleneck is not CPU-bound.
- **SCOZ** (SPE 2021): System-wide causal profiling including kernel code.
  Useful for syscall-heavy workloads.
- **VCoz** (SIGMETRICS 2020): Virtual machine-based causal profiling that
  works across architectures without hardware PMU support.
- **Slowpoke** (NSDI 2026): Distributed causal profiling for microservices.
  Applies virtual speedups across service boundaries.

---

## References

### Academic Papers

1. Curtsinger & Berger, "Coz: Finding Code that Counts with Causal Profiling,"
   SOSP 2015. https://dl.acm.org/doi/abs/10.1145/2815400.2815409
2. CACM Research Highlight (accessible version):
   https://cacm.acm.org/magazines/2018/6/228044-coz/fulltext
3. USENIX ;login: article:
   https://www.usenix.org/publications/login/summer2016/curtsinger

### Tools

- coz repository: https://github.com/plasma-umass/coz
- coz Rust crate (docs): https://docs.rs/coz/latest/coz/
- Emery Berger "Performance Matters" talk (Strange Loop 2019) — excellent
  intuition-builder for why traditional profiling misleads

### Related Tools Documentation

- Rust Performance Book profiling chapter:
  https://nnethercote.github.io/perf-book/profiling.html

---

## Related Skills

- `/linux-perf-profile` — Flamegraph + PMU counter analysis (use first to identify hot functions, then use this skill to determine which are worth optimizing)
- `/perf-topdown` — Microarchitectural classification (use after this skill identifies the target line, to understand WHY it is slow)
- `/asm-forge` — Assembly-level codegen optimization (use after perf-topdown diagnoses the issue, to apply the fix)
- `/bench-compare` — Criterion before/after measurement (use to validate that the fix produced real improvement)
- `/pgo-bolt` — Binary layout optimization (use after exhausting source-level gains)
- `/perf-regression` — Full regression testing workflow (use before merging optimized code)
