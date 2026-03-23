# Speedup Curve Interpretation & Risk Mitigation

## Speedup Curve Shapes — Complete Reference

### Shape 1: Steep Positive Slope

```
Program   ^
Speedup   |         ____----
(%)       |    ____/
          |___/
          +-------------------->
          0%    50%    100%
          Virtual Speedup of Line L
```

**Meaning:** Line L is on the critical path. Speeding it up directly speeds
up the program. The slope indicates how much of the critical path this line
represents.

**Interpretation:**
- Slope near 1.0 at origin: L dominates the critical path. Near-linear
  program speedup from optimizing L.
- Slope 0.3-0.7: L is a significant contributor but not the only one.
  Optimizing L will help but won't eliminate the bottleneck entirely.
- The curve flattens as virtual speedup increases because other lines
  become the new bottleneck (Amdahl's Law).

**Action:** This is your primary optimization target. Use `/perf-topdown` to
classify WHY this line is slow, then `/asm-forge` to fix the codegen.

### Shape 2: Flat (Near Zero Slope)

```
Program   ^
Speedup   |
(%)       |
          |________________________
          +-------------------->
          0%    50%    100%
          Virtual Speedup of Line L
```

**Meaning:** Line L is NOT on the critical path. No matter how fast you make
it, the program does not speed up. The work done at L is either:
- Hidden by parallelism (another thread is doing the real work)
- Off the critical path (downstream of L is not the bottleneck)
- Dominated by other serialized work elsewhere

**Interpretation:** This is the most important finding causal profiling
provides. Traditional profiling may show L consuming significant CPU time,
leading you to waste effort optimizing it. Causal profiling proves it does
not matter.

**Action:** Do NOT optimize this line. Look elsewhere. If a traditional
profiler flagged this as hot, the bottleneck is elsewhere in the dependency
chain.

### Shape 3: Negative Slope (Contention)

```
Program   ^
Speedup   |
(%)       |_______
          |       \____
          |            \____
          +-------------------->
          0%    50%    100%
          Virtual Speedup of Line L
```

**Meaning:** Speeding up line L makes the program SLOWER. This uniquely
indicates contention:

1. L is inside or near a contention point (lock acquisition, barrier,
   atomic CAS loop, false sharing)
2. Making L faster means threads arrive at the contention point sooner
3. Threads spend more time waiting on each other
4. Net effect: more contention overhead than time saved

**This finding is invisible to traditional profilers.** A sampling profiler
shows L as a normal hot function. Only causal profiling reveals the
contention dynamic.

**Action:** Do NOT make L faster. Instead:
- Reduce lock granularity (fine-grained locking, per-shard locks)
- Replace locks with lock-free data structures
- Remove unnecessary synchronization barriers
- Fix false sharing (pad struct fields to cache-line boundaries)
- Batch work to reduce synchronization frequency

### Shape 4: Step Function

```
Program   ^
Speedup   |
(%)       |         ___________
          |        |
          |________|
          +-------------------->
          0%    50%    100%
          Virtual Speedup of Line L
```

**Meaning:** L must be sped up past a threshold to have any effect. Below
the threshold, another line dominates. Above it, L was the bottleneck all
along but was masked by the other line.

**Action:** If the threshold is achievable (e.g., 20% speedup needed, and
you can realistically optimize L by 30%), it is worth pursuing. If the
threshold is unrealistically high, treat as flat.

### Shape 5: Noisy / Inconsistent

```
Program   ^
Speedup   |   *    *
(%)       | *   *    *
          |  * *   *  *
          +-------------------->
          0%    50%    100%
          Virtual Speedup of Line L
```

**Meaning:** Insufficient data or non-deterministic behavior. Common causes:
- Too few experiments at this line (short runtime)
- Non-deterministic workload (random inputs, timing-dependent branches)
- Line executed too infrequently for statistical significance
- External interference (other processes, I/O variability)

**Action:** Re-run with:
- Longer total runtime (2+ minutes)
- Scoped profiling (`-s` flag) to focus experiments on this file
- Fixed line (`-f` flag) to force all experiments on this line
- More deterministic workload (fixed seed, pre-generated inputs)

---

## Statistical Significance

coz requires multiple experiments at each (line, speedup_level) pair to
produce reliable curves. Rules of thumb:

| Criterion | Minimum | Recommended |
|-----------|---------|-------------|
| Experiments per line | 5 | 20+ |
| Experiments per speedup level | 3 | 10+ |
| Total experiments | 50 | 500+ |
| Runtime | 30 seconds | 2-5 minutes |
| Progress point visits per experiment | 5 | 50+ |

If you see fewer than 5 experiments for a line, do not trust the curve.
Re-run with `-s` or `-f` flags to concentrate experiments.

---

## Risk Mitigation Checklist

### Before Instrumenting

- [ ] Target code path is synchronous (no `.await`, no Tokio spawn)
- [ ] Target code path is on Linux (or Docker with CAP_PERFMON)
- [ ] Using coz crate from git master (NOT crates.io v0.1.3)
- [ ] Feature gate: `causal-profiling = ["dep:coz"]` in Cargo.toml
- [ ] All macros behind `#[cfg(feature = "causal-profiling")]`

### Before Building

- [ ] `[profile.causal]` exists in workspace Cargo.toml with `debug = 1`
- [ ] Not using jemalloc as global allocator (or switched to system for profiling)
- [ ] Building with `cargo build --profile causal --features causal-profiling`

### Before Running

- [ ] `coz` binary is installed and in PATH
- [ ] Binary has `.debug_line` section (verified with readelf)
- [ ] Progress point is reachable (dry run without coz succeeds)
- [ ] `perf_event_paranoid <= 1` or running as root
- [ ] If Docker: `--cap-add CAP_PERFMON --cap-add SYS_PTRACE`
- [ ] No other SIGPROF-based profilers running simultaneously
- [ ] Workload runs for at least 30 seconds

### After Running

- [ ] Profile has > 0 experiments (check with parse script)
- [ ] At least 5 experiments per profiled line
- [ ] Progress point was visited (throughput-point or latency-point records exist)
- [ ] Results make physical sense (sanity-check against known bottlenecks)

### Interpreting Results

- [ ] Negative slopes interpreted as contention, not tool error
- [ ] Flat curves for "hot" functions accepted as valid (not on critical path)
- [ ] Line attribution cross-referenced with source context (may be off by a few lines)
- [ ] Findings validated with Criterion benchmark before and after fix

---

## Failure Mode Quick Reference

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Segfault on startup | Missing `thread_init!()` | Add to all spawned threads |
| 0 experiments | crates.io v0.1.3 bug | Use git master crate |
| Empty profile | Missing debug info | Add `debug = 1` to profile |
| Wrong line numbers | LLVM optimization shifts | Use `debug = 2`, interpret at block level |
| All curves flat | Async code path | Do not use coz on Tokio paths |
| Process hangs | jemalloc deadlock | Switch to system allocator |
| Permission denied | perf_event_paranoid | `echo 1 \| sudo tee /proc/sys/kernel/perf_event_paranoid` |
| Docker: permission denied | Missing capability | Add `--cap-add CAP_PERFMON` |
| Noisy results | Too short runtime | Run for 2+ minutes, use `-s` flag |
