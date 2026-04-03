---
name: perf-pipeline
description: Use when /bench-compare or /perf-regression identifies a regression needing root cause, when multiple performance dimensions need simultaneous triage, or when optimization work should be dispatched automatically. Two-phase diagnose-then-optimize pipeline.
user-invocable: true
---

# Performance Pipeline

Two-phase performance team: triage from multiple angles in parallel, then
dispatch the right specialist skill for each finding.

## When to Use

- After writing or modifying hot-path code
- When benchmarks show unexpected regressions
- Before merging performance-sensitive changes
- When you need deeper analysis than a single `/performance-analyzer` pass
- For systematic optimization of a module or subsystem

## Invocation

```
/perf-pipeline [<target>]
```

- No argument: analyze recently changed files in the working tree
- File path or glob: analyze specific files or modules
- `--bench <name>`: start from Criterion benchmark results
- `--crate <name>`: analyze an entire crate's hot paths

## Phase 1: Parallel Triage

Launch **three diagnostic agents in parallel** using the Agent tool. Each
agent approaches performance diagnosis from a different angle.

### Agent A — Benchmark Triage

Analyze Criterion benchmark data for regressions, outliers, and trends.

**Agent prompt template:**
```
You are a Rust performance analyst specializing in benchmark interpretation.
Analyze the target code and any available Criterion benchmark results.

Look for:
- Statistical regressions (>5% median change)
- High variance indicating measurement instability
- Outlier samples suggesting GC pressure or system noise
- Benchmark gaps (hot code paths with no benchmarks)
- Comparison opportunities (before/after data available)

For each finding, report:
- Category: benchmark-regression | benchmark-gap | measurement-instability
- Location: file:line or benchmark name
- Evidence: numbers, percentages, statistical significance
- Impact estimate: how much latency/throughput is affected
- Recommended next step: which tool or skill to use

Target: {target_description}

Run `cargo bench --bench <relevant> -- --list` to discover available benchmarks.
Run benchmarks if needed to gather data.
```

### Agent B — Static Analysis

Analyze code patterns for performance anti-patterns without running anything.

**Agent prompt template:**
```
You are a Rust performance analyst specializing in static code analysis for
performance issues. Analyze the target code for anti-patterns.

Check for:

Memory & Allocation:
- Unnecessary allocations in loops (Vec, String, Box)
- Missing with_capacity() for known-size collections
- Cloning where borrowing would suffice
- Large structs passed by value

CPU & Cache:
- False sharing in concurrent data structures
- Cache-unfriendly access patterns (strided, random)
- Branch-heavy code amenable to branchless alternatives
- Missing #[inline] on small hot functions

Async & Concurrency:
- Blocking operations in async contexts
- Lock contention patterns
- Oversized futures
- Unnecessary Arc when ownership would work

Project-specific patterns:
- NONE_U32 = u32::MAX sentinels (avoid Option overhead)
- Allocation tier violations (HOT paths must be allocation-silent)
- ByteSlab/InlineVec/RingBuffer usage opportunities

For each finding, report:
- Category: allocation-hotspot | cache-hostile | lock-contention |
  async-blocking | codegen-issue | vectorization-opportunity
- Location: file:line
- Evidence: the specific code pattern
- Severity: Critical (measurable impact) | High (likely impact) |
  Medium (potential impact) | Low (minor)
- Recommended fix: actionable change with code sketch

Target: {target_description}
```

### Agent C — Hotspot Detection

Pre-profiling heuristic scan for likely performance bottlenecks.

**Agent prompt template:**
```
You are a Rust performance analyst specializing in hotspot detection. Scan
the target code to find functions and code paths most likely to be performance
bottlenecks, without running profilers.

Heuristics:
- Loop nesting depth and iteration counts
- Allocation density (allocs per iteration)
- Call graph depth in hot paths
- Data structure choice vs access pattern mismatch
- Serialization/deserialization in request paths
- Redundant computation (same value computed multiple times)
- Missed opportunities for short-circuit evaluation

For each hotspot, report:
- Risk level: High | Medium | Low
- Location: file:line (function name)
- Why it's likely hot: evidence from code structure
- Impact estimate: order-of-magnitude guess
- Ease of fix: Easy | Medium | Hard
- Recommended Phase 2 skill:
  * /heap-profile — for allocation attribution
  * /simd-optimize — for vectorizable loops
  * /asm-forge — for codegen quality issues
  * /bench-compare — for before/after measurement
  * /perf-topdown — for CPU microarchitecture bottlenecks
  * /pgo-bolt — for binary layout optimization
  * /causal-profile — for critical-path ambiguity
  * /linux-perf-profile — for PMU counter evidence

Target: {target_description}
```

## Synthesis & Classification

After all three agents complete, merge and classify findings:

1. **Match by location**: Group findings referencing the same function or file:line
2. **Score convergence**: Findings from multiple agents get elevated priority
3. **Classify each finding** into one of these categories:

| Category | Phase 2 Skill | Description |
|----------|---------------|-------------|
| `allocation-hotspot` | `/heap-profile` | Excessive heap allocations in hot path |
| `vectorization-opportunity` | `/simd-optimize` | Loop pattern amenable to SIMD |
| `codegen-issue` | `/asm-forge` | Missed optimization visible in assembly |
| `benchmark-regression` | `/bench-compare` | Needs before/after measurement |
| `microarch-bottleneck` | `/perf-topdown` | Cache misses, branch misprediction |
| `pgo-candidate` | `/pgo-bolt` | Binary layout optimization opportunity |
| `critical-path-unclear` | `/causal-profile` | Hot function may not be on critical path |
| `needs-pmu-data` | `/linux-perf-profile` | Need hardware counter evidence |
| `general-optimization` | `/asm-forge` | Default: assembly-guided optimization |

4. **Tag Phase 2 type**: Mark each finding as:
   - **Diagnostic** (read-only): heap-profile, perf-topdown, linux-perf-profile, causal-profile
   - **Optimization** (read-write): asm-forge, simd-optimize, pgo-bolt
   - **Measurement** (read-only): bench-compare

## Human Gate

Present findings to the user:

```
## Perf Pipeline — Phase 1 Complete

Found {N} performance findings across {M} files.

### Findings (ranked by impact + convergence)

| #  | Risk | Location               | Issue                        | Category              | Phase 2 Skill    | Type        |
|----|------|------------------------|------------------------------|-----------------------|------------------|-------------|
| 1  | High | src/engine/core.rs:42  | Vec alloc in per-claim loop  | allocation-hotspot    | /heap-profile    | Diagnostic  |
| 2  | High | src/shard/split.rs:88  | Branchless opportunity       | codegen-issue         | /asm-forge       | Optimization|
| 3  | Med  | src/stdx/inline_vec.rs | Loop amenable to NEON SIMD   | vectorization-opp     | /simd-optimize   | Optimization|
| 4  | Med  | bench: acquire_restore | 12% regression vs baseline   | benchmark-regression  | /bench-compare   | Measurement |

Approve all? Enter numbers to select, or modify skill assignments:
```

The user can:
- Approve all: "all"
- Select specific findings: "1,2,3"
- Override skill assignment: "3 -> /asm-forge" (change recommended skill)
- Skip: "none"

## Phase 2: Targeted Execution

### Dispatch Order

1. **Diagnostic findings first** (read-only) — these produce deeper data that
   may inform optimization decisions
2. **Present diagnostic results** — brief summary of what profiling found
3. **Optimization findings** (read-write) — these modify code, dispatched with
   file ownership boundaries
4. **Measurement findings** (read-only) — run after optimizations to validate

### Agent Dispatch

For each approved finding, launch an Agent whose prompt embeds the relevant
skill's methodology:

```
You are a performance specialist applying {skill_name} methodology.

Finding to address:
- Category: {category}
- Location: {file:line}
- Issue: {description}
- Evidence from triage: {evidence}

{Skill-specific methodology and checklist inlined here}

Files you own (only modify these): {file list}

After any code changes, run:
  cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings
```

### Parallel vs Sequential

- Diagnostic agents (read-only) → all **in parallel**
- Optimization agents on non-overlapping files → **in parallel**
- Optimization agents on overlapping files → **sequential**
- Measurement agents → **after** optimizations complete

### Feedback Loop

If diagnostic Phase 2 agents (heap-profile, perf-topdown, etc.) produce findings
that change the optimization picture, present an **intermediate gate**:

```
## Perf Pipeline — Diagnostic Phase 2 Complete

/heap-profile found: Top allocator is `ShardMap::resize` at 4.2MB/s
/perf-topdown found: 38% of cycles are backend-bound (L3 cache misses)

Updated recommendations:
| # | Location | Original Skill | Updated Skill | Reason |
|---|----------|---------------|---------------|--------|
| 2 | split.rs:88 | /asm-forge | /simd-optimize | Cache-line alignment more impactful |

Proceed with updated plan? Or modify:
```

## Completion

```
## Perf Pipeline — Complete

### Results

| Finding | Phase 2 Skill | Status    | Result                              |
|---------|---------------|-----------|-------------------------------------|
| #1      | /heap-profile | Diagnosed | ShardMap::resize is top allocator   |
| #2      | /asm-forge    | Optimized | Eliminated branch in split loop     |
| #3      | /simd-optimize| Optimized | NEON vectorized InlineVec scan      |
| #4      | /bench-compare| Measured  | 8% improvement vs baseline          |

### Verification

Run to confirm:
  cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings
  cargo bench --bench <relevant>
```

## Error Handling

- If a Phase 1 agent fails, proceed with the other agents' findings
- If a Phase 2 optimization makes cargo check fail, revert and report
- If bench-compare shows regression after optimization, flag for user review

## Related Skills

- `/rust-perf-triage` — Phase 1 methodology (benchmark data)
- `/performance-analyzer` — Phase 1 methodology (static analysis)
- `/rust-hotspot-finder` — Phase 1 methodology (hotspot heuristics)
- `/heap-profile` `/simd-optimize` `/asm-forge` `/bench-compare` `/perf-topdown` `/pgo-bolt` `/causal-profile` `/linux-perf-profile` — Phase 2 specialists
- `/review-pipeline` — Code quality team pipeline
- `/test-pipeline` — Testing team pipeline
