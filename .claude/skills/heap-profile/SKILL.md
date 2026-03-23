---
name: heap-profile
description: Use when AllocGuard trips and you need the call site, when /performance-analyzer flags allocations but you need attribution, when verifying HOT-tier allocation silence, or when /bench-compare shows regression and you suspect allocation overhead. Heap allocation profiling with DHAT.
---

# Heap Profile — Allocation Attribution and Verification

**Philosophy: CountingAllocator tells you *how many*. DHAT tells you *where*.**

Attribute heap allocations to specific call sites, verify hot-path allocation
silence, and catch allocation regressions with programmatic assertions. Uses
the `dhat` crate in two complementary modes that coexist with the project's
existing `CountingAllocator` and `AllocGuard`.

## When to Use

- `/performance-analyzer` flagged allocations in a hot loop but you need the exact call site
- `AllocGuard` tripped and you need to identify which line allocated
- Verifying a new code path is allocation-silent on HOT-tier paths
- Investigating whether pool infrastructure (ByteSlab, InlineVec, PooledShardSpec)
  is being bypassed with direct heap allocation
- After `/bench-compare` shows a timing regression and you suspect allocation overhead
- Before marking a HOT-path change as complete (tiered allocation policy compliance)
- After `/linux-perf-profile` shows high dTLB walks or backend memory stalls

## When NOT to Use

- For timing measurements -- use `/bench-compare`
- For CPU cycle attribution -- use `/linux-perf-profile`
- For aggregate allocation counts without call sites -- use `AllocGuard` / `CountingAllocator`
- For production profiling -- use jemalloc sampling (DHAT is dev/test only)
- For codegen quality -- use `/asm-forge`

## Prerequisites

### Cargo.toml Changes (Per-Crate, Feature-Gated)

Add `dhat` as an optional dependency behind a feature flag in the crate under
investigation:

```toml
[features]
dhat-heap = ["dep:dhat"]

[dependencies]
dhat = { version = "0.3", optional = true }
```

Convention: use `dhat-heap` as the feature name across all workspace crates.
This matches existing conventions (`perf-stats`, `sim-harness`, `test-support`).

### Cargo Profile (Workspace-Level, One-Time)

Add to workspace `Cargo.toml`:

```toml
[profile.dhat]
inherits = "release"
opt-level = 2
debug = 1          # Line-level debug info for backtrace resolution
lto = false        # LTO inlines away call sites DHAT needs
strip = "none"     # Preserve symbols for viewer
```

**Why this matters**: Without `debug = 1` the viewer shows raw addresses
instead of source locations. With `lto = true` or `strip != "none"`, output
is corrupted or useless. `opt-level = 2` preserves function boundaries while
still running optimized code.

Build with: `cargo build --profile dhat --features dhat-heap`

## Two-Mode Architecture

DHAT has two modes that serve different purposes. Use both.

### Mode 1: Heap Mode (Full Attribution — Isolated Binary)

Replaces the global allocator with `dhat::Alloc`. Captures a backtrace on
every allocation, tracks sizes, lifetimes, and peak usage. Writes a JSON
profile for the DHAT viewer.

**Constraint**: `dhat::Alloc` and `CountingAllocator` cannot coexist -- Rust
permits exactly one `#[global_allocator]` per binary. Heap mode MUST run in a
separate integration test file (each compiles to its own binary).

**Use for**: Investigation -- finding where allocations come from, understanding
allocation lifetimes, identifying churn.

### Mode 2: Ad-Hoc Mode (Targeted — Coexists with CountingAllocator)

Does NOT require `dhat::Alloc`. Instead, you call `dhat::ad_hoc_event(weight)`
at instrumentation points. This can run alongside `CountingAllocator` in the
same binary.

**Use for**: Targeted instrumentation of specific code paths, measuring pool
utilization, tracking custom events at known hot-path boundaries.

### Mode 3: Testing Mode (CI Assertions)

Adds programmatic access to `HeapStats` for assertion-based budget enforcement.
Uses heap mode's allocator (needs isolated test file).

**Use for**: CI-gated allocation budgets on HOT-tier paths.

## Workflow

### Investigation Workflow (Finding Unknown Allocations)

Use when you know allocations exist but not where.

```
1. Identify target (AllocGuard trip, bench regression, /performance-analyzer finding)
      |
2. Create integration test file with dhat::Alloc (heap mode, see template below)
      |
3. Build and run:
      cargo test -p <crate> --profile dhat --features dhat-heap \
          --test <test_file_name> -- --test-threads=1
      |
4. Open dhat-heap.json in DHAT viewer:
      https://nnethercote.github.io/dh_view/dh_view.html
      |
5. Sort by "Total blocks" to find high-frequency allocators
   Sort by "Total bytes" to find high-volume allocators
      |
6. Correlate with source (viewer shows file:line for each site)
      |
7. Fix: replace with pool (ByteSlab, InlineVec) or restructure to avoid
      |
8. Re-run to verify the fix eliminated the allocation
```

### Verification Workflow (Confirming Allocation Silence)

Use when you need to prove a HOT-tier path is allocation-free.

```
1. Create testing-mode integration test with HeapStats assertions
      |
2. Build and run:
      cargo test -p <crate> --profile dhat --features dhat-heap \
          --test <test_file_name> -- --test-threads=1
      |
3. If assertions pass: path meets its allocation tier requirements
   If assertions fail: dhat::assert! saves profile JSON for diagnosis
      |
4. Open saved profile in viewer to find the violating call site
```

### Regression Gating Workflow (CI)

```
1. Add testing-mode test with HeapStats budget assertions (see template)
      |
2. CI command:
      cargo test -p <crate> --features dhat-heap \
          --test <test_file_name> -- --test-threads=1
      |
3. Change introduces allocations -> dhat::assert! fails -> investigate
```

## Templates

### Heap Mode — Full Attribution

File: `crates/<crate>/tests/dhat_<target>_profile.rs`

```rust
//! Heap allocation profiling for <description>.
//!
//! Installs dhat::Alloc as the global allocator. This conflicts with
//! CountingAllocator, so this must be a separate integration test file.

#[cfg(feature = "dhat-heap")]
mod dhat_profile {
    #[global_allocator]
    static ALLOC: dhat::Alloc = dhat::Alloc;

    #[test]
    fn profile_target_allocations() {
        let _profiler = dhat::Profiler::new_heap();

        // --- Exercise the code path under investigation ---
        // Keep the workload representative but bounded.
        // Example:
        //   let mut engine = Engine::new(test_config());
        //   for item in test_workload(1000) {
        //       engine.process(item);
        //   }

        // Profiler drops here, writes dhat-heap.json to cwd.
        // Open in: https://nnethercote.github.io/dh_view/dh_view.html
    }
}
```

### Testing Mode — Allocation Budget Assertions

File: `crates/<crate>/tests/dhat_<target>_budget.rs`

```rust
//! Allocation budget enforcement for <HOT-tier path>.
//!
//! Asserts that the target path stays within its allocation budget.
//! On failure, saves dhat-heap.json for post-mortem analysis.

#[cfg(feature = "dhat-heap")]
mod dhat_budget {
    #[global_allocator]
    static ALLOC: dhat::Alloc = dhat::Alloc;

    #[test]
    fn allocation_budget() {
        let _profiler = dhat::Profiler::builder().testing().build();

        // --- Exercise the HOT path (after any setup) ---
        // Capture stats AFTER setup but BEFORE teardown if setup allocates.

        let stats = dhat::HeapStats::get();

        // HOT tier: allocation-silent
        dhat::assert!(stats.total_blocks == 0,
            "path allocated {} blocks (expected 0 for HOT tier)",
            stats.total_blocks);

        // Or WARM tier with budget:
        // dhat::assert!(stats.total_blocks <= 100,
        //     "path allocated {} blocks (budget: 100)", stats.total_blocks);
        // dhat::assert!(stats.max_bytes <= 64 * 1024,
        //     "peak {} bytes exceeded 64 KiB budget", stats.max_bytes);
    }
}
```

### Ad-Hoc Mode — Coexists with CountingAllocator

Can go in any test file (does NOT require `dhat::Alloc`):

```rust
#[cfg(feature = "dhat-heap")]
#[test]
fn adhoc_profile_pipeline() {
    // CountingAllocator remains as global allocator if already installed.
    let _profiler = dhat::Profiler::builder().ad_hoc().build();

    for batch in workload.chunks(BATCH_SIZE) {
        process_batch(batch);

        // Instrument specific points of interest:
        #[cfg(feature = "dhat-heap")]
        dhat::ad_hoc_event(batch.len());
    }

    // Writes dhat-ad-hoc.json with call-site attribution.
    // CountingAllocator tracks totals separately.
}
```

## HeapStats Fields

| Field | Type | Meaning |
|-------|------|---------|
| `total_blocks` | `u64` | Cumulative number of allocations |
| `total_bytes` | `u64` | Cumulative bytes allocated |
| `curr_blocks` | `usize` | Currently live allocations |
| `curr_bytes` | `usize` | Currently live bytes |
| `max_blocks` | `usize` | Peak simultaneous live allocations |
| `max_bytes` | `usize` | Peak simultaneous live bytes |

Use `dhat::assert!` / `dhat::assert_eq!` / `dhat::assert_ne!` instead of
`std::assert!` -- on failure they save the profile JSON for post-mortem.

## DHAT Viewer Sorting Strategies

Open `dhat-heap.json` at https://nnethercote.github.io/dh_view/dh_view.html
(runs entirely in-browser, no data leaves your machine).

| Sort Column | Reveals |
|-------------|---------|
| Total bytes | Biggest allocation sources (optimization targets) |
| Total blocks | High-frequency allocators (hot-path violations) |
| At t-end bytes | Potential leaks (should be ~0 for request-scoped work) |
| Max bytes | Peak memory pressure sources |
| Avg block size | Small-object churn (InlineVec / stack-alloc candidates) |
| Avg lifetime | Short = transient churn, long = possible leak |

Alternative visualization: `cargo install dhat-to-flamegraph` then
`dhat-to-flamegraph dhat-heap.json > alloc-flame.svg`.

## Pool Infrastructure Interaction

DHAT heap mode sees allocations at the system allocator level:

| Infrastructure | What DHAT Sees |
|----------------|----------------|
| `ByteSlab` pre-allocation | Large upfront allocation (expected) |
| `InlineVec` stack-resident | Nothing (no heap allocation) |
| `InlineVec` spill-to-heap | The spill allocation (this is what you want to catch) |
| `PooledShardSpec` slab-backed | Initial slab allocation, not individual slot usage |
| `RingBuffer` fixed-capacity | Single allocation at construction |
| `AcquireScratch` / `FixedBuf` | Single allocation at construction |

This is ideal for tier enforcement: DHAT catches exactly the allocations that
violate HOT-tier requirements (direct heap allocs bypassing the pool layer).

## Output Format

```markdown
## Heap Profile: [target / scenario]

### Environment
- Mode: [Heap / Ad-hoc / Testing]
- Profile: `cargo test --profile dhat --features dhat-heap`
- Target: [crate and code path]

### Allocation Summary

| Metric | Value |
|--------|-------|
| Total allocations | X,XXX blocks |
| Total bytes | X.X MB |
| Peak live blocks | XXX |
| Peak live bytes | X.X KB |
| At-end live bytes | X bytes |

### Top Allocation Sites

| Rank | Call Site | Total Blocks | Total Bytes | Avg Size | Tier | Status |
|------|-----------|-------------|-------------|----------|------|--------|
| 1 | module::func (file:line) | X,XXX | X.X MB | XXX B | HOT | VIOLATION |
| 2 | module::func (file:line) | XXX | XX KB | XX B | WARM | Acceptable |

### Tier Compliance

| Path | Tier | Budget | Actual | Status |
|------|------|--------|--------|--------|
| acquire_and_restore_into | HOT | 0 allocs | 0 allocs | PASS |
| checkpoint | HOT | 0 allocs | 3 allocs | FAIL |
| list_shards | WARM | <100 | 42 allocs | PASS |

### Recommendations

1. [Call site] at `file:line` -- [specific fix]
   - Current: X allocs / Y bytes per invocation
   - Fix: use InlineVec / ByteSlab / pre-allocated buffer
   - Tier: HOT -- must be allocation-silent
```

## Caveats

### macOS Apple Silicon Instability

The `dhat` crate has known open issues on macOS AArch64:

- **TLS recursion** (GitHub #31): `dhat::Alloc` may recurse through thread-local
  storage on first access. Mitigate by initializing the profiler before spawning
  any threads.
- **Tokio assertion failures** (GitHub #23): ~40% failure rate in async tests
  on macOS ARM. Avoid heap mode in Tokio async contexts. Use ad-hoc mode instead.
- **backtrace-rs deadlock** (GitHub #38): Multi-threaded programs may deadlock
  during backtrace capture. Always run DHAT tests single-threaded:
  `-- --test-threads=1`

**Before first use**: Run the smoke test at the bottom of this document. If it
hangs or crashes, do not use heap mode on this platform. Ad-hoc mode is
unaffected.

### Singleton Constraint

Only one `dhat::Profiler` can exist per process. If a second is created, the
process panics. Each heap-mode test must be in its own integration test file
(each file compiles to a separate binary).

### Observer Effect

DHAT's backtrace capture adds overhead. Allocation *counts and sizes* are
accurate, but *timing* is not. Never draw timing conclusions from a DHAT run.
Use `/bench-compare` for timing.

### Compiler Optimization

In release builds, the compiler may optimize away allocations that are unused.
A test passing with 0 allocations in release may show allocations in debug.
Always run DHAT tests with the `dhat` profile (opt-level 2) for consistent
results. Use `std::hint::black_box()` to prevent elimination of test data.

### Crate Status

The `dhat` crate is explicitly experimental with minimal maintenance. Pin to
`0.3.x`. Keep usage behind the `dhat-heap` feature flag so it can be removed
without code changes if a successor emerges.

## Smoke Test

Run before first use on a new platform:

```bash
cd /tmp && cargo init --name dhat-smoke && cd dhat-smoke
echo 'dhat = "0.3"' >> Cargo.toml
cat > src/main.rs << 'EOF'
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    let _profiler = dhat::Profiler::new_heap();
    let v: Vec<u8> = vec![0u8; 1024];
    std::hint::black_box(&v);
    drop(v);
}
EOF
cargo run --release
# Should print allocation summary and create dhat-heap.json.
# If it hangs or crashes: do not use heap mode on this platform.
```

## Integration with Existing Skills

### Escalation Path

```
/performance-analyzer  -->  "allocations in hot loop"
        |
/heap-profile          -->  "call site X allocated Y bytes"
        |
/asm-forge             -->  "bounds check at line Z caused Vec growth"
        |
/bench-compare         -->  "fix reduced latency by 15%"
```

### Handoff Points

| From Skill | Signal | Action |
|------------|--------|--------|
| `/performance-analyzer` | "Unnecessary allocations in loops" | Use heap mode to identify exact call sites |
| `/bench-compare` | Timing regression, allocation suspected | Use heap mode to attribute allocations |
| `/perf-regression` | Regression on HOT-tier code | Use testing mode to set allocation budget |
| `/linux-perf-profile` | High dTLB walks or backend memory stalls | Use heap mode to find scattered allocations |

| To Skill | Signal | Action |
|----------|--------|--------|
| `/asm-forge` | DHAT shows allocation from bounds check or Vec growth | Inspect codegen to eliminate bounds check |
| `/bench-compare` | After fixing allocations found by DHAT | Measure timing improvement |
| `/performance-analyzer` | DHAT found pool bypass | Review for other similar patterns |

## Related Skills

- `/performance-analyzer` -- Static hotspot analysis (identifies allocation patterns to investigate)
- `/bench-compare` -- Timing measurement (use after fixing allocations found by DHAT)
- `/perf-regression` -- Full regression workflow (DHAT provides the allocation-specific gate)
- `/linux-perf-profile` -- Hardware counter analysis (correlate dTLB/cache data with allocation sites)
- `/asm-forge` -- Assembly analysis (inspect codegen that causes unexpected allocations)
- `/pgo-bolt` -- Binary layout optimization (after exhausting allocation and codegen improvements)
