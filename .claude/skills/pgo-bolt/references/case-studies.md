# PGO + BOLT Case Studies

Real-world results from projects that have deployed PGO, BOLT, or both.
Numbers are approximate and system-dependent — use them to calibrate expectations,
not as guarantees.

## Rust Compiler (rustc)

The Rust project uses PGO + BOLT for official release builds.

**Setup:**
- PGO profiles collected by compiling the `cargo` crate (realistic workload)
- BOLT applied to the PGO-optimized rustc binary
- Automated in CI (src/ci/stage-build.py)

**Results (from Kobzol 2022, measured on Ryzen 1700X, 20 iterations):**

| Optimization | Mean Improvement | Max Improvement | Notes |
|-------------|-----------------|-----------------|-------|
| PGO (LLVM portion) | -2.48% instruction count | -5.56% | Profiled against diesel, webrender, etc. |
| PGO (Rust portion) | -5% instruction count | ~5% | Check builds benefit most |
| PGO (combined, wall-time) | -10 to -16% wall-time | -15% (webrender-opt) | |
| BOLT (LLVM library) | -3.67% cycles | -6.60% cycles | Also -3.97% mean RSS, -10.25% max RSS |
| LTO (librustc_driver) | -4.10% instruction count | -9.62% | 5-10% on real-world crates |

PGO profiles collected by compiling a curated set of crates including `diesel`
(trait-heavy) and `webrender` (LLVM-intensive). Uses PID-based filenames (`%m_%p`)
to prevent profile overwrites in multi-process builds.

**Reference:** `kobzol.github.io/rust/rustc/2022/10/27/speeding-rustc-without-changing-its-code.html`

## Chromium / Chrome

Google applies PGO to Chromium builds and has documented BOLT experiments.

**PGO Results (Chrome):**
- Page load: 5-10% faster
- JavaScript execution: 5-15% faster (V8 JIT-compiled code benefits less; C++ host benefits more)
- Binary startup: 10-20% faster

**BOLT Results (experimental):**
- Additional 2-5% on PGO'd builds
- Larger benefits on cold start (layout-sensitive)

**Key insight:** Chrome is one of the largest C++ binaries in the world. PGO's inlining
and branch weight guidance are crucial for a codebase this large.

## Meta (Facebook) — Original BOLT Paper

Meta created BOLT and published results on their internal workloads.

**Paper:** "BOLT: A Practical Binary Optimizer for Data Centers and Beyond" (CGO 2019)

**Key results:**
- Data center workloads: 7-10% throughput improvement from BOLT alone
- Stacking with PGO: additional 5-7% on top of PGO
- I-cache miss reduction: 20-30% on large binaries
- Page fault reduction: 10-15% (better TLB utilization)

**Key insight:** BOLT benefits are largest on server workloads with large code footprints
and clear hot/cold separation. This is the closest analogy to gossip-rs's worker binary.

## CPython

Python 3.12+ uses PGO by default in recommended build configurations.

**Results:**
- pyperformance suite: 5-10% faster (PGO only)
- Some benchmarks: up to 20% improvement
- Startup: ~10% faster

**Key insight:** Even interpreted language runtimes benefit from PGO. The interpreter
loop and dispatch code have very predictable hot paths.

## ripgrep

The ripgrep project has been used as a PGO benchmark target.

**Results (community reports):**
- Search throughput: 5-10% improvement with PGO
- Larger improvements on pattern-heavy searches (more branch-heavy code paths)
- Smaller improvements on simple byte searches (already SIMD-optimized, less branch-sensitive)

**Key insight:** For tools with SIMD-optimized hot paths, PGO helps less on the SIMD
portions but still helps on the surrounding dispatch and I/O code.

## General Expectations

### By Workload Type

| Workload Type | PGO Alone | BOLT Alone | PGO + BOLT |
|--------------|----------|-----------|-----------|
| Large server binary (>20MB) | 10-15% | 5-10% | 15-25% |
| Medium binary (5-20MB) | 5-10% | 3-7% | 8-15% |
| Small CLI tool (<5MB) | 2-5% | 1-3% | 3-7% |
| Compute-bound (SIMD/math) | 1-3% | 0-2% | 1-5% |

### Where the Improvement Comes From

| Optimization | Mechanism | Measured By |
|-------------|-----------|------------|
| PGO: Branch weights | LLVM generates fall-through for hot branches | Fewer branch mispredictions |
| PGO: Inlining | Hot callers inline hot callees aggressively | Fewer call/ret overhead |
| PGO: Cold code separation | Cold blocks moved to end of function | Tighter I-cache |
| BOLT: Block reordering | Hot blocks packed contiguously | Lower I-cache miss rate |
| BOLT: Function reordering | Hot functions grouped together | Fewer iTLB misses |
| BOLT: Cold splitting | Cold code moved to `.cold` section | Hot section fits in cache |

### When to Expect the High End (20-30%)

All of these conditions should be true:
1. Binary is large (>20MB, many functions)
2. Workload is branch-heavy (dispatch loops, pattern matching)
3. Clear hot/cold separation exists
4. I-cache pressure is measurable (check iTLB walks)
5. Profile is representative of production workload
6. Both PGO and BOLT are applied

### When to Expect the Low End (2-5%)

Any of these conditions:
1. Binary is small and already fits in L1i
2. Hot loop is compute-bound (SIMD, math)
3. Profile doesn't match actual workload
4. Only PGO or only BOLT applied (not both)

## Relevance to gossip-rs

The gossip-worker binary is a long-running server process with:
- Gossip protocol dispatch loops (branch-heavy)
- Coordination state machine transitions (branch-heavy)
- Scanner engine with pattern matching (branch-heavy)
- Slab allocator and data structure operations (mixed)

**Expected benefit:** 10-20% range for PGO+BOLT, based on the server workload
profile and significant dispatch/branching code. The coordination hot path and
scanner engine are the most likely beneficiaries.

**Profile collection approach:**
- Use realistic gossip traffic (multiple nodes communicating)
- Exercise the scanner pipeline with representative repositories
- Run for at least 60 seconds to capture steady-state behavior
