---
name: pgo-bolt
description: Use when optimizing Rust binary performance via profile-guided compilation and post-link layout — squeezing 10-30% from I-cache, branch prediction, and function placement without source changes
user-invocable: true
---

# PGO + BOLT — Profile-Guided and Post-Link Binary Optimization

**Philosophy: Runtime profiles are truth. Layout matters.**

PGO teaches LLVM which paths are hot — better inlining, branch hints, and code placement.
BOLT reorders basic blocks and functions in the final binary using real branch profiles —
tighter I-cache footprint and fewer BTB mispredicts. Together they yield 10-30% on
branch-heavy, I-cache-sensitive workloads without changing a single line of source code.

## When to Use

- After `/asm-forge` and `/simd-optimize` have exhausted source-level gains
- When profiling shows high frontend stalls or iTLB misses (`/linux-perf-profile` Mode 1)
- For production release builds of long-running binaries (servers, workers, daemons)
- When you need the last 10-30% without algorithmic changes
- Building optimized CI release artifacts

## When NOT to Use

- Prototyping or debug builds (PGO adds compile time)
- Tiny binaries where I-cache pressure is negligible
- Code that changes frequently (profiles go stale)
- When the bottleneck is I/O, memory bandwidth, or algorithmic (PGO/BOLT fix layout, not logic)
- macOS-only workflows where you need BOLT (BOLT requires Linux ELF binaries)

## Prerequisites

### Required

```bash
# LLVM tools for profile data manipulation
rustup component add llvm-tools-preview

# cargo-pgo: automates the PGO pipeline
cargo install cargo-pgo

# hyperfine: A/B comparison of binaries
cargo install hyperfine
```

### Required for BOLT (Linux only)

```bash
# llvm-bolt and related tools (from LLVM 14+)
# Option 1: System package
apt install llvm-bolt  # or from LLVM apt repo

# Option 2: Build from LLVM source (includes bolt, merge-fdata, llvm-profgen)
# Option 3: cargo-pgo Docker image (bundles everything)
docker pull zamazan4ik/cargo-pgo
```

### Required for Profile Collection (Linux only, for BOLT)

```bash
# perf: branch sampling for BOLT profiles
apt install linux-tools-$(uname -r)  # or linux-perf on some distros
```

### Build Configuration

Always build with frame pointers and debug info for profile collection:

```bash
RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C force-frame-pointers=yes -C debuginfo=2" \
  cargo build --release
```

## Workflow Overview

```
/pgo-bolt @binary "description"
    |
    +-- Phase 0: Platform & Toolchain Detection
    |   +-- Detect OS, arch, available tools
    |   +-- Route: macOS -> PGO-only / Linux -> PGO+BOLT
    |
    +-- Phase 1: Baseline (2 parallel agents)
    |   +-- Agent A: Build release with frame pointers + debuginfo
    |   +-- Agent B: Run baseline benchmarks (Criterion + hyperfine)
    |
    +-- Phase 2: PGO Pipeline
    |   +-- Step 1: Instrumented build (-Cprofile-generate)
    |   +-- Step 2: Run representative workload(s)
    |   +-- Step 3: Merge profiles (llvm-profdata merge)
    |   +-- Step 4: PGO-optimized build (-Cprofile-use)
    |   +-- Step 5: Benchmark PGO vs baseline
    |
    +-- Phase 3: BOLT Pipeline (Linux only)
    |   +-- Step 1: Collect branch profile (perf record -b)
    |   +-- Step 2: Convert to fdata (perf2bolt or llvm-profgen)
    |   +-- Step 3: Apply BOLT (reorder blocks + functions)
    |   +-- Step 4: Benchmark PGO+BOLT vs PGO-only
    |
    +-- Phase 4: Validation
    |   +-- A/B with hyperfine (3-way: baseline / PGO / PGO+BOLT)
    |   +-- Functional correctness (test suite against optimized binary)
    |   +-- Symbol/debug info verification
    |
    +-- Phase 5: Report
        +-- Per-phase improvement breakdown
        +-- Profile quality metrics
        +-- Reproduction commands
```

## Phase 0: Platform & Toolchain Detection

Run the detection script:

```bash
bash <skill_dir>/scripts/pgo_build.sh detect
```

Or manually check:

```bash
# OS and architecture
uname -s -m

# cargo-pgo available?
cargo pgo --version 2>/dev/null || echo "MISSING: cargo install cargo-pgo"

# LLVM profdata available? (needed for PGO)
llvm-profdata --version 2>/dev/null || \
  $(rustc --print sysroot)/lib/rustlib/$(rustc -vV | grep host | cut -d' ' -f2)/bin/llvm-profdata --version 2>/dev/null || \
  echo "MISSING: rustup component add llvm-tools-preview"

# llvm-bolt available? (Linux only, needed for BOLT)
llvm-bolt --version 2>/dev/null || echo "MISSING: apt install llvm-bolt (Linux only)"

# perf available? (Linux only, needed for BOLT profile collection)
perf version 2>/dev/null || echo "MISSING: apt install linux-tools-$(uname -r)"
```

**Platform routing:**

| Platform | PGO | BOLT | Notes |
|----------|-----|------|-------|
| Linux x86-64 | Yes | Yes | Full pipeline. LBR for branch sampling. |
| Linux AArch64 | Yes | Yes (LLVM 16+) | SPE for branch sampling. BOLT AArch64 support maturing. |
| macOS (any arch) | Yes | No | Instrumentation PGO only. BOLT requires ELF. |

Present the detection results before proceeding.

## Phase 1: Baseline

Launch two parallel agents:

### Agent A: Release Build

```bash
# Build with frame pointers and full debug info
RUSTFLAGS="-C opt-level=3 -C target-cpu=native -C force-frame-pointers=yes -C debuginfo=2" \
  cargo build --release --bin <target>
```

**Critical settings for PGO compatibility:**
- `codegen-units=1` improves PGO effectiveness (all code in one codegen unit)
- `lto=fat` gives best PGO results but slower compile; `lto=thin` is acceptable
- `target-cpu=native` ensures CPU-specific optimizations are available
- `force-frame-pointers=yes` needed for `perf` stack unwinding

### Agent B: Benchmark Baseline

```bash
# Criterion benchmarks (save baseline)
cargo bench --bench <name> -- --save-baseline pgo-before

# Binary throughput (hyperfine)
hyperfine --warmup 3 --min-runs 10 \
  './target/release/<binary> <realistic_args>'
```

Record both Criterion and wall-clock numbers. Both matter — Criterion isolates hot
functions, hyperfine captures whole-binary effects (startup, I-cache, branch prediction).

## Phase 2: PGO Pipeline

### Via cargo-pgo (recommended)

```bash
# Step 1: Build instrumented binary
cargo pgo build -- --bin <target>

# Step 2: Run representative workload(s)
# Run multiple times with different inputs for profile diversity
./target/x86_64-unknown-linux-gnu/release/<target> <input_1>
./target/x86_64-unknown-linux-gnu/release/<target> <input_2>
./target/x86_64-unknown-linux-gnu/release/<target> <input_3>

# Step 3+4: cargo-pgo handles merge + optimized build automatically
cargo pgo optimize -- --bin <target>
```

### Via manual LLVM flags (fine-grained control)

```bash
# Step 1: Instrumented build
RUSTFLAGS="-Cprofile-generate=/tmp/pgo-data" \
  cargo build --release --bin <target>

# Step 2: Run representative workload(s)
# Each run creates .profraw files in /tmp/pgo-data/
LLVM_PROFILE_FILE="/tmp/pgo-data/run-%p-%m.profraw" \
  ./target/release/<target> <input_1>
LLVM_PROFILE_FILE="/tmp/pgo-data/run-%p-%m.profraw" \
  ./target/release/<target> <input_2>

# Step 3: Merge profiles
# Find llvm-profdata in the Rust toolchain
LLVM_PROFDATA=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | grep host | cut -d' ' -f2)/bin/llvm-profdata
$LLVM_PROFDATA merge -o /tmp/pgo-data/merged.profdata /tmp/pgo-data/*.profraw

# Step 4: PGO-optimized build
RUSTFLAGS="-Cprofile-use=/tmp/pgo-data/merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  cargo build --release --bin <target>
```

### Step 5: Benchmark PGO vs Baseline

```bash
# Criterion comparison
cargo bench --bench <name> -- --baseline pgo-before

# Wall-clock comparison
hyperfine --warmup 3 --min-runs 10 \
  './target/release/<target>.baseline <args>' \
  './target/release/<target> <args>'
```

**Profile quality guidelines:**
- Run at least 3 distinct input scenarios
- Exercise both common and important-but-rare paths
- Profile runs should last at least 10 seconds each
- More runs with different inputs > fewer runs with same input
- Criterion bench workloads are acceptable profile inputs

## Phase 3: BOLT Pipeline (Linux Only)

Skip this phase on macOS. BOLT requires Linux ELF binaries.

### Step 1: Collect Branch Profile

**Intel (LBR — Last Branch Record):**

```bash
sudo perf record -o perf.data -e br_inst_retired.near_taken:upp \
  -b -c 100003 --  ./target/release/<target> <realistic_input>
```

- `-b` enables branch recording
- `-c 100003` samples every ~100K branches (prime number avoids aliasing)
- `-e br_inst_retired.near_taken:upp` captures taken branches at user level
- Run for at least 30 seconds to collect sufficient branch data

**AMD (IBS — Instruction-Based Sampling):**

```bash
# Via perf (if IBS support available in kernel)
sudo perf record -o perf.data -e ibs_op// -c 100003 -- \
  ./target/release/<target> <realistic_input>

# Via AMDuProfCLI (alternative)
AMDuProfCLI collect --config ibs -g -o ./uprof_out \
  ./target/release/<target> <realistic_input>
```

**ARM (SPE — Statistical Profiling Extension, Graviton2/3):**

```bash
# SPE branch sampling (requires kernel 5.8+ with SPE support)
sudo perf record -o perf.data \
  -e arm_spe_0/branch_filter=1,min_latency=0/ -c 100003 -- \
  ./target/release/<target> <realistic_input>
```

Load `references/profile-collection.md` for architecture-specific details and
troubleshooting.

### Step 2: Convert to BOLT Format

**Path A: perf2bolt (direct conversion, preferred)**

```bash
perf2bolt -p perf.data -o perf.fdata ./target/release/<target>
```

**Path B: llvm-profgen (via perf script intermediate)**

```bash
perf script -i perf.data -F +ip,brstack > perf.script
llvm-profgen --perfscript=perf.script --binary=./target/release/<target> \
  --output=perf.fdata
```

**Path C: merge multiple profile runs**

```bash
# Collect multiple runs
perf2bolt -p perf1.data -o prof1.fdata ./target/release/<target>
perf2bolt -p perf2.data -o prof2.fdata ./target/release/<target>
# Merge
merge-fdata prof1.fdata prof2.fdata > merged.fdata
```

### Step 3: Apply BOLT

```bash
llvm-bolt ./target/release/<target> \
  -o ./target/release/<target>.bolt \
  -data=perf.fdata \
  -reorder-blocks=ext-tsp \
  -reorder-functions=hfsort+ \
  -split-functions \
  -split-all-cold \
  -icf=1 \
  -align-blocks=64 \
  -update-debug-sections
```

**Flags explained:**

| Flag | Purpose |
|------|---------|
| `-reorder-blocks=ext-tsp` | Reorder basic blocks using Extended TSP algorithm (best layout) |
| `-reorder-functions=hfsort+` | Reorder functions by call frequency (hot functions adjacent) |
| `-split-functions` | Move cold blocks out of hot functions |
| `-split-all-cold` | Aggressively split all cold code |
| `-icf=1` | Identical code folding (merge duplicate functions) |
| `-align-blocks=64` | Align hot block entries to cache lines |
| `-update-debug-sections` | Preserve DWARF debug info in output |

Load `references/bolt-guide.md` for advanced flags and tuning.

### Step 4: Benchmark BOLT'd Binary

```bash
hyperfine --warmup 3 --min-runs 10 \
  './target/release/<target> <args>' \
  './target/release/<target>.bolt <args>'
```

## Phase 4: Validation

### A/B Comparison (3-way)

```bash
hyperfine --warmup 3 --min-runs 10 \
  -n 'baseline' './target/release/<target>.baseline <args>' \
  -n 'pgo-only' './target/release/<target>.pgo <args>' \
  -n 'pgo+bolt'  './target/release/<target>.bolt <args>'
```

### Functional Correctness

Run the test suite against the optimized binary to verify it produces identical
results:

```bash
# If the binary has a test mode or can be validated against known output:
diff <(./target/release/<target>.baseline <test_input>) \
     <(./target/release/<target>.bolt <test_input>)
```

### Debug Info Verification

```bash
# Verify symbols survived BOLT
nm ./target/release/<target>.bolt | head -20

# Verify DWARF is intact (if -update-debug-sections was used)
readelf --debug-dump=info ./target/release/<target>.bolt | head -30
```

## Phase 5: Report

```markdown
## PGO + BOLT Report: [target binary]

### Environment
- OS: [Linux x86-64 / Linux AArch64 / macOS]
- CPU: [model]
- Rust: [rustc version]
- LLVM: [llvm version]
- Build: opt-level=3, lto=[thin/fat], codegen-units=[1/N], target-cpu=native

### Profile Collection
- PGO workload: [description of inputs, N runs, total duration]
- BOLT profiler: [perf LBR / AMD IBS / ARM SPE]
- BOLT samples: [N branch samples collected]

### Results

| Build | Criterion (hot fn) | Hyperfine (wall) | Delta vs Baseline |
|-------|-------------------|------------------|-------------------|
| Baseline | X ns | X.XX s | - |
| PGO only | X ns | X.XX s | -X.X% |
| PGO + BOLT | X ns | X.XX s | -X.X% |

### Per-Phase Breakdown
- PGO alone: -X.X% (inlining, branch hints)
- BOLT alone: -X.X% (layout, I-cache, BTB)
- Combined: -X.X%

### Correctness
- Test suite: [PASS/FAIL]
- Output diff: [identical/differences found]

### Reproduction Commands
```bash
[exact commands to reproduce the optimized build]
```

### Notes
[Profile quality observations, potential for further improvement, etc.]
```

## Stacking Order

When combining PGO and BOLT, the order matters:

```
Source code
    |
    v
PGO (compile-time)  <-- feeds profile into LLVM optimizer
    |
    v
Linked ELF binary
    |
    v
BOLT (post-link)    <-- reorders the already-PGO'd binary
    |
    v
Final optimized binary
```

**Always PGO first, then BOLT.** PGO affects code generation (inlining, branch weights).
BOLT rearranges the generated code for better layout. Reversing the order wastes the
BOLT pass since PGO would regenerate the code.

## Tips

### Profile Representativeness

The single most important factor for PGO/BOLT effectiveness:

- **Good profile**: Exercises the same hot paths as production. Even a 60-second run of
  a representative workload is sufficient.
- **Bad profile**: Exercises only startup or tests. PGO will optimize the wrong paths.
- **Multiple workloads**: Merge profiles from different scenarios. PGO handles mixed
  profiles well.

### When PGO Helps Most

- Large binaries with many functions (more layout optimization opportunity)
- Branch-heavy code (match/if chains, dispatch loops)
- Code with clear hot/cold separation (servers: request handling is hot, startup is cold)
- Workloads where I-cache pressure is measurable (check iTLB walks via `/linux-perf-profile`)

### When PGO Helps Least

- Tiny binaries that fit entirely in L1i cache
- Compute-bound code with no branches (pure SIMD loops)
- Code where all paths are equally hot (no hot/cold distinction)

### Debugging PGO Issues

```bash
# Check profile was applied (look for PGO-related remarks)
RUSTFLAGS="-Cprofile-use=merged.profdata -Cremark=all" cargo build --release 2>&1 | grep -i pgo

# Verify profile coverage
llvm-profdata show merged.profdata --all-functions | head -50

# Check for profile mismatch warnings
# (function signatures changed between profile collection and optimized build)
RUSTFLAGS="-Cprofile-use=merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  cargo build --release 2>&1 | grep -i warning
```

### BOLT on AArch64

BOLT AArch64 support has been improving since LLVM 16. Key considerations:

- Use LLVM 17+ for best AArch64 BOLT support
- ARM SPE provides branch data similar to Intel LBR
- Some BOLT optimizations (ICF, certain block alignments) may behave differently on ARM
- Always benchmark — AArch64's larger register file and different branch predictor may
  shift the benefit profile compared to x86-64

### Stabilizing Measurements

```bash
# Fix CPU frequency (Linux)
sudo cpupower frequency-set -g performance

# Isolate cores (Linux, at boot)
# Add to kernel cmdline: isolcpus=2,3

# Pin process to isolated cores
taskset -c 2,3 ./target/release/<target> <args>

# Disable turbo boost (Intel)
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Disable turbo boost (AMD)
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
```

## Related Skills

- `/asm-forge` — After PGO+BOLT, verify codegen quality at the ASM level
- `/linux-perf-profile` — Hardware counter analysis; branch sampling data can feed BOLT
- `/perf-regression` — Regression testing with PGO+BOLT optimized builds
- `/bench-compare` — Quick before/after benchmark comparison
- `/performance-analyzer` — Static hotspot analysis (run before PGO to identify targets)
- `/simd-optimize` — SIMD vectorization (complementary: SIMD fixes compute, PGO/BOLT fixes layout)
