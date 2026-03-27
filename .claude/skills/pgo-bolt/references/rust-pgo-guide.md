# Rust PGO Guide

Profile-Guided Optimization in Rust uses LLVM's PGO infrastructure. Rust exposes two
`-C` flags that control the pipeline: `-Cprofile-generate` and `-Cprofile-use`.

## How PGO Works

```
Instrumented build               Profile collection              Optimized build
(-Cprofile-generate)              (run workloads)                 (-Cprofile-use)
       |                                |                               |
       v                                v                               v
   Binary with                    .profraw files                  LLVM uses profile
   counter probes                 (one per run)                   data for:
   inserted at                         |                          - branch weights
   branch points                       v                          - inlining decisions
                                  llvm-profdata merge             - block placement
                                       |                          - function ordering
                                       v                          - switch lowering
                                  merged.profdata                 - virtual call devirt
```

## Two Paths: cargo-pgo vs Manual

### cargo-pgo (recommended for most cases)

Automates the entire pipeline:

```bash
# Install
cargo install cargo-pgo

# Step 1: Instrument
cargo pgo build -- --bin <target>
# Creates: target/<triple>/release/<target>

# Step 2: Collect (run multiple times for diversity)
./target/<triple>/release/<target> <input1>
./target/<triple>/release/<target> <input2>

# Step 3: Optimize (merge + rebuild automatic)
cargo pgo optimize -- --bin <target>
# Creates: target/<triple>/release/<target> (PGO-optimized)
```

**cargo-pgo features:**
- Handles `llvm-profdata` path resolution automatically
- Supports `--bolt` flag for integrated BOLT pipeline (Linux)
- Docker image available: `zamazan4ik/cargo-pgo` (includes llvm-bolt, perf tools)
- Pass `-- --features bench` or other cargo args after `--`

### Manual LLVM Flags (fine-grained control)

```bash
# Step 1: Instrumented build
RUSTFLAGS="-Cprofile-generate=/tmp/pgo-data" \
  cargo build --release --bin <target>

# Step 2: Collect profiles
LLVM_PROFILE_FILE="/tmp/pgo-data/run-%p-%m.profraw" \
  ./target/release/<target> <input>

# Step 3: Merge
PROFDATA=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | grep host | cut -d' ' -f2)/bin/llvm-profdata
$PROFDATA merge -o /tmp/pgo-data/merged.profdata /tmp/pgo-data/*.profraw

# Step 4: Optimized build
RUSTFLAGS="-Cprofile-use=/tmp/pgo-data/merged.profdata" \
  cargo build --release --bin <target>
```

## Interaction with Build Settings

### LTO (Link-Time Optimization)

| LTO Mode | PGO Compatibility | Notes |
|-----------|-------------------|-------|
| `lto = false` | Works | PGO applies per-CGU only |
| `lto = "thin"` | Works (recommended) | Good balance: PGO + cross-module inlining |
| `lto = "fat"` | Works (best quality) | Slowest compile, but PGO has full program view |

**Recommendation:** Use `lto = "thin"` for development PGO builds, `lto = "fat"` for
final production builds.

### codegen-units

PGO effectiveness improves with fewer codegen units because LLVM can see more code
at once when applying profile data:

| Setting | PGO Impact | Compile Time |
|---------|-----------|-------------|
| `codegen-units = 1` | Best (all code visible) | Slowest |
| `codegen-units = 16` (default) | Reduced (profiles fragmented) | Fastest |

**Recommendation:** Use `codegen-units = 1` for PGO builds. The extra compile time is
worthwhile since you only build the optimized version once.

### target-cpu

`-C target-cpu=native` is independent of PGO and stacks with it. PGO improves layout
and branch hints; `target-cpu=native` enables CPU-specific instructions. Use both.

## Profile File Format

| Extension | Tool | Purpose |
|-----------|------|---------|
| `.profraw` | Runtime | Raw counter data from one program execution |
| `.profdata` | `llvm-profdata merge` | Merged profile from multiple runs |
| `.fdata` | BOLT | Branch frequency data (different format, used by BOLT only) |

### LLVM_PROFILE_FILE Patterns

```bash
# %p = PID (unique per process)
# %m = binary hash (unique per binary version)
# Both together guarantee unique filenames for parallel/repeated runs
LLVM_PROFILE_FILE="/tmp/pgo-data/run-%p-%m.profraw" ./binary
```

### Profile Merging

```bash
# Merge all .profraw files in a directory
llvm-profdata merge -o merged.profdata /tmp/pgo-data/*.profraw

# Show profile summary (function counts, max counts)
llvm-profdata show merged.profdata --all-functions | head -50

# Show profile overlap between two profiles (useful for checking representativeness)
llvm-profdata overlap merged1.profdata merged2.profdata
```

## Instrumentation vs Sampling PGO

Rust (via LLVM) supports **instrumentation PGO**:
- Probes inserted at compile time
- Exact edge counts (no sampling noise)
- ~2x runtime overhead (acceptable for profiling runs)
- Works on all platforms including macOS

LLVM also supports **sampling PGO** (AutoFDO):
- Uses `perf` branch samples instead of instrumentation
- Near-zero overhead
- Requires Linux with hardware performance counters
- Less precise than instrumentation

**For Rust:** Use instrumentation PGO unless the overhead is unacceptable for your
profiling workload. Instrumentation gives more precise data and works cross-platform.

## When PGO Helps

PGO provides the most benefit when:

- **Large binary with many functions**: More opportunity for function reordering and
  I-cache optimization
- **Branch-heavy code**: `match` statements, `if/else` chains, dispatch loops — PGO
  gives LLVM accurate branch weights
- **Clear hot/cold separation**: Server request handlers (hot) vs startup code (cold)
- **Virtual dispatch**: PGO can devirtualize calls when profiles show a dominant callee

## When PGO Hurts or Doesn't Help

- **Profile mismatch**: Profiles collected on workload A, binary runs workload B.
  PGO will optimize the wrong paths.
- **Tiny binaries** that fit entirely in L1i: No I-cache benefit from layout optimization
- **Compute-bound SIMD loops**: No branches to optimize
- **All paths equally hot**: No cold code to move away from hot code

## Debugging PGO

### Check profile was applied

```bash
# Look for PGO optimization remarks
RUSTFLAGS="-Cprofile-use=merged.profdata -Cremark=all" \
  cargo build --release 2>&1 | grep -i 'pgo\|profile'
```

### Check for stale profiles

```bash
# Warns when functions in the binary don't appear in the profile
RUSTFLAGS="-Cprofile-use=merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  cargo build --release 2>&1 | grep -i warning
```

Profile staleness happens when:
- Source code changed significantly after profiles were collected
- Functions were renamed, split, or inlined differently
- New code paths were added that weren't profiled

**Fix:** Re-collect profiles whenever the code changes significantly. Profile data
does not need to be bit-perfect — profiles from a nearby revision are often sufficient
for the majority of the benefit.

### Verify profile quality

```bash
# Show function coverage
llvm-profdata show merged.profdata --all-functions --counts 2>&1 | \
  awk '/^[^ ]/ {name=$0} /Total count:/ {print $NF, name}' | sort -rn | head -20
```

The top functions by count should be your known hot functions. If startup functions
dominate, your profiling workload is not representative.
