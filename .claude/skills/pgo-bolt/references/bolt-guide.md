# BOLT Guide — Post-Link Binary Optimization

BOLT (Binary Optimization and Layout Tool) is a post-link optimizer from Meta/LLVM that
reorders basic blocks and functions in a compiled binary using runtime branch profiles.
It operates on the final ELF binary — after compilation, LTO, and linking are complete.

## How BOLT Works

```
Compiled ELF binary
       |
       v
BOLT reads:                     BOLT applies:
- .fdata branch profile         - Block reordering (ext-tsp)
- Binary's control flow graph   - Function reordering (hfsort+)
- Relocation information        - Cold code splitting
                                - Identical code folding
       |                        - Block alignment
       v
Optimized ELF binary (.bolt)
- Same semantics
- Different physical layout
- Better I-cache utilization
- Fewer branch mispredictions
```

## Why Layout Matters

Modern CPUs fetch instructions in cache lines (64 bytes). When hot code is scattered
across the binary, the CPU wastes I-cache capacity on cold code that happens to share
the same cache lines. BOLT:

1. **Packs hot blocks together**: Reduces I-cache footprint of the working set
2. **Reorders blocks to favor fall-through**: Reduces branch mispredictions
3. **Splits cold code out**: Cold blocks moved to a separate section (`.cold`)
4. **Reorders functions by call frequency**: Hot callers placed near hot callees

## BOLT Flags Reference

### Essential Flags (safe defaults)

```bash
llvm-bolt <input> -o <output> \
  -data=<profile.fdata> \
  -reorder-blocks=ext-tsp \
  -reorder-functions=hfsort+ \
  -split-functions \
  -split-all-cold \
  -icf=1 \
  -align-blocks=64 \
  -update-debug-sections
```

### Flag Details

| Flag | Values | Purpose |
|------|--------|---------|
| `-data=<path>` | Path to .fdata | Branch frequency profile |
| `-reorder-blocks=` | `none`, `normal`, `ext-tsp`, `cache+` | Block layout algorithm |
| `-reorder-functions=` | `none`, `exec-count`, `hfsort`, `hfsort+`, `cdsort` | Function ordering |
| `-split-functions` | (flag) | Split cold blocks to `.cold` section |
| `-split-all-cold` | (flag) | Split ALL cold blocks, not just frequently-cold ones |
| `-icf=1` | 0 or 1 | Identical Code Folding (merge duplicates) |
| `-align-blocks=N` | 0-64 | Align hot block entries to N bytes |
| `-update-debug-sections` | (flag) | Rewrite DWARF to match new layout |
| `-hugify` | (flag) | Map hot code with huge pages (2MB) |

### Block Reordering Algorithms

| Algorithm | Description | When to Use |
|-----------|-------------|-------------|
| `ext-tsp` | Extended Travelling Salesman — minimizes branch cost + cache misses | Default. Best general-purpose choice. |
| `cache+` | Optimizes specifically for I-cache hit rate | When I-cache misses dominate (high iTLB walks) |
| `normal` | Basic greedy block ordering | Fallback if ext-tsp fails |
| `none` | No reordering | Debugging only |

### Function Reordering Algorithms

| Algorithm | Description |
|-----------|-------------|
| `hfsort+` | Call-graph-aware ordering. Hot callers placed near hot callees. |
| `hfsort` | Original hfsort algorithm. hfsort+ is strictly better. |
| `cdsort` | Community Detection Sort. Good for very large binaries (>10K functions). |
| `exec-count` | Simple: most-executed functions first. |

## Profile Input Paths

BOLT requires branch frequency data. Three ways to provide it:

### Path A: perf2bolt (preferred)

Direct conversion from perf.data:

```bash
perf2bolt -p perf.data -o perf.fdata ./binary
```

Requires perf.data recorded with branch sampling (`-b` flag).

### Path B: BOLT Instrumentation (no perf needed)

BOLT can instrument the binary itself to collect branch profiles — useful when perf
LBR/IBS/SPE is unavailable (VMs, cloud instances without bare metal):

```bash
# Instrument binary
llvm-bolt ./binary -instrument -o ./binary.inst \
    --instrumentation-file=/tmp/prof.fdata \
    --instrumentation-file-append-pid

# Run instrumented binary (collects branch data on exit)
./binary.inst <workload>

# Merge profiles from multiple runs
merge-fdata /tmp/prof.fdata.* > merged.fdata

# Optimize
llvm-bolt ./binary -o ./binary.bolt -data=merged.fdata ...
```

cargo-pgo uses this path by default (`cargo pgo bolt build` / `cargo pgo bolt optimize`).

### Path C: llvm-profgen

Via perf script intermediate:

```bash
perf script -i perf.data -F +ip,brstack > perf.script
llvm-profgen --perfscript=perf.script --binary=./binary --output=perf.fdata
```

Useful when perf2bolt is not available but llvm-profgen is.

### Path D: Merge multiple profiles

```bash
perf2bolt -p run1.perf.data -o run1.fdata ./binary
perf2bolt -p run2.perf.data -o run2.fdata ./binary
merge-fdata run1.fdata run2.fdata > merged.fdata

llvm-bolt ./binary -o ./binary.bolt -data=merged.fdata ...
```

## BOLT with Rust Binaries

### Critical: --emit-relocs Linker Flag

BOLT **requires** relocations in the binary to rearrange functions. Without this flag,
BOLT will fail with: `BOLT-ERROR: ... requires relocations`.

```toml
# .cargo/config.toml (target-specific to avoid overriding PGO flags)
[target.x86_64-unknown-linux-gnu]
rustflags = ["-Clink-arg=-Wl,--emit-relocs"]
```

Or via environment:
```bash
RUSTFLAGS="-Clink-arg=-Wl,--emit-relocs" cargo build --release
```

Also keep `strip = false` in Cargo.toml — BOLT needs the symbol table:
```toml
[profile.release]
strip = false
```

### Symbol Mangling

BOLT works with Rust's mangled symbol names. No special flags needed — BOLT reads the
ELF symbol table directly and doesn't need demangled names.

### LTO Compatibility

| LTO Mode | BOLT Compatibility | Notes |
|----------|-------------------|-------|
| `lto = false` | Works | Normal separate compilation |
| `lto = "thin"` | Works | Recommended: thin LTO + BOLT is a strong combo |
| `lto = "fat"` | Works | Best: full LTO + BOLT maximizes both optimizations |

**No known compatibility issues.** BOLT operates on the final linked ELF, after LTO
has already been applied.

### Static vs Dynamic Linking

- **Static** (default for Rust): BOLT works directly on the single binary
- **Dynamic**: BOLT can optimize individual shared objects (`.so` files)

Rust typically produces statically-linked binaries, so BOLT operates on the full binary.

### Debug Info

Use `-update-debug-sections` to preserve DWARF in the BOLT'd binary. This rewrites
addresses in `.debug_info`, `.debug_line`, etc. to match the new layout.

If debug info is too large or causing issues, you can:
- Split DWARF before BOLT: `-C split-debuginfo=unpacked` in RUSTFLAGS
- Skip debug rewriting: omit `-update-debug-sections` (debug info will be stale)

## BOLT on AArch64

BOLT AArch64 support has been steadily improving:

| LLVM Version | AArch64 BOLT Status |
|-------------|---------------------|
| LLVM 14-15 | Experimental. Basic block reordering works. |
| LLVM 16 | Improved. Most flags functional. |
| LLVM 17+ | Production-ready for most use cases. |

**Key differences from x86-64:**
- AArch64 uses fixed-width (4-byte) instructions — simpler for BOLT to relocate
- No variable-length encoding complications
- ARM's conditional execution affects block splitting (fewer opportunities)
- Branch range limits (26-bit offset for B, 19-bit for B.cond) may prevent some
  reorderings — BOLT inserts trampolines when needed

**ARM SPE for profile collection:**
```bash
sudo perf record -e arm_spe_0/branch_filter=1,min_latency=0/ -c 100003 -- ./binary <args>
```

SPE (Statistical Profiling Extension) is available on:
- AWS Graviton2 (Neoverse N1)
- AWS Graviton3 (Neoverse V1)
- AWS Graviton4 (Neoverse V2)
- Ampere Altra (Neoverse N1)

## Stacking PGO + BOLT

**Always apply PGO first, then BOLT.** The pipeline:

```
Source → PGO Build → BOLT → Final Binary

1. cargo pgo optimize -- --bin <target>     # PGO-optimized build
2. perf record -b ... ./target/.../binary   # Collect branch profile of PGO'd binary
3. perf2bolt -p perf.data -o perf.fdata ./binary
4. llvm-bolt ./binary -o ./binary.bolt -data=perf.fdata ...
```

**Why this order?**
- PGO changes code generation (inlining, branch prediction hints, block layout at LLVM level)
- BOLT reorders the generated code at the binary level
- If you BOLT first, PGO will regenerate all the code, wasting BOLT's work
- BOLT applied to PGO'd code gets better input: PGO already made better inlining
  decisions, so BOLT's layout optimization is more effective

**Expected combined improvement:**
- PGO alone: 5-15% on branch-heavy, I-cache-sensitive code
- BOLT alone: 5-15% (similar category)
- PGO + BOLT: 10-25% (partially overlapping but often additive in different dimensions)

## Common Failure Modes

### BOLT fails with relocation errors

```
BOLT-ERROR: cannot process binaries with relocations in non-allocated sections
```

**Fix:** Build with both `-C relocation-model=pic` **and** `-C link-arg=-Wl,--emit-relocs`
(see the Prerequisites section above). The relocation model alone is insufficient;
`--emit-relocs` ensures relocations land in allocated sections where BOLT can process them.
Stripping debug info before BOLT may also help:
```bash
objcopy --only-keep-debug binary binary.debug
strip binary
llvm-bolt binary -o binary.bolt -data=perf.fdata ...
objcopy --add-gnu-debuglink=binary.debug binary.bolt
```

### BOLT produces a larger binary

Expected behavior. BOLT may:
- Add trampolines for long-range branches
- Add padding for alignment
- Create `.cold` sections for split code

The binary is larger but the hot code is more tightly packed. Performance improves
despite the size increase.

### Insufficient profile data

```
BOLT-WARNING: N functions have no profile data
```

This is normal — BOLT only optimizes functions that appear in the profile. Functions
without profile data are left unchanged. Improve by:
- Running longer profiling workloads
- Exercising more code paths
- Increasing the sample rate (smaller `-c` value in perf record)

### BOLT + strip doesn't work

BOLT needs the symbol table. Don't strip the binary before BOLT. You can strip after:
```bash
llvm-bolt binary -o binary.bolt -data=perf.fdata ...
strip binary.bolt  # OK: strip after BOLT
```
