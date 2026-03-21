# TMA Diagnosis → Action Mapping

Maps Top-Down Microarchitecture Analysis categories to concrete Rust-level fixes.
Actions are mostly architecture-agnostic since fixes are at the source level.

## Intel TMA Expected Ranges (reference baseline)

| Category | Client | Server | HPC |
|----------|--------|--------|-----|
| Retiring | 20-50% | 10-30% | 30-70% |
| Backend Bound | 20-40% | 20-60% | 20-40% |
| Frontend Bound | 5-10% | 10-25% | 5-10% |
| Bad Speculation | 5-10% | 5-10% | 1-5% |

Source: Intel VTune TMA Cookbook.

---

## Bad Speculation High (> 15%)

**Root cause**: Unpredictable branches in hot loops. The CPU speculatively
executes the wrong path, then discards work.

**Level 2 drill-down** (if available):
- Branch Mispredictions → specific branch sites causing the issue
- Machine Clears → pipeline flushes from memory ordering violations, self-modifying code

### Actions

1. **Restructure hot loop to reduce unpredictable branches.**
   Replace conditional branches with arithmetic/bit-twiddling:
   ```rust
   // BAD: unpredictable branch
   if value > threshold { acc += delta; }

   // GOOD: branchless with conditional select
   acc += delta * (value > threshold) as u64;
   // Or use mask:
   let mask = -((value > threshold) as i64) as u64;
   acc += delta & mask;
   ```

2. **Merge rare paths out of line.** Keep the hot fallthrough path linear.
   Mark cold helpers with `#[cold]` and `#[inline(never)]`:
   ```rust
   #[cold]
   #[inline(never)]
   fn handle_rare_case(ctx: &mut Context) { /* ... */ }
   ```

3. **Use LBR/SPE to find exact misprediction sites.** See SKILL.md Mode 4.
   Then apply targeted fixes at those specific branches.

4. **BOLT for binary-level code layout.** See the BOLT section below.

Cross-ref: `asm-forge/references/asm-red-flags.md` for branch-heavy codegen patterns.

---

## Frontend Bound High (> 20%)

**Root cause**: The instruction fetch/decode pipeline cannot supply µops fast
enough. Usually caused by instruction cache misses, iTLB misses, or decode
bottlenecks from large code footprint.

**Level 2 drill-down** (if available):
- Fetch Latency → icache misses, iTLB misses, branch target misses
- Fetch Bandwidth → decoder throughput limits, µop cache misses

### Actions

1. **Reduce codegen units to 1.** More codegen units = more duplicate code =
   more icache pressure. The LLVM linker merges CGUs, but with `codegen-units > 1`
   some functions get duplicated across CGUs before linking:
   ```bash
   # In Cargo.toml [profile.release]
   codegen-units = 1

   # Or via RUSTFLAGS (temporary)
   RUSTFLAGS='-C codegen-units=1' cargo build --release
   ```
   Trade-off: slower compilation. Worth it for deployment binaries.

2. **Mark cold helpers `#[inline(never)]`.** Prevents inlining cold code into
   hot functions, keeping hot code compact:
   ```rust
   #[inline(never)]
   fn format_error(e: &Error) -> String { /* cold path */ }
   ```

3. **Reduce monomorphization.** Generic functions instantiated for many types
   bloat code size. Consider:
   - Using `dyn Trait` for cold-path generics
   - Using inner non-generic functions that do the real work
   - Using `#[inline(never)]` on generic functions called from many sites

4. **BOLT for function reordering.** Reorders functions so hot code is
   contiguous, dramatically reducing icache and iTLB pressure. See BOLT section.

Cross-ref: `asm-forge/references/asm-red-flags.md` for cold-code-in-hot-path patterns.

---

## Backend Bound High (> 40%)

**Root cause**: The execution engine cannot retire µops fast enough because
it is waiting on data (memory bound) or execution ports (core bound).

**Level 2 drill-down** (if available):
- Memory Bound → L1/L2/L3/DRAM latency, store forwarding failures
- Core Bound → execution port saturation, long-latency operations, dependency chains

### Actions (Memory Bound)

1. **Improve data locality — SoA over AoS for hot scans.**
   When scanning a collection and accessing only 1-2 fields per element:
   ```rust
   // BAD: Array of Structs — loads entire 64-byte struct per iteration
   struct Record { id: u64, score: f64, name: String, metadata: Vec<u8> }
   let records: Vec<Record> = /* ... */;
   let total: f64 = records.iter().map(|r| r.score).sum();

   // GOOD: Struct of Arrays — scores are contiguous in memory
   struct Records { ids: Vec<u64>, scores: Vec<f64>, names: Vec<String>, metadata: Vec<Vec<u8>> }
   let total: f64 = records.scores.iter().sum();
   ```

2. **Add software prefetch hints** for predictable access patterns:
   ```rust
   #[cfg(target_arch = "x86_64")]
   unsafe {
       std::arch::x86_64::_mm_prefetch(ptr.add(64) as *const i8, std::arch::x86_64::_MM_HINT_T0);
   }
   ```

3. **Audit for false sharing** in concurrent code. Pad shared atomics to
   cache line boundaries:
   ```rust
   #[repr(align(128))]  // two cache lines for Intel prefetcher
   struct PaddedCounter {
       value: AtomicU64,
   }
   ```

4. **Reduce struct sizes** to fit more elements per cache line. Use smaller
   types, pack fields, consider indices instead of pointers.

### Actions (Core Bound)

5. **Break dependency chains** for better instruction-level parallelism.
   See `asm-forge/references/ilp-and-microarch.md`.

6. **Avoid long-latency operations** in hot loops: divisions, modulo,
   `format!()`, virtual dispatch.

Cross-ref: `asm-forge/references/forge-techniques.md` (struct packing, memory traffic reduction).
Cross-ref: `/linux-perf-profile` Mode 3 for cache hierarchy drill-down.

---

## Retiring High (> 80%) but CPI > 1

**Root cause**: The CPU is retiring useful work efficiently, but each
instruction takes more cycles than expected. This means the instruction mix
contains long-latency or high-µop-count operations.

### Actions

1. **Avoid divisions and modulo** in hot loops. Replace with shifts, masks,
   or multiply-by-reciprocal:
   ```rust
   // BAD: integer division is 20-40 cycles
   let bucket = index / BUCKET_SIZE;
   let offset = index % BUCKET_SIZE;

   // GOOD: if BUCKET_SIZE is power of 2
   let bucket = index >> BUCKET_SHIFT;
   let offset = index & BUCKET_MASK;
   ```

2. **Use smaller integer operations.** 64-bit multiply is slower than 32-bit
   on some µarchs. Use the narrowest type that works.

3. **Lean on rotates, xors, and adds** for hash/mix functions instead of
   multiplies.

4. **Check for fuseable patterns.** Compare-and-branch (cmp+jcc on x86,
   cmp+b.cond on ARM) fuse into a single µop. Ensure the compiler generates
   these instead of separate compare and branch instructions.

5. **Inspect µop count** via `/asm-forge`. Some "simple" instructions decode
   to multiple µops (e.g., `lock cmpxchg`, unaligned loads crossing cache lines).

Cross-ref: `asm-forge/references/x86-64-codegen.md` (instruction costs).
Cross-ref: `asm-forge/references/aarch64-codegen.md` (ARM instruction costs).

---

## BOLT Binary Optimization

BOLT (Binary Optimization and Layout Tool) reorders functions and basic blocks
in the compiled binary based on a runtime profile. Most effective for
**Frontend Bound** workloads. Gains: 7-20% on FE-bound, up to 52% on unoptimized.

### When to use BOLT

- TMA shows Frontend Bound > 20%
- Large binary with poor default code locality
- Already applied `codegen-units=1` and `#[inline(never)]` for cold paths

### When NOT to use BOLT

- TMA shows Backend Bound as dominant — BOLT won't help
- Small binary (< 1MB text section) — insufficient locality opportunity

### Two profiling approaches

**Method A: LBR sampling (higher quality, requires hardware LBR)**

```bash
# Build with relocations
RUSTFLAGS="-C link-arg=-Wl,--emit-relocs -C force-frame-pointers=yes" cargo build --release

# Collect profile (run representative workload, ~60s)
perf record -e cycles:u -j any,u -o perf.data -- ./target/release/mybinary <args>

# Convert and optimize
perf2bolt -p perf.data -o perf.fdata ./target/release/mybinary
llvm-bolt ./target/release/mybinary -o ./target/release/mybinary.bolt \
  -data=perf.fdata \
  -reorder-blocks=ext-tsp \
  -reorder-functions=cdsort \
  -split-functions \
  -split-all-cold \
  -dyno-stats
```

**Method B: BOLT instrumentation (works everywhere, no LBR needed)**

```bash
# Build with relocations
RUSTFLAGS="-C link-arg=-Wl,--emit-relocs" cargo build --release

# Instrument
llvm-bolt ./target/release/mybinary -instrument \
  --instrumentation-file=/tmp/prof.fdata \
  -o ./target/release/mybinary.inst

# Run instrumented binary with representative workload
./target/release/mybinary.inst <args>

# Optimize
llvm-bolt ./target/release/mybinary -o ./target/release/mybinary.bolt \
  -data=/tmp/prof.fdata \
  -reorder-blocks=ext-tsp \
  -reorder-functions=hfsort \
  -split-functions \
  -split-all-cold \
  -dyno-stats
```

**Simpler path via `cargo-pgo`:**

```bash
cargo install cargo-pgo
# Requires llvm-bolt and merge-fdata on PATH
cargo pgo bolt build
./target/release/<name>-bolt-instrumented <workload>
cargo pgo bolt optimize
```

### Installation

```bash
# Ubuntu/Debian
sudo apt install llvm-bolt

# Or from LLVM apt repo (latest)
sudo apt install bolt-20  # or bolt-21, bolt-22

# Verify
llvm-bolt --version
```

### Compatibility

| Feature | Works with BOLT? |
|---------|:---:|
| Frame pointers | Yes |
| Debug info (DWARF 4/5) | Yes (add `-update-debug-sections`) |
| LTO (thin or fat) | Yes |
| PIE binaries | Yes |
| AArch64 | Yes |
| Stripped symbols | **No** — do not strip before BOLT |
| Sanitizers | **No** |

### Key BOLT flags reference

- `-reorder-blocks=ext-tsp` — Extended TSP algorithm for block layout (best quality)
- `-reorder-functions=cdsort` — Call-distance sort for function layout (newer, preferred)
- `-reorder-functions=hfsort` — Hierarchical function sort (older, still good)
- `-split-functions` — Split hot/cold function parts
- `-split-all-cold` — Maximize cold code outlining
- `-dyno-stats` — Print before/after execution statistics
- `-lite=1` — Skip cold functions (faster processing, slightly less optimal)
- `-update-debug-sections` — Preserve DWARF debugging info
- `-hugify` — Place hot code on 2MB huge pages at runtime

Source: LLVM BOLT documentation, CGO'19 paper, Rust compiler CI experience.
