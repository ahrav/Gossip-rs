# PGO + BOLT Troubleshooting

Common problems, diagnostics, and fixes for the PGO and BOLT pipeline.

## PGO Issues

### No .profraw files generated

**Symptom:** After running the instrumented binary, no `.profraw` files appear.

**Causes:**
1. Binary wasn't built with `-Cprofile-generate`
2. `LLVM_PROFILE_FILE` path doesn't exist or isn't writable
3. Binary crashed before flushing profile (profiles flush on clean exit)
4. Using cargo-pgo but running the wrong binary (check the target-triple path)

**Fix:**
```bash
# Verify the binary is instrumented (look for __llvm_profile sections)
nm ./target/release/<binary> | grep -i llvm_profile

# Ensure output directory exists
mkdir -p /tmp/pgo-data

# Force profile flush on crash (set handler)
# In Rust, ensure the binary exits cleanly (not SIGKILL)
```

### Profile merge fails

**Symptom:** `llvm-profdata merge` errors or produces an empty profile.

**Causes:**
1. `.profraw` files from different binary versions (profile counter mismatch)
2. Corrupted `.profraw` (incomplete write, disk full)

**Fix:**
```bash
# Check .profraw file sizes (0 bytes = corrupt)
ls -la /tmp/pgo-data/*.profraw

# Try merging one file at a time to find the bad one
for f in /tmp/pgo-data/*.profraw; do
  llvm-profdata merge -o /dev/null "$f" 2>&1 && echo "OK: $f" || echo "BAD: $f"
done

# Rebuild and re-collect if binary changed between profiling runs
```

### PGO build warns about missing functions

**Symptom:** `-pgo-warn-missing-function` produces many warnings.

**Causes:**
1. Profile collected from a different code version
2. Functions were renamed, inlined differently, or removed
3. Profile workload didn't exercise those functions

**Assessment:**
- A few warnings are normal (cold code may not appear in profiles)
- Many warnings (>50% of functions) = profile is stale, re-collect
- Functions in the warning list should be cold functions, not hot ones

### PGO makes performance worse

**Symptom:** PGO-optimized binary is slower than baseline.

**Causes:**
1. **Profile mismatch**: Profile collected on workload A, benchmarking workload B
2. **Over-inlining**: PGO's aggressive inlining bloated the hot path, causing I-cache pressure
3. **Measurement noise**: Warmup insufficient or system not stabilized

**Fix:**
```bash
# Verify profile matches benchmark workload
# Run the same workload for profiling and benchmarking

# Check binary size — if much larger, PGO may have over-inlined
ls -la ./target/release/<binary>*

# Re-measure with more warmup and runs
hyperfine --warmup 10 --min-runs 30 baseline pgo-binary
```

### llvm-profdata not found

**Symptom:** `llvm-profdata: command not found`

**Fix:**
```bash
# It's bundled with rustup's llvm-tools-preview
rustup component add llvm-tools-preview

# Find it in the sysroot
PROFDATA=$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | grep host | cut -d' ' -f2)/bin/llvm-profdata
echo "Found at: $PROFDATA"

# Add to PATH (or use full path)
export PATH="$(dirname $PROFDATA):$PATH"
```

## BOLT Issues

### BOLT relocation error

**Symptom:**
```
BOLT-ERROR: cannot process binaries with relocations in non-allocated sections
```

**Causes:**
- Debug info contains relocations that BOLT can't handle
- Some Rust compiler flag interactions produce these

**Fix:**
```bash
# Option 1: Strip debug info, BOLT, then re-add
objcopy --only-keep-debug binary binary.debug
strip --strip-debug binary
llvm-bolt binary -o binary.bolt -data=perf.fdata ...
objcopy --add-gnu-debuglink=binary.debug binary.bolt

# Option 2: Build with split DWARF
RUSTFLAGS="... -C split-debuginfo=unpacked" cargo build --release

# Option 3: Build without debug info for BOLT, keep debuginfo binary separate
RUSTFLAGS="-C debuginfo=0" cargo build --release
```

### BOLT: "no profile data for binary"

**Symptom:** BOLT runs but reports 0 functions optimized.

**Causes:**
1. Profile was collected from a different binary (different build)
2. perf2bolt conversion failed silently
3. perf.data was collected without branch recording (`-b` flag missing)

**Fix:**
```bash
# Verify perf.data has branch stacks
perf report -i perf.data --stdio 2>&1 | head -20
# Should show branch information, not just IP samples

# Verify .fdata has content
wc -l perf.fdata
# Should have thousands of lines for a meaningful profile

# Re-record with correct flags
sudo perf record -e br_inst_retired.near_taken:upp -b -c 100003 -- ./binary <args>
```

### BOLT output binary crashes

**Symptom:** BOLT produces a binary that segfaults or produces wrong results.

**Causes:**
1. BOLT version too old for the binary's instruction set
2. Rare BOLT bug with specific instruction sequences
3. BOLT and the binary were built with different LLVM versions

**Fix:**
```bash
# Try with fewer optimizations
llvm-bolt binary -o binary.bolt -data=perf.fdata \
  -reorder-blocks=ext-tsp \
  -reorder-functions=hfsort+ \
  # Remove: -split-functions -split-all-cold -icf=1

# If still crashes, try block reordering only
llvm-bolt binary -o binary.bolt -data=perf.fdata \
  -reorder-blocks=ext-tsp

# Update LLVM/BOLT to latest version
# Use LLVM 17+ for best Rust compatibility
```

### BOLT: symbols missing

**Symptom:** BOLT warns about missing symbols or refuses to process.

**Fix:**
```bash
# BOLT needs the symbol table — don't strip before BOLT
# Check symbol table exists
nm binary | head -10

# If stripped, rebuild without stripping
# Strip AFTER BOLT, not before
```

### perf2bolt not found

**Symptom:** `perf2bolt: command not found`

**Fix:**
```bash
# perf2bolt ships with LLVM BOLT
apt install llvm-bolt  # Debian/Ubuntu
# or build LLVM with BOLT enabled

# Alternative: use llvm-profgen instead
perf script -i perf.data -F +ip,brstack > perf.script
llvm-profgen --perfscript=perf.script --binary=./binary --output=perf.fdata

# Alternative: use cargo-pgo Docker image
docker run -v $(pwd):/src zamazan4ik/cargo-pgo bash
# All tools available inside the container
```

## perf Issues

### Permission denied for perf record

**Symptom:** `perf record: Permission denied`

**Fix:**
```bash
# Option 1: Run as root
sudo perf record ...

# Option 2: Adjust perf_event_paranoid
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
# 0 = allow non-root to access all events
# 1 = allow non-root to access user events (usually sufficient)
# 2 = allow non-root only with limits

# Option 3: Grant CAP_PERFMON capability
sudo setcap cap_perfmon+ep $(which perf)
```

### perf: event not supported

**Symptom:** `br_inst_retired.near_taken:upp` not available

**Causes:**
1. Running in a VM that doesn't expose PMU counters
2. CPU doesn't support the specific event
3. perf version mismatch with kernel

**Fix:**
```bash
# List available events
perf list | grep br_inst

# Try alternative events
perf record -e branches:u -b ...  # Generic branch event
perf record -e cpu-cycles ...     # Fallback (less precise for BOLT)

# Check if running in VM (limited PMU access)
systemd-detect-virt
```

### ARM SPE not available

**Symptom:** `arm_spe_0` not in perf list

**Causes:**
1. Kernel doesn't have SPE support (needs 5.8+)
2. Running in VM without SPE passthrough
3. CPU doesn't have SPE (Cortex-A series generally doesn't)

**Fix:**
```bash
# Check kernel version (need 5.8+)
uname -r

# Check if SPE module is loaded
lsmod | grep arm_spe

# Verify CPU supports SPE
cat /proc/cpuinfo | grep 'CPU part'
# Neoverse N1/V1/V2 have SPE; Cortex-A72/A76 do not

# Fallback: use generic branch event (less precise)
perf record -e branches:u -b -c 100003 -- ./binary <args>
```

## Measurement Issues

### Noisy benchmarks

**Symptom:** Results vary by >5% between runs.

**Fix:**
```bash
# 1. Fix CPU frequency
sudo cpupower frequency-set -g performance

# 2. Disable turbo boost
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo  # Intel
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost          # AMD

# 3. Pin to specific cores
taskset -c 2,3 hyperfine ...

# 4. Close background applications

# 5. Increase minimum runs
hyperfine --warmup 10 --min-runs 30 ...

# 6. Use statistical significance testing
hyperfine --warmup 5 --min-runs 20 'binary1' 'binary2'
# hyperfine reports if the difference is statistically significant
```

### A/B shows no improvement

**Symptom:** PGO or BOLT binary is no faster than baseline.

**Possible reasons:**
1. Workload is not I-cache or branch sensitive (compute-bound)
2. Binary is small enough to fit in L1i cache entirely
3. Profile doesn't match benchmark workload
4. Measurement noise is masking a small improvement

**Diagnostics:**
```bash
# Check if I-cache is the bottleneck
perf stat -e L1-icache-load-misses,L1-icache-loads,iTLB-load-misses ./binary <args>
# If miss rate < 1%, PGO/BOLT layout optimizations won't help much

# Check binary size
ls -la binary
# If < 1MB, I-cache pressure is unlikely

# Verify profile was actually applied (PGO)
nm binary | grep __llvm_profile  # Should NOT be present in optimized build
# (Instrumented build has these; optimized build should not)
```
