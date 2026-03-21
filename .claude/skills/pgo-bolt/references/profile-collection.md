# Profile Collection Guide

Branch profile collection for BOLT varies by CPU architecture and vendor.
This guide covers the three major platforms: Intel (LBR), AMD (IBS), and ARM (SPE),
plus the macOS PGO-only path.

## Quick Reference

| Platform | Mechanism | perf Event | BOLT Support |
|----------|-----------|------------|-------------|
| Intel x86-64 | LBR (Last Branch Record) | `br_inst_retired.near_taken:upp` | Full |
| AMD x86-64 | IBS (Instruction-Based Sampling) | `ibs_op//` or `branches:u` | Via conversion |
| ARM AArch64 | SPE (Statistical Profiling Extension) | `arm_spe_0/branch_filter=1/` | LLVM 17+ |
| macOS (any) | Instrumentation only | N/A | No BOLT (Mach-O, not ELF) |

## Intel — LBR (Last Branch Record)

### How It Works

Intel CPUs have dedicated hardware (LBR) that records the last 32 taken branches in a
circular buffer. perf can snapshot this buffer at each sample, giving precise
source→target branch pairs.

### Collection Command

```bash
sudo perf record \
  -o perf.data \
  -e br_inst_retired.near_taken:upp \
  -b \
  -c 100003 \
  -- ./target/release/<binary> <args>
```

**Flag breakdown:**
- `-e br_inst_retired.near_taken:upp` — Sample on retired near-taken branches at
  user-level precise (`:upp` = user + precise level 2)
- `-b` — Record branch stacks (LBR dump at each sample)
- `-c 100003` — Sample every ~100K events (prime to avoid aliasing with periodic code)

### Alternative Events

```bash
# All retired branches (taken + not-taken)
-e br_inst_retired.all_branches:upp

# Conditional branches only (skip unconditional jumps)
-e br_inst_retired.conditional:upp

# Near return branches (call/return profiling)
-e br_inst_retired.near_return:upp
```

### Conversion to BOLT

```bash
# Direct: perf2bolt
perf2bolt -p perf.data -o perf.fdata ./target/release/<binary>

# Via perf script (if perf2bolt unavailable)
perf script -i perf.data -F +ip,brstack > perf.script
llvm-profgen --perfscript=perf.script --binary=./target/release/<binary> --output=perf.fdata
```

### Sampling Rate Guidance

| Use Case | `-c` Value | Samples/sec (approx) | Duration |
|----------|-----------|---------------------|----------|
| Quick check | 500003 | ~2K/s | 10s |
| Normal profiling | 100003 | ~10K/s | 30s+ |
| High precision | 10007 | ~100K/s | 60s+ |

Use prime numbers for `-c` to avoid aliasing with loop iterations.

### Checking LBR Availability

```bash
# Verify LBR support
perf list | grep br_inst_retired

# Check max LBR depth (usually 32)
dmesg | grep -i lbr
```

## AMD — IBS (Instruction-Based Sampling)

### How It Works

AMD Instruction-Based Sampling provides precise per-instruction attribution including
branch outcomes. Unlike Intel LBR which records branch stacks, IBS tags individual
instructions with their execution characteristics.

### Collection via perf

```bash
# IBS Op sampling (branch + memory info)
sudo perf record \
  -o perf.data \
  -e ibs_op// \
  -c 100003 \
  -- ./target/release/<binary> <args>
```

If IBS is not available in the kernel:

```bash
# Fallback: generic branch event
sudo perf record \
  -o perf.data \
  -e branches:u \
  -b \
  -c 100003 \
  -- ./target/release/<binary> <args>
```

### Collection via AMDuProfCLI

AMD provides a dedicated profiling tool:

```bash
# Collect IBS data
AMDuProfCLI collect --config ibs -g -o ./uprof_out \
  ./target/release/<binary> <args>

# Generate report
AMDuProfCLI report -i ./uprof_out/*.ses -o ./uprof_report
```

### Conversion to BOLT

IBS data from perf can be converted via the standard perf2bolt or llvm-profgen path.
AMDuProfCLI output may need manual conversion — check AMDuProf documentation for
export-to-perf-script capability.

### Checking IBS Availability

```bash
# Check for IBS support
perf list 2>&1 | grep -i ibs

# Check CPU model
cat /proc/cpuinfo | grep -m1 'model name'
# IBS available on Zen/Zen2/Zen3/Zen4+
```

## ARM — SPE (Statistical Profiling Extension)

### How It Works

ARM's SPE is a hardware profiling extension that records sampled instructions with rich
metadata including branch outcomes, data addresses, and latency. It's the ARM equivalent
of Intel's LBR for branch profiling purposes.

### Prerequisites

- Kernel 5.8+ with SPE support enabled
- AWS Graviton2/3/4, Ampere Altra, or other Neoverse cores
- perf built with ARM SPE support

### Collection Command

```bash
sudo perf record \
  -o perf.data \
  -e arm_spe_0/branch_filter=1,min_latency=0/ \
  -c 100003 \
  -- ./target/release/<binary> <args>
```

**Filter options:**
- `branch_filter=1` — Record only branch operations
- `min_latency=0` — No minimum latency threshold
- `load_filter=1` — Record only load operations (for cache profiling)
- `store_filter=1` — Record only store operations

### Conversion to BOLT

BOLT AArch64 support (LLVM 17+) can use SPE profiles via the standard perf2bolt path:

```bash
perf2bolt -p perf.data -o perf.fdata ./target/release/<binary>
```

### Checking SPE Availability

```bash
# Check for SPE support
perf list 2>&1 | grep -i arm_spe

# Verify via /proc
cat /proc/cpuinfo | grep -m1 'CPU part'
# Neoverse N1: 0xd0c (Graviton2)
# Neoverse V1: 0xd40 (Graviton3)
# Neoverse V2: 0xd4f (Graviton4)
```

## macOS — PGO Only

macOS uses Mach-O binaries, not ELF. BOLT is an ELF-only tool. On macOS, only
instrumentation-based PGO is available.

### What Works on macOS

- **cargo-pgo**: Full PGO pipeline (instrument → collect → optimize)
- **Manual PGO**: `-Cprofile-generate` / `-Cprofile-use` RUSTFLAGS
- **llvm-profdata merge**: Works on macOS (via `rustup component add llvm-tools-preview`)

### What Does NOT Work on macOS

- **BOLT**: ELF-only (Mach-O support is not planned)
- **perf**: Linux-only tool
- **LBR/IBS/SPE**: Linux perf_events interface only

### macOS Profiling Alternatives (for analysis, not BOLT)

```bash
# Instruments.app (macOS native profiler)
xcrun xctrace record --template 'Time Profiler' --launch ./target/release/<binary>

# dtrace (system-wide)
sudo dtrace -x ustackframes=100 -n 'profile-99 /execname == "<binary>"/ { @[ustack()] = count(); }' -c './target/release/<binary> <args>'

# sample (quick snapshot)
sample <PID> 10 -file sample.txt
```

These tools are useful for hotspot analysis but cannot produce BOLT-compatible branch
profiles.

## General Guidance

### How Many Samples Are "Enough"?

| Quality Level | Branch Samples | Typical Duration | Use Case |
|--------------|---------------|-----------------|----------|
| Minimal | 100K | ~10 seconds | Quick sanity check |
| Good | 1M+ | ~30 seconds | Most optimization work |
| High quality | 10M+ | ~2 minutes | Maximum BOLT effectiveness |

More samples → more accurate branch frequencies → better BOLT decisions. But returns
diminish above ~10M samples.

### Stabilizing the Measurement Environment

```bash
# 1. Fix CPU frequency (Linux)
sudo cpupower frequency-set -g performance

# 2. Disable turbo boost (Intel)
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# 3. Disable turbo boost (AMD)
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost

# 4. Pin to specific cores
taskset -c 2,3 ./target/release/<binary> <args>

# 5. Isolate cores at boot (kernel cmdline)
# isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3
```

### Profile Representativeness

The profiling workload should exercise the same code paths as production:

- **Server binaries**: Use a realistic request mix, not just startup
- **CLI tools**: Use representative input files/sizes
- **Benchmark suites**: Criterion benchmarks are acceptable profile inputs
- **Multiple scenarios**: Merge profiles from different workloads via `merge-fdata`

### Profile Staleness

Profiles become stale when code changes. Indicators:
- BOLT warns about functions without profile data
- PGO warns about missing functions (`-pgo-warn-missing-function`)
- Performance degrades instead of improving

**Re-profile when:**
- Hot paths change (new algorithms, refactored dispatch)
- Significant code is added/removed
- Performance numbers stop improving

**Don't need to re-profile for:**
- Minor bug fixes in cold paths
- Documentation changes
- Test-only changes
