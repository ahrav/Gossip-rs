---
name: perf-topdown
description: Top-Down Microarchitecture Analysis (TMA) with branch tracing on x86-64 (LBR) and AArch64 (SPE) — classifies bottlenecks and maps them to concrete Rust-level fixes
user-invocable: true
---

# Top-Down Profiling — Classify, Trace, Fix

Structured workflow for diagnosing *why* code is slow using hardware performance
counters. Works on both x86-64 (Intel/AMD) and AArch64 (ARM Neoverse/Cortex).

The recipe: **build harness → classify bottleneck → trace branches → apply fix**.

## When to Use

- Need to classify *why* code is slow (front-end vs back-end vs speculation vs retiring)
- Need branch-level traces to find misprediction sites
- Need an isolated hot-loop harness for stable profiling
- After `/bench-compare` or `/perf-regression` finds a regression and you need root cause
- Want the structured classify→trace→fix workflow instead of ad-hoc counter exploration

## When NOT to Use

- For deep ARM cache/TLB/lock drill-down → `/linux-perf-profile` (Modes 3-7)
- For assembly-level codegen optimization → `/asm-forge`
- For Criterion before/after measurement → `/bench-compare`
- For analyzing existing profiling data → `/rust-perf-triage`

---

## Prerequisites — Build & Stability

### Build flags (both architectures)

```bash
RUSTFLAGS='-C opt-level=3 -C target-cpu=native -C force-frame-pointers=yes -C debuginfo=2' \
  cargo build --release --bin <target>
```

- `-C force-frame-pointers=yes` — enables lightweight call-graph capture alongside LBR
- `-C debuginfo=2` — maps samples back to Rust source lines without affecting optimization

### Stability setup (prioritized by impact)

Apply these before profiling. Each reduces measurement variance:

```bash
# 1. CPU governor to performance (biggest single impact)
sudo cpupower frequency-set --governor performance
# Or: echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 2. Disable turbo/boost
# Intel:
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
# AMD/generic:
echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
# ARM Graviton: fixed frequency, no action needed

# 3. Pin to a specific core (avoid core 0 — handles IRQs)
taskset -c 2 ./target/release/binary

# 4. Disable ASLR (per-process, no global security impact)
setarch $(uname -m) -R ./target/release/binary

# 5. Disable NMI watchdog (frees a PMU counter)
echo 0 | sudo tee /proc/sys/kernel/nmi_watchdog

# 6. Set perf_event_paranoid for counter access
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

**Graviton note**: AWS Graviton processors run at fixed frequency with no
turbo/boost control. Steps 2 is unnecessary; steps 1, 3-6 still apply.

---

## Mode 1: Harness Scaffold

Use when no existing Criterion benchmark covers the suspected hot path.
If a benchmark already exists, use `/bench-compare` instead.

Create `src/bin/tiny_hot.rs`:

```rust
use std::hint::black_box;
use std::time::{Duration, Instant};
use std::thread;

fn hot_loop(iter: usize) -> u64 {
    let mut acc: u64 = 0;
    for i in 0..iter {
        // Replace with the suspected hotspot, keep inputs stable
        acc = acc.wrapping_add((i as u64).rotate_left(13) ^ 0x9E3779B97F4A7C15);
    }
    acc
}

fn main() {
    let start = Instant::now();
    let target = Duration::from_secs(60);
    let mut reps = 0u64;
    let mut sink = 0u64;
    while start.elapsed() < target {
        sink ^= hot_loop(black_box(2_000_000));
        reps += 1;
    }
    eprintln!("done reps={reps} sink={sink}");
    thread::sleep(Duration::from_millis(10)); // profiler tail time
}
```

Build and run:

```bash
RUSTFLAGS='-C opt-level=3 -C target-cpu=native -C force-frame-pointers=yes -C debuginfo=2' \
  cargo build --release --bin tiny_hot
taskset -c 2 ./target/release/tiny_hot
```

---

## Mode 2: Quick CPI & Cache Sanity

Fast triage to determine if the workload is compute-bound, memory-bound, or
branch-bound. Run 5 repetitions for statistical stability.

**x86-64:**

```bash
sudo perf stat -r 5 -e cycles,instructions,branch-misses,cache-misses,LLC-loads,icache_misses \
  taskset -c 2 ./target/release/tiny_hot
```

**AArch64:**

```bash
sudo perf stat -r 5 -e cpu_cycles,inst_retired,br_mis_pred_retired,l1d_cache_refill,l2d_cache_refill,l1i_cache_refill \
  taskset -c 2 ./target/release/tiny_hot
```

### Derived metrics and decision tree

| Metric | Formula | Healthy | Investigate |
|--------|---------|---------|-------------|
| CPI | cycles / instructions | < 1.0 | > 1.0 |
| Branch miss rate | branch-misses / branches | < 2% | > 5% |
| L1d miss rate | l1d misses / l1d accesses | < 5% | > 10% |
| ICache miss rate | icache_misses / instructions | < 0.1% | > 1% |

**Decision tree:**
- CPI > 1.0 → proceed to **Mode 3** (Top-Down Classification)
- High `branch-misses` → suspect predictor/layout, proceed to **Mode 4** (Branch Trace)
- High `icache_misses` → suspect code size, see `references/tma-diagnosis-actions.md` FE-Bound section
- High `cache-misses` or `LLC-loads` → memory/locality issue, see `/linux-perf-profile` Mode 3 (ARM) or BE-Bound remediation

Cross-ref `rust-perf-triage/references/profiling-tools.md` for detailed counter interpretation.

---

## Mode 3: Top-Down Classification

Classify the bottleneck into four categories: Retiring, Bad Speculation,
Frontend Bound, Backend Bound. The commands differ by architecture and vendor.

### x86-64 Intel

```bash
# Level 1 (kernel 4.8+, Sandy Bridge+)
sudo perf stat --topdown -a -- taskset -c 2 ./target/release/tiny_hot

# Level 2 (kernel ~5.13+, Sapphire Rapids+)
sudo perf stat --topdown --td-level 2 -- taskset -c 2 ./target/release/tiny_hot
```

The `--topdown` flag requires system-wide mode (`-a`) on pre-Ice Lake CPUs.
Ice Lake and later allow per-thread topdown collection.

**Alternative (deeper drill-down via JSON metrics, kernel 6.1+):**

```bash
# Level 1
perf stat -M TopdownL1 -- taskset -c 2 ./target/release/tiny_hot

# Drill into a specific L1 category
perf stat -M tma_backend_bound_group -- taskset -c 2 ./target/release/tiny_hot

# Drill further into L3
perf stat -M tma_core_bound_group -- taskset -c 2 ./target/release/tiny_hot
```

### x86-64 AMD (Zen 4+, kernel 6.2+)

AMD does NOT support `--topdown`. Use `-M PipelineL1` instead:

```bash
# Level 1 (5 categories — AMD adds smt_contention)
perf stat -M PipelineL1 -- taskset -c 2 ./target/release/tiny_hot

# Level 2
perf stat -M PipelineL2 -- taskset -c 2 ./target/release/tiny_hot

# Drill into specific category
perf stat -M frontend_bound_group -- taskset -c 2 ./target/release/tiny_hot
```

**AMD pipeline widths**: Zen 4 = 6-wide, Zen 5 = 8-wide. Raw slot counts are
not comparable across Intel (4-wide) and AMD.

### AArch64 (ARM Neoverse)

ARM has no `--topdown` flag. Use manual event-based topdown:

**Neoverse N2/V2+ (slot-based topdown, kernel metric support):**

```bash
# If perf supports -M on this core:
perf stat -M frontend_bound,backend_bound,bad_speculation,retiring \
  -- taskset -c 2 ./target/release/tiny_hot

# Manual event collection:
perf stat -r 5 -e cpu_cycles,inst_retired,stall_slot_frontend,stall_slot_backend,stall_slot,op_retired,op_spec,br_mis_pred \
  -- taskset -c 2 ./target/release/tiny_hot
# Compute: FE% = stall_slot_frontend / (cpu_cycles * slots)
# Compute: BE% = stall_slot_backend / (cpu_cycles * slots)
```

**Neoverse N1/V1 (cycle-based only, no slot events):**

```bash
perf stat -r 5 -e cpu_cycles,inst_retired,stall_frontend,stall_backend,stall_backend_mem,br_mis_pred_retired \
  -- taskset -c 2 ./target/release/tiny_hot
# Compute: FE% = stall_frontend / cpu_cycles * 100
# Compute: BE% = stall_backend / cpu_cycles * 100
```

See `linux-perf-profile` Mode 1 for the full ARM topdown derived metrics table.

### Unified interpretation

| Category | Threshold | Meaning | Next step |
|----------|-----------|---------|-----------|
| **Retiring** high | > 80% | Near peak efficiency | Mode 2 for µop reduction; see `references/tma-diagnosis-actions.md` |
| **Bad Speculation** high | > 15% | Branch mispredictions | **Mode 4** for branch traces |
| **Frontend Bound** high | > 20% | ICache / decode stalls | `references/tma-diagnosis-actions.md` FE section |
| **Backend Bound** high | > 40% | Memory / execution ports | `references/tma-diagnosis-actions.md` BE section |

See `references/tma-diagnosis-actions.md` for the complete diagnosis-to-action mapping.

---

## Mode 4: Branch Trace Recording & Decoding

After Mode 3 identifies Bad Speculation or you see high branch-misses in Mode 2,
record branch traces to find the exact misprediction sites.

### x86-64 (Intel LBR, Skylake+ = 32 entries)

```bash
# Record with LBR (user-space branches, ~100K sample period)
sudo perf record -o perf.data -c 100000 -b -e cycles:u \
  -- taskset -c 2 ./target/release/tiny_hot

# Identify misprediction hotspots (function-level)
perf report --sort symbol_from,symbol_to,mispredict --stdio

# Dump raw branch stacks with Rust demangling
perf script -F ip,sym,brstack | rustfilt | head -200

# Map specific addresses to source
addr2line -e ./target/release/tiny_hot 0x<ADDRESS>

# View disassembly around a hot branch
objdump -dr --no-show-raw-insn ./target/release/tiny_hot | rustfilt | less

# Annotate with per-basic-block cycles/IPC (Skylake+ timed LBR)
perf annotate --symbol=<function_name> --stdio
```

**Branch type filtering** (narrow capture to specific branch types):

```bash
perf record -j cond,u ./binary       # conditional branches only (mispredict candidates)
perf record -j any_call,any_ret,u ./binary  # calls and returns only
perf record -j ind_call,u ./binary    # indirect calls only
```

**brstack output format**: `FROM/TO/M_or_P/INTX/ABORT/CYCLES/TYPE/SPEC`
- `M` = mispredicted, `P` = predicted
- CYCLES = elapsed cycles since previous recorded branch

### x86-64 (AMD Zen 4+ LbrExtV2, kernel 6.1+)

Same perf commands as Intel LBR. AMD Zen 4 supports hardware branch filtering
and misprediction flags. Zen 3 BRS is limited (16 entries, no filtering, no
prediction info) — use Zen 4+ for serious LBR work.

### AArch64 (ARM SPE branch sampling)

ARM SPE provides statistical branch sampling. For branch misprediction profiling:

```bash
# Record branch mispredictions (event_filter bit 7 = 0x80)
sudo perf record -e arm_spe/branch_filter=1,event_filter=0x80/ \
  -- taskset -c 2 ./target/release/tiny_hot

# Record all branches
sudo perf record -e arm_spe/branch_filter=1/ \
  -- taskset -c 2 ./target/release/tiny_hot

# Analyze
perf report --stdio --percent-limit=1.0

# View decoded samples
perf script
```

**SPE vs LBR**: SPE is a statistical sampler (like Intel PEBS) — it samples
individual operations with rich metadata (addresses, latency, cache level).
It does NOT provide a continuous branch history like LBR. ARM BRBE (ARMv9.2,
FEAT_BRBE) is the true LBR equivalent but is only available on the newest cores.

**Fallback (no SPE):**

```bash
perf record -e br_mis_pred_retired -c 1000 -g --call-graph dwarf \
  -- taskset -c 2 ./target/release/tiny_hot
perf report --stdio --percent-limit=1.0
```

**SPE-supported cores**: Neoverse N1/N2/V1/V2/V3, Cortex-X1/X2/X3/X4/X925,
Cortex-A715/A720/A725, Ampere1A. Covers AWS Graviton 2/3/4.

See `references/branch-trace-cookbook.md` for detailed decode procedures.

---

## Event Groups for Copy-Paste

### x86-64 Intel

```
# TMA Level 1 raw events
topdown-retiring,topdown-bad-spec,topdown-fe-bound,topdown-be-bound

# LBR recording
cycles:u with -b flag, or br_inst_retired.any:u

# ICache pressure
icache_64b.iftag_miss,frontend_retired.l1i_miss,frontend_retired.l2_miss
```

### x86-64 AMD (Zen 4+)

Use `-M PipelineL1` and `-M PipelineL2` metric groups (AMD events have
vendor-specific names accessed through the JSON metric system).

### AArch64

```
# Topdown (N1/V1 cycle-based)
cpu_cycles,inst_retired,stall_frontend,stall_backend,stall_backend_mem

# Topdown (N2/V2+ slot-based)
cpu_cycles,inst_retired,stall_slot_frontend,stall_slot_backend,stall_slot,op_retired,op_spec

# SPE branch misprediction
arm_spe/branch_filter=1,event_filter=0x80/

# SPE all branches with timestamps
arm_spe/branch_filter=1,ts_enable=1/
```

Cross-ref `linux-perf-profile` for ARM cache/TLB/branch event sets.
Cross-ref `rust-perf-triage/scripts/perf_counters.sh` for generic presets.

---

## Output Format

Report findings using this structure:

```markdown
## Top-Down Profile: [target / scenario]

### Environment
- CPU: [model], [arch] (x86-64 / AArch64)
- Build: `RUSTFLAGS="-C target-cpu=native -C debuginfo=2 -C force-frame-pointers=yes"` release
- Stability: governor=performance, turbo=off, pinned to core N

### TMA Level 1

| Category | Value | Assessment |
|----------|-------|------------|
| Retiring | X.X% | [ok/high — near peak] |
| Bad Speculation | X.X% | [ok/high — branch misses] |
| Frontend Bound | X.X% | [ok/high — icache/decode] |
| Backend Bound | X.X% | [ok/high — memory/ports] |

### Branch Trace Hotspots (if Mode 4 was used)

| Rank | From → To | Mispredict Rate | Type | Likely Cause |
|------|-----------|-----------------|------|--------------|
| 1 | func_a+0x42 → func_b | 23% | COND | unpredictable match arm |

### Diagnosis & Remediation

[TMA category] is the bottleneck.

**Root cause**: [specific code pattern tied to PMU data]
**Fix applied**: [source-level change with rationale]

### Validation Plan

[Commands to re-run after applying fixes to confirm improvement]
```

---

## Caveats

- **Intel `--topdown`**: Requires kernel 4.8+. System-wide (`-a`) required pre-Ice Lake. Disable NMI watchdog.
- **AMD**: No `--topdown` flag. Use `-M PipelineL1` (kernel 6.2+ for Zen 4, ~6.9+ for Zen 5).
- **LBR depth**: 32 entries (Skylake+), 16 (Haswell). AMD Zen 4 depth is CPUID-enumerated. Zen 3 BRS is NOT true LBR.
- **ARM SPE**: Available on Neoverse N1+ / Cortex-X1+. Not a branch history buffer — it's a statistical sampler.
- **ARM BRBE**: True LBR equivalent, but requires ARMv9.2 (newest cores only).
- **ARM topdown**: N1/V1 = cycle-based only. N2/V2+ = full slot-based topdown.
- **Multiplexing**: At Level 2+, perf may time-share counters. Output shows `(XX.XX%)` duty cycle. Keep groups small.
- **Metric naming**: Stabilized in kernel 6.1. Older kernels may use inconsistent names.
- **Graviton**: Fixed frequency (no turbo control needed). ~3 simultaneous HW counters in VMs — expect multiplexing.
- **Cloud/VMs**: LBR often disabled. Use BOLT instrumentation mode or SPE where available.

## Related Skills

- `/linux-perf-profile` — Deep ARM counter drill-down (cache/TLB/lock, Modes 3-7)
- `/asm-forge` — Assembly-level follow-up after identifying hot functions
- `/bench-compare` — Criterion before/after measurement
- `/perf-regression` — Full regression workflow with acceptance criteria
- `/rust-perf-triage` — Post-hoc analysis of collected perf data
