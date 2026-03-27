# Branch Trace Cookbook

Detailed branch tracing procedures for x86-64 (LBR) and AArch64 (SPE/BRBE).

## x86-64: Intel/AMD LBR

### Availability check

```bash
# Check if LBR is available
perf list | grep br_inst_retired

# Check LBR depth (kernel messages at boot)
dmesg | grep -i lbr

# Test LBR recording
perf record -b -e cycles:u -- sleep 1 && echo "LBR available" || echo "LBR unavailable"
```

LBR is often disabled in VMs and cloud instances. Error message when
unavailable: `PMU Hardware doesn't support sampling/overflow-interrupts`.

### LBR depth by microarchitecture

| CPU Family | Microarchitecture | LBR Entries | LBR Type |
|---|---|---|---|
| Core 2 | Merom | 4 | Legacy |
| Atom | Bonnell/Silvermont | 8 | Legacy |
| 1st Gen Core | Nehalem/Westmere | 16 | Legacy |
| 2nd-3rd Gen | Sandy Bridge/Ivy Bridge | 16 | Legacy |
| 4th-5th Gen | Haswell/Broadwell | 16 | Legacy |
| 6th-10th Gen | Skylake through Comet Lake | 32 | Legacy |
| 11th Gen | Tiger Lake/Ice Lake | 32 | Legacy |
| 12th Gen+ | Alder Lake, Raptor Lake | 32 | Architectural |
| Xeon 4th Gen+ | Sapphire Rapids, Emerald Rapids | 32 | Architectural |
| AMD Zen 3 | BRS (limited, not true LBR) | 16 | BRS |
| AMD Zen 4+ | LbrExtV2 (true LBR) | CPUID-enumerated | LbrExtV2 |

Architectural LBR (Alder Lake+) uses XSAVES/XRSTORS for fast context switching.
User-facing behavior is identical to Legacy LBR.

### Recording modes

```bash
# Basic LBR capture (all branch types)
perf record -b -e cycles:u -- ./binary

# Conditional branches only (best for misprediction hunting)
perf record -j cond,u -e cycles:u -- ./binary

# Calls and returns only (call-graph reconstruction)
perf record -j any_call,any_ret,u -e cycles:u -- ./binary

# Indirect calls only (vtable dispatch analysis)
perf record -j ind_call,u -e cycles:u -- ./binary

# With specific sample period
perf record -c 100000 -b -e cycles:u -- ./binary

# LBR-based call graph (alternative to DWARF unwinding)
perf record --call-graph lbr -e cycles:u -- ./binary
# Note: -b and --call-graph lbr cannot be combined
```

### Branch type filters (`-j` / `--branch-filter`)

| Filter | Meaning |
|--------|---------|
| `any` | All branch types |
| `any_call` | Function calls + syscalls |
| `any_ret` | Function returns + sysrets |
| `ind_call` | Indirect calls (vtable, fn ptr) |
| `ind_jmp` | Indirect jumps |
| `call` | Direct calls including far calls |
| `cond` | Conditional branches |
| `u` | User-space targets only |
| `k` | Kernel targets only |
| `save_type` | Record branch type in output |
| `no_flags` | Skip M/P prediction flags |
| `no_cycles` | Skip cycle counts |

### Decode pipeline

```bash
# Step 1: Dump branch stacks with symbolic names
perf script -F ip,sym,brstack | rustfilt > branches.txt

# Step 2: Find misprediction hotspots (function-level)
perf report --sort symbol_from,symbol_to,mispredict --stdio

# Step 3: Map a specific address to source
addr2line -e ./target/release/binary 0x<ADDRESS>

# Step 4: Disassemble around a hot branch site
objdump -dr --no-show-raw-insn --start-address=0x<ADDR> --stop-address=0x<ADDR+0x40> \
  ./target/release/binary | rustfilt

# Step 5: Full disassembly with demangling
objdump -Mintel -S -d ./target/release/binary | rustfilt | less
```

### brstack output format

Each branch entry: `FROM/TO/EVENT/INTX/ABORT/CYCLES/TYPE/SPEC`

| Field | Values | Meaning |
|-------|--------|---------|
| FROM | hex address | Branch source instruction |
| TO | hex address | Branch target instruction |
| EVENT | `M`, `P`, `-` | **M**ispredicted, **P**redicted, not supported |
| INTX | `X`, `-` | Inside TSX transaction |
| ABORT | `A`, `-` | TSX abort entry |
| CYCLES | integer | Cycles since previous recorded branch |
| TYPE | `COND`, `UNCOND`, `IND`, `CALL`, `IND_CALL`, `RET`, `-` | Branch type |
| SPEC | `SPEC_WRONG_PATH`, `SPEC_CORRECT_PATH`, `NON_SPEC_CORRECT_PATH`, `-` | Speculation status |

Example: `0x40062f/0x4005b0/M/-/-/12/COND/-`
= conditional branch from 0x40062f to 0x4005b0, mispredicted, 12 cycles.

### Variants of brstack output

```bash
perf script -F brstack      # raw addresses
perf script -F brstacksym    # symbolic names (function+offset)
perf script -F brstackinsn   # full disassembly per branch
perf script -F brstackoff    # DSO-relative offsets
```

### Annotate with per-block cycles and IPC (Skylake+ timed LBR)

```bash
perf record -b -e cycles:u -- ./binary
perf annotate --symbol=<function> --stdio
# First column = avg cycles for the basic block
# Second column = IPC (instructions per cycle)
# Low IPC in annotate = potential bottleneck
```

---

## AArch64: ARM SPE

SPE (Statistical Profiling Extension) samples individual operations with rich
metadata. It is NOT a branch history buffer — each sample captures one
operation, not a sequence of branches.

### Availability check

```bash
# Check for SPE device
ls /sys/bus/event_source/devices/arm_spe_0/ 2>/dev/null && echo "SPE available" || echo "SPE unavailable"

# Check supported filters
ls /sys/bus/event_source/devices/arm_spe_0/format/

# Check capabilities
cat /sys/bus/event_source/devices/arm_spe_0/caps/*
```

Requires `CONFIG_ARM_SPE_PMU=y` in kernel config. May not work in VMs unless
SPE is paravirtualized.

### SPE-supported ARM cores

| Core | SPE Version | Notes |
|------|-------------|-------|
| Neoverse N1 | SPEv1.0 | Graviton2 |
| Neoverse V1 | SPEv1.0+ | Graviton3 |
| Neoverse N2, V2 | SPEv1.2+ | Graviton4 |
| Neoverse V3, N3 | SPEv1.4+ | Latest |
| Cortex-X1, X1C | SPEv1.0 | |
| Cortex-X2, X3, X4, X925 | SPEv1.1+ | |
| Cortex-A715, A720, A725 | SPEv1.1+ | |
| Ampere1A | SPEv1.0+ | AmpereOne |

Older Cortex-A cores (A53, A55, A57, A72, A73, A75, A76, A77, A78) do NOT
support SPE despite some being ARMv8.2.

### Recording commands

```bash
# Record branch mispredictions only (event_filter bit 7 = 0x80)
perf record -e arm_spe/branch_filter=1,event_filter=0x80/ -- ./binary

# Record all branches
perf record -e arm_spe/branch_filter=1/ -- ./binary

# Record all branches with timestamps
perf record -e arm_spe/branch_filter=1,ts_enable=1/ -- ./binary

# Record loads with latency >= 10 cycles
perf record -e arm_spe/load_filter=1,min_latency=10/ -- ./binary

# Record stores
perf record -e arm_spe/store_filter=1/ -- ./binary

# Record only retired instructions (exclude speculative)
perf record -e arm_spe/event_filter=2/ -- ./binary
```

### SPE filter options

| Filter | Bit | Meaning |
|--------|-----|---------|
| `ts_enable` | 0 | Enable timestamping |
| `pa_enable` | 1 | Collect physical address (requires privilege) |
| `pct_enable` | 2 | Physical timestamp (requires privilege) |
| `jitter` | 16 | Randomize sampling interval |
| `branch_filter` | 32 | Collect branch operations |
| `load_filter` | 33 | Collect load operations |
| `store_filter` | 34 | Collect store operations |
| `min_latency` | config2 | Only samples with >= N cycle latency |
| `event_filter` | config1 | Logical AND filter on event bits |

### Event filter bits (for `event_filter=`)

| Bit | Value | Event |
|-----|-------|-------|
| 1 | 0x02 | Instruction retired |
| 3 | 0x08 | L1D refill (miss) |
| 5 | 0x20 | TLB refill (miss) |
| 6 | 0x40 | Not-taken branch (SPEv1.2+) |
| **7** | **0x80** | **Mispredicted branch** |
| 11 | 0x800 | Misaligned access (SPEv1.1+) |

Combine with OR for multiple events: `event_filter=0x88` = L1D miss AND mispredict.

### Analyzing SPE data

```bash
# Standard report (grouped by event type)
perf report

# Memory access details
perf report --mem-mode

# All unique instruction samples
perf report --itrace=i1i

# Raw decoded samples
perf script

# Synthetic events generated: l1d-miss, l1d-access, llc-miss, llc-access,
# tlb-miss, tlb-access, branch, remote-access, memory, instructions
```

SPE decoded records contain: operation type (BRANCH/LDST/OTHER), from_ip,
to_ip, latency (total/issue/translation), virtual address, physical address,
data source (L1D/L2/LLC/DRAM), and event flags (BRANCH_MISS, L1D_MISS, etc.).

### SPE vs LBR comparison

| Feature | ARM SPE | Intel LBR |
|---------|---------|-----------|
| Type | Statistical sampler | Branch history buffer |
| Captures | One operation per sample | Last 8-32 branches per sample |
| Branch info | from/to, mispredict, type | from/to, mispredict, cycles |
| Memory info | Address, data source, cache level, latency | None (use PEBS) |
| Call graph | No | Yes (from branch history) |
| Overhead | Low (hardware sampling) | Very low (passive recording) |

**ARM BRBE** (Branch Record Buffer Extension, FEAT_BRBE, ARMv9.2) is the true
LBR equivalent — a ring buffer of 32-64 recent branches. Available on the
newest cores only (limited deployment as of 2026). Kernel config: `CONFIG_ARM64_BRBE`.

---

## Common Analysis Workflow

Regardless of architecture:

1. **Record** branch data (LBR or SPE)
2. **Identify hotspots** — `perf report` shows which functions have the most mispredictions
3. **Map to source** — `addr2line` or `perf annotate` to find exact source lines
4. **Read assembly** — `objdump | rustfilt` or `cargo asm` to understand codegen
5. **Apply fix** — restructure branch, use branchless logic, mark cold paths
6. **Validate** — re-profile to confirm misprediction rate dropped
7. **Escalate to `/asm-forge`** for assembly-level optimization if needed
