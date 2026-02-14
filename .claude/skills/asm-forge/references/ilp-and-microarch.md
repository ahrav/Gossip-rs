# Instruction-Level Parallelism and Microarchitecture

Understanding how modern CPUs execute instructions is essential for optimizing
hot code. This reference covers the execution model and how to exploit it.

## Reference Documentation

- **Agner Fog's Microarchitecture Manual**: https://www.agner.org/optimize/microarchitecture.pdf
  (The definitive reference for x86-64 microarchitecture details)
- **Agner Fog's Instruction Tables**: https://www.agner.org/optimize/instruction_tables.pdf
  (Latency and throughput for every instruction on every microarchitecture)
- **Agner Fog's Optimizing Assembly**: https://www.agner.org/optimize/optimizing_assembly.pdf
- **Intel Optimization Manual**: https://www.intel.com/content/www/us/en/develop/download/intel-64-and-ia-32-architectures-optimization-reference-manual.html
- **ARM Cortex-A Performance Guide**: https://developer.arm.com/documentation/102160/latest
- **ARM NEON Programmer's Guide**: https://developer.arm.com/documentation/den0018/latest
- **What Every Programmer Should Know About Memory (Drepper)**: https://people.freebsd.org/~lstewart/articles/cpumemory.pdf
- **A Primer on Memory Consistency and Cache Coherence**: https://pages.cs.wisc.edu/~markhill/papers/primer2020_2nd_edition.pdf

## The Out-of-Order Execution Model

Modern CPUs don't execute instructions in program order. They:

1. **Fetch** instructions from memory (4-8 per cycle)
2. **Decode** into micro-ops (μops)
3. **Rename** registers to eliminate false dependencies
4. **Dispatch** to a reservation station (reorder buffer, ROB)
5. **Execute** when operands are ready (out of order!)
6. **Retire** in program order (to maintain correctness)

### Key Structures

| Structure | Alder Lake (x86) | Apple M3 (P-core) | Graviton3 (V1) |
|-----------|:-:|:-:|:-:|
| Decode width | 6 μops/cycle | 9 inst/cycle | 5 inst/cycle |
| ROB entries | ~512 | ~630 | ~256 |
| Execution ports | 12 | ~14 | ~8 |
| Int ALUs | 5 | 6 | 4 |
| Load ports | 2 | 3 | 2 |
| Store ports | 2 | 2 | 2 |

**Key insight**: The CPU can execute 4-14 instructions per cycle, but ONLY if there
are enough independent instructions available. Dependency chains serialize execution.

## Dependency Types

### True Dependencies (Read-After-Write — RAW)
```asm
add     x0, x1, x2     ; writes x0
mul     x3, x0, x4     ; reads x0 — MUST wait for add to complete
```
**Cannot be eliminated.** This is the fundamental serialization constraint.
The only fix is to restructure the computation.

### Anti-Dependencies (Write-After-Read — WAR)
```asm
add     x0, x1, x2     ; reads x1
sub     x1, x3, x4     ; writes x1 — WAR dependency on line above
```
**Eliminated by register renaming.** The CPU renames x1 to a physical register,
so these can execute in parallel. No action needed.

### Output Dependencies (Write-After-Write — WAW)
```asm
mov     x0, #1          ; writes x0
mov     x0, #2          ; writes x0 — WAW dependency
```
**Eliminated by register renaming.** No action needed.

### Memory Dependencies
```asm
str     x0, [x1]        ; store to [x1]
ldr     x2, [x3]        ; load from [x3] — are x1 and x3 the same?
```
**Partially resolved at runtime.** The CPU has a store buffer and can forward
store results to subsequent loads at the same address. But if the CPU can't
prove the addresses differ, it may stall. This is why aliasing analysis matters.

## Dependency Chain Analysis

### How to Analyze

For a hot loop body, trace the critical path:

1. Write down each instruction and its latency
2. Draw arrows from each producer to its consumers
3. The longest path through the graph is the critical path
4. The critical path length (in cycles) is the minimum loop iteration time

### Example Analysis

```asm
; Inner loop body:
ldr     x0, [x1]           ; L=4: load value           (depends on x1)
add     x0, x0, #1         ; L=1: increment            (depends on load → chain: 5)
str     x0, [x1]           ; L=0: store result          (depends on add → chain: 5)
ldr     x2, [x3]           ; L=4: load second value     (INDEPENDENT of above!)
mul     x2, x2, x4         ; L=3: multiply              (depends on second load → chain: 7)
add     x5, x5, x2         ; L=1: accumulate            (depends on mul → chain: 8)
add     x1, x1, #8         ; L=1: advance pointer 1     (INDEPENDENT)
add     x3, x3, #8         ; L=1: advance pointer 2     (INDEPENDENT)
```

**Critical path**: `ldr x2 → mul → add x5` = 4+3+1 = **8 cycles per iteration**

**But x5 has a loop-carried dependency!** `add x5, x5, x2` produces x5, and the next
iteration's accumulation will read x5. So the actual critical path per iteration is:
`x5 → (next iter's) add x5, x5, x2` = max(8, 1) = **8 cycles**.

The loop also has 8 instructions. At peak throughput (4-6 IPC), 8 instructions
take ~1-2 cycles. But the 8-cycle dependency chain means we're at ~1 IPC.

### Breaking the Chain: Multiple Accumulators

```asm
; BEFORE: single accumulator (chain = 8 cycles per iteration)
add     x5, x5, x2         ; loop-carried: x5 → x5

; AFTER: two independent accumulators (each chain = 8 cycles, but overlapped!)
; Iteration 0: accumulate into x5
add     x5, x5, x2_even
; Iteration 1: accumulate into x6 (INDEPENDENT of x5 chain!)
add     x6, x6, x2_odd
; Final: combine
add     x5, x5, x6
```

**Result**: Two iterations in flight simultaneously → ~2x throughput.

**In Rust:**
```rust
// Before: serial accumulator
let mut sum = 0u64;
for &x in data.iter() {
    sum += process(x);
}

// After: two independent accumulators
let (mut sum0, mut sum1) = (0u64, 0u64);
for chunk in data.chunks_exact(2) {
    sum0 += process(chunk[0]);  // independent chain A
    sum1 += process(chunk[1]);  // independent chain B
}
sum0 + sum1 + data.chunks_exact(2).remainder().iter().map(|&x| process(x)).sum::<u64>()
```

## Port Pressure Analysis

### Concept

Each execution unit (port) can handle certain instructions. If too many instructions
target the same port, they queue up even if data dependencies allow parallelism.

### Common Bottlenecks

**Load port saturation**: Too many memory loads per cycle
```asm
; If a loop has 4 loads and the CPU has 2 load ports:
; Best case = 2 cycles per iteration (load-bound)
ldr     x0, [x1]       ; port 2
ldr     x2, [x3]       ; port 3
ldr     x4, [x5]       ; port 2 (queued behind first load)
ldr     x6, [x7]       ; port 3 (queued behind second load)
```

**Fix**: Reduce loads by packing data tighter, computing derived values instead
of loading them, or restructuring the algorithm.

**Branch port saturation**: Too many branches per cycle
- Most CPUs have 1-2 branch execution ports
- Multiple branches in a loop body can saturate the branch port
- Fix: Branchless alternatives (cmov, lookup tables, bit manipulation)

## Practical ILP Optimization Strategies

### 1. Loop Unrolling

The compiler usually handles this, but check:
- Is the loop unrolled? (Look for repeated instruction patterns)
- Is the unroll factor appropriate? (2x, 4x, 8x depending on chain length)

If not unrolled, the compiler may be blocked by:
- Unknown trip count (add `exact_chunks()` or known-size processing)
- Side effects in the loop body
- Complex control flow

### 2. Software Pipelining

Process multiple iterations simultaneously by interleaving their instructions:

```asm
; Before: process A, then B, then C (serial)
; Iteration 0:
ldr  x0, [x1]        ; load A
add  x0, x0, #1      ; process A (waits 4 cycles for load)
str  x0, [x1]        ; store A

; After: overlap load of next iteration with processing current:
; Prologue: load first
ldr  x0, [x1]        ; load A[0]
.loop:
  ldr  x2, [x1, #8]  ; load A[1] (start loading NEXT while processing current)
  add  x0, x0, #1    ; process A[0] (runs in parallel with load of A[1])
  str  x0, [x1]      ; store A[0]
  mov  x0, x2        ; move next to current
  add  x1, x1, #8
  ; ...
```

### 3. Data Layout for ILP

**Structure of Arrays (SoA)** enables processing columns independently:
```rust
// AoS: fields interleaved, accessing one field loads all fields
struct Particle { x: f32, y: f32, z: f32, mass: f32 }
let particles: Vec<Particle>; // x,y,z,mass,x,y,z,mass,...

// SoA: fields packed, accessing one field has perfect locality
struct Particles {
    x: Vec<f32>,  // x,x,x,x,...
    y: Vec<f32>,  // y,y,y,y,...
    z: Vec<f32>,  // z,z,z,z,...
    mass: Vec<f32>,
}
// Processing x values only loads x cache lines (4x less memory traffic)
// Also SIMD-friendly: load 4 x values at once
```

### 4. Reducing Critical Path Length

Strategies ordered by common applicability:

1. **Use fused operations**: `madd` (AArch64) or `lea` (x86-64) combines two ops into one
2. **Strength reduction**: Replace expensive ops with cheaper equivalents
   - `x / 8` → `x >> 3`
   - `x % 16` → `x & 15`
   - `x * 3` → `x + (x << 1)`
3. **Associativity**: Rearrange operations to shorten the tree
   - `((a + b) + c) + d` has depth 3
   - `(a + b) + (c + d)` has depth 2 (a+b and c+d are independent)
4. **Lookup tables**: Replace computation with memory lookup when the domain is small

## Measurement: How to Verify ILP

### Using Benchmarks

ILP improvements should show as:
- Fewer cycles for the same instruction count → higher IPC
- Same cycles with fewer instructions → algorithmic improvement
- Both → great

### Using perf (Linux only)

```bash
# Measure IPC directly:
perf stat -e cpu_cycles,instructions ./target/release/bench
# IPC = instructions / cycles

# Measure port pressure (x86-64, Intel):
perf stat -e uops_dispatched_port.port_0,uops_dispatched_port.port_1,...
```

### Using cargo-show-asm

Count instructions in the critical path manually:
1. Identify the inner loop in the ASM
2. Trace data dependencies
3. Sum latencies along the longest chain
4. Compare to instruction count → theoretical IPC

If critical_path_cycles >> instruction_count / execution_width, there's ILP
opportunity. The ratio of achieved IPC to theoretical peak IPC tells you how
much runway remains.

## Microarchitectural Hazards

### Store-to-Load Forwarding

When a store is followed by a load from the same address, the CPU can forward
the store data directly without going through cache. But forwarding fails if:
- The load is wider than the store
- The load is misaligned relative to the store
- There are too many stores in the buffer

**Failed forwarding**: ~10-20 cycles penalty. Check if you see unexpectedly
slow load instructions.

### Cache Line Splits

Accessing data that straddles a 64-byte cache line boundary:
- Load/store must access two cache lines instead of one
- ~2x latency penalty

**Check**: If struct size + alignment allows an access to cross a 64-byte
boundary, add `#[repr(align(64))]` or pad the struct.

### 4KB Page Splits

Accessing data that straddles a 4KB page boundary:
- Requires two TLB lookups
- ~100+ cycle penalty (rare but devastating when it happens)
- Usually only matters for large SIMD loads on array boundaries

### False Sharing

Two cores writing to different fields in the same 64-byte cache line:
- Cache line bounces between cores
- Each write invalidates the other core's cache copy
- Can reduce throughput to ~10-50% of single-threaded speed

**Check**: Use `#[repr(align(64))]` padding between fields accessed by different threads.
