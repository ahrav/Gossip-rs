# ASM Red Flags — Cross-ISA Codegen Issues

Universal patterns that indicate suboptimal compiler output, regardless of whether
the target is x86-64 or AArch64. These are ordered by typical impact.

## Reference Documentation

When investigating any red flag, cross-reference with these authoritative sources:

- **Rust Reference — Unsafe Code Guidelines**: https://doc.rust-lang.org/reference/unsafety.html
- **LLVM Language Reference**: https://llvm.org/docs/LangRef.html
- **cargo-show-asm documentation**: https://github.com/pacak/cargo-show-asm
- **Agner Fog's Instruction Tables (x86-64)**: https://www.agner.org/optimize/instruction_tables.pdf
- **Agner Fog's Microarchitecture Manual**: https://www.agner.org/optimize/microarchitecture.pdf
- **ARM Architecture Reference Manual**: https://developer.arm.com/documentation/ddi0487/latest
- **ARM Cortex Optimization Guide**: https://developer.arm.com/documentation/102160/latest
- **Apple Silicon Optimization Guide**: https://developer.apple.com/documentation/apple-silicon/tuning-your-code-s-performance-for-apple-silicon
- **Criterion.rs User Guide**: https://bheisler.github.io/criterion.rs/book/
- **The Rust Performance Book**: https://nnethercote.github.io/perf-book/

Always verify ASM interpretations against these references. Do not rely solely on
pattern matching — understand *why* a pattern is problematic.

## 1. Panic Paths in Hot Loops (Critical)

**What it looks like:**
```
; Any of these in a tight loop body:
call    core::panicking::panic_bounds_check     ; x86-64
bl      core::panicking::panic_bounds_check     ; AArch64
call    core::panicking::panic                  ; x86-64
bl      core::panicking::panic                  ; AArch64
call    alloc::raw_vec::RawVec<*>::grow_one     ; Vec capacity exceeded
call    core::slice::index::slice_index_len_fail
```

**Why it matters:**
- Each bounds check adds a compare + conditional branch
- The panic path code pollutes the icache even though it's (almost) never executed
- The compiler's optimizer treats code before and after the check as separate regions,
  limiting optimization scope
- Multiple bounds checks in a loop can prevent vectorization

**How to count them:**
```bash
# In collected ASM, count panic-related calls:
grep -c 'panic\|slice_index\|grow_one' /tmp/asm-before.s
```

**Fixes (ordered by preference):**
1. Use iterators instead of indexing: `for item in slice.iter()` instead of `for i in 0..n { slice[i] }`
2. Use `.chunks_exact()` or `.windows()` for known access patterns
3. Assert the length once before the loop: `assert!(n <= slice.len())`
4. `unsafe { slice.get_unchecked(i) }` with a safety comment proving the index is valid
5. Split the loop to handle the "fits SIMD width" part separately from remainder

**Verification**: After fixing, re-collect ASM and confirm the panic call is gone.
Also verify with `cargo test` that no bounds are violated.

**Reference**: Rust Reference on [Index operations](https://doc.rust-lang.org/reference/expressions/array-expr.html),
The Rust Performance Book on [Bounds Checking](https://nnethercote.github.io/perf-book/bounds-checks.html).

## 2. Register Spills (High)

**What it looks like:**
```
; x86-64: stack save/restore in the function body (not prologue/epilogue)
mov     [rsp+0x48], rax       ; spill
; ... other instructions ...
mov     rax, [rsp+0x48]       ; reload

; AArch64:
str     x19, [sp, #0x30]      ; spill
; ... other instructions ...
ldr     x19, [sp, #0x30]      ; reload
```

**How to count them:**
```bash
# x86-64: count stack accesses in function body
grep -c '\[rsp' /tmp/asm-before.s

# AArch64: count stack accesses beyond prologue/epilogue
grep -c '\[sp,' /tmp/asm-before.s
```

**Why it matters:**
- Each spill+reload pair costs 5-10 cycles (L1 cache latency both ways)
- Spills indicate the register allocator ran out of registers
- On x86-64 (16 GP registers), spills in complex functions are common
- On AArch64 (31 GP registers), spills indicate severe complexity

**Impact estimate:**
- Count spill+reload pairs in the hot loop body
- Multiply by ~8 cycles per pair
- Multiply by iterations per call
- Compare to total function cost (from benchmark)

**Fixes:**
1. Split the function: move cold paths into separate `#[cold] #[inline(never)]` functions
2. Reduce live variables: recompute cheap values instead of keeping them alive
3. Reduce scope: use blocks `{ }` to limit variable lifetimes
4. Simplify control flow: fewer branches = fewer merge points = fewer live variables

## 3. Long Dependency Chains (High)

**What it looks like:**
A sequence of instructions where each depends on the result of the previous one:
```asm
; Serial chain — CPU cannot execute these in parallel
ldr     x0, [x1]           ; cycle 0-3: load (4 cycle latency)
add     x0, x0, x2         ; cycle 4: depends on load result
lsl     x0, x0, #3         ; cycle 5: depends on add result
ldr     x0, [x0]           ; cycle 5-8: pointer chase, depends on shift
add     x0, x0, x3         ; cycle 9: depends on second load
```
Total: ~9 cycles for 5 instructions. The CPU is stalled most of the time.

**How to detect:**
Trace the data dependencies through the ASM. If register X is written then immediately
read by the next instruction, which writes to X, which is read by the next... that's
a dependency chain. The length in cycles is the sum of latencies.

**Why it matters:**
Modern CPUs can execute 4-8 instructions per cycle out-of-order, BUT only if there
are independent instructions to fill the pipeline. A serial dependency chain of
length N takes at minimum N cycles regardless of CPU width.

**Fixes:**
1. **Unroll and interleave**: Process two or more elements simultaneously with independent chains
   ```rust
   // Before: one chain
   for x in data { sum += expensive(x); }

   // After: two independent chains
   let (mut sum0, mut sum1) = (0, 0);
   for chunk in data.chunks_exact(2) {
       sum0 += expensive(chunk[0]);  // chain A
       sum1 += expensive(chunk[1]);  // chain B (independent!)
   }
   let sum = sum0 + sum1;
   ```
2. **Restructure to break chains**: Reorder operations so independent work separates dependent steps
3. **Reduce chain length**: Use faster instructions (LEA instead of mul+add, fused multiply-add)

**Reference**: Agner Fog's [Optimizing software in C++](https://www.agner.org/optimize/optimizing_cpp.pdf),
Chapter 9: "Dependency chains".

## 4. Missed Vectorization (High)

**What it looks like:**
Scalar instructions processing one element at a time in a loop over contiguous data:
```asm
; Processing 1 byte/word at a time
.loop:
  ldrb    w0, [x1]         ; load 1 byte
  ; ... process ...
  add     x1, x1, #1       ; advance 1 byte
  cmp     x1, x2
  b.lo    .loop
```

When SIMD instructions could process 16/32/64 bytes at a time.

**Why it matters:**
- NEON: 16 bytes/cycle (16x speedup potential)
- AVX2: 32 bytes/cycle (32x speedup potential)
- AVX-512: 64 bytes/cycle (64x speedup potential)

**Common vectorization blockers (check these in the LLVM-IR):**
1. **Function calls in loop body**: LLVM won't vectorize loops with arbitrary calls
2. **Loop-carried dependencies**: Each iteration depends on the previous iteration's result
3. **Complex control flow**: if/else in the loop body (though masked operations can help)
4. **Non-contiguous access**: Stride > 1 or random access patterns
5. **Small iteration count**: Not worth vectorizing if < 4-8 iterations
6. **Aliasing concerns**: LLVM can't prove input/output don't overlap (add `#[restrict]`-like hints)

**How to investigate:**
```bash
# Check LLVM-IR for vectorization remarks:
RUSTFLAGS="-C target-cpu=native -C llvm-args=-pass-remarks-analysis=loop-vectorize" \
  cargo build --release 2>&1 | grep -i 'vectorize\|remark'

# Or check LLVM-IR directly:
cargo asm --lib -p scanner-rs --llvm 'function_name'
# Look for vector types: <16 x i8>, <4 x i32>, etc.
```

**Fixes:**
1. Remove function calls from loop body (inline them)
2. Break loop-carried dependencies (accumulate into multiple independent sums)
3. Use `.chunks_exact()` to guarantee alignment and size
4. Use explicit SIMD intrinsics via `std::arch` if auto-vectorization fails
5. Try `core::simd` (portable SIMD, nightly) for cross-platform vectorization

**Reference**: LLVM Vectorizer documentation: https://llvm.org/docs/Vectorizers.html

## 5. Unnecessary Memory Traffic (Medium-High)

**What it looks like:**
```asm
; Value loaded, used, then reloaded instead of staying in a register:
ldr     x0, [x1, #8]       ; first load
; ... some instructions NOT writing to x0 or [x1+8] ...
ldr     x0, [x1, #8]       ; redundant reload!

; Or value stored then immediately reloaded:
str     x0, [x1]
ldr     x2, [x1]            ; could just: mov x2, x0
```

**Why it matters:**
Even L1 cache hits cost 3-5 cycles. Keeping values in registers costs 0 cycles.

**Common causes:**
1. **Aliasing**: Compiler can't prove `ptr_a` and `ptr_b` don't overlap, so it reloads
   after every store through `ptr_a` in case `ptr_b` aliases the same location
2. **Volatile-like patterns**: `UnsafeCell`, `Cell`, atomics force reloads
3. **Complex control flow**: Value defined on one path, used after merge — compiler
   may reload instead of keeping in register through all paths
4. **Struct field access through reference**: Each field access may reload the base pointer

**Fixes:**
1. Load values into local variables at the start of the hot section
2. Use `restrict`-like patterns (different types, or `&mut` exclusivity proofs)
3. Simplify control flow so the compiler can track values through all paths
4. For struct fields accessed repeatedly: load into locals, compute, write back

## 6. Suboptimal Instruction Selection (Medium)

**What it looks like:**
```asm
; Division where shift works:
udiv    x0, x0, x1          ; x1 known to be power of 2 at compile time?
; Should be: lsr x0, x0, #N

; Modulo where mask works:
udiv    x2, x0, x1          ; x1 known to be power of 2?
msub    x0, x2, x1, x0     ; remainder = x0 - (x0/x1)*x1
; Should be: and x0, x0, #(N-1)

; Multiply by small constant could use shift+add:
mul     x0, x0, x1          ; x1 = 3
; Could be: add x0, x0, x0, lsl #1  (x0 = x0 + x0*2)
```

**Why it matters:**
- Division: 7-90 cycles depending on ISA and operand width
- Shift: 1 cycle
- That's a 7-90x difference for a single instruction

**Note:** The compiler almost always optimizes division by compile-time constants.
If you see an actual `div` instruction, the divisor is likely a runtime value.
Check if it could be made const.

## 7. Cold Code Inlined Into Hot Path (Medium)

**What it looks like:**
Error handling, logging, or debug code appears interleaved with the hot loop body:
```asm
.hot_loop:
  ; ... hot path instructions ...
  cmp     x0, #0
  b.eq    .error_handling      ; branch to error code
  ; ... more hot path ...
  b       .hot_loop

; Error handling inlined right after the hot loop (wastes icache):
.error_handling:
  ; 20+ instructions for formatting error message
  ; call to logging/panic
  ; This code runs <0.01% of the time but occupies cache space
```

**Why it matters:**
- Hot loop body should fit in L1 instruction cache (32-64KB)
- Inlined cold code wastes icache space
- Larger code → more iTLB entries needed → more iTLB misses

**Fixes:**
1. Mark error/cold functions: `#[cold] #[inline(never)]`
2. Use `unlikely()` hints: `if unlikely(condition) { cold_path() }`
3. Move error formatting out of the hot function entirely
4. Check `#[inline(always)]` annotations — remove from cold functions

**Reference**: The Rust Performance Book on [Inlining](https://nnethercote.github.io/perf-book/inlining.html).

## 8. Excessive Branching (Medium)

**What it looks like:**
Many conditional branches in a tight loop:
```asm
.loop:
  cmp     w0, #1
  b.eq    .case1
  cmp     w0, #2
  b.eq    .case2
  cmp     w0, #3
  b.eq    .case3
  ; ... more cases ...
```

**Why it matters:**
- Branch predictor has limited capacity (~4000-8000 entries)
- Multiple branches in a loop body consume predictor entries
- Unpredictable branches (data-dependent) cost 12-20 cycles per mispredict

**When to investigate:** Count branches in the hot loop. If there are more than
2-3 conditional branches per iteration, consider branchless alternatives.

**Fixes:**
1. **Lookup table**: Replace match/switch with array indexing
2. **Branchless select**: Use conditional moves (`cmov` / `csel`)
3. **Bit manipulation**: Replace boolean chains with bitwise operations
4. **Predication**: Compute both paths and select the result

## 9. Function Call Overhead in Hot Loops (Medium)

**What it looks like:**
```asm
.loop:
  ; ... setup args ...
  call    some_function       ; x86-64
  bl      some_function       ; AArch64
  ; ... use result ...
  ; repeat
```

**Why it matters:**
- Direct call: ~3-5 cycles overhead (call + ret + possible spills)
- Indirect call (virtual dispatch): ~5-10 cycles + possible branch mispredict
- Functions called in loops should ideally be inlined

**When to investigate:**
- If the called function is small (<20 instructions), it should be inlined
- If it's a trait method (`dyn Trait`), it's virtual dispatch → consider monomorphization
- If it's a function from another crate, check if LTO is enabled

**Fixes:**
1. `#[inline]` or `#[inline(always)]` on small hot functions
2. Enable LTO: `lto = "thin"` or `lto = "fat"` in Cargo.toml
3. Replace `dyn Trait` with generic `T: Trait` for hot-path dispatch
4. Manually inline if the compiler won't cooperate

## 10. Alignment Issues (Low-Medium)

**What it looks like:**
```asm
; Unaligned SIMD loads (slower than aligned):
vmovdqu  ymm0, [rdi]        ; unaligned load (works but may be slower)
; vs
vmovdqa  ymm0, [rdi]        ; aligned load (faster, requires 32-byte alignment)

; AArch64 unaligned load (usually fast but check):
ldr      q0, [x0]           ; may cross cache line boundary
```

**Why it matters:**
- Cache line split: ~2x latency if access crosses a 64-byte boundary
- SIMD alignment: Some SIMD operations require or prefer aligned data
- Page split: ~100x latency if access crosses a 4KB page boundary (rare)

**When to investigate:**
Only if you see high L1 cache miss rates or unexpectedly slow SIMD code.
Modern CPUs handle unaligned access well in most cases.

**Fixes:**
1. `#[repr(align(N))]` on structs that feed SIMD operations
2. Use `.align_to::<T>()` for runtime alignment checks
3. Ensure hot arrays start at cache-line boundaries

## Verification Checklist

After identifying any red flag, always:

- [ ] **Measure before fixing**: Benchmark the current state
- [ ] **Collect ASM evidence**: Save the ASM showing the issue
- [ ] **Apply one fix at a time**: Don't combine multiple changes
- [ ] **Verify ASM changed**: Re-collect and diff — did the codegen actually improve?
- [ ] **Verify benchmark improved**: Run against baseline — did wall-clock time drop?
- [ ] **Run tests**: Ensure correctness is preserved
- [ ] **Cross-check both ISAs**: If targeting both x86-64 and AArch64, verify on both
