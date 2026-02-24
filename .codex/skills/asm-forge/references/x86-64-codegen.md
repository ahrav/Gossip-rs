# x86-64 Codegen Patterns for Rust

Reference for reading x86-64 assembly emitted by rustc/LLVM and identifying
optimization opportunities.

## Registers

### General Purpose (16 registers)
| Register | Convention | Notes |
|----------|-----------|-------|
| `rax` | Return value, scratch | Accumulator |
| `rcx` | 4th arg (Windows), scratch | Counter for shifts/loops |
| `rdx` | 3rd arg, scratch | Used in div/mul |
| `rbx` | Callee-saved | Must be preserved |
| `rsp` | Stack pointer | Don't touch |
| `rbp` | Frame pointer (optional) | Callee-saved |
| `rsi` | 2nd arg (SysV) | Source index |
| `rdi` | 1st arg (SysV) | Destination index |
| `r8-r11` | Args 5-6, scratch | Caller-saved |
| `r12-r15` | Callee-saved | Must be preserved, push/pop overhead |

**Key insight**: Only 16 GP registers. Complex functions with many live variables
will spill to stack. x86-64 is more spill-prone than AArch64 (31 GP registers).

### SIMD Registers
| Registers | Width | ISA |
|-----------|-------|-----|
| `xmm0-xmm15` | 128-bit | SSE |
| `ymm0-ymm15` | 256-bit | AVX/AVX2 |
| `zmm0-zmm31` | 512-bit | AVX-512 |

## Calling Convention (System V AMD64 — Linux/macOS)

- Args: `rdi, rsi, rdx, rcx, r8, r9` (integer/pointer), `xmm0-xmm7` (float)
- Return: `rax` (integer), `xmm0` (float)
- Callee-saved: `rbx, rbp, r12-r15`
- Caller-saved: everything else

**Spill indicator**: If you see `push rbx` / `push r12` at function entry, the
compiler needs callee-saved registers → function has high register pressure.

## Common rustc/LLVM Codegen Patterns

### Bounds Check Pattern
```asm
; Rust: slice[i]
cmp     rdi, rsi            ; compare index against length
jae     .panic              ; jump if above or equal → panic path
mov     al, [rdx + rdi]     ; the actual access

; ... later in the function or a separate section:
.panic:
  lea     rdi, [rip + .Lpanic_loc]
  call    core::panicking::panic_bounds_check
  ud2                       ; unreachable
```

**Red flag**: Every `cmp + jae` pair followed by a panic call is a bounds check.
Count them in hot loops. Each one:
- Adds a branch (usually predicted correctly, so ~0 cycles normally)
- Adds cold code that pollutes icache
- Prevents some optimizations (compiler can't prove what happens after the check)

**Fix**: Use iterators (`.iter()`, `.chunks_exact()`), or `unsafe { get_unchecked() }`
with a safety comment proving the index is in bounds.

### Option/Result Discriminant Check
```asm
; Rust: match opt { Some(v) => ..., None => ... }
; Option<NonZeroU32> uses niche optimization (0 = None)
test    eax, eax
je      .none_branch

; Option<u32> without niche: discriminant is separate byte
cmp     byte [rsp+offset], 0
je      .none_branch
```

**Red flag in hot loops**: Discriminant checks that could be eliminated if the
value is known to always be `Some` at that point. Consider restructuring to
avoid the Option, or using sentinel values.

### Function Prologue/Epilogue (Spill Indicators)
```asm
; Light function (few registers needed):
push    rbx                 ; save 1 callee-saved register
; ... body ...
pop     rbx
ret

; Heavy function (many registers needed):
push    rbp
push    r15
push    r14
push    r13
push    r12
push    rbx
sub     rsp, 48             ; 48 bytes of stack space for locals
; ... body with many [rsp+offset] accesses ...
add     rsp, 48
pop     rbx
pop     r12
pop     r13
pop     r14
pop     r15
pop     rbp
ret
```

**Red flag**: If a hot function pushes 4+ callee-saved registers AND has
`sub rsp, N` with N > 32, it has significant register pressure. Consider:
- Breaking into smaller functions
- Reducing the number of live variables at any point
- Moving cold paths into separate `#[cold]` functions

### Loop Patterns
```asm
; Counted loop (compiler knows iteration count)
.loop:
  ; ... body ...
  add     rdi, 1           ; or inc rdi
  cmp     rdi, rsi         ; compare against limit
  jne     .loop            ; or jb (below) for unsigned

; Pointer-based loop (iterating through memory)
.loop:
  ; ... body using [rdi] ...
  add     rdi, 8           ; advance pointer by element size
  cmp     rdi, rsi         ; compare against end pointer
  jne     .loop

; Unrolled loop (compiler decided to unroll)
.loop:
  ; ... body × N (2, 4, or 8 copies) ...
  add     rdi, N*elem_size
  cmp     rdi, rsi
  jne     .loop
```

**Good sign**: Unrolled loops mean the compiler is optimizing.
**Red flag**: Non-unrolled tight loop with complex body → check if unrolling
or SIMD would help.

### Conditional Move (Branchless)
```asm
; Rust: if cond { a } else { b } — sometimes compiled branchless
cmp     edi, 42
cmovge  eax, ecx           ; conditional move: eax = ecx if edi >= 42

; vs branching version (worse for unpredictable conditions):
cmp     edi, 42
jl      .else
mov     eax, ecx
jmp     .end
.else:
mov     eax, edx
.end:
```

**Opportunity**: If you see a branch where a `cmov` would work, the compiler
may need help. Try:
- Branchless arithmetic: `let result = [b, a][(cond) as usize];`
- `core::cmp::min/max` (often compiles to `cmov`)

### SIMD Auto-Vectorization
```asm
; Good: compiler auto-vectorized a byte comparison loop
.loop:
  vmovdqu ymm0, [rdi]         ; load 32 bytes
  vpcmpeqb ymm1, ymm0, ymm2  ; compare 32 bytes at once
  vpmovmskb eax, ymm1         ; extract comparison results
  ; ...
  add     rdi, 32
  cmp     rdi, rsi
  jne     .loop

; Bad: scalar fallback
.loop:
  movzx   eax, byte [rdi]     ; load 1 byte
  cmp     al, cl               ; compare 1 byte
  ; ...
  inc     rdi
  cmp     rdi, rsi
  jne     .loop
```

**Check**: Is the loop processing elements one at a time when SIMD exists?
Common blockers for auto-vectorization:
- Loop body has side effects (function calls)
- Loop-carried dependencies
- Complex control flow in loop body
- Non-contiguous memory access

### LEA for Arithmetic
```asm
; Compiler uses LEA for multi-operand arithmetic (fast, uses AGU port)
lea     rax, [rdi + rsi*4 + 16]   ; rax = rdi + rsi*4 + 16 in one instruction

; vs multiple instructions:
mov     rax, rsi
shl     rax, 2
add     rax, rdi
add     rax, 16
```

**Good sign**: Heavy LEA usage means the compiler is using the address generation
unit for arithmetic. This is free parallelism.

## Instruction Cost Guide (Approximate)

| Instruction | Latency (cycles) | Throughput (per cycle) |
|-------------|:-:|:-:|
| `mov reg, reg` | 0 (eliminated) | N/A |
| `add/sub/and/or/xor` | 1 | 3-4 |
| `lea` | 1 | 2 |
| `imul` (64-bit) | 3 | 1 |
| `div` (64-bit) | 35-90 | 35-90 (fully pipelined: NO) |
| `cmp + jcc` (predicted) | 1 | 1-2 |
| `cmp + jcc` (mispredicted) | ~15-20 | - |
| `cmov` | 1 | 1 |
| `mov reg, [mem]` (L1 hit) | 4-5 | 2 |
| `mov reg, [mem]` (L2 hit) | ~12 | - |
| `mov reg, [mem]` (L3 hit) | ~30-40 | - |
| `mov reg, [mem]` (DRAM) | ~100-200 | - |
| `call` (direct) | ~3 | 1 |
| `call` (indirect/virtual) | ~5 + branch prediction | 1 |
| `vmovdqu ymm` (L1 hit) | 4-5 | 2 |
| `vpaddb/vpcmpeqb ymm` | 1 | 2-3 |

**Key insight**: Division is catastrophically expensive. Multiply by reciprocal
or use shifts for powers of 2. The compiler usually does this, but check.

## x86-64 Specific Optimization Opportunities

### Flag Reuse
x86-64 has implicit flags register. Some patterns set flags redundantly:
```asm
; Bad: test after arithmetic that already set flags
sub     eax, 1
test    eax, eax     ; redundant: sub already set ZF
je      .done

; Good: compiler should eliminate the test
sub     eax, 1
je      .done        ; use flags from sub directly
```

### Memory Operands
x86-64 can fold memory loads into ALU instructions:
```asm
; Good: fused load+operate
add     eax, [rdi]          ; load and add in one micro-op

; Less good: separate load then operate
mov     ecx, [rdi]
add     eax, ecx
```

If you see separate load+operate where fusion should work, something is
preventing it (aliasing, alignment, or the value is needed again later).

### SSE/AVX Transition Penalties
Mixing SSE (128-bit `xmm`) and AVX (256-bit `ymm`) instructions causes
a state transition penalty. Look for:
```asm
; Penalty: SSE instruction after AVX without VZEROUPPER
vmovdqu ymm0, [rdi]         ; AVX
; ... some code ...
movdqa  xmm1, [rsi]         ; SSE ← causes transition penalty!

; Fix: use VEX-encoded version
vmovdqa xmm1, [rsi]         ; AVX (VEX prefix) — no penalty
```

The compiler usually handles this, but check when mixing hand-written
intrinsics with auto-vectorized code.
