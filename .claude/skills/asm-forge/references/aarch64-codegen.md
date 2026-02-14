# AArch64 Codegen Patterns for Rust

Reference for reading AArch64 (ARM64) assembly emitted by rustc/LLVM and
identifying optimization opportunities. Applies to Apple Silicon (M1/M2/M3/M4)
and AWS Graviton (Neoverse V1/V2).

## Registers

### General Purpose (31 registers — much more than x86-64's 16)
| Register | Convention | Notes |
|----------|-----------|-------|
| `x0-x7` | Arguments + return | First 8 args passed in registers |
| `x8` | Indirect result | Struct return pointer |
| `x9-x15` | Scratch (caller-saved) | Temporaries |
| `x16-x17` | Intra-procedure call | Linker veneers |
| `x18` | Platform register | Reserved (don't use) |
| `x19-x28` | Callee-saved | Must be preserved across calls |
| `x29` | Frame pointer (FP) | Callee-saved |
| `x30` | Link register (LR) | Return address |
| `sp` | Stack pointer | 16-byte aligned |
| `xzr` | Zero register | Reads as 0, writes discarded |

**Key insight**: 31 GP registers means significantly less register pressure than
x86-64 (16 GP). Spills are much less common. If you see spills on AArch64, the
function is *extremely* complex and should definitely be split.

`w0-w28` are the 32-bit views of `x0-x28`.

### SIMD/FP Registers (32 registers)
| Register | Width | Notes |
|----------|-------|-------|
| `v0-v7` / `q0-q7` | 128-bit | Arguments + scratch |
| `v8-v15` | 128-bit | Lower 64 bits callee-saved |
| `v16-v31` | 128-bit | Scratch |

NEON: 128-bit fixed-width SIMD (always available)
SVE: Scalable Vector Extension (128-2048 bit, Graviton3+)

## Calling Convention (AAPCS64)

- Args: `x0-x7` (integer/pointer), `v0-v7` (float/SIMD)
- Return: `x0` (integer), `v0` (float/SIMD)
- Callee-saved: `x19-x28, x29(fp), x30(lr)`, `v8-v15` (lower 64 bits)
- Stack: 16-byte aligned, grows downward

**Spill indicator**: `stp x29, x30, [sp, #-N]!` saves frame pointer + link register.
If you also see `stp x19, x20, [sp, ...]` etc., the function needs callee-saved
registers → elevated register pressure (unusual on AArch64).

## Common rustc/LLVM Codegen Patterns

### Bounds Check Pattern
```asm
; Rust: slice[i]
cmp     x0, x1              ; compare index against length
b.hs    .panic              ; branch if higher-or-same (unsigned >=) → panic

ldrb    w2, [x3, x0]       ; the actual access

; panic path (usually at end of function or in separate section):
.panic:
  adrp    x0, .Lpanic_loc@PAGE
  add     x0, x0, .Lpanic_loc@PAGEOFF
  bl      core::panicking::panic_bounds_check
  brk     #0x1               ; unreachable (trap)
```

**Red flag**: `cmp + b.hs` (or `b.cs`) followed by `bl core::panicking::*` is a
bounds check. Same fix as x86-64: iterators or `get_unchecked()`.

### Conditional Select (Branchless)
```asm
; AArch64 excels at branchless code with CSEL family
cmp     w0, #42
csel    w1, w2, w3, ge      ; w1 = (w0 >= 42) ? w2 : w3

; Variants:
csinc   w0, w1, wzr, eq     ; w0 = (eq) ? w1 : 0+1  (conditional increment)
csinv   w0, w1, wzr, ne     ; w0 = (ne) ? w1 : ~0    (conditional invert)
csneg   w0, w1, w2, lt      ; w0 = (lt) ? w1 : -w2   (conditional negate)
```

**Opportunity**: AArch64 has richer branchless primitives than x86-64. If you see
a branch for a simple select, the compiler may need help. Use `min/max`,
conditional expressions, or explicit branchless patterns.

### Load/Store Pair (LDP/STP)
```asm
; AArch64 can load/store two registers at once
ldp     x0, x1, [x2]       ; load x0 from [x2], x1 from [x2+8]
stp     x0, x1, [x2]       ; store both

; Pre-index (update base):
ldp     x0, x1, [x2, #16]! ; load from [x2+16], then x2 += 16

; Post-index:
ldp     x0, x1, [x2], #16  ; load from [x2], then x2 += 16
```

**Good sign**: `ldp/stp` usage means the compiler is exploiting AArch64's ability
to move 16 bytes per instruction. If you see two separate `ldr` instructions to
adjacent addresses, the compiler missed an LDP opportunity (rare, but check).

### Function Prologue/Epilogue
```asm
; Minimal function (leaf, no callee-saved registers needed):
; No prologue/epilogue at all — just the body + ret

; Standard function:
stp     x29, x30, [sp, #-16]!   ; save FP and LR, allocate 16 bytes
mov     x29, sp                   ; set up frame pointer
; ... body ...
ldp     x29, x30, [sp], #16     ; restore FP and LR
ret

; Heavy function (needs callee-saved regs):
stp     x29, x30, [sp, #-64]!
stp     x19, x20, [sp, #16]
stp     x21, x22, [sp, #32]
stp     x23, x24, [sp, #48]
mov     x29, sp
; ... body ...
ldp     x23, x24, [sp, #48]
ldp     x21, x22, [sp, #32]
ldp     x19, x20, [sp, #16]
ldp     x29, x30, [sp], #64
ret
```

**Red flag**: If a hot function saves 3+ pairs of callee-saved registers
(6+ registers), it has unusually high register pressure for AArch64. Consider
splitting or simplifying.

### NEON SIMD (128-bit)
```asm
; Processing 16 bytes at a time with NEON
.loop:
  ldr     q0, [x0]              ; load 16 bytes into v0
  cmeq    v1.16b, v0.16b, v2.16b  ; compare 16 bytes against pattern
  umaxv   b3, v1.16b            ; horizontal max (any match?)
  fmov    w4, s3                ; move result to GP register
  cbnz    w4, .found            ; branch if any match
  add     x0, x0, #16
  cmp     x0, x1
  b.lo    .loop

; Scalar fallback (bad):
.loop:
  ldrb    w2, [x0]
  cmp     w2, w3
  b.eq    .found
  add     x0, x0, #1
  cmp     x0, x1
  b.lo    .loop
```

**Check**: Is the loop processing one byte at a time? On AArch64, NEON is always
available (no feature detection needed), so there's no reason for scalar byte loops
on array data.

### Address Calculation
```asm
; AArch64 addressing modes are powerful
ldr     x0, [x1, x2, lsl #3]   ; x0 = mem[x1 + x2*8]  (scaled register offset)
ldr     x0, [x1, #16]           ; x0 = mem[x1 + 16]     (immediate offset)
ldr     x0, [x1, w2, sxtw #3]  ; x0 = mem[x1 + sign_extend(w2)*8]

; ADRP + ADD for PC-relative addressing (globals, statics):
adrp    x0, symbol@PAGE         ; load page address
add     x0, x0, symbol@PAGEOFF  ; add page offset
ldr     x0, [x0]                ; load the value
```

### Bitfield Operations
```asm
; AArch64 has excellent bitfield instructions
ubfx    w0, w1, #4, #8     ; extract 8 bits starting at bit 4 (unsigned)
sbfx    w0, w1, #4, #8     ; same but sign-extended
bfi     w0, w1, #4, #8     ; insert 8 bits of w1 into w0 at bit 4
bfxil   w0, w1, #4, #8     ; extract and insert into low bits

; These replace multiple shift+mask operations
; If you see: lsr + and (shift then mask), the compiler should use ubfx
```

**Good sign**: `ubfx/sbfx/bfi` usage for flag/field extraction. If you see manual
shift+mask chains for bitfield work, the compiler may have missed an optimization.

## Instruction Cost Guide (Apple M-series, approximate)

| Instruction | Latency (cycles) | Throughput |
|-------------|:-:|:-:|
| `mov/add/sub/and/orr` | 1 | 4-6 per cycle |
| `madd/msub` (multiply-add) | 3 | 2 per cycle |
| `sdiv/udiv` (64-bit) | 7-12 | 1 per 7-12 cycles |
| `csel/csinc/csneg` | 1 | 3-4 per cycle |
| `ldr` (L1 hit) | 3-4 | 2 per cycle |
| `ldp` (L1 hit) | 3-4 | 1 per cycle (2 regs) |
| `ldr` (L2 hit) | ~10 | - |
| `bl` (direct call) | 1-2 | 1 per cycle |
| `blr` (indirect call) | ~3-5 | 1 per cycle |
| `b.cond` (predicted) | 1 | 1-2 per cycle |
| `b.cond` (mispredicted) | ~12-14 | - |
| NEON arith (`add/sub/mul v`) | 2-4 | 2-4 per cycle |
| NEON load (`ldr q`) | 3-4 | 2 per cycle |

**Key differences from x86-64**:
- Branch misprediction is cheaper (~12-14 vs ~15-20 cycles)
- Conditional select (`csel`) is a single-cycle instruction (very cheap branchless)
- `madd` fused multiply-add is available for integers (not just FP)
- Division is faster than x86-64 (7-12 vs 35-90 cycles for 64-bit)

## AArch64 Specific Optimization Opportunities

### Fused Multiply-Add/Subtract
```asm
; AArch64 has integer fused multiply-add (not just FP)
madd    x0, x1, x2, x3     ; x0 = x1*x2 + x3 (one instruction, 3 cycles)

; vs separate multiply + add:
mul     x0, x1, x2          ; x0 = x1*x2 (3 cycles)
add     x0, x0, x3          ; x0 = x0+x3 (1 cycle, but serial dependency)
```

**Check**: If the compiler emits `mul` followed by `add`, it missed `madd`. Usually
the compiler handles this, but complex expressions may prevent it.

### Compare-and-Branch (CBZ/CBNZ/TBZ/TBNZ)
```asm
; Fused compare-and-branch (saves an instruction):
cbz     x0, .label          ; branch if x0 == 0
cbnz    x0, .label          ; branch if x0 != 0
tbz     x0, #7, .label      ; branch if bit 7 of x0 is 0
tbnz    x0, #7, .label      ; branch if bit 7 of x0 is 1

; vs separate compare then branch:
cmp     x0, #0
b.eq    .label               ; two instructions for the same thing
```

**Good sign**: `cbz/cbnz/tbz/tbnz` usage. If you see `cmp x0, #0` followed by
`b.eq`, the compiler missed the fusion (rare).

### Pre/Post Increment Addressing
```asm
; AArch64 supports pre- and post-increment addressing
; Great for loop pointer advancement:
ldr     x0, [x1], #8        ; load from [x1], then x1 += 8 (post-increment)
ldr     x0, [x1, #8]!       ; x1 += 8, then load from [x1] (pre-increment)

; This saves a separate ADD instruction for pointer advancement in loops
```

### Apple Silicon Specifics (M1/M2/M3/M4)

- **Wide decode**: 8 instructions per cycle (M1), 9 (M3). Very wide, loves ILP.
- **Large ROB**: ~630 entries (M1). Can look far ahead for independent work.
- **L1D cache**: 128KB (M1 P-core), 3-cycle latency. 2x larger than typical x86-64.
- **L2 cache**: 12-16MB shared. Very fast.
- **Branch prediction**: Excellent. Misprediction cost ~12 cycles (lower than x86-64).

**Implication**: Apple Silicon rewards ILP heavily. Multiple independent operations
in flight is more important than on x86-64 because the out-of-order window is larger.

### Graviton Specifics (Neoverse V1/V2)

- **Decode**: 5 instructions per cycle (V1). Narrower than Apple Silicon.
- **ROB**: ~256 entries (V1). Smaller OOO window.
- **L1D cache**: 64KB, 4-cycle latency.
- **L2 cache**: 1MB per core (V1), 2MB per core (V2).
- **SVE**: 256-bit fixed on Graviton3. Available for wider SIMD than NEON.

**Implication**: Graviton has a narrower pipeline. ILP still matters but there's
less room to exploit it. Memory latency is relatively more important.
