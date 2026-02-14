# ARM SVE / SVE2 in Rust

Reference for ARM's Scalable Vector Extension and its use from Rust.
SVE provides a width-agnostic SIMD programming model where vector length
is determined by hardware, not code. Covers intrinsics, predicated loop
patterns, hardware availability, and current Rust support status.

**CRITICAL**: SVE is NOT available on Apple Silicon (M1-M4). Apple has
not adopted SVE. All local development on macOS/Apple hardware must use
NEON. SVE targets server-class ARM chips (Graviton 3/4, Neoverse, A64FX).

## Scalable Vector Model

Unlike NEON (fixed 128-bit) or AVX2 (fixed 256-bit), SVE vectors are
**scalable**: 128 to 2048 bits wide in 128-bit increments. The exact
width is implementation-defined and invisible to the programmer.

| Concept | Description |
|---------|-------------|
| VL (Vector Length) | Hardware-defined width of Z registers, in bits |
| `svcntb()` | Number of byte lanes = VL / 8 |
| `svcnth()` | Number of halfword lanes = VL / 16 |
| `svcntw()` | Number of word lanes = VL / 32 |
| `svcntd()` | Number of doubleword lanes = VL / 64 |

A binary compiled for Graviton 3 (256-bit VL) runs unchanged on A64FX
(512-bit VL) and automatically processes twice as many elements per
instruction. You cannot write `let chunk: [u8; 32] = ...` and assume it
fills a register -- the lane count is a runtime value from `svcntb()`.

### Register File

| Register Class | Count | Purpose |
|----------------|-------|---------|
| Z0-Z31 | 32 | Scalable vector registers (VL bits wide) |
| P0-P15 | 16 | Predicate registers (VL/8 bits wide) |
| FFR | 1 | First Fault Register (speculative loads) |

Z registers overlay NEON V registers: Z0[127:0] aliases V0.

## Predicate Registers

Predicates are SVE's defining feature. Every vector operation is governed
by a predicate register controlling which lanes are active. Each predicate
bit maps to one byte of vector width:
- `b8`: every bit is a lane mask
- `b16`: every 2nd bit governs a lane
- `b32`: every 4th bit governs a lane
- `b64`: every 8th bit governs a lane

```c
svbool_t all_bytes = svptrue_b8();                 // all byte lanes active
svbool_t all_words = svptrue_b32();                // all 32-bit lanes active
svbool_t first_four = svptrue_pat_b32(SV_VL4);    // first 4 word lanes
svbool_t pg = svwhilelt_b32(i, n);                 // lanes where i+lane < n
```

### Predicate Suffixes

| Suffix | Inactive lane behavior |
|--------|------------------------|
| `_z` | Zeroing -- inactive lanes produce zero |
| `_m` | Merging -- inactive lanes keep previous value |
| `_x` | Don't care -- compiler picks fastest encoding |

Use `_x` when you do not read inactive lanes (maximum performance).
Use `_z` when feeding into a reduction. Use `_m` when accumulating.

## Key Intrinsics

All intrinsics use C ACLE names. Rust does not yet expose SVE intrinsics
in `std::arch::aarch64` (see Rust Support Status below).

### Predicated Load and Store

```c
svuint8_t  svld1_u8(svbool_t pg, const uint8_t *ptr);    // load bytes
svuint32_t svld1_u32(svbool_t pg, const uint32_t *ptr);   // load words
svst1_u8(svbool_t pg, uint8_t *ptr, svuint8_t data);      // store bytes
svst1_u32(svbool_t pg, uint32_t *ptr, svuint32_t data);   // store words
// Gather/scatter (indexed access)
svuint32_t svld1_gather_u32offset_u32(svbool_t pg, const uint32_t *base,
                                       svuint32_t offsets);
```

### Arithmetic and Compare

```c
svuint8_t svadd_u8_x(svbool_t pg, svuint8_t a, svuint8_t b);   // a + b
svuint8_t svsub_u8_x(svbool_t pg, svuint8_t a, svuint8_t b);   // a - b
svuint32_t svmul_u32_x(svbool_t pg, svuint32_t a, svuint32_t b);

svbool_t svcmpeq_u8(svbool_t pg, svuint8_t a, svuint8_t b);    // a == b
// Compare returns a predicate: true where comparison holds

float svaddv_f32(svbool_t pg, svfloat32_t vec);  // horizontal sum
float svmaxv_f32(svbool_t pg, svfloat32_t vec);  // horizontal max
```

### First-Faulting Loads

Safe speculative memory access. The first active element must be at a
valid address; subsequent elements may fault silently -- the hardware
clears the FFR for those lanes instead of raising a signal.

```c
svuint8_t svldff1_u8(svbool_t pg, const uint8_t *ptr);  // speculative load
svbool_t  svrdffr();    // read First Fault Register: which lanes succeeded?
```

Use cases: string search without knowing length, processing near page
boundaries, any situation where the valid extent is unknown.

## Loop Control Without Remainder

This is SVE's killer feature. The `svwhilelt` predicate eliminates the
scalar tail loop that fixed-width SIMD always requires.

**Traditional NEON** (requires cleanup):
```
main_loop:   process 16 bytes per iteration (fixed 128-bit)
remainder:   scalar loop for leftover 0-15 bytes
```

**SVE** (no cleanup):
```c
void vector_add(float *dst, const float *a, const float *b, int64_t n) {
    for (int64_t i = 0; i < n; i += svcntw()) {
        svbool_t pg = svwhilelt_b32(i, n);           // predicate for this iter
        svfloat32_t va = svld1_f32(pg, &a[i]);       // predicated load
        svfloat32_t vb = svld1_f32(pg, &b[i]);       // predicated load
        svfloat32_t vc = svadd_f32_x(pg, va, vb);    // predicated add
        svst1_f32(pg, &dst[i], vc);                   // predicated store
    }
    // No remainder loop. The last iteration's predicate automatically
    // masks off out-of-bounds lanes. If n=100 and VL gives 8 lanes,
    // the final iteration processes 96-99 (active) and 100-103 (masked).
}
```

The loop body is identical for every iteration including the last one.
The predicate does all the work. This eliminates an entire class of
off-by-one bugs that plague fixed-width SIMD tail handling.

## SVE2 Additions

SVE2 is mandatory in ARMv9-A. It is a strict superset of SVE -- every
SVE instruction is valid SVE2. New instruction categories:

| Category | Key Instructions | Use Case |
|----------|-----------------|----------|
| Extended integer arithmetic | Widening multiply-add, saturating ops | DSP, media |
| Bitwise permutations | BDEP, BEXT, BGRP | Bit-level manipulation |
| Complex number arithmetic | FCMLA (rotate + accumulate) | Signal processing |
| Cryptographic operations | AES, SM4, SHA3 on SVE registers | Crypto acceleration |
| Narrowing operations | Narrowing shifts, saturating narrows | Format conversion |
| Histogram / match | HISTCNT, HISTSEG, MATCH | Databases, compression |
| Polynomial multiplication | PMUL, PMULLB, PMULLT | CRC, error correction |
| Cross-lane operations | Extended TBL/TBX table lookup | Permutation, shuffling |

SVE1 targeted HPC/scientific computing. SVE2 broadens reach to media/DSP,
cryptography, database analytics, and general-purpose code.

## Hardware Availability

| Processor | Core | SVE | SVE2 | VL | Notes |
|-----------|------|:---:|:----:|:--:|-------|
| Fujitsu A64FX | Custom | Yes | No | 512-bit | Fugaku supercomputer (2020) |
| AWS Graviton 3 | Neoverse V1 | Yes | No | 256-bit | EC2 C7g/M7g/R7g |
| AWS Graviton 4 | Neoverse V2 | Yes | Yes | 128-bit | EC2 R8g |
| NVIDIA Grace | Neoverse V2 | Yes | Yes | 128-bit | Grace Hopper |
| Microsoft Cobalt 100 | Neoverse N2 | Yes | Yes | 128-bit | Azure ARM |
| Apple M1/M2/M3/M4 | Custom | **No** | **No** | N/A | Apple has NOT adopted SVE |
| Ampere Altra | Neoverse N1 | No | No | N/A | NEON only |
| AmpereOne | Custom | No | No | N/A | NEON only |

**Key observations**:

1. **Apple Silicon has NO SVE.** Any SVE code path requires a NEON
   fallback for Apple hardware. This is the top portability fact.

2. **Graviton 3 at 256-bit matches AVX2 width.** Both process 32 bytes
   per vector instruction. Real 2x throughput over NEON, but the same
   width as x86-64 AVX2 -- not wider.

3. **Most SVE2 chips use 128-bit vectors.** Neoverse V2/N2 implement
   SVE2 at only 128-bit. No throughput gain over NEON at this width --
   the advantage is purely the programming model (predication, no tail
   loops, forward compatibility with wider future hardware).

4. **512-bit SVE exists only on A64FX.** No mainstream server chip
   exceeds 256-bit.

## Rust Support Status

As of Rust 1.93 (February 2026), SVE intrinsics are **NOT available**
in stable or nightly Rust.

| Feature | Status |
|---------|--------|
| NEON intrinsics (`std::arch::aarch64`) | **Stable** |
| `is_aarch64_feature_detected!("sve")` | **Stable** (runtime detection) |
| `is_aarch64_feature_detected!("sve2")` | **Stable** (runtime detection) |
| `#[target_feature(enable = "sve")]` | Stable attribute, no intrinsics to call |
| SVE types (`svfloat32_t`, `svbool_t`) | Not available |
| SVE intrinsics (`svld1`, `svwhilelt`) | Not available |

A draft PR to add SVE to `stdarch` was opened December 2023 but closed
without merging in November 2025. No active stabilization effort exists.

### Workarounds

1. **Auto-vectorization** (recommended). Compile with SVE-capable
   target-cpu and let LLVM emit SVE from scalar/NEON code:
   ```bash
   # Graviton 3 (Neoverse V1, SVE 256-bit)
   RUSTFLAGS="-C target-cpu=neoverse-v1" cargo build --release
   # Graviton 4 / Grace (Neoverse V2, SVE2 128-bit)
   RUSTFLAGS="-C target-cpu=neoverse-v2" cargo build --release
   ```
   Works for simple loops. Unreliable for complex algorithms. Always
   verify SVE emission with `objdump`.

2. **Inline assembly** (`core::arch::asm!`). Write SVE instructions
   directly. Nightly-only for SVE register constraints. Fragile.

3. **C FFI boundary**. Write SVE code in C using ACLE intrinsics
   (GCC 10+ / Clang 12+), compile as static lib, call from Rust.
   Most practical path for complex SVE algorithms today.

### Practical Recommendation for Rust (2026)

1. Write NEON intrinsics for the hot path (stable, portable to all AArch64)
2. Compile with `-C target-cpu=neoverse-v1` on SVE servers for LLVM
   auto-vectorization into wider SVE
3. Do NOT hand-write SVE intrinsics in Rust until `std::arch` support lands
4. If SVE intrinsics are essential, use a C FFI boundary

## When to Use SVE vs NEON

### Prefer NEON

- Targeting Apple Silicon (SVE not available)
- Writing portable AArch64 code (NEON is universal)
- Need explicit SIMD intrinsics in Rust (NEON stable in `std::arch`)
- Deterministic 128-bit width simplifies reasoning

### Prefer SVE

- Server-side batch processing on Graviton 3 or A64FX where wider
  vectors provide genuine throughput gains
- HPC / scientific computing where VL-agnostic code runs across hardware
- Auto-vectorization is sufficient (let LLVM handle SVE emission)
- Future-proofing for wider SVE implementations

### Decision Matrix

| Criterion | NEON | SVE |
|-----------|:----:|:---:|
| Apple Silicon support | Yes | No |
| Rust intrinsics stable | Yes | No |
| Width > 128-bit available | No | Yes (hardware-dependent) |
| No tail loop needed | No | Yes (predicated loops) |
| Forward-compatible with wider HW | No | Yes |
| Available on all AArch64 | Yes | No |
