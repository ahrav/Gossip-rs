# AArch64 NEON / Advanced SIMD Intrinsics for Rust

Reference for AArch64 NEON (Advanced SIMD) intrinsics via `core::arch::aarch64`.
NEON is **mandatory** on AArch64 (ARMv8-A+). No runtime feature detection needed.

## Register Model

**32 x 128-bit SIMD/FP registers** named V0--V31, accessible at multiple widths:

| View  | Bits | Name      | Example Lanes             |
|-------|------|-----------|---------------------------|
| **B** | 8    | B0--B31   | Scalar byte               |
| **H** | 16   | H0--H31   | Scalar half-word          |
| **S** | 32   | S0--S31   | Scalar single-float       |
| **D** | 64   | D0--D31   | 1x64, 2x32, 4x16, 8x8   |
| **Q** | 128  | Q0--Q31   | 2x64, 4x32, 8x16, 16x8  |

Writing to D0 zeroes the upper 64 bits of V0. Assembly uses arrangement
suffixes: `.16B` (16 bytes, 128-bit), `.8H` (8 half-words), `.4S` (4 singles).

**AAPCS64**: V0--V7 caller-saved (args/return). V8--V15 lower 64 bits
callee-saved, upper half scratch. V16--V31 fully caller-saved.

**Type suffixes** map to Rust types:

| Suffix | Rust Type (128-bit) | Lanes | Suffix | Rust Type (128-bit) | Lanes |
|--------|---------------------|-------|--------|---------------------|-------|
| `_u8`  | `uint8x16_t`        | 16    | `_s8`  | `int8x16_t`         | 16    |
| `_u16` | `uint16x8_t`        | 8     | `_s16` | `int16x8_t`         | 8     |
| `_u32` | `uint32x4_t`        | 4     | `_s32` | `int32x4_t`         | 4     |
| `_u64` | `uint64x2_t`        | 2     | `_f32` | `float32x4_t`       | 4     |
| `_p8`  | `poly8x16_t`        | 16    | `_f64` | `float64x2_t`       | 2     |

64-bit (D-register) variants: `uint8x8_t`, `uint16x4_t`, `uint32x2_t`, etc.

## Intrinsic Naming Convention

All intrinsics in `core::arch::aarch64` (stable since Rust 1.59). Pattern:

```
v <op> [modifier] [q] _ <type> [_n]
```

| Component    | Meaning                                                     |
|--------------|-------------------------------------------------------------|
| `v`          | Always present. Marks a NEON intrinsic.                     |
| `<op>`       | Operation: `add`, `ceq`, `ld1`, `bsl`, `tbl`, etc.         |
| `[modifier]` | `l`(widen), `n`(narrow), `q`(saturating), `r`(rounding), `p`(pairwise) |
| `q`          | 128-bit (Q register). Without `q` = 64-bit (D register).   |
| `_<type>`    | Element type: `_u8`, `_s16`, `_f32`, etc.                   |
| `_n`         | Immediate (compile-time constant) operand.                  |

| Intrinsic       | Breakdown                               | Operation            |
|-----------------|-----------------------------------------|----------------------|
| `vaddq_u8`      | v + add + q(128) + _u8                  | Add 16 bytes         |
| `vaddvq_u8`     | v + addv(across) + q + _u8             | Horizontal sum 16B   |
| `vshrq_n_u8`    | v + shr + q + _n(imm) + _u8            | Shift right by const |
| `vqmovn_u16`    | v + q(saturating) + movn(narrow) + _u16 | Saturating narrow    |
| `vld3q_u8`      | v + ld3(load-3-struct) + q + _u8        | Load+deinterleave 3  |
| `vbslq_u8`      | v + bsl(bit-select) + q + _u8          | Bitwise select       |

**The `q` ambiguity**: after the operation = 128-bit width; before = saturating.
Combined: `vqaddq_u8` = saturating add on 128-bit u8 vector.

## Key Intrinsics by Category

### Load / Store

```rust
// Contiguous loads/stores (always unaligned-safe, no penalty)
pub unsafe fn vld1q_u8(ptr: *const u8) -> uint8x16_t       // 16 bytes
pub unsafe fn vst1q_u8(ptr: *mut u8, a: uint8x16_t)

// Multi-structure: single-instruction interleave/de-interleave
pub unsafe fn vld2q_u8(ptr: *const u8) -> uint8x16x2_t     // 32B -> 2 regs
pub unsafe fn vld3q_u8(ptr: *const u8) -> uint8x16x3_t     // 48B -> 3 regs (RGB)
pub unsafe fn vld4q_u8(ptr: *const u8) -> uint8x16x4_t     // 64B -> 4 regs (RGBA)
pub unsafe fn vst2q_u8(ptr: *mut u8, a: uint8x16x2_t)
pub unsafe fn vst3q_u8(ptr: *mut u8, a: uint8x16x3_t)
```

`vld3q_u8` reads 48 bytes `[a0,b0,c0, a1,b1,c1, ...]` and de-interleaves
into `[a0..a15]`, `[b0..b15]`, `[c0..c15]`. Single hardware instruction.

### Arithmetic

```rust
pub fn vaddq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t   // add
pub fn vsubq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t   // subtract
pub fn vmulq_u16(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t  // multiply
pub fn vmlaq_u16(a: uint16x8_t, b: uint16x8_t, c: uint16x8_t) -> uint16x8_t  // a+(b*c)
pub fn vfmaq_f32(a: float32x4_t, b: float32x4_t, c: float32x4_t) -> float32x4_t  // FMA
```

FMA (`vfmaq`) is always available on AArch64 -- no feature flag needed.
Broadcast with `vdupq_n_u8(val)` / `vdupq_n_u32(val)` / `vdupq_n_f32(val)`.

### Compare

All comparisons return **full-width masks**: `0xFF` per element for true,
`0x00` for false. Return type is unsigned.

```rust
pub fn vceqq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // a == b
pub fn vcgtq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // a > b
pub fn vcltq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // a < b
pub fn vcgeq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // a >= b
pub fn vcleq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // a <= b
pub fn vceqzq_u8(a: uint8x16_t) -> uint8x16_t                 // a == 0
```

No `movemask` -- use `vmaxvq_u8(mask) != 0` for "any match?" checks.

### Bitwise

```rust
pub fn vandq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // AND
pub fn vorrq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // OR
pub fn veorq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // XOR
pub fn vbicq_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // a AND NOT(b)
pub fn vmvnq_u8(a: uint8x16_t) -> uint8x16_t                  // NOT

// Bitwise Select: per-bit mux. mask=1 -> b, mask=0 -> c
pub fn vbslq_u8(mask: uint8x16_t, b: uint8x16_t, c: uint8x16_t) -> uint8x16_t
```

`vbslq_u8` operates at **bit** granularity (not byte like x86 `_mm_blendv_epi8`).

### Shuffle / Permute

```rust
// Table lookup: 8-byte table (indices >= 8 -> 0)
pub unsafe fn vtbl1_u8(table: uint8x8_t, idx: uint8x8_t) -> uint8x8_t
// 16-byte table lookup (indices >= 16 -> 0). Equivalent to x86 PSHUFB.
pub fn vqtbl1q_u8(table: uint8x16_t, idx: uint8x16_t) -> uint8x16_t
// Multi-register tables: 32B / 48B / 64B
pub fn vqtbl2q_u8(t: uint8x16x2_t, idx: uint8x16_t) -> uint8x16_t
pub fn vqtbl4q_u8(t: uint8x16x4_t, idx: uint8x16_t) -> uint8x16_t

// Extract: concatenate a:b, select 16B window at byte offset N
pub fn vextq_u8<const N: i32>(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t

// Zip (interleave), Unzip (de-interleave), Transpose
pub fn vzip1q_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // low interleave
pub fn vzip2q_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // high interleave
pub fn vuzp1q_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // even elements
pub fn vuzp2q_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // odd elements
pub fn vtrn1q_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // even pairs
pub fn vtrn2q_u8(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t  // odd pairs
```

**Important**: `vtbl1_u8` = 8-byte D-register table. For 16-byte table use
`vqtbl1q_u8`. For >16 bytes, use `vqtbl2q_u8` (32B) through `vqtbl4q_u8` (64B).

### Narrow / Widen

```rust
// Narrow: truncate to lower bits. Result is 64-bit (D register).
pub fn vmovn_u16(a: uint16x8_t) -> uint8x8_t          // 16->8 bit
pub fn vqmovn_u16(a: uint16x8_t) -> uint8x8_t         // saturating 16->8
pub fn vqmovun_s16(a: int16x8_t) -> uint8x8_t         // signed->unsigned saturating

// Widen: zero/sign extend. Result is 128-bit.
pub fn vmovl_u8(a: uint8x8_t) -> uint16x8_t           // zero-extend 8->16
pub fn vmovl_s8(a: int8x8_t) -> int16x8_t             // sign-extend 8->16
pub fn vmovl_high_u8(a: uint8x16_t) -> uint16x8_t     // widen lanes 8..15
```

Narrow produces 64-bit; use `vcombine_u8(lo, hi)` to merge into 128-bit.

### Reduce (AArch64-Only)

Single-instruction horizontal reductions. Not available on ARM32.

```rust
pub fn vaddvq_u8(a: uint8x16_t) -> u8     // sum 16 bytes (wrapping)
pub fn vaddvq_u32(a: uint32x4_t) -> u32   // sum 4 u32s
pub fn vaddlvq_u8(a: uint8x16_t) -> u16   // widening sum (no overflow)
pub fn vmaxvq_u8(a: uint8x16_t) -> u8     // max of 16 bytes
pub fn vminvq_u8(a: uint8x16_t) -> u8     // min of 16 bytes
```

### Shift

```rust
pub fn vshlq_u8(a: uint8x16_t, b: int8x16_t) -> uint8x16_t   // variable per-lane
pub fn vshrq_n_u8<const N: i32>(a: uint8x16_t) -> uint8x16_t  // right by constant
pub fn vshlq_n_u8<const N: i32>(a: uint8x16_t) -> uint8x16_t  // left by constant
pub fn vshrn_n_u16<const N: i32>(a: uint16x8_t) -> uint8x8_t  // shift right + narrow
```

## AArch64 vs ARM32 NEON

| Feature                        | ARM32 (ARMv7)       | AArch64 (ARMv8+)           |
|--------------------------------|---------------------|----------------------------|
| SIMD registers                 | 16 (Q0--Q15)        | **32** (V0--V31)           |
| Scalar FP registers            | Separate VFP        | **Shared** with NEON       |
| Horizontal reductions          | Not available        | `vaddvq`, `vmaxvq`, `vminvq` |
| IEEE 754 compliance            | Partial              | **Full**                   |
| FMA instruction                | Optional (VFPv4)     | **Always available**       |
| 16B table lookup (single reg)  | Not available        | `vqtbl1q_u8`              |
| ZIP/UZP/TRN single-result      | Must use pair form   | `vzip1q`/`vzip2q` etc.    |

## Common Patterns

### Byte Search: Find Byte in Buffer

```rust
use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
unsafe fn find_byte_neon(haystack: &[u8], needle: u8) -> Option<usize> {
    let (len, ptr) = (haystack.len(), haystack.as_ptr());
    let needle_vec = vdupq_n_u8(needle);
    let mut i = 0usize;

    while i + 16 <= len {
        let cmp = vceqq_u8(vld1q_u8(ptr.add(i)), needle_vec);
        // Fast reject: vmaxvq returns 0 if no lane matched.
        if vmaxvq_u8(cmp) != 0 {
            let mut buf = [0u8; 16];
            vst1q_u8(buf.as_mut_ptr(), cmp);
            for j in 0..16 {
                if buf[j] != 0 { return Some(i + j); }
            }
        }
        i += 16;
    }
    // Scalar tail
    (i..len).find(|&j| *ptr.add(j) == needle)
}
```

`vmaxvq_u8(cmp) != 0` is the NEON "any match?" idiom, replacing x86's
`_mm_movemask_epi8(cmp) != 0`.

### Table Lookup: 4-bit Nibble LUT

Foundation for SIMD parsers (JSON, UTF-8, URL encoding).

```rust
use core::arch::aarch64::*;

/// Two-nibble classification (simdjson-style). Looks up both low and high
/// nibbles in separate 16-entry tables, ANDs results.
#[target_feature(enable = "neon")]
unsafe fn classify_two_nibble(
    input: uint8x16_t, lo_tbl: uint8x16_t, hi_tbl: uint8x16_t,
) -> uint8x16_t {
    let mask = vdupq_n_u8(0x0F);
    let lo = vqtbl1q_u8(lo_tbl, vandq_u8(input, mask));
    let hi = vqtbl1q_u8(hi_tbl, vshrq_n_u8::<4>(input));
    vandq_u8(lo, hi)
}
```

### AoS to SoA: RGB with vld3/vst3

```rust
use core::arch::aarch64::*;

/// De-interleave 16 RGB pixels. Single instruction for the load.
#[target_feature(enable = "neon")]
unsafe fn rgb_deinterleave(src: *const u8, r: &mut [u8; 16], g: &mut [u8; 16], b: &mut [u8; 16]) {
    let rgb: uint8x16x3_t = vld3q_u8(src);  // 1 instruction: load 48B, split
    vst1q_u8(r.as_mut_ptr(), rgb.0);
    vst1q_u8(g.as_mut_ptr(), rgb.1);
    vst1q_u8(b.as_mut_ptr(), rgb.2);
}

/// Re-interleave back to packed RGB. Single instruction for the store.
#[target_feature(enable = "neon")]
unsafe fn rgb_interleave(r: &[u8; 16], g: &[u8; 16], b: &[u8; 16], dst: *mut u8) {
    let planar = uint8x16x3_t(vld1q_u8(r.as_ptr()), vld1q_u8(g.as_ptr()), vld1q_u8(b.as_ptr()));
    vst3q_u8(dst, planar);
}
```

Use `vzip`/`vuzp` for pair-wise interleave when data does not match `vld2`--`vld4`.

## AArch64 Advantages

**32 SIMD registers** -- x86 SSE/AVX has 16 (xmm/ymm0--15). Complex
multi-table algorithms fit in registers without spills.

**No frequency throttling** -- x86 AVX-512 (and partially AVX2) can downclock
the CPU. NEON runs at full clock speed always. Safe to use on any code path.

**Deterministic latency** -- most NEON ops are 2--4 cycles, no data-dependent
timing. Performance modeling is straightforward.

**FMA always available** -- x86 FMA3 requires runtime detection. AArch64 FMA
is baseline. `vfmaq_f32` works on every AArch64 CPU.

**Native unaligned access** -- `vld1q_u8` handles unaligned pointers with no
penalty. No separate aligned/unaligned load variants needed.

**Multi-structure load/store** -- `vld2`--`vld4` de-interleave in hardware.
x86 has no equivalent (requires multiple shuffles).

## x86 Equivalence Table

| x86 Intrinsic                 | NEON Equivalent               | Notes |
|-------------------------------|-------------------------------|-------|
| `_mm_loadu_si128`             | `vld1q_u8`                    | NEON always unaligned-safe |
| `_mm_storeu_si128`            | `vst1q_u8`                    | Always unaligned-safe |
| `_mm_set1_epi8(x)`            | `vdupq_n_u8(x)`              | Broadcast to all lanes |
| `_mm_setzero_si128()`         | `vdupq_n_u8(0)`              | Zero vector |
| `_mm_add_epi8`                | `vaddq_u8`                    | Wrapping add |
| `_mm_sub_epi8`                | `vsubq_u8`                    | Wrapping subtract |
| `_mm_adds_epu8`               | `vqaddq_u8`                   | Saturating add |
| `_mm_subs_epu8`               | `vqsubq_u8`                   | Saturating subtract |
| `_mm_cmpeq_epi8`              | `vceqq_u8`                    | Returns full 0xFF mask per lane |
| `_mm_cmpgt_epi8`              | `vcgtq_s8`                    | Signed greater-than |
| `_mm_movemask_epi8`           | `vmaxvq_u8` (!= 0)           | No direct equiv; different pattern |
| `_mm_and_si128`               | `vandq_u8`                    | Bitwise AND |
| `_mm_or_si128`                | `vorrq_u8`                    | Bitwise OR |
| `_mm_xor_si128`               | `veorq_u8`                    | Bitwise XOR |
| `_mm_andnot_si128(a,b)`       | `vbicq_u8(b, a)`             | **Operand swap!** x86: ~a&b, NEON: a&~b |
| `_mm_blendv_epi8(a,b,m)`      | `vbslq_u8(m, b, a)`          | **Operand swap!** NEON bit-level |
| `_mm_shuffle_epi8`            | `vqtbl1q_u8`                  | NEON zeros idx>=16; SSE zeros on MSB set |
| `_mm_unpacklo_epi8`           | `vzip1q_u8`                   | Interleave low halves |
| `_mm_unpackhi_epi8`           | `vzip2q_u8`                   | Interleave high halves |
| `_mm_alignr_epi8(a,b,N)`      | `vextq_u8::<N>(b, a)`        | **Operand swap!** |
| `_mm_slli_epi16(a,N)`         | `vshlq_n_u16::<N>(a)`        | Shift left by immediate |
| `_mm_srli_epi16(a,N)`         | `vshrq_n_u16::<N>(a)`        | Shift right by immediate |
| `_mm_cvtepu8_epi16`           | `vmovl_u8`                    | Zero-extend 8->16 |
| `_mm_packs_epi16`             | `vqmovn_s16` + `vcombine`    | Narrow is 64-bit; combine for 128 |
| `_mm_packus_epi16`            | `vqmovun_s16` + `vcombine`   | Signed->unsigned narrow |
| (shuffle+add chain)           | `vaddvq_u32`                  | Single-instruction horiz sum |

### Critical Differences

1. **No `movemask`**: use `vmaxvq_u8` for "any non-zero?", store-and-scan
   or powers-of-two trick for precise lane identification.
2. **`vbicq` operand swap**: NEON `vbicq(a,b) = a & ~b`.
   x86 `_mm_andnot(a,b) = ~a & b`.
3. **`vqtbl1q_u8` vs `_mm_shuffle_epi8`**: SSE zeros on index MSB set.
   NEON zeros on index >= table size (>= 16). Different zero condition.
4. **128-bit only**: for wider vectors use SVE/SVE2 (128--2048 bits).

## Rust Boilerplate

```rust
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

// NEON function: unsafe + target_feature required by Rust compiler
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn process_neon(data: &[u8]) -> u8 {
    let v = vld1q_u8(data.as_ptr());
    vmaxvq_u8(v)
}

// Safe wrapper: NEON is always available on AArch64
#[cfg(target_arch = "aarch64")]
fn process(data: &[u8]) -> u8 {
    unsafe { process_neon(data) }
}

// Cross-platform dispatch
fn process_cross(data: &[u8]) -> u8 {
    #[cfg(target_arch = "aarch64")]
    { return unsafe { process_neon(data) }; }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sse2") {
            return unsafe { process_sse2(data) };
        }
    }
    process_scalar(data)
}
```

`#[target_feature(enable = "neon")]` is required by Rust to unlock intrinsics,
even though hardware always supports NEON. The `unsafe` is for intrinsic calls,
not feature availability.
