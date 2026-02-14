# x86 SSE/AVX2 Intrinsics Reference

Reference for SSE2 through AVX2 SIMD intrinsics in Rust via `core::arch::x86_64`.

## ISA Progression

| ISA Level | Width | Key Additions | Rust `target_feature` |
|-----------|:-----:|---|---|
| SSE2 | 128-bit | Integer SIMD, f64. Baseline for x86-64. | `sse2` |
| SSE3 | 128-bit | Horizontal add/sub, `lddqu` | `sse3` |
| SSSE3 | 128-bit | `pshufb` (byte shuffle LUT), `pmaddubsw`, `pabs*` | `ssse3` |
| SSE4.1 | 128-bit | `blendv`, `ptest`, `pmovsx/zx`, variable blend | `sse4.1` |
| SSE4.2 | 128-bit | String ops (`pcmpistri/m`), `popcnt`, CRC32 | `sse4.2` |
| AVX | 256-bit | 256-bit float, VEX encoding (3-operand), `vbroadcast` | `avx` |
| AVX2 | 256-bit | 256-bit integer, gather, lane-crossing permutes | `avx2` |

**Baseline**: All x86-64 CPUs support SSE2. Everything above requires runtime
detection or compile-time `target_feature`.

## Intrinsic Naming Conventions

| Prefix | Width | Reg | Type Suffix | Meaning |
|--------|:-----:|-----|-------------|---------|
| `_mm_` | 128 | `xmm` | `_epi8/16/32/64` | Signed int (8/16/32/64-bit) |
| `_mm256_` | 256 | `ymm` | `_epu8/16` | Unsigned int |
| | | | `_ps` / `_pd` | Packed float / double |
| | | | `_si128` / `_si256` | Whole register (untyped) |

Rust types: `__m128i` (128-bit int), `__m128` (f32x4), `__m128d` (f64x2),
`__m256i` (256-bit int), `__m256` (f32x8), `__m256d` (f64x4).

## Key Intrinsics by Category

### Load / Store

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_loadu_si128(p)` | SSE2 | Unaligned 128-bit load |
| `_mm_load_si128(p)` | SSE2 | Aligned 128-bit load (16-byte aligned ptr) |
| `_mm_storeu_si128(p, a)` | SSE2 | Unaligned 128-bit store |
| `_mm256_loadu_si256(p)` | AVX | Unaligned 256-bit load |
| `_mm256_storeu_si256(p, a)` | AVX | Unaligned 256-bit store |
| `_mm_set1_epi8(b)` | SSE2 | Broadcast byte to all 16 lanes |
| `_mm256_set1_epi8(b)` | AVX2 | Broadcast byte to all 32 lanes |
| `_mm_setzero_si128()` | SSE2 | All-zero 128-bit vector |
| `_mm256_setzero_si256()` | AVX | All-zero 256-bit vector |

Prefer unaligned loads (`loadu`). Modern CPUs (Haswell+) have no penalty for
unaligned loads that do not cross cache-line boundaries.

### Arithmetic

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_add_epi8/16/32(a, b)` | SSE2 | Add packed integers (wrapping) |
| `_mm_sub_epi8/16/32(a, b)` | SSE2 | Subtract packed integers |
| `_mm_mullo_epi16(a, b)` | SSE2 | Multiply i16, keep low 16 bits |
| `_mm_mullo_epi32(a, b)` | SSE4.1 | Multiply i32, keep low 32 bits |
| `_mm_adds_epu8(a, b)` | SSE2 | Saturating add unsigned u8 |
| `_mm_subs_epu8(a, b)` | SSE2 | Saturating subtract unsigned u8 |
| `_mm_madd_epi16(a, b)` | SSE2 | Multiply i16 pairs, add adjacent to i32 |
| `_mm_sad_epu8(a, b)` | SSE2 | Sum of absolute differences u8, result in u16 |
| `_mm256_add_epi8/32(a, b)` | AVX2 | 256-bit add |
| `_mm256_mullo_epi32(a, b)` | AVX2 | 256-bit multiply i32, keep low 32 |
| `_mm256_sad_epu8(a, b)` | AVX2 | 256-bit sum of absolute differences |

### Compare

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_cmpeq_epi8(a, b)` | SSE2 | Per-byte equality: `0xFF` if equal, `0x00` if not |
| `_mm_cmpeq_epi32(a, b)` | SSE2 | Per-dword equality |
| `_mm_cmpgt_epi8(a, b)` | SSE2 | Per-byte signed greater-than |
| `_mm_cmpgt_epi32(a, b)` | SSE2 | Per-dword signed greater-than |
| `_mm256_cmpeq_epi8(a, b)` | AVX2 | 256-bit per-byte equality |
| `_mm256_cmpgt_epi8(a, b)` | AVX2 | 256-bit per-byte signed greater-than |

**No unsigned compares in SSE2.** Workaround: XOR both operands with `0x80` to
flip the sign bit, then use signed compare.

### Bitwise

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_and_si128(a, b)` | SSE2 | AND |
| `_mm_or_si128(a, b)` | SSE2 | OR |
| `_mm_xor_si128(a, b)` | SSE2 | XOR |
| `_mm_andnot_si128(a, b)` | SSE2 | `(!a) & b` -- note operand order |
| `_mm256_and/or/xor_si256(a, b)` | AVX2 | 256-bit bitwise |
| `_mm256_andnot_si256(a, b)` | AVX2 | 256-bit `(!a) & b` |
| `_mm_slli_epi32(a, IMM8)` | SSE2 | Shift left each 32-bit lane |
| `_mm_srli_epi32(a, IMM8)` | SSE2 | Shift right logical each 32-bit lane |
| `_mm_srli_si128(a, IMM8)` | SSE2 | Byte-shift entire register right |

**Gotcha**: `andnot` computes `(!a) & b`, not `a & (!b)`. Operand order matters.

### Shuffle / Permute

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_shuffle_epi32(a, IMM8)` | SSE2 | Shuffle 32-bit lanes within register |
| `_mm_shuffle_epi8(a, b)` | **SSSE3** | Byte-granularity shuffle/LUT |
| `_mm256_shuffle_epi8(a, b)` | AVX2 | 256-bit byte shuffle (**within each 128-bit lane**) |
| `_mm256_permutevar8x32_epi32(a, idx)` | AVX2 | Lane-crossing 32-bit permute (vpermd) |
| `_mm256_permute2x128_si256(a, b, IMM8)` | AVX2 | Select/swap 128-bit halves |
| `_mm256_permute4x64_epi64(a, IMM8)` | AVX2 | Lane-crossing 64-bit permute |

**Critical**: `_mm_shuffle_epi8` requires **SSSE3**, not SSE2. Many older AMD
CPUs (pre-Bulldozer) lack SSSE3. Always guard with `target_feature`.

**Critical**: `_mm256_shuffle_epi8` operates within each 128-bit lane
independently. Byte index 0 in the high lane selects byte 0 of the *high*
lane, not byte 0 of the low lane. Cannot shuffle bytes across the lane boundary.

### Pack / Unpack

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_packus_epi16(a, b)` | SSE2 | Pack i16 to u8 with unsigned saturation |
| `_mm_packs_epi16(a, b)` | SSE2 | Pack i16 to i8 with signed saturation |
| `_mm_unpacklo_epi8(a, b)` | SSE2 | Interleave low bytes: `a0 b0 a1 b1 ...` |
| `_mm_unpackhi_epi8(a, b)` | SSE2 | Interleave high bytes |
| `_mm256_packus_epi16(a, b)` | AVX2 | 256-bit pack (within lanes) |

AVX2 pack/unpack operates within 128-bit lanes. Result ordering may surprise.

### Blend

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_blendv_epi8(a, b, mask)` | SSE4.1 | Per-byte blend: select `b` where mask bit 7 set |
| `_mm_blend_epi16(a, b, IMM8)` | SSE4.1 | Immediate blend on 16-bit granularity |
| `_mm256_blendv_epi8(a, b, mask)` | AVX2 | 256-bit per-byte variable blend |

`blendv` checks only bit 7 of each mask byte. Comparison results (`0xFF`/`0x00`)
work directly as masks.

### Movemask (Vector to Scalar)

| Intrinsic | ISA | Description |
|-----------|-----|-------------|
| `_mm_movemask_epi8(a)` | SSE2 | High bit of each byte to 16-bit int |
| `_mm256_movemask_epi8(a)` | AVX2 | High bit of each byte to 32-bit int |
| `_mm_testz_si128(a, b)` | SSE4.1 | Returns 1 if `(a & b) == 0` |
| `_mm256_testz_si256(a, b)` | AVX | Returns 1 if `(a & b) == 0` |

**Pattern**: `cmpeq` + `movemask` + `trailing_zeros()` = find first matching byte.

## Common Patterns

### Byte Search: Find First Occurrence in Buffer

```rust
use core::arch::x86_64::*;

/// Find first occurrence of `needle` in `haystack`.
/// # Safety
/// Requires SSE2 (baseline on x86-64).
#[target_feature(enable = "sse2")]
unsafe fn find_byte_sse2(haystack: &[u8], needle: u8) -> Option<usize> {
    let len = haystack.len();
    let ptr = haystack.as_ptr();
    let needle_v = _mm_set1_epi8(needle as i8);
    let mut offset = 0usize;

    while offset + 16 <= len {
        // SAFETY: offset + 16 <= len guarantees in-bounds.
        let chunk = _mm_loadu_si128(ptr.add(offset) as *const __m128i);
        let cmp = _mm_cmpeq_epi8(chunk, needle_v);
        let mask = _mm_movemask_epi8(cmp) as u32;
        if mask != 0 {
            return Some(offset + mask.trailing_zeros() as usize);
        }
        offset += 16;
    }
    // Scalar tail.
    for i in offset..len {
        if *haystack.get_unchecked(i) == needle {
            return Some(i);
        }
    }
    None
}
```

### Horizontal Sum: Reduce i32x4 / i32x8 to Scalar

```rust
use core::arch::x86_64::*;

/// # Safety: Requires SSE2.
#[target_feature(enable = "sse2")]
unsafe fn hsum_i32_sse2(v: __m128i) -> i32 {
    // [a, b, c, d] -> shift right 8 bytes -> [c, d, 0, 0]
    let hi64 = _mm_srli_si128(v, 8);
    let sum64 = _mm_add_epi32(v, hi64);   // [a+c, b+d, *, *]
    let hi32 = _mm_srli_si128(sum64, 4);   // [b+d, *, *, *]
    let sum32 = _mm_add_epi32(sum64, hi32); // [a+b+c+d, *, *, *]
    _mm_cvtsi128_si32(sum32)
}

/// # Safety: Requires AVX2.
#[target_feature(enable = "avx2")]
unsafe fn hsum_i32_avx2(v: __m256i) -> i32 {
    let hi128 = _mm256_extracti128_si256(v, 1);
    let lo128 = _mm256_castsi256_si128(v);
    let sum128 = _mm_add_epi32(lo128, hi128);
    hsum_i32_sse2(sum128)
}
```

**Avoid** `_mm_hadd_epi32` -- 3-cycle latency, 0.5/cycle throughput. The
shuffle+add approach above is faster.

### Shuffle-Based LUT: 4-Bit Index to Byte Mapping

`_mm_shuffle_epi8` acts as a 16-entry LUT: each byte of the index operand
selects a table entry by its low 4 bits. If bit 7 is set, output is zeroed.

```rust
use core::arch::x86_64::*;

/// Classify bytes by high nibble using a 16-entry LUT.
/// # Safety: Requires SSSE3.
#[target_feature(enable = "ssse3")]
unsafe fn classify_high_nibble(data: __m128i, lut: __m128i) -> __m128i {
    let indices = _mm_srli_epi16(data, 4);
    let mask = _mm_set1_epi8(0x0F);
    let indices = _mm_and_si128(indices, mask);
    // SAFETY: pshufb uses low 4 bits as index into lut.
    _mm_shuffle_epi8(lut, indices)
}
```

Combine two LUT lookups (high nibble + low nibble) with AND to classify from a
256-entry space. This is the backbone of SIMD parsers (JSON, CSV, URL).

## SSE4.2 String Operations

### Core Intrinsics

| Intrinsic | Returns |
|-----------|---------|
| `_mm_cmpistrm(a, b, IMM8)` | Mask (`__m128i`) of match results |
| `_mm_cmpistri(a, b, IMM8)` | Index (`i32`) of first/last match |
| `_mm_cmpestrm(a, la, b, lb, IMM8)` | Mask (explicit length) |
| `_mm_cmpestri(a, la, b, lb, IMM8)` | Index (explicit length) |

### IMM8 Control Flags (`_SIDD_*`)

| Flag | Value | Meaning |
|------|:-----:|---------|
| `_SIDD_UBYTE_OPS` | 0x00 | Unsigned byte operands |
| `_SIDD_CMP_EQUAL_ANY` | 0x00 | Match if byte is in set |
| `_SIDD_CMP_RANGES` | 0x04 | Match if byte in [lo, hi] range pairs |
| `_SIDD_CMP_EQUAL_EACH` | 0x08 | Per-position equality (strcmp) |
| `_SIDD_CMP_EQUAL_ORDERED` | 0x0C | Substring search (strstr) |
| `_SIDD_NEGATIVE_POLARITY` | 0x10 | Invert result bits |
| `_SIDD_LEAST_SIGNIFICANT` | 0x00 | Index of least significant set bit |
| `_SIDD_MOST_SIGNIFICANT` | 0x40 | Index of most significant set bit |

### Example: Find First Byte in Character Set

```rust
use core::arch::x86_64::*;

/// Find index of first byte in `data` matching any byte in `set` (up to 16).
/// Returns 16 if no match found.
/// # Safety: Requires SSE4.2.
#[target_feature(enable = "sse4.2")]
unsafe fn find_any_of(data: __m128i, set: __m128i) -> i32 {
    _mm_cmpistri(
        set, data,
        _SIDD_UBYTE_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_LEAST_SIGNIFICANT,
    )
}
```

`pcmpistri` has ~10 cycle latency. For single-byte searches, `cmpeq` + `movemask`
is faster. SSE4.2 string ops shine for multi-character set matching and range
checks (e.g., "find first byte NOT in [a-zA-Z0-9]").

## AVX2 Lane-Crossing Operations

AVX2 256-bit registers split into two 128-bit "lanes". Most shuffles/packs
operate within each lane. Crossing requires special instructions:

| Intrinsic | Description |
|-----------|-------------|
| `_mm256_permutevar8x32_epi32(a, idx)` | Arbitrary 32-bit permute across all 8 dwords (vpermd) |
| `_mm256_permute4x64_epi64(a, IMM8)` | Arbitrary 64-bit permute across all 4 qwords |
| `_mm256_permute2x128_si256(a, b, IMM8)` | Select 128-bit halves from two registers |
| `_mm256_extracti128_si256(a, IMM1)` | Extract high or low 128-bit half |
| `_mm256_inserti128_si256(a, b, IMM1)` | Insert 128-bit value into half |

### Gather

| Intrinsic | Description |
|-----------|-------------|
| `_mm256_i32gather_epi32(base, idx, SCALE)` | Gather 8 x i32 from `base + idx[i] * SCALE` |
| `_mm256_mask_i32gather_epi32(src, base, idx, mask, SCALE)` | Masked gather |

`SCALE` must be 1, 2, 4, or 8. For `i32` array, use `SCALE = 4`.

**Gather is slow**: ~5+ cycles per element. Prefer sequential access.

### Example: Lane-Crossing Permute

```rust
use core::arch::x86_64::*;

/// Reverse 8 x i32 elements in a 256-bit vector.
/// # Safety: Requires AVX2.
#[target_feature(enable = "avx2")]
unsafe fn reverse_i32x8(v: __m256i) -> __m256i {
    let idx = _mm256_set_epi32(0, 1, 2, 3, 4, 5, 6, 7);
    _mm256_permutevar8x32_epi32(v, idx)
}
```

## Performance Notes

Approximate latency/throughput on Skylake/Ice Lake class cores. Consult
[uops.info](https://uops.info/) for exact numbers per microarchitecture.

| Operation | Intrinsic | Lat | Tput (ops/cyc) | Notes |
|-----------|-----------|:---:|:--------------:|-------|
| Byte compare eq | `_mm[256]_cmpeq_epi8` | 1 | 2 | Search foundation |
| Movemask | `_mm[256]_movemask_epi8` | 3 | 1 | Vector-to-scalar bridge |
| Byte shuffle (pshufb) | `_mm[256]_shuffle_epi8` | 1 | 1 | SSSE3. LUT workhorse |
| Blend variable | `_mm[256]_blendv_epi8` | 1 | 1 | SSE4.1 |
| Bitwise AND/OR/XOR | `_mm[256]_and_si*` | 1 | 3 | Very cheap |
| Integer add | `_mm[256]_add_epi*` | 1 | 2-3 | |
| Horizontal add i32 | `_mm_hadd_epi32` | 3 | 0.5 | **AVOID in hot paths** |
| SAD | `_mm[256]_sad_epu8` | 5 | 1 | Great for byte counting |
| Multiply i32 | `_mm[256]_mullo_epi32` | 10 | 0.5 | Expensive |
| Test zero | `_mm[256]_testz_si*` | 3 | 1 | Good for early-out |
| Dword permute (vpermd) | `_mm256_permutevar8x32_epi32` | 3 | 1 | Cross-lane workhorse |
| 128-bit lane swap | `_mm256_permute2x128_si256` | 3 | 1 | |
| Gather i32 | `_mm256_i32gather_epi32` | ~12 | ~0.2 | Use sparingly |
| String compare | `_mm_cmpistri` | 10 | 0.33 | High latency |

## Runtime Feature Detection

```rust
fn process(data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: We just confirmed AVX2 is available.
            return unsafe { process_avx2(data) };
        }
        if is_x86_feature_detected!("ssse3") {
            // SAFETY: We just confirmed SSSE3 is available.
            return unsafe { process_ssse3(data) };
        }
    }
    process_scalar(data)
}

#[target_feature(enable = "avx2")]
unsafe fn process_avx2(data: &[u8]) -> usize { todo!() }

#[target_feature(enable = "ssse3")]
unsafe fn process_ssse3(data: &[u8]) -> usize { todo!() }

fn process_scalar(data: &[u8]) -> usize { todo!() }
```

**Key points on `#[target_feature]`**:
- Makes the function `unsafe` to call (caller must ensure CPU support).
- Enables the feature for the entire function body including inlined callees.
- `is_x86_feature_detected!` is cached after first call (single branch).
- Multiple features: `#[target_feature(enable = "avx2,bmi2")]`.
- Cannot be inlined into functions lacking those features.

## SSE/AVX Transition Penalty

Mixing legacy SSE (non-VEX) and AVX (VEX-encoded) instructions causes a
pipeline penalty on Intel CPUs (not AMD Zen). Within an AVX2-enabled function,
the Rust compiler emits VEX-encoded instructions for all SSE intrinsics
automatically. No manual `_mm256_zeroupper()` is needed when using Rust
intrinsics exclusively.

## Quick Reference: "Which ISA Do I Need?"

| I want to... | Minimum ISA | Key intrinsic |
|--------------|-------------|---------------|
| Compare 16 bytes at once | SSE2 | `_mm_cmpeq_epi8` |
| Compare 32 bytes at once | AVX2 | `_mm256_cmpeq_epi8` |
| Byte-level LUT (pshufb) | SSSE3 | `_mm_shuffle_epi8` |
| Conditional select per byte | SSE4.1 | `_mm_blendv_epi8` |
| Character-class search | SSE4.2 | `_mm_cmpistri` |
| Widen u8 to u16 zero-extend | SSE4.1 | `_mm_cvtepu8_epi16` |
| Popcount | POPCNT | `_popcnt32` (scalar) or pshufb-based |
| Cross-lane 32-bit permute | AVX2 | `_mm256_permutevar8x32_epi32` |
| Gather from scattered memory | AVX2 | `_mm256_i32gather_epi32` |
