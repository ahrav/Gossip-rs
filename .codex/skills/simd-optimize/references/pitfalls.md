# Common SIMD Pitfalls and Bugs in Rust

Reference covering 10 frequent mistakes in hand-written and auto-vectorized
SIMD code, with x86-64 and AArch64 guidance.

## 1. Alignment: Unaligned vs Aligned Loads

x86 aligned loads (`_mm_load_si128`) segfault on misaligned pointers.
AArch64 NEON `vld1q_u8` is always unaligned-safe with no penalty.

```rust
// BUG: Segfaults if ptr is not 16-byte aligned.
unsafe fn load_bug(ptr: *const u8) -> __m128i {
    _mm_load_si128(ptr as *const __m128i)
}

// FIX: Unaligned load. Safe at any alignment.
unsafe fn load_fix(ptr: *const u8) -> __m128i {
    _mm_loadu_si128(ptr as *const __m128i)
}
```

**Why it matters.** On modern x86 (Sandy Bridge+), unaligned loads have zero
penalty except when crossing a 64-byte cache line boundary. Aligned loads
save nothing but add a segfault risk. **Rule: always use unaligned loads
unless you have proven alignment AND measured a benefit.**

## 2. Denormalized Floats: The 100x Slowdown

Subnormal floats trigger microcode assists on x86: 10-100x slower. Appears
in audio fade-outs, physics at rest, neural net activations near zero.

```rust
// BUG: IIR filter producing subnormals runs 100x slower.
fn process_audio(data: &mut [f32]) {
    for s in data.iter_mut() { *s = *s * 0.999 + feedback * 0.001; }
}

// FIX: Enable flush-to-zero and denormals-are-zero.
use std::arch::x86_64::*;
unsafe fn enable_ftz_daz() {
    _MM_SET_FLUSH_ZERO_MODE(_MM_FLUSH_ZERO_ON);
    _MM_SET_DENORMALS_ZERO_MODE(_MM_DENORMALS_ZERO_ON);
}
// AArch64: set FZ bit (bit 24) in FPCR via inline asm. Default is
// often already FTZ on most toolchains.
```

**Why it matters.** FTZ/DAZ eliminates the performance cliff at the cost of
numerical accuracy (small values become zero). Acceptable for audio/graphics/
inference. Document when enabled; unacceptable for scientific computing that
relies on gradual underflow.

## 3. NaN Handling in Float Comparisons

NaN is unordered: `NaN > x`, `NaN < x`, `NaN == NaN` are all false.
"Not less than" does NOT imply "greater than or equal" when NaN is present.

```rust
// BUG: NaN lanes never win _mm_cmpgt_ps, so NaN silently disappears.
unsafe fn find_max_bug(data: &[__m128]) -> __m128 {
    let mut max_v = _mm_set1_ps(f32::NEG_INFINITY);
    for &v in data {
        let mask = _mm_cmpgt_ps(v, max_v);
        max_v = _mm_blendv_ps(max_v, v, mask); // NaN lanes skipped
    }
    max_v
}

// FIX: Detect NaN explicitly with _mm_cmpunord_ps (x86)
// or NOT(vceqq_f32(x, x)) on NEON (x != x is true only for NaN).
unsafe fn has_nan_x86(v: __m128) -> bool {
    _mm_movemask_ps(_mm_cmpunord_ps(v, v)) != 0
}
```

**Why it matters.** Silent NaN loss corrupts results without visible error.
Always decide whether your function propagates, ignores, or rejects NaN, and
test accordingly. NEON has no unordered compare; use `NOT(ceq(x, x))`.

## 4. Remainder Loop Off-by-One

Input lengths are rarely a multiple of the vector width. Mishandling the
tail is the most common SIMD bug.

```rust
// BUG: Last (len % 16) bytes never checked.
fn search_bug(haystack: &[u8], needle: u8) -> bool {
    let mut offset = 0;
    while offset + 16 <= haystack.len() {
        /* SIMD compare */ offset += 16;
    }
    false // remainder silently dropped!
}
```

**Fix 1 -- scalar remainder:**
```rust
// After the SIMD loop, process leftover bytes one at a time.
while offset < haystack.len() {
    if haystack[offset] == needle { return true; }
    offset += 1;
}
```

**Fix 2 -- overlapping final vector:** Re-read the last 16 bytes starting at
`len - 16`. Safe for idempotent ops (search, min, max). NOT safe for
append/write where duplicates corrupt output.

**Fix 3 -- masked tail (AVX-512 / SVE):**
```rust
let remaining = len - offset;
let tail_mask: __mmask64 = (1u64 << remaining) - 1;
let chunk = _mm512_maskz_loadu_epi8(tail_mask, ptr.add(offset) as *const i8);
```

**Why it matters.** Off-by-one in tail handling causes silent data loss or
out-of-bounds reads near page boundaries. Always test with lengths 0, 1,
`width-1`, `width`, and `width+1`.

## 5. Auto-Vectorization Barriers

LLVM can auto-vectorize scalar loops, but common patterns silently prevent
it. The code compiles and runs correctly but stays scalar (4-64x slower).

**Function calls:** Any opaque call in the loop body blocks vectorization.
Fix: `#[inline(always)]` or move the body inline.

**FP accumulator (serial dependency):**
```rust
// NOT vectorized: serial dependency chain (FP add is not associative).
let mut acc = 0.0f32;
for &x in data { acc += x; }

// FIX: Multiple accumulators break the chain.
let (mut a, mut b, mut c, mut d) = (0.0f32, 0.0, 0.0, 0.0);
for chunk in data.chunks_exact(4) {
    a += chunk[0]; b += chunk[1]; c += chunk[2]; d += chunk[3];
}
```

**Other barriers:** Early return in loop, `.filter()` (variable-length
output), non-contiguous memory (linked list), complex match/if chains.
Prefer `.chunks_exact()` over `.enumerate()` in hot loops.

**Check:** `cargo asm --lib crate::function` -- look for `vpaddb`,
`vmovdqu` (x86) or `ld1`, `cmeq` (NEON).

## 6. AVX-512 Frequency Throttling (Intel)

Intel CPUs (Skylake-X through Rocket Lake) downclock for 512-bit ops.
Heavy instructions (FP multiply, FMA) drop to license level 2, losing
200-400 MHz. Recovery takes ~670 us after the last 512-bit instruction.

```rust
// BUG: Full 512-bit FMA triggers L2 throttling on Intel.
#[target_feature(enable = "avx512f")]
unsafe fn dot_throttled(a: &[f32], b: &[f32]) {
    let mut acc = _mm512_setzero_ps();
    for i in (0..a.len()).step_by(16) {
        acc = _mm512_fmadd_ps(_mm512_loadu_ps(a.as_ptr().add(i)),
                              _mm512_loadu_ps(b.as_ptr().add(i)), acc);
    }
}

// FIX: Use 256-bit width + AVX-512VL for mask features without throttle.
#[target_feature(enable = "avx512f,avx512vl")]
unsafe fn dot_no_throttle(a: &[f32], b: &[f32]) {
    let mut acc = _mm256_setzero_ps();
    for i in (0..a.len()).step_by(8) {
        acc = _mm256_fmadd_ps(_mm256_loadu_ps(a.as_ptr().add(i)),
                              _mm256_loadu_ps(b.as_ptr().add(i)), acc);
    }
}
```

**Why it matters.** AMD Zen 4/5 have NO throttling (they split 512-bit ops
into two 256-bit micro-ops). On Intel, the wider vectors can be negated by
the frequency drop, especially in mixed SIMD/scalar workloads. Default to
256-bit; only use 512-bit after benchmarking on target hardware.

## 7. AVX/SSE Transition Penalty

Mixing legacy SSE (`movdqa xmm`) with VEX-encoded AVX (`vmovdqa ymm`)
causes a ~70-cycle penalty on Intel Haswell through Ice Lake. The CPU must
save/restore the upper 128 bits of YMM registers.

```asm
; PENALTY: legacy SSE after AVX without vzeroupper.
vmovdqu ymm0, [rdi]         ; AVX (VEX-encoded)
call    some_sse_lib_fn      ; callee uses legacy SSE -> 70-cycle stall
```

```rust
// FIX: Zero upper YMM state before calling potential SSE code.
#[target_feature(enable = "avx")]
unsafe fn clean_avx_state() {
    _mm256_zeroupper(); // compiles to vzeroupper
}
```

**Why it matters.** LLVM inserts `vzeroupper` at function returns
automatically. It can miss indirect calls, closures, FFI, and trait object
dispatch. AMD Zen has no penalty. ARM is not affected (NEON is fixed
128-bit, SVE is length-agnostic).

## 8. Type Punning and Transmute

`std::mem::transmute` between SIMD types works in practice but is not
guaranteed by Rust layout rules. The proper cast intrinsics are zero-cost
(no instruction emitted) and always correct.

```rust
// BUG: Fragile, not guaranteed by layout rules.
unsafe fn cast_bad(v: __m128i) -> __m128 { std::mem::transmute(v) }
unsafe fn extract_bad(v: __m128i) -> [u8; 16] { std::mem::transmute(v) }

// FIX: Zero-cost cast intrinsics.
unsafe fn cast_good(v: __m128i) -> __m128 { _mm_castsi128_ps(v) }
unsafe fn extract_good(v: __m128i) -> [u8; 16] {
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, v);
    out
}
// NEON: vreinterpretq_u32_u8(v), vreinterpretq_f32_u32(v), etc.
```

**Why it matters.** Zero performance cost. Proper intrinsics are portable,
self-documenting, and immune to future layout changes. For extracting to
arrays, always use store intrinsics instead of transmute.

## 9. Unsafe Contract Documentation

SIMD code is nearly all `unsafe`. Without precise safety comments, reviewers
cannot verify correctness and future refactors silently introduce UB.

```rust
// BAD: Restates the code, does not explain why it is safe.
unsafe {
    // SAFETY: loading 16 bytes from ptr
    let v = _mm_loadu_si128(ptr as *const __m128i);
}

// GOOD: States the invariant that makes the access valid.
unsafe {
    // SAFETY: `offset + 16 <= haystack.len()` (loop guard), so
    // ptr.add(offset)..ptr.add(offset+15) are within the allocation.
    // _mm_loadu_si128 accepts unaligned pointers.
    let v = _mm_loadu_si128(ptr.add(offset) as *const __m128i);
}
```

**Checklist for every `unsafe` SIMD block:**
1. **Bounds** -- what guarantees the read/write is in-bounds.
2. **Alignment** -- unaligned intrinsic used, or proof of alignment.
3. **Feature** -- `#[target_feature]` or runtime detection guarantees ISA.
4. **No aliasing/races** -- if applicable.

Enable `clippy::undocumented_unsafe_blocks = "warn"` to enforce this.

## 10. Testing Edge Cases

SIMD bugs cluster at chunk boundaries. Every function must be tested against
a known-good scalar reference with these inputs:

```rust
#[test]
fn edge_lengths() {
    // 128-bit (16), 256-bit (32), 512-bit (64) vector boundaries.
    for &len in &[0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
        let data = vec![0x42u8; len];
        assert_eq!(simd_fn(&data), scalar_fn(&data), "len={len}");
    }
}

#[test]
fn extreme_values() {
    assert_eq!(simd_fn(&[0x00; 64]), scalar_fn(&[0x00; 64])); // all zeros
    assert_eq!(simd_fn(&[0xFF; 64]), scalar_fn(&[0xFF; 64])); // all ones
    assert_eq!(simd_fn(&[0x80; 64]), scalar_fn(&[0x80; 64])); // i8::MIN
}

#[test]
fn float_specials() {
    for &v in &[f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.0,
                f32::MIN_POSITIVE / 2.0 /* subnormal */] {
        let data = vec![v; 16];
        // Verify no panic, no garbage, matches scalar reference.
    }
}

#[test]
fn misaligned_inputs() {
    let buf = vec![0x42u8; 256];
    for off in 0..16 {
        assert_eq!(simd_fn(&buf[off..off+64]), scalar_fn(&buf[off..off+64]));
    }
}
```

Use `proptest` for thorough coverage:
```rust
proptest! {
    #[test]
    fn simd_matches_scalar(
        data in proptest::collection::vec(any::<u8>(), 0..1024),
        needle in any::<u8>(),
    ) {
        prop_assert_eq!(simd_fn(&data, needle), scalar_fn(&data, needle));
    }
}
```

| Test Case | Catches |
|-----------|---------|
| len=0 | Null deref, underflow in `len - 16` |
| len=1 | Scalar-only path correctness |
| len=15/31/63 | All-remainder, no SIMD iteration |
| len=16/32/64 | Exact iteration, no remainder |
| len=17/33/65 | One iteration + 1-element remainder |
| All zeros / all 0xFF | Signed/unsigned confusion |
| NaN / infinity / subnormals | Pitfalls 2 and 3 |
| Misaligned pointer | Pitfall 1 |
| Needle at vector boundary | Off-by-one between iterations |
