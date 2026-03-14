//! SIMD-accelerated byte classification for character-class distribution gating.
//!
//! Classifies every byte in a window into four ASCII classes (lowercase,
//! uppercase, digit, special) and returns aggregate counts. The hot path
//! dispatches to architecture-specific SIMD (NEON on aarch64, SSE2 on x86_64)
//! with an automatic scalar fallback for short tails and unsupported targets.
//!
//! # Algorithm
//!
//! **NEON** (2 ops per range): wrapping subtract + unsigned compare.
//! `vsubq_u8(v, base)` wraps out-of-range bytes to large values that fail
//! the `vcltq_u8(result, width)` check. This is cheaper than saturating
//! subtract, which incorrectly clamps bytes below the base to zero.
//!
//! **SSE2** (3 ops per range): signed comparison pairs.
//! `_mm_cmpgt_epi8(v, lo_minus_1) & _mm_cmpgt_epi8(hi_plus_1, v)` — correct
//! for all 256 byte values because ASCII ranges are positive in signed i8,
//! and bytes >= 0x80 are negative (failing all `> positive` comparisons).
//!
//! **Scalar**: byte-by-byte match used as the proptest/Miri oracle and for
//! the tail of SIMD loops (0–15 remaining bytes).
//!
//! # Accumulator overflow prevention
//!
//! SIMD paths accumulate per-lane u8 counters via `sub(acc, mask)` where mask
//! lanes are 0xFF (match) or 0x00 (no match), effectively incrementing by 1.
//! Lanes are flushed to u32 totals every 255 iterations (before any lane can
//! overflow u8::MAX).
//!
//! # Safety
//!
//! All unsafe blocks are SIMD intrinsics gated by `#[cfg(target_arch)]` and
//! `not(miri)`. See per-block `// SAFETY:` comments for invariant proofs.

/// Byte-class counts for a window of bytes.
///
/// Invariant: `lower + upper + digit + special == window.len() as u32`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CharClassProfile {
    pub(crate) upper: u32,
    pub(crate) lower: u32,
    pub(crate) digit: u32,
    pub(crate) special: u32,
}

/// Classify all bytes in `window` by ASCII character class.
///
/// Dispatches to NEON (aarch64), SSE2 (x86_64), or scalar fallback.
/// All paths produce identical results for the same input.
///
/// # Panics (debug only)
///
/// Debug-asserts that `window.len() <= u32::MAX`. All counts in
/// [`CharClassProfile`] are `u32`, so inputs exceeding 4 GiB cannot be
/// represented correctly. In practice, scanning windows are KB-sized.
#[inline]
pub(crate) fn classify_window(window: &[u8]) -> CharClassProfile {
    debug_assert!(
        window.len() <= u32::MAX as usize,
        "CharClassProfile uses u32 counts; input length {} exceeds u32::MAX",
        window.len(),
    );
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    {
        // SAFETY: NEON is architecturally guaranteed on all AArch64 targets.
        // The callee handles all input lengths (including < 16) via scalar tail.
        return unsafe { neon::classify_window_neon(window) };
    }
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    {
        // SAFETY: SSE2 is architecturally guaranteed on all x86_64 targets.
        // The callee handles all input lengths (including < 16) via scalar tail.
        return unsafe { sse2::classify_window_sse2(window) };
    }
    #[allow(unreachable_code)]
    classify_window_scalar(window)
}

/// Scalar reference implementation — also serves as the proptest/Miri oracle.
fn classify_window_scalar(window: &[u8]) -> CharClassProfile {
    let (mut lower, mut upper, mut digit) = (0u32, 0u32, 0u32);
    for &b in window {
        match b {
            b'a'..=b'z' => lower += 1,
            b'A'..=b'Z' => upper += 1,
            b'0'..=b'9' => digit += 1,
            _ => {}
        }
    }
    CharClassProfile {
        lower,
        upper,
        digit,
        special: window.len() as u32 - lower - upper - digit,
    }
}

// ---------------------------------------------------------------------------
// NEON implementation (aarch64)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::CharClassProfile;
    use std::arch::aarch64::*;

    /// NEON-accelerated byte classification using wrapping-subtract range checks.
    ///
    /// # Safety
    /// Requires aarch64 NEON intrinsics (architecturally guaranteed on this
    /// target). Handles all input lengths including empty and sub-16-byte inputs.
    pub(super) unsafe fn classify_window_neon(bytes: &[u8]) -> CharClassProfile {
        let splat_a = vdupq_n_u8(b'a'); // 0x61
        let splat_upper_a = vdupq_n_u8(b'A'); // 0x41
        let splat_0 = vdupq_n_u8(b'0'); // 0x30
        let width_26 = vdupq_n_u8(26);
        let width_10 = vdupq_n_u8(10);
        let zero = vdupq_n_u8(0);

        let mut lower_acc = zero;
        let mut upper_acc = zero;
        let mut digit_acc = zero;
        let mut lower_total = 0u32;
        let mut upper_total = 0u32;
        let mut digit_total = 0u32;

        let mut i = 0usize;
        let mut chunks_in_epoch = 0u8;

        // SAFETY: loop guard ensures i + 16 <= bytes.len(); vld1q_u8 reads
        // exactly 16 bytes from bytes[i..i+16]. No overread possible.
        // vld1q_u8 is unaligned-safe on AArch64 (no penalty).
        while i + 16 <= bytes.len() {
            let v = vld1q_u8(bytes.as_ptr().add(i));

            // Wrapping subtract: out-of-range bytes wrap to >= width → fail compare.
            // CRITICAL: vsubq_u8 (wrapping), NOT vqsubq_u8 (saturating).
            // Saturating subtract clamps bytes below base to zero, which falsely
            // passes the < width comparison.
            let is_lower = vcltq_u8(vsubq_u8(v, splat_a), width_26);
            let is_upper = vcltq_u8(vsubq_u8(v, splat_upper_a), width_26);
            let is_digit = vcltq_u8(vsubq_u8(v, splat_0), width_10);

            // Accumulate: mask lanes are 0xFF on match; subtracting 0xFF wraps to +1.
            lower_acc = vsubq_u8(lower_acc, is_lower);
            upper_acc = vsubq_u8(upper_acc, is_upper);
            digit_acc = vsubq_u8(digit_acc, is_digit);

            i += 16;
            chunks_in_epoch += 1;

            // Flush before u8 lane overflow (max 255 increments per lane).
            if chunks_in_epoch == 255 {
                lower_total += vaddlvq_u8(lower_acc) as u32;
                upper_total += vaddlvq_u8(upper_acc) as u32;
                digit_total += vaddlvq_u8(digit_acc) as u32;
                lower_acc = zero;
                upper_acc = zero;
                digit_acc = zero;
                chunks_in_epoch = 0;
            }
        }

        // Final flush of remaining accumulator lanes.
        lower_total += vaddlvq_u8(lower_acc) as u32;
        upper_total += vaddlvq_u8(upper_acc) as u32;
        digit_total += vaddlvq_u8(digit_acc) as u32;

        // Scalar tail for 0–15 remaining bytes.
        for &b in &bytes[i..] {
            match b {
                b'a'..=b'z' => lower_total += 1,
                b'A'..=b'Z' => upper_total += 1,
                b'0'..=b'9' => digit_total += 1,
                _ => {}
            }
        }

        CharClassProfile {
            lower: lower_total,
            upper: upper_total,
            digit: digit_total,
            special: bytes.len() as u32 - lower_total - upper_total - digit_total,
        }
    }
}

// ---------------------------------------------------------------------------
// SSE2 implementation (x86_64)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod sse2 {
    use super::CharClassProfile;
    use std::arch::x86_64::*;

    /// Horizontal sum of 16 u8 lanes via `_mm_sad_epu8` (psadbw against zero).
    ///
    /// # Safety
    /// Requires SSE2 intrinsics (baseline on all x86_64 targets).
    #[inline(always)]
    unsafe fn hsum_epu8(v: __m128i) -> u32 {
        let zero = _mm_setzero_si128();
        let sad = _mm_sad_epu8(v, zero); // sum each 8-byte half
        let hi = _mm_srli_si128(sad, 8); // shift high half to low
        let sum = _mm_add_epi32(sad, hi); // combine
        _mm_cvtsi128_si32(sum) as u32
    }

    /// SSE2-accelerated byte classification using signed-comparison pairs.
    ///
    /// # Safety
    /// Requires SSE2 intrinsics (baseline on all x86_64 targets).
    /// Handles all input lengths including empty and sub-16-byte inputs.
    pub(super) unsafe fn classify_window_sse2(bytes: &[u8]) -> CharClassProfile {
        // Signed comparison boundaries: byte in [lo, hi] ↔
        //   byte > (lo-1) AND (hi+1) > byte
        // Works for all 256 values: ASCII ranges are positive in i8;
        // bytes >= 0x80 are negative, failing all "> positive" checks.
        let lower_lo = _mm_set1_epi8((b'a' - 1) as i8); // 0x60
        let lower_hi = _mm_set1_epi8((b'z' + 1) as i8); // 0x7B
        let upper_lo = _mm_set1_epi8((b'A' - 1) as i8); // 0x40
        let upper_hi = _mm_set1_epi8((b'Z' + 1) as i8); // 0x5B
        let digit_lo = _mm_set1_epi8((b'0' - 1) as i8); // 0x2F
        let digit_hi = _mm_set1_epi8((b'9' + 1) as i8); // 0x3A

        let zero = _mm_setzero_si128();
        let mut lower_acc = zero;
        let mut upper_acc = zero;
        let mut digit_acc = zero;
        let (mut lower_total, mut upper_total, mut digit_total) = (0u32, 0u32, 0u32);

        let mut i = 0usize;
        let mut chunks_in_epoch = 0u8;

        // SAFETY: loop guard ensures i + 16 <= bytes.len(); _mm_loadu_si128
        // reads exactly 16 bytes (unaligned load, no alignment requirement).
        while i + 16 <= bytes.len() {
            let v = _mm_loadu_si128(bytes.as_ptr().add(i) as *const __m128i);

            let is_lower = _mm_and_si128(_mm_cmpgt_epi8(v, lower_lo), _mm_cmpgt_epi8(lower_hi, v));
            let is_upper = _mm_and_si128(_mm_cmpgt_epi8(v, upper_lo), _mm_cmpgt_epi8(upper_hi, v));
            let is_digit = _mm_and_si128(_mm_cmpgt_epi8(v, digit_lo), _mm_cmpgt_epi8(digit_hi, v));

            // Accumulate: mask lanes are 0xFF on match (all bits set = -1 in i8);
            // subtracting -1 wraps to +1.
            lower_acc = _mm_sub_epi8(lower_acc, is_lower);
            upper_acc = _mm_sub_epi8(upper_acc, is_upper);
            digit_acc = _mm_sub_epi8(digit_acc, is_digit);

            i += 16;
            chunks_in_epoch += 1;

            // Flush before u8 lane overflow (max 255 increments per lane).
            if chunks_in_epoch == 255 {
                lower_total += hsum_epu8(lower_acc);
                upper_total += hsum_epu8(upper_acc);
                digit_total += hsum_epu8(digit_acc);
                lower_acc = zero;
                upper_acc = zero;
                digit_acc = zero;
                chunks_in_epoch = 0;
            }
        }

        // Final flush of remaining accumulator lanes.
        lower_total += hsum_epu8(lower_acc);
        upper_total += hsum_epu8(upper_acc);
        digit_total += hsum_epu8(digit_acc);

        // Scalar tail for 0–15 remaining bytes.
        for &b in &bytes[i..] {
            match b {
                b'a'..=b'z' => lower_total += 1,
                b'A'..=b'Z' => upper_total += 1,
                b'0'..=b'9' => digit_total += 1,
                _ => {}
            }
        }

        CharClassProfile {
            lower: lower_total,
            upper: upper_total,
            digit: digit_total,
            special: bytes.len() as u32 - lower_total - upper_total - digit_total,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_all_zeros() {
        let p = classify_window(b"");
        assert_eq!(p, CharClassProfile::default());
    }

    #[test]
    fn all_lowercase() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let p = classify_window(input);
        assert_eq!(p.lower, 26);
        assert_eq!(p.upper, 0);
        assert_eq!(p.digit, 0);
        assert_eq!(p.special, 0);
    }

    #[test]
    fn all_uppercase() {
        let input = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let p = classify_window(input);
        assert_eq!(p.lower, 0);
        assert_eq!(p.upper, 26);
        assert_eq!(p.digit, 0);
        assert_eq!(p.special, 0);
    }

    #[test]
    fn all_digits() {
        let input = b"0123456789";
        let p = classify_window(input);
        assert_eq!(p.lower, 0);
        assert_eq!(p.upper, 0);
        assert_eq!(p.digit, 10);
        assert_eq!(p.special, 0);
    }

    #[test]
    fn mixed_known_counts() {
        // 5 lower, 3 upper, 2 digit, 4 special
        let input = b"abcdeXYZ01!@#$";
        let p = classify_window(input);
        assert_eq!(p.lower, 5);
        assert_eq!(p.upper, 3);
        assert_eq!(p.digit, 2);
        assert_eq!(p.special, 4);
    }

    #[test]
    fn high_bytes_are_special() {
        let input: Vec<u8> = (128..=255).collect();
        let p = classify_window(&input);
        assert_eq!(p.lower, 0);
        assert_eq!(p.upper, 0);
        assert_eq!(p.digit, 0);
        assert_eq!(p.special, 128);
    }

    #[test]
    fn all_256_byte_values() {
        let input: Vec<u8> = (0..=255).collect();
        let p = classify_window(&input);
        assert_eq!(p.lower, 26); // a-z
        assert_eq!(p.upper, 26); // A-Z
        assert_eq!(p.digit, 10); // 0-9
        assert_eq!(p.special, 194); // 256 - 26 - 26 - 10
    }

    #[test]
    fn tail_handling() {
        // Test various lengths around SIMD boundaries.
        for &len in &[1, 15, 16, 17, 31, 32, 33, 47, 48, 49] {
            let input: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            let p = classify_window(&input);
            assert_eq!(p.lower, len as u32, "lower count mismatch for len={}", len);
            assert_eq!(
                p.upper + p.digit + p.special,
                0,
                "non-lower for len={}",
                len
            );
        }
    }

    #[test]
    fn sum_equals_length() {
        let input: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let p = classify_window(&input);
        assert_eq!(p.lower + p.upper + p.digit + p.special, 1024);
    }

    #[test]
    fn scalar_matches_dispatch() {
        let input: Vec<u8> = (0..=255).cycle().take(300).collect();
        let from_dispatch = classify_window(&input);
        let from_scalar = classify_window_scalar(&input);
        assert_eq!(from_dispatch, from_scalar);
    }

    /// Boundary bytes: just outside each range should be special.
    #[test]
    fn boundary_bytes() {
        // Bytes just outside lowercase: '`' (0x60) and '{' (0x7B)
        // Bytes just outside uppercase: '@' (0x40) and '[' (0x5B)
        // Bytes just outside digits: '/' (0x2F) and ':' (0x3A)
        let input = b"`{@[/:";
        let p = classify_window(input);
        assert_eq!(p.special, 6);
        assert_eq!(p.lower + p.upper + p.digit, 0);
    }

    /// Large input that forces accumulator flush (255 chunks × 16 = 4080 bytes).
    #[test]
    fn large_input_flush() {
        let input = vec![b'a'; 4096];
        let p = classify_window(&input);
        assert_eq!(p.lower, 4096);
        assert_eq!(p.upper + p.digit + p.special, 0);
    }

    /// Deterministic test that forces all four accumulator lanes to flush,
    /// verifying counts are correct across multiple flush epochs.
    #[test]
    fn large_input_flush_all_lanes() {
        // Cycling pattern: one byte from each class, repeated to 4096+ bytes.
        let pattern = [b'a', b'A', b'0', b'!'];
        let input: Vec<u8> = pattern.iter().copied().cycle().take(4100).collect();
        let p = classify_window(&input);
        // 4100 / 4 = 1025 of each class.
        assert_eq!(p.lower, 1025, "lower count");
        assert_eq!(p.upper, 1025, "upper count");
        assert_eq!(p.digit, 1025, "digit count");
        assert_eq!(p.special, 1025, "special count");
        assert_eq!(
            p.lower + p.upper + p.digit + p.special,
            4100,
            "sum must equal length"
        );
    }
}

// ---------------------------------------------------------------------------
// Property-based tests (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "stdx-proptest"))]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(crate::test_utils::proptest_cases(256)))]

        #[test]
        fn simd_matches_scalar(input in prop::collection::vec(any::<u8>(), 0..8192)) {
            prop_assert_eq!(classify_window(&input), classify_window_scalar(&input));
        }

        #[test]
        fn sum_equals_length(input in prop::collection::vec(any::<u8>(), 0..8192)) {
            let p = classify_window(&input);
            prop_assert_eq!(p.lower + p.upper + p.digit + p.special, input.len() as u32);
        }

        #[test]
        fn concatenation_additivity(
            a in prop::collection::vec(any::<u8>(), 0..4096),
            b in prop::collection::vec(any::<u8>(), 0..4096),
        ) {
            let pa = classify_window(&a);
            let pb = classify_window(&b);
            let combined: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
            let pc = classify_window(&combined);
            prop_assert_eq!(pc.lower, pa.lower + pb.lower);
            prop_assert_eq!(pc.upper, pa.upper + pb.upper);
            prop_assert_eq!(pc.digit, pa.digit + pb.digit);
            prop_assert_eq!(pc.special, pa.special + pb.special);
        }
    }
}
