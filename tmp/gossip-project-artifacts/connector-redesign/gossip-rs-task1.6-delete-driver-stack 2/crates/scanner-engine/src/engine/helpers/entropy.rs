//! Entropy gating helpers for Shannon and min-entropy checks.
//!
//! This module implements the entropy-family gate used to discard low-randomness
//! regex matches early in the detection pipeline. Two complementary metrics are
//! supported:
//!
//! - **Shannon entropy** (always): measures average information per byte. Rejects
//!   many non-secret matches (repeated characters, prose fragments).
//! - **Min-entropy** (optional, per NIST SP 800-90B): `H_inf = log2(n) - log2(max_count)`.
//!   Catches skewed distributions where one byte dominates even though Shannon
//!   looks moderate.
//! - **Digit-only penalty** (optional): for all-ASCII-digit slices, subtract
//!   `DIGIT_ONLY_PENALTY_NUMERATOR / log2(len)` from Shannon before
//!   thresholding (detect-secrets style).
//!
//! # Role in the confidence model
//!
//! The entropy gate serves a dual purpose:
//! 1. **Hard gate**: findings with `EntropyGateOutcome::Failed` are discarded
//!    unconditionally (they never reach the emission pipeline).
//! 2. **Evidence signal**: findings with `EntropyGateOutcome::PassedMeasured`
//!    contribute `confidence::ENTROPY_PASS` (+1) to the additive confidence
//!    score. Findings that bypass the gate due to short length (`BypassedShortLen`)
//!    contribute 0 — they are not penalized, but they do not earn positive evidence.
//!
//! # Gate evaluation sequence
//!
//! [`entropy_gate_outcome`] evaluates checks in a specific order to fail fast:
//!
//! 1. **Length check** -- `len < min_len` returns `BypassedShortLen` immediately.
//!    Short samples have noisy entropy; failing open avoids false negatives.
//! 2. **Histogram + metrics** -- two fused loops compute all metrics over
//!    `bytes[..min(len, max_len)]`: a byte-level pass builds the histogram
//!    and tracks the all-digits flag, then a 256-bin scan derives Shannon
//!    entropy and max-bin-count.
//! 3. **Digit penalty** (if enabled) -- for all-digit slices, subtract
//!    `DIGIT_ONLY_PENALTY_NUMERATOR / log2(capped_len)` from Shannon before
//!    thresholding.
//! 4. **Shannon check** -- compare effective Shannon against `min_bits_per_byte`.
//! 5. **Min-entropy check** (if configured) -- compare `H_inf` against
//!    `min_entropy_bits_per_byte`. Checked second because Shannon already
//!    rejects most low-randomness inputs at lower cost.
//!
//! # Performance
//!
//! The histogram is computed in a single branchless pass over the input bytes.
//! A pre-built `log2` lookup table avoids per-bin floating-point calls
//! during the Shannon summation over all 256 histogram bins.
//! Scratch memory (`EntropyScratch`) is reused across checks to avoid allocation.

use crate::engine::rule_repr::EntropyCompiled;
use crate::engine::scratch::EntropyScratch;

/// Numerator of the detect-secrets digit-only penalty: `penalty = 1.2 / log2(len)`.
///
/// Derived from detect-secrets' heuristic for all-digit strings, which tend to
/// have inflated Shannon entropy because the 10-symbol alphabet is dense relative
/// to its byte representation. The penalty scales inversely with length so that
/// shorter digit sequences (where false-positive risk is highest) receive a
/// stronger downward adjustment.
const DIGIT_ONLY_PENALTY_NUMERATOR: f32 = 1.2;

/// Builds the `log2(i)` lookup table used by entropy calculations.
///
/// Built once per [`Engine`](super::core::Engine) at construction time, sized to
/// `max(entropy_gate.max_len)` across all compiled rules. The table is stored on
/// the `Engine` and passed by reference into every entropy check, eliminating
/// per-window `f32::log2` calls on the hot path.
///
/// Index 0 is unused (log2(0) is undefined); index 1 is `log2(1) = 0.0`.
/// Values beyond the table length fall back to a runtime `log2` call via
/// [`log2_lookup`].
pub(crate) fn build_log2_table(max: usize) -> Vec<f32> {
    let len = max.saturating_add(1).max(2);
    let mut t = vec![0.0f32; len];
    for (i, val) in t.iter_mut().enumerate().skip(1) {
        *val = (i as f32).log2();
    }
    t
}

/// Returns `log2(n)` from the precomputed table, falling back to a runtime
/// `f32::log2` call for values beyond the table bounds. The fallback is
/// cold-path only: table sizing in [`build_log2_table`] guarantees all
/// in-spec entropy windows hit the table.
#[inline]
fn log2_lookup(table: &[f32], n: usize) -> f32 {
    if n < table.len() {
        table[n]
    } else {
        (n as f32).log2()
    }
}

/// Raw metric values from the entropy-family gate.
///
/// Shannon entropy and max-bin-count are computed in a single fused pass over
/// the 256-bin histogram inside [`compute_entropy_metrics`]; the all-digits
/// flag is piggybacked onto the preceding histogram-building loop; `log2_n`
/// is a standalone table lookup.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EntropyMetrics {
    /// Shannon entropy in bits per byte.
    pub(crate) shannon_bpb: f32,
    /// Maximum bin count across all 256 histogram bins.
    ///
    /// Used for min-entropy: `H_inf = log2(n) - log2(max_bin_count)`.
    pub(crate) max_bin_count: u32,
    /// Precomputed `log2(n)` where `n` is the input length.
    ///
    /// Cached here so that [`entropy_gate_outcome`] can reuse the value for the
    /// min-entropy calculation without a second table lookup after the
    /// `scratch.reset()` / `bzero` barrier that prevents CSE.
    pub(crate) log2_n: f32,
    /// True when every evaluated byte is an ASCII digit (`0..=9`).
    pub(crate) all_ascii_digits: bool,
}

/// Canonical decision outcome for an entropy gate evaluation.
///
/// Consumed by the confidence-scoring pipeline in `window_validate.rs`:
/// - `Failed` vetoes the finding (hard gate, never emitted).
/// - `PassedMeasured` awards `confidence::ENTROPY_PASS` (+1).
/// - `BypassedShortLen` awards 0 (fail-open, no evidence either way).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntropyGateOutcome {
    /// Candidate failed measured entropy validation. The finding is
    /// unconditionally discarded — it never reaches confidence scoring.
    Failed,
    /// Candidate length is below `min_len`, so entropy is bypassed (fail-open).
    /// No positive evidence is contributed to the confidence score.
    BypassedShortLen,
    /// Candidate met all measured entropy checks (Shannon and optional min-entropy).
    /// Contributes `confidence::ENTROPY_PASS` to the finding's confidence score.
    PassedMeasured,
}

impl EntropyGateOutcome {
    /// Returns true when the candidate should proceed through detection flow.
    #[inline(always)]
    #[allow(dead_code)] // Used by bench/test-only call sites.
    pub(crate) fn allows_candidate(self) -> bool {
        !matches!(self, Self::Failed)
    }
}

/// Computes Shannon entropy and max-bin-count in a single fused pass.
///
/// # Effects
/// - Uses and resets `scratch` for histogram bookkeeping.
/// - `scratch` contents are unspecified after return; it is meant for reuse.
///
/// # Returns
/// - `EntropyMetrics { shannon_bpb: 0.0, max_bin_count: 0, log2_n: 0.0, all_ascii_digits: false }` for empty input.
#[inline]
pub(crate) fn compute_entropy_metrics(
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> EntropyMetrics {
    let n = bytes.len();
    if n == 0 {
        return EntropyMetrics {
            shannon_bpb: 0.0,
            max_bin_count: 0,
            log2_n: 0.0,
            all_ascii_digits: false,
        };
    }

    // Branchless histogram: unconditionally increment the bin for each byte.
    // No "first touch" tracking -- the reset zeroes all 256 bins via memset.
    // The digit-flag check is fused here to avoid a second pass over the input.
    let mut all_ascii_digits = true;
    for &b in bytes {
        // SAFETY: b is u8, so b as usize is in 0..256; counts has exactly 256 entries.
        unsafe { *scratch.counts.get_unchecked_mut(b as usize) += 1 };
        all_ascii_digits &= b.is_ascii_digit();
    }

    // Shannon entropy: H = log2(n) - (1/n) * sum(c_i * log2(c_i))
    // This rearrangement avoids repeated divisions.
    let log2_n = log2_lookup(log2_table, n);
    let mut sum_c_log2_c = 0.0f32;
    let mut max_bin_count: u32 = 0;

    // Scan all 256 bins. For random data most bins are nonzero (predictable);
    // for short inputs most bins are zero (also predictable). Either way the
    // branch predictor handles this well, and we avoid the per-byte branch
    // that the previous "touched list" approach required in the hot histogram loop.
    //
    // The `max_bin_count` tracking adds ~1 instruction per iteration (cmov),
    // a <5% cost increase over the Shannon-only loop.
    for i in 0..256 {
        // SAFETY: loop bounds guarantee `i` is always in 0..256, which matches
        // the exact length of `counts`.
        let c = unsafe { *scratch.counts.get_unchecked(i) };
        if c > max_bin_count {
            max_bin_count = c;
        }
        let cu = c as usize;
        if cu > 0 {
            sum_c_log2_c += (cu as f32) * log2_lookup(log2_table, cu);
        }
    }

    scratch.reset();

    EntropyMetrics {
        shannon_bpb: log2_n - (sum_c_log2_c / (n as f32)),
        max_bin_count,
        log2_n,
        all_ascii_digits,
    }
}

/// Computes Shannon entropy in bits per byte for the given slice.
///
/// Thin wrapper over [`compute_entropy_metrics`] for callers that only need
/// Shannon entropy. Kept as a separate function for benchmark helper
/// compatibility.
///
/// # Returns
/// - 0.0 for empty input.
#[inline]
#[allow(dead_code)] // Used by bench helpers and tests.
pub(crate) fn shannon_entropy_bits_per_byte(
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> f32 {
    compute_entropy_metrics(bytes, scratch, log2_table).shannon_bpb
}

/// Returns the canonical entropy gate outcome for this candidate.
///
/// This is the single entry point for entropy-based filtering in the detection
/// pipeline. It is called from `window_validate.rs` after a regex match
/// extracts the secret span, and its outcome feeds both the hard-gate discard
/// logic and the additive confidence score.
///
/// # Evaluation order
///
/// Checks are ordered to fail fast on the cheapest test first:
///
/// 1. Length bypass (`< min_len`) -- O(1), no histogram work.
/// 2. Shannon threshold -- rejects the vast majority of low-randomness input.
/// 3. Min-entropy threshold (optional) -- only reached by inputs that pass
///    Shannon, catching the narrower class of skewed-but-moderate distributions.
///
/// # Behavior
/// - Buffers shorter than `spec.min_len` always pass (entropy is noisy).
/// - Longer buffers are capped at `spec.max_len` for the computation.
/// - If `spec.digit_penalty` is enabled, all-digit bytes in the capped slice
///   use `effective_shannon = shannon - (DIGIT_ONLY_PENALTY_NUMERATOR / log2(capped_len))`.
///   (`capped_len == 1` skips the penalty to avoid division by zero.)
///   The penalty can push effective Shannon below zero, rejecting candidates
///   even with `min_bits_per_byte: 0.0`.
/// - Shannon entropy is always checked first.
/// - Min-entropy (optional, per NIST SP 800-90B) is checked second: it catches
///   distributions where one byte dominates even though Shannon looks moderate.
///
/// # Preconditions
/// - `spec.min_len >= 1`.
/// - `spec.min_len <= spec.max_len`.
/// - `spec.min_bits_per_byte` is in [0.0, 8.0].
#[inline]
pub(crate) fn entropy_gate_outcome(
    spec: &EntropyCompiled,
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> EntropyGateOutcome {
    let len = bytes.len();
    if len < spec.min_len {
        // For tiny samples entropy is noisy; let them pass rather than
        // discarding true positives.
        return EntropyGateOutcome::BypassedShortLen;
    }
    let capped = len.min(spec.max_len);
    let metrics = compute_entropy_metrics(&bytes[..capped], scratch, log2_table);

    // detect-secrets style penalty for digit-only strings in the capped slice:
    // effective_shannon = shannon - (DIGIT_ONLY_PENALTY_NUMERATOR / log2(capped_len)); skip when len==1.
    let effective_shannon =
        if spec.digit_penalty && metrics.all_ascii_digits && metrics.log2_n > 0.0 {
            metrics.shannon_bpb - (DIGIT_ONLY_PENALTY_NUMERATOR / metrics.log2_n)
        } else {
            metrics.shannon_bpb
        };

    // Shannon (always checked).
    if effective_shannon < spec.min_bits_per_byte {
        return EntropyGateOutcome::Failed;
    }

    // Min-entropy (optional, per NIST SP 800-90B).
    if let Some(me_min) = spec.min_entropy_bits_per_byte {
        // max_bin_count == 0 only for empty input, which cannot reach this
        // branch when specs are validated (`min_len >= 1`).
        if metrics.max_bin_count == 0 {
            return EntropyGateOutcome::Failed;
        }
        let me = metrics.log2_n - log2_lookup(log2_table, metrics.max_bin_count as usize);
        if me < me_min {
            return EntropyGateOutcome::Failed;
        }
    }

    EntropyGateOutcome::PassedMeasured
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Shannon entropy (standalone) ----

    // Sidekiq secrets are `[a-f0-9]{8}:[a-f0-9]{8}` (17 bytes). The embedded
    // colon and short length make Shannon entropy noisy — random hex pairs can
    // dip below 3.0 bits/byte. The gate is set to 2.5 to avoid false negatives.
    #[test]
    fn sidekiq_hex_pair_entropy_above_gate() {
        let secret = b"76609006:7d494d19";
        let table = build_log2_table(secret.len());
        let mut scratch = EntropyScratch::new();
        let e = shannon_entropy_bits_per_byte(secret, &mut scratch, &table);
        // Should pass the 2.5 gate but would fail a 3.0 gate.
        assert!(
            e >= 2.5,
            "sidekiq hex-pair secret has entropy {e:.3} bits/byte, below the 2.5 gate"
        );
        assert!(
            e < 3.0,
            "expected entropy below 3.0 for this hex-pair, got {e:.3}"
        );
    }

    // ---- min-entropy (NIST SP 800-90B) ----

    /// All-same-byte: max_count = n, H_inf = log2(n) - log2(n) = 0.0.
    #[test]
    fn min_entropy_all_same_byte() {
        let input = [0xAAu8; 100];
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 100);
        let me = (100f32).log2() - (100f32).log2();
        assert!((me - 0.0).abs() < f32::EPSILON, "expected 0.0, got {me}");
    }

    /// Perfectly uniform 256 values: max_count = 1, H_inf = log2(256) - log2(1) = 8.0.
    #[test]
    fn min_entropy_perfectly_uniform() {
        let input: Vec<u8> = (0..=255).collect();
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 1);
        let me = (256f32).log2() - (1f32).log2();
        assert!((me - 8.0).abs() < 0.001, "expected 8.0, got {me}");
    }

    /// Uniform hex 32 bytes (2 per bin for 16 bins): H_inf = log2(32) - log2(2) = 4.0.
    #[test]
    fn min_entropy_uniform_hex() {
        let input: Vec<u8> = (0..16u8).cycle().take(32).collect();
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 2);
        let me = (32f32).log2() - (2f32).log2();
        assert!((me - 4.0).abs() < 0.001, "expected 4.0, got {me}");
    }

    /// Discriminative power: 50 copies of 'a' + one each of 49 other chars.
    /// Shannon is moderate (many distinct chars). Min-entropy is extremely low
    /// (~1.0 bpb) because one char dominates. A `min_entropy_bits_per_byte: 2.0`
    /// rejects this while Shannon alone would pass.
    #[test]
    fn min_entropy_discriminates_skewed_distribution() {
        let mut input = vec![b'a'; 50];
        for i in 0..49u8 {
            input.push(b'b' + i);
        }
        let n = input.len(); // 99
        let table = build_log2_table(n);
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 50);
        let me = (n as f32).log2() - (50f32).log2();
        // me = log2(99) - log2(50) ~ 6.63 - 5.64 = 0.98
        assert!(me < 2.0, "expected min-entropy < 2.0, got {me}");
        // Shannon should be moderate (many distinct chars contribute)
        assert!(
            m.shannon_bpb > 2.5,
            "expected Shannon > 2.5, got {}",
            m.shannon_bpb
        );
    }

    /// n=1: max_count = 1, min-entropy = 0.0 (log2(1) - log2(1) = 0).
    #[test]
    fn min_entropy_single_byte() {
        let input = [42u8];
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        let m = compute_entropy_metrics(&input, &mut scratch, &table);
        assert_eq!(m.max_bin_count, 1);
        let me = (1f32).log2() - (1f32).log2();
        assert!((me - 0.0).abs() < f32::EPSILON);
    }

    // ---- entropy_gate_outcome integration ----

    /// With min_entropy_bits_per_byte = None, outcome follows Shannon-only behavior.
    #[test]
    fn entropy_gate_none_min_entropy_is_shannon_only() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 3.0,
            digit_penalty: false,
            min_len: 1,
            max_len: 256,
            min_entropy_bits_per_byte: None,
        };
        // High-entropy random bytes should pass.
        let input: Vec<u8> = (0..=255).collect();
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        assert!(
            entropy_gate_outcome(&spec, &input, &mut scratch, &table).allows_candidate(),
            "high-entropy input should pass Shannon-only gate"
        );
    }

    #[test]
    fn entropy_outcome_failed_when_measured_entropy_below_threshold() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 7.0,
            digit_penalty: false,
            min_len: 8,
            max_len: 64,
            min_entropy_bits_per_byte: None,
        };
        let input = b"AAAAAAAA";
        let table = build_log2_table(64);
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&spec, input, &mut scratch, &table),
            EntropyGateOutcome::Failed
        );
    }

    #[test]
    fn entropy_outcome_bypassed_for_short_input() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 8.0,
            digit_penalty: false,
            min_len: 10,
            max_len: 64,
            min_entropy_bits_per_byte: Some(8.0),
        };
        let input = b"short";
        let table = build_log2_table(64);
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&spec, input, &mut scratch, &table),
            EntropyGateOutcome::BypassedShortLen
        );
    }

    #[test]
    fn entropy_outcome_passed_when_measured_entropy_meets_threshold() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 3.0,
            digit_penalty: false,
            min_len: 8,
            max_len: 64,
            min_entropy_bits_per_byte: None,
        };
        let input = b"A1b2C3d4";
        let table = build_log2_table(64);
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&spec, input, &mut scratch, &table),
            EntropyGateOutcome::PassedMeasured
        );
    }

    /// entropy_gate_outcome rejects skewed distribution via min-entropy.
    #[test]
    fn entropy_gate_rejects_via_min_entropy() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 1.0, // Very low Shannon threshold (passes)
            digit_penalty: false,
            min_len: 1,
            max_len: 256,
            min_entropy_bits_per_byte: Some(2.0), // Min-entropy gate catches it
        };
        // 50 copies of 'a' + one each of 49 other chars (99 bytes).
        let mut input = vec![b'a'; 50];
        for i in 0..49u8 {
            input.push(b'b' + i);
        }
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        // Shannon passes (> 1.0) but min-entropy (~0.98) fails the 2.0 gate.
        assert_eq!(
            entropy_gate_outcome(&spec, &input, &mut scratch, &table),
            EntropyGateOutcome::Failed
        );
    }

    /// Boundary: input at exactly min_len - 1 always passes (bypass).
    #[test]
    fn entropy_gate_below_min_len_passes() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 8.0, // Impossibly high
            digit_penalty: false,
            min_len: 10,
            max_len: 256,
            min_entropy_bits_per_byte: Some(8.0), // Impossibly high
        };
        let input = [0u8; 9]; // Below min_len
        let table = build_log2_table(256);
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&spec, &input, &mut scratch, &table),
            EntropyGateOutcome::BypassedShortLen
        );
    }

    /// Boundary: input at exactly max_len + 1 is capped to max_len.
    #[test]
    fn entropy_gate_caps_at_max_len() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 3.0,
            digit_penalty: false,
            min_len: 1,
            max_len: 10,
            min_entropy_bits_per_byte: None,
        };
        // 10 unique + 10 zeros. If capped to 10, all unique -> high entropy.
        let mut input: Vec<u8> = (0..10).collect();
        input.extend([0u8; 10]);
        let table = build_log2_table(20);
        let mut scratch = EntropyScratch::new();
        // Capped to first 10 bytes (all unique) -> max entropy -> passes.
        assert_eq!(
            entropy_gate_outcome(&spec, &input, &mut scratch, &table),
            EntropyGateOutcome::PassedMeasured
        );
    }

    /// Short hex tokens (n=17, k=16) without min-entropy pass the gate.
    ///
    /// `sidekiq-secret` / `sidekiq-sensitive-url` match `[a-f0-9]{8}:[a-f0-9]{8}`
    /// (17 bytes). At this length, a 2.0 bpb min-entropy gate rejects ~3.7%
    /// of uniformly random valid tokens (any hex nibble appearing 5+ times
    /// drives H_inf below 2.0). The production rule therefore omits the
    /// min-entropy gate and relies on Shannon + keyword alone.
    #[test]
    fn short_hex_token_passes_without_min_entropy_gate() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 2.5,
            digit_penalty: false,
            min_len: 16,
            max_len: 256,
            min_entropy_bits_per_byte: None, // No min-entropy for short hex
        };
        let table = build_log2_table(256);
        let mut scratch = EntropyScratch::new();

        // Token with repeated nibble ('6' appears 5 times) -- would fail a
        // 2.0 bpb min-entropy gate but must pass Shannon-only.
        let token = b"66609066:7d494d16";
        assert!(
            entropy_gate_outcome(&spec, token, &mut scratch, &table).allows_candidate(),
            "short hex token with repeated nibble should pass without min-entropy gate"
        );
    }

    // ---- digit-only penalty (detect-secrets style) ----

    #[test]
    fn digit_penalty_is_opt_in() {
        let base = EntropyCompiled {
            min_bits_per_byte: 3.0,
            digit_penalty: false,
            min_len: 1,
            max_len: 64,
            min_entropy_bits_per_byte: None,
        };
        let with_penalty = EntropyCompiled {
            digit_penalty: true,
            ..base
        };

        let input = b"0123456789";
        let table = build_log2_table(64);
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&base, input, &mut scratch, &table),
            EntropyGateOutcome::PassedMeasured
        );
        assert_eq!(
            entropy_gate_outcome(&with_penalty, input, &mut scratch, &table),
            EntropyGateOutcome::Failed
        );
    }

    #[test]
    fn digit_penalty_skips_mixed_candidates() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 3.0,
            digit_penalty: true,
            min_len: 1,
            max_len: 64,
            min_entropy_bits_per_byte: None,
        };
        let input = b"01234a6789";
        let table = build_log2_table(64);
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&spec, input, &mut scratch, &table),
            EntropyGateOutcome::PassedMeasured
        );
    }

    #[test]
    fn digit_penalty_uses_capped_entropy_window() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 3.0,
            digit_penalty: true,
            min_len: 1,
            max_len: 10,
            min_entropy_bits_per_byte: None,
        };
        // First max_len bytes are all digits; tail byte is non-digit.
        let input = b"0123456789X";
        let table = build_log2_table(input.len());
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&spec, input, &mut scratch, &table),
            EntropyGateOutcome::Failed
        );
    }

    #[test]
    fn digit_penalty_len_one_guard_does_not_penalize() {
        let spec = EntropyCompiled {
            min_bits_per_byte: 0.0,
            digit_penalty: true,
            min_len: 1,
            max_len: 1,
            min_entropy_bits_per_byte: None,
        };
        let input = b"7";
        let table = build_log2_table(1);
        let mut scratch = EntropyScratch::new();
        assert_eq!(
            entropy_gate_outcome(&spec, input, &mut scratch, &table),
            EntropyGateOutcome::PassedMeasured
        );
    }
}
