//! Property-based tests for archive kind detection (`detect.rs`).
//!
//! These tests verify invariants of the single-byte dispatch refactoring:
//! case insensitivity, trailing-slash stripping, short-input rejection,
//! `str`↔`bytes` delegation parity, and the `| 0x20` false-positive guard.

use super::*;
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

// ── Reference implementation ──────────────────────────────────────────

/// Naive reference implementation using `ends_with_ignore_ascii_case`.
/// Used as an oracle to verify the optimized single-byte dispatch.
fn reference_detect(name: &[u8]) -> Option<ArchiveKind> {
    let name = strip_trailing_slashes(name);
    if ends_with_ignore_ascii_case(name, b".tar.gz") || ends_with_ignore_ascii_case(name, b".tgz") {
        Some(ArchiveKind::TarGz)
    } else if ends_with_ignore_ascii_case(name, b".tar.bz2")
        || ends_with_ignore_ascii_case(name, b".tbz2")
    {
        Some(ArchiveKind::TarBz2)
    } else if ends_with_ignore_ascii_case(name, b".bz2") {
        Some(ArchiveKind::Bzip2)
    } else if ends_with_ignore_ascii_case(name, b".gz") {
        Some(ArchiveKind::Gzip)
    } else if ends_with_ignore_ascii_case(name, b".tar") {
        Some(ArchiveKind::Tar)
    } else if ends_with_ignore_ascii_case(name, b".zip") {
        Some(ArchiveKind::Zip)
    } else {
        None
    }
}

fn ends_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    let start = haystack.len() - needle.len();
    haystack[start..]
        .iter()
        .zip(needle)
        .all(|(h, n)| h.eq_ignore_ascii_case(n))
}

// ── Strategies ────────────────────────────────────────────────────────

/// Arbitrary byte slices 0..256 bytes (exercises the full input domain).
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

/// Realistic filenames: ASCII alphanumeric + common path/extension chars.
fn arb_filename() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_./-]{0,64}"
}

// ── Property tests ────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(PROPTEST_CASES)
    ))]

    /// The optimized dispatch must agree with the naive reference on all byte inputs.
    #[test]
    fn oracle_equivalence(name in arb_bytes()) {
        let optimized = detect_kind_from_name_bytes(&name);
        let reference = reference_detect(&name);
        prop_assert_eq!(
            optimized, reference,
            "mismatch on {:?} (len {})",
            String::from_utf8_lossy(&name), name.len()
        );
    }

    /// Case insensitivity: lowercasing all bytes must not change the result.
    #[test]
    fn case_insensitive(name in arb_bytes()) {
        let lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        prop_assert_eq!(
            detect_kind_from_name_bytes(&name),
            detect_kind_from_name_bytes(&lower),
            "case sensitivity bug on {:?}",
            String::from_utf8_lossy(&name)
        );
    }

    /// Appending a trailing `/` must not change the result.
    #[test]
    fn trailing_slash_invariance(name in arb_bytes()) {
        let base = detect_kind_from_name_bytes(&name);
        let mut with_slash = name.clone();
        with_slash.push(b'/');
        prop_assert_eq!(
            detect_kind_from_name_bytes(&with_slash),
            base,
            "trailing / changed result for {:?}",
            String::from_utf8_lossy(&name)
        );
    }

    /// Appending a trailing `\` must not change the result.
    #[test]
    fn trailing_backslash_invariance(name in arb_bytes()) {
        let base = detect_kind_from_name_bytes(&name);
        let mut with_backslash = name.clone();
        with_backslash.push(b'\\');
        prop_assert_eq!(
            detect_kind_from_name_bytes(&with_backslash),
            base,
            "trailing \\ changed result for {:?}",
            String::from_utf8_lossy(&name)
        );
    }

    /// Inputs shorter than 3 bytes (after trailing-slash stripping) must return None.
    #[test]
    fn short_input_returns_none(len in 0usize..3) {
        // Build a non-slash payload of exactly `len` bytes.
        let name: Vec<u8> = (0..len).map(|i| b'a' + (i as u8 % 26)).collect();
        prop_assert_eq!(
            detect_kind_from_name_bytes(&name),
            None,
            "short input {:?} should be None",
            String::from_utf8_lossy(&name)
        );
        // Also test inputs that become < 3 bytes after trailing-slash stripping.
        let mut with_slashes = name.clone();
        with_slashes.extend_from_slice(b"///");
        prop_assert_eq!(
            detect_kind_from_name_bytes(&with_slashes),
            None,
            "input {:?} with trailing slashes should be None",
            String::from_utf8_lossy(&with_slashes)
        );
    }

    /// `detect_kind_from_name(s)` must equal `detect_kind_from_name_bytes(s.as_bytes())`
    /// for all valid UTF-8 filenames.
    #[test]
    fn str_bytes_delegation_parity(name in arb_filename()) {
        prop_assert_eq!(
            detect_kind_from_name(&name),
            detect_kind_from_name_bytes(name.as_bytes()),
            "str/bytes mismatch for {:?}",
            name
        );
    }

    /// Append various non-alpha bytes (control chars, punctuation, high bytes)
    /// and verify the optimized dispatch agrees with the reference oracle.
    /// This guards against `| 0x20` mapping a non-letter to a dispatch target.
    #[test]
    fn or_0x20_false_positive_guard(prefix in arb_bytes()) {
        let non_alpha_tails: &[u8] = &[
            0x00, 0x1A, 0x3A, 0x5B, 0x5C, 0x5D, 0x7B, 0x7C, 0x7D, 0xFF,
        ];
        for &tail in non_alpha_tails {
            let mut input = prefix.clone();
            input.push(tail);
            let result = detect_kind_from_name_bytes(&input);
            // The reference oracle tells us what's correct.
            let expected = reference_detect(&input);
            prop_assert_eq!(
                result, expected,
                "false positive with tail byte 0x{:02X} on {:?}",
                tail, String::from_utf8_lossy(&input)
            );
        }
    }

    /// `strip_trailing_slashes` is idempotent: stripping twice yields the same
    /// result as stripping once.
    #[test]
    fn strip_idempotent(name in arb_bytes()) {
        let once = strip_trailing_slashes(&name);
        let twice = strip_trailing_slashes(once);
        prop_assert_eq!(once, twice, "strip not idempotent on {:?}", name);
    }
}
