//! Property tests for archive entry path canonicalization.
//!
//! # Invariants
//! - Output is deterministic, bounded, and traversal-safe.
//! - Percent-encoding is well-formed.

use proptest::prelude::*;
use scanner_scheduler::archive::{DEFAULT_MAX_COMPONENTS, EntryPathCanonicalizer};

fn is_upper_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'A'..=b'F').contains(&b)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn canonicalizer_is_bounded_deterministic_and_traversal_safe(raw in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let max_len = 128usize;
        let mut canon = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, max_len);

        let a = canon.canonicalize(&raw, DEFAULT_MAX_COMPONENTS, max_len);
        let out_a = a.bytes.to_vec();
        let had_traversal_a = a.had_traversal;
        let truncated_a = a.truncated;

        let b = canon.canonicalize(&raw, DEFAULT_MAX_COMPONENTS, max_len);
        let out_b = b.bytes.to_vec();
        let had_traversal_b = b.had_traversal;
        let truncated_b = b.truncated;

        prop_assert_eq!(&out_a, &out_b);
        prop_assert_eq!(had_traversal_a, had_traversal_b);
        prop_assert_eq!(truncated_a, truncated_b);

        prop_assert!(!out_a.is_empty());
        prop_assert!(out_a.len() <= max_len);
        prop_assert!(!out_a.contains(&b'\\'));

        for comp in out_a.split(|&c| c == b'/') {
            prop_assert!(comp != b".");
            prop_assert!(comp != b"..");
        }
    }

    #[test]
    fn truncation_sets_flag_for_long_inputs(raw in proptest::collection::vec(any::<u8>(), 1024..4096)) {
        let max_len = 64usize;
        let mut canon = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, max_len);

        let r = canon.canonicalize(&raw, DEFAULT_MAX_COMPONENTS, max_len);
        prop_assert!(r.bytes.len() <= max_len);
        // If input is large, we usually truncate (allow false if canonicalization collapses heavily).
        if raw.len() > 2048 {
            prop_assert!(r.truncated || r.bytes.len() < max_len);
        }
    }

    #[test]
    fn percent_encoding_is_well_formed(raw in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let max_len = 128usize;
        let mut canon = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, max_len);
        let r = canon.canonicalize(&raw, DEFAULT_MAX_COMPONENTS, max_len);

        let out = r.bytes;
        let mut i = 0usize;
        while i < out.len() {
            if out[i] == b'%' {
                prop_assert!(i + 2 < out.len());
                prop_assert!(is_upper_hex(out[i + 1]));
                prop_assert!(is_upper_hex(out[i + 2]));
                i += 3;
            } else {
                i += 1;
            }
        }
    }
}

#[test]
fn canonicalizer_normalizes_separators() {
    let mut canon = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 128);
    let r = canon.canonicalize(br"\foo\bar//baz/", DEFAULT_MAX_COMPONENTS, 128);
    assert_eq!(r.bytes, b"foo/bar/baz");
    assert!(!r.bytes.contains(&b'\\'));
}

#[test]
fn canonicalizer_preserves_drive_prefix_component() {
    let mut canon = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 128);
    let r = canon.canonicalize(
        br"C:\Windows\System32\..\Temp\file.txt",
        DEFAULT_MAX_COMPONENTS,
        128,
    );
    assert_eq!(r.bytes, b"C:/Windows/Temp/file.txt");
    assert!(!r.bytes.contains(&b'\\'));
}
