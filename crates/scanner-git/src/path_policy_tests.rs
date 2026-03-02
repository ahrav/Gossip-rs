//! Property-based tests for path policy classification (`path_policy.rs`).
//!
//! Gated behind `feature = "stdx-proptest"`. Validates universal invariants of
//! `classify_path` and `is_nonscannable` over random byte paths and realistic
//! git-style paths.

use super::*;
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 256;

// ── Strategies ───────────────────────────────────────────────────────

/// Arbitrary byte slices 0..128 bytes.
fn arb_path_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..128)
}

/// Realistic ASCII git path: 1–5 segments joined by `/`, each segment is
/// lowercase alphanumeric 1–12 chars, last segment may have a `.ext`.
fn arb_git_path() -> impl Strategy<Value = Vec<u8>> {
    let segment = "[a-z0-9_-]{1,12}";
    let ext = prop::option::of("[a-z]{1,5}");
    (prop::collection::vec(segment, 1..=5), ext).prop_map(|(segs, ext)| {
        let mut path = segs.join("/");
        if let Some(e) = ext {
            path.push('.');
            path.push_str(&e);
        }
        path.into_bytes()
    })
}

/// A path guaranteed to contain one of the vendor directory segments.
fn arb_vendor_path() -> impl Strategy<Value = Vec<u8>> {
    let vendor_dir = prop::sample::select(&[
        "vendor",
        "third_party",
        "third-party",
        "thirdparty",
        "deps",
        "external",
        "extern",
        "node_modules",
    ]);
    let prefix = prop::option::of("[a-z]{1,8}");
    let suffix = "[a-z]{1,8}\\.[a-z]{1,4}";
    (vendor_dir, prefix, suffix).prop_map(|(vdir, pfx, file)| {
        let mut path = String::new();
        if let Some(p) = pfx {
            path.push_str(&p);
            path.push('/');
        }
        path.push_str(vdir);
        path.push('/');
        path.push_str(&file);
        path.into_bytes()
    })
}

// ── Properties ───────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(PROPTEST_CASES)
    ))]

    /// classify_path never returns an empty bitfield.
    #[test]
    fn result_is_never_empty(path in arb_path_bytes()) {
        let class = classify_path(&path);
        prop_assert!(!class.is_empty(), "empty result for path {:?}", path);
    }

    /// If UNKNOWN is set, no other bit is set.
    #[test]
    fn unknown_is_exclusive(path in arb_path_bytes()) {
        let class = classify_path(&path);
        if class.contains(PathClass::UNKNOWN) {
            prop_assert_eq!(
                class, PathClass::UNKNOWN,
                "UNKNOWN set alongside other bits: {:#04x}", class.bits()
            );
        }
    }

    /// If any known bit (SOURCE/TEST/VENDOR/GENERATED/BINARY) is set,
    /// UNKNOWN must be absent.
    #[test]
    fn non_unknown_excludes_unknown(path in arb_path_bytes()) {
        let class = classify_path(&path);
        let known = PathClass::SOURCE.0
            | PathClass::TEST.0
            | PathClass::VENDOR.0
            | PathClass::GENERATED.0
            | PathClass::BINARY.0
            | PathClass::LOCK_FILE.0;
        if (class.0 & known) != 0 {
            prop_assert!(
                !class.contains(PathClass::UNKNOWN),
                "UNKNOWN set with known bits: {:#04x}", class.bits()
            );
        }
    }

    /// Same input always yields the same output.
    #[test]
    fn deterministic(path in arb_path_bytes()) {
        let a = classify_path(&path);
        let b = classify_path(&path);
        prop_assert_eq!(a, b);
    }

    /// Lowercasing a path does not change the classification.
    #[test]
    fn case_insensitive(path in arb_git_path()) {
        let lower: Vec<u8> = path.iter().map(|b| b.to_ascii_lowercase()).collect();
        let upper: Vec<u8> = path.iter().map(|b| b.to_ascii_uppercase()).collect();
        let class_orig = classify_path(&path);
        let class_lower = classify_path(&lower);
        let class_upper = classify_path(&upper);
        prop_assert_eq!(
            class_orig, class_lower,
            "lowercase mismatch for {:?}", String::from_utf8_lossy(&path)
        );
        prop_assert_eq!(
            class_orig, class_upper,
            "uppercase mismatch for {:?}", String::from_utf8_lossy(&path)
        );
    }

    /// BINARY and SOURCE are never both set (the extension tables are disjoint).
    #[test]
    fn binary_and_source_exclusive(path in arb_path_bytes()) {
        let class = classify_path(&path);
        prop_assert!(
            !(class.contains(PathClass::BINARY) && class.contains(PathClass::SOURCE)),
            "BINARY and SOURCE both set for {:?}: {:#04x}",
            String::from_utf8_lossy(&path),
            class.bits()
        );
    }

    /// `is_nonscannable` is true iff BINARY or LOCK_FILE is set.
    #[test]
    fn nonscannable_iff_binary_or_lock(path in arb_path_bytes()) {
        let class = classify_path(&path);
        let expected = class.contains(PathClass::BINARY)
            || class.contains(PathClass::LOCK_FILE);
        prop_assert_eq!(
            class.is_nonscannable(), expected,
            "is_nonscannable mismatch for {:?}: class={:#04x}",
            String::from_utf8_lossy(&path), class.bits()
        );
    }

    /// LOCK_FILE and SOURCE are never both set.
    #[test]
    fn lock_file_and_source_exclusive(path in arb_path_bytes()) {
        let class = classify_path(&path);
        prop_assert!(
            !(class.contains(PathClass::LOCK_FILE) && class.contains(PathClass::SOURCE)),
            "LOCK_FILE and SOURCE both set for {:?}: {:#04x}",
            String::from_utf8_lossy(&path),
            class.bits()
        );
    }

    /// Paths containing a vendor directory segment always get the VENDOR bit.
    #[test]
    fn vendor_strategy_hits(path in arb_vendor_path()) {
        let class = classify_path(&path);
        prop_assert!(
            class.contains(PathClass::VENDOR),
            "VENDOR not set for {:?}: {:#04x}",
            String::from_utf8_lossy(&path),
            class.bits()
        );
    }
}
