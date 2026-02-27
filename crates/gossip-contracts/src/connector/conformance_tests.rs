use std::collections::HashSet;

use rstest::rstest;

use super::*;

const RAW_KEY_BYTES: &[u8] = b"raw-key-material";
const RAW_KEY_BYTES_ALT: &[u8] = b"raw-key-material-alt";
const RAW_FINGERPRINT_A: &[u8] = b"raw-fingerprint-a";
const RAW_FINGERPRINT_B: &[u8] = b"raw-fingerprint-b";
const RAW_PATTERN_BYTES: &[u8] = b"raw-pattern-secret";
const RAW_ITEM_REF_BYTES: &[u8] = b"raw-item-ref-secret";
const RAW_SPEC_START: &[u8] = b"zz-raw-spec-start";
const RAW_SPEC_END: &[u8] = b"aa-raw-spec-end";

fn sample_observation(key: &[u8], fingerprint_seed: &[u8]) -> ItemObservation {
    ItemObservation {
        key: Digest32::of_bytes(key),
        fingerprint: *blake3::hash(fingerprint_seed).as_bytes(),
    }
}

fn sample_page_validation_error() -> PageValidationError {
    struct EmptyItem;
    impl crate::connector::page_validator::PageItem<[u8]> for EmptyItem {
        fn item_key(&self) -> &[u8] {
            b""
        }
    }

    crate::connector::page_validator::validate_page_range::<[u8], EmptyItem>(
        RAW_SPEC_START,
        RAW_SPEC_END,
        None,
        &[],
        None,
    )
    .expect_err("descending bounded range must fail validation")
}

#[test]
fn conformance_config_default_is_strict() {
    let cfg = ConformanceConfig::default();
    assert_eq!(cfg.max_pages, 10_000);
    assert_eq!(cfg.max_total_items, 1_000_000);
    assert_eq!(cfg.page_budgets.max_items(), 32);
    assert_eq!(cfg.page_budgets.max_bytes(), u64::MAX);
    assert_eq!(cfg.page_budgets.deadline(), None);
    assert!(cfg.require_strict_key_order);
    assert!(cfg.require_cursor_eq_last_item);
    assert_eq!(cfg.determinism, DeterminismExpectation::Deterministic);
    assert_eq!(
        cfg.resume_checks,
        ResumeChecks {
            drop_token: true,
            corrupt_token: true,
        }
    );
    assert!(cfg.secret_scan.enabled);
    assert_eq!(cfg.restart_points, RestartPoints::Auto(4));
}

#[test]
fn secret_scan_config_default_matches_policy() {
    let cfg = SecretScanConfig::default();
    assert!(cfg.enabled);
    assert_eq!(
        cfg.forbidden_substrings,
        DEFAULT_FORBIDDEN_ITEMREF_PATTERNS.to_vec()
    );
    assert!(cfg.secret_canaries.is_empty());
}

#[test]
fn digest32_is_deterministic_hashable_and_redacted() {
    let digest_a = Digest32::of_bytes(RAW_KEY_BYTES);
    let digest_a_same = Digest32::of_bytes(RAW_KEY_BYTES);
    let digest_b = Digest32::of_bytes(RAW_KEY_BYTES_ALT);

    assert_eq!(digest_a, digest_a_same);
    assert_ne!(digest_a, digest_b);

    let mut seen = HashSet::new();
    seen.insert(digest_a);
    assert!(seen.contains(&digest_a_same));
    assert!(!seen.contains(&digest_b));

    let display = digest_a.to_string();
    let debug = format!("{digest_a:?}");
    assert!(display.starts_with("len="));
    assert!(display.contains(" hash_prefix8="));
    assert!(debug.starts_with("Digest32 { len: "));
    assert!(debug.contains("hash_prefix8: "));
    assert!(!display.contains("raw-key-material"));
    assert!(!debug.contains("raw-key-material"));
}

#[test]
fn item_observation_display_uses_only_safe_digests() {
    let obs = sample_observation(RAW_KEY_BYTES, RAW_FINGERPRINT_A);
    let rendered = obs.to_string();
    assert!(rendered.contains("key=("));
    assert!(rendered.contains("item_fp_prefix8="));
    assert!(rendered.contains(&format!("{}", obs.key)));
    assert!(!rendered.contains("raw-key-material"));
    assert!(!rendered.contains("raw-fingerprint-a"));
}

#[rstest]
#[case::capability_missing(
    ConformanceError::CapabilityMissingSeekByKey {
        caps: ConnectorCapabilities::default(),
    },
    "connector caps missing seek_by_key:"
)]
#[case::enumerate_failed(
    ConformanceError::EnumerateFailed {
        at_page: 2,
        class: ErrorClass::Retryable,
    },
    "enumerate_page failed at page 2 with retryable"
)]
#[case::too_many_items_page(
    ConformanceError::ReturnedTooManyItems {
        at_page: 3,
        got: 50,
        max: 32,
    },
    "enumerate_page returned too many items at page 3 (got 50, max 32)"
)]
#[case::page_validation_failed(
    ConformanceError::PageValidationFailed {
        at_page: 4,
        err: sample_page_validation_error(),
    },
    "page validation failed at page 4:"
)]
#[case::strict_increase_violation(
    ConformanceError::NotStrictlyIncreasingWithinPage {
        at_page: 5,
        at_index: 1,
        prev_key: Digest32::of_bytes(RAW_KEY_BYTES),
        next_key: Digest32::of_bytes(RAW_KEY_BYTES_ALT),
    },
    "keys not strictly increasing within page 5 at index 1:"
)]
#[case::cursor_last_item_mismatch(
    ConformanceError::CursorDoesNotMatchLastItem {
        at_page: 6,
        cursor_key: Some(Digest32::of_bytes(RAW_KEY_BYTES)),
        last_item_key: Digest32::of_bytes(RAW_KEY_BYTES_ALT),
    },
    "next_cursor.last_key mismatch at page 6:"
)]
#[case::cursor_last_item_mismatch_none(
    ConformanceError::CursorDoesNotMatchLastItem {
        at_page: 7,
        cursor_key: None,
        last_item_key: Digest32::of_bytes(RAW_KEY_BYTES),
    },
    "cursor_key=<none>"
)]
#[case::duplicate_key(
    ConformanceError::DuplicateKeyInRun {
        key: Digest32::of_bytes(RAW_KEY_BYTES),
    },
    "duplicate key observed in run:"
)]
#[case::too_many_pages(
    ConformanceError::TooManyPages { max_pages: 100 },
    "too many pages (max 100)"
)]
#[case::too_many_items_total(
    ConformanceError::TooManyItems {
        max_total_items: 1_000,
    },
    "too many items collected (max 1000)"
)]
#[case::determinism_mismatch(
    ConformanceError::DeterminismMismatch {
        at_index: 9,
        run1: sample_observation(RAW_KEY_BYTES, RAW_FINGERPRINT_A),
        run2: sample_observation(RAW_KEY_BYTES_ALT, RAW_FINGERPRINT_B),
    },
    "determinism mismatch at item index 9:"
)]
#[case::resume_mismatch(
    ConformanceError::ResumeMismatch {
        restart_cursor_index: 2,
        mode: ResumeMode::DropToken,
        at_index: 1,
        expected: sample_observation(RAW_KEY_BYTES, RAW_FINGERPRINT_A),
        got: sample_observation(RAW_KEY_BYTES_ALT, RAW_FINGERPRINT_B),
    },
    "resume mismatch (restart_cursor_index=2, mode=DropToken) at suffix index 1:"
)]
#[case::resume_length_mismatch(
    ConformanceError::ResumeLengthMismatch {
        restart_cursor_index: 3,
        mode: ResumeMode::CorruptToken,
        expected_len: 4,
        got_len: 3,
    },
    "resume length mismatch (restart_cursor_index=3, mode=CorruptToken): expected_len=4 got_len=3"
)]
#[case::item_ref_secret_match(
    ConformanceError::ItemRefAppearsToContainSecret {
        pattern: Digest32::of_bytes(RAW_PATTERN_BYTES),
        item_ref: Digest32::of_bytes(RAW_ITEM_REF_BYTES),
    },
    "item_ref appears to contain secret substring:"
)]
fn conformance_error_display_is_safe_and_variant_specific(
    #[case] err: ConformanceError,
    #[case] expected_snippet: &str,
) {
    let rendered = err.to_string();
    assert!(
        rendered.contains(expected_snippet),
        "missing snippet: {expected_snippet}; rendered={rendered}"
    );
    for raw in [
        "raw-key-material",
        "raw-key-material-alt",
        "raw-fingerprint-a",
        "raw-fingerprint-b",
        "raw-pattern-secret",
        "raw-item-ref-secret",
        "zz-raw-spec-start",
        "aa-raw-spec-end",
    ] {
        assert!(
            !rendered.contains(raw),
            "rendered output leaked raw bytes marker {raw}: {rendered}"
        );
    }
}

#[test]
fn digest32_display_only_contains_len_and_prefix() {
    let rendered = Digest32::of_bytes(b"secret").to_string();
    assert!(rendered.starts_with("len=6 hash_prefix8="));
    assert!(!rendered.contains("secret"));
    let prefix = rendered
        .strip_prefix("len=6 hash_prefix8=")
        .expect("display format should include len and hash prefix");
    assert_eq!(prefix.len(), 16);
    assert!(
        prefix.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')),
        "prefix must be lowercase hex: {prefix}"
    );
}

#[test]
fn digest32_empty_input() {
    let d = Digest32::of_bytes(b"");
    assert_eq!(d, Digest32::of_bytes(b""), "empty input must be stable");
    assert_ne!(d, Digest32::of_bytes(b"\0"), "empty differs from null byte");
    let rendered = d.to_string();
    assert!(
        rendered.starts_with("len=0 hash_prefix8="),
        "empty input must display len=0: {rendered}"
    );
}

proptest::proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn digest32_stability(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
        let a = Digest32::of_bytes(&bytes);
        let b = Digest32::of_bytes(&bytes);
        proptest::prop_assert_eq!(a, b, "of_bytes must be deterministic");
    }

    #[test]
    fn digest32_collision_freedom(
        x in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        y in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
    ) {
        proptest::prelude::prop_assume!(x != y);
        let dx = Digest32::of_bytes(&x);
        let dy = Digest32::of_bytes(&y);
        proptest::prop_assert_ne!(dx, dy, "distinct inputs must produce distinct digests");
    }
}
