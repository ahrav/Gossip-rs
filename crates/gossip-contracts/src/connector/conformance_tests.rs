//! Conformance harness unit tests.
//!
//! Test strategy in this module:
//!
//! - Use a scripted connector fixture (`scripted_make`) so each test controls
//!   exact page sequences and failure injection.
//! - Start from a reduced baseline config (`harness_cfg`) that disables
//!   optional checks, then opt into one behavior per test to keep failures
//!   attributable.
//! - Use raw byte marker constants only as leak sentinels to assert that
//!   diagnostics remain digest-only.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;

use rstest::rstest;

use crate::connector::{
    Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationPage, ErrorClass, ItemKey,
    ItemRef, ScanItem, TokenBytes, VersionId,
};
use crate::identity::{ObjectVersionId, StableItemId};

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
        key: ToxicDigest::of_bytes(key),
        fingerprint: ToxicDigest::of_bytes(fingerprint_seed),
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

#[derive(Clone)]
struct ScriptConnector {
    pages: VecDeque<Result<EnumerationPage, EnumerateError>>,
}

/// Build a connector factory where each factory call consumes one scripted run.
///
/// This mirrors `check_connector_conforms` behavior, which may construct
/// multiple connector instances (baseline, determinism rerun, resume checks).
fn scripted_make(
    runs: Vec<Vec<Result<EnumerationPage, EnumerateError>>>,
) -> impl Fn() -> ScriptConnector {
    let runs: VecDeque<VecDeque<Result<EnumerationPage, EnumerateError>>> =
        runs.into_iter().map(VecDeque::from).collect();
    let runs = Rc::new(RefCell::new(runs));
    move || {
        let pages = runs
            .borrow_mut()
            .pop_front()
            .expect("missing scripted connector run");
        ScriptConnector { pages }
    }
}

fn scripted_caps(_connector: &ScriptConnector) -> ConnectorCapabilities {
    ConnectorCapabilities {
        seek_by_key: true,
        token_resume: true,
        range_read: false,
        split_hints: false,
    }
}

fn scripted_enumerate(
    connector: &mut ScriptConnector,
    _cursor: &Cursor,
    _budgets: Budgets,
) -> Result<EnumerationPage, EnumerateError> {
    connector
        .pages
        .pop_front()
        .expect("unexpected enumerate_page call")
}

/// Baseline config for focused unit tests.
///
/// Optional conformance phases are disabled by default so tests can opt into
/// exactly one phase and assert a specific error mapping.
fn harness_cfg() -> ConformanceConfig {
    ConformanceConfig {
        determinism: DeterminismExpectation::BestEffort,
        resume_checks: ResumeChecks {
            drop_token: false,
            corrupt_token: false,
        },
        secret_scan: SecretScanConfig {
            enabled: false,
            ..SecretScanConfig::default()
        },
        restart_points: RestartPoints::Auto(0),
        ..ConformanceConfig::default()
    }
}

fn scan_item(key: &[u8], item_ref: &[u8]) -> ScanItem {
    let mut stable_id_bytes = [0_u8; 32];
    stable_id_bytes.copy_from_slice(blake3::hash(key).as_bytes());
    ScanItem::new(
        ItemKey::try_from_slice(key).expect("valid item key bytes"),
        ItemRef::try_from_slice(item_ref).expect("valid item_ref bytes"),
        StableItemId::from_bytes(stable_id_bytes),
        VersionId::Strong(ObjectVersionId::from_version_bytes(item_ref)),
    )
}

fn cursor(next_key: Option<&[u8]>, token: Option<&[u8]>) -> Cursor {
    match (next_key, token) {
        (None, None) => Cursor::initial(),
        (Some(last_key), None) => {
            Cursor::with_last_key(ItemKey::try_from_slice(last_key).expect("valid cursor key"))
        }
        (Some(last_key), Some(token)) => Cursor::with_token(
            ItemKey::try_from_slice(last_key).expect("valid cursor key"),
            TokenBytes::try_from_slice(token).expect("valid token bytes"),
        ),
        (None, Some(_)) => panic!("token requires a last_key"),
    }
}

fn page(
    items: &[(&[u8], &[u8])],
    next_key: Option<&[u8]>,
    token: Option<&[u8]>,
) -> EnumerationPage {
    let scan_items = items
        .iter()
        .map(|(key, item_ref)| scan_item(key, item_ref))
        .collect();
    EnumerationPage::new(scan_items, cursor(next_key, token))
}

fn default_range() -> (ItemKey, ItemKey) {
    (
        ItemKey::try_from_slice(b"a").expect("valid range start"),
        ItemKey::try_from_slice(b"z").expect("valid range end"),
    )
}

#[test]
fn conformance_config_default_is_strict() {
    let cfg = ConformanceConfig::default();
    assert_eq!(cfg.max_pages.get(), 10_000);
    assert_eq!(cfg.max_total_items.get(), 1_000_000);
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
fn toxic_digest_is_deterministic_hashable_and_redacted() {
    let digest_a = ToxicDigest::of_bytes(RAW_KEY_BYTES);
    let digest_a_same = ToxicDigest::of_bytes(RAW_KEY_BYTES);
    let digest_b = ToxicDigest::of_bytes(RAW_KEY_BYTES_ALT);

    assert_eq!(digest_a, digest_a_same);
    assert_ne!(digest_a, digest_b);

    let mut seen = HashSet::new();
    seen.insert(digest_a);
    assert!(seen.contains(&digest_a_same));
    assert!(!seen.contains(&digest_b));

    let display = digest_a.to_string();
    let debug = format!("{digest_a:?}");
    assert!(display.starts_with("len="));
    assert!(display.contains(", hash="));
    // ToxicDigest delegates Debug to Display.
    assert!(debug.starts_with("len="));
    assert!(debug.contains(", hash="));
    assert!(!display.contains("raw-key-material"));
    assert!(!debug.contains("raw-key-material"));
}

#[test]
fn item_observation_display_uses_only_safe_digests() {
    let obs = sample_observation(RAW_KEY_BYTES, RAW_FINGERPRINT_A);
    let rendered = obs.to_string();
    assert!(rendered.contains("key=("));
    assert!(rendered.contains("fingerprint=("));
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
        prev_key: ToxicDigest::of_bytes(RAW_KEY_BYTES),
        next_key: ToxicDigest::of_bytes(RAW_KEY_BYTES_ALT),
    },
    "keys not strictly increasing within page 5 at index 1:"
)]
#[case::cursor_last_item_mismatch(
    ConformanceError::CursorDoesNotMatchLastItem {
        at_page: 6,
        cursor_key: Some(ToxicDigest::of_bytes(RAW_KEY_BYTES)),
        last_item_key: ToxicDigest::of_bytes(RAW_KEY_BYTES_ALT),
    },
    "next_cursor.last_key mismatch at page 6:"
)]
#[case::cursor_last_item_mismatch_none(
    ConformanceError::CursorDoesNotMatchLastItem {
        at_page: 7,
        cursor_key: None,
        last_item_key: ToxicDigest::of_bytes(RAW_KEY_BYTES),
    },
    "cursor_key=<none>"
)]
#[case::duplicate_key(
    ConformanceError::DuplicateKeyInRun {
        key: ToxicDigest::of_bytes(RAW_KEY_BYTES),
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
#[case::cursor_key_not_in_baseline(
    ConformanceError::CursorKeyNotInBaseline {
        cursor_key: ToxicDigest::of_bytes(RAW_KEY_BYTES),
    },
    "resume cursor last_key not found in baseline items:"
)]
#[case::item_ref_secret_match(
    ConformanceError::ItemRefAppearsToContainSecret {
        pattern: ToxicDigest::of_bytes(RAW_PATTERN_BYTES),
        item_ref: ToxicDigest::of_bytes(RAW_ITEM_REF_BYTES),
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
fn toxic_digest_display_only_contains_len_and_prefix() {
    let rendered = ToxicDigest::of_bytes(b"secret").to_string();
    assert!(rendered.starts_with("len=6, hash="));
    assert!(!rendered.contains("secret"));
    let prefix = rendered
        .strip_prefix("len=6, hash=")
        .expect("display format should include len and hash prefix");
    assert_eq!(prefix.len(), 16);
    assert!(
        prefix.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')),
        "prefix must be lowercase hex: {prefix}"
    );
}

#[test]
fn toxic_digest_empty_input() {
    let d = ToxicDigest::of_bytes(b"");
    assert_eq!(d, ToxicDigest::of_bytes(b""), "empty input must be stable");
    assert_ne!(
        d,
        ToxicDigest::of_bytes(b"\0"),
        "empty differs from null byte"
    );
    let rendered = d.to_string();
    assert!(
        rendered.starts_with("len=0, hash="),
        "empty input must display len=0: {rendered}"
    );
}

#[test]
fn conformance_error_implements_std_error() {
    use std::error::Error;

    let err: Box<dyn Error> = Box::new(ConformanceError::TooManyPages { max_pages: 100 });
    assert!(
        err.source().is_none(),
        "ConformanceError must be a leaf error"
    );
    let s1 = err.to_string();
    let s2 = err.to_string();
    assert_eq!(s1, s2, "Display must be deterministic");
}

#[test]
fn resume_checks_modes_all_combinations() {
    let both = ResumeChecks {
        drop_token: true,
        corrupt_token: true,
    };
    let modes: Vec<_> = both.modes().collect();
    assert_eq!(modes, vec![ResumeMode::DropToken, ResumeMode::CorruptToken]);

    let none = ResumeChecks {
        drop_token: false,
        corrupt_token: false,
    };
    assert_eq!(none.modes().count(), 0);

    let drop_only = ResumeChecks {
        drop_token: true,
        corrupt_token: false,
    };
    let modes: Vec<_> = drop_only.modes().collect();
    assert_eq!(modes, vec![ResumeMode::DropToken]);

    let corrupt_only = ResumeChecks {
        drop_token: false,
        corrupt_token: true,
    };
    let modes: Vec<_> = corrupt_only.modes().collect();
    assert_eq!(modes, vec![ResumeMode::CorruptToken]);
}

#[test]
fn enumeration_trace_debug_does_not_leak_raw_bytes() {
    use crate::connector::{Cursor, ItemKey, TokenBytes};

    let raw_key = b"secret-key-material-xyzzy";
    let raw_token = b"opaque-token-material-plugh";
    let raw_fp_seed = b"fingerprint-seed-abcde";

    let cursor = Cursor::with_token(
        ItemKey::try_from_slice(raw_key).unwrap(),
        TokenBytes::try_from_slice(raw_token).unwrap(),
    );
    let trace = EnumerationTrace {
        items: vec![sample_observation(raw_key, raw_fp_seed)],
        cursors: vec![cursor],
        pages: 1,
    };

    let rendered = format!("{trace:?}");

    for raw in [
        "secret-key-material-xyzzy",
        "opaque-token-material-plugh",
        "fingerprint-seed-abcde",
    ] {
        assert!(
            !rendered.contains(raw),
            "EnumerationTrace Debug leaked raw bytes marker {raw}: {rendered}"
        );
    }
}

#[test]
fn select_restart_points_auto_is_bounded_and_sorted() {
    assert_eq!(
        select_restart_points(RestartPoints::Auto(4), 0),
        Vec::<usize>::new()
    );

    let points = select_restart_points(RestartPoints::Auto(4), 10);
    assert_eq!(points, vec![0, 3, 6, 9]);
    assert!(points.windows(2).all(|window| window[0] < window[1]));
    assert!(points.iter().all(|&idx| idx < 10));
}

#[test]
fn select_restart_points_auto_one_returns_first() {
    assert_eq!(select_restart_points(RestartPoints::Auto(1), 5), vec![0]);
}

#[test]
fn select_restart_points_auto_exceeding_len_caps_at_len() {
    assert_eq!(
        select_restart_points(RestartPoints::Auto(100), 3),
        vec![0, 1, 2]
    );
}

#[test]
fn select_restart_points_explicit_filters_sorts_and_dedupes() {
    const EXPLICIT: &[usize] = &[4, 1, 1, 999, 0, 4];
    let points = select_restart_points(RestartPoints::Explicit(EXPLICIT), 5);
    assert_eq!(points, vec![0, 1, 4]);
}

#[test]
fn contains_subslice_basic() {
    assert!(contains_subslice(b"abcde", b"bcd"));
    assert!(!contains_subslice(b"abcde", b"ace"));
    assert!(contains_subslice(b"abcde", b""));
    assert!(!contains_subslice(b"ab", b"abc"));
}

#[test]
fn contains_subslice_equal_length() {
    assert!(contains_subslice(b"abc", b"abc"));
    assert!(!contains_subslice(b"abc", b"def"));
}

#[test]
fn drop_token_on_initial_cursor_returns_initial() {
    let initial = Cursor::initial();
    let dropped = drop_token(&initial);
    assert_eq!(dropped.last_key().map(|k| k.as_bytes()), None);
    assert_eq!(dropped.token(), None);
}

#[test]
fn drop_token_preserves_last_key_and_removes_token() {
    let original = cursor(Some(b"cursor-k"), Some(b"cursor-token"));
    let dropped = drop_token(&original);
    assert_eq!(
        dropped.last_key().map(|key| key.as_bytes()),
        original.last_key().map(|key| key.as_bytes())
    );
    assert_eq!(dropped.token(), None);
}

#[test]
fn corrupt_token_on_initial_cursor_returns_initial() {
    let result = corrupt_token(&Cursor::initial(), 42);
    assert_eq!(result.last_key().map(|k| k.as_bytes()), None);
}

#[test]
fn corrupt_token_is_deterministic_for_seed_and_preserves_last_key() {
    let original = cursor(Some(b"cursor-k"), Some(b"cursor-token"));
    let first = corrupt_token(&original, 7);
    let second = corrupt_token(&original, 7);
    let different_seed = corrupt_token(&original, 8);

    assert_eq!(first, second);
    assert_ne!(first, different_seed);
    assert_eq!(
        first.last_key().map(|key| key.as_bytes()),
        original.last_key().map(|key| key.as_bytes())
    );
    assert!(first.token().is_some());
    assert_ne!(first.token(), original.token());
}

#[test]
fn check_connector_conforms_rejects_missing_seek_by_key() {
    let make = scripted_make(vec![vec![]]);
    let (start, end) = default_range();
    let err = check_connector_conforms(
        make,
        |_connector: &ScriptConnector| ConnectorCapabilities::default(),
        scripted_enumerate,
        &start,
        &end,
        harness_cfg(),
    )
    .expect_err("seek_by_key capability gate should fail");
    assert!(matches!(
        err,
        ConformanceError::CapabilityMissingSeekByKey { .. }
    ));
}

#[test]
fn check_connector_conforms_maps_page_validator_failure() {
    let make = scripted_make(vec![vec![Ok(page(
        &[(b"0", b"item-ref")],
        Some(b"a"),
        None,
    ))]]);
    let (start, end) = default_range();
    let err = check_connector_conforms(
        make,
        scripted_caps,
        scripted_enumerate,
        &start,
        &end,
        harness_cfg(),
    )
    .expect_err("out-of-range page should fail validation");
    assert!(matches!(
        err,
        ConformanceError::PageValidationFailed { at_page: 0, .. }
    ));
}

#[test]
fn check_connector_conforms_maps_strict_order_violation() {
    let make = scripted_make(vec![vec![Ok(page(
        &[(b"b", b"item-ref-1"), (b"b", b"item-ref-2")],
        Some(b"b"),
        None,
    ))]]);
    let (start, end) = default_range();
    let err = check_connector_conforms(
        make,
        scripted_caps,
        scripted_enumerate,
        &start,
        &end,
        harness_cfg(),
    )
    .expect_err("strict order violation should fail");
    assert!(matches!(
        err,
        ConformanceError::NotStrictlyIncreasingWithinPage {
            at_page: 0,
            at_index: 1,
            ..
        }
    ));
}

#[test]
fn check_connector_conforms_maps_cursor_last_item_mismatch() {
    let make = scripted_make(vec![vec![Ok(page(
        &[(b"b", b"item-ref")],
        Some(b"c"),
        None,
    ))]]);
    let (start, end) = default_range();
    let err = check_connector_conforms(
        make,
        scripted_caps,
        scripted_enumerate,
        &start,
        &end,
        harness_cfg(),
    )
    .expect_err("cursor last-item mismatch should fail");
    assert!(matches!(
        err,
        ConformanceError::CursorDoesNotMatchLastItem { at_page: 0, .. }
    ));
}

#[test]
fn check_connector_conforms_maps_duplicate_key_in_run() {
    let make = scripted_make(vec![vec![Ok(page(
        &[(b"b", b"item-ref-1"), (b"b", b"item-ref-2")],
        Some(b"b"),
        None,
    ))]]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.require_strict_key_order = false;
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("duplicate keys should fail");
    assert!(matches!(err, ConformanceError::DuplicateKeyInRun { .. }));
}

#[test]
fn check_connector_conforms_maps_determinism_mismatch() {
    let make = scripted_make(vec![
        vec![
            Ok(page(&[(b"b", b"item-ref-1")], Some(b"b"), None)),
            Ok(page(&[], Some(b"b"), None)),
        ],
        vec![
            Ok(page(&[(b"b", b"item-ref-2")], Some(b"b"), None)),
            Ok(page(&[], Some(b"b"), None)),
        ],
    ]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.determinism = DeterminismExpectation::Deterministic;
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("determinism mismatch should fail");
    assert!(matches!(
        err,
        ConformanceError::DeterminismMismatch { at_index: 0, .. }
    ));
}

#[test]
fn check_connector_conforms_maps_resume_suffix_mismatch_for_drop_token() {
    const RESTART_0: &[usize] = &[0];
    let make = scripted_make(vec![
        vec![
            Ok(page(&[(b"b", b"item-ref-b")], Some(b"b"), Some(b"token-b"))),
            Ok(page(&[(b"c", b"item-ref-c")], Some(b"c"), None)),
            Ok(page(&[], Some(b"c"), None)),
        ],
        vec![
            Ok(page(&[(b"d", b"item-ref-d")], Some(b"d"), None)),
            Ok(page(&[], Some(b"d"), None)),
        ],
    ]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.resume_checks = ResumeChecks {
        drop_token: true,
        corrupt_token: false,
    };
    cfg.restart_points = RestartPoints::Explicit(RESTART_0);
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("resume suffix mismatch should fail");
    assert!(matches!(
        err,
        ConformanceError::ResumeMismatch {
            restart_cursor_index: 0,
            mode: ResumeMode::DropToken,
            at_index: 0,
            ..
        }
    ));
}

#[test]
fn check_connector_conforms_maps_resume_length_mismatch_for_corrupt_token() {
    const RESTART_0: &[usize] = &[0];
    let make = scripted_make(vec![
        vec![
            Ok(page(&[(b"b", b"item-ref-b")], Some(b"b"), Some(b"token-b"))),
            Ok(page(&[(b"c", b"item-ref-c")], Some(b"c"), None)),
            Ok(page(&[], Some(b"c"), None)),
        ],
        vec![
            Ok(page(
                &[(b"c", b"item-ref-c"), (b"d", b"item-ref-d")],
                Some(b"d"),
                None,
            )),
            Ok(page(&[], Some(b"d"), None)),
        ],
    ]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.resume_checks = ResumeChecks {
        drop_token: false,
        corrupt_token: true,
    };
    cfg.restart_points = RestartPoints::Explicit(RESTART_0);
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("resume length mismatch should fail");
    assert!(matches!(
        err,
        ConformanceError::ResumeLengthMismatch {
            restart_cursor_index: 0,
            mode: ResumeMode::CorruptToken,
            expected_len: 1,
            got_len: 2,
        }
    ));
}

#[test]
fn check_connector_conforms_maps_item_ref_secret_scan_findings() {
    let make = scripted_make(vec![vec![Ok(page(
        &[(b"b", b"xx-sekret-yy")],
        Some(b"b"),
        None,
    ))]]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.secret_scan.enabled = true;
    cfg.secret_scan.forbidden_substrings = vec![b"sekret"];
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("secret scan should fail on matching pattern");
    assert!(matches!(
        err,
        ConformanceError::ItemRefAppearsToContainSecret { .. }
    ));
}

/// Happy-path test: a well-behaved 2-page connector passes all conformance checks.
#[test]
fn check_connector_conforms_succeeds_for_well_behaved_connector() {
    let make = scripted_make(vec![vec![
        Ok(page(
            &[(b"b", b"ref-b"), (b"c", b"ref-c")],
            Some(b"c"),
            Some(b"tok"),
        )),
        Ok(page(&[(b"d", b"ref-d")], Some(b"d"), None)),
        Ok(page(&[], Some(b"d"), None)),
    ]]);
    let (start, end) = default_range();
    check_connector_conforms(
        make,
        scripted_caps,
        scripted_enumerate,
        &start,
        &end,
        harness_cfg(),
    )
    .expect("well-behaved connector should pass");
}

/// Resume with a cursor whose `last_key` was never observed in the baseline
/// trace must produce `CursorKeyNotInBaseline`, not silently pass.
#[test]
fn resume_with_unrecognized_cursor_key_returns_error() {
    const RESTART_0: &[usize] = &[0];
    // Baseline: one page with item key "b", but cursor claims last_key "x"
    // which was never emitted as an item. With `require_cursor_eq_last_item =
    // false` the baseline collection succeeds, but resume suffix lookup must
    // fail because "x" is not in key_to_index.
    let make = scripted_make(vec![
        // Baseline run.
        vec![
            Ok(page(&[(b"b", b"ref-b")], Some(b"x"), None)),
            Ok(page(&[], Some(b"x"), None)),
        ],
    ]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.require_cursor_eq_last_item = false;
    cfg.resume_checks = ResumeChecks {
        drop_token: true,
        corrupt_token: false,
    };
    cfg.restart_points = RestartPoints::Explicit(RESTART_0);
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("unrecognized cursor key must fail");
    assert!(
        matches!(err, ConformanceError::CursorKeyNotInBaseline { .. }),
        "expected CursorKeyNotInBaseline, got: {err:?}",
    );
}

/// Secret canaries: the harness detects canary values planted in item_refs.
#[test]
fn check_connector_conforms_detects_secret_canaries() {
    let canary = b"my-secret-canary-value";
    let make = scripted_make(vec![vec![Ok(page(&[(b"b", canary)], Some(b"b"), None))]]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.secret_scan.enabled = true;
    cfg.secret_scan.forbidden_substrings = vec![];
    cfg.secret_scan.secret_canaries = vec![canary.to_vec()];
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("canary should trigger secret scan");
    assert!(matches!(
        err,
        ConformanceError::ItemRefAppearsToContainSecret { .. }
    ));
}

/// Determinism check catches length mismatches between two full runs.
#[test]
fn check_connector_conforms_detects_determinism_length_mismatch() {
    let make = scripted_make(vec![
        // Run 1: two items.
        vec![
            Ok(page(
                &[(b"b", b"ref-b"), (b"c", b"ref-c")],
                Some(b"c"),
                None,
            )),
            Ok(page(&[], Some(b"c"), None)),
        ],
        // Run 2: one item.
        vec![
            Ok(page(&[(b"b", b"ref-b")], Some(b"b"), None)),
            Ok(page(&[], Some(b"b"), None)),
        ],
    ]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.determinism = DeterminismExpectation::Deterministic;
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("length mismatch should fail determinism");
    assert!(matches!(err, ConformanceError::DeterminismMismatch { .. }));
}

/// Verify that collecting exactly `max_total_items` items succeeds.
///
/// The `collect_trace` loop uses `>` (post-push), so a trace with exactly
/// `max_total_items` items must be accepted. If this test fails, the
/// limit comparison operator is wrong.
#[test]
fn max_total_items_boundary_accepts_exact_limit() {
    let max_items: usize = 3;
    // Three items across two pages, each page within budgets.
    let make = scripted_make(vec![vec![
        Ok(page(
            &[(b"b", b"ref-b"), (b"c", b"ref-c")],
            Some(b"c"),
            None,
        )),
        Ok(page(&[(b"d", b"ref-d")], Some(b"d"), None)),
        Ok(page(&[], Some(b"d"), None)),
    ]]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.max_total_items = std::num::NonZeroUsize::new(max_items).expect("nonzero max_total_items");
    check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect("exactly max_total_items items must be accepted");
}

/// Verify that collecting `max_total_items + 1` items triggers `TooManyItems`.
///
/// Companion to `max_total_items_boundary_accepts_exact_limit` — proves the
/// limit is enforced at exactly one-past-max.
#[test]
fn max_total_items_boundary_rejects_one_over() {
    let max_items: usize = 2;
    // Three items but limit is 2.
    let make = scripted_make(vec![vec![
        Ok(page(
            &[(b"b", b"ref-b"), (b"c", b"ref-c")],
            Some(b"c"),
            None,
        )),
        Ok(page(&[(b"d", b"ref-d")], Some(b"d"), None)),
        Ok(page(&[], Some(b"d"), None)),
    ]]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.max_total_items = std::num::NonZeroUsize::new(max_items).expect("nonzero max_total_items");
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("one over max_total_items must fail");
    assert!(
        matches!(err, ConformanceError::TooManyItems { max_total_items } if max_total_items == max_items),
        "expected TooManyItems with max={max_items}, got: {err:?}",
    );
}

/// `TooManyPages` fires when pages reach the configured limit.
#[test]
fn check_connector_conforms_rejects_too_many_pages() {
    // Two non-empty pages followed by a third; limit is 2.
    let make = scripted_make(vec![vec![
        Ok(page(&[(b"b", b"ref-b")], Some(b"b"), None)),
        Ok(page(&[(b"c", b"ref-c")], Some(b"c"), None)),
        Ok(page(&[(b"d", b"ref-d")], Some(b"d"), None)),
    ]]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.max_pages = std::num::NonZeroUsize::new(2).expect("nonzero max_pages");
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("exceeding max_pages must fail");
    assert!(
        matches!(err, ConformanceError::TooManyPages { max_pages: 2 }),
        "expected TooManyPages with max=2, got: {err:?}",
    );
}

/// `ReturnedTooManyItems` fires when a single page exceeds `max_items` budget.
#[test]
fn check_connector_conforms_rejects_page_exceeding_max_items_budget() {
    // Single page returns 3 items, but budget allows only 2 per page.
    let make = scripted_make(vec![vec![Ok(page(
        &[(b"b", b"ref-b"), (b"c", b"ref-c"), (b"d", b"ref-d")],
        Some(b"d"),
        None,
    ))]]);
    let (start, end) = default_range();
    let mut cfg = harness_cfg();
    cfg.page_budgets = Budgets::try_new(2, u64::MAX, None).expect("valid budgets");
    let err = check_connector_conforms(make, scripted_caps, scripted_enumerate, &start, &end, cfg)
        .expect_err("page exceeding max_items budget must fail");
    assert!(
        matches!(
            err,
            ConformanceError::ReturnedTooManyItems {
                at_page: 0,
                got: 3,
                max: 2,
            }
        ),
        "expected ReturnedTooManyItems, got: {err:?}",
    );
}

/// `EnumerateFailed` fires when the connector returns an error.
#[test]
fn check_connector_conforms_maps_enumerate_error() {
    let make = scripted_make(vec![vec![Err(EnumerateError::retryable(
        "simulated failure",
    ))]]);
    let (start, end) = default_range();
    let err = check_connector_conforms(
        make,
        scripted_caps,
        scripted_enumerate,
        &start,
        &end,
        harness_cfg(),
    )
    .expect_err("enumerate error must propagate");
    assert!(
        matches!(
            err,
            ConformanceError::EnumerateFailed {
                at_page: 0,
                class: ErrorClass::Retryable,
            }
        ),
        "expected EnumerateFailed at page 0, got: {err:?}",
    );
}

proptest::proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn toxic_digest_stability(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
        let a = ToxicDigest::of_bytes(&bytes);
        let b = ToxicDigest::of_bytes(&bytes);
        proptest::prop_assert_eq!(a, b, "of_bytes must be deterministic");
    }

    #[test]
    fn toxic_digest_collision_freedom(
        x in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
        y in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
    ) {
        proptest::prelude::prop_assume!(x != y);
        let dx = ToxicDigest::of_bytes(&x);
        let dy = ToxicDigest::of_bytes(&y);
        proptest::prop_assert_ne!(dx, dy, "distinct inputs must produce distinct digests");
    }
}
