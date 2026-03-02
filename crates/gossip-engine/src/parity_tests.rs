use gossip_contracts::connector::{Cursor, ItemKey, TokenBytes};

use crate::test_support::make_item;
use crate::{PageScanContext, PageScanRequest, ScannerCore};

use super::{
    CanonicalVersionStrength, ThroughputError, canonicalize_stream_output,
    enforce_throughput_thresholds, median, throughput_delta_pct,
};

#[test]
fn canonicalize_stream_output_preserves_emission_order() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::with_token(
        ItemKey::try_from_slice(b"n").expect("key"),
        TokenBytes::try_from_slice(b"tok").expect("token"),
    );

    let page1_items = [
        make_item(b"a", b"ra", [0x01; 32], b"v1"),
        make_item(b"b", b"rb", [0x02; 32], b"v2"),
    ];
    let page2_items = [make_item(b"c", b"rc", [0x03; 32], b"v3")];
    let page1_bytes: [&[u8]; 2] = [b"payload-a", b"payload-b"];
    let page2_bytes: [&[u8]; 1] = [b"payload-c"];

    let output = core
        .scan_stream([
            PageScanRequest::with_item_bytes(
                PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1),
                &page1_items,
                &page1_bytes,
            ),
            PageScanRequest::with_item_bytes(
                PageScanContext::new(b"a", b"z", &next_cursor, &Cursor::initial(), 2),
                &page2_items,
                &page2_bytes,
            ),
        ])
        .expect("stream scan succeeds");

    let canonical = canonicalize_stream_output(&output);
    assert_eq!(canonical.findings.len(), 3);
    assert_eq!(canonical.findings[0].page_num, 1);
    assert_eq!(canonical.findings[1].page_num, 1);
    assert_eq!(canonical.findings[2].page_num, 2);
    assert_eq!(
        canonical.findings[0].version_strength,
        CanonicalVersionStrength::Strong
    );
}

#[test]
fn throughput_delta_allows_zero_vs_zero() {
    let delta = throughput_delta_pct(0.0, 0.0).expect("zero baseline/candidate should be stable");
    assert_eq!(delta, 0.0);
}

#[test]
fn throughput_thresholds_validate_per_case_and_median() {
    let passed = enforce_throughput_thresholds(&[1.0, -2.0, 3.0], 2.0, 5.0)
        .expect("deltas should pass 2%/5% policy");
    assert_eq!(passed, 2.0);

    let per_case_err =
        enforce_throughput_thresholds(&[5.1], 2.0, 5.0).expect_err("per-case must fail");
    assert!(matches!(
        per_case_err,
        ThroughputError::ThresholdExceeded {
            scope: "per-case",
            ..
        }
    ));

    let median_err =
        enforce_throughput_thresholds(&[2.1, 2.2, 2.3], 2.0, 5.0).expect_err("median must fail");
    assert!(matches!(
        median_err,
        ThroughputError::ThresholdExceeded {
            scope: "median",
            ..
        }
    ));
}

#[test]
fn median_handles_even_and_odd_input() {
    assert_eq!(median(&[1.0, 3.0, 2.0]).expect("odd median"), 2.0);
    assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]).expect("even median"), 2.5);
}

#[test]
fn negative_candidate_throughput_is_rejected() {
    let err = throughput_delta_pct(100.0, -5.0).expect_err("negative candidate must be rejected");
    assert!(
        matches!(err, ThroughputError::NegativeCandidate { candidate } if candidate == -5.0),
        "expected NegativeCandidate, got {err:?}"
    );
}

// ── Concrete throughput delta calculations (F10) ────────────────

#[rstest::rstest]
#[case::positive_20pct(100.0, 120.0, 20.0)]
#[case::negative_20pct(100.0, 80.0, -20.0)]
#[case::equal(200.0, 200.0, 0.0)]
#[case::positive_50pct(50.0, 75.0, 50.0)]
fn throughput_delta_pct_concrete_values(
    #[case] baseline: f64,
    #[case] candidate: f64,
    #[case] expected: f64,
) {
    let delta = throughput_delta_pct(baseline, candidate).expect("valid inputs");
    assert!(
        (delta - expected).abs() < 1e-10,
        "throughput_delta_pct({baseline}, {candidate}) = {delta}, expected {expected}"
    );
}

// ── Normal throughput delta calculations ─────────────────────────

#[test]
fn throughput_delta_pct_normal_cases() {
    let delta = throughput_delta_pct(100.0, 110.0).expect("100→110");
    assert!(
        (delta - 10.0).abs() < 1e-10,
        "100→110 should be +10%, got {delta}"
    );

    let delta = throughput_delta_pct(100.0, 90.0).expect("100→90");
    assert!(
        (delta - (-10.0)).abs() < 1e-10,
        "100→90 should be -10%, got {delta}"
    );

    let delta = throughput_delta_pct(42.0, 42.0).expect("42→42");
    assert_eq!(delta, 0.0, "42→42 should be 0%");
}

// ── Median edge cases ───────────────────────────────────────────

#[test]
fn median_single_element() {
    assert_eq!(median(&[7.5]).expect("single element"), 7.5);
}

#[test]
fn median_empty_input_is_error() {
    let err = median(&[]).expect_err("empty input");
    assert!(
        matches!(err, ThroughputError::EmptyInput),
        "expected EmptyInput, got {err:?}"
    );
}

#[test]
fn median_nan_is_rejected() {
    let err = median(&[1.0, f64::NAN, 3.0]).expect_err("NaN input");
    assert!(
        matches!(
            err,
            ThroughputError::NonFinite {
                label: "sample",
                ..
            }
        ),
        "expected NonFinite for sample, got {err:?}"
    );
}

#[test]
fn median_infinity_is_rejected() {
    let err = median(&[1.0, f64::INFINITY]).expect_err("infinite input");
    assert!(
        matches!(
            err,
            ThroughputError::NonFinite {
                label: "sample",
                ..
            }
        ),
        "expected NonFinite for sample, got {err:?}"
    );
}

// ── NonFinite throughput rejection ──────────────────────────────

#[test]
fn throughput_delta_rejects_nan_baseline() {
    let err = throughput_delta_pct(f64::NAN, 1.0).expect_err("NaN baseline");
    assert!(
        matches!(
            err,
            ThroughputError::NonFinite {
                label: "baseline",
                ..
            }
        ),
        "expected NonFinite for baseline, got {err:?}"
    );
}

#[test]
fn throughput_delta_rejects_infinite_candidate() {
    let err = throughput_delta_pct(1.0, f64::INFINITY).expect_err("infinite candidate");
    assert!(
        matches!(
            err,
            ThroughputError::NonFinite {
                label: "candidate",
                ..
            }
        ),
        "expected NonFinite for candidate, got {err:?}"
    );
}
