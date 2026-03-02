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

// ── Valid throughput delta calculations ──────────────────────────

#[rstest::rstest]
#[case::zero_vs_zero(0.0, 0.0, 0.0)]
#[case::positive_10pct(100.0, 110.0, 10.0)]
#[case::positive_20pct(100.0, 120.0, 20.0)]
#[case::positive_50pct(50.0, 75.0, 50.0)]
#[case::negative_10pct(100.0, 90.0, -10.0)]
#[case::negative_20pct(100.0, 80.0, -20.0)]
#[case::equal(200.0, 200.0, 0.0)]
fn throughput_delta_pct_valid_inputs(
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
fn negative_candidate_throughput_is_rejected() {
    let err = throughput_delta_pct(100.0, -5.0).expect_err("negative candidate must be rejected");
    assert!(
        matches!(err, ThroughputError::NegativeCandidate { candidate } if candidate == -5.0),
        "expected NegativeCandidate, got {err:?}"
    );
}

// ── NonFinite throughput rejection ──────────────────────────────

#[rstest::rstest]
#[case::nan_baseline(f64::NAN, 1.0, "baseline")]
#[case::infinite_candidate(1.0, f64::INFINITY, "candidate")]
fn throughput_delta_rejects_non_finite(
    #[case] baseline: f64,
    #[case] candidate: f64,
    #[case] expected_label: &str,
) {
    let err = throughput_delta_pct(baseline, candidate).expect_err("non-finite input");
    assert!(
        matches!(err, ThroughputError::NonFinite { label, .. } if label == expected_label),
        "expected NonFinite for {expected_label}, got {err:?}"
    );
}

// ── Median valid inputs ─────────────────────────────────────────

#[rstest::rstest]
#[case::single_element(&[7.5], 7.5)]
#[case::odd_count(&[1.0, 3.0, 2.0], 2.0)]
#[case::even_count(&[1.0, 2.0, 3.0, 4.0], 2.5)]
fn median_valid_inputs(#[case] values: &[f64], #[case] expected: f64) {
    assert_eq!(median(values).expect("valid input"), expected);
}

#[test]
fn median_empty_input_is_error() {
    let err = median(&[]).expect_err("empty input");
    assert!(
        matches!(err, ThroughputError::EmptyInput),
        "expected EmptyInput, got {err:?}"
    );
}

// ── Median non-finite rejection ─────────────────────────────────

#[rstest::rstest]
#[case::nan(vec![1.0, f64::NAN, 3.0])]
#[case::infinity(vec![1.0, f64::INFINITY])]
fn median_rejects_non_finite(#[case] values: Vec<f64>) {
    let err = median(&values).expect_err("non-finite input");
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
