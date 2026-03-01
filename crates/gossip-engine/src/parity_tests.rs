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
