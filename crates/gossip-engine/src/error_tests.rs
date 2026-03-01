use rstest::rstest;

use super::*;

// ---------------------------------------------------------------------------
// Display formatting — rstest consolidates 3 ScannerCoreError variants into 1
// ---------------------------------------------------------------------------

#[test]
fn build_error_display() {
    assert_eq!(
        ScannerCoreBuildError::ZeroMaxFindingsPerPage.to_string(),
        "max_findings_per_page must be greater than zero"
    );
}

#[rstest]
#[case::item_bytes_mismatch(
    ScannerCoreError::ItemBytesLenMismatch { page_num: 3, items: 10, item_bytes: 5 },
    "page 3: item_bytes length mismatch (items=10, item_bytes=5)"
)]
#[case::payload_overflow(
    ScannerCoreError::PayloadLengthOverflow { page_num: 7, item_index: 2, payload_len: 999 },
    "page 7 item 2: payload length 999 overflows u64"
)]
#[case::non_monotonic(
    ScannerCoreError::NonMonotonicPageNum { previous_page_num: 5, page_num: 3 },
    "non-monotonic stream page order: previous=5, current=3"
)]
fn core_error_display(#[case] err: ScannerCoreError, #[case] expected: &str) {
    assert_eq!(err.to_string(), expected);
}

// ---------------------------------------------------------------------------
// std::error::Error trait implementation
// ---------------------------------------------------------------------------

#[test]
fn build_error_is_std_error() {
    let err: &dyn std::error::Error = &ScannerCoreBuildError::ZeroMaxFindingsPerPage;
    assert!(err.source().is_none());
}

#[test]
fn core_error_is_std_error() {
    let err: &dyn std::error::Error = &ScannerCoreError::NonMonotonicPageNum {
        previous_page_num: 2,
        page_num: 1,
    };
    assert!(err.source().is_none());
}
