use rstest::rstest;

use crate::{
    identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
    test_util::canonical_digest,
};

use super::*;
use DoneLedgerStatus::{
    FailedPermanent, FailedRetryable, ScannedClean, ScannedWithFindings, Skipped,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const ALL_STATUSES: [DoneLedgerStatus; 5] = [
    FailedRetryable,
    FailedPermanent,
    Skipped,
    ScannedClean,
    ScannedWithFindings,
];

fn tenant(seed: u8) -> TenantId {
    TenantId::from_bytes([seed; 32])
}

fn policy(seed: u8) -> PolicyHash {
    PolicyHash::from_bytes([seed; 32])
}

fn ovid(seed: u8) -> OvidHash {
    OvidHash::from_bytes([seed; 32])
}

fn make_provenance() -> DoneLedgerProvenance {
    DoneLedgerProvenance::new(
        RunId::from_raw(1),
        ShardId::from_raw(2),
        FenceEpoch::from_raw(3),
        LogicalTime::from_raw(100),
        LogicalTime::from_raw(200),
    )
}

// ---------------------------------------------------------------------------
// DoneLedgerStatus lattice properties
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_status_merge_is_commutative_idempotent_and_monotonic() {
    for left in ALL_STATUSES {
        assert_eq!(left.merge(left), left, "idempotence failed for {left:?}");

        for right in ALL_STATUSES {
            let merged = left.merge(right);

            assert_eq!(
                merged,
                right.merge(left),
                "commutativity failed for {left:?} and {right:?}"
            );
            assert_eq!(
                merged.rank(),
                left.rank().max(right.rank()),
                "monotonicity failed for {left:?} and {right:?}"
            );
        }
    }
}

#[test]
fn done_ledger_status_merge_is_associative() {
    for a in ALL_STATUSES {
        for b in ALL_STATUSES {
            for c in ALL_STATUSES {
                assert_eq!(
                    a.merge(b.merge(c)),
                    a.merge(b).merge(c),
                    "associativity failed for ({a:?}, {b:?}, {c:?})"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DoneLedgerStatus::from_rank round-trip
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_status_from_rank_round_trips_all_variants() {
    for status in ALL_STATUSES {
        let rank = status.rank();
        let reconstituted = DoneLedgerStatus::from_rank(rank)
            .unwrap_or_else(|| panic!("from_rank({rank}) should reconstitute {status:?}"));
        assert_eq!(reconstituted, status);
    }
}

#[test]
fn done_ledger_status_from_rank_rejects_unknown_discriminants() {
    // Gaps in the rank space and out-of-range values.
    for invalid in [0, 4, 5, 6, 7, 8, 9, 12, 255] {
        assert!(
            DoneLedgerStatus::from_rank(invalid).is_none(),
            "from_rank({invalid}) should return None"
        );
    }
}

// ---------------------------------------------------------------------------
// DoneLedgerKey canonical digest
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_key_canonical_digest_is_stable() {
    let key = DoneLedgerKey::new(tenant(5), policy(7), ovid(11));

    assert_eq!(canonical_digest(&key), canonical_digest(&key));
}

// ---------------------------------------------------------------------------
// DoneLedgerErrorCode validation (parameterized)
// ---------------------------------------------------------------------------

/// Anchor: documents the happy-path contract for error-code construction.
#[test]
fn done_ledger_error_code_accepts_bounded_safe_bytes() {
    let error_code = DoneLedgerErrorCode::try_new("HTTP 403/TIMEOUT:UPSTREAM").unwrap();

    assert_eq!(error_code.as_str(), "HTTP 403/TIMEOUT:UPSTREAM");
}

/// Consolidates four rejection paths (empty, invalid byte, oversized,
/// all-whitespace) that previously lived in two separate tests with
/// three inline assertions. Each case now runs as an independent sub-test.
#[rstest]
#[case::empty(
    "".to_string(),
    PersistenceInputError::Empty { field: "DoneLedgerErrorCode" }
)]
#[case::invalid_byte(
    "BAD*CODE".to_string(),
    PersistenceInputError::InvalidByte { field: "DoneLedgerErrorCode", index: 3, byte: b'*' }
)]
#[case::oversized(
    "A".repeat(MAX_DONE_LEDGER_ERROR_CODE_SIZE + 1),
    PersistenceInputError::TooLarge {
        field: "DoneLedgerErrorCode",
        size: MAX_DONE_LEDGER_ERROR_CODE_SIZE + 1,
        max: MAX_DONE_LEDGER_ERROR_CODE_SIZE,
    }
)]
#[case::all_whitespace(
    "   ".to_string(),
    PersistenceInputError::Empty { field: "DoneLedgerErrorCode" }
)]
fn error_code_rejects_invalid_input(
    #[case] input: String,
    #[case] expected: PersistenceInputError,
) {
    assert_eq!(DoneLedgerErrorCode::try_new(input).unwrap_err(), expected);
}

// ---------------------------------------------------------------------------
// DoneLedgerRecord::try_new findings_count consistency (parameterized)
//
// Consolidates five separate tests (two rejection + two acceptance + one
// loop over failure/skip statuses) into a single rstest covering all ten
// (status, findings_count) combinations.
// ---------------------------------------------------------------------------

#[rstest]
#[case::swf_count_zero(ScannedWithFindings, 0, false)]
#[case::clean_count_nonzero(ScannedClean, 5, false)]
#[case::swf_count_positive(ScannedWithFindings, 3, true)]
#[case::clean_count_zero(ScannedClean, 0, true)]
#[case::failed_retryable_count_zero(FailedRetryable, 0, true)]
#[case::failed_retryable_count_positive(FailedRetryable, 5, true)]
#[case::failed_permanent_count_zero(FailedPermanent, 0, true)]
#[case::failed_permanent_count_positive(FailedPermanent, 5, true)]
#[case::skipped_count_zero(Skipped, 0, true)]
#[case::skipped_count_positive(Skipped, 5, true)]
fn try_new_enforces_findings_count_consistency(
    #[case] status: DoneLedgerStatus,
    #[case] findings_count: u32,
    #[case] should_succeed: bool,
) {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let result =
        DoneLedgerRecord::try_new(key, status, 1024, findings_count, make_provenance(), None);

    assert_eq!(
        result.is_ok(),
        should_succeed,
        "status={status:?}, findings_count={findings_count}"
    );
    if should_succeed {
        assert_eq!(result.unwrap().findings_count(), findings_count);
    }
}

// ---------------------------------------------------------------------------
// DoneLedgerRecord::validate cross-field invariants (parameterized)
//
// Consolidates eight separate validate_accepts_* / validate_rejects_* tests
// into a single rstest. Each case constructs a record via try_new (which
// always succeeds for these parameter combinations) and then asserts the
// expected validate() outcome.
// ---------------------------------------------------------------------------

#[rstest]
#[case::accept_scanned_clean(ScannedClean, 0, None, None)]
#[case::accept_scanned_with_findings(ScannedWithFindings, 3, None, None)]
#[case::accept_failed_retryable_with_code(FailedRetryable, 0, Some("TIMEOUT"), None)]
#[case::accept_failed_permanent_with_code(FailedPermanent, 0, Some("FATAL"), None)]
#[case::accept_skipped_with_code(Skipped, 0, Some("UNSUPPORTED_FORMAT"), None)]
#[case::reject_scanned_clean_with_code(
    ScannedClean, 0, Some("STALE"),
    Some(PersistenceInputError::UnexpectedErrorCode { status: "ScannedClean" })
)]
#[case::reject_scanned_with_findings_with_code(
    ScannedWithFindings, 5, Some("STALE"),
    Some(PersistenceInputError::UnexpectedErrorCode { status: "ScannedWithFindings" })
)]
#[case::reject_failed_retryable_no_code(
    FailedRetryable, 0, None,
    Some(PersistenceInputError::MissingErrorCode { status: "FailedRetryable" })
)]
#[case::reject_failed_permanent_no_code(
    FailedPermanent, 0, None,
    Some(PersistenceInputError::MissingErrorCode { status: "FailedPermanent" })
)]
#[case::reject_skipped_no_code(
    Skipped, 0, None,
    Some(PersistenceInputError::MissingErrorCode { status: "Skipped" })
)]
fn validate_enforces_cross_field_invariants(
    #[case] status: DoneLedgerStatus,
    #[case] findings_count: u32,
    #[case] error_code_str: Option<&str>,
    #[case] expected_err: Option<PersistenceInputError>,
) {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let error_code = error_code_str.map(|s| DoneLedgerErrorCode::try_new(s).unwrap());
    let record = DoneLedgerRecord::try_new(
        key,
        status,
        1024,
        findings_count,
        make_provenance(),
        error_code,
    )
    .expect("record construction should succeed for all validate test cases");

    match expected_err {
        None => record
            .validate()
            .expect("validate should accept this record"),
        Some(expected) => assert_eq!(record.validate().unwrap_err(), expected),
    }
}

// ---------------------------------------------------------------------------
// DoneLedgerRecord::merge_with
// ---------------------------------------------------------------------------

#[test]
fn merge_with_returns_dominant_record() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let code = DoneLedgerErrorCode::try_new("TIMEOUT").unwrap();
    let failure =
        DoneLedgerRecord::try_new(key, FailedRetryable, 0, 0, make_provenance(), Some(code))
            .unwrap();
    let success =
        DoneLedgerRecord::try_new(key, ScannedClean, 1024, 0, make_provenance(), None).unwrap();

    // ScannedClean dominates FailedRetryable.
    let merged = success.clone().merge_with(&failure);
    assert_eq!(merged.status(), ScannedClean);

    // When incoming is dominated, existing wins.
    let merged = failure.merge_with(&success);
    assert_eq!(merged.status(), ScannedClean);
}

#[test]
fn merge_with_same_status_returns_incoming() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let a = DoneLedgerRecord::try_new(key, ScannedClean, 100, 0, make_provenance(), None).unwrap();
    let b = DoneLedgerRecord::try_new(key, ScannedClean, 200, 0, make_provenance(), None).unwrap();

    // Equal ranks: self wins (incoming record).
    let merged = a.clone().merge_with(&b);
    assert_eq!(merged.bytes_scanned(), 100);
}

// ---------------------------------------------------------------------------
// Provenance temporal ordering
// ---------------------------------------------------------------------------

#[test]
fn provenance_accepts_equal_timestamps() {
    let t = LogicalTime::from_raw(100);
    let prov = DoneLedgerProvenance::new(
        RunId::from_raw(1),
        ShardId::from_raw(2),
        FenceEpoch::from_raw(3),
        t,
        t,
    );
    assert_eq!(prov.started_at(), t);
    assert_eq!(prov.finished_at(), t);
}

#[test]
fn provenance_accepts_start_before_finish() {
    let prov = DoneLedgerProvenance::new(
        RunId::from_raw(1),
        ShardId::from_raw(2),
        FenceEpoch::from_raw(3),
        LogicalTime::from_raw(10),
        LogicalTime::from_raw(20),
    );
    assert_eq!(prov.started_at().as_raw(), 10);
    assert_eq!(prov.finished_at().as_raw(), 20);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "must not exceed")]
fn provenance_rejects_start_after_finish_in_debug() {
    let _ = DoneLedgerProvenance::new(
        RunId::from_raw(1),
        ShardId::from_raw(2),
        FenceEpoch::from_raw(3),
        LogicalTime::from_raw(200),
        LogicalTime::from_raw(100),
    );
}
