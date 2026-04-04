use rstest::rstest;

use crate::test_util::{canonical_digest, ovid, policy, provenance, tenant};

use super::*;
use DoneLedgerStatus::{
    FailedPermanent, FailedRetryable, ScannedClean, ScannedWithFindings, Skipped,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_provenance() -> DoneLedgerProvenance {
    provenance(1, 2, 3, 100, 200)
}

#[test]
fn provenance_from_write_context_preserves_fence_fields() {
    let write_context = WriteContext::new(
        tenant(1),
        policy(2),
        RunId::from_raw(3),
        ShardId::from_raw(4),
        FenceEpoch::from_raw(5),
    );

    let provenance = DoneLedgerProvenance::from_write_context(
        write_context,
        LogicalTime::from_raw(100),
        LogicalTime::from_raw(200),
    );

    assert_eq!(provenance.run_id(), write_context.run_id());
    assert_eq!(provenance.shard_id(), write_context.shard_id());
    assert_eq!(provenance.fence_epoch(), write_context.fence_epoch());
    assert_eq!(provenance.started_at(), LogicalTime::from_raw(100));
    assert_eq!(provenance.finished_at(), LogicalTime::from_raw(200));
}

#[test]
fn done_ledger_record_reconstructs_write_context() {
    let write_context = WriteContext::new(
        tenant(7),
        policy(8),
        RunId::from_raw(9),
        ShardId::from_raw(10),
        FenceEpoch::from_raw(11),
    );

    let record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(
            write_context.tenant_id(),
            write_context.policy_hash(),
            ovid(12),
        ),
        ScannedClean,
        123,
        0,
        DoneLedgerProvenance::from_write_context(
            write_context,
            LogicalTime::from_raw(200),
            LogicalTime::from_raw(300),
        ),
        None,
    )
    .expect("record should be valid");

    assert_eq!(record.write_context(), write_context);
}

// ---------------------------------------------------------------------------
// DoneLedgerStatus lattice properties
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_status_merge_is_commutative_idempotent_and_monotonic() {
    for left in DoneLedgerStatus::ALL {
        assert_eq!(left.merge(left), left, "idempotence failed for {left:?}");

        for right in DoneLedgerStatus::ALL {
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
    for a in DoneLedgerStatus::ALL {
        for b in DoneLedgerStatus::ALL {
            for c in DoneLedgerStatus::ALL {
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
    for status in DoneLedgerStatus::ALL {
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

#[rstest]
#[case(FailedRetryable, false)]
#[case(FailedPermanent, true)]
#[case(Skipped, true)]
#[case(ScannedClean, true)]
#[case(ScannedWithFindings, true)]
fn done_ledger_status_is_terminal_matches_expected(
    #[case] status: DoneLedgerStatus,
    #[case] expected: bool,
) {
    assert_eq!(status.is_terminal(), expected);
}

#[test]
fn done_ledger_status_terminal_is_a_superset_of_scanned() {
    for status in DoneLedgerStatus::ALL {
        if status.is_scanned() {
            assert!(status.is_terminal(), "{status:?} should also be terminal");
        }
    }
}

// ---------------------------------------------------------------------------
// DoneLedgerKey canonical digest
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_key_canonical_digest_is_deterministic() {
    let a = DoneLedgerKey::new(tenant(5), policy(7), ovid(11));
    let b = DoneLedgerKey::new(tenant(5), policy(7), ovid(11));
    assert_eq!(canonical_digest(&a), canonical_digest(&b));
}

#[test]
fn done_ledger_key_canonical_digest_golden_value() {
    let key = DoneLedgerKey::new(tenant(5), policy(7), ovid(11));
    let digest = canonical_digest(&key);
    // Golden hash — if this changes, the canonical encoding changed.
    // Regenerate with: cargo test done_ledger_key_canonical_digest_golden -- --nocapture
    assert_eq!(
        digest.to_hex().as_str(),
        "5e27eaa0abcf3d6a721958222ea7ee068b00bc182123d6beb5a467aaa1d8016b",
        "golden hash mismatch — did DoneLedgerKey::write_canonical change?"
    );
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
// DoneLedgerRecord::merge
// ---------------------------------------------------------------------------

#[test]
fn merge_scanned_dominates_failed() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let code = DoneLedgerErrorCode::try_new("TIMEOUT").unwrap();
    let failure =
        DoneLedgerRecord::try_new(key, FailedRetryable, 0, 0, make_provenance(), Some(code))
            .unwrap();
    let success =
        DoneLedgerRecord::try_new(key, ScannedClean, 1024, 0, make_provenance(), None).unwrap();

    // ScannedClean dominates FailedRetryable regardless of argument order.
    let merged = failure.merge(&success).unwrap();
    assert_eq!(merged.status(), ScannedClean);

    let merged = success.merge(&failure).unwrap();
    assert_eq!(merged.status(), ScannedClean);
}

#[test]
fn merge_takes_max_bytes_scanned() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let code = DoneLedgerErrorCode::try_new("X").unwrap();
    let a = DoneLedgerRecord::try_new(
        key,
        FailedRetryable,
        9_000,
        7,
        make_provenance(),
        Some(code.clone()),
    )
    .unwrap();
    let b = DoneLedgerRecord::try_new(key, ScannedWithFindings, 1_000, 1, make_provenance(), None)
        .unwrap();

    let merged = a.merge(&b).unwrap();
    assert_eq!(merged.bytes_scanned(), 9_000);
    assert_eq!(
        merged.error_code(),
        None,
        "scanned status clears error code"
    );
}

#[test]
fn merge_findings_count_is_status_aware() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let code = DoneLedgerErrorCode::try_new("X").unwrap();

    // ScannedClean forces findings_count to 0.
    let a = DoneLedgerRecord::try_new(key, FailedRetryable, 0, 5, make_provenance(), Some(code))
        .unwrap();
    let b = DoneLedgerRecord::try_new(key, ScannedClean, 0, 0, make_provenance(), None).unwrap();
    let merged = a.merge(&b).unwrap();
    assert_eq!(merged.findings_count(), 0);

    // ScannedWithFindings clamps to >= 1.
    let c =
        DoneLedgerRecord::try_new(key, ScannedWithFindings, 0, 3, make_provenance(), None).unwrap();
    let d =
        DoneLedgerRecord::try_new(key, ScannedWithFindings, 0, 7, make_provenance(), None).unwrap();
    let merged = c.merge(&d).unwrap();
    assert_eq!(merged.findings_count(), 7);

    // Lower-status counts do not contribute once ScannedWithFindings wins.
    let e = DoneLedgerRecord::try_new(
        key,
        FailedPermanent,
        0,
        9,
        make_provenance(),
        Some(DoneLedgerErrorCode::try_new("FAILED").unwrap()),
    )
    .unwrap();
    let merged = e.merge(&c).unwrap();
    assert_eq!(merged.findings_count(), 3);
}

#[test]
fn merge_equal_rank_prefers_newer_finished_then_started() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let code_a = DoneLedgerErrorCode::try_new("A").unwrap();
    let code_b = DoneLedgerErrorCode::try_new("B").unwrap();

    let prov_old = DoneLedgerProvenance::new(
        RunId::from_raw(1),
        ShardId::from_raw(1),
        FenceEpoch::from_raw(1),
        LogicalTime::from_raw(100),
        LogicalTime::from_raw(200),
    );
    let prov_newer_finished = DoneLedgerProvenance::new(
        RunId::from_raw(2),
        ShardId::from_raw(2),
        FenceEpoch::from_raw(2),
        LogicalTime::from_raw(80),
        LogicalTime::from_raw(300),
    );

    let a =
        DoneLedgerRecord::try_new(key, FailedPermanent, 100, 3, prov_old, Some(code_a)).unwrap();
    let b = DoneLedgerRecord::try_new(
        key,
        FailedPermanent,
        90,
        1,
        prov_newer_finished,
        Some(code_b.clone()),
    )
    .unwrap();

    let merged = a.merge(&b).unwrap();
    assert_eq!(merged.provenance(), prov_newer_finished);
    assert_eq!(merged.error_code(), Some(&code_b));
}

#[test]
fn merge_different_keys_returns_key_mismatch_error() {
    let key_a = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let key_b = DoneLedgerKey::new(tenant(9), policy(8), ovid(7));
    let a =
        DoneLedgerRecord::try_new(key_a, ScannedClean, 100, 0, make_provenance(), None).unwrap();
    let b =
        DoneLedgerRecord::try_new(key_b, ScannedClean, 200, 0, make_provenance(), None).unwrap();

    assert_eq!(
        a.merge(&b).unwrap_err(),
        PersistenceInputError::KeyMismatch {
            existing: Box::new(key_a),
            incoming: Box::new(key_b),
        }
    );
    assert_eq!(
        b.merge(&a).unwrap_err(),
        PersistenceInputError::KeyMismatch {
            existing: Box::new(key_b),
            incoming: Box::new(key_a),
        }
    );
}

#[test]
fn merge_fail_then_scan_uses_scanned_findings_and_provenance() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let code = DoneLedgerErrorCode::try_new("IO_TIMEOUT").unwrap();
    let prov_fail = DoneLedgerProvenance::new(
        RunId::from_raw(10),
        ShardId::from_raw(11),
        FenceEpoch::from_raw(12),
        LogicalTime::from_raw(100),
        LogicalTime::from_raw(200),
    );
    let prov_scan = DoneLedgerProvenance::new(
        RunId::from_raw(20),
        ShardId::from_raw(21),
        FenceEpoch::from_raw(22),
        LogicalTime::from_raw(150),
        LogicalTime::from_raw(250),
    );

    let failed =
        DoneLedgerRecord::try_new(key, FailedRetryable, 9_000, 7, prov_fail, Some(code)).unwrap();
    let scanned =
        DoneLedgerRecord::try_new(key, ScannedWithFindings, 1_000, 1, prov_scan, None).unwrap();

    let merged = failed.merge(&scanned).unwrap();
    assert_eq!(merged.status(), ScannedWithFindings);
    assert_eq!(merged.bytes_scanned(), 9_000);
    assert_eq!(merged.findings_count(), 1);
    assert_eq!(
        merged.provenance(),
        prov_scan,
        "higher status wins provenance"
    );
    assert_eq!(
        merged.error_code(),
        None,
        "scanned status clears error code"
    );
}

#[test]
fn merge_scan_then_fail_keeps_scanned_findings_and_provenance() {
    let key = DoneLedgerKey::new(tenant(4), policy(5), ovid(6));
    let code = DoneLedgerErrorCode::try_new("PERM_DENY").unwrap();
    let prov_scan = DoneLedgerProvenance::new(
        RunId::from_raw(30),
        ShardId::from_raw(31),
        FenceEpoch::from_raw(32),
        LogicalTime::from_raw(100),
        LogicalTime::from_raw(500),
    );
    let prov_fail = DoneLedgerProvenance::new(
        RunId::from_raw(40),
        ShardId::from_raw(41),
        FenceEpoch::from_raw(42),
        LogicalTime::from_raw(110),
        LogicalTime::from_raw(120),
    );

    let scanned =
        DoneLedgerRecord::try_new(key, ScannedWithFindings, 2_000, 2, prov_scan, None).unwrap();
    let failed =
        DoneLedgerRecord::try_new(key, FailedPermanent, 8_000, 5, prov_fail, Some(code)).unwrap();

    let merged = scanned.merge(&failed).unwrap();
    assert_eq!(merged.status(), ScannedWithFindings);
    assert_eq!(merged.bytes_scanned(), 8_000);
    assert_eq!(merged.findings_count(), 2);
    assert_eq!(
        merged.provenance(),
        prov_scan,
        "higher status wins provenance"
    );
    assert_eq!(
        merged.error_code(),
        None,
        "scanned status clears error code"
    );
}

#[test]
fn merge_rejects_unvalidated_operand_missing_error_code() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    let error_code = DoneLedgerErrorCode::try_new("TIMEOUT").unwrap();

    // Constructible via try_new but fails validate(): FailedRetryable
    // without an error_code.
    let unvalidated = DoneLedgerRecord::try_new(
        key,
        FailedRetryable,
        100,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(999),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(200),
        ),
        None,
    )
    .unwrap();

    let valid = DoneLedgerRecord::try_new(
        key,
        FailedRetryable,
        100,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(1),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(200),
        ),
        Some(error_code),
    )
    .unwrap();

    // merge rejects unvalidated operands to preserve associativity.
    assert!(unvalidated.merge(&valid).is_err());
    assert!(valid.merge(&unvalidated).is_err());
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

// Verify that `done_record()` rejects invalid status/error_code combos
// after the `validate()` hardening.
#[test]
#[should_panic(expected = "test record should pass full validation")]
fn done_record_rejects_failure_status_without_error_code() {
    // FailedRetryable requires error_code per `validate()`.
    let _ = crate::test_util::done_record(
        1,
        1,
        1,
        FailedRetryable,
        0,
        0,
        1,
        1,
        1,
        1,
        2,
        None, // missing error_code
    );
}

// ---------------------------------------------------------------------------
// Verify: merge rejects the unvalidated-error_code scenario that previously
// broke associativity. With validated operands, the fallback path is
// unreachable for non-scanned statuses (validate() guarantees error_code is
// Some), so associativity holds.
// ---------------------------------------------------------------------------

#[test]
fn merge_rejects_all_operands_in_associativity_counterexample() {
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));

    // The counterexample that broke associativity before the fix:
    // A: FailedRetryable, run_id=5, error_code=None (unvalidated).
    let a = DoneLedgerRecord::try_new(
        key,
        FailedRetryable,
        100,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(5),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(200),
        ),
        None,
    )
    .unwrap();

    let b = DoneLedgerRecord::try_new(
        key,
        FailedRetryable,
        100,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(3),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(200),
        ),
        Some(DoneLedgerErrorCode::try_new("ZZZZ").unwrap()),
    )
    .unwrap();

    // merge rejects A because it fails validate().
    assert!(
        a.merge(&b).is_err(),
        "merge must reject unvalidated operand A"
    );
    assert!(
        b.merge(&a).is_err(),
        "merge must reject unvalidated operand A"
    );
}
