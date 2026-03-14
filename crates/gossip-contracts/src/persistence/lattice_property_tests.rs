use proptest::{
    prelude::*,
    sample::select,
    test_runner::{Config as ProptestConfig, TestCaseError},
};

use crate::test_util::done_record;

use super::*;

const FIXED_TENANT_SEED: u8 = 0x41;
const FIXED_POLICY_SEED: u8 = 0x52;
const FIXED_OVID_SEED: u8 = 0x63;
const VALID_ERROR_CODES: [&str; 6] = [
    "TIMEOUT",
    "HTTP_403",
    "IO:RETRY",
    "SKIPPED_RULE",
    "SCAN-FAILED",
    "UNSUPPORTED_FORMAT",
];

fn lattice_proptest_config() -> ProptestConfig {
    if cfg!(miri) {
        crate::test_util::miri_proptest_config()
    } else {
        ProptestConfig::with_cases(gossip_stdx::test_support::proptest_cases(1024))
    }
}

/// Independent re-implementation of `DoneLedgerRecord::provenance_winner_key`
/// via public accessors. Must remain in exact lockstep with the production
/// method — any divergence means the property tests are not exercising the
/// real merge logic.
fn winner_key(record: &DoneLedgerRecord) -> (u8, u64, u64, u64, i64, i64, &[u8]) {
    (
        record.status().rank(),
        record.provenance().finished_at().as_raw(),
        record.provenance().started_at().as_raw(),
        record.provenance().fence_epoch().as_raw(),
        pg_bigint_bits_sort_key(record.provenance().run_id().as_raw()),
        pg_bigint_bits_sort_key(record.provenance().shard_id().as_raw()),
        record
            .error_code()
            .map_or(&[][..], |code| code.as_str().as_bytes()),
    )
}

fn prop_failure(context: &str, err: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(format!("{context}: {err}"))
}

fn merge_pair(
    left: &DoneLedgerRecord,
    right: &DoneLedgerRecord,
    context: &str,
) -> Result<DoneLedgerRecord, TestCaseError> {
    left.merge(right).map_err(|err| prop_failure(context, err))
}

fn merge_all(
    records: &[DoneLedgerRecord],
    order: &[usize],
) -> Result<DoneLedgerRecord, TestCaseError> {
    let (&first, rest) = order
        .split_first()
        .expect("merge_all requires at least one record index");
    let mut merged = records[first].clone();
    for &index in rest {
        merged = merge_pair(&merged, &records[index], "merge_all")?;
    }
    Ok(merged)
}

fn for_each_permutation(
    indices: &mut [usize],
    start: usize,
    visit: &mut impl FnMut(&[usize]) -> Result<(), TestCaseError>,
) -> Result<(), TestCaseError> {
    if start == indices.len() {
        return visit(indices);
    }

    for index in start..indices.len() {
        indices.swap(start, index);
        for_each_permutation(indices, start + 1, visit)?;
        indices.swap(start, index);
    }

    Ok(())
}

fn assert_permutation_convergence(records: &[DoneLedgerRecord]) -> Result<(), TestCaseError> {
    let baseline_order: Vec<_> = (0..records.len()).collect();
    let baseline = merge_all(records, &baseline_order)?;
    let mut indices = baseline_order;

    for_each_permutation(&mut indices, 0, &mut |order| {
        let merged = merge_all(records, order)?;
        prop_assert_eq!(
            &merged,
            &baseline,
            "merge should converge for permutation {:?}",
            order
        );
        Ok(())
    })
}

fn normalize_findings_count(status: DoneLedgerStatus, raw_findings_count: u32) -> u32 {
    match status {
        DoneLedgerStatus::ScannedClean => 0,
        DoneLedgerStatus::ScannedWithFindings => raw_findings_count.max(1),
        DoneLedgerStatus::FailedRetryable
        | DoneLedgerStatus::FailedPermanent
        | DoneLedgerStatus::Skipped => raw_findings_count,
    }
}

fn error_code_for_status(
    status: DoneLedgerStatus,
    error_code_index: usize,
) -> Option<&'static str> {
    (!status.is_scanned()).then_some(VALID_ERROR_CODES[error_code_index % VALID_ERROR_CODES.len()])
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors the done-ledger row shape under merge"
)]
fn build_record(
    status: DoneLedgerStatus,
    bytes_scanned: u64,
    raw_findings_count: u32,
    run_id: u64,
    shard_id: u64,
    fence_epoch: u64,
    started_at_raw: u64,
    finished_at_raw: u64,
    error_code_index: usize,
) -> DoneLedgerRecord {
    let (started_at, finished_at) = if started_at_raw <= finished_at_raw {
        (started_at_raw, finished_at_raw)
    } else {
        (finished_at_raw, started_at_raw)
    };

    done_record(
        FIXED_TENANT_SEED,
        FIXED_POLICY_SEED,
        FIXED_OVID_SEED,
        status,
        bytes_scanned,
        normalize_findings_count(status, raw_findings_count),
        run_id,
        shard_id,
        fence_epoch,
        started_at,
        finished_at,
        error_code_for_status(status, error_code_index),
    )
}

fn arb_status() -> BoxedStrategy<DoneLedgerStatus> {
    select(DoneLedgerStatus::ALL.to_vec()).boxed()
}

fn arb_bigint_boundary_u64() -> BoxedStrategy<u64> {
    prop_oneof![
        4 => any::<u64>(),
        1 => Just(0u64),
        1 => Just(u64::MAX),
        1 => Just(i64::MAX as u64),
        1 => Just(i64::MAX as u64 + 1),
    ]
    .boxed()
}

fn arb_record() -> BoxedStrategy<DoneLedgerRecord> {
    (
        arb_status(),
        any::<u64>(),
        any::<u32>(),
        arb_bigint_boundary_u64(),
        arb_bigint_boundary_u64(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        0usize..VALID_ERROR_CODES.len(),
    )
        .prop_map(
            |(
                status,
                bytes_scanned,
                raw_findings_count,
                run_id,
                shard_id,
                fence_epoch,
                started_at,
                finished_at,
                error_code_index,
            )| {
                build_record(
                    status,
                    bytes_scanned,
                    raw_findings_count,
                    run_id,
                    shard_id,
                    fence_epoch,
                    started_at,
                    finished_at,
                    error_code_index,
                )
            },
        )
        .boxed()
}

fn arb_record_batch(
    range: std::ops::RangeInclusive<usize>,
) -> BoxedStrategy<Vec<DoneLedgerRecord>> {
    proptest::collection::vec(arb_record(), range).boxed()
}

proptest::proptest! {
    #![proptest_config(lattice_proptest_config())]

    #[test]
    fn done_ledger_record_merge_is_commutative(
        left in arb_record(),
        right in arb_record(),
    ) {
        let merged_left = merge_pair(&left, &right, "left.merge(right)")?;
        let merged_right = merge_pair(&right, &left, "right.merge(left)")?;

        prop_assert_eq!(&merged_left, &merged_right);
        prop_assert!(merged_left.validate().is_ok());
    }

    #[test]
    fn done_ledger_record_merge_is_associative(
        a in arb_record(),
        b in arb_record(),
        c in arb_record(),
    ) {
        let left = merge_pair(
            &merge_pair(&a, &b, "a.merge(b)")?,
            &c,
            "(a.merge(b)).merge(c)",
        )?;
        let right = merge_pair(
            &a,
            &merge_pair(&b, &c, "b.merge(c)")?,
            "a.merge(b.merge(c))",
        )?;

        prop_assert_eq!(&left, &right);
        prop_assert!(left.validate().is_ok());
    }

    #[test]
    fn done_ledger_record_merge_is_idempotent(record in arb_record()) {
        let merged = merge_pair(&record, &record, "record.merge(record)")?;

        prop_assert_eq!(&merged, &record);
        prop_assert!(merged.validate().is_ok());
    }

    #[test]
    fn done_ledger_record_merge_is_monotonic(
        left in arb_record(),
        right in arb_record(),
    ) {
        let merged = merge_pair(&left, &right, "left.merge(right)")?;

        prop_assert!(merged.status().rank() >= left.status().rank());
        prop_assert!(merged.status().rank() >= right.status().rank());
        prop_assert!(merged.bytes_scanned() >= left.bytes_scanned());
        prop_assert!(merged.bytes_scanned() >= right.bytes_scanned());

        // findings_count is conditionally monotonic when both sides share
        // ScannedWithFindings status — the merge takes max of SwF contributors.
        if left.status() == DoneLedgerStatus::ScannedWithFindings
            && right.status() == DoneLedgerStatus::ScannedWithFindings
        {
            prop_assert!(merged.findings_count() >= left.findings_count());
            prop_assert!(merged.findings_count() >= right.findings_count());
        }
        // ScannedClean resets findings to zero by definition.
        if merged.status() == DoneLedgerStatus::ScannedClean {
            prop_assert_eq!(merged.findings_count(), 0);
        }
    }

    #[test]
    fn done_ledger_record_merge_never_downgrades_scanned_status(
        left in arb_record(),
        right in arb_record(),
    ) {
        let merged = merge_pair(&left, &right, "left.merge(right)")?;

        if left.status().is_scanned() {
            prop_assert!(merged.status().is_scanned());
        }
        if right.status().is_scanned() {
            prop_assert!(merged.status().is_scanned());
        }
    }

    #[test]
    fn done_ledger_record_merge_preserves_winner_field_coherence(
        records in arb_record_batch(1..=8),
    ) {
        let order: Vec<_> = (0..records.len()).collect();
        let merged = merge_all(&records, &order)?;
        let expected_winner = records
            .iter()
            .max_by_key(|record| winner_key(record))
            .expect("records is non-empty");

        prop_assert!(merged.validate().is_ok());
        prop_assert_eq!(merged.provenance(), expected_winner.provenance());
        if merged.status().is_scanned() {
            prop_assert_eq!(merged.error_code(), None);
        } else {
            prop_assert_eq!(
                merged.error_code().map(DoneLedgerErrorCode::as_str),
                expected_winner.error_code().map(DoneLedgerErrorCode::as_str),
            );
        }

        match merged.status() {
            DoneLedgerStatus::ScannedClean => prop_assert_eq!(merged.findings_count(), 0),
            DoneLedgerStatus::ScannedWithFindings => prop_assert!(merged.findings_count() >= 1),
            DoneLedgerStatus::FailedRetryable
            | DoneLedgerStatus::FailedPermanent
            | DoneLedgerStatus::Skipped => prop_assert!(merged.error_code().is_some()),
        }
    }
}

proptest::proptest! {
    #![proptest_config(lattice_proptest_config())]

    #[test]
    fn done_ledger_record_merge_converges_under_all_permutations(
        records in arb_record_batch(2..=7),
    ) {
        assert_permutation_convergence(&records)?;
    }
}

#[test]
fn done_ledger_record_merge_resolves_exact_timestamp_ties_commutatively() {
    let left = build_record(
        DoneLedgerStatus::FailedPermanent,
        100,
        3,
        u64::MAX,
        10,
        50,
        400,
        400,
        0,
    );
    let right = build_record(
        DoneLedgerStatus::FailedPermanent,
        120,
        5,
        2,
        u64::MAX,
        51,
        400,
        400,
        5,
    );

    let left_then_right = left.merge(&right).expect("merge should succeed");
    let right_then_left = right.merge(&left).expect("merge should succeed");

    assert_eq!(left_then_right, right_then_left);
    assert_eq!(left_then_right.provenance(), right.provenance());
    assert_eq!(
        left_then_right
            .error_code()
            .map(DoneLedgerErrorCode::as_str),
        right.error_code().map(DoneLedgerErrorCode::as_str),
    );
}

#[test]
fn done_ledger_record_merge_converges_for_all_eight_record_permutations() {
    let records = vec![
        build_record(
            DoneLedgerStatus::FailedRetryable,
            90,
            4,
            1,
            1,
            10,
            100,
            150,
            0,
        ),
        build_record(
            DoneLedgerStatus::FailedPermanent,
            91,
            7,
            2,
            2,
            11,
            100,
            150,
            1,
        ),
        build_record(DoneLedgerStatus::Skipped, 92, 2, 3, 3, 12, 100, 151, 2),
        build_record(DoneLedgerStatus::ScannedClean, 93, 0, 4, 4, 13, 100, 152, 3),
        build_record(
            DoneLedgerStatus::ScannedWithFindings,
            120,
            1,
            5,
            5,
            20,
            200,
            250,
            4,
        ),
        build_record(
            DoneLedgerStatus::ScannedWithFindings,
            121,
            6,
            6,
            6,
            20,
            200,
            250,
            5,
        ),
        build_record(
            DoneLedgerStatus::ScannedWithFindings,
            122,
            8,
            u64::MAX,
            7,
            20,
            200,
            250,
            0,
        ),
        build_record(
            DoneLedgerStatus::ScannedWithFindings,
            200,
            9,
            8,
            u64::MAX,
            21,
            200,
            250,
            1,
        ),
    ];

    assert_permutation_convergence(&records)
        .expect("eight-record permutation convergence should hold");
}
