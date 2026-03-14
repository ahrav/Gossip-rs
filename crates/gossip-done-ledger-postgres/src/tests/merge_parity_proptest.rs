//! Property tests that compare PostgreSQL `ON CONFLICT` merge behavior with
//! the in-memory `DoneLedgerRecord::merge` implementation.

use crate::DoneLedgerPg;
use crate::test_postgres::test_client;
use gossip_contracts::{
    persistence::{
        CommitHandle, DoneLedger, DoneLedgerErrorCode, DoneLedgerRecord, DoneLedgerStatus,
    },
    test_util::done_record,
};
use gossip_stdx::test_support::proptest_cases;
use proptest::{
    prelude::*,
    sample::select,
    test_runner::{Config as ProptestConfig, TestCaseError, TestRunner},
};
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
};

/// Upper bound of `u64` values that fit in a PostgreSQL `BIGINT` (signed `i64`).
///
/// The domain strategies concentrate test values near 0 and near this ceiling
/// to exercise boundary conditions in the Rust ↔ SQL type-mapping layer.
const PG_BIGINT_MAX: u64 = i64::MAX as u64;

/// Upper bound of `u32` values that fit in a PostgreSQL `INTEGER` (signed `i32`).
const PG_INTEGER_MAX: u32 = i32::MAX as u32;

/// Representative error-code strings used by proptest generators.
///
/// Non-scanned statuses require a non-`NULL` `error_code`; strategies index
/// into this array (mod length) to select one deterministically.
const VALID_ERROR_CODES: [&str; 5] = [
    "TIMEOUT",
    "HTTP_403",
    "IO:RETRY",
    "SKIPPED_RULE",
    "SCAN-FAILED",
];
/// All five [`DoneLedgerStatus`] variants, used for exhaustiveness checks
/// after proptest runs and as the sampling universe for `arb_status()`.
const ALL_STATUSES: [DoneLedgerStatus; 5] = DoneLedgerStatus::ALL;

/// Which branch of the merge tie-breaking logic a proptest case is designed
/// to exercise.
///
/// The five scenarios cover the full decision tree of `DoneLedgerRecord::merge`:
/// - `General` — unconstrained; both statuses and timestamps are independent.
/// - `HigherStatus` — the incoming record has a strictly higher status rank.
/// - `LaterFinishedAt` — equal status, incoming has a later `finished_at`.
/// - `LaterStartedAt` — equal status and `finished_at`, incoming has a later `started_at`.
/// - `ExactTie` — identical status and timestamps; later tie-break fields
///   (`fence_epoch`, `run_id`, `shard_id`, `error_code`) choose the winner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MergeScenario {
    General,
    HigherStatus,
    LaterFinishedAt,
    LaterStartedAt,
    ExactTie,
}

/// Random seeds that [`build_generated_record`] expands into 32-byte
/// identity hashes via `test_util::{tenant, policy, ovid}`.
#[derive(Clone, Copy, Debug)]
struct KeySeeds {
    tenant_seed: u8,
    policy_seed: u8,
    ovid_seed: u8,
}

/// Raw provenance fields before `started_at ≤ finished_at` normalisation.
///
/// Strategies generate these freely; [`build_generated_record`] swaps the
/// pair if needed so the constructed record satisfies the schema invariant.
#[derive(Clone, Copy, Debug)]
struct RawProvenance {
    run_id: u64,
    shard_id: u64,
    fence_epoch: u64,
    started_at: u64,
    finished_at: u64,
}

/// Raw record fields before status-dependent normalisation.
///
/// `raw_findings_count` is adjusted by [`normalized_findings_count`] based
/// on the chosen status, and `error_code_index` selects from
/// [`VALID_ERROR_CODES`] only for non-scanned statuses.
#[derive(Clone, Copy, Debug)]
struct RawRecordSpec {
    bytes_scanned: u64,
    raw_findings_count: u32,
    error_code_index: usize,
    provenance: RawProvenance,
}

/// A single test case for the SQL/Rust merge parity property test.
///
/// Both records share the same key (guaranteed by the strategies).
/// The `scenario` tag determines which merge-winner branch is being
/// exercised, and is used in assertion context messages on failure.
#[derive(Clone, Debug)]
struct MergeParityCase {
    scenario: MergeScenario,
    existing: DoneLedgerRecord,
    incoming: DoneLedgerRecord,
}

fn arb_key_seeds() -> BoxedStrategy<KeySeeds> {
    (any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(tenant_seed, policy_seed, ovid_seed)| KeySeeds {
            tenant_seed,
            policy_seed,
            ovid_seed,
        })
        .boxed()
}

fn arb_status() -> BoxedStrategy<DoneLedgerStatus> {
    select(ALL_STATUSES.to_vec()).boxed()
}

/// Generates `u64` values concentrated at the boundaries of the PostgreSQL
/// `BIGINT` domain: zero, small positives, and values near `i64::MAX`.
///
/// This biased distribution catches off-by-one errors at the Rust `u64` →
/// SQL `BIGINT` (`i64`) boundary that uniform sampling would almost never hit.
fn arb_bigint_domain_u64() -> BoxedStrategy<u64> {
    prop_oneof![
        Just(0),
        Just(1),
        Just(2),
        Just(PG_BIGINT_MAX - 1),
        Just(PG_BIGINT_MAX),
        3u64..=4_096u64,
        (PG_BIGINT_MAX / 4)..=(PG_BIGINT_MAX / 2),
        (PG_BIGINT_MAX - 4_096u64)..=PG_BIGINT_MAX,
    ]
    .boxed()
}

/// Generates `u32` values concentrated at the boundaries of the PostgreSQL
/// `INTEGER` domain: zero, small positives, and values near `i32::MAX`.
fn arb_integer_domain_u32() -> BoxedStrategy<u32> {
    prop_oneof![
        Just(0),
        Just(1),
        Just(2),
        Just(PG_INTEGER_MAX - 1),
        Just(PG_INTEGER_MAX),
        3u32..=4_096u32,
        (PG_INTEGER_MAX - 4_096u32)..=PG_INTEGER_MAX,
    ]
    .boxed()
}

fn arb_error_code_index() -> BoxedStrategy<usize> {
    (0usize..VALID_ERROR_CODES.len()).boxed()
}

fn arb_raw_provenance() -> BoxedStrategy<RawProvenance> {
    (
        arb_bigint_domain_u64(),
        arb_bigint_domain_u64(),
        arb_bigint_domain_u64(),
        arb_bigint_domain_u64(),
        arb_bigint_domain_u64(),
    )
        .prop_map(
            |(run_id, shard_id, fence_epoch, started_at, finished_at)| RawProvenance {
                run_id,
                shard_id,
                fence_epoch,
                started_at,
                finished_at,
            },
        )
        .boxed()
}

fn arb_raw_record_spec() -> BoxedStrategy<RawRecordSpec> {
    (
        arb_bigint_domain_u64(),
        arb_integer_domain_u32(),
        arb_error_code_index(),
        arb_raw_provenance(),
    )
        .prop_map(
            |(bytes_scanned, raw_findings_count, error_code_index, provenance)| RawRecordSpec {
                bytes_scanned,
                raw_findings_count,
                error_code_index,
                provenance,
            },
        )
        .boxed()
}

/// Enforce status-dependent `findings_count` invariants so the generated
/// record passes `DoneLedgerRecord::validate()`.
///
/// - `ScannedClean` must have 0 findings.
/// - `ScannedWithFindings` must have at least 1.
/// - Non-scanned statuses accept any count.
fn normalized_findings_count(status: DoneLedgerStatus, raw_findings_count: u32) -> u32 {
    match status {
        DoneLedgerStatus::ScannedClean => 0,
        DoneLedgerStatus::ScannedWithFindings => raw_findings_count.max(1),
        DoneLedgerStatus::FailedRetryable
        | DoneLedgerStatus::FailedPermanent
        | DoneLedgerStatus::Skipped => raw_findings_count,
    }
}

/// Scanned statuses must have `NULL` error codes; non-scanned statuses
/// must have a non-`NULL` error code. Returns `Some(code)` only when
/// the status requires one.
fn error_code_for_status(
    status: DoneLedgerStatus,
    error_code_index: usize,
) -> Option<&'static str> {
    (!status.is_scanned()).then_some(VALID_ERROR_CODES[error_code_index % VALID_ERROR_CODES.len()])
}

/// Assemble a valid [`DoneLedgerRecord`] from raw strategy output.
///
/// Normalises `started_at ≤ finished_at`, adjusts `findings_count` for the
/// chosen status, and selects an error code only when the status demands one.
/// The resulting record passes `validate()` — any failure is a test bug.
fn build_generated_record(
    key_seeds: KeySeeds,
    status: DoneLedgerStatus,
    raw_record: RawRecordSpec,
) -> DoneLedgerRecord {
    // Strategies emit wide raw values, then this helper coerces them into a
    // record that the backend accepts without changing the winner relation
    // each scenario is trying to exercise.
    let (started_at, finished_at) =
        if raw_record.provenance.started_at <= raw_record.provenance.finished_at {
            (
                raw_record.provenance.started_at,
                raw_record.provenance.finished_at,
            )
        } else {
            (
                raw_record.provenance.finished_at,
                raw_record.provenance.started_at,
            )
        };
    let record = done_record(
        key_seeds.tenant_seed,
        key_seeds.policy_seed,
        key_seeds.ovid_seed,
        status,
        raw_record.bytes_scanned,
        normalized_findings_count(status, raw_record.raw_findings_count),
        raw_record.provenance.run_id,
        raw_record.provenance.shard_id,
        raw_record.provenance.fence_epoch,
        started_at,
        finished_at,
        error_code_for_status(status, raw_record.error_code_index),
    );
    record
        .validate()
        .expect("generated parity-test record should satisfy backend invariants");
    record
}

/// Override `started_at` and `finished_at` while preserving all other
/// fields. Used by scenario-specific strategies that need to control the
/// timestamp relationship between existing and incoming records.
fn raw_record_with_timing(
    raw_record: RawRecordSpec,
    started_at: u64,
    finished_at: u64,
) -> RawRecordSpec {
    RawRecordSpec {
        provenance: RawProvenance {
            started_at,
            finished_at,
            ..raw_record.provenance
        },
        ..raw_record
    }
}

/// Unconstrained pair: both statuses and all timestamps are independently
/// generated. Exercises the full merge logic without biasing toward any
/// particular tie-breaking branch.
fn arb_general_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_status(),
        arb_raw_record_spec(),
    )
        .prop_map(
            |(
                key_seeds,
                existing_status,
                existing_raw_record,
                incoming_status,
                incoming_raw_record,
            )| MergeParityCase {
                scenario: MergeScenario::General,
                existing: build_generated_record(key_seeds, existing_status, existing_raw_record),
                incoming: build_generated_record(key_seeds, incoming_status, incoming_raw_record),
            },
        )
        .boxed()
}

/// The incoming record always has a strictly higher status rank than the
/// existing record, guaranteeing that the merge winner is determined by
/// the first tier of the tie-breaking rule (status rank).
///
/// Uses structural index generation (`existing_idx` < `incoming_idx` into
/// the rank-sorted `ALL_STATUSES`) instead of `prop_filter`, eliminating
/// rejections and improving shrinkability.
fn arb_higher_status_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        0usize..ALL_STATUSES.len() - 1,
        arb_raw_record_spec(),
        arb_raw_record_spec(),
    )
        .prop_flat_map(
            |(key_seeds, existing_idx, existing_raw_record, incoming_raw_record)| {
                (existing_idx + 1..ALL_STATUSES.len()).prop_map(move |incoming_idx| {
                    let existing_status = ALL_STATUSES[existing_idx];
                    let incoming_status = ALL_STATUSES[incoming_idx];

                    MergeParityCase {
                        scenario: MergeScenario::HigherStatus,
                        existing: build_generated_record(
                            key_seeds,
                            existing_status,
                            existing_raw_record,
                        ),
                        incoming: build_generated_record(
                            key_seeds,
                            incoming_status,
                            incoming_raw_record,
                        ),
                    }
                })
            },
        )
        .boxed()
}

/// Same status for both records, but the incoming record has a strictly
/// later `finished_at`. This isolates the second tier of the tie-breaking
/// rule (latest `finished_at` wins when statuses are equal).
///
/// Uses `prop_flat_map` so `incoming_started_at` is drawn uniformly from
/// `0..=incoming_finished_at` rather than clamped from a wider range. This
/// avoids collapsing most values to `incoming_finished_at` when the
/// combined existing timestamps produce a small `incoming_finished_at`.
fn arb_later_finished_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_raw_record_spec(),
        prop_oneof![Just(0u64), Just(PG_BIGINT_MAX - 3_000u64)],
        (0u64..=2_000u64, 0u64..=200u64, 1u64..=200u64),
    )
        .prop_flat_map(
            |(
                key_seeds,
                status,
                existing_raw_record,
                incoming_raw_record,
                base_offset,
                (existing_started_at_raw, existing_duration, later_finished_gap),
            )| {
                let existing_started_at = base_offset + existing_started_at_raw;
                let existing_finished_at = existing_started_at + existing_duration;
                let incoming_finished_at = existing_finished_at + later_finished_gap;

                // Draw incoming_started_at uniformly from valid range
                // instead of clamping a wider range.
                (0u64..=incoming_finished_at).prop_map(move |incoming_started_at| {
                    debug_assert!(
                        incoming_finished_at > existing_finished_at,
                        "LaterFinishedAt requires strictly later finished_at"
                    );

                    MergeParityCase {
                        scenario: MergeScenario::LaterFinishedAt,
                        existing: build_generated_record(
                            key_seeds,
                            status,
                            raw_record_with_timing(
                                existing_raw_record,
                                existing_started_at,
                                existing_finished_at,
                            ),
                        ),
                        incoming: build_generated_record(
                            key_seeds,
                            status,
                            raw_record_with_timing(
                                incoming_raw_record,
                                incoming_started_at,
                                incoming_finished_at,
                            ),
                        ),
                    }
                })
            },
        )
        .boxed()
}

/// Same status and identical `finished_at`, but the incoming record has a
/// strictly later `started_at`. This isolates the third tier of
/// the tie-breaking rule (latest `started_at` wins when status and
/// `finished_at` are equal).
///
/// Uses `prop_flat_map` so the gap between `existing_started_at` and
/// `incoming_started_at` is drawn uniformly from `1..=max_gap` rather
/// than generated from a fixed range and clamped (which biases toward
/// the boundary when `max_gap` is small).
fn arb_later_started_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_raw_record_spec(),
        prop_oneof![Just(0u64), Just(PG_BIGINT_MAX - 3_000u64)],
        (1u64..=2_000u64, 0u64..=1_999u64),
    )
        .prop_flat_map(
            |(
                key_seeds,
                status,
                existing_raw_record,
                incoming_raw_record,
                base_offset,
                (finished_at_rel, existing_started_raw),
            )| {
                let existing_started_at_rel = existing_started_raw.min(finished_at_rel - 1);
                let max_gap = finished_at_rel - existing_started_at_rel;

                (1u64..=max_gap.max(1)).prop_map(move |gap| {
                    let finished_at = base_offset + finished_at_rel;
                    let existing_started_at = base_offset + existing_started_at_rel;
                    let incoming_started_at = existing_started_at + gap;

                    debug_assert!(
                        incoming_started_at > existing_started_at,
                        "LaterStartedAt requires strictly later started_at"
                    );

                    MergeParityCase {
                        scenario: MergeScenario::LaterStartedAt,
                        existing: build_generated_record(
                            key_seeds,
                            status,
                            raw_record_with_timing(
                                existing_raw_record,
                                existing_started_at,
                                finished_at,
                            ),
                        ),
                        incoming: build_generated_record(
                            key_seeds,
                            status,
                            raw_record_with_timing(
                                incoming_raw_record,
                                incoming_started_at,
                                finished_at,
                            ),
                        ),
                    }
                })
            },
        )
        .boxed()
}

/// Same status, same `started_at`, same `finished_at` — a tie on the
/// semantic ordering fields. The remaining tie-break suffix
/// (`fence_epoch`, `run_id`, `shard_id`, `error_code`) must resolve the
/// winner identically in Rust and SQL.
fn arb_exact_tie_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_raw_record_spec(),
        prop_oneof![Just(0u64), Just(PG_BIGINT_MAX - 3_000u64)],
        (0u64..=2_000u64, 0u64..=200u64),
    )
        .prop_map(
            |(
                key_seeds,
                status,
                existing_raw_record,
                incoming_raw_record,
                base_offset,
                (started_at_raw, duration),
            )| {
                let started_at = base_offset + started_at_raw;
                let finished_at = started_at + duration;

                MergeParityCase {
                    scenario: MergeScenario::ExactTie,
                    existing: build_generated_record(
                        key_seeds,
                        status,
                        raw_record_with_timing(existing_raw_record, started_at, finished_at),
                    ),
                    incoming: build_generated_record(
                        key_seeds,
                        status,
                        raw_record_with_timing(incoming_raw_record, started_at, finished_at),
                    ),
                }
            },
        )
        .boxed()
}

/// Weighted union of all five merge scenarios.
///
/// `General` gets 2× weight because it covers the broadest input space and
/// implicitly exercises all tie-breaking tiers. The remaining four targeted
/// scenarios each get 1× weight to ensure adequate coverage of specific
/// decision branches.
fn arb_merge_parity_case() -> BoxedStrategy<MergeParityCase> {
    prop_oneof![
        2 => arb_general_case(),
        1 => arb_higher_status_case(),
        1 => arb_later_finished_case(),
        1 => arb_later_started_case(),
        1 => arb_exact_tie_case(),
    ]
    .boxed()
}

/// Wrap a backend error into a proptest failure with a descriptive context prefix.
fn prop_failure(context: &str, err: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(format!("{context}: {err}"))
}

/// Assert that every observable field of two records matches, producing
/// per-field proptest failure messages that include `context` for
/// diagnosing which scenario and write order failed.
fn assert_record_fields_match(
    expected: &DoneLedgerRecord,
    actual: &DoneLedgerRecord,
    context: &str,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(actual.key(), expected.key(), "{}: key diverged", context);
    prop_assert_eq!(
        actual.status(),
        expected.status(),
        "{}: status diverged",
        context
    );
    prop_assert_eq!(
        actual.bytes_scanned(),
        expected.bytes_scanned(),
        "{}: bytes_scanned diverged",
        context
    );
    prop_assert_eq!(
        actual.findings_count(),
        expected.findings_count(),
        "{}: findings_count diverged",
        context
    );
    prop_assert_eq!(
        actual.provenance(),
        expected.provenance(),
        "{}: provenance diverged",
        context
    );
    prop_assert_eq!(
        actual.error_code().map(DoneLedgerErrorCode::as_str),
        expected.error_code().map(DoneLedgerErrorCode::as_str),
        "{}: error_code diverged",
        context
    );
    Ok(())
}

/// Write `existing` then `incoming` to PostgreSQL and read back the merged
/// row.
///
/// Truncates the table first so the merge is isolated from prior state.
/// The first `batch_upsert` inserts the row; the second hits the SQL
/// `ON CONFLICT` path and exercises the merge expression.
fn run_sql_merge_order(
    backend: &DoneLedgerPg,
    existing: &DoneLedgerRecord,
    incoming: &DoneLedgerRecord,
) -> Result<DoneLedgerRecord, TestCaseError> {
    // The first write seeds the row; the second write is the one that must
    // travel through the SQL ON CONFLICT merge path.
    backend
        .truncate_all_for_tests()
        .map_err(|err| prop_failure("truncate_all_for_tests failed", err))?;
    backend
        .batch_upsert(std::slice::from_ref(existing))
        .map_err(|err| prop_failure("existing batch_upsert failed", err))?
        .wait()
        .map_err(|err| prop_failure("existing batch_upsert commit failed", err))?;
    backend
        .batch_upsert(std::slice::from_ref(incoming))
        .map_err(|err| prop_failure("incoming batch_upsert failed", err))?
        .wait()
        .map_err(|err| prop_failure("incoming batch_upsert commit failed", err))?;

    let fetched = backend
        .batch_get(
            existing.key().tenant_id(),
            existing.key().policy_hash(),
            &[existing.key().ovid_hash()],
        )
        .map_err(|err| prop_failure("batch_get failed", err))?;

    match fetched.as_slice() {
        [Some(record)] => Ok(record.clone()),
        [None] => Err(TestCaseError::fail(
            "expected merged row to exist after SQL upsert parity check",
        )),
        _ => Err(TestCaseError::fail(format!(
            "expected exactly one batch_get result, got {}",
            fetched.len()
        ))),
    }
}

/// The core parity assertion: compute the expected result via
/// `DoneLedgerRecord::merge` (Rust), then compare field-by-field against
/// the actual result from [`run_sql_merge_order`] (PostgreSQL).
///
/// Returns the SQL merge result on success so callers can perform
/// additional assertions without a redundant database round-trip.
fn assert_sql_merge_matches_rust_merge(
    backend: &DoneLedgerPg,
    existing: &DoneLedgerRecord,
    incoming: &DoneLedgerRecord,
    scenario: MergeScenario,
    order_label: &str,
) -> Result<DoneLedgerRecord, TestCaseError> {
    let context = format!("{scenario:?}/{order_label}");
    let expected = existing
        .merge(incoming)
        .map_err(|err| prop_failure(&format!("{context}: rust merge failed"), err))?;
    let actual = run_sql_merge_order(backend, existing, incoming)?;
    assert_record_fields_match(&expected, &actual, &context)?;
    Ok(actual)
}

/// Property test: for randomly generated record pairs, the SQL
/// `ON CONFLICT` merge must produce the same result as the in-memory
/// `DoneLedgerRecord::merge`. The case count is governed by
/// [`proptest_cases`] (4 locally, 256 in CI, overridable via
/// `PROPTEST_CASES`).
///
/// Each case is tested in *both* write orders (existing→incoming and
/// incoming→existing) so the parity check covers both insert/update paths
/// and independently verifies that SQL stays commutative across write order.
///
/// Post-loop assertions verify that the proptest run achieved adequate
/// coverage: all five status variants appeared, and all four non-General
/// scenarios (`HigherStatus`, `LaterFinishedAt`, `LaterStartedAt`,
/// `ExactTie`) were each exercised at least once.
#[test]
fn sql_on_conflict_merge_matches_rust_merge_proptest() {
    let backend = DoneLedgerPg::from_client(test_client());
    let strategy = arb_merge_parity_case();
    let case_count = proptest_cases(256);
    let mut runner = TestRunner::new(ProptestConfig {
        cases: case_count,
        max_shrink_iters: 256,
        source_file: Some(file!()),
        ..ProptestConfig::default()
    });
    let seen_statuses = RefCell::new(HashSet::new());
    let saw_higher_status = Cell::new(false);
    let saw_later_finished = Cell::new(false);
    let saw_later_started = Cell::new(false);
    let saw_exact_tie = Cell::new(false);

    runner
        .run(&strategy, |case| {
            seen_statuses.borrow_mut().insert(case.existing.status());
            seen_statuses.borrow_mut().insert(case.incoming.status());
            saw_higher_status
                .set(saw_higher_status.get() || case.scenario == MergeScenario::HigherStatus);
            saw_later_finished
                .set(saw_later_finished.get() || case.scenario == MergeScenario::LaterFinishedAt);
            saw_later_started
                .set(saw_later_started.get() || case.scenario == MergeScenario::LaterStartedAt);
            saw_exact_tie.set(saw_exact_tie.get() || case.scenario == MergeScenario::ExactTie);

            let sql_existing_first = assert_sql_merge_matches_rust_merge(
                &backend,
                &case.existing,
                &case.incoming,
                case.scenario,
                "existing_then_incoming",
            )?;
            let sql_incoming_first = assert_sql_merge_matches_rust_merge(
                &backend,
                &case.incoming,
                &case.existing,
                case.scenario,
                "incoming_then_existing",
            )?;
            assert_record_fields_match(
                &sql_existing_first,
                &sql_incoming_first,
                &format!("{:?}/write_order_commutativity", case.scenario),
            )?;

            Ok(())
        })
        .expect("SQL and Rust merge parity proptest should pass");

    // Coverage assertions require enough cases to hit every scenario arm.
    // With fewer than 100 cases (e.g., the local default of 4), the
    // weighted scenario distribution cannot reliably exercise all five
    // status variants and all four targeted scenarios. Set PROPTEST_CASES
    // or run under CI to enable these checks.
    if case_count < 100 {
        eprintln!(
            "note: coverage assertions skipped (case_count={case_count} < 100). \
             Set PROPTEST_CASES=256 or run under CI to enable."
        );
    } else {
        let seen_statuses = seen_statuses.into_inner();
        let expected_statuses: HashSet<_> = ALL_STATUSES.into_iter().collect();
        assert_eq!(
            seen_statuses, expected_statuses,
            "proptest should exercise every DoneLedgerStatus variant"
        );
        assert!(
            saw_higher_status.get(),
            "proptest should cover higher-status provenance winner selection"
        );
        assert!(
            saw_later_finished.get(),
            "proptest should cover later-finished provenance winner selection"
        );
        assert!(
            saw_later_started.get(),
            "proptest should cover later-started provenance winner selection"
        );
        assert!(
            saw_exact_tie.get(),
            "proptest should cover exact-tie canonical winner selection"
        );
    }
}
