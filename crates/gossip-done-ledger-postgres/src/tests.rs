//! Integration tests for the PostgreSQL done-ledger schema and migration runner.
//!
//! All tests in this module require a running PostgreSQL instance (either via
//! Docker/testcontainers or an external `GOSSIP_POSTGRES_TEST_URL`). They are marked
//! `#[ignore]` so that `cargo test` without Docker skips them cleanly.
//!
//! ## Test categories
//!
//! - **Migration runner** — migration-from-scratch, idempotent reapply,
//!   checksum-mismatch detection (synthetic and persisted-history tamper),
//!   connection smoke checks, and concurrent advisory-lock serialisation.
//! - **`DoneLedger` backend behavior** — conformance suite, positional
//!   alignment of `batch_get`, empty-input and absent-key edge handling,
//!   and duplicate-key merge in `batch_upsert`.
//! - **Schema constraint enforcement** — verifies that SQL `CHECK`
//!   constraints reject invalid status values, negative counters,
//!   wrong-length `BYTEA` columns, and shape-inconsistent rows.
//!
//! ## Running
//!
//! ```bash
//! # With Docker:
//! cargo test -p gossip-done-ledger-postgres -- --ignored
//!
//! # With an external PostgreSQL (needs CREATE DATABASE privilege):
//! GOSSIP_POSTGRES_TEST_URL="host=localhost user=postgres password=postgres" \
//!   cargo test -p gossip-done-ledger-postgres -- --ignored
//! ```

use crate::test_postgres::{test_client, test_client_bare};
use crate::{DoneLedgerPg, DoneLedgerPgMigrationError, apply_all_migrations, apply_migrations};
use gossip_contracts::{
    identity::{FenceEpoch, LogicalTime, RunId, ShardId},
    persistence::{
        CommitHandle, DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance,
        DoneLedgerRecord, DoneLedgerStatus, run_done_ledger_conformance,
    },
    test_util::{ovid, policy, tenant},
};
use proptest::{
    prelude::*,
    sample::select,
    test_runner::{Config as ProptestConfig, TestCaseError, TestRunner},
};
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
};

// ── Migration runner ────────────────────────────────────────────────────

/// Applying the full migration set twice must leave exactly one history row
/// per migration — the second pass is a no-op.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migrations_are_idempotent() {
    let mut client = test_client_bare();

    apply_all_migrations(&mut client).expect("first application should succeed");
    apply_all_migrations(&mut client).expect("second application should succeed (idempotent)");

    let count: i64 = client
        .query_one(
            &format!(
                "SELECT COUNT(*) FROM {}",
                crate::schema::SCHEMA_MIGRATIONS_TABLE
            ),
            &[],
        )
        .expect("count query should succeed")
        .get(0);

    assert_eq!(
        count,
        crate::migrations::MIGRATIONS.len() as i64,
        "history table should contain exactly one row per migration"
    );
}

/// Replaying migrations whose SQL text differs from the originally-applied
/// version must fail with `ChecksumMismatch`. This guards against accidental
/// edits to already-applied migration files.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn checksum_mismatch_is_detected() {
    let mut client = test_client_bare();

    // Apply the real migrations first.
    apply_all_migrations(&mut client).expect("initial migration should succeed");

    // Now try to apply a migration with the same version but different SQL.
    let tampered = [crate::migrations::EmbeddedMigration::new(
        "0001_done_ledger_entries",
        "SELECT 1; -- tampered",
    )];

    let err = apply_migrations(&mut client, &tampered, std::time::Duration::from_secs(5))
        .expect_err("tampered migration should produce ChecksumMismatch");

    match err {
        DoneLedgerPgMigrationError::ChecksumMismatch { version, .. } => {
            assert_eq!(version, "0001_done_ledger_entries");
        }
        DoneLedgerPgMigrationError::Postgres { source, .. } => {
            panic!("expected ChecksumMismatch, got Postgres error: {source}");
        }
        DoneLedgerPgMigrationError::CorruptedHistoryRecord { version, found_len } => {
            panic!(
                "expected ChecksumMismatch, got CorruptedHistoryRecord: version={version}, len={found_len}"
            );
        }
    }
}

/// Two threads racing to apply migrations on the same database must both
/// succeed without deadlock. The advisory lock serialises them; the second
/// thread sees all migrations already applied and becomes a no-op.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn concurrent_migrations_both_succeed() {
    // Create a single bare database — both threads target the same DB.
    let url = crate::test_postgres::create_test_db();
    let url2 = url.clone();

    // Barrier ensures both threads attempt migration at roughly the same
    // instant, maximising the chance of real advisory-lock contention.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b1 = barrier.clone();
    let b2 = barrier.clone();

    let t1 = std::thread::spawn(move || {
        let mut c =
            postgres::Client::connect(&url, postgres::NoTls).expect("thread 1 connect failed");
        b1.wait();
        apply_all_migrations(&mut c)
    });
    let t2 = std::thread::spawn(move || {
        let mut c =
            postgres::Client::connect(&url2, postgres::NoTls).expect("thread 2 connect failed");
        b2.wait();
        apply_all_migrations(&mut c)
    });

    t1.join()
        .expect("thread 1 panicked")
        .expect("thread 1 migration failed");
    t2.join()
        .expect("thread 2 panicked")
        .expect("thread 2 migration failed");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn provisioned_database_url_is_connectable() {
    let url = crate::test_postgres::create_test_db();
    let mut client =
        postgres::Client::connect(&url, postgres::NoTls).expect("connect should succeed");
    let one: i32 = client
        .query_one("SELECT 1", &[])
        .expect("smoke query should succeed")
        .get(0);
    assert_eq!(one, 1);
}

/// Directly mutating the stored checksum in the history table must be
/// caught on the next migration run. This simulates corruption of the
/// migration history (e.g., manual SQL edits) rather than the migration
/// SQL text itself, complementing [`checksum_mismatch_is_detected`].
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn persisted_checksum_tamper_is_detected_on_reapply() {
    let mut client = test_client_bare();

    apply_all_migrations(&mut client).expect("initial migration should succeed");

    let updated = client
        .execute(
            &format!(
                "UPDATE {} SET checksum = decode(repeat('00', {}), 'hex') WHERE version = $1",
                crate::schema::SCHEMA_MIGRATIONS_TABLE,
                blake3::OUT_LEN, // BLAKE3 output width; matches schema CHECK constraint.
            ),
            &[&"0001_done_ledger_entries"],
        )
        .expect("checksum tamper update should succeed");
    assert_eq!(updated, 1, "expected to tamper exactly one migration row");

    let err = apply_all_migrations(&mut client)
        .expect_err("tampered persisted checksum should fail re-application");
    match err {
        DoneLedgerPgMigrationError::ChecksumMismatch { version, .. } => {
            assert_eq!(version, "0001_done_ledger_entries");
        }
        DoneLedgerPgMigrationError::Postgres { source, .. } => {
            panic!("expected ChecksumMismatch, got Postgres error: {source}");
        }
        DoneLedgerPgMigrationError::CorruptedHistoryRecord { version, found_len } => {
            panic!(
                "expected ChecksumMismatch, got CorruptedHistoryRecord: version={version}, len={found_len}"
            );
        }
    }
}

// ── DoneLedger backend behavior ───────────────────────────────────────────

/// Shorthand to construct a [`DoneLedgerProvenance`] from raw `u64` fields.
fn provenance(
    run_id: u64,
    shard_id: u64,
    fence_epoch: u64,
    started_at: u64,
    finished_at: u64,
) -> DoneLedgerProvenance {
    DoneLedgerProvenance::new(
        RunId::from_raw(run_id),
        ShardId::from_raw(shard_id),
        FenceEpoch::from_raw(fence_epoch),
        LogicalTime::from_raw(started_at),
        LogicalTime::from_raw(finished_at),
    )
}

/// Construct a [`DoneLedgerRecord`] from flat scalar arguments.
///
/// Seeds are expanded into deterministic 32-byte identity hashes via
/// `test_util::{tenant, policy, ovid}`. Panics on invalid combinations
/// (e.g., `ScannedClean` with `findings_count > 0`), which is intentional
/// for test code — the caller is responsible for providing self-consistent
/// arguments.
#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors the done-ledger durable row shape"
)]
fn done_record(
    tenant_seed: u8,
    policy_seed: u8,
    ovid_seed: u8,
    status: DoneLedgerStatus,
    bytes_scanned: u64,
    findings_count: u32,
    run_id: u64,
    shard_id: u64,
    fence_epoch: u64,
    started_at: u64,
    finished_at: u64,
    error_code: Option<&str>,
) -> DoneLedgerRecord {
    DoneLedgerRecord::try_new(
        DoneLedgerKey::new(tenant(tenant_seed), policy(policy_seed), ovid(ovid_seed)),
        status,
        bytes_scanned,
        findings_count,
        provenance(run_id, shard_id, fence_epoch, started_at, finished_at),
        error_code.map(|code| {
            DoneLedgerErrorCode::try_new(code).expect("test error code should be valid")
        }),
    )
    .expect("test record should satisfy construction invariants")
}

/// Upper bound of `u64` values that fit in a PostgreSQL `BIGINT` (signed `i64`).
///
/// The domain strategies concentrate test values near 0 and near this ceiling
/// to exercise boundary conditions in the Rust ↔ SQL type-mapping layer.
const PG_BIGINT_MAX: u64 = i64::MAX as u64;

/// Upper bound of `u32` values that fit in a PostgreSQL `INTEGER` (signed `i32`).
const PG_INTEGER_MAX: u32 = i32::MAX as u32;

/// Number of proptest cases for the SQL/Rust merge parity test.
///
/// 1,000 cases across five weighted scenarios (General ×2, HigherStatus,
/// LaterFinishedAt, LaterStartedAt, ExactTie) provide high confidence that
/// the SQL `ON CONFLICT` clause and `DoneLedgerRecord::merge` agree on all
/// reachable merge outcomes. Post-run assertions verify that all five status
/// variants and all non-General scenarios were exercised.
const SQL_RUST_MERGE_PROPTEST_CASES: u32 = 1_000;

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
const ALL_STATUSES: [DoneLedgerStatus; 5] = [
    DoneLedgerStatus::FailedRetryable,
    DoneLedgerStatus::FailedPermanent,
    DoneLedgerStatus::Skipped,
    DoneLedgerStatus::ScannedClean,
    DoneLedgerStatus::ScannedWithFindings,
];

/// Which branch of the merge tie-breaking logic a proptest case is designed
/// to exercise.
///
/// The five scenarios cover the full decision tree of `DoneLedgerRecord::merge`:
/// - `General` — unconstrained; both statuses and timestamps are independent.
/// - `HigherStatus` — the incoming record has a strictly higher status rank.
/// - `LaterFinishedAt` — equal status, incoming has a later `finished_at`.
/// - `LaterStartedAt` — equal status and `finished_at`, incoming has a later `started_at`.
/// - `ExactTie` — identical status and timestamps; existing row wins (stability).
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
fn arb_higher_status_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_status(),
        arb_raw_record_spec(),
    )
        .prop_filter(
            "higher-status scenario needs distinct statuses",
            |(_, existing_status, _, incoming_status, _)| existing_status != incoming_status,
        )
        .prop_map(
            |(key_seeds, left_status, left_raw_record, right_status, right_raw_record)| {
                let (existing_status, incoming_status, existing_raw_record, incoming_raw_record) =
                    if left_status.rank() < right_status.rank() {
                        (left_status, right_status, left_raw_record, right_raw_record)
                    } else {
                        (right_status, left_status, right_raw_record, left_raw_record)
                    };

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
            },
        )
        .boxed()
}

/// Same status for both records, but the incoming record has a strictly
/// later `finished_at`. This isolates the second tier of the tie-breaking
/// rule (latest `finished_at` wins when statuses are equal).
fn arb_later_finished_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_raw_record_spec(),
        (
            0u64..=2_000u64,
            0u64..=200u64,
            1u64..=200u64,
            0u64..=2_400u64,
        ),
    )
        .prop_map(
            |(
                key_seeds,
                status,
                existing_raw_record,
                incoming_raw_record,
                (existing_started_at, existing_duration, later_finished_gap, incoming_started_raw),
            )| {
                let existing_finished_at = existing_started_at + existing_duration;
                let incoming_finished_at = existing_finished_at + later_finished_gap;
                let incoming_started_at = incoming_started_raw.min(incoming_finished_at);

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
            },
        )
        .boxed()
}

/// Same status and identical `finished_at`, but the incoming record has a
/// strictly later `started_at`. This isolates the third and final tier of
/// the tie-breaking rule (latest `started_at` wins when status and
/// `finished_at` are equal).
fn arb_later_started_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_raw_record_spec(),
        (1u64..=2_000u64, 0u64..=1_999u64, 1u64..=2_000u64),
    )
        .prop_map(
            |(
                key_seeds,
                status,
                existing_raw_record,
                incoming_raw_record,
                (finished_at, existing_started_raw, incoming_started_gap_raw),
            )| {
                let existing_started_at = existing_started_raw.min(finished_at - 1);
                let max_gap = finished_at - existing_started_at;
                // When `finished_at` is small (e.g., 1), `max_gap` can be 1,
                // collapsing `incoming_started_gap_raw` to a single effective
                // value. This is harmless: the strict-inequality invariant
                // still holds and larger `finished_at` values exercise the
                // full gap range.
                let incoming_started_at =
                    existing_started_at + incoming_started_gap_raw.min(max_gap);

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
            },
        )
        .boxed()
}

/// Same status, same `started_at`, same `finished_at` — a perfect tie.
/// The merge rule preserves the existing (first-written) row, so the
/// parity check must account for write order when comparing SQL and Rust
/// merge results.
fn arb_exact_tie_case() -> BoxedStrategy<MergeParityCase> {
    (
        arb_key_seeds(),
        arb_status(),
        arb_raw_record_spec(),
        arb_raw_record_spec(),
        (0u64..=2_000u64, 0u64..=200u64),
    )
        .prop_map(
            |(
                key_seeds,
                status,
                existing_raw_record,
                incoming_raw_record,
                (started_at, duration),
            )| {
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
fn assert_sql_merge_matches_rust_merge(
    backend: &DoneLedgerPg,
    existing: &DoneLedgerRecord,
    incoming: &DoneLedgerRecord,
    scenario: MergeScenario,
    order_label: &str,
) -> Result<(), TestCaseError> {
    let context = format!("{scenario:?}/{order_label}");
    let expected = existing
        .merge(incoming)
        .map_err(|err| prop_failure(&format!("{context}: rust merge failed"), err))?;
    let actual = run_sql_merge_order(backend, existing, incoming)?;
    assert_record_fields_match(&expected, &actual, &context)
}

/// Run the contract-defined conformance suite against the PostgreSQL backend.
///
/// The suite verifies idempotent upsert, fail→scan dominance, scan→fail
/// dominance, and `batch_get` positional semantics (4 checks total).
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn done_ledger_backend_passes_conformance_suite() {
    let backend = DoneLedgerPg::from_client(test_client());
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before conformance");

    let checks = run_done_ledger_conformance(&backend)
        .unwrap_or_else(|err| panic!("done-ledger conformance failed: {err}"));
    assert_eq!(checks, 4);
}

/// Property test: for 1,000 randomly generated record pairs, the SQL
/// `ON CONFLICT` merge must produce the same result as the in-memory
/// `DoneLedgerRecord::merge`.
///
/// Each case is tested in *both* write orders (existing→incoming and
/// incoming→existing) because exact ties preserve the first-written row,
/// so commutativity only holds relative to the Rust merge called in the
/// same order.
///
/// Post-loop assertions verify that the proptest run achieved adequate
/// coverage: all five status variants appeared, and all four non-General
/// scenarios (`HigherStatus`, `LaterFinishedAt`, `LaterStartedAt`,
/// `ExactTie`) were each exercised at least once.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn sql_on_conflict_merge_matches_rust_merge_proptest() {
    let backend = DoneLedgerPg::from_client(test_client());
    let strategy = arb_merge_parity_case();
    let mut runner = TestRunner::new(ProptestConfig {
        cases: SQL_RUST_MERGE_PROPTEST_CASES,
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

            assert_sql_merge_matches_rust_merge(
                &backend,
                &case.existing,
                &case.incoming,
                case.scenario,
                "existing_then_incoming",
            )?;
            // Exact ties preserve the existing row, so parity has to be
            // checked against the Rust merge in each write order separately.
            assert_sql_merge_matches_rust_merge(
                &backend,
                &case.incoming,
                &case.existing,
                case.scenario,
                "incoming_then_existing",
            )?;
            Ok(())
        })
        .expect("SQL and Rust merge parity proptest should pass");

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
        "proptest should cover exact-tie stability (existing row wins)"
    );
}

/// `batch_get` with an empty `ovid_hashes` slice must return an empty vec
/// without issuing a SQL query.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_get_empty_input_returns_empty_vec() {
    let backend = DoneLedgerPg::from_client(test_client());
    let fetched = backend
        .batch_get(tenant(5), policy(6), &[])
        .expect("empty batch_get should succeed");
    assert!(fetched.is_empty());
}

/// Querying a key that was never written must produce `[None]`, not an error.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_get_nonexistent_key_returns_none() {
    let backend = DoneLedgerPg::from_client(test_client());
    let fetched = backend
        .batch_get(tenant(5), policy(6), &[ovid(200)])
        .expect("batch_get should succeed for absent key");
    assert_eq!(fetched.len(), 1);
    assert!(fetched[0].is_none());
}

/// Upserting an empty slice must succeed and return a zero-count receipt.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_upsert_empty_input_returns_zero_receipt() {
    let backend = DoneLedgerPg::from_client(test_client());
    let receipt = backend
        .batch_upsert(&[])
        .expect("empty batch_upsert should succeed")
        .wait()
        .expect("empty batch_upsert commit handle should resolve");
    assert_eq!(receipt.record_count(), 0);
    assert_eq!(receipt.scanned_count(), 0);
    assert_eq!(receipt.findings_count(), 0);
}

/// `batch_get` must return results in the same positional order as the
/// input `ovid_hashes` slice — including `None` for absent keys and
/// duplicated `Some` entries when the same key appears multiple times.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_get_preserves_positional_alignment_with_duplicates() {
    let backend = DoneLedgerPg::from_client(test_client());
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    let record_one = done_record(
        1,
        2,
        11,
        DoneLedgerStatus::ScannedClean,
        100,
        0,
        1,
        1,
        1,
        10,
        20,
        None,
    );
    let record_two = done_record(
        1,
        2,
        12,
        DoneLedgerStatus::ScannedWithFindings,
        250,
        2,
        2,
        2,
        2,
        15,
        30,
        None,
    );
    backend
        .batch_upsert(&[record_one.clone(), record_two.clone()])
        .expect("upsert should succeed")
        .wait()
        .expect("commit should succeed");

    let absent = ovid(99);
    let fetched = backend
        .batch_get(
            tenant(1),
            policy(2),
            &[
                record_two.key().ovid_hash(),
                absent,
                record_one.key().ovid_hash(),
                record_two.key().ovid_hash(),
            ],
        )
        .expect("batch_get should succeed");

    assert_eq!(fetched.len(), 4);
    assert_eq!(fetched[0].as_ref(), Some(&record_two));
    assert_eq!(fetched[1], None);
    assert_eq!(fetched[2].as_ref(), Some(&record_one));
    assert_eq!(fetched[3].as_ref(), Some(&record_two));
}

/// When a single `batch_upsert` call contains two records with the same
/// key, the Rust-side `dedupe_and_validate` pass must merge them before
/// SQL mutation. The receipt should report 1 record (not 2), and the
/// persisted row must reflect the lattice-merge result.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_upsert_merges_duplicate_keys_before_persist() {
    let backend = DoneLedgerPg::from_client(test_client());
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    let failed = done_record(
        3,
        4,
        21,
        DoneLedgerStatus::FailedRetryable,
        900,
        8,
        10,
        11,
        12,
        100,
        200,
        Some("RETRY"),
    );
    let scanned = done_record(
        3,
        4,
        21,
        DoneLedgerStatus::ScannedWithFindings,
        200,
        1,
        20,
        21,
        22,
        110,
        250,
        None,
    );

    let receipt = backend
        .batch_upsert(&[failed, scanned.clone()])
        .expect("upsert should succeed")
        .wait()
        .expect("commit should succeed");
    assert_eq!(receipt.record_count(), 1);
    assert_eq!(receipt.scanned_count(), 1);
    assert_eq!(receipt.findings_count(), 8);

    let fetched = backend
        .batch_get(tenant(3), policy(4), &[ovid(21)])
        .expect("batch_get should succeed");
    let merged = fetched[0]
        .as_ref()
        .expect("row should exist after successful upsert");

    assert_eq!(merged.status(), DoneLedgerStatus::ScannedWithFindings);
    assert_eq!(merged.bytes_scanned(), 900);
    assert_eq!(merged.findings_count(), 8);
    assert_eq!(merged.error_code(), None);
    assert_eq!(merged.provenance(), scanned.provenance());
}

/// Writing two records with the same key in *separate* `batch_upsert` calls
/// exercises the PostgreSQL `ON CONFLICT` merge path (not the Rust-side
/// `dedupe_and_validate` path). Verifies status promotion, `bytes_scanned`
/// high-water-mark, `error_code` clearing, and provenance winner selection.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn cross_batch_upsert_exercises_sql_on_conflict_merge() {
    let backend = DoneLedgerPg::from_client(test_client());
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    // First batch: insert a failed record.
    let failed = done_record(
        5,
        6,
        31,
        DoneLedgerStatus::FailedRetryable,
        400,
        3,
        10,
        11,
        12,
        100,
        200,
        Some("TIMEOUT"),
    );
    backend
        .batch_upsert(std::slice::from_ref(&failed))
        .expect("first upsert should succeed")
        .wait()
        .expect("first commit should succeed");

    // Second batch: insert a scanned record with the same key.
    // This triggers the SQL ON CONFLICT clause (not Rust-side dedup).
    let scanned = done_record(
        5,
        6,
        31,
        DoneLedgerStatus::ScannedWithFindings,
        200,
        5,
        20,
        21,
        22,
        110,
        250,
        None,
    );
    backend
        .batch_upsert(std::slice::from_ref(&scanned))
        .expect("second upsert should succeed")
        .wait()
        .expect("second commit should succeed");

    let fetched = backend
        .batch_get(tenant(5), policy(6), &[ovid(31)])
        .expect("batch_get should succeed");
    let merged = fetched[0]
        .as_ref()
        .expect("row should exist after cross-batch upsert");

    // ScannedWithFindings (rank 11) > FailedRetryable (rank 1).
    assert_eq!(merged.status(), DoneLedgerStatus::ScannedWithFindings);
    // bytes_scanned takes the GREATEST across both batches.
    assert_eq!(merged.bytes_scanned(), 400);
    // Scanned status clears error_code.
    assert_eq!(merged.error_code(), None);
    // Provenance comes from the status winner (ScannedWithFindings).
    assert_eq!(merged.provenance(), scanned.provenance());
}

/// When two cross-batch records share the same status, the merge rule
/// falls through to the `finished_at` tie-break. The later `finished_at`
/// record wins provenance (and its associated `error_code`), while
/// `bytes_scanned` and `findings_count` still take `GREATEST`.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn cross_batch_upsert_equal_status_picks_later_finished_at() {
    let backend = DoneLedgerPg::from_client(test_client());
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    // First batch: FailedRetryable with finished_at=200.
    let earlier = done_record(
        6,
        7,
        41,
        DoneLedgerStatus::FailedRetryable,
        300,
        2,
        10,
        11,
        12,
        100,
        200,
        Some("ERR_A"),
    );
    backend
        .batch_upsert(std::slice::from_ref(&earlier))
        .expect("first upsert should succeed")
        .wait()
        .expect("first commit should succeed");

    // Second batch: same status, later finished_at=300.
    // The provenance tie-break should select this record's provenance.
    let later = done_record(
        6,
        7,
        41,
        DoneLedgerStatus::FailedRetryable,
        100,
        1,
        20,
        21,
        22,
        150,
        300,
        Some("ERR_B"),
    );
    backend
        .batch_upsert(std::slice::from_ref(&later))
        .expect("second upsert should succeed")
        .wait()
        .expect("second commit should succeed");

    let fetched = backend
        .batch_get(tenant(6), policy(7), &[ovid(41)])
        .expect("batch_get should succeed");
    let merged = fetched[0]
        .as_ref()
        .expect("row should exist after equal-status cross-batch upsert");

    // Same status — no promotion.
    assert_eq!(merged.status(), DoneLedgerStatus::FailedRetryable);
    // bytes_scanned takes the GREATEST.
    assert_eq!(merged.bytes_scanned(), 300);
    // findings_count takes the GREATEST (non-scanned status branch).
    assert_eq!(merged.findings_count(), 2);
    // Provenance winner is the later finished_at record.
    assert_eq!(merged.provenance(), later.provenance());
    // error_code from the provenance winner (COALESCE picks winner first).
    assert_eq!(merged.error_code().map(|c| c.as_str()), Some("ERR_B"),);
}

// ── Schema constraint enforcement ───────────────────────────────────────
//
// These tests bypass `DoneLedgerPg` and issue raw SQL `INSERT` statements
// against the schema to verify that PostgreSQL `CHECK` constraints reject
// invalid data. This ensures the database is a defense-in-depth layer
// independent of Rust-side validation.

/// Assert that a Postgres error is a CHECK_VIOLATION (SQLSTATE 23514).
fn assert_check_violation(err: &postgres::Error) {
    let db_err = err.as_db_error().expect("expected server-side DbError");
    assert_eq!(
        *db_err.code(),
        postgres::error::SqlState::CHECK_VIOLATION,
        "expected CHECK_VIOLATION, got: {db_err}"
    );
}

/// Assert that a Postgres error is a CHECK_VIOLATION on a specific
/// named constraint.
fn assert_constraint_violation(err: &postgres::Error, expected_constraint: &str) {
    assert_check_violation(err);
    let db_err = err.as_db_error().unwrap();
    let constraint = db_err.constraint().expect("expected constraint name");
    assert!(
        constraint.contains(expected_constraint),
        "expected constraint containing {expected_constraint:?}, got {constraint:?}"
    );
}

/// Insert a row into `done_ledger_entries` with raw SQL, using
/// caller-supplied overrides merged onto valid defaults.
///
/// Bypasses all Rust-side validation so that intentionally invalid data
/// reaches the database's `CHECK` constraints. Returns the number of
/// rows inserted (normally 1) or a Postgres error.
fn try_insert(
    client: &mut postgres::Client,
    overrides: RowOverrides,
) -> Result<u64, postgres::Error> {
    let defaults = RowOverrides::defaults();
    let tenant_id = overrides.tenant_id.unwrap_or(defaults.tenant_id.unwrap());
    let policy_hash = overrides
        .policy_hash
        .unwrap_or(defaults.policy_hash.unwrap());
    let ovid_hash = overrides.ovid_hash.unwrap_or(defaults.ovid_hash.unwrap());
    let status = overrides.status.unwrap_or(defaults.status.unwrap());
    let bytes_scanned = overrides
        .bytes_scanned
        .unwrap_or(defaults.bytes_scanned.unwrap());
    let findings_count = overrides
        .findings_count
        .unwrap_or(defaults.findings_count.unwrap());
    let fence_epoch = overrides
        .fence_epoch
        .unwrap_or(defaults.fence_epoch.unwrap());
    let started_at = overrides.started_at.unwrap_or(defaults.started_at.unwrap());
    let finished_at = overrides
        .finished_at
        .unwrap_or(defaults.finished_at.unwrap());
    let run_id = overrides.run_id.unwrap_or(defaults.run_id.unwrap());
    let shard_id = overrides.shard_id.unwrap_or(defaults.shard_id.unwrap());
    let error_code = overrides.error_code.or(defaults.error_code);

    client.execute(
        &format!(
            "INSERT INTO {} (tenant_id, policy_hash, ovid_hash, status, bytes_scanned, \
             findings_count, fence_epoch, started_at, finished_at, run_id, shard_id, error_code) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            crate::schema::DONE_LEDGER_ENTRIES_TABLE
        ),
        &[
            &tenant_id,
            &policy_hash,
            &ovid_hash,
            &status,
            &bytes_scanned,
            &findings_count,
            &fence_epoch,
            &started_at,
            &finished_at,
            &run_id,
            &shard_id,
            &error_code,
        ],
    )
}

/// Per-field overrides for [`try_insert`]. `None` fields fall back to
/// the valid baseline from [`defaults()`](Self::defaults).
///
/// Fields use raw SQL types (`i16`, `i64`, `Vec<u8>`) rather than domain
/// types so that tests can inject values that Rust constructors would reject.
#[derive(Default)]
struct RowOverrides {
    tenant_id: Option<Vec<u8>>,
    policy_hash: Option<Vec<u8>>,
    ovid_hash: Option<Vec<u8>>,
    status: Option<i16>,
    bytes_scanned: Option<i64>,
    findings_count: Option<i32>,
    fence_epoch: Option<i64>,
    started_at: Option<i64>,
    finished_at: Option<i64>,
    run_id: Option<i64>,
    shard_id: Option<i64>,
    error_code: Option<String>,
}

impl RowOverrides {
    /// Baseline row that satisfies all schema constraints: `ScannedClean`
    /// (status=10), zero findings, no error code, 32-byte identity columns,
    /// and `started_at ≤ finished_at`.
    fn defaults() -> Self {
        Self {
            tenant_id: Some(vec![0xAA; 32]),
            policy_hash: Some(vec![0xBB; 32]),
            ovid_hash: Some(vec![0xCC; 32]),
            status: Some(10),
            bytes_scanned: Some(1024),
            findings_count: Some(0),
            fence_epoch: Some(1),
            started_at: Some(100),
            finished_at: Some(200),
            run_id: Some(1),
            shard_id: Some(1),
            error_code: None,
        }
    }
}

/// Status value 99 is not in the allowed set {1, 2, 3, 10, 11}.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_invalid_status() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(99),
            ..Default::default()
        },
    )
    .expect_err("status=99 should violate CHECK constraint");
    assert_check_violation(&err);
}

/// `bytes_scanned` is stored as `BIGINT` but must be non-negative.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_negative_bytes_scanned() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            bytes_scanned: Some(-1),
            ..Default::default()
        },
    )
    .expect_err("bytes_scanned=-1 should violate CHECK constraint");
    assert_check_violation(&err);
}

/// The `status_shape` constraint enforces cross-field consistency:
/// - `ScannedClean` must have `findings_count = 0`.
/// - Error statuses (1, 2, 3) must have a non-`NULL` `error_code`.
///
/// These mirror the Rust-side `DoneLedgerRecord::validate()` rules at
/// the SQL level.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_enforces_status_shape_constraint() {
    let mut client = test_client();

    // ScannedClean (10) with findings_count > 0 should be rejected.
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(10),
            findings_count: Some(5),
            ..Default::default()
        },
    )
    .expect_err("ScannedClean with findings > 0 should violate shape constraint");
    assert_constraint_violation(&err, "status_shape");

    // Error status (1) with error_code IS NULL should be rejected.
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(1),
            error_code: None,
            ovid_hash: Some(vec![0xDD; 32]),
            ..Default::default()
        },
    )
    .expect_err("error status without error_code should violate shape constraint");
    assert_constraint_violation(&err, "status_shape");
}

/// Identity columns (`tenant_id`, `policy_hash`, `ovid_hash`) must be
/// exactly 32 bytes. A 31-byte `tenant_id` must trigger an
/// `octet_length` CHECK violation.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_invalid_bytea_length() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            tenant_id: Some(vec![0xAA; 31]), // 31 bytes instead of 32
            ..Default::default()
        },
    )
    .expect_err("31-byte tenant_id should violate octet_length CHECK");
    assert_check_violation(&err);
}

/// The temporal ordering invariant `finished_at >= started_at` is enforced
/// at the schema level. Inserting `finished_at < started_at` must fail.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_enforces_finished_at_ge_started_at() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            started_at: Some(200),
            finished_at: Some(100), // finished_at < started_at
            ..Default::default()
        },
    )
    .expect_err("finished_at < started_at should violate CHECK constraint");
    assert_check_violation(&err);
}
