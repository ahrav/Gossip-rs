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
use crate::{
    DoneLedgerPg, DoneLedgerPgError, DoneLedgerPgMigrationError, apply_all_migrations,
    apply_migrations,
};
use gossip_contracts::{
    persistence::{
        CommitHandle, DoneLedger, DoneLedgerStatus, RECOMMENDED_MAX_BATCH_SIZE,
        run_done_ledger_conformance,
    },
    test_util::{done_record, ovid, policy, tenant},
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

#[path = "tests/merge_parity_proptest.rs"]
mod merge_parity_proptest;

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

/// `batch_get` with more than `RECOMMENDED_MAX_BATCH_SIZE` ovid hashes
/// must be rejected before issuing any SQL.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_get_rejects_oversized_input() {
    let backend = DoneLedgerPg::from_client(test_client());
    let too_many: Vec<_> = (0..=RECOMMENDED_MAX_BATCH_SIZE)
        .map(|i| ovid((i % 256) as u8))
        .collect();
    let err = backend
        .batch_get(tenant(1), policy(1), &too_many)
        .expect_err("oversized batch_get should be rejected");
    assert!(
        matches!(err, DoneLedgerPgError::BatchTooLarge { .. }),
        "expected BatchTooLarge, got: {err}"
    );
}

/// `batch_upsert` with more than `RECOMMENDED_MAX_BATCH_SIZE` records
/// must be rejected before issuing any SQL.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_upsert_rejects_oversized_input() {
    let backend = DoneLedgerPg::from_client(test_client());
    let record = done_record(
        1,
        1,
        1,
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
    let too_many: Vec<_> = std::iter::repeat_n(record, RECOMMENDED_MAX_BATCH_SIZE + 1).collect();
    let err = backend
        .batch_upsert(&too_many)
        .expect_err("oversized batch_upsert should be rejected");
    assert!(
        matches!(err, DoneLedgerPgError::BatchTooLarge { .. }),
        "expected BatchTooLarge, got: {err}"
    );
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
    // findings_count takes GREATEST: max(3, 5) = 5.
    assert_eq!(merged.findings_count(), 5);
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

/// The SQL merge uses `GREATEST(EXCLUDED.findings_count, done_ledger_entries.findings_count, 1)`
/// for `ScannedWithFindings` status. This test verifies that a valid
/// cross-batch promotion from `FailedRetryable` to `ScannedWithFindings`
/// picks up the incoming record's provenance and findings via the GREATEST
/// merge. The floor clamp (trailing `1`) is not independently observable
/// here because `GREATEST(1, 0, 1)` equals `GREATEST(1, 0)`;
/// [`sql_greatest_floor_clamp_is_observable_at_sql_level`] exercises it
/// directly via raw SQL with a zero-count incoming row.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn cross_batch_upsert_scanned_with_findings_clamps_findings_floor() {
    let backend = DoneLedgerPg::from_client(test_client());
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    // First batch: FailedRetryable with findings_count=0.
    let failed = done_record(
        7,
        8,
        51,
        DoneLedgerStatus::FailedRetryable,
        100,
        0,
        10,
        11,
        12,
        50,
        100,
        Some("ERR"),
    );
    backend
        .batch_upsert(std::slice::from_ref(&failed))
        .expect("first upsert should succeed")
        .wait()
        .expect("first commit should succeed");

    // Second batch: ScannedWithFindings with findings_count=1.
    // Merge promotes status to ScannedWithFindings (rank 11 > rank 1).
    // SQL GREATEST(1, 0, 1) = 1, exercising the floor clamp.
    let scanned = done_record(
        7,
        8,
        51,
        DoneLedgerStatus::ScannedWithFindings,
        200,
        1,
        20,
        21,
        22,
        60,
        150,
        None,
    );
    backend
        .batch_upsert(std::slice::from_ref(&scanned))
        .expect("second upsert should succeed")
        .wait()
        .expect("second commit should succeed");

    let fetched = backend
        .batch_get(tenant(7), policy(8), &[ovid(51)])
        .expect("batch_get should succeed");
    let merged = fetched[0]
        .as_ref()
        .expect("row should exist after cross-batch upsert");

    assert_eq!(merged.status(), DoneLedgerStatus::ScannedWithFindings);
    // GREATEST(1, 0, 1) = 1 — the floor clamp is exercised because the
    // existing record contributed findings_count=0.
    assert_eq!(merged.findings_count(), 1);
    assert_eq!(merged.provenance(), scanned.provenance());
}

/// Verifies that an invalid `ScannedWithFindings` `EXCLUDED` row is rejected
/// before the SQL floor clamp can rescue it.
///
/// The reachable clamp coverage lives in
/// `cross_batch_upsert_scanned_with_findings_clamps_findings_floor`. This raw
/// SQL test instead documents the schema boundary: PostgreSQL enforces
/// `done_ledger_entries_status_shape_ck` on the incoming tuple before
/// `ON CONFLICT DO UPDATE` can evaluate `GREATEST(..., 1)`.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn sql_on_conflict_rejects_invalid_scanned_with_findings_excluded_row() {
    let mut client = test_client();

    // Seed a valid ScannedWithFindings row so the second write takes the
    // ON CONFLICT path.
    try_insert(
        &mut client,
        RowOverrides {
            status: Some(11),
            findings_count: Some(1),
            ovid_hash: Some(vec![0xE1; 32]),
            ..Default::default()
        },
    )
    .expect("seed insert should succeed");

    // The incoming row is invalid (`status=11` with `findings_count=0`), so
    // PostgreSQL rejects it before the ON CONFLICT update can clamp the value
    // with GREATEST(EXCLUDED.findings_count, existing.findings_count, 1).
    let err = client
        .execute(
            &format!(
                "INSERT INTO {t} (tenant_id, policy_hash, ovid_hash, status, bytes_scanned, \
                 findings_count, fence_epoch, started_at, finished_at, run_id, shard_id, error_code) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (tenant_id, policy_hash, ovid_hash) DO UPDATE SET \
                 status = GREATEST(EXCLUDED.status, {t}.status), \
                 findings_count = CASE \
                     WHEN GREATEST(EXCLUDED.status, {t}.status) = 10 THEN 0 \
                     WHEN GREATEST(EXCLUDED.status, {t}.status) = 11 THEN \
                         GREATEST(EXCLUDED.findings_count, {t}.findings_count, 1) \
                     ELSE GREATEST(EXCLUDED.findings_count, {t}.findings_count) \
                 END",
                t = crate::schema::DONE_LEDGER_ENTRIES_TABLE
            ),
            &[
                &vec![0xAAu8; 32] as &(dyn postgres::types::ToSql + Sync),
                &vec![0xBBu8; 32],
                &vec![0xE1u8; 32],
                &11i16,
                &1024i64,
                &0i32, // invalid for ScannedWithFindings
                &1i64,
                &100i64,
                &200i64, // later → would win provenance if the row were accepted
                &2i64,
                &2i64,
                &None::<String>,
            ],
        )
        .expect_err("invalid ScannedWithFindings EXCLUDED row should violate the shape constraint");
    assert_constraint_violation(&err, "status_shape");
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

    // ScannedWithFindings (11) with findings_count = 0 should be rejected.
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(11),
            findings_count: Some(0),
            ovid_hash: Some(vec![0xEE; 32]),
            ..Default::default()
        },
    )
    .expect_err("ScannedWithFindings with findings == 0 should violate shape constraint");
    assert_constraint_violation(&err, "status_shape");

    // ScannedWithFindings (11) with non-NULL error_code should be rejected.
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(11),
            findings_count: Some(3),
            error_code: Some("OOPS".to_string()),
            ovid_hash: Some(vec![0xEF; 32]),
            ..Default::default()
        },
    )
    .expect_err("ScannedWithFindings with error_code should violate shape constraint");
    assert_constraint_violation(&err, "status_shape");

    // ScannedClean (10) with non-NULL error_code should be rejected.
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(10),
            error_code: Some("OOPS".to_string()),
            ovid_hash: Some(vec![0xF0; 32]),
            ..Default::default()
        },
    )
    .expect_err("ScannedClean with error_code should violate shape constraint");
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

/// `findings_count` is stored as `INTEGER` and must be non-negative.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_negative_findings_count() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            findings_count: Some(-1),
            ..Default::default()
        },
    )
    .expect_err("findings_count=-1 should violate CHECK constraint");
    assert_check_violation(&err);
}

/// `fence_epoch` is stored as `BIGINT` and must be non-negative.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_negative_fence_epoch() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            fence_epoch: Some(-1),
            ..Default::default()
        },
    )
    .expect_err("fence_epoch=-1 should violate CHECK constraint");
    assert_check_violation(&err);
}

/// `started_at` is stored as `BIGINT` and must be non-negative.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_negative_started_at() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            started_at: Some(-1),
            finished_at: Some(0),
            ..Default::default()
        },
    )
    .expect_err("started_at=-1 should violate CHECK constraint");
    assert_check_violation(&err);
}

/// `error_code` has a max length of 128 bytes. A 129-byte string must be
/// rejected by the `octet_length(...) BETWEEN 1 AND 128` CHECK.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_oversized_error_code() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(1),
            error_code: Some("X".repeat(129)),
            ..Default::default()
        },
    )
    .expect_err("129-byte error_code should violate CHECK constraint");
    assert_check_violation(&err);
}

/// An empty `error_code` string violates the `octet_length(...) BETWEEN 1
/// AND 128` CHECK — the minimum length is 1, not 0.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn schema_rejects_empty_error_code() {
    let mut client = test_client();
    let err = try_insert(
        &mut client,
        RowOverrides {
            status: Some(1),
            error_code: Some(String::new()),
            ovid_hash: Some(vec![0xF1; 32]),
            ..Default::default()
        },
    )
    .expect_err("empty error_code should violate CHECK constraint");
    assert_check_violation(&err);
}

// ── ON CONFLICT error_code coverage ─────────────────────────────────────
//
// These tests use inline SQL rather than the production `UPSERT_SQL` for
// two reasons: (1) the production statement uses `unnest()` arrays, while
// these tests need single-row INSERT...VALUES to control exact inputs;
// (2) the first test intentionally sends invalid data to trigger a CHECK
// constraint — it must bypass all Rust-side validation and the production
// path. The proptest parity suite covers drift between production SQL and
// Rust merge logic; these tests isolate specific PostgreSQL behaviors
// (CHECK enforcement timing, COALESCE semantics).
//
// The SQL `ON CONFLICT` merge uses `COALESCE(winner, loser)` for
// `error_code`, but PostgreSQL enforces CHECK constraints on the incoming
// tuple before the update branch can reuse the existing row's value.
// That means a non-scanned `EXCLUDED` row with `error_code = NULL` is
// rejected before the fallback arm can run.

/// Verifies that `ON CONFLICT DO UPDATE` does not repair an invalid
/// non-scanned incoming row before `done_ledger_entries_status_shape_ck`
/// fires.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn sql_on_conflict_rejects_invalid_non_scanned_excluded_row() {
    let mut client = test_client();

    // Insert initial row: non-scanned status with error_code and finished_at=100.
    try_insert(
        &mut client,
        RowOverrides {
            status: Some(1), // FailedRetryable
            error_code: Some("ORIGINAL_ERR".to_string()),
            finished_at: Some(100),
            ..Default::default()
        },
    )
    .expect("initial insert should succeed");

    // Upsert with same key, same status, later finished_at (wins provenance),
    // but NULL error_code. PostgreSQL rejects the incoming row before the
    // conflict update can evaluate COALESCE against the existing row.
    let err = client
        .execute(
            &format!(
                "INSERT INTO {t} (tenant_id, policy_hash, ovid_hash, status, bytes_scanned, \
                 findings_count, fence_epoch, started_at, finished_at, run_id, shard_id, error_code) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (tenant_id, policy_hash, ovid_hash) DO UPDATE SET \
                 status = GREATEST(EXCLUDED.status, {t}.status), \
                 error_code = CASE \
                     WHEN GREATEST(EXCLUDED.status, {t}.status) IN (10, 11) THEN NULL \
                     WHEN ( \
                         EXCLUDED.status > {t}.status \
                         OR (EXCLUDED.status = {t}.status AND EXCLUDED.finished_at > {t}.finished_at) \
                         OR (EXCLUDED.status = {t}.status AND EXCLUDED.finished_at = {t}.finished_at \
                             AND EXCLUDED.started_at > {t}.started_at) \
                     ) THEN COALESCE(EXCLUDED.error_code, {t}.error_code) \
                     ELSE COALESCE({t}.error_code, EXCLUDED.error_code) \
                 END",
                t = crate::schema::DONE_LEDGER_ENTRIES_TABLE
            ),
            &[
                &vec![0xAAu8; 32] as &(dyn postgres::types::ToSql + Sync),
                &vec![0xBBu8; 32],
                &vec![0xCCu8; 32],
                &1i16,           // same status
                &1024i64,        // bytes_scanned
                &0i32,           // findings_count
                &1i64,           // fence_epoch
                &100i64,         // started_at
                &200i64,         // finished_at (later → wins provenance)
                &2i64,           // run_id
                &2i64,           // shard_id
                &None::<String>, // NULL error_code on the winner
            ],
        )
        .expect_err("invalid non-scanned EXCLUDED row should violate the shape constraint");
    assert_constraint_violation(&err, "status_shape");
}

/// Verifies the reverse path: when the existing (loser) has a non-NULL
/// `error_code` and the incoming winner also has one, the winner's code
/// is used directly (COALESCE short-circuits on its first non-NULL arg).
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn sql_coalesce_winner_error_code_takes_precedence() {
    let mut client = test_client();

    // Insert initial row with error_code "OLD_ERR" and finished_at=100.
    try_insert(
        &mut client,
        RowOverrides {
            status: Some(1),
            error_code: Some("OLD_ERR".to_string()),
            finished_at: Some(100),
            ovid_hash: Some(vec![0xDD; 32]),
            ..Default::default()
        },
    )
    .expect("initial insert should succeed");

    // Upsert: same status, later finished_at (wins), non-NULL error_code.
    // COALESCE(EXCLUDED.error_code, existing.error_code) returns EXCLUDED's
    // value because the first argument is non-NULL.
    client
        .execute(
            &format!(
                "INSERT INTO {t} (tenant_id, policy_hash, ovid_hash, status, bytes_scanned, \
                 findings_count, fence_epoch, started_at, finished_at, run_id, shard_id, error_code) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (tenant_id, policy_hash, ovid_hash) DO UPDATE SET \
                 status = GREATEST(EXCLUDED.status, {t}.status), \
                 error_code = CASE \
                     WHEN GREATEST(EXCLUDED.status, {t}.status) IN (10, 11) THEN NULL \
                     WHEN ( \
                         EXCLUDED.status > {t}.status \
                         OR (EXCLUDED.status = {t}.status AND EXCLUDED.finished_at > {t}.finished_at) \
                         OR (EXCLUDED.status = {t}.status AND EXCLUDED.finished_at = {t}.finished_at \
                             AND EXCLUDED.started_at > {t}.started_at) \
                     ) THEN COALESCE(EXCLUDED.error_code, {t}.error_code) \
                     ELSE COALESCE({t}.error_code, EXCLUDED.error_code) \
                 END",
                t = crate::schema::DONE_LEDGER_ENTRIES_TABLE
            ),
            &[
                &vec![0xAAu8; 32] as &(dyn postgres::types::ToSql + Sync),
                &vec![0xBBu8; 32],
                &vec![0xDDu8; 32],
                &1i16,
                &1024i64,
                &0i32,
                &1i64,
                &100i64,
                &200i64,
                &3i64,
                &3i64,
                &Some("NEW_ERR".to_string()),
            ],
        )
        .expect("winner-with-code upsert should succeed");

    let rows = client
        .query(
            &format!(
                "SELECT error_code FROM {} WHERE tenant_id = $1 AND policy_hash = $2 AND ovid_hash = $3",
                crate::schema::DONE_LEDGER_ENTRIES_TABLE
            ),
            &[
                &vec![0xAAu8; 32] as &(dyn postgres::types::ToSql + Sync),
                &vec![0xBBu8; 32],
                &vec![0xDDu8; 32],
            ],
        )
        .expect("query should succeed");

    assert_eq!(rows.len(), 1);
    let error_code: Option<String> = rows[0].get("error_code");
    assert_eq!(
        error_code.as_deref(),
        Some("NEW_ERR"),
        "winner's non-NULL error_code should be used directly"
    );
}
