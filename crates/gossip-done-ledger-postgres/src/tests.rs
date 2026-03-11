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

// ── Migration runner ────────────────────────────────────────────────────

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

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn batch_get_empty_input_returns_empty_vec() {
    let backend = DoneLedgerPg::from_client(test_client());
    let fetched = backend
        .batch_get(tenant(5), policy(6), &[])
        .expect("empty batch_get should succeed");
    assert!(fetched.is_empty());
}

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

// ── Schema constraint enforcement ───────────────────────────────────────

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

/// Helper: insert a row into `done_ledger_entries` with caller-controlled
/// field values, returning the Postgres error (if any).
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

/// Field overrides for [`try_insert`]. `None` means "use default".
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
    /// Valid ScannedClean row: status=10, findings=0, no error.
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
