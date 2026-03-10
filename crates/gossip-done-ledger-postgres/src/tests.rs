//! Integration tests for the PostgreSQL done-ledger schema and migration runner.
//!
//! All tests in this module require a running PostgreSQL instance (either via
//! Docker/testcontainers or an external `POSTGRES_TEST_URL`). They are marked
//! `#[ignore]` so that `cargo test` without Docker skips them cleanly.

use crate::test_postgres::{test_client, test_client_bare};
use crate::{DoneLedgerPgMigrationError, apply_all_migrations, apply_migrations};

// ── Migration runner ────────────────────────────────────────────────────

#[test]
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
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
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
fn checksum_mismatch_is_detected() {
    let mut client = test_client_bare();

    // Apply the real migrations first.
    apply_all_migrations(&mut client).expect("initial migration should succeed");

    // Now try to apply a migration with the same version but different SQL.
    let tampered = [crate::migrations::EmbeddedMigration::new(
        "0001_done_ledger_entries",
        "SELECT 1; -- tampered",
    )];

    let err = apply_migrations(&mut client, &tampered)
        .expect_err("tampered migration should produce ChecksumMismatch");

    match err {
        DoneLedgerPgMigrationError::ChecksumMismatch { version, .. } => {
            assert_eq!(version, "0001_done_ledger_entries");
        }
        DoneLedgerPgMigrationError::Postgres(e) => {
            panic!("expected ChecksumMismatch, got Postgres error: {e}");
        }
    }
}

#[test]
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
fn concurrent_migrations_both_succeed() {
    // Create a single bare database — both threads target the same DB.
    let url = crate::test_postgres::create_test_db();
    let url2 = url.clone();

    let t1 = std::thread::spawn(move || {
        let mut c =
            postgres::Client::connect(&url, postgres::NoTls).expect("thread 1 connect failed");
        apply_all_migrations(&mut c)
    });
    let t2 = std::thread::spawn(move || {
        let mut c =
            postgres::Client::connect(&url2, postgres::NoTls).expect("thread 2 connect failed");
        apply_all_migrations(&mut c)
    });

    t1.join()
        .expect("thread 1 panicked")
        .expect("thread 1 migration failed");
    t2.join()
        .expect("thread 2 panicked")
        .expect("thread 2 migration failed");
}

// ── Schema constraint enforcement ───────────────────────────────────────

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
    findings_count: Option<i64>,
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
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
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
    let msg = err.to_string();
    assert!(
        msg.contains("check") || msg.contains("CHECK") || msg.contains("violates"),
        "error should reference constraint violation: {msg}"
    );
}

#[test]
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
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
    let msg = err.to_string();
    assert!(
        msg.contains("check") || msg.contains("CHECK") || msg.contains("violates"),
        "error should reference constraint violation: {msg}"
    );
}

#[test]
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
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
    assert!(
        err.to_string().contains("status_shape"),
        "error should name status_shape constraint: {}",
        err
    );

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
    assert!(
        err.to_string().contains("status_shape"),
        "error should name status_shape constraint: {}",
        err
    );
}

#[test]
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
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
    let msg = err.to_string();
    assert!(
        msg.contains("check") || msg.contains("CHECK") || msg.contains("violates"),
        "error should reference constraint violation: {msg}"
    );
}

#[test]
#[ignore = "requires Docker or POSTGRES_TEST_URL"]
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
    let msg = err.to_string();
    assert!(
        msg.contains("check") || msg.contains("CHECK") || msg.contains("violates"),
        "error should reference constraint violation: {msg}"
    );
}
