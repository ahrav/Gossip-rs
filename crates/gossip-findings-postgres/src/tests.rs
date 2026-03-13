//! Live-PostgreSQL integration tests for the findings schema and migration
//! runner.
//!
//! These tests require either Docker (for testcontainers) or an external
//! PostgreSQL advertised through `GOSSIP_POSTGRES_TEST_URL`. They are marked
//! `#[ignore]` so routine `cargo test` runs skip them cleanly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use gossip_contracts::persistence::run_findings_conformance;
use postgres::Client;
use postgres::error::{DbError, SqlState};

use crate::schema;
use crate::test_postgres::{create_test_db, test_client, test_client_bare};
use crate::{
    EmbeddedMigration, FindingsPgMigrationError, FindingsSinkPg, MIGRATIONS, apply_all_migrations,
    apply_migrations,
};

/// Field overrides for a `findings` row. `None` means "use the valid default".
#[derive(Default)]
struct FindingOverrides {
    tenant_id: Option<Vec<u8>>,
    finding_id: Option<Vec<u8>>,
    stable_item_id: Option<Vec<u8>>,
    rule_fingerprint: Option<Vec<u8>>,
    secret_hash: Option<Vec<u8>>,
}

impl FindingOverrides {
    fn defaults() -> Self {
        Self {
            tenant_id: Some(bytes32(0x10)),
            finding_id: Some(bytes32(0x11)),
            stable_item_id: Some(bytes32(0x12)),
            rule_fingerprint: Some(bytes32(0x13)),
            secret_hash: Some(bytes32(0x14)),
        }
    }
}

/// Field overrides for an `occurrences` row. `None` means "use the valid default".
#[derive(Default)]
struct OccurrenceOverrides {
    tenant_id: Option<Vec<u8>>,
    occurrence_id: Option<Vec<u8>>,
    finding_id: Option<Vec<u8>>,
    object_version_id: Option<Vec<u8>>,
    byte_offset: Option<i64>,
    byte_length: Option<i64>,
}

impl OccurrenceOverrides {
    fn defaults() -> Self {
        Self {
            tenant_id: Some(bytes32(0x10)),
            occurrence_id: Some(bytes32(0x21)),
            finding_id: Some(bytes32(0x11)),
            object_version_id: Some(bytes32(0x22)),
            byte_offset: Some(128),
            byte_length: Some(64),
        }
    }
}

/// Field overrides for an `observations` row. `None` means "use the valid default".
#[derive(Default)]
struct ObservationOverrides {
    tenant_id: Option<Vec<u8>>,
    observation_id: Option<Vec<u8>>,
    occurrence_id: Option<Vec<u8>>,
    policy_hash: Option<Vec<u8>>,
    ovid_hash: Option<Vec<u8>>,
    run_id: Option<i64>,
    shard_id: Option<i64>,
    fence_epoch: Option<i64>,
    seen_at: Option<i64>,
    location_display: Option<Option<String>>,
    location_url: Option<Option<String>>,
}

impl ObservationOverrides {
    fn defaults() -> Self {
        Self {
            tenant_id: Some(bytes32(0x10)),
            observation_id: Some(bytes32(0x31)),
            occurrence_id: Some(bytes32(0x21)),
            policy_hash: Some(bytes32(0x32)),
            ovid_hash: Some(bytes32(0x33)),
            run_id: Some(4_096),
            shard_id: Some(8_192),
            fence_epoch: Some(16_384),
            seen_at: Some(32_768),
            location_display: Some(Some("src/findings/example.txt:42".to_owned())),
            location_url: Some(Some(
                "https://example.test/findings/example.txt#L42".to_owned(),
            )),
        }
    }
}

fn bytes32(fill: u8) -> Vec<u8> {
    vec![fill; 32]
}

fn resolve<T>(value: Option<T>, default: Option<T>, field: &str) -> T {
    value
        .or(default)
        .unwrap_or_else(|| panic!("default fixture for {field} must be present"))
}

fn expected_columns(entries: &[(&str, &str, bool)]) -> BTreeMap<String, (String, bool)> {
    entries
        .iter()
        .map(|(name, ty, nullable)| ((*name).to_owned(), ((*ty).to_owned(), *nullable)))
        .collect()
}

fn assert_has_expected_indexes(actual: &BTreeMap<String, String>, expected: &[(&str, &[&str])]) {
    for (name, columns) in expected {
        let def = actual
            .get(*name)
            .unwrap_or_else(|| panic!("expected index {name:?} to exist; actual: {actual:?}"));
        for col in *columns {
            assert!(
                def.contains(col),
                "index {name:?} should contain column {col:?}; actual definition: {def:?}"
            );
        }
    }
}

fn table_exists(client: &mut Client, table: &str) -> bool {
    client
        .query_opt(
            "SELECT 1
             FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = $1",
            &[&table],
        )
        .expect("table existence query should succeed")
        .is_some()
}

fn table_columns(client: &mut Client, table: &str) -> BTreeMap<String, (String, bool)> {
    client
        .query(
            "SELECT column_name, data_type, is_nullable
             FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = $1
             ORDER BY ordinal_position",
            &[&table],
        )
        .expect("column introspection query should succeed")
        .into_iter()
        .map(|row| {
            let name: String = row.get(0);
            let data_type: String = row.get(1);
            let nullable: String = row.get(2);
            (name, (data_type, nullable == "YES"))
        })
        .collect()
}

fn table_indexes(client: &mut Client, table: &str) -> BTreeMap<String, String> {
    client
        .query(
            "SELECT indexname, indexdef
             FROM pg_indexes
             WHERE schemaname = 'public' AND tablename = $1",
            &[&table],
        )
        .expect("index introspection query should succeed")
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .collect()
}

fn stored_migration_versions(client: &mut Client) -> BTreeSet<String> {
    client
        .query(
            &format!(
                "SELECT version FROM {} ORDER BY version",
                schema::SCHEMA_MIGRATIONS_TABLE
            ),
            &[],
        )
        .expect("migration version query should succeed")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect()
}

mod merge_parity_proptest;

fn table_foreign_keys(client: &mut Client, table: &str) -> BTreeMap<String, String> {
    client
        .query(
            "SELECT c.conname, pg_get_constraintdef(c.oid)
             FROM pg_constraint AS c
             JOIN pg_class AS rel ON rel.oid = c.conrelid
             JOIN pg_namespace AS nsp ON nsp.oid = rel.relnamespace
             WHERE nsp.nspname = 'public' AND rel.relname = $1 AND c.contype = 'f'
             ORDER BY c.conname",
            &[&table],
        )
        .expect("foreign-key introspection query should succeed")
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .collect()
}

fn findings_tables(client: &mut Client) -> BTreeSet<String> {
    client
        .query(
            "SELECT table_name
             FROM information_schema.tables
             WHERE table_schema = 'public'
             ORDER BY table_name",
            &[],
        )
        .expect("table enumeration query should succeed")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .filter(|table| {
            matches!(
                table.as_str(),
                schema::FINDINGS_TABLE
                    | schema::OCCURRENCES_TABLE
                    | schema::OBSERVATIONS_TABLE
                    | schema::SCHEMA_MIGRATIONS_TABLE
            )
        })
        .collect()
}

fn row_count(client: &mut Client, table: &str) -> i64 {
    client
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .expect("row count query should succeed")
        .get(0)
}

fn assert_sqlstate<'a>(err: &'a postgres::Error, expected: &'static SqlState) -> &'a DbError {
    let db_err = err.as_db_error().expect("expected server-side DbError");
    assert_eq!(
        *db_err.code(),
        *expected,
        "expected SQLSTATE {:?}, got: {db_err}",
        expected
    );
    db_err
}

fn assert_check_violation(err: &postgres::Error) {
    let _ = assert_sqlstate(err, &SqlState::CHECK_VIOLATION);
}

fn assert_unique_violation(err: &postgres::Error) {
    let _ = assert_sqlstate(err, &SqlState::UNIQUE_VIOLATION);
}

fn assert_fk_violation(err: &postgres::Error) {
    let _ = assert_sqlstate(err, &SqlState::FOREIGN_KEY_VIOLATION);
}

fn assert_constraint_name(err: &postgres::Error, expected: &str) {
    let db_err = err.as_db_error().expect("expected server-side DbError");
    assert_eq!(
        db_err.constraint(),
        Some(expected),
        "expected constraint {expected:?}, got {:?}",
        db_err.constraint()
    );
}

fn try_insert_finding(
    client: &mut Client,
    overrides: FindingOverrides,
) -> Result<u64, postgres::Error> {
    let defaults = FindingOverrides::defaults();
    let tenant_id = resolve(overrides.tenant_id, defaults.tenant_id, "tenant_id");
    let finding_id = resolve(overrides.finding_id, defaults.finding_id, "finding_id");
    let stable_item_id = resolve(
        overrides.stable_item_id,
        defaults.stable_item_id,
        "stable_item_id",
    );
    let rule_fingerprint = resolve(
        overrides.rule_fingerprint,
        defaults.rule_fingerprint,
        "rule_fingerprint",
    );
    let secret_hash = resolve(overrides.secret_hash, defaults.secret_hash, "secret_hash");

    client.execute(
        &format!(
            "INSERT INTO {} (
                tenant_id,
                finding_id,
                stable_item_id,
                rule_fingerprint,
                secret_hash
            ) VALUES ($1, $2, $3, $4, $5)",
            schema::FINDINGS_TABLE
        ),
        &[
            &tenant_id,
            &finding_id,
            &stable_item_id,
            &rule_fingerprint,
            &secret_hash,
        ],
    )
}

fn try_insert_occurrence(
    client: &mut Client,
    overrides: OccurrenceOverrides,
) -> Result<u64, postgres::Error> {
    let defaults = OccurrenceOverrides::defaults();
    let tenant_id = resolve(overrides.tenant_id, defaults.tenant_id, "tenant_id");
    let occurrence_id = resolve(
        overrides.occurrence_id,
        defaults.occurrence_id,
        "occurrence_id",
    );
    let finding_id = resolve(overrides.finding_id, defaults.finding_id, "finding_id");
    let object_version_id = resolve(
        overrides.object_version_id,
        defaults.object_version_id,
        "object_version_id",
    );
    let byte_offset = resolve(overrides.byte_offset, defaults.byte_offset, "byte_offset");
    let byte_length = resolve(overrides.byte_length, defaults.byte_length, "byte_length");

    client.execute(
        &format!(
            "INSERT INTO {} (
                tenant_id,
                occurrence_id,
                finding_id,
                object_version_id,
                byte_offset,
                byte_length
            ) VALUES ($1, $2, $3, $4, $5, $6)",
            schema::OCCURRENCES_TABLE
        ),
        &[
            &tenant_id,
            &occurrence_id,
            &finding_id,
            &object_version_id,
            &byte_offset,
            &byte_length,
        ],
    )
}

fn try_insert_observation(
    client: &mut Client,
    overrides: ObservationOverrides,
) -> Result<u64, postgres::Error> {
    let defaults = ObservationOverrides::defaults();
    let tenant_id = resolve(overrides.tenant_id, defaults.tenant_id, "tenant_id");
    let observation_id = resolve(
        overrides.observation_id,
        defaults.observation_id,
        "observation_id",
    );
    let occurrence_id = resolve(
        overrides.occurrence_id,
        defaults.occurrence_id,
        "occurrence_id",
    );
    let policy_hash = resolve(overrides.policy_hash, defaults.policy_hash, "policy_hash");
    let ovid_hash = resolve(overrides.ovid_hash, defaults.ovid_hash, "ovid_hash");
    let run_id = resolve(overrides.run_id, defaults.run_id, "run_id");
    let shard_id = resolve(overrides.shard_id, defaults.shard_id, "shard_id");
    let fence_epoch = resolve(overrides.fence_epoch, defaults.fence_epoch, "fence_epoch");
    let seen_at = resolve(overrides.seen_at, defaults.seen_at, "seen_at");
    let location_display = resolve(
        overrides.location_display,
        defaults.location_display,
        "location_display",
    );
    let location_url = resolve(
        overrides.location_url,
        defaults.location_url,
        "location_url",
    );

    client.execute(
        &format!(
            "INSERT INTO {} (
                tenant_id,
                observation_id,
                occurrence_id,
                policy_hash,
                ovid_hash,
                run_id,
                shard_id,
                fence_epoch,
                seen_at,
                location_display,
                location_url
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            schema::OBSERVATIONS_TABLE
        ),
        &[
            &tenant_id,
            &observation_id,
            &occurrence_id,
            &policy_hash,
            &ovid_hash,
            &run_id,
            &shard_id,
            &fence_epoch,
            &seen_at,
            &location_display,
            &location_url,
        ],
    )
}

fn insert_valid_finding(client: &mut Client) {
    try_insert_finding(client, FindingOverrides::default())
        .expect("default findings row should insert cleanly");
}

fn insert_valid_occurrence(client: &mut Client) {
    insert_valid_finding(client);
    try_insert_occurrence(client, OccurrenceOverrides::default())
        .expect("default occurrences row should insert cleanly");
}

// ── Migration runner ──────────────────────────────────────────────────────

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migration_creates_findings_table() {
    let mut client = test_client();

    assert!(table_exists(&mut client, schema::FINDINGS_TABLE));
    assert_eq!(
        table_columns(&mut client, schema::FINDINGS_TABLE),
        expected_columns(&[
            ("tenant_id", "bytea", false),
            ("finding_id", "bytea", false),
            ("stable_item_id", "bytea", false),
            ("rule_fingerprint", "bytea", false),
            ("secret_hash", "bytea", false),
        ])
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migration_creates_occurrences_table() {
    let mut client = test_client();

    assert!(table_exists(&mut client, schema::OCCURRENCES_TABLE));
    assert_eq!(
        table_columns(&mut client, schema::OCCURRENCES_TABLE),
        expected_columns(&[
            ("tenant_id", "bytea", false),
            ("occurrence_id", "bytea", false),
            ("finding_id", "bytea", false),
            ("object_version_id", "bytea", false),
            ("byte_offset", "bigint", false),
            ("byte_length", "bigint", false),
        ])
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migration_creates_observations_table() {
    let mut client = test_client();

    assert!(table_exists(&mut client, schema::OBSERVATIONS_TABLE));
    assert_eq!(
        table_columns(&mut client, schema::OBSERVATIONS_TABLE),
        expected_columns(&[
            ("tenant_id", "bytea", false),
            ("observation_id", "bytea", false),
            ("occurrence_id", "bytea", false),
            ("policy_hash", "bytea", false),
            ("ovid_hash", "bytea", false),
            ("run_id", "bigint", false),
            ("shard_id", "bigint", false),
            ("fence_epoch", "bigint", false),
            ("seen_at", "bigint", false),
            ("location_display", "text", true),
            ("location_url", "text", true),
        ])
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migration_is_idempotent() {
    let mut client = test_client_bare();

    apply_all_migrations(&mut client).expect("initial migration run should succeed");
    apply_all_migrations(&mut client).expect("second migration run should be idempotent");

    let expected_versions: BTreeSet<String> =
        MIGRATIONS.iter().map(|m| m.version().to_owned()).collect();
    assert_eq!(
        stored_migration_versions(&mut client),
        expected_versions,
        "stored migration versions must match embedded migration set exactly"
    );
    assert_eq!(
        row_count(&mut client, schema::SCHEMA_MIGRATIONS_TABLE),
        MIGRATIONS.len() as i64,
        "history table must have exactly one row per migration (no duplicates)"
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migration_detects_checksum_mismatch() {
    let mut client = test_client_bare();
    apply_all_migrations(&mut client).expect("initial migration run should succeed");

    let tampered = [EmbeddedMigration::new(
        "0001_findings_schema",
        "SELECT 1; -- tampered",
    )];
    let err = apply_migrations(&mut client, &tampered, Duration::from_secs(5))
        .expect_err("checksum mismatch should fail re-application");

    let FindingsPgMigrationError::ChecksumMismatch { version, .. } = err else {
        panic!("expected ChecksumMismatch, got: {err:?}");
    };
    assert_eq!(version, "0001_findings_schema");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn persisted_checksum_tamper_is_detected_on_reapply() {
    let mut client = test_client_bare();
    apply_all_migrations(&mut client).expect("initial migration run should succeed");

    let updated = client
        .execute(
            &format!(
                "UPDATE {} SET checksum = decode(repeat('00', {}), 'hex') WHERE version = $1",
                schema::SCHEMA_MIGRATIONS_TABLE,
                blake3::OUT_LEN,
            ),
            &[&"0001_findings_schema"],
        )
        .expect("checksum tamper update should succeed");
    assert_eq!(updated, 1, "expected to tamper exactly one history row");

    let err = apply_all_migrations(&mut client)
        .expect_err("tampered checksum should fail re-application");
    let FindingsPgMigrationError::ChecksumMismatch { version, .. } = err else {
        panic!("expected ChecksumMismatch, got: {err:?}");
    };
    assert_eq!(version, "0001_findings_schema");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn concurrent_migrations_both_succeed() {
    let url = create_test_db();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let barrier_a = Arc::clone(&barrier);
    let barrier_b = Arc::clone(&barrier);
    let url_verify = url.clone();

    // Connect both clients on the main thread so a connection failure
    // panics immediately rather than stranding the peer at the barrier.
    let client_a = postgres::Client::connect(&url, postgres::NoTls)
        .expect("first worker should connect to shared test database");
    let client_b = postgres::Client::connect(&url, postgres::NoTls)
        .expect("second worker should connect to shared test database");

    let worker = |mut client: postgres::Client, barrier: Arc<std::sync::Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            apply_all_migrations(&mut client)
        })
    };

    let thread_a = worker(client_a, barrier_a);
    let thread_b = worker(client_b, barrier_b);

    thread_a
        .join()
        .expect("first migration thread should not panic")
        .expect("first migration thread should succeed");
    thread_b
        .join()
        .expect("second migration thread should not panic")
        .expect("second migration thread should succeed");

    // Verify the database state: exactly one history row per migration, no
    // duplicates and no missing entries.
    let mut client = postgres::Client::connect(&url_verify, postgres::NoTls)
        .expect("post-verification connection should succeed");
    let expected_versions: BTreeSet<String> =
        MIGRATIONS.iter().map(|m| m.version().to_owned()).collect();
    assert_eq!(
        stored_migration_versions(&mut client),
        expected_versions,
        "each migration must appear exactly once regardless of concurrent application"
    );
    assert_eq!(
        row_count(&mut client, schema::SCHEMA_MIGRATIONS_TABLE),
        MIGRATIONS.len() as i64,
        "history table must have exactly one row per migration (no duplicates)"
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn bare_db_has_no_findings_tables() {
    let mut client = test_client_bare();
    assert!(findings_tables(&mut client).is_empty());
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migration_creates_history_table() {
    let mut client = test_client();

    assert!(table_exists(&mut client, schema::SCHEMA_MIGRATIONS_TABLE));
    assert_eq!(
        table_columns(&mut client, schema::SCHEMA_MIGRATIONS_TABLE),
        expected_columns(&[
            ("version", "text", false),
            ("checksum", "bytea", false),
            ("applied_at", "timestamp with time zone", false),
        ])
    );
}

// ── Schema verification ───────────────────────────────────────────────────

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_table_has_expected_indexes() {
    let mut client = test_client();
    let indexes = table_indexes(&mut client, schema::FINDINGS_TABLE);

    assert_has_expected_indexes(
        &indexes,
        &[
            (
                schema::FINDINGS_TENANT_SECRET_HASH_INDEX,
                &["tenant_id", "secret_hash", "finding_id"],
            ),
            (
                schema::FINDINGS_TENANT_STABLE_ITEM_ID_INDEX,
                &["tenant_id", "stable_item_id", "finding_id"],
            ),
        ],
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_table_has_expected_indexes() {
    let mut client = test_client();
    let indexes = table_indexes(&mut client, schema::OCCURRENCES_TABLE);

    assert_has_expected_indexes(
        &indexes,
        &[
            (
                schema::OCCURRENCES_TENANT_FINDING_ID_INDEX,
                &["tenant_id", "finding_id", "occurrence_id"],
            ),
            (
                schema::OCCURRENCES_TENANT_OBJECT_VERSION_ID_INDEX,
                &["tenant_id", "object_version_id", "occurrence_id"],
            ),
        ],
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_table_has_expected_indexes() {
    let mut client = test_client();
    let indexes = table_indexes(&mut client, schema::OBSERVATIONS_TABLE);
    assert_has_expected_indexes(
        &indexes,
        &[
            (
                schema::OBSERVATIONS_TENANT_SEEN_AT_INDEX,
                &["tenant_id", "seen_at", "observation_id"],
            ),
            (
                schema::OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX,
                &["tenant_id", "policy_hash", "seen_at", "observation_id"],
            ),
            (
                schema::OBSERVATIONS_TENANT_OCCURRENCE_ID_INDEX,
                &["tenant_id", "occurrence_id", "observation_id"],
            ),
            (
                schema::OBSERVATIONS_TENANT_OVID_HASH_INDEX,
                &["tenant_id", "ovid_hash", "observation_id"],
            ),
            (
                schema::OBSERVATIONS_TENANT_RUN_SHARD_INDEX,
                &["tenant_id", "run_id", "shard_id", "observation_id"],
            ),
        ],
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_has_no_policy_hash_column() {
    let mut client = test_client();
    let columns = table_columns(&mut client, schema::OCCURRENCES_TABLE);
    assert!(!columns.contains_key("policy_hash"));
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_has_policy_hash_column() {
    let mut client = test_client();
    let columns = table_columns(&mut client, schema::OBSERVATIONS_TABLE);
    assert!(columns.contains_key("policy_hash"));
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn foreign_key_cascade_from_findings() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    try_insert_occurrence(&mut client, OccurrenceOverrides::default())
        .expect("default occurrence should insert once parent finding exists");

    assert_eq!(row_count(&mut client, schema::OCCURRENCES_TABLE), 1);
    client
        .execute(&format!("DELETE FROM {}", schema::FINDINGS_TABLE), &[])
        .expect("deleting parent findings should succeed");
    assert_eq!(
        row_count(&mut client, schema::FINDINGS_TABLE),
        0,
        "parent findings table should be empty after explicit delete"
    );
    assert_eq!(
        row_count(&mut client, schema::OCCURRENCES_TABLE),
        0,
        "child occurrences should cascade-delete with parent finding"
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn foreign_key_cascade_from_occurrences() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    try_insert_observation(&mut client, ObservationOverrides::default())
        .expect("default observation should insert once parent occurrence exists");

    assert_eq!(row_count(&mut client, schema::OBSERVATIONS_TABLE), 1);
    client
        .execute(&format!("DELETE FROM {}", schema::OCCURRENCES_TABLE), &[])
        .expect("deleting parent occurrences should succeed");
    assert_eq!(
        row_count(&mut client, schema::OBSERVATIONS_TABLE),
        0,
        "child observations should cascade-delete with parent occurrence"
    );
    assert_eq!(
        row_count(&mut client, schema::FINDINGS_TABLE),
        1,
        "grandparent findings row must survive child occurrence deletion"
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn migration_creates_foreign_keys() {
    let mut client = test_client();

    let occurrence_fks = table_foreign_keys(&mut client, schema::OCCURRENCES_TABLE);
    let observation_fks = table_foreign_keys(&mut client, schema::OBSERVATIONS_TABLE);

    let occurrence_fk = occurrence_fks
        .get("occurrences_finding_fk")
        .expect("occurrences -> findings FK should exist");
    assert!(
        occurrence_fk.contains("FOREIGN KEY (tenant_id, finding_id) REFERENCES findings(tenant_id, finding_id) ON DELETE CASCADE")
    );

    let observation_fk = observation_fks
        .get("observations_occurrence_fk")
        .expect("observations -> occurrences FK should exist");
    assert!(
        observation_fk.contains("FOREIGN KEY (tenant_id, occurrence_id) REFERENCES occurrences(tenant_id, occurrence_id) ON DELETE CASCADE")
    );

    let occurrence_err = try_insert_occurrence(&mut client, OccurrenceOverrides::default())
        .expect_err("occurrence insert without parent finding should fail");
    assert_fk_violation(&occurrence_err);
    assert_constraint_name(&occurrence_err, "occurrences_finding_fk");

    let observation_err = try_insert_observation(&mut client, ObservationOverrides::default())
        .expect_err("observation insert without parent occurrence should fail");
    assert_fk_violation(&observation_err);
    assert_constraint_name(&observation_err, "observations_occurrence_fk");
}

// ── Constraint enforcement ────────────────────────────────────────────────

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_rejects_short_bytea() {
    let mut client = test_client();
    let err = try_insert_finding(
        &mut client,
        FindingOverrides {
            tenant_id: Some(vec![0x10; 31]),
            ..Default::default()
        },
    )
    .expect_err("31-byte tenant_id should violate findings length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "findings_tenant_id_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_rejects_long_bytea() {
    let mut client = test_client();
    let err = try_insert_finding(
        &mut client,
        FindingOverrides {
            tenant_id: Some(vec![0x10; 33]),
            ..Default::default()
        },
    )
    .expect_err("33-byte tenant_id should violate findings length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "findings_tenant_id_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_rejects_short_bytea() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            occurrence_id: Some(vec![0x21; 31]),
            ..Default::default()
        },
    )
    .expect_err("31-byte occurrence_id should violate occurrences length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "occurrences_occurrence_id_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_rejects_long_bytea() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            occurrence_id: Some(vec![0x21; 33]),
            ..Default::default()
        },
    )
    .expect_err("33-byte occurrence_id should violate occurrences length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "occurrences_occurrence_id_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_short_bytea() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            policy_hash: Some(vec![0x32; 31]),
            ..Default::default()
        },
    )
    .expect_err("31-byte policy_hash should violate observations length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_policy_hash_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_long_bytea() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            policy_hash: Some(vec![0x32; 33]),
            ..Default::default()
        },
    )
    .expect_err("33-byte policy_hash should violate observations length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_policy_hash_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_rejects_negative_byte_offset() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            byte_offset: Some(-1),
            ..Default::default()
        },
    )
    .expect_err("negative byte_offset should violate occurrences checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "occurrences_byte_offset_nonnegative_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_rejects_zero_byte_length() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            byte_length: Some(0),
            ..Default::default()
        },
    )
    .expect_err("zero byte_length should violate occurrences checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "occurrences_byte_length_positive_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_span_overflow_rejected_by_sql() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            byte_offset: Some(i64::MAX - 1),
            byte_length: Some(2),
            ..Default::default()
        },
    )
    .expect_err("byte_offset + byte_length > i64::MAX should violate span overflow check");

    assert_check_violation(&err);
    assert_constraint_name(&err, "occurrences_span_no_overflow_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_negative_fence_epoch() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            fence_epoch: Some(-1),
            ..Default::default()
        },
    )
    .expect_err("negative fence_epoch should violate observations checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_fence_epoch_nonnegative_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_negative_seen_at() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            seen_at: Some(-1),
            ..Default::default()
        },
    )
    .expect_err("negative seen_at should violate observations checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_seen_at_nonnegative_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_accepts_negative_run_id() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let tenant_id = ObservationOverrides::defaults()
        .tenant_id
        .expect("defaults must provide tenant_id");
    let observation_id = bytes32(0x41);

    let inserted = try_insert_observation(
        &mut client,
        ObservationOverrides {
            observation_id: Some(observation_id.clone()),
            run_id: Some(i64::MIN),
            ..Default::default()
        },
    )
    .expect("negative run_id must remain valid for bit-pattern storage");
    assert_eq!(inserted, 1);

    let stored: i64 = client
        .query_one(
            &format!(
                "SELECT run_id FROM {} WHERE tenant_id = $1 AND observation_id = $2",
                schema::OBSERVATIONS_TABLE
            ),
            &[&tenant_id, &observation_id],
        )
        .expect("stored observation should be queryable")
        .get(0);
    assert_eq!(stored, i64::MIN);
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_accepts_negative_shard_id() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let tenant_id = ObservationOverrides::defaults()
        .tenant_id
        .expect("defaults must provide tenant_id");
    let observation_id = bytes32(0x42);

    let inserted = try_insert_observation(
        &mut client,
        ObservationOverrides {
            observation_id: Some(observation_id.clone()),
            shard_id: Some(i64::MIN + 1),
            ..Default::default()
        },
    )
    .expect("negative shard_id must remain valid for bit-pattern storage");
    assert_eq!(inserted, 1);

    let stored: i64 = client
        .query_one(
            &format!(
                "SELECT shard_id FROM {} WHERE tenant_id = $1 AND observation_id = $2",
                schema::OBSERVATIONS_TABLE
            ),
            &[&tenant_id, &observation_id],
        )
        .expect("stored observation should be queryable")
        .get(0);
    assert_eq!(stored, i64::MIN + 1);
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_location_display_size_limit() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            location_display: Some(Some("x".repeat(4_097))),
            ..Default::default()
        },
    )
    .expect_err("4097-byte location_display should violate observations checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_location_display_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_location_url_size_limit() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            location_url: Some(Some("x".repeat(4_097))),
            ..Default::default()
        },
    )
    .expect_err("4097-byte location_url should violate observations checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_location_url_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_empty_location_display() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            location_display: Some(Some(String::new())),
            ..Default::default()
        },
    )
    .expect_err("empty location_display should violate observations checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_location_display_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_empty_location_url() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            location_url: Some(Some(String::new())),
            ..Default::default()
        },
    )
    .expect_err("empty location_url should violate observations checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_location_url_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_location_url_accepts_null() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let tenant_id = ObservationOverrides::defaults()
        .tenant_id
        .expect("defaults must provide tenant_id");
    let observation_id = bytes32(0x43);

    let inserted = try_insert_observation(
        &mut client,
        ObservationOverrides {
            observation_id: Some(observation_id.clone()),
            location_display: Some(None),
            location_url: Some(None),
            ..Default::default()
        },
    )
    .expect("NULL location fields should remain valid");
    assert_eq!(inserted, 1);

    let row = client
        .query_one(
            &format!(
                "SELECT location_display, location_url
                 FROM {}
                 WHERE tenant_id = $1 AND observation_id = $2",
                schema::OBSERVATIONS_TABLE
            ),
            &[&tenant_id, &observation_id],
        )
        .expect("stored observation should be queryable");
    let stored_display: Option<String> = row.get(0);
    let stored_url: Option<String> = row.get(1);
    assert!(stored_display.is_none());
    assert!(stored_url.is_none());
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_natural_unique_prevents_duplicates() {
    let mut client = test_client();
    try_insert_finding(&mut client, FindingOverrides::default())
        .expect("first findings row should insert cleanly");

    let err = try_insert_finding(
        &mut client,
        FindingOverrides {
            finding_id: Some(bytes32(0x15)),
            ..Default::default()
        },
    )
    .expect_err("duplicate findings natural key should fail");

    assert_unique_violation(&err);
    assert_constraint_name(&err, "findings_natural_unique");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_natural_unique_prevents_duplicates() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    try_insert_occurrence(&mut client, OccurrenceOverrides::default())
        .expect("first occurrences row should insert cleanly");

    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            occurrence_id: Some(bytes32(0x23)),
            ..Default::default()
        },
    )
    .expect_err("duplicate occurrences natural key should fail");

    assert_unique_violation(&err);
    assert_constraint_name(&err, "occurrences_natural_unique");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_natural_unique_prevents_duplicates() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    try_insert_observation(&mut client, ObservationOverrides::default())
        .expect("first observations row should insert cleanly");

    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            observation_id: Some(bytes32(0x34)),
            ..Default::default()
        },
    )
    .expect_err("duplicate observations natural key should fail");

    assert_unique_violation(&err);
    assert_constraint_name(&err, "observations_natural_unique");
}

// ── Additional bytea length constraint tests ──────────────────────────────

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_rejects_short_secret_hash() {
    let mut client = test_client();
    let err = try_insert_finding(
        &mut client,
        FindingOverrides {
            secret_hash: Some(vec![0x14; 31]),
            ..Default::default()
        },
    )
    .expect_err("31-byte secret_hash should violate findings length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "findings_secret_hash_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_rejects_long_secret_hash() {
    let mut client = test_client();
    let err = try_insert_finding(
        &mut client,
        FindingOverrides {
            secret_hash: Some(vec![0x14; 33]),
            ..Default::default()
        },
    )
    .expect_err("33-byte secret_hash should violate findings length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "findings_secret_hash_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_rejects_short_finding_id() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            finding_id: Some(vec![0x11; 31]),
            ..Default::default()
        },
    )
    .expect_err("31-byte finding_id should violate occurrences length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "occurrences_finding_id_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_rejects_long_finding_id() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    let err = try_insert_occurrence(
        &mut client,
        OccurrenceOverrides {
            finding_id: Some(vec![0x11; 33]),
            ..Default::default()
        },
    )
    .expect_err("33-byte finding_id should violate occurrences length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "occurrences_finding_id_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_short_ovid_hash() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            ovid_hash: Some(vec![0x33; 31]),
            ..Default::default()
        },
    )
    .expect_err("31-byte ovid_hash should violate observations length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_ovid_hash_len_ck");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_rejects_long_ovid_hash() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    let err = try_insert_observation(
        &mut client,
        ObservationOverrides {
            ovid_hash: Some(vec![0x33; 33]),
            ..Default::default()
        },
    )
    .expect_err("33-byte ovid_hash should violate observations length checks");

    assert_check_violation(&err);
    assert_constraint_name(&err, "observations_ovid_hash_len_ck");
}

// ── Round-trip read-back tests ────────────────────────────────────────────

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_round_trip_all_columns() {
    let mut client = test_client();
    try_insert_finding(&mut client, FindingOverrides::default())
        .expect("default finding should insert cleanly");

    let defaults = FindingOverrides::defaults();
    let tenant_id = defaults.tenant_id.unwrap();
    let finding_id = defaults.finding_id.unwrap();

    let row = client
        .query_one(
            &format!(
                "SELECT tenant_id, finding_id, stable_item_id, rule_fingerprint, secret_hash
                 FROM {} WHERE tenant_id = $1 AND finding_id = $2",
                schema::FINDINGS_TABLE
            ),
            &[&tenant_id, &finding_id],
        )
        .expect("inserted finding should be readable");

    assert_eq!(row.get::<_, Vec<u8>>(0), tenant_id);
    assert_eq!(row.get::<_, Vec<u8>>(1), finding_id);
    assert_eq!(row.get::<_, Vec<u8>>(2), defaults.stable_item_id.unwrap());
    assert_eq!(row.get::<_, Vec<u8>>(3), defaults.rule_fingerprint.unwrap());
    assert_eq!(row.get::<_, Vec<u8>>(4), defaults.secret_hash.unwrap());
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn occurrences_round_trip_all_columns() {
    let mut client = test_client();
    insert_valid_finding(&mut client);
    try_insert_occurrence(&mut client, OccurrenceOverrides::default())
        .expect("default occurrence should insert cleanly");

    let defaults = OccurrenceOverrides::defaults();
    let tenant_id = defaults.tenant_id.unwrap();
    let occurrence_id = defaults.occurrence_id.unwrap();

    let row = client
        .query_one(
            &format!(
                "SELECT tenant_id, occurrence_id, finding_id, object_version_id,
                        byte_offset, byte_length
                 FROM {} WHERE tenant_id = $1 AND occurrence_id = $2",
                schema::OCCURRENCES_TABLE
            ),
            &[&tenant_id, &occurrence_id],
        )
        .expect("inserted occurrence should be readable");

    assert_eq!(row.get::<_, Vec<u8>>(0), tenant_id);
    assert_eq!(row.get::<_, Vec<u8>>(1), occurrence_id);
    assert_eq!(row.get::<_, Vec<u8>>(2), defaults.finding_id.unwrap());
    assert_eq!(
        row.get::<_, Vec<u8>>(3),
        defaults.object_version_id.unwrap()
    );
    assert_eq!(row.get::<_, i64>(4), defaults.byte_offset.unwrap());
    assert_eq!(row.get::<_, i64>(5), defaults.byte_length.unwrap());
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn observations_round_trip_all_columns() {
    let mut client = test_client();
    insert_valid_occurrence(&mut client);
    try_insert_observation(&mut client, ObservationOverrides::default())
        .expect("default observation should insert cleanly");

    let defaults = ObservationOverrides::defaults();
    let tenant_id = defaults.tenant_id.unwrap();
    let observation_id = defaults.observation_id.unwrap();

    let row = client
        .query_one(
            &format!(
                "SELECT tenant_id, observation_id, occurrence_id, policy_hash, ovid_hash,
                        run_id, shard_id, fence_epoch, seen_at,
                        location_display, location_url
                 FROM {} WHERE tenant_id = $1 AND observation_id = $2",
                schema::OBSERVATIONS_TABLE
            ),
            &[&tenant_id, &observation_id],
        )
        .expect("inserted observation should be readable");

    assert_eq!(row.get::<_, Vec<u8>>(0), tenant_id);
    assert_eq!(row.get::<_, Vec<u8>>(1), observation_id);
    assert_eq!(row.get::<_, Vec<u8>>(2), defaults.occurrence_id.unwrap());
    assert_eq!(row.get::<_, Vec<u8>>(3), defaults.policy_hash.unwrap());
    assert_eq!(row.get::<_, Vec<u8>>(4), defaults.ovid_hash.unwrap());
    assert_eq!(row.get::<_, i64>(5), defaults.run_id.unwrap());
    assert_eq!(row.get::<_, i64>(6), defaults.shard_id.unwrap());
    assert_eq!(row.get::<_, i64>(7), defaults.fence_epoch.unwrap());
    assert_eq!(row.get::<_, i64>(8), defaults.seen_at.unwrap());
    assert_eq!(
        row.get::<_, Option<String>>(9),
        defaults.location_display.unwrap()
    );
    assert_eq!(
        row.get::<_, Option<String>>(10),
        defaults.location_url.unwrap()
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn findings_sink_pg_passes_findings_conformance() {
    let mut client = test_client();
    client
        .batch_execute(schema::TRUNCATE_ALL_SQL)
        .expect("pre-conformance truncate should succeed");
    let backend = FindingsSinkPg::from_client(client);

    run_findings_conformance(&backend)
        .expect("FindingsSinkPg should satisfy the findings conformance harness");
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn upsert_batch_returns_zero_receipt_for_empty_batch() {
    use gossip_contracts::persistence::{
        CommitHandle, FindingsCommitReceipt, FindingsSink, FindingsUpsertBatch,
    };

    let backend = FindingsSinkPg::from_client(test_client());
    let handle = backend
        .upsert_batch(FindingsUpsertBatch::default())
        .expect("empty batch should succeed");
    let receipt = handle.wait().expect("empty batch commit should succeed");

    assert_eq!(receipt, FindingsCommitReceipt::new(0, 0, 0));
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn upsert_batch_rejects_oversized_batch() {
    use gossip_contracts::persistence::{
        FindingsSink, FindingsUpsertBatch, RECOMMENDED_MAX_BATCH_SIZE,
    };

    let backend = FindingsSinkPg::from_client(test_client());

    // The batch size check uses total_records() which sums all three layer
    // slice lengths. Filling the findings slice alone past the limit is
    // sufficient — the records need not be unique because the size gate
    // fires before deduplication.
    let finding = gossip_contracts::persistence::FindingRecord::new(
        gossip_contracts::identity::TenantId::from_bytes([0x11; 32]),
        gossip_contracts::identity::StableItemId::from_bytes([0x22; 32]),
        gossip_contracts::identity::RuleFingerprint::from_bytes([0x33; 32]),
        gossip_contracts::identity::key_secret_hash(
            &gossip_contracts::identity::TenantSecretKey::from_bytes([0x44; 32]),
            &gossip_contracts::identity::NormHash::from_digest([0x55; 32]),
        ),
    );
    let findings: Vec<_> = std::iter::repeat_n(finding, RECOMMENDED_MAX_BATCH_SIZE + 1).collect();

    let err = backend
        .upsert_batch(FindingsUpsertBatch::new(&findings, &[], &[]))
        .expect_err("oversized batch should be rejected");

    match err {
        crate::FindingsPgError::BatchTooLarge { len, max } => {
            assert_eq!(len, RECOMMENDED_MAX_BATCH_SIZE + 1);
            assert_eq!(max, RECOMMENDED_MAX_BATCH_SIZE);
        }
        other => panic!("expected BatchTooLarge, got {other:?}"),
    }
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn upsert_batch_rolls_back_on_conflict_error() {
    use gossip_contracts::identity::{
        FenceEpoch, LogicalTime, NormHash, ObjectVersionId, ObservationId, OccurrenceId,
        PolicyHash, RuleFingerprint, RunId, ShardId, StableItemId, TenantId, TenantSecretKey,
        key_secret_hash,
    };
    use gossip_contracts::persistence::{
        CommitHandle, FindingRecord, FindingsConformanceProbe, FindingsSink, FindingsUpsertBatch,
        OccurrenceRecord, OvidHash,
    };
    use gossip_contracts::test_util::observation_record_with_stored_id;

    let backend = FindingsSinkPg::from_client(test_client());

    let tenant_id = TenantId::from_bytes([0x11; 32]);
    let finding = FindingRecord::new(
        tenant_id,
        StableItemId::from_bytes([0x22; 32]),
        RuleFingerprint::from_bytes([0x33; 32]),
        key_secret_hash(
            &TenantSecretKey::from_bytes([0x44; 32]),
            &NormHash::from_digest([0x55; 32]),
        ),
    );
    let occurrence = OccurrenceRecord::new(
        tenant_id,
        finding.finding_id(),
        ObjectVersionId::from_bytes([0x66; 32]),
        100,
        std::num::NonZeroU64::new(50).unwrap(),
    );

    backend
        .upsert_batch(FindingsUpsertBatch::new(
            &[finding],
            std::slice::from_ref(&occurrence),
            &[],
        ))
        .expect("initial batch should succeed")
        .wait()
        .expect("initial commit should succeed");

    let counts_before = backend
        .durable_counts()
        .expect("counts should succeed before error");

    // Construct a batch with a new valid finding and an observation that
    // references a nonexistent occurrence_id. The finding insert will succeed,
    // but the observation foreign key constraint will fail, causing the entire
    // transaction to roll back.
    let new_finding = FindingRecord::new(
        tenant_id,
        StableItemId::from_bytes([0xAA; 32]),
        RuleFingerprint::from_bytes([0xBB; 32]),
        key_secret_hash(
            &TenantSecretKey::from_bytes([0xCC; 32]),
            &NormHash::from_digest([0xDD; 32]),
        ),
    );
    let bad_occurrence_id = OccurrenceId::from_bytes([0xFF; 32]);
    let bad_observation_id = ObservationId::from_bytes([0xEE; 32]);
    let bad_observation = observation_record_with_stored_id(
        tenant_id,
        bad_observation_id,
        bad_occurrence_id,
        PolicyHash::from_bytes([0x77; 32]),
        OvidHash::from_bytes([0x88; 32]),
        RunId::from_raw(1),
        ShardId::from_raw(2),
        FenceEpoch::from_raw(3),
        LogicalTime::from_raw(10),
        None,
    );

    let _err = backend
        .upsert_batch(FindingsUpsertBatch::new(
            &[new_finding],
            &[],
            &[bad_observation],
        ))
        .expect_err("batch with FK violation should fail");

    let counts_after = backend
        .durable_counts()
        .expect("counts should succeed after rollback");

    assert_eq!(
        counts_before, counts_after,
        "transaction rollback should leave durable state unchanged"
    );
}

#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn upsert_batch_detects_observation_identity_conflict_against_persisted_rows() {
    use gossip_contracts::identity::{
        FenceEpoch, LogicalTime, NormHash, ObjectVersionId, PolicyHash, RuleFingerprint, RunId,
        ShardId, StableItemId, TenantId, TenantSecretKey, key_secret_hash,
    };
    use gossip_contracts::persistence::{
        CommitHandle, FindingRecord, FindingsConformanceProbe, FindingsSink, FindingsUpsertBatch,
        ObservationRecord, OccurrenceRecord, OvidHash,
    };
    use gossip_contracts::test_util::observation_record_with_stored_id;

    let backend = FindingsSinkPg::from_client(test_client());

    let tenant_id = TenantId::from_bytes([0x11; 32]);
    let finding = FindingRecord::new(
        tenant_id,
        StableItemId::from_bytes([0x22; 32]),
        RuleFingerprint::from_bytes([0x33; 32]),
        key_secret_hash(
            &TenantSecretKey::from_bytes([0x44; 32]),
            &NormHash::from_digest([0x55; 32]),
        ),
    );
    let occurrence = OccurrenceRecord::new(
        tenant_id,
        finding.finding_id(),
        ObjectVersionId::from_bytes([0x66; 32]),
        100,
        std::num::NonZeroU64::new(50).unwrap(),
    );
    let observation = ObservationRecord::new(
        tenant_id,
        occurrence.occurrence_id(),
        PolicyHash::from_bytes([0x77; 32]),
        OvidHash::from_bytes([0x88; 32]),
        RunId::from_raw(1),
        ShardId::from_raw(2),
        FenceEpoch::from_raw(3),
        LogicalTime::from_raw(10),
    );

    backend
        .upsert_batch(FindingsUpsertBatch::new(
            &[finding],
            &[occurrence],
            std::slice::from_ref(&observation),
        ))
        .expect("initial batch should succeed")
        .wait()
        .expect("initial commit should succeed");

    let counts_before = backend
        .durable_counts()
        .expect("counts should succeed before conflict");

    // Construct a conflicting observation: same tenant_id and observation_id,
    // but different policy_hash. The SQL identity-verifying WHERE clause
    // checks policy_hash, so this will trigger ObservationConflict.
    let conflicting = observation_record_with_stored_id(
        tenant_id,
        observation.observation_id(),
        observation.occurrence_id(),
        PolicyHash::from_bytes([0x99; 32]),
        observation.ovid_hash(),
        observation.run_id(),
        observation.shard_id(),
        observation.fence_epoch(),
        observation.seen_at(),
        None,
    );

    let err = backend
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &[conflicting]))
        .expect_err("conflicting observation should be rejected");

    match err {
        crate::FindingsPgError::ObservationConflict {
            tenant_id: err_tenant,
            observation_id: err_observation,
        } => {
            assert_eq!(err_tenant, tenant_id);
            assert_eq!(err_observation, observation.observation_id());
        }
        other => panic!("expected ObservationConflict, got {other:?}"),
    }

    let counts_after = backend
        .durable_counts()
        .expect("counts should succeed after rollback");

    assert_eq!(
        counts_before, counts_after,
        "transaction rollback should leave durable state unchanged"
    );
}
