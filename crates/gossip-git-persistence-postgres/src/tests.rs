//! Integration tests for the PostgreSQL Git persistence schema, backend, and
//! migration runner.
//!
//! All tests in this module require a running PostgreSQL instance (either via
//! Docker/testcontainers or an external `GOSSIP_POSTGRES_TEST_URL`). Each test
//! gets an isolated database via `gossip_pg_common::test_support::create_test_db()`.
//!
//! ## Test categories
//!
//! - **Migration runner** — migration-from-scratch, idempotent reapply,
//!   checksum-mismatch detection, persisted-history tamper, connection smoke
//!   checks, and concurrent advisory-lock serialization.
//! - **`GitPersistenceBackend` behavior** — single-key round-trips, positional
//!   multi-get alignment, last-op-wins normalization, transaction atomicity,
//!   empty-input handling, and arbitrary `BYTEA` round-trips.
//! - **Adapter integration** — wires the real PostgreSQL backend into
//!   `GitPersistenceAdapter` and exercises spill-stage seen persistence plus a
//!   complete finalize.
//!
//! ## Running
//!
//! ```bash
//! # With Docker (testcontainers auto-starts postgres):
//! cargo test -p gossip-git-persistence-postgres
//!
//! # With an external PostgreSQL (needs CREATE DATABASE privilege):
//! GOSSIP_POSTGRES_TEST_URL="host=localhost user=postgres password=postgres" \
//!   cargo test -p gossip-git-persistence-postgres
//! ```

use std::time::Duration;

use proptest::{
    collection::vec,
    prelude::*,
    test_runner::{Config, TestRunner},
};

use crate::test_postgres::{test_client, test_client_bare};
use crate::{
    GitPersistencePg, GitPersistencePgMigrationError, apply_all_migrations, apply_migrations,
    schema::{MAX_KEY_OCTETS, SCHEMA_MIGRATIONS_TABLE},
};
use gossip_scanner_runtime::git_persistence::{
    GitPersistenceAdapter, GitPersistenceBackend, GitPersistenceOp,
};
use scanner_git::{
    FinalizeOutcome, FinalizeOutput, OidBytes, PersistenceStore, RoaringSeenBitmap,
    SeenBitmapPersister, SeenBlobStore, WriteOp,
    finalize::{build_seen_scope_key, build_seen_staging_key},
};

fn put_op(key: &[u8], value: &[u8]) -> GitPersistenceOp {
    GitPersistenceOp::Put {
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

fn delete_op(key: &[u8]) -> GitPersistenceOp {
    GitPersistenceOp::Delete { key: key.to_vec() }
}

fn sim_oid(byte: u8) -> OidBytes {
    OidBytes::sha1([byte; 20])
}

fn finalize_output() -> FinalizeOutput {
    FinalizeOutput {
        data_ops: vec![WriteOp {
            key: b"bc\0blob".to_vec(),
            value: vec![0xAA],
        }],
        watermark_ops: vec![WriteOp {
            key: b"rw\0wm".to_vec(),
            value: vec![0xBB],
        }],
        outcome: FinalizeOutcome::Complete,
        stats: Default::default(),
    }
}

// ── Migration runner ────────────────────────────────────────────────────

#[test]
fn migrations_are_idempotent() {
    let mut client = test_client_bare();

    apply_all_migrations(&mut client).expect("first application should succeed");
    apply_all_migrations(&mut client).expect("second application should succeed (idempotent)");

    let count: i64 = client
        .query_one(
            &format!("SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE}"),
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
fn checksum_mismatch_is_detected() {
    let mut client = test_client_bare();

    apply_all_migrations(&mut client).expect("initial migration should succeed");

    let tampered = [crate::migrations::EmbeddedMigration::new(
        "0001_git_kv",
        "SELECT 1; -- tampered",
    )];

    let err = apply_migrations(&mut client, &tampered, Duration::from_secs(5))
        .expect_err("tampered migration should produce ChecksumMismatch");

    match err {
        GitPersistencePgMigrationError::ChecksumMismatch { version, .. } => {
            assert_eq!(version, "0001_git_kv");
        }
        GitPersistencePgMigrationError::Postgres { source, .. } => {
            panic!("expected ChecksumMismatch, got Postgres error: {source}");
        }
        GitPersistencePgMigrationError::CorruptedHistoryRecord { version, found_len } => {
            panic!(
                "expected ChecksumMismatch, got CorruptedHistoryRecord: version={version}, len={found_len}"
            );
        }
    }
}

#[test]
fn concurrent_migrations_both_succeed() {
    let url = crate::test_postgres::create_test_db();
    let url2 = url.clone();

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
fn persisted_checksum_tamper_is_detected_on_reapply() {
    let mut client = test_client_bare();

    apply_all_migrations(&mut client).expect("initial migration should succeed");

    let updated = client
        .execute(
            &format!(
                "UPDATE {SCHEMA_MIGRATIONS_TABLE} \
                 SET checksum = decode(repeat('00', {}), 'hex') \
                 WHERE version = $1",
                blake3::OUT_LEN,
            ),
            &[&"0001_git_kv"],
        )
        .expect("checksum tamper update should succeed");
    assert_eq!(updated, 1, "expected to tamper exactly one migration row");

    let err = apply_all_migrations(&mut client)
        .expect_err("tampered persisted checksum should fail re-application");
    match err {
        GitPersistencePgMigrationError::ChecksumMismatch { version, .. } => {
            assert_eq!(version, "0001_git_kv");
        }
        GitPersistencePgMigrationError::Postgres { source, .. } => {
            panic!("expected ChecksumMismatch, got Postgres error: {source}");
        }
        GitPersistencePgMigrationError::CorruptedHistoryRecord { version, found_len } => {
            panic!(
                "expected ChecksumMismatch, got CorruptedHistoryRecord: version={version}, len={found_len}"
            );
        }
    }
}

// ── GitPersistenceBackend behavior ──────────────────────────────────────

#[test]
fn get_nonexistent_key_returns_none() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");

    let fetched = GitPersistenceBackend::get(&backend, b"missing")
        .expect("get should succeed for absent key");
    assert!(fetched.is_none());
}

#[test]
fn empty_inputs_are_noops() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    GitPersistenceBackend::apply_batch(&backend, &[]).expect("empty batch should succeed");
    let fetched =
        GitPersistenceBackend::multi_get(&backend, &[]).expect("empty multi_get should succeed");

    assert!(fetched.is_empty());
}

#[test]
fn put_get_delete_roundtrip() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    GitPersistenceBackend::apply_batch(&backend, &[put_op(b"wm\0ref", &[0x10, 0x20, 0x30])])
        .expect("put should succeed");

    assert_eq!(
        GitPersistenceBackend::get(&backend, b"wm\0ref").expect("get should succeed"),
        Some(vec![0x10, 0x20, 0x30])
    );

    GitPersistenceBackend::apply_batch(&backend, &[delete_op(b"wm\0ref")])
        .expect("delete should succeed");

    assert_eq!(
        GitPersistenceBackend::get(&backend, b"wm\0ref").expect("get should succeed"),
        None
    );
}

#[test]
fn apply_batch_reports_atomic_and_rolls_back_failed_txn() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    assert!(
        GitPersistenceBackend::supports_atomic_batches(&backend),
        "PostgreSQL transactions make apply_batch atomic"
    );

    let too_long_key = vec![0u8; MAX_KEY_OCTETS + 1];
    let err = GitPersistenceBackend::apply_batch(
        &backend,
        &[
            put_op(b"good-key", &[0x01]),
            GitPersistenceOp::Put {
                key: too_long_key,
                value: vec![0x02],
            },
        ],
    )
    .expect_err("constraint violation should reject the whole transaction");

    assert!(
        err.to_string()
            .contains("postgres git-persistence operation failed"),
        "error should be surfaced through the redacted display path: {err}"
    );
    assert_eq!(
        GitPersistenceBackend::get(&backend, b"good-key").expect("get should succeed"),
        None,
        "the successful put must roll back with the failing one"
    );
}

#[test]
fn multi_get_preserves_order_with_missing_keys_and_duplicates() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    GitPersistenceBackend::apply_batch(
        &backend,
        &[
            put_op(b"key-a", &[0x01]),
            put_op(b"key-b", &[0x02]),
            put_op(b"key-c", &[0x03]),
        ],
    )
    .expect("seed batch should succeed");

    let fetched = GitPersistenceBackend::multi_get(
        &backend,
        &[
            b"key-b".to_vec(),
            b"missing".to_vec(),
            b"key-a".to_vec(),
            b"key-b".to_vec(),
            b"key-c".to_vec(),
        ],
    )
    .expect("multi_get should succeed");

    assert_eq!(
        fetched,
        vec![
            Some(vec![0x02]),
            None,
            Some(vec![0x01]),
            Some(vec![0x02]),
            Some(vec![0x03]),
        ]
    );
}

#[test]
fn put_overwrites_existing_value() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    GitPersistenceBackend::apply_batch(&backend, &[put_op(b"seen\0scope", &[0xAA])])
        .expect("first put should succeed");
    GitPersistenceBackend::apply_batch(&backend, &[put_op(b"seen\0scope", &[0xBB, 0xCC])])
        .expect("overwrite put should succeed");

    assert_eq!(
        GitPersistenceBackend::get(&backend, b"seen\0scope").expect("get should succeed"),
        Some(vec![0xBB, 0xCC])
    );
}

#[test]
fn apply_batch_uses_last_op_for_duplicate_keys() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    GitPersistenceBackend::apply_batch(
        &backend,
        &[
            put_op(b"dup-key", &[0x01]),
            delete_op(b"dup-key"),
            put_op(b"dup-key", &[0x02]),
            put_op(b"other-key", &[0x03]),
        ],
    )
    .expect("normalized batch should succeed");

    assert_eq!(
        GitPersistenceBackend::get(&backend, b"dup-key").expect("get should succeed"),
        Some(vec![0x02])
    );
    assert_eq!(
        GitPersistenceBackend::get(&backend, b"other-key").expect("get should succeed"),
        Some(vec![0x03])
    );
}

#[test]
fn kv_roundtrip_arbitrary_bytes() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");

    let mut runner = TestRunner::new(Config::with_cases(64));
    let strategy = (
        vec(any::<u8>(), 0..=MAX_KEY_OCTETS),
        vec(any::<u8>(), 0..=4096),
    );
    runner
        .run(&strategy, |(key, value)| {
            backend
                .truncate_all_for_tests()
                .expect("truncate should succeed before each case");

            GitPersistenceBackend::apply_batch(
                &backend,
                &[GitPersistenceOp::Put {
                    key: key.clone(),
                    value: value.clone(),
                }],
            )
            .expect("put should succeed");

            let fetched = GitPersistenceBackend::get(&backend, &key).expect("get should succeed");
            prop_assert_eq!(fetched, Some(value));
            Ok(())
        })
        .expect("all arbitrary byte cases should round-trip");
}

#[test]
fn adapter_integration_with_pg_backend() {
    let backend = GitPersistencePg::from_client(test_client()).expect("from_client should succeed");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before test");

    let repo_id = 77;
    let policy_hash = [0x55; 32];
    let adapter = GitPersistenceAdapter::new(backend.clone(), repo_id, policy_hash);
    let oid = sim_oid(0xAB);

    adapter
        .persist_seen_delta(&[oid])
        .expect("stage seen delta should succeed");
    adapter
        .commit_finalize(&finalize_output())
        .expect("complete finalize should succeed");

    assert_eq!(
        adapter
            .batch_check_seen(&[oid])
            .expect("seen check should succeed"),
        vec![true]
    );

    let unseen_oid = sim_oid(0xCD);
    assert_eq!(
        adapter
            .batch_check_seen(&[unseen_oid])
            .expect("unseen check should succeed"),
        vec![false],
        "OID that was never staged must not appear as seen"
    );

    assert_eq!(
        GitPersistenceBackend::get(&backend, b"bc\0blob").expect("blob get should succeed"),
        Some(vec![0xAA])
    );
    assert_eq!(
        GitPersistenceBackend::get(&backend, b"rw\0wm").expect("watermark get should succeed"),
        Some(vec![0xBB])
    );
    let scope_bytes =
        GitPersistenceBackend::get(&backend, &build_seen_scope_key(repo_id, &policy_hash))
            .expect("scope get should succeed")
            .expect("scope key must exist after complete finalize");
    let scope_bitmap = RoaringSeenBitmap::deserialize(&scope_bytes)
        .expect("scope value must be a valid serialized bitmap");
    assert!(
        scope_bitmap.contains(&oid),
        "committed bitmap must contain the staged OID"
    );
    assert!(
        !scope_bitmap.contains(&unseen_oid),
        "committed bitmap must not contain an OID that was never staged"
    );
    assert_eq!(
        GitPersistenceBackend::get(&backend, &build_seen_staging_key(repo_id, &policy_hash))
            .expect("staging get should succeed"),
        None,
        "complete finalize must remove the staging key"
    );
}
