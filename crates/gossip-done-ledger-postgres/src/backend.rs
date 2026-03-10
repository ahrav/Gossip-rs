//! PostgreSQL-backed implementation of [`DoneLedger`].
//!
//! ## Architecture
//!
//! A single synchronous `postgres::Client` is held behind an `Arc<Mutex<_>>`,
//! making [`DoneLedgerPg`] cheaply cloneable and `Send + Sync`. Every
//! `batch_upsert` executes inside an explicit transaction; the
//! [`ReadyCommitHandle`] is only constructed **after** `tx.commit()`
//! succeeds, so the receipt returned to the caller is durable-before-return.
//!
//! ## Duplicate-key handling
//!
//! When a single `batch_upsert` call contains multiple records with the same
//! [`DoneLedgerKey`], the backend folds them in submission order using the
//! same lattice-merge rules as the SQL `ON CONFLICT` clause (see
//! [`UPSERT_SQL`]). This ensures that the number of SQL statements equals
//! the number of *distinct* keys, not the number of input records.
//!
//! ## Positional alignment
//!
//! `batch_get` preserves the caller's requested order: the returned
//! `Vec<Option<DoneLedgerRecord>>` is positionally aligned with the input
//! `ovid_hashes` slice, with `None` for missing keys and duplicated results
//! for duplicated inputs.
//!
//! [`UPSERT_SQL`]: crate::schema::UPSERT_SQL

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use gossip_contracts::{
    identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
    persistence::{
        DoneLedger, DoneLedgerCommitReceipt, DoneLedgerErrorCode, DoneLedgerKey,
        DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus, OvidHash,
        RECOMMENDED_MAX_BATCH_SIZE, ReadyCommitHandle, merge_done_ledger_records,
    },
};
#[cfg(feature = "test-utils")]
use postgres::NoTls;
use postgres::{Client, Row, Transaction};

use crate::{
    error::{DoneLedgerPgConversionError, DoneLedgerPgError},
    migrations::apply_all_migrations,
    schema::{BATCH_GET_SQL, UPSERT_SQL},
    types::{
        pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits, u64_to_pg_bigint_bits,
        u64_to_pg_bigint_checked,
    },
};

/// Synchronous PostgreSQL implementation of [`DoneLedger`].
///
/// Internally wraps a `postgres::Client` in `Arc<Mutex<_>>` so that clones
/// share the same connection and callers can use `DoneLedgerPg` from
/// multiple threads.
///
/// # Concurrency
///
/// The mutex serialises **all** database access through a single connection.
/// Concurrent `batch_get` / `batch_upsert` calls block on the mutex, so
/// throughput is limited to one operation at a time. Callers that need
/// connection-level parallelism should create multiple `DoneLedgerPg`
/// instances (each with its own `Client`) or front them with a connection
/// pool.
///
/// # Construction
///
/// | Constructor | TLS | Migrations | Feature gate | Use case |
/// |---|---|---|---|---|
/// | [`connect`](Self::connect) | `NoTls` | No | `test-utils` | Quick local / test setup |
/// | [`connect_and_migrate`](Self::connect_and_migrate) | `NoTls` | Yes | `test-utils` | Local dev with auto-schema |
/// | [`from_client`](Self::from_client) | Caller-chosen | No | *(always)* | Production (TLS, pooling) |
///
/// After calling `from_client`, use [`apply_migrations`](Self::apply_migrations)
/// to run schema migrations if needed.
#[derive(Clone)]
pub struct DoneLedgerPg {
    client: Arc<Mutex<Client>>,
}

impl DoneLedgerPg {
    /// Connect to PostgreSQL without applying migrations.
    ///
    /// Uses `NoTls` — intended for local development and integration tests
    /// only. Production callers should construct a TLS-enabled
    /// [`Client`](postgres::Client) and use [`from_client`](Self::from_client).
    ///
    /// Requires the `test-utils` feature.
    ///
    /// # Errors
    ///
    /// Returns [`DoneLedgerPgError::Postgres`] on connection failure.
    #[cfg(feature = "test-utils")]
    pub fn connect(database_url: &str) -> Result<Self, DoneLedgerPgError> {
        let client = Client::connect(database_url, NoTls)?;
        Ok(Self::from_client(client))
    }

    /// Connect to PostgreSQL and apply crate-embedded migrations.
    ///
    /// Equivalent to [`connect`](Self::connect) followed by
    /// [`apply_migrations`](Self::apply_migrations). Uses `NoTls` —
    /// intended for local development and integration tests only.
    ///
    /// Requires the `test-utils` feature.
    ///
    /// # Errors
    ///
    /// Returns [`DoneLedgerPgError::Postgres`] on connection failure or
    /// [`DoneLedgerPgError::Migration`] if schema migration fails.
    #[cfg(feature = "test-utils")]
    pub fn connect_and_migrate(database_url: &str) -> Result<Self, DoneLedgerPgError> {
        let client = Client::connect(database_url, NoTls)?;
        let backend = Self::from_client(client);
        backend.apply_migrations()?;
        Ok(backend)
    }

    /// Wrap an already-connected PostgreSQL client.
    ///
    /// The preferred production constructor: the caller controls TLS
    /// configuration, connection parameters, and pooling. Call
    /// [`apply_migrations`](Self::apply_migrations) afterwards if the
    /// schema has not yet been applied.
    #[inline]
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
        }
    }

    /// Apply all embedded migrations using the held client.
    ///
    /// Idempotent and concurrency-safe — see [`crate::migrations`] for the
    /// advisory-lock and checksum-verification protocol.
    ///
    /// # Errors
    ///
    /// Returns [`DoneLedgerPgError::Migration`] on SQL failure or checksum
    /// mismatch, or [`DoneLedgerPgError::MutexPoisoned`] if the internal
    /// mutex was poisoned.
    pub fn apply_migrations(&self) -> Result<(), DoneLedgerPgError> {
        let mut client = self.lock_client()?;
        apply_all_migrations(&mut client)?;
        Ok(())
    }

    /// Validate the current connection by executing a simple query within
    /// the given `timeout`.
    ///
    /// Useful for health-check endpoints or connection-pool keep-alive
    /// probes.
    ///
    /// # Errors
    ///
    /// Returns [`DoneLedgerPgError::Postgres`] if the query times out or
    /// the connection is broken.
    pub fn validate_connection(&self, timeout: Duration) -> Result<(), DoneLedgerPgError> {
        let mut client = self.lock_client()?;
        client.is_valid(timeout)?;
        Ok(())
    }

    /// Remove all rows from the done-ledger table.
    ///
    /// This helper is intended for crate-local integration tests.
    #[cfg(test)]
    pub(crate) fn truncate_all_for_tests(&self) -> Result<(), DoneLedgerPgError> {
        let mut client = self.lock_client()?;
        client.batch_execute(&format!(
            "TRUNCATE TABLE {}",
            crate::schema::DONE_LEDGER_ENTRIES_TABLE
        ))?;
        Ok(())
    }

    /// Acquire the internal mutex, returning `MutexPoisoned` if a prior
    /// holder panicked.
    fn lock_client(&self) -> Result<MutexGuard<'_, Client>, DoneLedgerPgError> {
        self.client
            .lock()
            .map_err(|_| DoneLedgerPgError::MutexPoisoned)
    }
}

impl fmt::Debug for DoneLedgerPg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoneLedgerPg").finish_non_exhaustive()
    }
}

impl DoneLedger for DoneLedgerPg {
    type Error = DoneLedgerPgError;
    type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, DoneLedgerPgError>;

    fn batch_get(
        &self,
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        ovid_hashes: &[OvidHash],
    ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
        if ovid_hashes.len() > RECOMMENDED_MAX_BATCH_SIZE {
            return Err(DoneLedgerPgError::BatchTooLarge {
                operation: "batch_get",
                len: ovid_hashes.len(),
                max: RECOMMENDED_MAX_BATCH_SIZE,
            });
        }
        if ovid_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let requested_ovids: Vec<&[u8]> = ovid_hashes
            .iter()
            .map(|hash| hash.as_bytes().as_slice())
            .collect();
        let tenant_bytes: &[u8] = tenant_id.as_bytes();
        let policy_bytes: &[u8] = policy_hash.as_bytes();

        let mut client = self.lock_client()?;
        let stmt = client.prepare(BATCH_GET_SQL)?;
        let rows = client.query(&stmt, &[&tenant_bytes, &policy_bytes, &requested_ovids])?;

        let mut by_ovid = HashMap::with_capacity(rows.len());
        for row in rows {
            let record = decode_row(&row)?;
            by_ovid.insert(record.key().ovid_hash(), record);
        }

        Ok(ovid_hashes
            .iter()
            .map(|ovid_hash| by_ovid.get(ovid_hash).cloned())
            .collect())
    }

    fn batch_upsert(
        &self,
        records: &[DoneLedgerRecord],
    ) -> Result<Self::CommitHandle, Self::Error> {
        if records.len() > RECOMMENDED_MAX_BATCH_SIZE {
            return Err(DoneLedgerPgError::BatchTooLarge {
                operation: "batch_upsert",
                len: records.len(),
                max: RECOMMENDED_MAX_BATCH_SIZE,
            });
        }
        if records.is_empty() {
            return Ok(ReadyCommitHandle::ok(DoneLedgerCommitReceipt::new(0, 0, 0)));
        }

        let merged = dedupe_and_validate(records)?;
        let mut client = self.lock_client()?;
        let mut tx = client.transaction()?;
        let stmt = tx.prepare(UPSERT_SQL)?;

        for (idx, record) in merged.iter().enumerate() {
            upsert_record(&mut tx, &stmt, record).map_err(|e| DoneLedgerPgError::UpsertFailed {
                index: idx,
                source: Box::new(e),
            })?;
        }

        tx.commit()?;
        Ok(ReadyCommitHandle::ok(build_receipt(&merged)))
    }
}

/// Summarise the deduplicated record set into a commit receipt.
///
/// Counts are computed from the *merged* records, not from the original
/// input, so duplicates within a batch do not inflate the receipt.
fn build_receipt(records: &[DoneLedgerRecord]) -> DoneLedgerCommitReceipt {
    DoneLedgerCommitReceipt::new(
        records.len() as u64,
        records
            .iter()
            .filter(|record| record.status().is_scanned())
            .count() as u64,
        records.iter().fold(0u64, |acc, record| {
            acc.saturating_add(record.findings_count() as u64)
        }),
    )
}

/// Validate each input record and merge duplicate keys before SQL mutation.
///
/// The first occurrence of each key establishes output order. Later duplicates
/// are folded into that slot via [`merge_done_ledger_records`], so persistence
/// writes at most one row per key for the submitted batch.
fn dedupe_and_validate(
    records: &[DoneLedgerRecord],
) -> Result<Vec<DoneLedgerRecord>, DoneLedgerPgError> {
    let mut merged: HashMap<DoneLedgerKey, DoneLedgerRecord> =
        HashMap::with_capacity(records.len());
    let mut order: Vec<DoneLedgerKey> = Vec::new();

    for (index, record) in records.iter().enumerate() {
        record
            .validate()
            .map_err(|source| DoneLedgerPgError::InvalidRecord { index, source })?;

        let prov = record.provenance();
        if prov.started_at().as_raw() > prov.finished_at().as_raw() {
            return Err(DoneLedgerPgError::ProvenanceInvalid {
                index,
                started_at: prov.started_at().as_raw(),
                finished_at: prov.finished_at().as_raw(),
            });
        }

        match merged.entry(record.key()) {
            Entry::Vacant(slot) => {
                order.push(record.key());
                slot.insert(record.clone());
            }
            Entry::Occupied(mut slot) => {
                let merged_record = merge_done_ledger_records(slot.get(), record)
                    .map_err(|source| DoneLedgerPgError::InvalidMergedRecord { source })?;
                // Defensive: verify merged output satisfies the same cross-field
                // invariants that individual inputs were validated against.
                // The merge logic already maintains these, but this guard
                // catches regressions if the merge rules are modified.
                merged_record
                    .validate()
                    .map_err(|source| DoneLedgerPgError::InvalidMergedRecord { source })?;
                slot.insert(merged_record);
            }
        }
    }

    let mut deduped = Vec::with_capacity(order.len());
    for key in order {
        let record = merged
            .remove(&key)
            .expect("order vec and merged map are populated from the same input");
        deduped.push(record);
    }

    Ok(deduped)
}

/// Encode a single `DoneLedgerRecord` into SQL parameters and execute the
/// `UPSERT_SQL` statement within the given transaction.
///
/// Identity fields (`run_id`, `shard_id`) are encoded in bit-pattern mode;
/// ordered fields (`bytes_scanned`, `fence_epoch`, `started_at`,
/// `finished_at`) use checked non-negative mode. See [`crate::types`] for
/// the distinction.
fn upsert_record(
    tx: &mut Transaction<'_>,
    stmt: &postgres::Statement,
    record: &DoneLedgerRecord,
) -> Result<(), DoneLedgerPgError> {
    let key = record.key();
    let provenance = record.provenance();
    let tenant_id = key.tenant_id();
    let policy_hash = key.policy_hash();
    let ovid_hash = key.ovid_hash();

    let status = i16::from(record.status().rank());
    let bytes_scanned = u64_to_pg_bigint_checked(record.bytes_scanned(), "bytes_scanned")
        .map_err(DoneLedgerPgConversionError::from)?;
    let findings_count = i32::try_from(record.findings_count()).map_err(|_| {
        DoneLedgerPgConversionError::FindingsCountOutOfRange {
            value: i64::from(record.findings_count()),
        }
    })?;
    let run_id = u64_to_pg_bigint_bits(provenance.run_id().as_raw());
    let shard_id = u64_to_pg_bigint_bits(provenance.shard_id().as_raw());
    let fence_epoch = u64_to_pg_bigint_checked(provenance.fence_epoch().as_raw(), "fence_epoch")
        .map_err(DoneLedgerPgConversionError::from)?;
    let started_at = u64_to_pg_bigint_checked(provenance.started_at().as_raw(), "started_at")
        .map_err(DoneLedgerPgConversionError::from)?;
    let finished_at = u64_to_pg_bigint_checked(provenance.finished_at().as_raw(), "finished_at")
        .map_err(DoneLedgerPgConversionError::from)?;
    let error_code = record.error_code().map(DoneLedgerErrorCode::as_str);
    let tenant_bytes: &[u8] = tenant_id.as_bytes();
    let policy_bytes: &[u8] = policy_hash.as_bytes();
    let ovid_bytes: &[u8] = ovid_hash.as_bytes();

    tx.execute(
        stmt,
        &[
            &tenant_bytes,
            &policy_bytes,
            &ovid_bytes,
            &status,
            &bytes_scanned,
            &findings_count,
            &run_id,
            &shard_id,
            &fence_epoch,
            &started_at,
            &finished_at,
            &error_code,
        ],
    )?;

    Ok(())
}

/// Decode a PostgreSQL result row into a validated `DoneLedgerRecord`.
///
/// Applies three layers of validation:
/// 1. Type-level conversion (byte length, `u64` range, status rank mapping).
/// 2. Construction-time invariants via `DoneLedgerRecord::try_new`.
/// 3. Cross-field consistency via `DoneLedgerRecord::validate`.
///
/// Any failure at any layer produces `DoneLedgerPgError::PersistedRecordInvalid`
/// or `DoneLedgerPgError::Conversion`, indicating data corruption or
/// schema drift.
///
/// Each BYTEA column allocates a `Vec<u8>` (the `postgres` crate's return
/// type for `row.get`). This is a WARM-path cost accepted for simplicity;
/// a crate-local newtype with a `FromSql` impl would eliminate 3
/// allocations per row if profiling shows this is material.
fn decode_row(row: &Row) -> Result<DoneLedgerRecord, DoneLedgerPgError> {
    let tenant_id = TenantId::from_bytes(decode_fixed_32(row.get("tenant_id"), "tenant_id")?);
    let policy_hash =
        PolicyHash::from_bytes(decode_fixed_32(row.get("policy_hash"), "policy_hash")?);
    let ovid_hash = OvidHash::from_bytes(decode_fixed_32(row.get("ovid_hash"), "ovid_hash")?);

    let status_rank: i16 = row.get("status");
    let status_rank_u8 = u8::try_from(status_rank)
        .map_err(|_| DoneLedgerPgConversionError::UnknownStatusRank { rank: status_rank })?;
    let status = DoneLedgerStatus::from_rank(status_rank_u8)
        .ok_or(DoneLedgerPgConversionError::UnknownStatusRank { rank: status_rank })?;

    let bytes_scanned = pg_bigint_nonnegative_to_u64(row.get("bytes_scanned"), "bytes_scanned")
        .map_err(DoneLedgerPgConversionError::from)?;

    let findings_count_raw: i32 = row.get("findings_count");
    let findings_count = u32::try_from(findings_count_raw).map_err(|_| {
        DoneLedgerPgConversionError::FindingsCountOutOfRange {
            value: i64::from(findings_count_raw),
        }
    })?;

    let run_id = RunId::from_raw(pg_bigint_to_u64_bits(row.get("run_id")));
    let shard_id = ShardId::from_raw(pg_bigint_to_u64_bits(row.get("shard_id")));
    let fence_epoch = FenceEpoch::from_raw(
        pg_bigint_nonnegative_to_u64(row.get("fence_epoch"), "fence_epoch")
            .map_err(DoneLedgerPgConversionError::from)?,
    );
    let started_at = LogicalTime::from_raw(
        pg_bigint_nonnegative_to_u64(row.get("started_at"), "started_at")
            .map_err(DoneLedgerPgConversionError::from)?,
    );
    let finished_at = LogicalTime::from_raw(
        pg_bigint_nonnegative_to_u64(row.get("finished_at"), "finished_at")
            .map_err(DoneLedgerPgConversionError::from)?,
    );

    let error_code = row
        .get::<_, Option<String>>("error_code")
        .map(DoneLedgerErrorCode::try_new)
        .transpose()
        .map_err(|source| DoneLedgerPgError::PersistedRecordInvalid {
            context: "decode error_code",
            source,
        })?;

    let record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
        status,
        bytes_scanned,
        findings_count,
        DoneLedgerProvenance::new(run_id, shard_id, fence_epoch, started_at, finished_at),
        error_code,
    )
    .map_err(|source| DoneLedgerPgError::PersistedRecordInvalid {
        context: "decode row",
        source,
    })?;

    record
        .validate()
        .map_err(|source| DoneLedgerPgError::PersistedRecordInvalid {
            context: "validate decoded row",
            source,
        })?;

    Ok(record)
}

/// Convert a variable-length `BYTEA` column value into a fixed 32-byte
/// array, or return `InvalidByteLength` if the stored blob has the wrong
/// size.
fn decode_fixed_32(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 32], DoneLedgerPgError> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        DoneLedgerPgConversionError::InvalidByteLength {
            field,
            expected: 32,
            actual: bytes.len(),
        }
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::dedupe_and_validate;
    use gossip_contracts::{
        identity::{FenceEpoch, LogicalTime, RunId, ShardId},
        persistence::{
            DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
            DoneLedgerStatus, merge_done_ledger_records,
        },
        test_util::{ovid, policy, tenant},
    };

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
        reason = "test helper mirrors the flat done-ledger row shape"
    )]
    fn record(
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
    fn merge_fail_then_scan_preserves_metrics_and_clears_error_code() {
        let failed = record(
            1,
            2,
            3,
            DoneLedgerStatus::FailedRetryable,
            9_000,
            7,
            10,
            11,
            12,
            100,
            200,
            Some("IO_TIMEOUT"),
        );
        let scanned = record(
            1,
            2,
            3,
            DoneLedgerStatus::ScannedWithFindings,
            1_000,
            1,
            20,
            21,
            22,
            150,
            250,
            None,
        );

        let merged = merge_done_ledger_records(&failed, &scanned)
            .expect("merge should preserve done-ledger invariants");

        assert_eq!(merged.status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(merged.bytes_scanned(), 9_000);
        assert_eq!(merged.findings_count(), 7);
        assert_eq!(merged.provenance(), scanned.provenance());
        assert_eq!(merged.error_code(), None);
    }

    #[test]
    fn merge_scan_then_fail_keeps_scanned_status() {
        let scanned = record(
            4,
            5,
            6,
            DoneLedgerStatus::ScannedWithFindings,
            2_000,
            2,
            30,
            31,
            32,
            100,
            500,
            None,
        );
        let failed = record(
            4,
            5,
            6,
            DoneLedgerStatus::FailedPermanent,
            8_000,
            5,
            40,
            41,
            42,
            110,
            120,
            Some("PERM_DENY"),
        );

        let merged = merge_done_ledger_records(&scanned, &failed)
            .expect("merge should preserve done-ledger invariants");

        assert_eq!(merged.status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(merged.bytes_scanned(), 8_000);
        assert_eq!(merged.findings_count(), 5);
        assert_eq!(merged.provenance(), scanned.provenance());
        assert_eq!(merged.error_code(), None);
    }

    #[test]
    fn merge_equal_rank_prefers_newer_finished_then_started_time() {
        let existing = record(
            7,
            8,
            9,
            DoneLedgerStatus::FailedPermanent,
            100,
            3,
            50,
            51,
            52,
            100,
            200,
            Some("OLD"),
        );

        let newer_finished = record(
            7,
            8,
            9,
            DoneLedgerStatus::FailedPermanent,
            90,
            1,
            60,
            61,
            62,
            80,
            300,
            Some("NEW_FINISHED"),
        );

        let merged = merge_done_ledger_records(&existing, &newer_finished)
            .expect("merge should keep equal-rank freshness ordering");
        assert_eq!(merged.provenance(), newer_finished.provenance());
        assert_eq!(merged.error_code(), newer_finished.error_code());

        let newer_started = record(
            7,
            8,
            9,
            DoneLedgerStatus::FailedPermanent,
            95,
            2,
            70,
            71,
            72,
            150,
            200,
            Some("NEW_STARTED"),
        );

        let merged = merge_done_ledger_records(&existing, &newer_started)
            .expect("merge should use started_at as equal-finished tie-break");
        assert_eq!(merged.provenance(), newer_started.provenance());
        assert_eq!(merged.error_code(), newer_started.error_code());
    }

    #[test]
    fn dedupe_and_validate_merges_duplicate_keys_in_submission_order() {
        let key_a_failed = record(
            1,
            1,
            1,
            DoneLedgerStatus::FailedRetryable,
            500,
            9,
            1,
            1,
            1,
            10,
            20,
            Some("A"),
        );
        let key_b_scanned = record(
            1,
            1,
            2,
            DoneLedgerStatus::ScannedClean,
            100,
            0,
            2,
            2,
            2,
            11,
            21,
            None,
        );
        let key_a_scanned = record(
            1,
            1,
            1,
            DoneLedgerStatus::ScannedWithFindings,
            200,
            1,
            3,
            3,
            3,
            12,
            22,
            None,
        );

        let deduped = dedupe_and_validate(&[
            key_a_failed.clone(),
            key_b_scanned.clone(),
            key_a_scanned.clone(),
        ])
        .expect("dedupe should merge duplicate keys before SQL mutation");

        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].key(), key_a_failed.key());
        assert_eq!(deduped[1].key(), key_b_scanned.key());

        assert_eq!(deduped[0].status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(deduped[0].bytes_scanned(), 500);
        assert_eq!(deduped[0].findings_count(), 9);
        assert_eq!(deduped[0].error_code(), None);
    }
}
