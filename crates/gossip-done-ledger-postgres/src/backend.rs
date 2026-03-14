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
//! ## Bulk upsert
//!
//! `batch_upsert` sends a single SQL statement per call by using
//! `INSERT ... SELECT * FROM unnest($1::bytea[], ...) ON CONFLICT`.
//! Column-parallel arrays (one per schema column) are passed as 12 array
//! parameters; `unnest()` expands them into rows on the server side.
//! This avoids N round-trips for N records and sidesteps the PostgreSQL
//! 65,535 bind-parameter limit that a dynamic multi-row `VALUES` clause
//! would hit at ~5,400 rows (12 params x 5,461).
//!
//! ## Duplicate-key handling
//!
//! When a single `batch_upsert` call contains multiple records with the same
//! [`DoneLedgerKey`], the backend folds them in submission order using the
//! same lattice-merge rules as the SQL `ON CONFLICT` clause (see
//! [`UPSERT_SQL`]). This ensures that the array parameters contain at most
//! one entry per distinct key.
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
};

use gossip_contracts::{
    identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
    persistence::{
        DoneLedger, DoneLedgerCommitReceipt, DoneLedgerErrorCode, DoneLedgerKey,
        DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus, OvidHash,
        RECOMMENDED_MAX_BATCH_SIZE, ReadyCommitHandle,
    },
};
#[cfg(feature = "test-utils")]
use postgres::NoTls;
use postgres::{Client, Row};

use crate::{
    error::{DoneLedgerPgConversionError, DoneLedgerPgError},
    migrations::apply_all_migrations,
    schema::{BATCH_GET_SQL, UPSERT_SQL},
    types::{
        decode_fixed_32, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
        u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
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

    /// Remove all rows from the done-ledger table.
    ///
    /// This helper is intended for crate-local integration tests.
    #[cfg(test)]
    pub(crate) fn truncate_all_for_tests(&self) -> Result<(), DoneLedgerPgError> {
        let mut client = self.lock_client()?;
        client.batch_execute(&format!(
            "DELETE FROM {}",
            crate::schema::DONE_LEDGER_ENTRIES_TABLE
        ))?;
        Ok(())
    }

    /// Acquire the internal mutex, returning `MutexPoisoned` if a prior
    /// holder panicked.
    ///
    /// Poisoning is treated as terminal because the connection's internal
    /// state (prepared statements, transaction nesting) is indeterminate
    /// after a panic during SQL execution. Attempting to reuse a
    /// potentially half-committed connection risks silent data corruption.
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
        let columns = collect_columns(&merged)?;
        let mut client = self.lock_client()?;
        let mut tx = client.transaction()?;
        let stmt = tx.prepare(UPSERT_SQL)?;

        tx.execute(
            &stmt,
            &[
                &columns.tenant_ids as &(dyn postgres::types::ToSql + Sync),
                &columns.policy_hashes,
                &columns.ovid_hashes,
                &columns.statuses,
                &columns.bytes_scanned,
                &columns.findings_counts,
                &columns.run_ids,
                &columns.shard_ids,
                &columns.fence_epochs,
                &columns.started_ats,
                &columns.finished_ats,
                &columns.error_codes,
            ],
        )?;

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
/// are folded into that slot via [`DoneLedgerRecord::merge`], so persistence
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
                let merged_record = slot
                    .get()
                    .merge(record)
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

/// Columnar representation of a deduplicated record batch, ready for
/// binding to the `unnest()`-based [`UPSERT_SQL`] statement.
///
/// Each field is a `Vec` whose length equals the number of distinct keys
/// in the batch. The vectors are positionally aligned: element `i` across
/// all vectors describes the same logical row.
struct UpsertColumns {
    tenant_ids: Vec<Vec<u8>>,
    policy_hashes: Vec<Vec<u8>>,
    ovid_hashes: Vec<Vec<u8>>,
    statuses: Vec<i16>,
    bytes_scanned: Vec<i64>,
    findings_counts: Vec<i32>,
    run_ids: Vec<i64>,
    shard_ids: Vec<i64>,
    fence_epochs: Vec<i64>,
    started_ats: Vec<i64>,
    finished_ats: Vec<i64>,
    error_codes: Vec<Option<String>>,
}

/// Transpose a slice of validated `DoneLedgerRecord`s into column-parallel
/// arrays suitable for PostgreSQL array parameters.
///
/// Identity fields (`run_id`, `shard_id`) are encoded in bit-pattern mode;
/// ordered fields (`bytes_scanned`, `fence_epoch`, `started_at`,
/// `finished_at`) use checked non-negative mode. See [`crate::types`] for
/// the distinction.
fn collect_columns(records: &[DoneLedgerRecord]) -> Result<UpsertColumns, DoneLedgerPgError> {
    let n = records.len();
    let mut cols = UpsertColumns {
        tenant_ids: Vec::with_capacity(n),
        policy_hashes: Vec::with_capacity(n),
        ovid_hashes: Vec::with_capacity(n),
        statuses: Vec::with_capacity(n),
        bytes_scanned: Vec::with_capacity(n),
        findings_counts: Vec::with_capacity(n),
        run_ids: Vec::with_capacity(n),
        shard_ids: Vec::with_capacity(n),
        fence_epochs: Vec::with_capacity(n),
        started_ats: Vec::with_capacity(n),
        finished_ats: Vec::with_capacity(n),
        error_codes: Vec::with_capacity(n),
    };

    for (idx, record) in records.iter().enumerate() {
        let key = record.key();
        let prov = record.provenance();

        cols.tenant_ids.push(key.tenant_id().as_bytes().to_vec());
        cols.policy_hashes
            .push(key.policy_hash().as_bytes().to_vec());
        cols.ovid_hashes.push(key.ovid_hash().as_bytes().to_vec());

        cols.statuses.push(i16::from(record.status().rank()));

        cols.bytes_scanned.push(
            u64_to_pg_bigint_checked(record.bytes_scanned(), "bytes_scanned").map_err(|e| {
                DoneLedgerPgError::Conversion {
                    record_index: Some(idx),
                    source: e.into(),
                }
            })?,
        );

        cols.findings_counts
            .push(i32::try_from(record.findings_count()).map_err(|_| {
                DoneLedgerPgError::Conversion {
                    record_index: Some(idx),
                    source: DoneLedgerPgConversionError::FindingsCountOutOfRange {
                        value: i64::from(record.findings_count()),
                    },
                }
            })?);

        cols.run_ids
            .push(u64_to_pg_bigint_bits(prov.run_id().as_raw()));
        cols.shard_ids
            .push(u64_to_pg_bigint_bits(prov.shard_id().as_raw()));

        cols.fence_epochs.push(
            u64_to_pg_bigint_checked(prov.fence_epoch().as_raw(), "fence_epoch").map_err(|e| {
                DoneLedgerPgError::Conversion {
                    record_index: Some(idx),
                    source: e.into(),
                }
            })?,
        );
        cols.started_ats.push(
            u64_to_pg_bigint_checked(prov.started_at().as_raw(), "started_at").map_err(|e| {
                DoneLedgerPgError::Conversion {
                    record_index: Some(idx),
                    source: e.into(),
                }
            })?,
        );
        cols.finished_ats.push(
            u64_to_pg_bigint_checked(prov.finished_at().as_raw(), "finished_at").map_err(|e| {
                DoneLedgerPgError::Conversion {
                    record_index: Some(idx),
                    source: e.into(),
                }
            })?,
        );

        cols.error_codes
            .push(record.error_code().map(|c| c.as_str().to_owned()));
    }

    Ok(cols)
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
/// type for `row.try_get`). This is a WARM-path cost accepted for simplicity;
/// a crate-local newtype with a `FromSql` impl would eliminate 3
/// allocations per row if profiling shows this is material.
fn decode_row(row: &Row) -> Result<DoneLedgerRecord, DoneLedgerPgError> {
    let tenant_id = TenantId::from_bytes(decode_fixed_32(
        row.try_get::<_, &[u8]>("tenant_id")?,
        "tenant_id",
    )?);
    let policy_hash = PolicyHash::from_bytes(decode_fixed_32(
        row.try_get::<_, &[u8]>("policy_hash")?,
        "policy_hash",
    )?);
    let ovid_hash = OvidHash::from_bytes(decode_fixed_32(
        row.try_get::<_, &[u8]>("ovid_hash")?,
        "ovid_hash",
    )?);

    let status_rank: i16 = row.try_get("status")?;
    let status_rank_u8 = u8::try_from(status_rank)
        .map_err(|_| DoneLedgerPgConversionError::UnknownStatusRank { rank: status_rank })?;
    let status = DoneLedgerStatus::from_rank(status_rank_u8)
        .ok_or(DoneLedgerPgConversionError::UnknownStatusRank { rank: status_rank })?;

    let bytes_scanned =
        pg_bigint_nonnegative_to_u64(row.try_get("bytes_scanned")?, "bytes_scanned")
            .map_err(DoneLedgerPgConversionError::from)?;

    let findings_count_raw: i32 = row.try_get("findings_count")?;
    let findings_count = u32::try_from(findings_count_raw).map_err(|_| {
        DoneLedgerPgConversionError::FindingsCountOutOfRange {
            value: i64::from(findings_count_raw),
        }
    })?;

    let run_id = RunId::from_raw(pg_bigint_to_u64_bits(row.try_get("run_id")?));
    let shard_id = ShardId::from_raw(pg_bigint_to_u64_bits(row.try_get("shard_id")?));
    let fence_epoch = FenceEpoch::from_raw(
        pg_bigint_nonnegative_to_u64(row.try_get("fence_epoch")?, "fence_epoch")
            .map_err(DoneLedgerPgConversionError::from)?,
    );
    let started_at = LogicalTime::from_raw(
        pg_bigint_nonnegative_to_u64(row.try_get("started_at")?, "started_at")
            .map_err(DoneLedgerPgConversionError::from)?,
    );
    let finished_at = LogicalTime::from_raw(
        pg_bigint_nonnegative_to_u64(row.try_get("finished_at")?, "finished_at")
            .map_err(DoneLedgerPgConversionError::from)?,
    );

    let error_code = row
        .try_get::<_, Option<String>>("error_code")?
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

#[cfg(test)]
mod tests {
    use super::dedupe_and_validate;
    use gossip_contracts::{persistence::DoneLedgerStatus, test_util::done_record};

    #[test]
    fn collect_columns_conversion_error_identifies_failing_record_index() {
        // A record with bytes_scanned > i64::MAX passes domain validation
        // but fails SQL type conversion in collect_columns. The error
        // should identify which record in the batch caused the failure.
        let good = done_record(
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
        let bad = done_record(
            1,
            1,
            2,
            DoneLedgerStatus::ScannedClean,
            u64::MAX, // exceeds i64::MAX → conversion failure
            0,
            1,
            1,
            1,
            10,
            20,
            None,
        );

        let err = super::collect_columns(&[good, bad])
            .err()
            .expect("bytes_scanned = u64::MAX should fail SQL type conversion");
        let msg = err.to_string();
        assert!(
            msg.contains("index 1"),
            "conversion error should identify the failing record at index 1, got: {msg}"
        );
    }

    #[test]
    fn dedupe_and_validate_merges_duplicate_keys_in_submission_order() {
        let key_a_failed = done_record(
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
        let key_b_scanned = done_record(
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
        let key_a_scanned = done_record(
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
