//! PostgreSQL-backed implementation of the persistence [`DoneLedger`] trait.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use gossip_contracts::{
    identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
    persistence::{
        DoneLedger, DoneLedgerCommitReceipt, DoneLedgerErrorCode, DoneLedgerKey,
        DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus, OvidHash,
        RECOMMENDED_MAX_BATCH_SIZE, ReadyCommitHandle,
    },
};
use postgres::{Client, NoTls, Row};

use crate::{
    error::{DoneLedgerPgConversionError, DoneLedgerPgError},
    migrations::apply_all_migrations,
    schema::{DONE_LEDGER_ENTRIES_TABLE, SELECT_ONE_SQL, UPSERT_SQL},
};

/// Synchronous PostgreSQL MVP backend for [`DoneLedger`].
///
/// The backend owns a single `postgres::Client` protected by a mutex.
/// That gives correct `&self` semantics without hidden background threads:
/// writes are fully committed before a [`ReadyCommitHandle`] is returned.
#[derive(Clone)]
pub struct DoneLedgerPg {
    inner: Arc<Mutex<Client>>,
}

impl DoneLedgerPg {
    /// Connect to PostgreSQL without applying migrations.
    pub fn connect(database_url: &str) -> Result<Self, DoneLedgerPgError> {
        let client = Client::connect(database_url, NoTls)?;
        Ok(Self::from_client(client))
    }

    /// Connect to PostgreSQL and apply the embedded schema migrations.
    pub fn connect_and_migrate(database_url: &str) -> Result<Self, DoneLedgerPgError> {
        let client = Client::connect(database_url, NoTls)?;
        let backend = Self::from_client(client);
        backend.apply_migrations()?;
        Ok(backend)
    }

    /// Construct the backend from an already-connected `postgres::Client`.
    #[inline]
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self {
            inner: Arc::new(Mutex::new(client)),
        }
    }

    /// Apply embedded migrations on the held connection.
    pub fn apply_migrations(&self) -> Result<(), DoneLedgerPgError> {
        let mut client = self.lock_client()?;
        apply_all_migrations(&mut *client)?;
        Ok(())
    }

    /// Validate the current connection with a simple no-op query.
    pub fn validate_connection(&self, timeout: Duration) -> Result<(), DoneLedgerPgError> {
        let mut client = self.lock_client()?;
        client.is_valid(timeout)?;
        Ok(())
    }

    /// Remove all durable rows. Intended for crate-local live tests.
    pub(crate) fn truncate_all_for_tests(&self) -> Result<(), DoneLedgerPgError> {
        let mut client = self.lock_client()?;
        client.batch_execute(&format!("TRUNCATE TABLE {DONE_LEDGER_ENTRIES_TABLE}"))?;
        Ok(())
    }

    fn lock_client(&self) -> Result<std::sync::MutexGuard<'_, Client>, DoneLedgerPgError> {
        self.inner.lock().map_err(|_| DoneLedgerPgError::MutexPoisoned)
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

        let tenant_bytes: &[u8] = &tenant_id.as_bytes()[..];
        let policy_bytes: &[u8] = &policy_hash.as_bytes()[..];
        let mut client = self.lock_client()?;
        let mut out = Vec::with_capacity(ovid_hashes.len());

        for ovid_hash in ovid_hashes {
            let ovid_bytes: &[u8] = &ovid_hash.as_bytes()[..];
            let row = client.query_opt(
                SELECT_ONE_SQL,
                &[&tenant_bytes, &policy_bytes, &ovid_bytes],
            )?;
            match row {
                Some(row) => out.push(Some(decode_row(&row)?)),
                None => out.push(None),
            }
        }
        Ok(out)
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

        for record in &merged {
            execute_upsert(&mut tx, record)?;
        }
        tx.commit()?;

        let receipt = DoneLedgerCommitReceipt::new(
            merged.len() as u64,
            merged.iter().filter(|record| record.status().is_scanned()).count() as u64,
            merged
                .iter()
                .fold(0u64, |acc, record| acc.saturating_add(record.findings_count() as u64)),
        );
        Ok(ReadyCommitHandle::ok(receipt))
    }
}

fn dedupe_and_validate(records: &[DoneLedgerRecord]) -> Result<Vec<DoneLedgerRecord>, DoneLedgerPgError> {
    let mut merged: HashMap<DoneLedgerKey, DoneLedgerRecord> = HashMap::with_capacity(records.len());
    let mut order: Vec<DoneLedgerKey> = Vec::new();

    for (index, record) in records.iter().enumerate() {
        record
            .validate()
            .map_err(|source| DoneLedgerPgError::InvalidRecord { index, source })?;
        match merged.entry(record.key()) {
            Entry::Vacant(slot) => {
                order.push(record.key());
                slot.insert(record.clone());
            }
            Entry::Occupied(mut slot) => {
                let merged_record = record.clone().merge_with(slot.get());
                slot.insert(merged_record);
            }
        }
    }

    Ok(order
        .into_iter()
        .map(|key| merged.remove(&key).expect("dedupe map and order vector diverged"))
        .collect())
}

fn execute_upsert(
    tx: &mut postgres::Transaction<'_>,
    record: &DoneLedgerRecord,
) -> Result<(), DoneLedgerPgError> {
    let tenant_id = record.key().tenant_id();
    let policy_hash = record.key().policy_hash();
    let ovid_hash = record.key().ovid_hash();
    let status = i16::from(record.status().rank());
    let bytes_scanned = u64_to_nonnegative_i64(record.bytes_scanned(), "bytes_scanned")?;
    let findings_count = i32::try_from(record.findings_count())
        .map_err(|_| DoneLedgerPgConversionError::FindingsCountTooLarge {
            value: record.findings_count(),
        })?;
    let provenance = record.provenance();
    let run_id = u64_to_i64_bits(provenance.run_id().as_raw());
    let shard_id = u64_to_i64_bits(provenance.shard_id().as_raw());
    let fence_epoch = u64_to_nonnegative_i64(provenance.fence_epoch().as_raw(), "fence_epoch")?;
    let started_at = u64_to_nonnegative_i64(provenance.started_at().as_raw(), "started_at")?;
    let finished_at = u64_to_nonnegative_i64(provenance.finished_at().as_raw(), "finished_at")?;
    let error_code = record.error_code().map(DoneLedgerErrorCode::as_str);

    let tenant_bytes: &[u8] = &tenant_id.as_bytes()[..];
    let policy_bytes: &[u8] = &policy_hash.as_bytes()[..];
    let ovid_bytes: &[u8] = &ovid_hash.as_bytes()[..];

    tx.execute(
        UPSERT_SQL,
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

fn decode_row(row: &Row) -> Result<DoneLedgerRecord, DoneLedgerPgError> {
    let tenant_id = TenantId::from_bytes(decode_32(row.get("tenant_id"), "tenant_id")?);
    let policy_hash = PolicyHash::from_bytes(decode_32(row.get("policy_hash"), "policy_hash")?);
    let ovid_hash = OvidHash::from_bytes(decode_32(row.get("ovid_hash"), "ovid_hash")?);

    let status_rank: i16 = row.get("status");
    let status = DoneLedgerStatus::from_rank(u8::try_from(status_rank).map_err(|_| {
        DoneLedgerPgConversionError::UnknownStatusRank { rank: status_rank }
    })?)
    .ok_or(DoneLedgerPgConversionError::UnknownStatusRank { rank: status_rank })?;

    let bytes_scanned = nonnegative_i64_to_u64(row.get("bytes_scanned"), "bytes_scanned")?;

    let findings_count_i32: i32 = row.get("findings_count");
    let findings_count = u32::try_from(findings_count_i32).map_err(|_| {
        DoneLedgerPgConversionError::FindingsCountOutOfRange {
            value: findings_count_i32,
        }
    })?;

    let run_id_bits: i64 = row.get("run_id");
    let shard_id_bits: i64 = row.get("shard_id");
    let fence_epoch = FenceEpoch::from_raw(nonnegative_i64_to_u64(row.get("fence_epoch"), "fence_epoch")?);
    let started_at = LogicalTime::from_raw(nonnegative_i64_to_u64(row.get("started_at"), "started_at")?);
    let finished_at = LogicalTime::from_raw(nonnegative_i64_to_u64(row.get("finished_at"), "finished_at")?);

    let error_code_text: Option<String> = row.get("error_code");
    let error_code = match error_code_text {
        Some(code) => Some(
            DoneLedgerErrorCode::try_new(code).map_err(|source| {
                DoneLedgerPgError::PersistedRecordInvalid {
                    context: "error_code decode",
                    source,
                }
            })?,
        ),
        None => None,
    };

    let record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
        status,
        bytes_scanned,
        findings_count,
        DoneLedgerProvenance::new(
            RunId::from_raw(i64_bits_to_u64(run_id_bits)),
            ShardId::from_raw(i64_bits_to_u64(shard_id_bits)),
            fence_epoch,
            started_at,
            finished_at,
        ),
        error_code,
    )
    .map_err(|source| DoneLedgerPgError::PersistedRecordInvalid {
        context: "row decode",
        source,
    })?;

    record
        .validate()
        .map_err(|source| DoneLedgerPgError::PersistedRecordInvalid {
            context: "row validate",
            source,
        })?;

    Ok(record)
}

fn decode_32(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 32], DoneLedgerPgError> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        DoneLedgerPgConversionError::InvalidByteLength {
            field,
            expected: 32,
            actual: bytes.len(),
        }
        .into()
    })
}

#[inline]
fn u64_to_i64_bits(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
fn i64_bits_to_u64(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

#[inline]
fn u64_to_nonnegative_i64(
    value: u64,
    field: &'static str,
) -> Result<i64, DoneLedgerPgError> {
    i64::try_from(value)
        .map_err(|_| DoneLedgerPgConversionError::OutOfRangeForBigInt { field, value }.into())
}

#[inline]
fn nonnegative_i64_to_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, DoneLedgerPgError> {
    if value < 0 {
        return Err(DoneLedgerPgConversionError::NegativeStoredValue { field, value }.into());
    }
    Ok(value as u64)
}

