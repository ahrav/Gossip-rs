//! PostgreSQL-backed implementation of the persistence [`FindingsSink`] trait.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use gossip_contracts::{
    identity::{FindingId, ObservationId, OccurrenceId, TenantId},
    persistence::{
        CommitHandle, DurableFindingsCounts, FindingRecord, FindingsCommitReceipt,
        FindingsConformanceProbe, FindingsSink, FindingsUpsertBatch, ObservationRecord,
        OccurrenceRecord, PersistenceInputError, RECOMMENDED_MAX_BATCH_SIZE, ReadyCommitHandle,
    },
};
use postgres::{Client, NoTls, Transaction};

use crate::{
    error::{FindingsPgError, FindingsPgSchemaError},
    migrations::apply_all_migrations,
    schema::{
        FINDINGS_INSERT_SQL, FINDINGS_TABLE, FindingRow, OBSERVATIONS_COUNT_SQL,
        OBSERVATIONS_INSERT_OR_MERGE_SQL, ObservationRow, OCCURRENCES_COUNT_SQL,
        OCCURRENCES_INSERT_SQL, OccurrenceRow, SELECT_FINDINGS_COUNT_SQL, TRUNCATE_ALL_SQL,
    },
};

/// Synchronous PostgreSQL MVP backend for [`FindingsSink`].
///
/// The backend owns a single `postgres::Client` protected by a mutex. That is
/// intentional: the returned [`ReadyCommitHandle`] establishes durability only
/// after the enclosing SQL transaction commits.
#[derive(Clone)]
pub struct FindingsSinkPg {
    inner: Arc<Mutex<Client>>,
}

impl FindingsSinkPg {
    /// Connect to PostgreSQL without applying migrations.
    pub fn connect(database_url: &str) -> Result<Self, FindingsPgError> {
        let client = Client::connect(database_url, NoTls)?;
        Ok(Self::from_client(client))
    }

    /// Connect to PostgreSQL and apply embedded findings migrations.
    pub fn connect_and_migrate(database_url: &str) -> Result<Self, FindingsPgError> {
        let client = Client::connect(database_url, NoTls)?;
        let backend = Self::from_client(client);
        backend.apply_migrations()?;
        Ok(backend)
    }

    /// Construct from an already-connected synchronous client.
    #[inline]
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self {
            inner: Arc::new(Mutex::new(client)),
        }
    }

    /// Apply embedded migrations on the held connection.
    pub fn apply_migrations(&self) -> Result<(), FindingsPgError> {
        let mut client = self.lock_client()?;
        apply_all_migrations(&mut client)?;
        Ok(())
    }

    /// Validate the current connection with a simple no-op query.
    pub fn validate_connection(&self, timeout: Duration) -> Result<(), FindingsPgError> {
        let mut client = self.lock_client()?;
        client.is_valid(timeout)?;
        Ok(())
    }

    /// Remove all durable findings rows. Intended for integration tests.
    #[doc(hidden)]
    pub fn truncate_all_for_tests(&self) -> Result<(), FindingsPgError> {
        let mut client = self.lock_client()?;
        client.batch_execute(TRUNCATE_ALL_SQL)?;
        Ok(())
    }

    fn lock_client(&self) -> Result<std::sync::MutexGuard<'_, Client>, FindingsPgError> {
        self.inner.lock().map_err(|_| FindingsPgError::MutexPoisoned)
    }
}

impl fmt::Debug for FindingsSinkPg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FindingsSinkPg").finish_non_exhaustive()
    }
}

impl FindingsSink for FindingsSinkPg {
    type Error = FindingsPgError;
    type CommitHandle = ReadyCommitHandle<FindingsCommitReceipt, FindingsPgError>;

    fn upsert_batch(
        &self,
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<Self::CommitHandle, Self::Error> {
        if batch.total_records() > RECOMMENDED_MAX_BATCH_SIZE {
            return Err(FindingsPgError::BatchTooLarge {
                len: batch.total_records(),
                max: RECOMMENDED_MAX_BATCH_SIZE,
            });
        }
        if batch.is_empty() {
            return Ok(ReadyCommitHandle::ok(FindingsCommitReceipt::new(0, 0, 0)));
        }

        let projected = project_and_dedupe(batch)?;
        let mut client = self.lock_client()?;
        let mut tx = client.transaction()?;

        for row in &projected.findings {
            execute_finding_upsert(&mut tx, row)?;
        }
        for row in &projected.occurrences {
            execute_occurrence_upsert(&mut tx, row)?;
        }
        for row in &projected.observations {
            execute_observation_upsert(&mut tx, row)?;
        }

        tx.commit()?;

        Ok(ReadyCommitHandle::ok(FindingsCommitReceipt::new(
            projected.findings.len() as u64,
            projected.occurrences.len() as u64,
            projected.observations.len() as u64,
        )))
    }
}

impl FindingsConformanceProbe for FindingsSinkPg {
    type Error = FindingsPgError;

    fn durable_counts(&self) -> Result<DurableFindingsCounts, Self::Error> {
        let mut client = self.lock_client()?;
        let findings = read_count(&mut client, SELECT_FINDINGS_COUNT_SQL, FINDINGS_TABLE)?;
        let occurrences = read_count(
            &mut client,
            OCCURRENCES_COUNT_SQL,
            crate::schema::OCCURRENCES_TABLE,
        )?;
        let observations = read_count(
            &mut client,
            OBSERVATIONS_COUNT_SQL,
            crate::schema::OBSERVATIONS_TABLE,
        )?;
        Ok(DurableFindingsCounts::new(
            findings,
            occurrences,
            observations,
        ))
    }
}

fn read_count(
    client: &mut Client,
    sql: &str,
    table: &'static str,
) -> Result<u64, FindingsPgError> {
    let row = client.query_one(sql, &[])?;
    let value: i64 = row.get(0);
    if value < 0 {
        return Err(FindingsPgError::CountOutOfRange { table, value });
    }
    Ok(value as u64)
}

fn project_and_dedupe(batch: FindingsUpsertBatch<'_>) -> Result<DedupedBatch, FindingsPgError> {
    batch
        .validate_observation_identity()
        .map_err(FindingsPgSchemaError::from)?;
    ensure_consistent_tenant(batch).map_err(FindingsPgSchemaError::from)?;

    let mut findings_map: HashMap<([u8; 32], [u8; 32]), FindingRow> =
        HashMap::with_capacity(batch.findings().len());
    let mut findings_order = Vec::with_capacity(batch.findings().len());
    for record in batch.findings() {
        let row = FindingRow::from_record(record);
        let key = (row.tenant_id, row.finding_id);
        match findings_map.entry(key) {
            Entry::Vacant(slot) => {
                findings_order.push(key);
                slot.insert(row);
            }
            Entry::Occupied(slot) => {
                if slot.get() != &row {
                    return Err(FindingsPgError::FindingConflict {
                        tenant_id: record.tenant_id(),
                        finding_id: record.finding_id(),
                    });
                }
            }
        }
    }

    let mut occurrences_map: HashMap<([u8; 32], [u8; 32]), OccurrenceRow> =
        HashMap::with_capacity(batch.occurrences().len());
    let mut occurrences_order = Vec::with_capacity(batch.occurrences().len());
    for record in batch.occurrences() {
        let row = OccurrenceRow::from_record(record).map_err(FindingsPgSchemaError::from)?;
        let key = (row.tenant_id, row.occurrence_id);
        match occurrences_map.entry(key) {
            Entry::Vacant(slot) => {
                occurrences_order.push(key);
                slot.insert(row);
            }
            Entry::Occupied(slot) => {
                if slot.get() != &row {
                    return Err(FindingsPgError::OccurrenceConflict {
                        tenant_id: record.tenant_id(),
                        occurrence_id: record.occurrence_id(),
                    });
                }
            }
        }
    }

    let mut observations_map: HashMap<([u8; 32], [u8; 32]), ObservationRow> =
        HashMap::with_capacity(batch.observations().len());
    let mut observations_order = Vec::with_capacity(batch.observations().len());
    for record in batch.observations() {
        let row = ObservationRow::from_record(record).map_err(FindingsPgSchemaError::from)?;
        let key = (row.tenant_id, row.observation_id);
        match observations_map.entry(key) {
            Entry::Vacant(slot) => {
                observations_order.push(key);
                slot.insert(row);
            }
            Entry::Occupied(mut slot) => {
                let merged = merge_observation_rows(slot.get(), &row).map_err(|_| {
                    FindingsPgError::ObservationConflict {
                        tenant_id: record.tenant_id(),
                        observation_id: record.observation_id(),
                    }
                })?;
                slot.insert(merged);
            }
        }
    }

    Ok(DedupedBatch {
        findings: findings_order
            .into_iter()
            .map(|key| {
                findings_map
                    .remove(&key)
                    .expect("findings dedupe map and order diverged")
            })
            .collect(),
        occurrences: occurrences_order
            .into_iter()
            .map(|key| {
                occurrences_map
                    .remove(&key)
                    .expect("occurrences dedupe map and order diverged")
            })
            .collect(),
        observations: observations_order
            .into_iter()
            .map(|key| {
                observations_map
                    .remove(&key)
                    .expect("observations dedupe map and order diverged")
            })
            .collect(),
    })
}

fn ensure_consistent_tenant(batch: FindingsUpsertBatch<'_>) -> Result<(), PersistenceInputError> {
    let expected = batch
        .findings()
        .first()
        .map(FindingRecord::tenant_id)
        .or_else(|| batch.occurrences().first().map(OccurrenceRecord::tenant_id))
        .or_else(|| batch.observations().first().map(ObservationRecord::tenant_id));

    if let Some(expected) = expected {
        for finding in batch.findings() {
            if finding.tenant_id() != expected {
                return Err(PersistenceInputError::InconsistentTenant);
            }
        }
        for occurrence in batch.occurrences() {
            if occurrence.tenant_id() != expected {
                return Err(PersistenceInputError::InconsistentTenant);
            }
        }
        for observation in batch.observations() {
            if observation.tenant_id() != expected {
                return Err(PersistenceInputError::InconsistentTenant);
            }
        }
    }

    Ok(())
}

fn execute_finding_upsert(
    tx: &mut Transaction<'_>,
    row: &FindingRow,
) -> Result<(), FindingsPgError> {
    let tenant_bytes: &[u8] = &row.tenant_id[..];
    let finding_bytes: &[u8] = &row.finding_id[..];
    let stable_item_bytes: &[u8] = &row.stable_item_id[..];
    let rule_bytes: &[u8] = &row.rule_fingerprint[..];
    let secret_bytes: &[u8] = &row.secret_hash[..];

    let inserted = tx.query_opt(
        FINDINGS_INSERT_SQL,
        &[
            &tenant_bytes,
            &finding_bytes,
            &stable_item_bytes,
            &rule_bytes,
            &secret_bytes,
        ],
    )?;

    if inserted.is_none() {
        return Err(FindingsPgError::FindingConflict {
            tenant_id: TenantId::from_bytes(row.tenant_id),
            finding_id: FindingId::from_bytes(row.finding_id),
        });
    }
    Ok(())
}

fn execute_occurrence_upsert(
    tx: &mut Transaction<'_>,
    row: &OccurrenceRow,
) -> Result<(), FindingsPgError> {
    let tenant_bytes: &[u8] = &row.tenant_id[..];
    let occurrence_bytes: &[u8] = &row.occurrence_id[..];
    let finding_bytes: &[u8] = &row.finding_id[..];
    let version_bytes: &[u8] = &row.object_version_id[..];

    let inserted = tx.query_opt(
        OCCURRENCES_INSERT_SQL,
        &[
            &tenant_bytes,
            &occurrence_bytes,
            &finding_bytes,
            &version_bytes,
            &row.byte_offset,
            &row.byte_length,
        ],
    )?;

    if inserted.is_none() {
        return Err(FindingsPgError::OccurrenceConflict {
            tenant_id: TenantId::from_bytes(row.tenant_id),
            occurrence_id: OccurrenceId::from_bytes(row.occurrence_id),
        });
    }
    Ok(())
}

fn execute_observation_upsert(
    tx: &mut Transaction<'_>,
    row: &ObservationRow,
) -> Result<(), FindingsPgError> {
    let tenant_bytes: &[u8] = &row.tenant_id[..];
    let observation_bytes: &[u8] = &row.observation_id[..];
    let occurrence_bytes: &[u8] = &row.occurrence_id[..];
    let policy_bytes: &[u8] = &row.policy_hash[..];
    let ovid_bytes: &[u8] = &row.ovid_hash[..];

    let inserted = tx.query_opt(
        OBSERVATIONS_INSERT_OR_MERGE_SQL,
        &[
            &tenant_bytes,
            &observation_bytes,
            &occurrence_bytes,
            &policy_bytes,
            &ovid_bytes,
            &row.run_id,
            &row.shard_id,
            &row.fence_epoch,
            &row.seen_at,
            &row.location_display,
            &row.location_url,
        ],
    )?;

    if inserted.is_none() {
        return Err(FindingsPgError::ObservationConflict {
            tenant_id: TenantId::from_bytes(row.tenant_id),
            observation_id: ObservationId::from_bytes(row.observation_id),
        });
    }
    Ok(())
}

fn merge_observation_rows(
    existing: &ObservationRow,
    incoming: &ObservationRow,
) -> Result<ObservationRow, ()> {
    if existing.tenant_id != incoming.tenant_id
        || existing.observation_id != incoming.observation_id
        || existing.occurrence_id != incoming.occurrence_id
        || existing.policy_hash != incoming.policy_hash
        || existing.ovid_hash != incoming.ovid_hash
    {
        return Err(());
    }

    let incoming_has_location = incoming.location_display.is_some();
    let existing_has_location = existing.location_display.is_some();
    let use_incoming_provenance = incoming.seen_at > existing.seen_at
        || (incoming.seen_at == existing.seen_at && !existing_has_location && incoming_has_location);

    Ok(ObservationRow {
        tenant_id: existing.tenant_id,
        observation_id: existing.observation_id,
        occurrence_id: existing.occurrence_id,
        policy_hash: existing.policy_hash,
        ovid_hash: existing.ovid_hash,
        run_id: if use_incoming_provenance {
            incoming.run_id
        } else {
            existing.run_id
        },
        shard_id: if use_incoming_provenance {
            incoming.shard_id
        } else {
            existing.shard_id
        },
        fence_epoch: if use_incoming_provenance {
            incoming.fence_epoch
        } else {
            existing.fence_epoch
        },
        seen_at: existing.seen_at.max(incoming.seen_at),
        location_display: if use_incoming_provenance {
            incoming
                .location_display
                .clone()
                .or_else(|| existing.location_display.clone())
        } else {
            existing
                .location_display
                .clone()
                .or_else(|| incoming.location_display.clone())
        },
        location_url: if use_incoming_provenance {
            incoming
                .location_url
                .clone()
                .or_else(|| existing.location_url.clone())
        } else {
            existing
                .location_url
                .clone()
                .or_else(|| incoming.location_url.clone())
        },
    })
}

struct DedupedBatch {
    findings: Vec<FindingRow>,
    occurrences: Vec<OccurrenceRow>,
    observations: Vec<ObservationRow>,
}
