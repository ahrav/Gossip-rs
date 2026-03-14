//! PostgreSQL findings backend and Rust-side batch preprocessing helpers.
//!
//! The PostgreSQL backend folds duplicate rows within a single submitted batch
//! before issuing SQL so `INSERT ... ON CONFLICT` sees at most one row per
//! durable primary key. Observation duplicates use the same winner-selection
//! rules as [`crate::schema::OBSERVATIONS_INSERT_OR_MERGE_SQL`] so Rust-side
//! pre-processing and SQL-side replay converge on the same durable row.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    hash::Hash,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use gossip_contracts::{
    identity::{FindingId, ObservationId, OccurrenceId, PolicyHash, StableItemId, TenantId},
    persistence::{
        DurableFindingsCounts, FindingsCommitReceipt, FindingsConformanceProbe, FindingsSink,
        FindingsUpsertBatch, RECOMMENDED_MAX_BATCH_SIZE, ReadyCommitHandle,
    },
};
#[cfg(feature = "test-utils")]
use postgres::NoTls;
use postgres::{Client, Statement, Transaction};

use crate::{
    error::{FindingsPgError, FindingsPgSchemaError},
    migrations::apply_all_migrations,
    read_api::{ObservationCountByPolicy, PendingTriageFinding},
    schema::{
        COMBINED_COUNTS_SQL, COUNT_OBSERVATIONS_BY_TENANT_POLICY_SQL, FINDINGS_INSERT_SQL,
        FINDINGS_TABLE, FindingRow, LIST_FINDINGS_NEEDING_TRIAGE_SQL,
        OBSERVATIONS_INSERT_OR_MERGE_SQL, OBSERVATIONS_TABLE, OCCURRENCES_INSERT_SQL,
        OCCURRENCES_TABLE, ObservationRow, OccurrenceRow,
    },
    types::decode_fixed_32,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DedupedBatch {
    pub(crate) findings: Vec<FindingRow>,
    pub(crate) occurrences: Vec<OccurrenceRow>,
    pub(crate) observations: Vec<ObservationRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MergeIdentityMismatch {
    pub(crate) tenant_id: [u8; 32],
    pub(crate) observation_id: [u8; 32],
}

pub(crate) fn project_and_dedupe(
    batch: FindingsUpsertBatch<'_>,
) -> Result<DedupedBatch, FindingsPgError> {
    batch
        .validate_observation_identity()
        .map_err(FindingsPgSchemaError::Persistence)?;
    batch
        .validate_tenant_consistency()
        .map_err(FindingsPgSchemaError::Persistence)?;

    let findings = batch
        .findings()
        .iter()
        .map(FindingRow::from_record)
        .collect::<Vec<_>>();
    let occurrences = batch
        .occurrences()
        .iter()
        .map(OccurrenceRow::from_record)
        .collect::<Result<Vec<_>, _>>()?;
    let observations = batch
        .observations()
        .iter()
        .map(ObservationRow::from_record)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DedupedBatch {
        findings: dedupe_findings_rows(&findings)?,
        occurrences: dedupe_occurrence_rows(&occurrences)?,
        observations: dedupe_observation_rows(&observations)?,
    })
}

fn dedupe_findings_rows(rows: &[FindingRow]) -> Result<Vec<FindingRow>, FindingsPgError> {
    let mut merged: HashMap<([u8; 32], [u8; 32]), FindingRow> = HashMap::with_capacity(rows.len());
    let mut order: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(rows.len());

    for row in rows {
        let key = (row.tenant_id, row.finding_id);
        match merged.entry(key) {
            Entry::Vacant(slot) => {
                order.push(key);
                slot.insert(row.clone());
            }
            Entry::Occupied(slot) => {
                if slot.get() != row {
                    return Err(FindingsPgError::FindingConflict {
                        tenant_id: TenantId::from_bytes(row.tenant_id),
                        finding_id: FindingId::from_bytes(row.finding_id),
                    });
                }
            }
        }
    }

    Ok(drain_in_order(merged, order, "findings"))
}

fn dedupe_occurrence_rows(rows: &[OccurrenceRow]) -> Result<Vec<OccurrenceRow>, FindingsPgError> {
    let mut merged: HashMap<([u8; 32], [u8; 32]), OccurrenceRow> =
        HashMap::with_capacity(rows.len());
    let mut order: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(rows.len());

    for row in rows {
        let key = (row.tenant_id, row.occurrence_id);
        match merged.entry(key) {
            Entry::Vacant(slot) => {
                order.push(key);
                slot.insert(row.clone());
            }
            Entry::Occupied(slot) => {
                if slot.get() != row {
                    return Err(FindingsPgError::OccurrenceConflict {
                        tenant_id: TenantId::from_bytes(row.tenant_id),
                        occurrence_id: OccurrenceId::from_bytes(row.occurrence_id),
                    });
                }
            }
        }
    }

    Ok(drain_in_order(merged, order, "occurrences"))
}

fn dedupe_observation_rows(
    rows: &[ObservationRow],
) -> Result<Vec<ObservationRow>, FindingsPgError> {
    let mut merged: HashMap<([u8; 32], [u8; 32]), ObservationRow> =
        HashMap::with_capacity(rows.len());
    let mut order: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(rows.len());

    for row in rows {
        let key = (row.tenant_id, row.observation_id);
        match merged.entry(key) {
            Entry::Vacant(slot) => {
                order.push(key);
                slot.insert(row.clone());
            }
            Entry::Occupied(mut slot) => {
                let merged_row = merge_observation_rows(slot.get(), row).map_err(|mismatch| {
                    FindingsPgError::ObservationConflict {
                        tenant_id: TenantId::from_bytes(mismatch.tenant_id),
                        observation_id: ObservationId::from_bytes(mismatch.observation_id),
                    }
                })?;
                slot.insert(merged_row);
            }
        }
    }

    Ok(drain_in_order(merged, order, "observations"))
}

/// Merge two observation rows sharing the same primary key.
///
/// Winner selection mirrors [`OBSERVATIONS_INSERT_OR_MERGE_SQL`]: the row with
/// the higher `seen_at` wins provenance fields (`run_id`, `shard_id`,
/// `fence_epoch`). On equal `seen_at`, the row that has a `location_display`
/// wins if the other lacks one (tiebreaker). `seen_at` itself always takes
/// the max. Location fields follow whichever row contributed
/// `location_display` — the URL is never sourced from a different row than
/// the display path.
///
/// ## Merge-rule invariants (must converge with SQL)
///
/// 1. **Provenance winner**: `seen_at >` wins; on tie,
///    `location_display IS NULL` (existing) + `IS NOT NULL` (incoming) wins.
/// 2. **`seen_at`**: always `max(existing, incoming)`.
/// 3. **Provenance triple** `(run_id, shard_id, fence_epoch)`: all three
///    sourced from the winner — never mixed across records.
/// 4. **`location_display`**: sourced from the winner; if the winner lacks
///    it, falls back to the loser.
/// 5. **`location_url`**: follows whichever record contributed
///    `location_display` — never independently sourced from the other record.
///
/// [`OBSERVATIONS_INSERT_OR_MERGE_SQL`]: crate::schema::OBSERVATIONS_INSERT_OR_MERGE_SQL
pub(crate) fn merge_observation_rows(
    existing: &ObservationRow,
    incoming: &ObservationRow,
) -> Result<ObservationRow, MergeIdentityMismatch> {
    if existing.tenant_id != incoming.tenant_id
        || existing.observation_id != incoming.observation_id
        || existing.occurrence_id != incoming.occurrence_id
        || existing.policy_hash != incoming.policy_hash
        || existing.ovid_hash != incoming.ovid_hash
    {
        return Err(MergeIdentityMismatch {
            tenant_id: incoming.tenant_id,
            observation_id: incoming.observation_id,
        });
    }

    let use_incoming_provenance = incoming.seen_at > existing.seen_at
        || (incoming.seen_at == existing.seen_at
            && existing.location_display.is_none()
            && incoming.location_display.is_some());

    let (winner, loser) = if use_incoming_provenance {
        (incoming, existing)
    } else {
        (existing, incoming)
    };

    // URL follows whichever row contributed location_display.
    let location_source = if winner.location_display.is_some() {
        winner
    } else {
        loser
    };

    Ok(ObservationRow {
        tenant_id: existing.tenant_id,
        observation_id: existing.observation_id,
        occurrence_id: existing.occurrence_id,
        policy_hash: existing.policy_hash,
        ovid_hash: existing.ovid_hash,
        run_id: winner.run_id,
        shard_id: winner.shard_id,
        fence_epoch: winner.fence_epoch,
        seen_at: existing.seen_at.max(incoming.seen_at),
        location_display: location_source.location_display.clone(),
        location_url: location_source.location_url.clone(),
    })
}

fn drain_in_order<K, V>(mut map: HashMap<K, V>, order: Vec<K>, layer: &'static str) -> Vec<V>
where
    K: Copy + Eq + Hash,
{
    order
        .into_iter()
        .map(|key| {
            map.remove(&key)
                .unwrap_or_else(|| panic!("{layer} dedupe map and order diverged"))
        })
        .collect()
}

/// Synchronous PostgreSQL implementation of [`FindingsSink`].
///
/// Internally wraps a single `postgres::Client` in `Arc<Mutex<_>>` so clones
/// share one connection. Each `upsert_batch` call executes in a single SQL
/// transaction and only returns a [`ReadyCommitHandle`] after the commit
/// succeeds, making the resulting receipt durable-before-return.
///
/// The mutex is held for the full batch duration — statement preparation,
/// per-row execution, and transaction commit all happen under a single
/// lock acquisition. A connection-pool design would allow concurrent batch
/// execution; this single-connection design serializes all callers.
#[derive(Clone)]
pub struct FindingsSinkPg {
    client: Arc<Mutex<Client>>,
}

impl FindingsSinkPg {
    /// Connect to PostgreSQL without applying migrations.
    ///
    /// Uses `NoTls` and is intended for local development and integration
    /// tests. Production callers should construct their own client with the
    /// desired TLS configuration and pass it to [`from_client`](Self::from_client).
    ///
    /// Requires the `test-utils` feature.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgError::Postgres`] on connection failure.
    #[cfg(feature = "test-utils")]
    pub fn connect(database_url: &str) -> Result<Self, FindingsPgError> {
        let client = Client::connect(database_url, NoTls)?;
        Ok(Self::from_client(client))
    }

    /// Connect to PostgreSQL and apply embedded findings migrations.
    ///
    /// Equivalent to [`connect`](Self::connect) followed by
    /// [`apply_migrations`](Self::apply_migrations). Uses `NoTls`, so it is
    /// intended for tests and local development only.
    ///
    /// Requires the `test-utils` feature.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgError::Postgres`] on connection failure or
    /// [`FindingsPgError::Migration`] if schema migration fails.
    #[cfg(feature = "test-utils")]
    pub fn connect_and_migrate(database_url: &str) -> Result<Self, FindingsPgError> {
        let client = Client::connect(database_url, NoTls)?;
        let backend = Self::from_client(client);
        backend.apply_migrations()?;
        Ok(backend)
    }

    /// Wrap an already-connected PostgreSQL client.
    #[inline]
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
        }
    }

    /// Apply all embedded migrations using the held client.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgError::Migration`] on SQL/checksum failure or
    /// [`FindingsPgError::MutexPoisoned`] if the internal mutex was poisoned.
    pub fn apply_migrations(&self) -> Result<(), FindingsPgError> {
        let mut client = self.lock_client()?;
        apply_all_migrations(&mut client)?;
        Ok(())
    }

    /// Validate the held connection by asking the driver to ping the server.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgError::Postgres`] when the connection is not usable,
    /// or [`FindingsPgError::MutexPoisoned`] if the internal mutex was poisoned.
    pub fn validate_connection(&self, timeout: Duration) -> Result<(), FindingsPgError> {
        let mut client = self.lock_client()?;
        client.is_valid(timeout)?;
        Ok(())
    }

    /// Remove all rows from the durable findings tables.
    ///
    /// Requires the `test-utils` feature because cross-crate integration tests
    /// use this helper to reset backend state between runs.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgError::Postgres`] on SQL failure or
    /// [`FindingsPgError::MutexPoisoned`] if the internal mutex was poisoned.
    #[cfg(feature = "test-utils")]
    pub fn truncate_all_for_tests(&self) -> Result<(), FindingsPgError> {
        let mut client = self.lock_client()?;
        client.batch_execute(crate::schema::TRUNCATE_ALL_SQL)?;
        Ok(())
    }

    /// Count durable observations for one tenant, grouped by policy hash.
    ///
    /// This read path lets validation harnesses and operational tooling inspect
    /// observation volume by policy without reading raw SQL rows.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgError::Postgres`] on query failure,
    /// [`FindingsPgError::ByteDecode`] when a stored identity column is
    /// not 32 bytes, [`FindingsPgError::PgU64Conversion`] when a non-negative
    /// `BIGINT` result is invalid, or [`FindingsPgError::MutexPoisoned`] if the
    /// internal mutex was poisoned.
    pub fn count_observations_by_tenant_policy(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ObservationCountByPolicy>, FindingsPgError> {
        let tenant_bytes = tenant_id.as_bytes().as_slice();
        let mut client = self.lock_client()?;
        let stmt = client.prepare(COUNT_OBSERVATIONS_BY_TENANT_POLICY_SQL)?;
        let rows = client.query(&stmt, &[&tenant_bytes])?;

        let mut counts = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant_id = TenantId::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("tenant_id")?,
                "tenant_id",
            )?);
            let policy_hash = PolicyHash::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("policy_hash")?,
                "policy_hash",
            )?);
            let observation_count = crate::types::pg_bigint_nonnegative_to_u64(
                row.try_get::<_, i64>("observation_count")?,
                "observation_count",
            )?;
            counts.push(ObservationCountByPolicy::new(
                tenant_id,
                policy_hash,
                observation_count,
            ));
        }

        Ok(counts)
    }

    /// List the latest observation per finding for one tenant.
    ///
    /// This is a placeholder read path until mutable triage state exists. It
    /// returns the latest observation for each finding and orders the result by
    /// observation recency.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgError::LimitOutOfRange`] when `limit` exceeds the
    /// PostgreSQL `BIGINT` domain, plus the same SQL, decode, and mutex errors
    /// as [`count_observations_by_tenant_policy`](Self::count_observations_by_tenant_policy).
    pub fn list_findings_needing_triage(
        &self,
        tenant_id: TenantId,
        limit: usize,
    ) -> Result<Vec<PendingTriageFinding>, FindingsPgError> {
        let limit_i64 =
            i64::try_from(limit).map_err(|_| FindingsPgError::LimitOutOfRange { limit })?;
        let tenant_bytes = tenant_id.as_bytes().as_slice();
        let mut client = self.lock_client()?;
        let stmt = client.prepare(LIST_FINDINGS_NEEDING_TRIAGE_SQL)?;
        let rows = client.query(&stmt, &[&tenant_bytes, &limit_i64])?;

        let mut findings = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant_id = TenantId::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("tenant_id")?,
                "tenant_id",
            )?);
            let finding_id = FindingId::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("finding_id")?,
                "finding_id",
            )?);
            let stable_item_id = StableItemId::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("stable_item_id")?,
                "stable_item_id",
            )?);
            let occurrence_id = OccurrenceId::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("occurrence_id")?,
                "occurrence_id",
            )?);
            let observation_id = ObservationId::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("observation_id")?,
                "observation_id",
            )?);
            let policy_hash = PolicyHash::from_bytes(decode_fixed_32(
                row.try_get::<_, &[u8]>("policy_hash")?,
                "policy_hash",
            )?);
            let seen_at =
                crate::types::pg_bigint_nonnegative_to_u64(row.try_get("seen_at")?, "seen_at")?;
            let location_display = row.try_get("location_display")?;
            let location_url = row.try_get("location_url")?;

            findings.push(PendingTriageFinding::new(
                tenant_id,
                finding_id,
                stable_item_id,
                occurrence_id,
                observation_id,
                policy_hash,
                seen_at,
                location_display,
                location_url,
            ));
        }

        Ok(findings)
    }

    /// Acquire the held client, treating poisoning as unrecoverable.
    fn lock_client(&self) -> Result<MutexGuard<'_, Client>, FindingsPgError> {
        self.client
            .lock()
            .map_err(|_| FindingsPgError::MutexPoisoned)
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
        let total_records = batch.total_records();
        if total_records > RECOMMENDED_MAX_BATCH_SIZE {
            return Err(FindingsPgError::BatchTooLarge {
                len: total_records,
                max: RECOMMENDED_MAX_BATCH_SIZE,
            });
        }
        if batch.is_empty() {
            return Ok(ReadyCommitHandle::ok(FindingsCommitReceipt::new(0, 0, 0)));
        }

        let projected = project_and_dedupe(batch)?;
        let mut client = self.lock_client()?;
        let mut tx = client.transaction()?;
        // The `postgres` crate caches prepared statements by SQL text at the
        // connection level, so the server-side parse cost is amortized after
        // the first batch through a given connection. The per-call map lookup
        // is negligible relative to network round-trip time; pre-preparing
        // statements outside the transaction would avoid it but adds
        // complexity without measurable throughput gain at current batch rates.
        let findings_stmt = tx.prepare(FINDINGS_INSERT_SQL)?;
        let occurrences_stmt = tx.prepare(OCCURRENCES_INSERT_SQL)?;
        let observations_stmt = tx.prepare(OBSERVATIONS_INSERT_OR_MERGE_SQL)?;

        // Row-by-row execution: each execute_*_upsert call uses `query_opt`
        // on an INSERT ... RETURNING 1 statement to detect per-row identity
        // conflicts. A columnar UNNEST approach would batch all rows into a
        // single INSERT but cannot pinpoint which specific row triggered a
        // conflict when the identity-verifying WHERE clause suppresses the
        // RETURNING row. Uniform row-by-row dispatch across all three layers
        // keeps conflict attribution precise.
        //
        // The sibling done-ledger backend (`gossip-done-ledger-postgres`) uses
        // UNNEST-batch inserts because its merge is always safe — every write
        // targets the same logical object and silent merge is correct.
        // Findings rows are keyed by content hash and a collision with
        // mismatched identity fields is a hard error, not a silent merge.
        // If per-row conflict detection is ever relaxed, the UNNEST pattern
        // would reduce round-trips.
        for row in &projected.findings {
            execute_finding_upsert(&mut tx, &findings_stmt, row)?;
        }
        for row in &projected.occurrences {
            execute_occurrence_upsert(&mut tx, &occurrences_stmt, row)?;
        }
        for row in &projected.observations {
            execute_observation_upsert(&mut tx, &observations_stmt, row)?;
        }

        tx.commit()?;
        Ok(ReadyCommitHandle::ok(build_receipt(&projected)))
    }
}

impl FindingsConformanceProbe for FindingsSinkPg {
    type Error = FindingsPgError;

    /// Return global row counts across all tenants in the database.
    ///
    /// The conformance harness design assumes a clean database containing
    /// exactly one tenant's data — callers must call
    /// `truncate_all_for_tests` before each
    /// conformance run. No `WHERE tenant_id = ?` filter is applied because
    /// the [`FindingsConformanceProbe`] trait signature does not carry a
    /// tenant parameter.
    fn durable_counts(&self) -> Result<DurableFindingsCounts, Self::Error> {
        let mut client = self.lock_client()?;
        let row = client.query_one(COMBINED_COUNTS_SQL, &[])?;

        let findings = nonneg_count(row.get::<_, i64>(0), FINDINGS_TABLE)?;
        let occurrences = nonneg_count(row.get::<_, i64>(1), OCCURRENCES_TABLE)?;
        let observations = nonneg_count(row.get::<_, i64>(2), OBSERVATIONS_TABLE)?;

        Ok(DurableFindingsCounts::new(
            findings,
            occurrences,
            observations,
        ))
    }
}

/// Build a commit receipt from the deduplicated batch.
///
/// Counts reflect the **post-dedup batch size** — the number of unique rows
/// submitted to the database in this batch — not the net-new rows inserted.
/// Idempotent replays of identical data report the same counts as the
/// original write. Callers that need net-new semantics must compare
/// before/after snapshots via [`FindingsConformanceProbe::durable_counts`].
fn build_receipt(projected: &DedupedBatch) -> FindingsCommitReceipt {
    // Safe: batch size is bounded by RECOMMENDED_MAX_BATCH_SIZE (10,000),
    // well within u64 range on all platforms.
    FindingsCommitReceipt::new(
        projected.findings.len() as u64,
        projected.occurrences.len() as u64,
        projected.observations.len() as u64,
    )
}

fn execute_finding_upsert(
    tx: &mut Transaction<'_>,
    stmt: &Statement,
    row: &FindingRow,
) -> Result<(), FindingsPgError> {
    let tenant_id = row.tenant_id.as_slice();
    let finding_id = row.finding_id.as_slice();
    let stable_item_id = row.stable_item_id.as_slice();
    let rule_fingerprint = row.rule_fingerprint.as_slice();
    let secret_hash = row.secret_hash.as_slice();
    let inserted = tx.query_opt(
        stmt,
        &[
            &tenant_id,
            &finding_id,
            &stable_item_id,
            &rule_fingerprint,
            &secret_hash,
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
    stmt: &Statement,
    row: &OccurrenceRow,
) -> Result<(), FindingsPgError> {
    let tenant_id = row.tenant_id.as_slice();
    let occurrence_id = row.occurrence_id.as_slice();
    let finding_id = row.finding_id.as_slice();
    let object_version_id = row.object_version_id.as_slice();
    let inserted = tx
        .query_opt(
            stmt,
            &[
                &tenant_id,
                &occurrence_id,
                &finding_id,
                &object_version_id,
                &row.byte_offset,
                &row.byte_length,
            ],
        )
        .map_err(|e| intercept_fk_violation(e, OCCURRENCES_TABLE))?;
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
    stmt: &Statement,
    row: &ObservationRow,
) -> Result<(), FindingsPgError> {
    let tenant_id = row.tenant_id.as_slice();
    let observation_id = row.observation_id.as_slice();
    let occurrence_id = row.occurrence_id.as_slice();
    let policy_hash = row.policy_hash.as_slice();
    let ovid_hash = row.ovid_hash.as_slice();
    let inserted = tx
        .query_opt(
            stmt,
            &[
                &tenant_id,
                &observation_id,
                &occurrence_id,
                &policy_hash,
                &ovid_hash,
                &row.run_id,
                &row.shard_id,
                &row.fence_epoch,
                &row.seen_at,
                &row.location_display,
                &row.location_url,
            ],
        )
        .map_err(|e| intercept_fk_violation(e, OBSERVATIONS_TABLE))?;
    if inserted.is_none() {
        return Err(FindingsPgError::ObservationConflict {
            tenant_id: TenantId::from_bytes(row.tenant_id),
            observation_id: ObservationId::from_bytes(row.observation_id),
        });
    }
    Ok(())
}

/// Promote a `FOREIGN_KEY_VIOLATION` from a generic `Postgres` error into the
/// structured [`FindingsPgError::ReferentialIntegrityViolation`] variant.
/// All other errors pass through unchanged.
fn intercept_fk_violation(err: postgres::Error, table: &'static str) -> FindingsPgError {
    use postgres::error::SqlState;

    if let Some(db_err) = err.as_db_error()
        && *db_err.code() == SqlState::FOREIGN_KEY_VIOLATION
    {
        return FindingsPgError::ReferentialIntegrityViolation {
            table,
            detail: db_err.detail().unwrap_or("").to_owned(),
        };
    }
    FindingsPgError::Postgres(err)
}

/// Guard against negative counts (impossible in PostgreSQL but enforced
/// defensively for the non-negative count domain).
fn nonneg_count(value: i64, table: &'static str) -> Result<u64, FindingsPgError> {
    crate::types::pg_bigint_nonnegative_to_u64(value, table)
        .map_err(|_| FindingsPgError::CountOutOfRange { table, value })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use gossip_contracts::{
        identity::{
            FenceEpoch, FindingId, LogicalTime, NormHash, ObjectVersionId, ObservationId,
            OccurrenceId, PolicyHash, RuleFingerprint, RunId, ShardId, StableItemId, TenantId,
            TenantSecretKey, key_secret_hash,
        },
        persistence::{
            FindingRecord, FindingsCommitReceipt, FindingsUpsertBatch, ObservationRecord,
            OccurrenceRecord, PersistenceInputError,
        },
        test_util::{observation_record_with_stored_id, ovid},
    };

    use crate::{
        FindingsPgError, FindingsPgSchemaError, PgU64ConversionError,
        schema::{FindingRow, ObservationRow, OccurrenceRow},
    };

    use super::{
        DedupedBatch, build_receipt, dedupe_findings_rows, dedupe_observation_rows,
        dedupe_occurrence_rows, merge_observation_rows, project_and_dedupe,
    };

    #[test]
    fn dedupe_preserves_insertion_order() {
        let finding_a = finding_record(0x11, 0x31);
        let finding_b = finding_record(0x11, 0x32);
        let occurrence_a = occurrence_record(0x11, finding_a.finding_id(), 0x41, 10, 4);
        let occurrence_b = occurrence_record(0x11, finding_b.finding_id(), 0x42, 20, 5);
        let observation_a =
            observation_record(0x11, occurrence_a.occurrence_id(), 0x51, 0x61, 1, 2, 3, 10);
        let observation_b =
            observation_record(0x11, occurrence_b.occurrence_id(), 0x52, 0x62, 4, 5, 6, 20);

        let findings = [finding_b.clone(), finding_a.clone(), finding_b.clone()];
        let occurrences = [
            occurrence_b.clone(),
            occurrence_a.clone(),
            occurrence_b.clone(),
        ];
        let observations = [
            observation_b.clone(),
            observation_a.clone(),
            observation_b.clone(),
        ];

        let deduped = project_and_dedupe(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .expect("dedupe should succeed");

        assert_eq!(
            deduped
                .findings
                .iter()
                .map(|row| row.finding_id)
                .collect::<Vec<_>>(),
            vec![
                *finding_b.finding_id().as_bytes(),
                *finding_a.finding_id().as_bytes(),
            ]
        );
        assert_eq!(
            deduped
                .occurrences
                .iter()
                .map(|row| row.occurrence_id)
                .collect::<Vec<_>>(),
            vec![
                *occurrence_b.occurrence_id().as_bytes(),
                *occurrence_a.occurrence_id().as_bytes(),
            ]
        );
        assert_eq!(
            deduped
                .observations
                .iter()
                .map(|row| row.observation_id)
                .collect::<Vec<_>>(),
            vec![
                *observation_b.observation_id().as_bytes(),
                *observation_a.observation_id().as_bytes(),
            ]
        );
    }

    #[test]
    fn dedupe_finding_identical_duplicate_succeeds() {
        let row = finding_row(0x21);
        let deduped = dedupe_findings_rows(&[row.clone(), row.clone()])
            .expect("identical rows should dedupe");

        assert_eq!(deduped, vec![row]);
    }

    #[test]
    fn dedupe_finding_conflict_detected() {
        let row = finding_row(0x22);
        let conflicting = FindingRow {
            secret_hash: [0xF2; 32],
            ..row.clone()
        };

        let err = dedupe_findings_rows(&[row.clone(), conflicting]).expect_err("conflict expected");
        assert_finding_conflict(
            err,
            TenantId::from_bytes(row.tenant_id),
            FindingId::from_bytes(row.finding_id),
        );
    }

    #[test]
    fn dedupe_occurrence_identical_duplicate_succeeds() {
        let row = occurrence_row(0x31);
        let deduped = dedupe_occurrence_rows(&[row.clone(), row.clone()])
            .expect("identical rows should dedupe");

        assert_eq!(deduped, vec![row]);
    }

    #[test]
    fn dedupe_occurrence_conflict_detected() {
        let row = occurrence_row(0x32);
        let conflicting = OccurrenceRow {
            byte_offset: row.byte_offset + 1,
            ..row.clone()
        };

        let err =
            dedupe_occurrence_rows(&[row.clone(), conflicting]).expect_err("conflict expected");
        assert_occurrence_conflict(
            err,
            TenantId::from_bytes(row.tenant_id),
            OccurrenceId::from_bytes(row.occurrence_id),
        );
    }

    #[test]
    fn merge_observation_newer_seen_at_wins() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(
            11,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, incoming.run_id);
        assert_eq!(merged.shard_id, incoming.shard_id);
        assert_eq!(merged.fence_epoch, incoming.fence_epoch);
        assert_eq!(merged.seen_at, incoming.seen_at);
    }

    #[test]
    fn merge_observation_older_seen_at_loses() {
        let existing = observation_row(
            11,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(
            10,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, existing.run_id);
        assert_eq!(merged.shard_id, existing.shard_id);
        assert_eq!(merged.fence_epoch, existing.fence_epoch);
        assert_eq!(merged.seen_at, existing.seen_at);
    }

    #[test]
    fn merge_observation_equal_seen_at_location_tiebreaker() {
        let existing = observation_row(10, None, None, 1, 2, 3);
        let incoming = observation_row(
            10,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, incoming.run_id);
        assert_eq!(merged.shard_id, incoming.shard_id);
        assert_eq!(merged.fence_epoch, incoming.fence_epoch);
        assert_eq!(merged.location_display.as_deref(), Some("incoming/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://incoming.test")
        );
    }

    #[test]
    fn merge_observation_equal_seen_at_no_tiebreaker() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(
            10,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, existing.run_id);
        assert_eq!(merged.shard_id, existing.shard_id);
        assert_eq!(merged.fence_epoch, existing.fence_epoch);
        assert_eq!(merged.location_display.as_deref(), Some("existing/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://existing.test")
        );
    }

    #[test]
    fn merge_observation_equal_seen_at_neither_has_location() {
        let existing = observation_row(10, None, None, 1, 2, 3);
        let incoming = observation_row(10, None, None, 4, 5, 6);

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, existing.run_id);
        assert_eq!(merged.shard_id, existing.shard_id);
        assert_eq!(merged.fence_epoch, existing.fence_epoch);
        assert_eq!(merged.location_display, None);
        assert_eq!(merged.location_url, None);
    }

    #[test]
    fn merge_observation_equal_seen_at_orphan_urls_follow_loser() {
        // Both have display=None but different orphan URLs. This state cannot
        // arise through normal projection (Location requires display), but at
        // the raw row level, URL follows display source — here the loser
        // (incoming), which also lacks display but carries an orphan URL.
        let existing = ObservationRow {
            location_url: Some("https://existing.test".to_owned()),
            ..observation_row(10, None, None, 1, 2, 3)
        };
        let incoming = ObservationRow {
            location_url: Some("https://incoming.test".to_owned()),
            ..observation_row(10, None, None, 4, 5, 6)
        };

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, existing.run_id);
        assert_eq!(merged.location_display, None);
        // URL comes from location_source (loser = incoming).
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://incoming.test")
        );
    }

    #[test]
    fn merge_observation_identity_mismatch_rejected() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = ObservationRow {
            policy_hash: [0x99; 32],
            ..observation_row(
                10,
                Some("incoming/path"),
                Some("https://incoming.test"),
                4,
                5,
                6,
            )
        };

        let err = merge_observation_rows(&existing, &incoming).expect_err("mismatch expected");

        assert_eq!(err.tenant_id, incoming.tenant_id);
        assert_eq!(err.observation_id, incoming.observation_id);
    }

    #[test]
    fn merge_observation_location_coalesce_winner_has_location() {
        let existing = observation_row(10, None, None, 1, 2, 3);
        let incoming = observation_row(
            11,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.location_display.as_deref(), Some("incoming/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://incoming.test")
        );
    }

    #[test]
    fn merge_observation_location_coalesce_winner_lacks_location() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(11, None, None, 4, 5, 6);

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, incoming.run_id);
        assert_eq!(merged.location_display.as_deref(), Some("existing/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://existing.test")
        );
    }

    #[test]
    fn dedupe_observation_conflict_detected() {
        let row = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let conflicting = ObservationRow {
            policy_hash: [0xEE; 32],
            ..row.clone()
        };

        let err =
            dedupe_observation_rows(&[row.clone(), conflicting]).expect_err("conflict expected");
        assert_observation_conflict(
            err,
            TenantId::from_bytes(row.tenant_id),
            ObservationId::from_bytes(row.observation_id),
        );
    }

    #[test]
    fn consistent_tenant_rejects_mixed_tenants() {
        let finding_a = finding_record(0x11, 0x31);
        let finding_b = finding_record(0x12, 0x32);
        let findings = [finding_a, finding_b];

        let err = FindingsUpsertBatch::new(&findings, &[], &[])
            .validate_tenant_consistency()
            .expect_err("mixed tenants should fail");

        assert_eq!(err, PersistenceInputError::InconsistentTenant);
    }

    #[test]
    fn consistent_tenant_accepts_empty_batch() {
        FindingsUpsertBatch::default()
            .validate_tenant_consistency()
            .expect("empty batch should be valid");
    }

    #[test]
    fn project_and_dedupe_rejects_invalid_observation_identity() {
        let finding = finding_record(0x11, 0x31);
        let occurrence = occurrence_record(0x11, finding.finding_id(), 0x41, 10, 4);
        let observation = observation_record_with_stored_id(
            TenantId::from_bytes([0x11; 32]),
            ObservationId::from_bytes([0xFF; 32]),
            occurrence.occurrence_id(),
            PolicyHash::from_bytes([0x51; 32]),
            ovid(0x61),
            RunId::from_raw(1),
            ShardId::from_raw(2),
            FenceEpoch::from_raw(3),
            LogicalTime::from_raw(10),
            None,
        );
        let findings = [finding];
        let occurrences = [occurrence];
        let observations = [observation];

        let err = project_and_dedupe(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .expect_err("invalid observation identity should fail");

        match err {
            FindingsPgError::Schema(FindingsPgSchemaError::Persistence(
                PersistenceInputError::ObservationIdMismatch { .. },
            )) => {}
            other => panic!("expected observation-id mismatch, got {other:?}"),
        }
    }

    #[test]
    fn project_and_dedupe_rejects_projection_failure() {
        let finding = finding_record(0x11, 0x31);
        let occurrence =
            occurrence_record(0x11, finding.finding_id(), 0x41, i64::MAX as u64 + 1, 4);
        let findings = [finding];
        let occurrences = [occurrence];

        let err = project_and_dedupe(FindingsUpsertBatch::new(&findings, &occurrences, &[]))
            .expect_err("projection overflow should fail");

        match err {
            FindingsPgError::Schema(FindingsPgSchemaError::PgU64Conversion(
                PgU64ConversionError::OrderedOutOfRange { field, value },
            )) => {
                assert_eq!(field, "byte_offset");
                assert_eq!(value, i64::MAX as u64 + 1);
            }
            other => panic!("expected ordered bigint overflow, got {other:?}"),
        }
    }

    #[test]
    fn build_receipt_reflects_deduplication() {
        let batch = DedupedBatch {
            findings: vec![finding_row(0xA1), finding_row(0xA2)],
            occurrences: vec![occurrence_row(0xB1)],
            observations: vec![observation_row(10, Some("path"), None, 1, 2, 3)],
        };

        let receipt = build_receipt(&batch);

        assert_eq!(receipt, FindingsCommitReceipt::new(2, 1, 1));
    }

    fn finding_record(tenant_seed: u8, item_seed: u8) -> FindingRecord {
        let tenant_id = TenantId::from_bytes([tenant_seed; 32]);
        let stable_item_id = StableItemId::from_bytes([item_seed; 32]);
        let rule_fingerprint = RuleFingerprint::from_bytes([item_seed.wrapping_add(1); 32]);
        let secret_hash = key_secret_hash(
            &TenantSecretKey::from_bytes([0x42; 32]),
            &NormHash::from_digest([item_seed.wrapping_add(2); 32]),
        );

        FindingRecord::new(tenant_id, stable_item_id, rule_fingerprint, secret_hash)
    }

    fn occurrence_record(
        tenant_seed: u8,
        finding_id: FindingId,
        version_seed: u8,
        byte_offset: u64,
        byte_length: u64,
    ) -> OccurrenceRecord {
        OccurrenceRecord::new(
            TenantId::from_bytes([tenant_seed; 32]),
            finding_id,
            ObjectVersionId::from_bytes([version_seed; 32]),
            byte_offset,
            NonZeroU64::new(byte_length).expect("test span length must be non-zero"),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "test helper mirrors the observation durable row shape"
    )]
    fn observation_record(
        tenant_seed: u8,
        occurrence_id: OccurrenceId,
        policy_seed: u8,
        ovid_seed: u8,
        run_id: u64,
        shard_id: u64,
        fence_epoch: u64,
        seen_at: u64,
    ) -> ObservationRecord {
        ObservationRecord::new(
            TenantId::from_bytes([tenant_seed; 32]),
            occurrence_id,
            PolicyHash::from_bytes([policy_seed; 32]),
            ovid(ovid_seed),
            RunId::from_raw(run_id),
            ShardId::from_raw(shard_id),
            FenceEpoch::from_raw(fence_epoch),
            LogicalTime::from_raw(seen_at),
        )
    }

    fn finding_row(id_seed: u8) -> FindingRow {
        FindingRow {
            tenant_id: [0x11; 32],
            finding_id: [id_seed; 32],
            stable_item_id: [id_seed.wrapping_add(1); 32],
            rule_fingerprint: [id_seed.wrapping_add(2); 32],
            secret_hash: [id_seed.wrapping_add(3); 32],
        }
    }

    fn occurrence_row(id_seed: u8) -> OccurrenceRow {
        OccurrenceRow {
            tenant_id: [0x11; 32],
            occurrence_id: [id_seed; 32],
            finding_id: [id_seed.wrapping_add(1); 32],
            object_version_id: [id_seed.wrapping_add(2); 32],
            byte_offset: 100,
            byte_length: 50,
        }
    }

    fn observation_row(
        seen_at: i64,
        location_display: Option<&str>,
        location_url: Option<&str>,
        run_id: i64,
        shard_id: i64,
        fence_epoch: i64,
    ) -> ObservationRow {
        ObservationRow {
            tenant_id: [0x11; 32],
            observation_id: [0x21; 32],
            occurrence_id: [0x31; 32],
            policy_hash: [0x41; 32],
            ovid_hash: [0x51; 32],
            run_id,
            shard_id,
            fence_epoch,
            seen_at,
            location_display: location_display.map(str::to_owned),
            location_url: location_url.map(str::to_owned),
        }
    }

    fn empty_deduped_batch() -> DedupedBatch {
        DedupedBatch {
            findings: Vec::new(),
            occurrences: Vec::new(),
            observations: Vec::new(),
        }
    }

    fn assert_finding_conflict(err: FindingsPgError, tenant_id: TenantId, finding_id: FindingId) {
        match err {
            FindingsPgError::FindingConflict {
                tenant_id: actual_tenant,
                finding_id: actual_finding,
            } => {
                assert_eq!(actual_tenant, tenant_id);
                assert_eq!(actual_finding, finding_id);
            }
            other => panic!("expected finding conflict, got {other:?}"),
        }
    }

    fn assert_occurrence_conflict(
        err: FindingsPgError,
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    ) {
        match err {
            FindingsPgError::OccurrenceConflict {
                tenant_id: actual_tenant,
                occurrence_id: actual_occurrence,
            } => {
                assert_eq!(actual_tenant, tenant_id);
                assert_eq!(actual_occurrence, occurrence_id);
            }
            other => panic!("expected occurrence conflict, got {other:?}"),
        }
    }

    fn assert_observation_conflict(
        err: FindingsPgError,
        tenant_id: TenantId,
        observation_id: ObservationId,
    ) {
        match err {
            FindingsPgError::ObservationConflict {
                tenant_id: actual_tenant,
                observation_id: actual_observation,
            } => {
                assert_eq!(actual_tenant, tenant_id);
                assert_eq!(actual_observation, observation_id);
            }
            other => panic!("expected observation conflict, got {other:?}"),
        }
    }

    #[test]
    fn consistent_tenant_rejects_cross_layer_mismatch() {
        let finding = finding_record(0x11, 0x31);
        let occurrence = occurrence_record(0x12, finding.finding_id(), 0x41, 10, 4);
        // tenant 0x11 in findings, 0x12 in occurrences
        let err = project_and_dedupe(FindingsUpsertBatch::new(&[finding], &[occurrence], &[]))
            .expect_err("cross-layer tenant mismatch should fail");

        match err {
            FindingsPgError::Schema(FindingsPgSchemaError::Persistence(
                PersistenceInputError::InconsistentTenant,
            )) => {}
            other => panic!("expected InconsistentTenant, got {other:?}"),
        }
    }

    #[test]
    fn consistent_tenant_rejects_observation_layer_mismatch() {
        let finding = finding_record(0x11, 0x31);
        let occurrence = occurrence_record(0x11, finding.finding_id(), 0x41, 10, 4);
        // Observation uses tenant 0x12 while finding+occurrence use 0x11.
        let observation =
            observation_record(0x12, occurrence.occurrence_id(), 0x51, 0x61, 1, 2, 3, 10);
        let err = project_and_dedupe(FindingsUpsertBatch::new(
            &[finding],
            &[occurrence],
            &[observation],
        ))
        .expect_err("observation-layer tenant mismatch should fail");

        match err {
            FindingsPgError::Schema(FindingsPgSchemaError::Persistence(
                PersistenceInputError::InconsistentTenant,
            )) => {}
            other => panic!("expected InconsistentTenant, got {other:?}"),
        }
    }

    #[test]
    fn merge_observation_winner_has_display_but_no_url() {
        let existing = observation_row(10, None, Some("https://existing.test"), 1, 2, 3);
        let incoming = observation_row(11, Some("incoming/path"), None, 4, 5, 6);
        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        // Winner (incoming, higher seen_at) has display, so URL comes from winner too.
        assert_eq!(merged.location_display.as_deref(), Some("incoming/path"));
        assert_eq!(merged.location_url, None);
    }

    #[test]
    fn merge_observation_loser_has_display_but_no_url() {
        let existing = observation_row(10, Some("existing/path"), None, 1, 2, 3);
        let incoming = observation_row(11, None, Some("https://incoming.test"), 4, 5, 6);
        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        // Winner (incoming, higher seen_at) has no display, so location
        // falls back to loser (existing) which has display but no URL.
        assert_eq!(merged.run_id, incoming.run_id);
        assert_eq!(merged.location_display.as_deref(), Some("existing/path"));
        assert_eq!(merged.location_url, None);
    }

    #[test]
    fn merge_observation_winner_url_without_display_follows_loser_location() {
        // ObservationRow::from_record couples display and URL through the
        // Location type (display is always present when location exists), so
        // url-without-display cannot arise through the normal projection path.
        // At the raw row level, the merge rule "URL follows display source"
        // means the winner's orphaned URL is intentionally not carried forward.
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = ObservationRow {
            location_display: None,
            location_url: Some("https://incoming-orphan.test".to_owned()),
            ..observation_row(11, None, None, 4, 5, 6)
        };

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        // Incoming wins provenance (higher seen_at).
        assert_eq!(merged.run_id, incoming.run_id);
        // Winner has no display, so location falls back to loser.
        assert_eq!(merged.location_display.as_deref(), Some("existing/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://existing.test")
        );
    }

    #[test]
    fn dedupe_empty_inputs_return_empty() {
        assert_eq!(dedupe_findings_rows(&[]).unwrap(), vec![]);
        assert_eq!(dedupe_occurrence_rows(&[]).unwrap(), vec![]);
        assert_eq!(dedupe_observation_rows(&[]).unwrap(), vec![]);
    }

    #[test]
    fn dedupe_observation_rows_three_way_merge() {
        // Three observations with the same key but different seen_at values.
        // Oldest has location, middle has no location, newest has different location.
        let oldest = observation_row(8, Some("oldest/path"), Some("https://oldest.test"), 1, 2, 3);
        let middle = observation_row(10, None, None, 4, 5, 6);
        let newest = observation_row(
            12,
            Some("newest/path"),
            Some("https://newest.test"),
            7,
            8,
            9,
        );

        let deduped =
            dedupe_observation_rows(&[oldest, middle, newest]).expect("3-way merge should succeed");

        assert_eq!(deduped.len(), 1);
        let merged = &deduped[0];
        // Newest wins provenance.
        assert_eq!(merged.run_id, 7);
        assert_eq!(merged.shard_id, 8);
        assert_eq!(merged.fence_epoch, 9);
        assert_eq!(merged.seen_at, 12);
        // Newest has location_display, so location comes from newest.
        assert_eq!(merged.location_display.as_deref(), Some("newest/path"));
        assert_eq!(merged.location_url.as_deref(), Some("https://newest.test"));
    }

    #[test]
    fn dedupe_single_element_passes_through() {
        let f = finding_row(0x21);
        assert_eq!(
            dedupe_findings_rows(std::slice::from_ref(&f)).unwrap(),
            vec![f]
        );

        let o = occurrence_row(0x31);
        assert_eq!(
            dedupe_occurrence_rows(std::slice::from_ref(&o)).unwrap(),
            vec![o]
        );

        let obs = observation_row(10, Some("p"), Some("u"), 1, 2, 3);
        assert_eq!(
            dedupe_observation_rows(std::slice::from_ref(&obs)).unwrap(),
            vec![obs]
        );
    }

    #[test]
    fn build_receipt_uses_deduped_lengths() {
        let finding = finding_record(0x11, 0x31);
        let occurrence = occurrence_record(0x11, finding.finding_id(), 0x41, 10, 4);
        let observation =
            observation_record(0x11, occurrence.occurrence_id(), 0x51, 0x61, 1, 2, 3, 10);
        let batch = project_and_dedupe(FindingsUpsertBatch::new(
            std::slice::from_ref(&finding),
            std::slice::from_ref(&occurrence),
            std::slice::from_ref(&observation),
        ))
        .expect("batch should dedupe");

        assert_eq!(build_receipt(&batch), FindingsCommitReceipt::new(1, 1, 1),);
    }

    #[test]
    fn build_receipt_reports_zero_for_empty_batch() {
        assert_eq!(
            build_receipt(&empty_deduped_batch()),
            FindingsCommitReceipt::new(0, 0, 0),
        );
    }

    #[test]
    fn batch_exceeding_max_size_is_detected_before_sql() {
        use gossip_contracts::persistence::RECOMMENDED_MAX_BATCH_SIZE;

        // Build a batch whose total_records() exceeds the limit. The
        // records need not be unique — the size gate fires before
        // deduplication. The production `upsert_batch` path is covered
        // by the `upsert_batch_rejects_oversized_batch` integration test;
        // this unit test verifies `total_records()` counting without a
        // PostgreSQL connection.
        let finding = finding_record(0x11, 0x31);
        let oversized: Vec<_> =
            std::iter::repeat_n(finding, RECOMMENDED_MAX_BATCH_SIZE + 1).collect();
        let batch = FindingsUpsertBatch::new(&oversized, &[], &[]);

        assert_eq!(
            batch.total_records(),
            RECOMMENDED_MAX_BATCH_SIZE + 1,
            "batch total_records() should exceed the limit"
        );
    }
}
