//! Canonical PostgreSQL schema identifiers and row projections for findings
//! persistence.
//!
//! The schema plan keeps the relational write model compiled into Rust so that
//! migration SQL, query code, and tests all share the same names and row
//! shapes. The current plan intentionally models only the three durable tables
//! that exist today: findings, occurrences, and observations.
//!
//! Invariants:
//! - `policy_hash` is part of the observations layer, not the occurrences
//!   layer.
//! - Row field order matches the corresponding `*_INSERT_COLUMNS` constant so
//!   future bind-array SQL can share a single source of truth for column
//!   ordering.
//! - Ordered `BIGINT` columns (`fence_epoch`, `seen_at`, `byte_offset`,
//!   `byte_length`) use checked non-negative conversion because SQL `ORDER BY`
//!   and range-scan indexes depend on signed integer ordering matching the
//!   logical counter ordering. Equality-only identifiers (`run_id`, `shard_id`)
//!   use bit-pattern storage where ordering is irrelevant.

use gossip_contracts::persistence::{
    FindingRecord, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
};

use crate::{
    types::{u64_to_pg_bigint_bits, u64_to_pg_bigint_checked},
    FindingsPgSchemaError,
};

/// Durable findings table storing policy-independent finding identity.
pub const FINDINGS_TABLE: &str = "findings";

/// Durable occurrences table storing version-specific finding spans.
pub const OCCURRENCES_TABLE: &str = "occurrences";

/// Durable observations table storing policy-scoped detection facts.
pub const OBSERVATIONS_TABLE: &str = "observations";

/// History table recording which embedded schema migrations have run.
pub const SCHEMA_MIGRATIONS_TABLE: &str = "findings_schema_migrations";

/// PostgreSQL advisory-lock key for serialising migration application.
///
/// The big-endian bytes spell `"GFPGMIG1"` to keep the mnemonic readable when
/// debugging lock collisions.
pub const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x47465047_4d494731; // "GFPGMIG1"

/// Primary key columns for [`FINDINGS_TABLE`].
pub const FINDINGS_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "finding_id"];

/// Primary key columns for [`OCCURRENCES_TABLE`].
pub const OCCURRENCES_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "occurrence_id"];

/// Primary key columns for [`OBSERVATIONS_TABLE`].
pub const OBSERVATIONS_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "observation_id"];

/// Full insert column set for [`FINDINGS_TABLE`].
pub const FINDINGS_INSERT_COLUMNS: &[&str] = &[
    "tenant_id",
    "finding_id",
    "stable_item_id",
    "rule_fingerprint",
    "secret_hash",
];

/// Full insert column set for [`OCCURRENCES_TABLE`].
pub const OCCURRENCES_INSERT_COLUMNS: &[&str] = &[
    "tenant_id",
    "occurrence_id",
    "finding_id",
    "object_version_id",
    "byte_offset",
    "byte_length",
];

/// Full insert column set for [`OBSERVATIONS_TABLE`].
pub const OBSERVATIONS_INSERT_COLUMNS: &[&str] = &[
    "tenant_id",
    "observation_id",
    "occurrence_id",
    "policy_hash",
    "ovid_hash",
    "run_id",
    "shard_id",
    "fence_epoch",
    "seen_at",
    "location_display",
    "location_url",
];

/// Natural-key uniqueness columns for [`FINDINGS_TABLE`].
///
/// These columns define the stable finding identity and double as the future
/// `ON CONFLICT` target for immutable insert-or-skip writes.
pub const FINDINGS_CANONICAL_UNIQUE_COLUMNS: &[&str] = &[
    "tenant_id",
    "stable_item_id",
    "rule_fingerprint",
    "secret_hash",
];

/// Natural-key uniqueness columns for [`OCCURRENCES_TABLE`].
///
/// `policy_hash` is intentionally absent: occurrence identity is version- and
/// span-scoped, not policy-scoped.
pub const OCCURRENCES_CANONICAL_UNIQUE_COLUMNS: &[&str] = &[
    "tenant_id",
    "finding_id",
    "object_version_id",
    "byte_offset",
    "byte_length",
];

/// Natural-key uniqueness columns for [`OBSERVATIONS_TABLE`].
///
/// `policy_hash` belongs here because observations are the policy-scoped layer.
pub const OBSERVATIONS_CANONICAL_UNIQUE_COLUMNS: &[&str] =
    &["tenant_id", "policy_hash", "occurrence_id"];

/// Index name for tenant-scoped secret hash lookups.
pub const FINDINGS_TENANT_SECRET_HASH_INDEX: &str = "findings_tenant_secret_hash_idx";

/// Index name for tenant-scoped stable item lookups.
pub const FINDINGS_TENANT_STABLE_ITEM_ID_INDEX: &str = "findings_tenant_stable_item_id_idx";

/// Index name for finding-to-occurrence drill-down.
pub const OCCURRENCES_TENANT_FINDING_ID_INDEX: &str = "occurrences_tenant_finding_id_idx";

/// Index name for object-version-to-occurrence drill-down.
pub const OCCURRENCES_TENANT_OBJECT_VERSION_ID_INDEX: &str =
    "occurrences_tenant_object_version_id_idx";

/// Index name for tenant-scoped observation recency scans.
pub const OBSERVATIONS_TENANT_SEEN_AT_INDEX: &str = "observations_tenant_seen_at_idx";

/// Index name for policy-scoped observation recency scans.
pub const OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX: &str = "observations_tenant_policy_seen_at_idx";

/// Index name for occurrence-to-observation drill-down.
pub const OBSERVATIONS_TENANT_OCCURRENCE_ID_INDEX: &str = "observations_tenant_occurrence_id_idx";

/// Index name for done-ledger cross-reference lookups.
pub const OBSERVATIONS_TENANT_OVID_HASH_INDEX: &str = "observations_tenant_ovid_hash_idx";

/// Index name for run/shard provenance lookups.
pub const OBSERVATIONS_TENANT_RUN_SHARD_INDEX: &str = "observations_tenant_run_shard_idx";

/// Validate a contracts-layer batch against the schema constraints.
///
/// Runs the observation-identity invariant check before any Postgres-specific
/// integer conversions happen, so projection failures only need to handle
/// storage-boundary representation issues.
///
/// Referential integrity (occurrence→finding, observation→occurrence) is
/// **not** checked here because batches may legitimately reference parents
/// that are already persisted but absent from the current batch. The real
/// enforcement point is the PostgreSQL foreign-key constraints on the
/// durable tables.
pub fn validate_findings_batch(
    batch: FindingsUpsertBatch<'_>,
) -> Result<(), FindingsPgSchemaError> {
    batch.validate_observation_identity()?;
    Ok(())
}

/// Project a contracts-layer batch into Postgres-ready primitive row types.
///
/// Each projected layer preserves the input slice order, which lets later
/// SQL binders expand arrays in a stable row order without extra
/// reindexing.
pub fn project_findings_batch(
    batch: FindingsUpsertBatch<'_>,
) -> Result<ProjectedFindingsBatch, FindingsPgSchemaError> {
    validate_findings_batch(batch)?;

    let findings = batch
        .findings()
        .iter()
        .map(FindingRow::from_record)
        .collect();
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

    Ok(ProjectedFindingsBatch {
        findings,
        occurrences,
        observations,
    })
}

/// Postgres-ready row projection for [`FINDINGS_TABLE`].
///
/// Field order matches [`FINDINGS_INSERT_COLUMNS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRow {
    pub tenant_id: [u8; 32],
    pub finding_id: [u8; 32],
    pub stable_item_id: [u8; 32],
    pub rule_fingerprint: [u8; 32],
    pub secret_hash: [u8; 32],
}

impl FindingRow {
    /// Project a contracts-layer finding into its durable row shape.
    #[must_use]
    pub fn from_record(record: &FindingRecord) -> Self {
        Self {
            tenant_id: *record.tenant_id().as_bytes(),
            finding_id: *record.finding_id().as_bytes(),
            stable_item_id: *record.stable_item_id().as_bytes(),
            rule_fingerprint: *record.rule_fingerprint().as_bytes(),
            secret_hash: *record.secret_hash().as_bytes(),
        }
    }
}

/// Postgres-ready row projection for [`OCCURRENCES_TABLE`].
///
/// Field order matches [`OCCURRENCES_INSERT_COLUMNS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccurrenceRow {
    pub tenant_id: [u8; 32],
    pub occurrence_id: [u8; 32],
    pub finding_id: [u8; 32],
    pub object_version_id: [u8; 32],
    pub byte_offset: i64,
    pub byte_length: i64,
}

impl OccurrenceRow {
    /// Project a contracts-layer occurrence into its durable row shape.
    ///
    /// # Errors
    ///
    /// Returns [`FindingsPgSchemaError::PgU64Conversion`] when either ordered
    /// `BIGINT` field exceeds PostgreSQL's signed range, or
    /// [`FindingsPgSchemaError::SpanOverflow`] when the combined span
    /// (`byte_offset + byte_length`) exceeds `i64::MAX`, mirroring the SQL
    /// `occurrences_span_no_overflow_ck` constraint.
    pub fn from_record(record: &OccurrenceRecord) -> Result<Self, FindingsPgSchemaError> {
        let byte_offset = u64_to_pg_bigint_checked(record.byte_offset(), "byte_offset")?;
        let byte_length = u64_to_pg_bigint_checked(record.byte_length().get(), "byte_length")?;

        // Mirror the SQL constraint: byte_offset + byte_length <= i64::MAX.
        // Both values are non-negative i64, so checked_add returning None
        // means the combined span exceeds the BIGINT range.
        if byte_offset.checked_add(byte_length).is_none() {
            return Err(FindingsPgSchemaError::SpanOverflow {
                byte_offset,
                byte_length,
            });
        }

        Ok(Self {
            tenant_id: *record.tenant_id().as_bytes(),
            occurrence_id: *record.occurrence_id().as_bytes(),
            finding_id: *record.finding_id().as_bytes(),
            object_version_id: *record.object_version_id().as_bytes(),
            byte_offset,
            byte_length,
        })
    }
}

/// Postgres-ready row projection for [`OBSERVATIONS_TABLE`].
///
/// Field order matches [`OBSERVATIONS_INSERT_COLUMNS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationRow {
    pub tenant_id: [u8; 32],
    pub observation_id: [u8; 32],
    pub occurrence_id: [u8; 32],
    pub policy_hash: [u8; 32],
    pub ovid_hash: [u8; 32],
    pub run_id: i64,
    pub shard_id: i64,
    pub fence_epoch: i64,
    pub seen_at: i64,
    pub location_display: Option<String>,
    pub location_url: Option<String>,
}

impl ObservationRow {
    /// Project a contracts-layer observation into its durable row shape.
    ///
    /// `run_id` and `shard_id` use bit-pattern storage because callers only
    /// need equality and grouping semantics (`=`, `GROUP BY`) for provenance
    /// lookups — no SQL `ORDER BY` or range scan ever targets these columns.
    ///
    /// `fence_epoch` and `seen_at` use checked non-negative `BIGINT` conversion
    /// because SQL `ORDER BY` and indexed range scans on `observations_tenant_seen_at_idx`
    /// rely on PostgreSQL's signed integer ordering matching the logical
    /// monotonic counter ordering. Bit-pattern storage would invert the
    /// ordering for values above `i64::MAX`, breaking recency queries. Values
    /// exceeding `i64::MAX` are rejected rather than silently misordered.
    pub fn from_record(record: &ObservationRecord) -> Result<Self, FindingsPgSchemaError> {
        let (location_display, location_url) = match record.location() {
            Some(location) => (
                Some(location.display().to_owned()),
                location.url().map(str::to_owned),
            ),
            None => (None, None),
        };

        Ok(Self {
            tenant_id: *record.tenant_id().as_bytes(),
            observation_id: *record.observation_id().as_bytes(),
            occurrence_id: *record.occurrence_id().as_bytes(),
            policy_hash: *record.policy_hash().as_bytes(),
            ovid_hash: *record.ovid_hash().as_bytes(),
            run_id: u64_to_pg_bigint_bits(record.run_id().as_raw()),
            shard_id: u64_to_pg_bigint_bits(record.shard_id().as_raw()),
            fence_epoch: u64_to_pg_bigint_checked(record.fence_epoch().as_raw(), "fence_epoch")?,
            seen_at: u64_to_pg_bigint_checked(record.seen_at().as_raw(), "seen_at")?,
            location_display,
            location_url,
        })
    }
}

/// Fully projected findings batch ready for SQL binding.
///
/// Each vector contains one table layer in the same relative order as the
/// source batch so callers can derive per-column bind arrays without having to
/// reconstruct row order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectedFindingsBatch {
    findings: Vec<FindingRow>,
    occurrences: Vec<OccurrenceRow>,
    observations: Vec<ObservationRow>,
}

impl ProjectedFindingsBatch {
    /// Projected finding rows.
    #[must_use]
    pub fn findings(&self) -> &[FindingRow] {
        &self.findings
    }

    /// Projected occurrence rows.
    #[must_use]
    pub fn occurrences(&self) -> &[OccurrenceRow] {
        &self.occurrences
    }

    /// Projected observation rows.
    #[must_use]
    pub fn observations(&self) -> &[ObservationRow] {
        &self.observations
    }

    /// Returns `true` when every projected layer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.occurrences.is_empty() && self.observations.is_empty()
    }

    /// Total number of projected rows across all three layers.
    #[must_use]
    pub fn total_rows(&self) -> usize {
        self.findings.len() + self.occurrences.len() + self.observations.len()
    }
}

/// Idempotent finding insert with natural-key verification on conflict.
///
/// The `DO UPDATE ... WHERE` form intentionally returns no row when the same
/// `(tenant_id, finding_id)` maps to different immutable identity fields. The
/// backend uses that `query_opt` miss to surface
/// [`crate::FindingsPgError::FindingConflict`] instead of silently accepting
/// drift.
///
/// Bind parameters:
/// 1. `tenant_id`
/// 2. `finding_id`
/// 3. `stable_item_id`
/// 4. `rule_fingerprint`
/// 5. `secret_hash`
pub const FINDINGS_INSERT_SQL: &str = r#"
INSERT INTO findings (
    tenant_id, finding_id, stable_item_id, rule_fingerprint, secret_hash
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, finding_id) DO UPDATE
SET stable_item_id = findings.stable_item_id
WHERE findings.stable_item_id = EXCLUDED.stable_item_id
  AND findings.rule_fingerprint = EXCLUDED.rule_fingerprint
  AND findings.secret_hash = EXCLUDED.secret_hash
RETURNING 1
"#;

/// Idempotent occurrence insert with natural-key verification on conflict.
///
/// Like [`FINDINGS_INSERT_SQL`], this uses `DO UPDATE ... WHERE` to turn a
/// primary-key collision with mismatched natural-key fields into a missing
/// `RETURNING` row rather than a silent `DO NOTHING`.
///
/// Bind parameters:
/// 1. `tenant_id`
/// 2. `occurrence_id`
/// 3. `finding_id`
/// 4. `object_version_id`
/// 5. `byte_offset`
/// 6. `byte_length`
pub const OCCURRENCES_INSERT_SQL: &str = r#"
INSERT INTO occurrences (
    tenant_id, occurrence_id, finding_id, object_version_id, byte_offset, byte_length
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, occurrence_id) DO UPDATE
SET finding_id = occurrences.finding_id
WHERE occurrences.finding_id = EXCLUDED.finding_id
  AND occurrences.object_version_id = EXCLUDED.object_version_id
  AND occurrences.byte_offset = EXCLUDED.byte_offset
  AND occurrences.byte_length = EXCLUDED.byte_length
RETURNING 1
"#;

/// Observation upsert with monotonic merge semantics.
///
/// The `CASE` expressions must stay in lockstep with the Rust-side
/// observation-merge helper so that in-memory deduplication and PostgreSQL
/// replay produce identical durable rows for the same inputs.
///
/// ## Provenance triple
///
/// `(run_id, shard_id, fence_epoch)` always move as a unit — all three
/// columns come from whichever observation wins the `seen_at` tie-break.
/// `fence_epoch` is **not** independently max-tracked because doing so
/// would produce an incoherent record whose epoch belongs to a different
/// run/shard than the one stored. In the coordination layer `fence_epoch`
/// is monotonic per shard; here it is provenance metadata that records
/// _which_ epoch the observation was created under.
///
/// ## Location pairing
///
/// `location_display` and `location_url` are sourced as a unit from the
/// same observation record. The fallback chain is:
/// provenance winner → existing → incoming. `location_url` follows
/// whichever record provided `location_display`, never the other record's
/// URL, to avoid pairing a display string with an unrelated URL.
///
/// Bind parameters:
/// 1. `tenant_id`
/// 2. `observation_id`
/// 3. `occurrence_id`
/// 4. `policy_hash`
/// 5. `ovid_hash`
/// 6. `run_id`
/// 7. `shard_id`
/// 8. `fence_epoch`
/// 9. `seen_at`
/// 10. `location_display`
/// 11. `location_url`
pub const OBSERVATIONS_INSERT_OR_MERGE_SQL: &str = r#"
INSERT INTO observations (
    tenant_id, observation_id, occurrence_id, policy_hash, ovid_hash,
    run_id, shard_id, fence_epoch, seen_at, location_display, location_url
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (tenant_id, observation_id) DO UPDATE
SET
    run_id = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
          OR (EXCLUDED.seen_at = observations.seen_at
              AND observations.location_display IS NULL
              AND EXCLUDED.location_display IS NOT NULL)
            THEN EXCLUDED.run_id
        ELSE observations.run_id
    END,
    shard_id = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
          OR (EXCLUDED.seen_at = observations.seen_at
              AND observations.location_display IS NULL
              AND EXCLUDED.location_display IS NOT NULL)
            THEN EXCLUDED.shard_id
        ELSE observations.shard_id
    END,
    fence_epoch = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
          OR (EXCLUDED.seen_at = observations.seen_at
              AND observations.location_display IS NULL
              AND EXCLUDED.location_display IS NOT NULL)
            THEN EXCLUDED.fence_epoch
        ELSE observations.fence_epoch
    END,
    seen_at = GREATEST(observations.seen_at, EXCLUDED.seen_at),
    location_display = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
            THEN COALESCE(EXCLUDED.location_display, observations.location_display)
        WHEN EXCLUDED.seen_at < observations.seen_at
            THEN COALESCE(observations.location_display, EXCLUDED.location_display)
        WHEN observations.location_display IS NULL AND EXCLUDED.location_display IS NOT NULL
            THEN EXCLUDED.location_display
        ELSE COALESCE(observations.location_display, EXCLUDED.location_display)
    END,
    location_url = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
            THEN CASE
                WHEN EXCLUDED.location_display IS NOT NULL THEN EXCLUDED.location_url
                ELSE observations.location_url
            END
        WHEN EXCLUDED.seen_at < observations.seen_at
            THEN CASE
                WHEN observations.location_display IS NOT NULL THEN observations.location_url
                ELSE EXCLUDED.location_url
            END
        WHEN observations.location_display IS NULL AND EXCLUDED.location_display IS NOT NULL
            THEN EXCLUDED.location_url
        ELSE CASE
            WHEN observations.location_display IS NOT NULL THEN observations.location_url
            ELSE EXCLUDED.location_url
        END
    END
WHERE observations.occurrence_id = EXCLUDED.occurrence_id
  AND observations.policy_hash = EXCLUDED.policy_hash
  AND observations.ovid_hash = EXCLUDED.ovid_hash
RETURNING 1
"#;

/// Count all durable finding rows.
pub const FINDINGS_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT FROM findings";
/// Count all durable occurrence rows.
pub const OCCURRENCES_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT FROM occurrences";
/// Count all durable observation rows.
pub const OBSERVATIONS_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT FROM observations";

/// Remove all durable findings-layer rows in foreign-key order.
pub const TRUNCATE_ALL_SQL: &str = "TRUNCATE TABLE observations, occurrences, findings";

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, num::NonZeroU64};

    use crate::types::{pg_bigint_to_u64_bits, PgU64ConversionError};
    use gossip_contracts::{
        connector::Location,
        identity::{
            key_secret_hash, FenceEpoch, FindingId, LogicalTime, NormHash, ObjectVersionId,
            PolicyHash, RuleFingerprint, RunId, ShardId, StableItemId, TenantId, TenantSecretKey,
        },
        persistence::{
            FindingRecord, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord, OvidHash,
        },
    };

    use super::*;

    fn finding_record(tenant_id: TenantId) -> FindingRecord {
        FindingRecord::new(
            tenant_id,
            StableItemId::from_bytes([0x22; 32]),
            RuleFingerprint::from_bytes([0x33; 32]),
            key_secret_hash(
                &TenantSecretKey::from_bytes([0x44; 32]),
                &NormHash::from_digest([0x55; 32]),
            ),
        )
    }

    fn occurrence_record(
        tenant_id: TenantId,
        finding_id: FindingId,
        byte_offset: u64,
        byte_length: u64,
    ) -> OccurrenceRecord {
        OccurrenceRecord::new(
            tenant_id,
            finding_id,
            ObjectVersionId::from_bytes([0x66; 32]),
            byte_offset,
            NonZeroU64::new(byte_length).expect("test span length must be non-zero"),
        )
    }

    fn observation_record(
        tenant_id: TenantId,
        occurrence_id: gossip_contracts::identity::OccurrenceId,
        run_id: u64,
        shard_id: u64,
    ) -> ObservationRecord {
        ObservationRecord::new(
            tenant_id,
            occurrence_id,
            PolicyHash::from_bytes([0x77; 32]),
            OvidHash::from_bytes([0x88; 32]),
            RunId::from_raw(run_id),
            ShardId::from_raw(shard_id),
            FenceEpoch::from_raw(9),
            LogicalTime::from_raw(10),
        )
    }

    fn assert_non_empty_unique(columns: &[&str]) {
        assert!(!columns.is_empty(), "column list must not be empty");

        let mut seen = HashSet::new();
        for column in columns {
            assert!(
                seen.insert(*column),
                "column list contains duplicate entry: {column}"
            );
        }
    }

    fn assert_sql_contains_all(sql: &str, needles: &[&str]) {
        for needle in needles {
            assert!(
                sql.contains(needle),
                "expected SQL to contain {needle:?}, but it was:\n{sql}"
            );
        }
    }

    #[test]
    fn finding_row_from_record_projects_all_hash_fields() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let record = finding_record(tenant_id);
        let row = FindingRow::from_record(&record);

        assert_eq!(row.tenant_id, *record.tenant_id().as_bytes());
        assert_eq!(row.finding_id, *record.finding_id().as_bytes());
        assert_eq!(row.stable_item_id, *record.stable_item_id().as_bytes());
        assert_eq!(row.rule_fingerprint, *record.rule_fingerprint().as_bytes());
        assert_eq!(row.secret_hash, *record.secret_hash().as_bytes());
    }

    #[test]
    fn occurrence_row_from_record_projects_bigint_fields() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        // byte_offset + byte_length must not exceed i64::MAX (SQL span constraint).
        let record = occurrence_record(tenant_id, finding.finding_id(), i64::MAX as u64 - 7, 7);
        let row = OccurrenceRow::from_record(&record).expect("boundary values should project");

        assert_eq!(row.tenant_id, *record.tenant_id().as_bytes());
        assert_eq!(row.occurrence_id, *record.occurrence_id().as_bytes());
        assert_eq!(row.finding_id, *record.finding_id().as_bytes());
        assert_eq!(
            row.object_version_id,
            *record.object_version_id().as_bytes()
        );
        assert_eq!(row.byte_offset, i64::MAX - 7);
        assert_eq!(row.byte_length, 7);
    }

    #[test]
    fn occurrence_row_from_record_rejects_offsets_above_pg_bigint_max() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let record = occurrence_record(tenant_id, finding.finding_id(), i64::MAX as u64 + 1, 1);

        let err = OccurrenceRow::from_record(&record).expect_err("overflow should fail");
        assert_eq!(
            err,
            FindingsPgSchemaError::PgU64Conversion(PgU64ConversionError::OrderedOutOfRange {
                field: "byte_offset",
                value: i64::MAX as u64 + 1,
            })
        );
    }

    #[test]
    fn occurrence_row_from_record_rejects_byte_length_above_pg_bigint_max() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let record = occurrence_record(tenant_id, finding.finding_id(), 0, i64::MAX as u64 + 1);

        let err = OccurrenceRow::from_record(&record).expect_err("overflow should fail");
        assert_eq!(
            err,
            FindingsPgSchemaError::PgU64Conversion(PgU64ConversionError::OrderedOutOfRange {
                field: "byte_length",
                value: i64::MAX as u64 + 1,
            })
        );
    }

    #[test]
    fn observation_row_from_record_roundtrips_bit_pattern_ids() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let occurrence = occurrence_record(tenant_id, finding.finding_id(), 3, 4);
        let record = observation_record(
            tenant_id,
            occurrence.occurrence_id(),
            i64::MAX as u64 + 7,
            u64::MAX - 3,
        );

        let row = ObservationRow::from_record(&record).expect("bit-pattern projection should work");

        assert_eq!(pg_bigint_to_u64_bits(row.run_id), record.run_id().as_raw());
        assert_eq!(
            pg_bigint_to_u64_bits(row.shard_id),
            record.shard_id().as_raw()
        );
        assert_eq!(row.fence_epoch, 9);
        assert_eq!(row.seen_at, 10);
    }

    #[test]
    fn observation_row_from_record_handles_location_variants() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let occurrence = occurrence_record(tenant_id, finding.finding_id(), 3, 4);

        let no_location = observation_record(tenant_id, occurrence.occurrence_id(), 1, 2);
        let display_only = observation_record(tenant_id, occurrence.occurrence_id(), 3, 4)
            .with_location(Location::try_new("repo/path".into(), None).expect("valid location"));
        let with_url = observation_record(tenant_id, occurrence.occurrence_id(), 5, 6)
            .with_location(
                Location::try_new(
                    "repo/path".into(),
                    Some("https://example.test/findings/42".into()),
                )
                .expect("valid location"),
            );

        let no_location_row =
            ObservationRow::from_record(&no_location).expect("projection should succeed");
        let display_only_row =
            ObservationRow::from_record(&display_only).expect("projection should succeed");
        let with_url_row =
            ObservationRow::from_record(&with_url).expect("projection should succeed");

        assert_eq!(no_location_row.location_display, None);
        assert_eq!(no_location_row.location_url, None);
        assert_eq!(
            display_only_row.location_display.as_deref(),
            Some("repo/path")
        );
        assert_eq!(display_only_row.location_url, None);
        assert_eq!(with_url_row.location_display.as_deref(), Some("repo/path"));
        assert_eq!(
            with_url_row.location_url.as_deref(),
            Some("https://example.test/findings/42")
        );
    }

    #[test]
    fn observation_row_from_record_rejects_out_of_range_ordered_fields() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let occurrence = occurrence_record(tenant_id, finding.finding_id(), 3, 4);
        let record = ObservationRecord::new(
            tenant_id,
            occurrence.occurrence_id(),
            PolicyHash::from_bytes([0x77; 32]),
            OvidHash::from_bytes([0x88; 32]),
            RunId::from_raw(1),
            ShardId::from_raw(2),
            FenceEpoch::from_raw(i64::MAX as u64 + 1),
            LogicalTime::from_raw(10),
        );

        let err = ObservationRow::from_record(&record).expect_err("overflow should fail");
        assert_eq!(
            err,
            FindingsPgSchemaError::PgU64Conversion(PgU64ConversionError::OrderedOutOfRange {
                field: "fence_epoch",
                value: i64::MAX as u64 + 1,
            })
        );
    }

    #[test]
    fn observation_row_from_record_rejects_seen_at_above_pg_bigint_max() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let occurrence = occurrence_record(tenant_id, finding.finding_id(), 3, 4);
        let record = ObservationRecord::new(
            tenant_id,
            occurrence.occurrence_id(),
            PolicyHash::from_bytes([0x77; 32]),
            OvidHash::from_bytes([0x88; 32]),
            RunId::from_raw(1),
            ShardId::from_raw(2),
            FenceEpoch::from_raw(9),
            LogicalTime::from_raw(i64::MAX as u64 + 1),
        );

        let err = ObservationRow::from_record(&record).expect_err("overflow should fail");
        assert_eq!(
            err,
            FindingsPgSchemaError::PgU64Conversion(PgU64ConversionError::OrderedOutOfRange {
                field: "seen_at",
                value: i64::MAX as u64 + 1,
            })
        );
    }

    #[test]
    fn policy_hash_only_appears_in_observation_natural_key_columns() {
        assert!(
            !OCCURRENCES_CANONICAL_UNIQUE_COLUMNS.contains(&"policy_hash"),
            "occurrences natural key must remain policy-independent"
        );
        assert!(
            OBSERVATIONS_CANONICAL_UNIQUE_COLUMNS.contains(&"policy_hash"),
            "observations natural key must remain policy-scoped"
        );
    }

    #[test]
    fn column_lists_are_non_empty_and_unique() {
        for columns in [
            FINDINGS_PRIMARY_KEY_COLUMNS,
            OCCURRENCES_PRIMARY_KEY_COLUMNS,
            OBSERVATIONS_PRIMARY_KEY_COLUMNS,
            FINDINGS_INSERT_COLUMNS,
            OCCURRENCES_INSERT_COLUMNS,
            OBSERVATIONS_INSERT_COLUMNS,
            FINDINGS_CANONICAL_UNIQUE_COLUMNS,
            OCCURRENCES_CANONICAL_UNIQUE_COLUMNS,
            OBSERVATIONS_CANONICAL_UNIQUE_COLUMNS,
        ] {
            assert_non_empty_unique(columns);
        }
    }

    #[test]
    fn project_batch_returns_empty_projection_for_empty_batch() {
        let projected = project_findings_batch(FindingsUpsertBatch::default())
            .expect("empty batch should project");

        assert!(projected.is_empty());
        assert_eq!(projected.total_rows(), 0);
        assert!(projected.findings().is_empty());
        assert!(projected.occurrences().is_empty());
        assert!(projected.observations().is_empty());
    }

    #[test]
    fn project_batch_validates_and_projects_all_rows() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let occurrence = occurrence_record(tenant_id, finding.finding_id(), 3, 4);
        let observation = observation_record(tenant_id, occurrence.occurrence_id(), 12, 13)
            .with_location(Location::try_new("repo/path".into(), None).expect("valid location"));
        let findings = [finding.clone()];
        let occurrences = [occurrence.clone()];
        let observations = [observation.clone()];
        let batch = FindingsUpsertBatch::new(&findings, &occurrences, &observations);

        let projected = project_findings_batch(batch).expect("valid batch should project");

        assert_eq!(projected.total_rows(), 3);
        assert_eq!(projected.findings(), &[FindingRow::from_record(&finding)]);
        assert_eq!(
            projected.occurrences(),
            &[OccurrenceRow::from_record(&occurrence).expect("projection should succeed")]
        );
        assert_eq!(
            projected.observations(),
            &[ObservationRow::from_record(&observation).expect("projection should succeed")]
        );
    }

    #[test]
    fn validate_batch_accepts_canonical_batches_built_from_public_contracts() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let occurrence = occurrence_record(tenant_id, finding.finding_id(), 3, 4);
        let observation = observation_record(tenant_id, occurrence.occurrence_id(), 12, 13);
        let findings = [finding];
        let occurrences = [occurrence];
        let observations = [observation];
        let batch = FindingsUpsertBatch::new(&findings, &occurrences, &observations);

        validate_findings_batch(batch).expect("canonical batch should pass validation");
    }

    #[test]
    fn project_batch_accepts_incremental_submission_without_parent_finding() {
        // Simulate an incremental write: the parent FindingRecord was already
        // persisted in a prior batch, so this batch contains only an
        // OccurrenceRecord referencing that finding_id.
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let occurrence = occurrence_record(tenant_id, finding.finding_id(), 3, 4);
        let occurrences = [occurrence];
        // No findings in this batch — they're already durable.
        let batch = FindingsUpsertBatch::new(&[], &occurrences, &[]);

        // Per the FindingsSink contract, references may be "persisted or
        // in-batch". project_batch should accept this incremental batch.
        let result = project_findings_batch(batch);
        assert!(
            result.is_ok(),
            "incremental batch with already-durable parent should project, got: {result:?}"
        );
    }

    #[test]
    fn occurrence_row_rejects_span_exceeding_bigint_max() {
        // byte_offset and byte_length each fit in i64, but their sum exceeds
        // i64::MAX — mirroring the SQL occurrences_span_no_overflow_ck
        // constraint.
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let record = occurrence_record(tenant_id, finding.finding_id(), i64::MAX as u64 - 1, 3);

        let err = OccurrenceRow::from_record(&record)
            .expect_err("span overflow should be rejected at the Rust layer");
        assert_eq!(
            err,
            FindingsPgSchemaError::SpanOverflow {
                byte_offset: i64::MAX - 1,
                byte_length: 3,
            }
        );
    }

    #[test]
    fn occurrence_row_accepts_span_at_bigint_max_boundary() {
        // byte_offset + byte_length == i64::MAX is the largest valid span.
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding = finding_record(tenant_id);
        let record = occurrence_record(tenant_id, finding.finding_id(), i64::MAX as u64 - 1, 1);

        let row = OccurrenceRow::from_record(&record)
            .expect("span exactly at i64::MAX boundary should be accepted");
        assert_eq!(row.byte_offset, i64::MAX - 1);
        assert_eq!(row.byte_length, 1);
    }

    #[test]
    fn write_sql_constants_reference_canonical_table_names() {
        assert!(FINDINGS_INSERT_SQL.contains(FINDINGS_TABLE));
        assert!(OCCURRENCES_INSERT_SQL.contains(OCCURRENCES_TABLE));
        assert!(OBSERVATIONS_INSERT_OR_MERGE_SQL.contains(OBSERVATIONS_TABLE));
        assert!(FINDINGS_COUNT_SQL.contains(FINDINGS_TABLE));
        assert!(OCCURRENCES_COUNT_SQL.contains(OCCURRENCES_TABLE));
        assert!(OBSERVATIONS_COUNT_SQL.contains(OBSERVATIONS_TABLE));
        assert!(TRUNCATE_ALL_SQL.contains(OBSERVATIONS_TABLE));
        assert!(TRUNCATE_ALL_SQL.contains(OCCURRENCES_TABLE));
        assert!(TRUNCATE_ALL_SQL.contains(FINDINGS_TABLE));
    }

    #[test]
    fn findings_insert_sql_uses_identity_verifying_conflict_update() {
        assert_sql_contains_all(
            FINDINGS_INSERT_SQL,
            &[
                "ON CONFLICT (tenant_id, finding_id) DO UPDATE",
                "SET stable_item_id = findings.stable_item_id",
                "WHERE findings.stable_item_id = EXCLUDED.stable_item_id",
                "AND findings.rule_fingerprint = EXCLUDED.rule_fingerprint",
                "AND findings.secret_hash = EXCLUDED.secret_hash",
                "RETURNING 1",
            ],
        );
        assert!(
            !FINDINGS_INSERT_SQL.contains("DO NOTHING"),
            "finding upsert must detect identity mismatches rather than skipping them"
        );
    }

    #[test]
    fn occurrences_insert_sql_uses_identity_verifying_conflict_update() {
        assert_sql_contains_all(
            OCCURRENCES_INSERT_SQL,
            &[
                "ON CONFLICT (tenant_id, occurrence_id) DO UPDATE",
                "SET finding_id = occurrences.finding_id",
                "WHERE occurrences.finding_id = EXCLUDED.finding_id",
                "AND occurrences.object_version_id = EXCLUDED.object_version_id",
                "AND occurrences.byte_offset = EXCLUDED.byte_offset",
                "AND occurrences.byte_length = EXCLUDED.byte_length",
                "RETURNING 1",
            ],
        );
        assert!(
            !OCCURRENCES_INSERT_SQL.contains("DO NOTHING"),
            "occurrence upsert must detect identity mismatches rather than skipping them"
        );
    }

    #[test]
    fn observations_insert_sql_uses_monotonic_merge_keywords() {
        assert_sql_contains_all(
            OBSERVATIONS_INSERT_OR_MERGE_SQL,
            &[
                "ON CONFLICT (tenant_id, observation_id) DO UPDATE",
                "seen_at = GREATEST(observations.seen_at, EXCLUDED.seen_at)",
                "location_display = CASE",
                "location_url = CASE",
                "COALESCE",
                "RETURNING 1",
            ],
        );
    }

    #[test]
    fn observations_insert_sql_uses_correct_location_display_coalesce_branch() {
        assert!(
            OBSERVATIONS_INSERT_OR_MERGE_SQL.contains(
                "ELSE COALESCE(observations.location_display, EXCLUDED.location_display)"
            ),
            "location_display fallback must use EXCLUDED.location_display"
        );
        assert!(
            !OBSERVATIONS_INSERT_OR_MERGE_SQL
                .contains("ELSE COALESCE(observations.location_display, EXCLUDED.location_url)"),
            "location_display fallback must not reference EXCLUDED.location_url"
        );
        // location_url follows the same source as location_display — it does
        // not use independent COALESCE. The display-gated CASE ensures the url
        // and display always come from the same observation record.
        assert!(
            OBSERVATIONS_INSERT_OR_MERGE_SQL
                .contains("WHEN EXCLUDED.location_display IS NOT NULL THEN EXCLUDED.location_url"),
            "location_url must follow incoming display source in incoming-wins branch"
        );
        assert!(
            OBSERVATIONS_INSERT_OR_MERGE_SQL.contains(
                "WHEN observations.location_display IS NOT NULL THEN observations.location_url"
            ),
            "location_url must follow existing display source in existing-wins branch"
        );
    }

    #[test]
    fn observations_insert_sql_pairs_location_url_with_display_source() {
        // location_url must follow whichever record provided location_display,
        // never independently COALESCE to the other record's URL. Independent
        // COALESCE can pair a display string from one observation with a URL
        // from a different observation — incoherent provenance.
        assert!(
            !OBSERVATIONS_INSERT_OR_MERGE_SQL
                .contains("COALESCE(EXCLUDED.location_url, observations.location_url)"),
            "location_url must not independently fall back to the other record's URL \
             when the incoming record wins provenance — url must follow display source"
        );
        assert!(
            !OBSERVATIONS_INSERT_OR_MERGE_SQL
                .contains("COALESCE(observations.location_url, EXCLUDED.location_url)"),
            "location_url must not independently fall back to the other record's URL \
             when the existing record wins provenance — url must follow display source"
        );
    }

    #[test]
    fn observations_insert_sql_verifies_observation_identity_fields() {
        assert_sql_contains_all(
            OBSERVATIONS_INSERT_OR_MERGE_SQL,
            &[
                "WHERE observations.occurrence_id = EXCLUDED.occurrence_id",
                "AND observations.policy_hash = EXCLUDED.policy_hash",
                "AND observations.ovid_hash = EXCLUDED.ovid_hash",
            ],
        );
    }

    #[test]
    fn count_sql_constants_cast_to_bigint() {
        for sql in [
            FINDINGS_COUNT_SQL,
            OCCURRENCES_COUNT_SQL,
            OBSERVATIONS_COUNT_SQL,
        ] {
            assert!(
                sql.contains("COUNT(*)::BIGINT"),
                "count SQL must cast COUNT(*) to BIGINT: {sql}"
            );
        }
    }

    #[test]
    fn truncate_all_sql_uses_child_first_order() {
        assert_eq!(
            TRUNCATE_ALL_SQL,
            "TRUNCATE TABLE observations, occurrences, findings"
        );
    }

    #[test]
    fn migration_advisory_lock_key_matches_ascii_mnemonic() {
        let bytes = MIGRATION_ADVISORY_LOCK_KEY.to_be_bytes();
        let ascii = std::str::from_utf8(&bytes).expect("lock key bytes should be ASCII");
        assert_eq!(ascii, "GFPGMIG1");
    }
}
