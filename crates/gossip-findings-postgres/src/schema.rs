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
    FindingsPgSchemaError,
    types::{u64_to_pg_bigint_bits, u64_to_pg_bigint_checked},
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

/// Minimal schema plan for the current findings write model.
///
/// The type is intentionally zero-sized because the current backend exposes a
/// single canonical schema shape. If future storage surfaces add new durable
/// tables, they should become new constants and projection types rather than
/// optional toggles on this plan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FindingsSchemaPlan;

impl FindingsSchemaPlan {
    /// Construct the canonical findings schema plan.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Validate a contracts-layer batch against the schema plan.
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
    pub fn validate_batch(
        self,
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<(), FindingsPgSchemaError> {
        let _ = self;
        batch.validate_observation_identity()?;
        Ok(())
    }

    /// Project a contracts-layer batch into Postgres-ready primitive row types.
    ///
    /// Each projected layer preserves the input slice order, which lets later
    /// SQL binders expand arrays in a stable row order without extra
    /// reindexing.
    pub fn project_batch(
        self,
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<ProjectedFindingsBatch, FindingsPgSchemaError> {
        self.validate_batch(batch)?;

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
    /// `BIGINT` field exceeds PostgreSQL's signed range.
    pub fn from_record(record: &OccurrenceRecord) -> Result<Self, FindingsPgSchemaError> {
        Ok(Self {
            tenant_id: *record.tenant_id().as_bytes(),
            occurrence_id: *record.occurrence_id().as_bytes(),
            finding_id: *record.finding_id().as_bytes(),
            object_version_id: *record.object_version_id().as_bytes(),
            byte_offset: u64_to_pg_bigint_checked(record.byte_offset(), "byte_offset")?,
            byte_length: u64_to_pg_bigint_checked(record.byte_length().get(), "byte_length")?,
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, num::NonZeroU64};

    use gossip_contracts::{
        connector::Location,
        identity::{
            FenceEpoch, FindingId, LogicalTime, NormHash, ObjectVersionId, PolicyHash,
            RuleFingerprint, RunId, ShardId, StableItemId, TenantId, TenantSecretKey,
            key_secret_hash,
        },
        persistence::{
            FindingRecord, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord, OvidHash,
        },
    };
    use gossip_done_ledger_postgres::schema as done_ledger_schema;

    use crate::types::{PgU64ConversionError, pg_bigint_to_u64_bits};

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
        let record = occurrence_record(tenant_id, finding.finding_id(), i64::MAX as u64, 7);
        let row = OccurrenceRow::from_record(&record).expect("boundary values should project");

        assert_eq!(row.tenant_id, *record.tenant_id().as_bytes());
        assert_eq!(row.occurrence_id, *record.occurrence_id().as_bytes());
        assert_eq!(row.finding_id, *record.finding_id().as_bytes());
        assert_eq!(
            row.object_version_id,
            *record.object_version_id().as_bytes()
        );
        assert_eq!(row.byte_offset, i64::MAX);
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
        let projected = FindingsSchemaPlan::new()
            .project_batch(FindingsUpsertBatch::default())
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

        let projected = FindingsSchemaPlan::new()
            .project_batch(batch)
            .expect("valid batch should project");

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

        FindingsSchemaPlan::new()
            .validate_batch(batch)
            .expect("canonical batch should pass validation");
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
        let result = FindingsSchemaPlan::new().project_batch(batch);
        assert!(
            result.is_ok(),
            "incremental batch with already-durable parent should project, got: {result:?}"
        );
    }

    #[test]
    fn migration_advisory_lock_key_matches_ascii_mnemonic() {
        let bytes = MIGRATION_ADVISORY_LOCK_KEY.to_be_bytes();
        let ascii = std::str::from_utf8(&bytes).expect("lock key bytes should be ASCII");
        assert_eq!(ascii, "GFPGMIG1");
    }

    #[test]
    fn migration_advisory_lock_key_is_distinct_from_done_ledger() {
        assert_ne!(
            MIGRATION_ADVISORY_LOCK_KEY,
            done_ledger_schema::MIGRATION_ADVISORY_LOCK_KEY
        );
    }
}
