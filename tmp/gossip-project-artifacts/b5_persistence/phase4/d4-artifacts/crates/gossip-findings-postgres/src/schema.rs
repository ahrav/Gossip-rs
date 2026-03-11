//! Canonical PostgreSQL schema plan for findings persistence.
//!
//! D0/D1 lock the relational write model before backend SQL code is written.
//! This prevents backend code from drifting away from the contracts-layer
//! identity model.
//!
//! ## Table roles
//!
//! - `findings` stores stable finding identity and secret/rule linkage.
//! - `occurrences` stores version-specific byte ranges and references findings.
//! - `observations` stores policy-scoped detection/provenance facts and
//!   references occurrences.
//! - `secret_triage` is reserved for later work and intentionally **not**
//!   modeled yet because there is no contract type for mutable triage state.

use gossip_contracts::persistence::{
    FindingRecord, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
};

use crate::{
    FindingsPgSchemaError,
    pg_int::{u64_to_pg_i64_bits, u64_to_pg_i64_checked},
};

/// Durable findings table name.
pub const FINDINGS_TABLE: &str = "findings";
/// Durable occurrences table name.
pub const OCCURRENCES_TABLE: &str = "occurrences";
/// Durable observations table name.
pub const OBSERVATIONS_TABLE: &str = "observations";
/// Reserved future table name for secret-level triage state.
pub const OPTIONAL_SECRET_TRIAGE_TABLE: &str = "secret_triage";

/// Migration history table name.
pub const SCHEMA_MIGRATIONS_TABLE: &str = "findings_schema_migrations";

/// Advisory lock key guarding migration application.
///
/// Fixed 64-bit value derived once for the logical namespace
/// `gossip-findings-postgres:migrations`.
pub const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x47465047_4d494731; // "GFPGMIG1"

/// Primary key columns for `findings`.
pub const FINDINGS_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "finding_id"];
/// Primary key columns for `occurrences`.
pub const OCCURRENCES_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "occurrence_id"];
/// Primary key columns for `observations`.
pub const OBSERVATIONS_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "observation_id"];
/// Reserved future primary key columns for `secret_triage`.
pub const OPTIONAL_SECRET_TRIAGE_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "secret_hash"];

/// Full insert column set for `findings`.
pub const FINDINGS_COLUMNS: &[&str] = &[
    "tenant_id",
    "finding_id",
    "stable_item_id",
    "rule_fingerprint",
    "secret_hash",
];

/// Full insert column set for `occurrences`.
pub const OCCURRENCES_COLUMNS: &[&str] = &[
    "tenant_id",
    "occurrence_id",
    "finding_id",
    "object_version_id",
    "byte_offset",
    "byte_length",
];

/// Full insert column set for `observations`.
pub const OBSERVATIONS_COLUMNS: &[&str] = &[
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

/// Canonical natural-key uniqueness set for `findings`.
pub const FINDINGS_CANONICAL_UNIQUE_COLUMNS: &[&str] = &[
    "tenant_id",
    "stable_item_id",
    "rule_fingerprint",
    "secret_hash",
];

/// Canonical natural-key uniqueness set for `occurrences`.
///
/// Note the intentional absence of `policy_hash`: occurrences are version- and
/// span-scoped, not policy-scoped.
pub const OCCURRENCES_CANONICAL_UNIQUE_COLUMNS: &[&str] = &[
    "tenant_id",
    "finding_id",
    "object_version_id",
    "byte_offset",
    "byte_length",
];

/// Canonical natural-key uniqueness set for `observations`.
///
/// This is the policy-scoped layer, so `policy_hash` belongs here.
pub const OBSERVATIONS_CANONICAL_UNIQUE_COLUMNS: &[&str] = &[
    "tenant_id",
    "policy_hash",
    "occurrence_id",
];

/// Index name for tenant-scoped secret grouping lookups.
pub const FINDINGS_TENANT_SECRET_HASH_INDEX: &str = "findings_tenant_secret_hash_idx";
/// Index name for item-centric lookups.
pub const FINDINGS_TENANT_STABLE_ITEM_INDEX: &str = "findings_tenant_stable_item_id_idx";
/// Index name for joining occurrences back to findings.
pub const OCCURRENCES_TENANT_FINDING_INDEX: &str = "occurrences_tenant_finding_id_idx";
/// Index name for object-version provenance lookups.
pub const OCCURRENCES_TENANT_OBJECT_VERSION_INDEX: &str =
    "occurrences_tenant_object_version_id_idx";
/// Index name for tenant-wide latest-seen queries over observations.
pub const OBSERVATIONS_TENANT_SEEN_AT_INDEX: &str = "observations_tenant_seen_at_idx";
/// Index name for policy/time filtering over observations.
pub const OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX: &str =
    "observations_tenant_policy_seen_at_idx";
/// Index name for occurrence -> observation joins.
pub const OBSERVATIONS_TENANT_OCCURRENCE_INDEX: &str =
    "observations_tenant_occurrence_id_idx";
/// Index name for policy+done-ledger join/provenance lookups.
pub const OBSERVATIONS_TENANT_OVID_INDEX: &str = "observations_tenant_ovid_hash_idx";
/// Index name for operational provenance by `(tenant_id, run_id, shard_id)`.
pub const OBSERVATIONS_TENANT_RUN_SHARD_INDEX: &str =
    "observations_tenant_run_shard_idx";

/// Stable Postgres schema plan for the findings backend.
///
/// `include_secret_triage` only reserves whether later migrations may install
/// the optional triage table. D0/D1 do not model any mutable triage row shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsSchemaPlan {
    include_secret_triage: bool,
}

impl Default for FindingsSchemaPlan {
    fn default() -> Self {
        Self::mvp()
    }
}

impl FindingsSchemaPlan {
    /// MVP schema plan: three normalized write-path tables, no triage table yet.
    #[inline]
    #[must_use]
    pub const fn mvp() -> Self {
        Self {
            include_secret_triage: false,
        }
    }

    /// Enable reservation of the future `secret_triage` table.
    #[inline]
    #[must_use]
    pub const fn with_secret_triage(self) -> Self {
        Self {
            include_secret_triage: true,
        }
    }

    /// Returns whether the optional `secret_triage` table is part of the plan.
    #[inline]
    #[must_use]
    pub const fn include_secret_triage(self) -> bool {
        self.include_secret_triage
    }

    /// Validate a contracts-layer batch against the Postgres schema plan.
    ///
    /// This defers to the contracts layer for canonical observation identity and
    /// referential closure, then lets row projection enforce Postgres-specific
    /// integer encoding constraints.
    pub fn validate_batch(self, batch: FindingsUpsertBatch<'_>) -> Result<(), FindingsPgSchemaError> {
        let _ = self;
        batch.validate_observation_identity()?;
        batch.validate_referential_integrity()?;
        Ok(())
    }

    /// Project a contracts-layer batch into Postgres-friendly primitive rows.
    ///
    /// The resulting rows are schema-final: later D1 migrations and D2 insert
    /// statements should consume this shape directly.
    pub fn project_batch(
        self,
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<ProjectedFindingsBatch, FindingsPgSchemaError> {
        self.validate_batch(batch)?;

        let findings = batch.findings().iter().map(FindingRow::from_record).collect();

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

/// Stable-row projection for the `findings` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRow {
    pub tenant_id: [u8; 32],
    pub finding_id: [u8; 32],
    pub stable_item_id: [u8; 32],
    pub rule_fingerprint: [u8; 32],
    pub secret_hash: [u8; 32],
}

impl FindingRow {
    /// Project a contracts-layer [`FindingRecord`] into the durable row shape.
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

/// Version-specific row projection for the `occurrences` table.
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
    /// Project a contracts-layer [`OccurrenceRecord`] into the durable row
    /// shape, validating non-negative ordered `BIGINT` columns.
    pub fn from_record(record: &OccurrenceRecord) -> Result<Self, FindingsPgSchemaError> {
        Ok(Self {
            tenant_id: *record.tenant_id().as_bytes(),
            occurrence_id: *record.occurrence_id().as_bytes(),
            finding_id: *record.finding_id().as_bytes(),
            object_version_id: *record.object_version_id().as_bytes(),
            byte_offset: u64_to_pg_i64_checked(record.byte_offset(), "occurrences.byte_offset")?,
            byte_length: u64_to_pg_i64_checked(
                record.byte_length().get(),
                "occurrences.byte_length",
            )?,
        })
    }
}

/// Policy-scoped row projection for the `observations` table.
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
    /// Project a contracts-layer [`ObservationRecord`] into the durable row
    /// shape.
    ///
    /// `run_id` and `shard_id` use bit reinterpretation because they behave as
    /// opaque equality/grouping identifiers. `fence_epoch` and `seen_at` use
    /// checked non-negative `BIGINT` because ordering semantics matter.
    pub fn from_record(record: &ObservationRecord) -> Result<Self, FindingsPgSchemaError> {
        let (location_display, location_url) = match record.location() {
            Some(location) => (
                Some(location.display().to_owned()),
                location.url().map(ToOwned::to_owned),
            ),
            None => (None, None),
        };

        Ok(Self {
            tenant_id: *record.tenant_id().as_bytes(),
            observation_id: *record.observation_id().as_bytes(),
            occurrence_id: *record.occurrence_id().as_bytes(),
            policy_hash: *record.policy_hash().as_bytes(),
            ovid_hash: *record.ovid_hash().as_bytes(),
            run_id: u64_to_pg_i64_bits(record.run_id().as_raw()),
            shard_id: u64_to_pg_i64_bits(record.shard_id().as_raw()),
            fence_epoch: u64_to_pg_i64_checked(
                record.fence_epoch().as_raw(),
                "observations.fence_epoch",
            )?,
            seen_at: u64_to_pg_i64_checked(record.seen_at().as_raw(), "observations.seen_at")?,
            location_display,
            location_url,
        })
    }
}

/// Fully projected, Postgres-friendly findings batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectedFindingsBatch {
    findings: Vec<FindingRow>,
    occurrences: Vec<OccurrenceRow>,
    observations: Vec<ObservationRow>,
}

impl ProjectedFindingsBatch {
    /// Project the contracts batch using the default MVP schema plan.
    pub fn from_contract_batch(batch: FindingsUpsertBatch<'_>) -> Result<Self, FindingsPgSchemaError> {
        FindingsSchemaPlan::mvp().project_batch(batch)
    }

    /// Stable finding rows.
    #[inline]
    #[must_use]
    pub fn findings(&self) -> &[FindingRow] {
        &self.findings
    }

    /// Version-specific occurrence rows.
    #[inline]
    #[must_use]
    pub fn occurrences(&self) -> &[OccurrenceRow] {
        &self.occurrences
    }

    /// Policy-scoped observation rows.
    #[inline]
    #[must_use]
    pub fn observations(&self) -> &[ObservationRow] {
        &self.observations
    }

    /// Returns `true` if all three layers are empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.occurrences.is_empty() && self.observations.is_empty()
    }

    /// Total number of projected rows.
    #[inline]
    #[must_use]
    pub fn total_rows(&self) -> usize {
        self.findings.len() + self.occurrences.len() + self.observations.len()
    }
}

// Tests intentionally omitted for this task.
// D2/D3 should add coverage for:
// - schema plan projections preserving policy-independent occurrence keys
// - observation rows differing across policy_hash for same occurrence
// - BIGINT conversion bounds for seen_at/fence_epoch/byte offsets
// - location projection preserving safe display/url fields only


/// Idempotent insert / identity-verification SQL for `findings`.
pub const FINDINGS_INSERT_SQL: &str = r#"
INSERT INTO findings (
    tenant_id,
    finding_id,
    stable_item_id,
    rule_fingerprint,
    secret_hash
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, finding_id) DO UPDATE
SET stable_item_id = findings.stable_item_id
WHERE findings.stable_item_id = EXCLUDED.stable_item_id
  AND findings.rule_fingerprint = EXCLUDED.rule_fingerprint
  AND findings.secret_hash = EXCLUDED.secret_hash
RETURNING 1
"#;

/// Idempotent insert / identity-verification SQL for `occurrences`.
pub const OCCURRENCES_INSERT_SQL: &str = r#"
INSERT INTO occurrences (
    tenant_id,
    occurrence_id,
    finding_id,
    object_version_id,
    byte_offset,
    byte_length
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, occurrence_id) DO UPDATE
SET finding_id = occurrences.finding_id
WHERE occurrences.finding_id = EXCLUDED.finding_id
  AND occurrences.object_version_id = EXCLUDED.object_version_id
  AND occurrences.byte_offset = EXCLUDED.byte_offset
  AND occurrences.byte_length = EXCLUDED.byte_length
RETURNING 1
"#;

/// Idempotent insert / monotonic-merge SQL for `observations`.
///
/// On replay of the same observation identity (`tenant_id`, `observation_id`):
/// - `seen_at` advances monotonically to the maximum timestamp,
/// - `run_id`, `shard_id`, and `fence_epoch` follow the winning provenance row,
/// - safe location metadata is filled if the existing row lacks it,
/// - conflicting immutable identity fields are rejected by the `WHERE` clause
///   and surfaced as a backend conflict when no row is returned.
pub const OBSERVATIONS_INSERT_OR_MERGE_SQL: &str = r#"
INSERT INTO observations (
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
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (tenant_id, observation_id) DO UPDATE
SET
    run_id = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
          OR (
              EXCLUDED.seen_at = observations.seen_at
              AND observations.location_display IS NULL
              AND EXCLUDED.location_display IS NOT NULL
          )
            THEN EXCLUDED.run_id
        ELSE observations.run_id
    END,
    shard_id = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
          OR (
              EXCLUDED.seen_at = observations.seen_at
              AND observations.location_display IS NULL
              AND EXCLUDED.location_display IS NOT NULL
          )
            THEN EXCLUDED.shard_id
        ELSE observations.shard_id
    END,
    fence_epoch = CASE
        WHEN EXCLUDED.seen_at > observations.seen_at
          OR (
              EXCLUDED.seen_at = observations.seen_at
              AND observations.location_display IS NULL
              AND EXCLUDED.location_display IS NOT NULL
          )
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
            THEN COALESCE(EXCLUDED.location_url, observations.location_url)
        WHEN EXCLUDED.seen_at < observations.seen_at
            THEN COALESCE(observations.location_url, EXCLUDED.location_url)
        WHEN observations.location_display IS NULL AND EXCLUDED.location_display IS NOT NULL
            THEN EXCLUDED.location_url
        ELSE COALESCE(observations.location_url, EXCLUDED.location_url)
    END
WHERE observations.occurrence_id = EXCLUDED.occurrence_id
  AND observations.policy_hash = EXCLUDED.policy_hash
  AND observations.ovid_hash = EXCLUDED.ovid_hash
RETURNING 1
"#;

/// Count all durable finding rows.
pub const SELECT_FINDINGS_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT FROM findings";
/// Count all durable occurrence rows.
pub const OCCURRENCES_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT FROM occurrences";
/// Count all durable observation rows.
pub const OBSERVATIONS_COUNT_SQL: &str = "SELECT COUNT(*)::BIGINT FROM observations";

/// Remove all durable findings-layer rows in foreign-key order.
pub const TRUNCATE_ALL_SQL: &str =
    "TRUNCATE TABLE observations, occurrences, findings";


/// Count grouped observations for one tenant, broken down by policy hash.
pub const COUNT_OBSERVATIONS_BY_TENANT_POLICY_SQL: &str = r#"
SELECT
    tenant_id,
    policy_hash,
    COUNT(*)::BIGINT AS observation_count
FROM observations
WHERE tenant_id = $1
GROUP BY tenant_id, policy_hash
ORDER BY policy_hash ASC
"#;

/// List the latest observation per finding for a tenant.
///
/// This is the D4 placeholder for "findings needing triage" until mutable
/// triage state exists. It returns one row per finding, choosing the latest
/// observation by `(seen_at DESC, observation_id DESC)`.
pub const LIST_FINDINGS_NEEDING_TRIAGE_SQL: &str = r#"
SELECT
    latest.tenant_id,
    latest.finding_id,
    latest.stable_item_id,
    latest.occurrence_id,
    latest.observation_id,
    latest.policy_hash,
    latest.seen_at,
    latest.location_display,
    latest.location_url
FROM (
    SELECT DISTINCT ON (f.finding_id)
        f.tenant_id,
        f.finding_id,
        f.stable_item_id,
        o.occurrence_id,
        ob.observation_id,
        ob.policy_hash,
        ob.seen_at,
        ob.location_display,
        ob.location_url
    FROM findings AS f
    INNER JOIN occurrences AS o
        ON o.tenant_id = f.tenant_id
       AND o.finding_id = f.finding_id
    INNER JOIN observations AS ob
        ON ob.tenant_id = o.tenant_id
       AND ob.occurrence_id = o.occurrence_id
    WHERE f.tenant_id = $1
    ORDER BY f.finding_id, ob.seen_at DESC, ob.observation_id DESC
) AS latest
ORDER BY latest.seen_at DESC, latest.observation_id DESC
LIMIT $2
"#;
