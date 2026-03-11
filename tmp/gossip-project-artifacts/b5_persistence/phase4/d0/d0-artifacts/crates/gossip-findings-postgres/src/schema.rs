//! Canonical PostgreSQL schema plan for findings persistence.
//!
//! D0 intentionally locks the relational write model before migrations or SQL
//! statements are written. This prevents backend code from drifting away from
//! the contracts-layer identity model.
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

/// Canonical table name for stable findings.
pub const FINDINGS_TABLE: &str = "findings";
/// Canonical table name for version-scoped occurrences.
pub const OCCURRENCES_TABLE: &str = "occurrences";
/// Canonical table name for policy-scoped observations.
pub const OBSERVATIONS_TABLE: &str = "observations";
/// Reserved future table name for secret-level triage state.
pub const OPTIONAL_SECRET_TRIAGE_TABLE: &str = "secret_triage";

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
///
/// This is defense-in-depth on top of the derived `finding_id` primary key.
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
/// Index name for policy/time filtering over observations.
pub const OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX: &str =
    "observations_tenant_policy_seen_at_idx";
/// Index name for occurrence -> observation joins.
pub const OBSERVATIONS_TENANT_OCCURRENCE_INDEX: &str =
    "observations_tenant_occurrence_id_idx";
/// Index name for policy+done-ledger join/provenance lookups.
pub const OBSERVATIONS_TENANT_OVID_INDEX: &str = "observations_tenant_ovid_hash_idx";
/// Index name for operational provenance by `(run_id, shard_id)`.
pub const OBSERVATIONS_TENANT_RUN_SHARD_INDEX: &str =
    "observations_tenant_run_shard_idx";

/// Stable Postgres schema plan for the findings backend.
///
/// `include_secret_triage` only reserves whether later migrations may install
/// the optional triage table. D0 does not model any mutable triage row shape.
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
    pub fn validate_batch(
        self,
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<(), FindingsPgSchemaError> {
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
    pub fn from_contract_batch(
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<Self, FindingsPgSchemaError> {
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
// D1/D2 should add coverage for:
// - schema plan projections preserving policy-independent occurrence keys
// - observation rows differing across policy_hash for same occurrence
// - BIGINT conversion bounds for seen_at/fence_epoch/byte offsets
// - location projection preserving safe display/url fields only
