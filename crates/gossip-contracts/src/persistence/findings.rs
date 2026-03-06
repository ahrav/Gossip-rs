//! Findings persistence: the three-layer data model for detected secrets.
//!
//! Scan results are persisted in three normalized layers, each with different
//! stability and scoping properties:
//!
//! 1. **[`FindingRecord`]** — Stable identity layer. A finding is uniquely
//!    identified by `(tenant, stable_item_id, rule_fingerprint, secret_hash)`.
//!    This key is policy-independent and version-independent: the same secret
//!    detected by the same rule in the same logical item produces the same
//!    finding regardless of which object version or scan policy surfaced it.
//!
//! 2. **[`OccurrenceRecord`]** — Version-specific layer. An occurrence pins a
//!    finding to a specific `ObjectVersionId` with a `(byte_offset, byte_length)`
//!    span. The same finding can have multiple occurrences across different
//!    versions of the same item.
//!
//! 3. **[`ObservationRecord`]** — Policy- and run-scoped layer. An observation
//!    records that a particular occurrence was seen during a specific scan run,
//!    under a specific policy, in a specific shard and fence epoch. Optional
//!    display metadata ([`Location`]) lives here because it is presentation
//!    context, not stable identity.
//!
//! ## Referential integrity
//!
//! Each occurrence references a finding; each observation references an
//! occurrence. Backends must enforce this either through foreign keys or by
//! accepting referential closure within a single [`FindingsUpsertBatch`].
//!
//! ## Idempotency
//!
//! All writes go through [`FindingsSink::upsert_batch`], which backends must
//! implement as an idempotent upsert. Replaying the same batch — or
//! overlapping batches — must not create duplicate rows.

use std::{error::Error, num::NonZeroU64};

use crate::{
    connector::Location,
    identity::{
        FenceEpoch, FindingId, FindingIdInputs, LogicalTime, ObjectVersionId, ObservationId,
        ObservationIdInputs, OccurrenceId, OccurrenceIdInputs, PolicyHash, RuleFingerprint, RunId,
        SecretHash, ShardId, StableItemId, TenantId, derive_finding_id, derive_observation_id,
        derive_occurrence_id,
    },
};

use super::{PersistenceInputError, ovid::OvidHash};

/// Stable finding record (layer 1 of 3).
///
/// A finding represents "this secret (identified by [`SecretHash`]) was
/// detected by this rule ([`RuleFingerprint`]) in this logical item
/// ([`StableItemId`])". This identity is version-independent and
/// policy-independent: if the same secret appears in multiple versions of
/// the same item, or is detected by the same rule under different scan
/// policies, only one `FindingRecord` exists.
///
/// The [`FindingId`] is a content-addressed hash derived from the natural
/// key `(tenant, stable_item_id, rule_fingerprint, secret_hash)`, so
/// identical inputs always produce the same `finding_id` without
/// coordination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRecord {
    tenant_id: TenantId,
    finding_id: FindingId,
    stable_item_id: StableItemId,
    rule_fingerprint: RuleFingerprint,
    secret_hash: SecretHash,
}

impl FindingRecord {
    /// Construct a stable finding record, deriving [`FindingId`] from the
    /// natural key fields.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        stable_item_id: StableItemId,
        rule_fingerprint: RuleFingerprint,
        secret_hash: SecretHash,
    ) -> Self {
        let finding_id = derive_finding_id(&FindingIdInputs {
            tenant: tenant_id,
            item: stable_item_id,
            rule: rule_fingerprint,
            secret: secret_hash,
        });
        Self {
            tenant_id,
            finding_id,
            stable_item_id,
            rule_fingerprint,
            secret_hash,
        }
    }

    /// Tenant isolation boundary.
    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Content-addressed finding identity derived from the natural key.
    #[inline]
    #[must_use]
    pub const fn finding_id(&self) -> FindingId {
        self.finding_id
    }

    /// Logical item where the secret was detected (connector-scoped).
    #[inline]
    #[must_use]
    pub const fn stable_item_id(&self) -> StableItemId {
        self.stable_item_id
    }

    /// Detection rule that matched the secret.
    #[inline]
    #[must_use]
    pub const fn rule_fingerprint(&self) -> RuleFingerprint {
        self.rule_fingerprint
    }

    /// One-way hash of the secret material (raw bytes never stored).
    #[inline]
    #[must_use]
    pub const fn secret_hash(&self) -> SecretHash {
        self.secret_hash
    }

    /// Verify that the stored `finding_id` matches the content-addressed
    /// derivation from the record's natural key fields.
    ///
    /// Returns `true` if the stored ID is consistent with the derivation.
    /// Write-path callers can use this as a verification checkpoint.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        let expected = derive_finding_id(&FindingIdInputs {
            tenant: self.tenant_id,
            item: self.stable_item_id,
            rule: self.rule_fingerprint,
            secret: self.secret_hash,
        });
        self.finding_id == expected
    }
}

/// Version-specific occurrence record (layer 2 of 3).
///
/// An occurrence pins a [`FindingRecord`] to a concrete byte range within a
/// specific object version. The span `[byte_offset, byte_offset + byte_length)`
/// identifies where the secret material appears. `byte_length` is guaranteed
/// non-zero at construction time via [`NonZeroU64`].
///
/// Multiple occurrences can reference the same `finding_id` when the same
/// secret appears at different offsets or in different versions of the item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccurrenceRecord {
    tenant_id: TenantId,
    occurrence_id: OccurrenceId,
    finding_id: FindingId,
    object_version_id: ObjectVersionId,
    byte_offset: u64,
    byte_length: NonZeroU64,
}

impl OccurrenceRecord {
    /// Construct an occurrence record, validating that `byte_length > 0` and
    /// deriving [`OccurrenceId`] from the natural key fields.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceInputError::ZeroSpanLength`] if `byte_length`
    /// is zero — a zero-length span is meaningless for a secret occurrence.
    pub fn try_new(
        tenant_id: TenantId,
        finding_id: FindingId,
        object_version_id: ObjectVersionId,
        byte_offset: u64,
        byte_length: u64,
    ) -> Result<Self, PersistenceInputError> {
        let byte_length =
            NonZeroU64::new(byte_length).ok_or(PersistenceInputError::ZeroSpanLength)?;
        Ok(Self::new(
            tenant_id,
            finding_id,
            object_version_id,
            byte_offset,
            byte_length,
        ))
    }

    /// Construct an occurrence record from a pre-validated [`NonZeroU64`]
    /// span length, deriving [`OccurrenceId`] from the natural key fields.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        finding_id: FindingId,
        object_version_id: ObjectVersionId,
        byte_offset: u64,
        byte_length: NonZeroU64,
    ) -> Self {
        let occurrence_id = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_id,
            version: object_version_id,
            byte_offset,
            byte_length: byte_length.get(),
        });
        Self {
            tenant_id,
            occurrence_id,
            finding_id,
            object_version_id,
            byte_offset,
            byte_length,
        }
    }

    /// Tenant isolation boundary.
    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Content-addressed occurrence identity.
    #[inline]
    #[must_use]
    pub const fn occurrence_id(&self) -> OccurrenceId {
        self.occurrence_id
    }

    /// Parent finding this occurrence belongs to.
    #[inline]
    #[must_use]
    pub const fn finding_id(&self) -> FindingId {
        self.finding_id
    }

    /// Specific object version containing this occurrence.
    #[inline]
    #[must_use]
    pub const fn object_version_id(&self) -> ObjectVersionId {
        self.object_version_id
    }

    /// Byte offset within the object version where the secret begins.
    #[inline]
    #[must_use]
    pub const fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    /// Length of the secret span in bytes (guaranteed non-zero).
    #[inline]
    #[must_use]
    pub const fn byte_length(&self) -> NonZeroU64 {
        self.byte_length
    }

    /// Verify that the stored `occurrence_id` matches the content-addressed
    /// derivation from the record's identity fields.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        let expected = derive_occurrence_id(&OccurrenceIdInputs {
            finding: self.finding_id,
            version: self.object_version_id,
            byte_offset: self.byte_offset,
            byte_length: self.byte_length.get(),
        });
        self.occurrence_id == expected
    }
}

/// Policy- and run-scoped observation record (layer 3 of 3).
///
/// An observation records the fact that a specific [`OccurrenceRecord`] was
/// seen during a particular scan run, under a particular scan policy, in a
/// specific shard and fence epoch. This is the most granular layer — it
/// captures *when* and *how* a secret was detected, not just *where*.
///
/// [`Location`] metadata (display path and optional URL) is attached here
/// rather than on the occurrence or finding because it is presentation
/// context tied to the specific policy and run that produced the observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationRecord {
    tenant_id: TenantId,
    observation_id: ObservationId,
    occurrence_id: OccurrenceId,
    policy_hash: PolicyHash,
    ovid_hash: OvidHash,
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
    seen_at: LogicalTime,
    location: Option<Location>,
}

impl ObservationRecord {
    /// Construct an observation record, deriving [`ObservationId`] from the
    /// natural key fields.
    ///
    /// Location metadata is set to `None` by default; use
    /// [`with_location`](Self::with_location) to attach it via builder
    /// pattern.
    #[expect(
        clippy::too_many_arguments,
        reason = "ObservationRecord intentionally mirrors a flat durable row schema"
    )]
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        seen_at: LogicalTime,
    ) -> Self {
        let observation_id = derive_observation_id(&ObservationIdInputs {
            tenant: tenant_id,
            policy: policy_hash,
            occurrence: occurrence_id,
        });
        Self {
            tenant_id,
            observation_id,
            occurrence_id,
            policy_hash,
            ovid_hash,
            run_id,
            shard_id,
            fence_epoch,
            seen_at,
            location: None,
        }
    }

    /// Attach display-safe location metadata (path and optional URL).
    #[must_use]
    pub fn with_location(self, location: Location) -> Self {
        Self {
            location: Some(location),
            ..self
        }
    }

    /// Tenant isolation boundary.
    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Content-addressed observation identity.
    #[inline]
    #[must_use]
    pub const fn observation_id(&self) -> ObservationId {
        self.observation_id
    }

    /// Parent occurrence this observation references.
    #[inline]
    #[must_use]
    pub const fn occurrence_id(&self) -> OccurrenceId {
        self.occurrence_id
    }

    /// Scan policy under which this observation was produced.
    #[inline]
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    /// Object-version identity linking back to the done-ledger.
    #[inline]
    #[must_use]
    pub const fn ovid_hash(&self) -> OvidHash {
        self.ovid_hash
    }

    /// Run that produced this observation.
    #[inline]
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Shard being processed when this observation was recorded.
    #[inline]
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Lease epoch under which the writing worker held its shard lease.
    #[inline]
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }

    /// Logical timestamp when the occurrence was observed.
    #[inline]
    #[must_use]
    pub const fn seen_at(&self) -> LogicalTime {
        self.seen_at
    }

    /// Display-safe location metadata (path and optional URL), if attached.
    #[inline]
    #[must_use]
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    /// Verify that the stored `observation_id` matches the content-addressed
    /// derivation from the record's identity fields.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        let expected = derive_observation_id(&ObservationIdInputs {
            tenant: self.tenant_id,
            policy: self.policy_hash,
            occurrence: self.occurrence_id,
        });
        self.observation_id == expected
    }
}

/// Borrowed, zero-copy batch view grouping all three record layers for a
/// single [`FindingsSink::upsert_batch`] call.
///
/// This type borrows slices rather than owning them so the caller retains
/// control over allocation and can reuse buffers across flushes. An empty
/// batch (all three slices empty) is a valid no-op input.
#[derive(Clone, Copy, Debug, Default)]
pub struct FindingsUpsertBatch<'a> {
    findings: &'a [FindingRecord],
    occurrences: &'a [OccurrenceRecord],
    observations: &'a [ObservationRecord],
}

impl<'a> FindingsUpsertBatch<'a> {
    /// Construct a batch view over the three record layers.
    #[inline]
    #[must_use]
    pub const fn new(
        findings: &'a [FindingRecord],
        occurrences: &'a [OccurrenceRecord],
        observations: &'a [ObservationRecord],
    ) -> Self {
        Self {
            findings,
            occurrences,
            observations,
        }
    }

    /// Stable finding records (layer 1) in this batch.
    #[inline]
    #[must_use]
    pub const fn findings(self) -> &'a [FindingRecord] {
        self.findings
    }

    /// Version-specific occurrence records (layer 2) in this batch.
    #[inline]
    #[must_use]
    pub const fn occurrences(self) -> &'a [OccurrenceRecord] {
        self.occurrences
    }

    /// Policy-scoped observation records (layer 3) in this batch.
    #[inline]
    #[must_use]
    pub const fn observations(self) -> &'a [ObservationRecord] {
        self.observations
    }

    /// Returns `true` if all three layers are empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.findings.is_empty() && self.occurrences.is_empty() && self.observations.is_empty()
    }

    /// Total number of records across all three layers.
    #[inline]
    #[must_use]
    pub const fn total_records(self) -> usize {
        self.findings.len() + self.occurrences.len() + self.observations.len()
    }

    /// Validate intra-batch referential integrity and tenant consistency.
    ///
    /// Checks that:
    /// 1. Every `OccurrenceRecord.finding_id` references a `FindingRecord`
    ///    in this batch.
    /// 2. Every `ObservationRecord.occurrence_id` references an
    ///    `OccurrenceRecord` in this batch.
    /// 3. All records across all three layers share the same `tenant_id`.
    ///
    /// This is a COLD-path diagnostic tool — backends may call it in debug
    /// mode or tests. It validates within-batch closure only; cross-batch
    /// references to already-persisted records cannot be checked here.
    pub fn validate_referential_integrity(self) -> Result<(), PersistenceInputError> {
        // Tenant consistency: all records must share the same tenant.
        let expected_tenant = self
            .findings
            .first()
            .map(|f| f.tenant_id())
            .or_else(|| self.occurrences.first().map(|o| o.tenant_id()))
            .or_else(|| self.observations.first().map(|o| o.tenant_id()));

        if let Some(expected) = expected_tenant {
            for f in self.findings {
                if f.tenant_id() != expected {
                    return Err(PersistenceInputError::InconsistentTenant);
                }
            }
            for occ in self.occurrences {
                if occ.tenant_id() != expected {
                    return Err(PersistenceInputError::InconsistentTenant);
                }
            }
            for obs in self.observations {
                if obs.tenant_id() != expected {
                    return Err(PersistenceInputError::InconsistentTenant);
                }
            }
        }

        // Referential integrity: occurrences → findings, observations → occurrences.
        for occ in self.occurrences {
            if !self
                .findings
                .iter()
                .any(|f| f.finding_id() == occ.finding_id())
            {
                return Err(PersistenceInputError::OrphanedReference {
                    child_type: "OccurrenceRecord",
                    parent_type: "FindingRecord",
                });
            }
        }
        for obs in self.observations {
            if !self
                .occurrences
                .iter()
                .any(|o| o.occurrence_id() == obs.occurrence_id())
            {
                return Err(PersistenceInputError::OrphanedReference {
                    child_type: "ObservationRecord",
                    parent_type: "OccurrenceRecord",
                });
            }
        }
        Ok(())
    }
}

/// Backend-neutral trait for persisting findings, occurrences, and observations.
///
/// # Implementor contract
///
/// 1. **Idempotent upsert.** Replaying the same batch, or overlapping batches,
///    must not create duplicate rows. Content-addressed IDs (`FindingId`,
///    `OccurrenceId`, `ObservationId`) serve as natural deduplication keys.
/// 2. **Referential integrity.** The backend must ensure that every
///    `OccurrenceRecord.finding_id` references a persisted or in-batch
///    `FindingRecord`, and every `ObservationRecord.occurrence_id` references
///    a persisted or in-batch `OccurrenceRecord`.
/// 3. **Atomicity scope.** Whether the batch is applied atomically (single
///    transaction) or row-by-row is a backend decision; the trait does not
///    mandate transactional guarantees beyond idempotency.
/// 4. **All-or-nothing success.** Returning `Ok(())` guarantees all records in
///    the batch were durably persisted. Implementations must not return `Ok(())`
///    for partial writes — partial failures must be reported as `Err`.
pub trait FindingsSink: Send + Sync {
    /// Backend-specific error type.
    type Error: Error + Send + Sync + 'static;

    /// Persist all rows in `batch`, inserting new records and ignoring
    /// duplicates (upsert semantics).
    ///
    /// Callers SHOULD keep `batch.total_records()` at or below
    /// [`RECOMMENDED_MAX_BATCH_SIZE`](super::RECOMMENDED_MAX_BATCH_SIZE).
    ///
    /// An empty batch is a valid no-op. The backend must enforce referential
    /// integrity as described in the trait-level documentation.
    fn upsert_batch(&self, batch: FindingsUpsertBatch<'_>) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use crate::{
        connector::Location,
        identity::{
            FenceEpoch, FindingId, LogicalTime, ObjectVersionId, ObservationId, OccurrenceId,
            PolicyHash, RunId, ShardId, TenantId,
        },
    };

    use super::*;

    fn tenant(seed: u8) -> TenantId {
        TenantId::from_bytes([seed; 32])
    }

    fn finding(seed: u8) -> FindingId {
        FindingId::from_bytes([seed; 32])
    }

    fn occurrence(seed: u8) -> OccurrenceId {
        OccurrenceId::from_bytes([seed; 32])
    }

    fn object_version(seed: u8) -> ObjectVersionId {
        ObjectVersionId::from_bytes([seed; 32])
    }

    fn policy(seed: u8) -> PolicyHash {
        PolicyHash::from_bytes([seed; 32])
    }

    fn ovid(seed: u8) -> OvidHash {
        OvidHash::from_bytes([seed; 32])
    }

    #[test]
    fn occurrence_record_rejects_zero_span_length() {
        let error =
            OccurrenceRecord::try_new(tenant(1), finding(3), object_version(4), 9, 0).unwrap_err();

        assert_eq!(error, PersistenceInputError::ZeroSpanLength);
    }

    #[test]
    fn occurrence_record_accepts_non_zero_span_length() {
        let record = OccurrenceRecord::new(
            tenant(1),
            finding(3),
            object_version(4),
            9,
            NonZeroU64::new(5).unwrap(),
        );

        assert_eq!(record.byte_length().get(), 5);
    }

    #[test]
    fn findings_upsert_batch_reports_empty_only_when_all_slices_are_empty() {
        let empty = FindingsUpsertBatch::default();
        let occurrence = OccurrenceRecord::new(
            tenant(1),
            finding(3),
            object_version(4),
            9,
            NonZeroU64::new(5).unwrap(),
        );
        let occurrences = [occurrence];
        let non_empty = FindingsUpsertBatch::new(&[], &occurrences, &[]);

        assert!(empty.is_empty());
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn observation_record_preserves_optional_location() {
        let observation = ObservationRecord::new(
            tenant(1),
            occurrence(3),
            policy(4),
            ovid(5),
            RunId::from_raw(6),
            ShardId::from_raw(7),
            FenceEpoch::from_raw(8),
            LogicalTime::from_raw(9),
        )
        .with_location(
            Location::try_new("repo/path".into(), Some("https://example.test".into())).unwrap(),
        );

        assert_eq!(observation.location().unwrap().display(), "repo/path");
    }

    // -- verify_id --

    fn make_finding_record(tenant_seed: u8) -> FindingRecord {
        use crate::identity::{
            NormHash, RuleFingerprint, StableItemId, TenantId, TenantSecretKey, key_secret_hash,
        };

        let tenant_id = TenantId::from_bytes([tenant_seed; 32]);
        let stable_item_id = StableItemId::from_bytes([0x02; 32]);
        let rule_fingerprint = RuleFingerprint::from_bytes([0x03; 32]);
        let secret_hash = key_secret_hash(
            &TenantSecretKey::from_bytes([0x42; 32]),
            &NormHash::from_digest([0xAB; 32]),
        );

        FindingRecord::new(tenant_id, stable_item_id, rule_fingerprint, secret_hash)
    }

    #[test]
    fn finding_record_verify_id_with_correct_derivation() {
        let record = make_finding_record(0x01);
        assert!(
            record.verify_id(),
            "correctly derived finding_id should verify"
        );
    }

    #[test]
    fn finding_record_verify_id_with_wrong_id() {
        let mut record = make_finding_record(0x01);
        // Tamper with the finding_id.
        record.finding_id = FindingId::from_bytes([0xFF; 32]);
        assert!(
            !record.verify_id(),
            "mismatched finding_id should not verify"
        );
    }

    fn make_occurrence_record(finding_seed: u8) -> OccurrenceRecord {
        use crate::identity::{FindingId, ObjectVersionId};

        let finding_id = FindingId::from_bytes([finding_seed; 32]);
        let object_version_id = ObjectVersionId::from_bytes([0x04; 32]);

        OccurrenceRecord::new(
            tenant(1),
            finding_id,
            object_version_id,
            100,
            NonZeroU64::new(50).unwrap(),
        )
    }

    #[test]
    fn occurrence_record_verify_id_with_correct_derivation() {
        let record = make_occurrence_record(0x05);
        assert!(
            record.verify_id(),
            "correctly derived occurrence_id should verify"
        );
    }

    #[test]
    fn occurrence_record_verify_id_with_wrong_id() {
        let mut record = make_occurrence_record(0x05);
        record.occurrence_id = OccurrenceId::from_bytes([0xFF; 32]);
        assert!(
            !record.verify_id(),
            "mismatched occurrence_id should not verify"
        );
    }

    fn make_observation_record(occurrence_seed: u8) -> ObservationRecord {
        use crate::identity::{OccurrenceId, PolicyHash, TenantId};

        let tenant_id = TenantId::from_bytes([0x01; 32]);
        let policy_hash = PolicyHash::from_bytes([0x04; 32]);
        let occurrence_id = OccurrenceId::from_bytes([occurrence_seed; 32]);

        ObservationRecord::new(
            tenant_id,
            occurrence_id,
            policy_hash,
            ovid(5),
            RunId::from_raw(6),
            ShardId::from_raw(7),
            FenceEpoch::from_raw(8),
            LogicalTime::from_raw(9),
        )
    }

    #[test]
    fn observation_record_verify_id_with_correct_derivation() {
        let record = make_observation_record(0x03);
        assert!(
            record.verify_id(),
            "correctly derived observation_id should verify"
        );
    }

    #[test]
    fn observation_record_verify_id_with_wrong_id() {
        let mut record = make_observation_record(0x03);
        record.observation_id = ObservationId::from_bytes([0xFF; 32]);
        assert!(
            !record.verify_id(),
            "mismatched observation_id should not verify"
        );
    }

    // -- total_records --

    #[test]
    fn total_records_sums_all_layers() {
        let fr = make_finding_record(0x01);
        let occ = make_occurrence_record(0x05);
        let obs = make_observation_record(0x03);
        let findings = [fr];
        let occurrences = [occ];
        let observations = [obs];
        let batch = FindingsUpsertBatch::new(&findings, &occurrences, &observations);

        assert_eq!(batch.total_records(), 3);
        assert_eq!(FindingsUpsertBatch::default().total_records(), 0);
    }

    // -- validate_referential_integrity --

    #[test]
    fn validate_accepts_referentially_consistent_batch() {
        use crate::identity::{
            NormHash, ObjectVersionId, RuleFingerprint, StableItemId, TenantId, TenantSecretKey,
            key_secret_hash,
        };

        let tenant_id = TenantId::from_bytes([0x01; 32]);
        let stable_item_id = StableItemId::from_bytes([0x02; 32]);
        let rule_fp = RuleFingerprint::from_bytes([0x03; 32]);
        let secret = key_secret_hash(
            &TenantSecretKey::from_bytes([0x42; 32]),
            &NormHash::from_digest([0xAB; 32]),
        );
        let fr = FindingRecord::new(tenant_id, stable_item_id, rule_fp, secret);

        let obj = ObjectVersionId::from_bytes([0x04; 32]);
        let occ = OccurrenceRecord::new(
            tenant_id,
            fr.finding_id(),
            obj,
            0,
            NonZeroU64::new(10).unwrap(),
        );

        let policy_h = PolicyHash::from_bytes([0x05; 32]);
        let obs = ObservationRecord::new(
            tenant_id,
            occ.occurrence_id(),
            policy_h,
            ovid(6),
            RunId::from_raw(7),
            ShardId::from_raw(8),
            FenceEpoch::from_raw(9),
            LogicalTime::from_raw(10),
        );

        let findings = [fr];
        let occurrences = [occ];
        let observations = [obs];
        let batch = FindingsUpsertBatch::new(&findings, &occurrences, &observations);
        batch
            .validate_referential_integrity()
            .expect("consistent batch should pass");
    }

    #[test]
    fn validate_rejects_orphaned_occurrence() {
        let occ = make_occurrence_record(0x05);
        let occurrences = [occ];
        // No findings in the batch — occurrence's finding_id is orphaned.
        let batch = FindingsUpsertBatch::new(&[], &occurrences, &[]);
        assert_eq!(
            batch.validate_referential_integrity().unwrap_err(),
            PersistenceInputError::OrphanedReference {
                child_type: "OccurrenceRecord",
                parent_type: "FindingRecord",
            }
        );
    }

    #[test]
    fn validate_rejects_orphaned_observation() {
        let obs = make_observation_record(0x03);
        let observations = [obs];
        // No occurrences in the batch — observation's occurrence_id is orphaned.
        let batch = FindingsUpsertBatch::new(&[], &[], &observations);
        assert_eq!(
            batch.validate_referential_integrity().unwrap_err(),
            PersistenceInputError::OrphanedReference {
                child_type: "ObservationRecord",
                parent_type: "OccurrenceRecord",
            }
        );
    }

    #[test]
    fn validate_accepts_empty_batch() {
        let batch = FindingsUpsertBatch::default();
        batch
            .validate_referential_integrity()
            .expect("empty batch is valid");
    }

    #[test]
    fn validate_rejects_mixed_tenants_in_findings() {
        use crate::identity::{
            NormHash, RuleFingerprint, StableItemId, TenantSecretKey, key_secret_hash,
        };

        let sid = StableItemId::from_bytes([0x02; 32]);
        let rule = RuleFingerprint::from_bytes([0x03; 32]);
        let secret = key_secret_hash(
            &TenantSecretKey::from_bytes([0x42; 32]),
            &NormHash::from_digest([0xAB; 32]),
        );
        let fr_a = FindingRecord::new(tenant(1), sid, rule, secret);
        let fr_b = FindingRecord::new(tenant(2), sid, rule, secret);

        let findings = [fr_a, fr_b];
        let batch = FindingsUpsertBatch::new(&findings, &[], &[]);
        assert_eq!(
            batch.validate_referential_integrity().unwrap_err(),
            PersistenceInputError::InconsistentTenant,
        );
    }

    #[test]
    fn validate_rejects_mixed_tenants_across_layers() {
        use crate::identity::{
            NormHash, ObjectVersionId, RuleFingerprint, StableItemId, TenantSecretKey,
            key_secret_hash,
        };

        let sid = StableItemId::from_bytes([0x02; 32]);
        let rule = RuleFingerprint::from_bytes([0x03; 32]);
        let secret = key_secret_hash(
            &TenantSecretKey::from_bytes([0x42; 32]),
            &NormHash::from_digest([0xAB; 32]),
        );
        let fr = FindingRecord::new(tenant(1), sid, rule, secret);
        // Occurrence belongs to a different tenant.
        let occ = OccurrenceRecord::new(
            tenant(2),
            fr.finding_id(),
            ObjectVersionId::from_bytes([0x04; 32]),
            0,
            NonZeroU64::new(10).unwrap(),
        );

        let findings = [fr];
        let occurrences = [occ];
        let batch = FindingsUpsertBatch::new(&findings, &occurrences, &[]);
        assert_eq!(
            batch.validate_referential_integrity().unwrap_err(),
            PersistenceInputError::InconsistentTenant,
        );
    }

    // -- Proptest: constructor-derived IDs match manual derivation --

    proptest::proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn finding_record_id_matches_manual_derivation(
            t in proptest::array::uniform32(proptest::num::u8::ANY),
            i in proptest::array::uniform32(proptest::num::u8::ANY),
            r in proptest::array::uniform32(proptest::num::u8::ANY),
            s in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            use crate::identity::{
                FindingIdInputs, SecretHash, StableItemId, RuleFingerprint,
                derive_finding_id,
            };
            let tid = TenantId::from_bytes(t);
            let item = StableItemId::from_bytes(i);
            let rule = RuleFingerprint::from_bytes(r);
            let secret = SecretHash::from_bytes_internal(s);
            let record = FindingRecord::new(tid, item, rule, secret);
            let expected = derive_finding_id(&FindingIdInputs {
                tenant: tid, item, rule, secret,
            });
            proptest::prop_assert_eq!(record.finding_id(), expected);
        }

        #[test]
        fn occurrence_record_id_matches_manual_derivation(
            f in proptest::array::uniform32(proptest::num::u8::ANY),
            v in proptest::array::uniform32(proptest::num::u8::ANY),
            offset in proptest::num::u64::ANY,
            length in 1u64..=u64::MAX,
        ) {
            use crate::identity::{
                OccurrenceIdInputs, derive_occurrence_id,
            };
            let fid = FindingId::from_bytes(f);
            let vid = ObjectVersionId::from_bytes(v);
            let bl = NonZeroU64::new(length).unwrap();
            let record = OccurrenceRecord::new(tenant(1), fid, vid, offset, bl);
            let expected = derive_occurrence_id(&OccurrenceIdInputs {
                finding: fid, version: vid, byte_offset: offset, byte_length: length,
            });
            proptest::prop_assert_eq!(record.occurrence_id(), expected);
        }

        #[test]
        fn observation_record_id_matches_manual_derivation(
            t in proptest::array::uniform32(proptest::num::u8::ANY),
            p in proptest::array::uniform32(proptest::num::u8::ANY),
            o in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            use crate::identity::{
                ObservationIdInputs, derive_observation_id,
            };
            let tid = TenantId::from_bytes(t);
            let ph = PolicyHash::from_bytes(p);
            let oid = OccurrenceId::from_bytes(o);
            let record = ObservationRecord::new(
                tid, oid, ph, ovid(1),
                RunId::from_raw(1), ShardId::from_raw(1),
                FenceEpoch::from_raw(1), LogicalTime::from_raw(1),
            );
            let expected = derive_observation_id(&ObservationIdInputs {
                tenant: tid, policy: ph, occurrence: oid,
            });
            proptest::prop_assert_eq!(record.observation_id(), expected);
        }
    }
}
