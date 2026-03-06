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
        FenceEpoch, FindingId, LogicalTime, ObjectVersionId, ObservationId, OccurrenceId,
        PolicyHash, RuleFingerprint, RunId, SecretHash, ShardId, StableItemId, TenantId,
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
    /// Construct a stable finding record from its identity components.
    ///
    /// # Caller responsibility
    ///
    /// `finding_id` must be the output of
    /// [`derive_finding_id`](crate::identity::derive_finding_id) applied to
    /// the matching `(tenant_id, stable_item_id, rule_fingerprint, secret_hash)`.
    /// Passing a mismatched `FindingId` breaks content-addressed deduplication
    /// but is not memory-unsafe.
    #[inline]
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        finding_id: FindingId,
        stable_item_id: StableItemId,
        rule_fingerprint: RuleFingerprint,
        secret_hash: SecretHash,
    ) -> Self {
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
    /// Construct an occurrence record, validating that `byte_length > 0`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceInputError::ZeroSpanLength`] if `byte_length`
    /// is zero — a zero-length span is meaningless for a secret occurrence.
    pub fn try_new(
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
        finding_id: FindingId,
        object_version_id: ObjectVersionId,
        byte_offset: u64,
        byte_length: u64,
    ) -> Result<Self, PersistenceInputError> {
        let byte_length =
            NonZeroU64::new(byte_length).ok_or(PersistenceInputError::ZeroSpanLength)?;
        Ok(Self::new(
            tenant_id,
            occurrence_id,
            finding_id,
            object_version_id,
            byte_offset,
            byte_length,
        ))
    }

    /// Construct an occurrence record from a pre-validated [`NonZeroU64`]
    /// span length.
    #[inline]
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
        finding_id: FindingId,
        object_version_id: ObjectVersionId,
        byte_offset: u64,
        byte_length: NonZeroU64,
    ) -> Self {
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
    /// Construct an observation record.
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
        observation_id: ObservationId,
        occurrence_id: OccurrenceId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        seen_at: LogicalTime,
    ) -> Self {
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
pub trait FindingsSink: Send + Sync {
    /// Backend-specific error type.
    type Error: Error + Send + Sync + 'static;

    /// Persist all rows in `batch`, inserting new records and ignoring
    /// duplicates (upsert semantics).
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

    fn observation(seed: u8) -> ObservationId {
        ObservationId::from_bytes([seed; 32])
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
        let error = OccurrenceRecord::try_new(
            tenant(1),
            occurrence(2),
            finding(3),
            object_version(4),
            9,
            0,
        )
        .unwrap_err();

        assert_eq!(error, PersistenceInputError::ZeroSpanLength);
    }

    #[test]
    fn occurrence_record_accepts_non_zero_span_length() {
        let record = OccurrenceRecord::new(
            tenant(1),
            occurrence(2),
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
            occurrence(2),
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
            observation(2),
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
}
