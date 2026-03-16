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

use std::{collections::HashSet, error::Error, num::NonZeroU64, sync::Arc};

use crate::{
    connector::Location,
    identity::{
        FenceEpoch, FindingId, FindingIdInputs, LogicalTime, ObjectVersionId, ObservationId,
        ObservationIdInputs, OccurrenceId, OccurrenceIdInputs, PolicyHash, RuleFingerprint, RunId,
        SecretHash, ShardId, StableItemId, TenantId, derive_finding_id, derive_observation_id,
        derive_occurrence_id,
    },
};

use super::{
    PersistenceInputError, WriteContext,
    commit::{CommitHandle, FindingsCommitReceipt},
    ovid::OvidHash,
};

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
    ///
    /// Note: `FindingRecord` uses a simple bool check because its ID is
    /// derived entirely from record-local fields. See
    /// [`ObservationRecord::validate_identity`] for the richer
    /// `Result`-returning validation used when the ID spans cross-boundary
    /// fields.
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
    ///
    /// Note: like [`FindingRecord::verify_id`], this returns a simple bool
    /// because the occurrence ID is derived entirely from record-local
    /// fields. See [`ObservationRecord::validate_identity`] for the richer
    /// `Result`-returning validation used when the ID spans cross-boundary
    /// fields.
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
    location: Option<Arc<Location>>,
}

impl ObservationRecord {
    /// Construct an observation record, deriving [`ObservationId`] canonically
    /// from `(tenant_id, policy_hash, occurrence_id)`.
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

    /// Construct an observation from a shared write context.
    ///
    /// Runtime code should prefer this constructor when the tenant, policy,
    /// run, shard, and fence epoch all come from the same leased write scope.
    #[must_use]
    pub fn from_write_context(
        write_context: WriteContext,
        occurrence_id: OccurrenceId,
        ovid_hash: OvidHash,
        seen_at: LogicalTime,
    ) -> Self {
        Self::new(
            write_context.tenant_id(),
            occurrence_id,
            write_context.policy_hash(),
            ovid_hash,
            write_context.run_id(),
            write_context.shard_id(),
            write_context.fence_epoch(),
            seen_at,
        )
    }

    /// Reconstruct an observation record from persisted storage and verify
    /// that the stored `observation_id` still matches the canonical
    /// derivation.
    #[expect(
        clippy::too_many_arguments,
        reason = "ObservationRecord intentionally mirrors a flat durable row schema"
    )]
    pub fn from_persisted(
        tenant_id: TenantId,
        stored_observation_id: ObservationId,
        occurrence_id: OccurrenceId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        seen_at: LogicalTime,
        location: Option<Location>,
    ) -> Result<Self, PersistenceInputError> {
        let mut record = Self::new(
            tenant_id,
            occurrence_id,
            policy_hash,
            ovid_hash,
            run_id,
            shard_id,
            fence_epoch,
            seen_at,
        );

        if record.observation_id != stored_observation_id {
            return Err(PersistenceInputError::ObservationIdMismatch {
                expected: record.observation_id,
                actual: stored_observation_id,
            });
        }

        record.location = location.map(Arc::new);
        Ok(record)
    }

    /// Reconstruct an observation record from persisted storage without
    /// revalidating the stored observation id.
    ///
    /// This constructor exists only for test code and downstream test-support
    /// helpers that need to model corrupted or untrusted persisted rows before
    /// batch-level validation runs.
    #[cfg(any(test, feature = "test-support"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "test-only helper mirrors the flat durable row shape"
    )]
    pub(crate) fn from_persisted_unchecked(
        tenant_id: TenantId,
        stored_observation_id: ObservationId,
        occurrence_id: OccurrenceId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        seen_at: LogicalTime,
        location: Option<Location>,
    ) -> Self {
        Self {
            tenant_id,
            observation_id: stored_observation_id,
            occurrence_id,
            policy_hash,
            ovid_hash,
            run_id,
            shard_id,
            fence_epoch,
            seen_at,
            location: location.map(Arc::new),
        }
    }

    /// Verify that the stored `observation_id` still matches the canonical
    /// derivation from `(tenant, policy_hash, occurrence_id)`.
    pub fn validate_identity(&self) -> Result<(), PersistenceInputError> {
        let expected = self.derived_observation_id();

        if self.observation_id != expected {
            return Err(PersistenceInputError::ObservationIdMismatch {
                expected,
                actual: self.observation_id,
            });
        }

        Ok(())
    }

    /// Attach display-safe location metadata (path and optional URL).
    ///
    /// Accepts `Arc<Location>` so multiple observations sharing the same
    /// location can avoid cloning the underlying `String` fields.
    #[must_use]
    pub fn with_location(self, location: Arc<Location>) -> Self {
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

    /// Recompute the canonical observation id from this record's identity
    /// fields.
    #[must_use]
    pub fn derived_observation_id(&self) -> ObservationId {
        derive_observation_id(&ObservationIdInputs {
            tenant: self.tenant_id,
            policy: self.policy_hash,
            occurrence: self.occurrence_id,
        })
    }

    /// Reconstruct the shared write context from this observation's stored
    /// routing and fencing fields.
    #[inline]
    #[must_use]
    pub const fn write_context(&self) -> WriteContext {
        WriteContext::new(
            self.tenant_id,
            self.policy_hash,
            self.run_id,
            self.shard_id,
            self.fence_epoch,
        )
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
        self.location.as_deref()
    }

    /// Shared reference to the `Arc`-wrapped location, if attached.
    ///
    /// Use this when you need a cheap `Arc::clone` of the location rather
    /// than cloning the underlying `String` fields — for example, during
    /// observation merges or batch translation loops.
    #[inline]
    #[must_use]
    pub fn location_arc(&self) -> Option<&Arc<Location>> {
        self.location.as_ref()
    }

    /// Verify that the stored `observation_id` matches the content-addressed
    /// derivation from the record's identity fields.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        self.validate_identity().is_ok()
    }
}

/// Borrowed, zero-copy batch view grouping all three record layers for a
/// single [`FindingsSink::upsert_batch`] call.
///
/// This type borrows slices rather than owning them so the caller retains
/// control over allocation and can reuse buffers across flushes. An empty
/// batch (all three slices empty) is a valid no-op input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

    /// Validate observation-identity invariants local to this batch.
    ///
    /// Checks that every observation's stored `observation_id` matches the
    /// canonical derivation from `(tenant, policy_hash, occurrence_id)`.
    /// This is a WARM-tier operation (per-batch, not per-item). Cost is
    /// O(n) in the number of observations, bounded by
    /// [`RECOMMENDED_MAX_BATCH_SIZE`](super::RECOMMENDED_MAX_BATCH_SIZE).
    ///
    /// Only observations are checked because `FindingRecord` and
    /// `OccurrenceRecord` always derive their IDs at construction — no
    /// caller-supplied ID is accepted. Any constructor that accepts a
    /// stored observation id (`from_persisted`, and in test builds
    /// `from_persisted_unchecked`) can introduce a mismatch, making
    /// observations the only layer where batch-level validation is needed.
    ///
    /// Note: this does **not** check referential integrity or tenant
    /// consistency — call
    /// [`validate_referential_integrity`](Self::validate_referential_integrity)
    /// separately for those.
    pub fn validate_observation_identity(self) -> Result<(), PersistenceInputError> {
        for observation in self.observations {
            observation.validate_identity()?;
        }

        Ok(())
    }

    /// Validate that all records in the batch share the same `tenant_id`.
    ///
    /// Multi-tenant batches are rejected because backends rely on
    /// single-tenant isolation for partition routing, index scans, and
    /// row-level security. Cost is O(n) across all three layers, bounded
    /// by [`RECOMMENDED_MAX_BATCH_SIZE`](super::RECOMMENDED_MAX_BATCH_SIZE).
    pub fn validate_tenant_consistency(self) -> Result<(), PersistenceInputError> {
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

        Ok(())
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
    /// 1. All records across all three layers share the same `tenant_id`.
    /// 2. Every `OccurrenceRecord.finding_id` references a `FindingRecord`
    ///    in this batch.
    /// 3. Every `ObservationRecord.occurrence_id` references an
    ///    `OccurrenceRecord` in this batch.
    ///
    /// This is a COLD-path diagnostic tool — backends may call it in debug
    /// mode or tests. It validates within-batch closure only; cross-batch
    /// references to already-persisted records cannot be checked here.
    pub fn validate_referential_integrity(self) -> Result<(), PersistenceInputError> {
        self.validate_tenant_consistency()?;

        // Referential integrity: occurrences → findings, observations → occurrences.
        let finding_ids: HashSet<_> = self.findings.iter().map(|f| f.finding_id()).collect();
        for occ in self.occurrences {
            if !finding_ids.contains(&occ.finding_id()) {
                return Err(PersistenceInputError::OrphanedReference {
                    child_type: "OccurrenceRecord",
                    parent_type: "FindingRecord",
                });
            }
        }
        let occurrence_ids: HashSet<_> =
            self.occurrences.iter().map(|o| o.occurrence_id()).collect();
        for obs in self.observations {
            if !occurrence_ids.contains(&obs.occurrence_id()) {
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
/// 3. **Canonical observation identity.** `ObservationRecord.observation_id`
///    must equal the canonical derivation from `(tenant_id, policy_hash,
///    occurrence_id)`. The primary enforcement point is
///    [`ObservationRecord::from_persisted`], which rejects mismatches at
///    construction. [`FindingsUpsertBatch::validate_observation_identity`]
///    provides batch-level defense-in-depth.
/// 4. **Atomicity scope.** Whether the batch is applied atomically (single
///    transaction) or row-by-row is a backend decision; the trait does not
///    mandate transactional guarantees beyond idempotency.
/// 5. **Submission is not durability.** Returning `Ok(handle)` means the
///    backend accepted the batch; durability is established only when
///    [`CommitHandle::wait`] yields a [`FindingsCommitReceipt`].
pub trait FindingsSink: Send + Sync {
    /// Backend-specific immediate submit or wait error type.
    type Error: Error + Send + Sync + 'static;
    /// Handle returned for eventual durable acknowledgement of submitted rows.
    type CommitHandle: CommitHandle<Receipt = FindingsCommitReceipt, Error = Self::Error>;

    /// Submit all rows in `batch`, inserting new records and ignoring
    /// duplicates (upsert semantics).
    ///
    /// Callers SHOULD keep `batch.total_records()` at or below
    /// [`RECOMMENDED_MAX_BATCH_SIZE`](super::RECOMMENDED_MAX_BATCH_SIZE).
    ///
    /// An empty batch is a valid no-op. The backend must enforce referential
    /// integrity and canonical observation-identity invariants as described in
    /// the trait-level documentation.
    ///
    /// `Ok(handle)` means the backend accepted responsibility for the batch.
    /// The caller must wait on the returned handle before treating the write as
    /// durable.
    fn upsert_batch(
        &self,
        batch: FindingsUpsertBatch<'_>,
    ) -> Result<Self::CommitHandle, Self::Error>;
}

#[cfg(test)]
#[path = "findings_tests.rs"]
mod tests;
