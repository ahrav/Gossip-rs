//! Persistence-boundary contracts: done-ledger keys/records, findings records,
//! and backend-neutral traits.
//!
//! This module is intentionally pure and storage-agnostic. It defines the data
//! model that Phase V backends will implement, but does not commit to any
//! backend-specific transaction, batching, or retry mechanism.
//!
//! Scope of **A1**:
//! - durable done-ledger identity (`OvidHash`, `DoneLedgerKey`)
//! - record shapes for stable findings / occurrences / policy-scoped
//!   observations
//! - safe bounded wrappers for persistence-only string fields
//! - backend-neutral traits (`DoneLedger`, `FindingsSink`)
//!
//! Explicitly **not** in this file yet:
//! - commit receipts / commit-handle typestate (Epic A2)
//! - in-memory reference backends (Epic A4)
//! - conformance harness (Epic A5)
//!
//! Dependency direction: this boundary may depend on `identity`, `connector`,
//! and `coordination` contracts, but no upstream boundary may depend on any
//! backend implementation.
//!
//! # Safety posture
//!
//! - No raw secret bytes appear in any public record shape.
//! - Secret-derived fields use dedicated fixed-width hash newtypes whose
//!   `Debug` output is already redacted or truncated.
//! - The only free-form strings in this module are explicitly safe/bounded:
//!   [`Location`] from the connector boundary and [`DoneLedgerErrorCode`]
//!   defined here.

use std::{
    error::Error,
    fmt,
    num::NonZeroU64,
    sync::LazyLock,
};

use blake3::Hasher;

use crate::{
    connector::{Location, VersionId},
    identity::{
        self, CanonicalBytes, FenceEpoch, FindingId, LogicalTime, ObservationId, ObjectVersionId,
        OccurrenceId, PolicyHash, RuleFingerprint, RunId, SecretHash, ShardId, StableItemId,
        TenantId,
    },
};

/// Maximum length of a done-ledger error code.
///
/// This field exists for short structured codes like `HTTP_403`, `TIMEOUT`,
/// `UNSUPPORTED_FORMAT`, not arbitrary messages.
pub const MAX_DONE_LEDGER_ERROR_CODE_SIZE: usize = 128;

// Cached derive-key hasher for OVID derivation.
static OVID_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(identity::domain::OVID_V1));

// ---------------------------------------------------------------------------
// PersistenceInputError
// ---------------------------------------------------------------------------

/// Validation errors for persistence-boundary value types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceInputError {
    /// A bounded string field was empty.
    Empty { field: &'static str },
    /// A bounded field exceeded its maximum size.
    TooLarge {
        field: &'static str,
        size: usize,
        max: usize,
    },
    /// A supposedly safe code contained a disallowed byte.
    InvalidByte {
        field: &'static str,
        index: usize,
        byte: u8,
    },
    /// Occurrence span length must be non-zero.
    ZeroSpanLength,
}

impl fmt::Display for PersistenceInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "{field} must not be empty"),
            Self::TooLarge { field, size, max } => {
                write!(f, "{field} too large ({size} bytes, max {max})")
            }
            Self::InvalidByte { field, index, byte } => write!(
                f,
                "{field} contains invalid byte 0x{byte:02X} at index {index}"
            ),
            Self::ZeroSpanLength => write!(f, "OccurrenceRecord.byte_length must be non-zero"),
        }
    }
}

impl Error for PersistenceInputError {}

// ---------------------------------------------------------------------------
// OVID hash
// ---------------------------------------------------------------------------

crate::define_id_32! {
    /// Fixed-width hash of an object-version identity.
    ///
    /// `OvidHash` is the done-ledger join key for “these exact bytes under this
    /// stable item identity”. It is derived from:
    ///
    /// - [`StableItemId`] — already scoped by connector tag + connector instance
    /// - [`VersionId`] — including strong-vs-weak claim strength
    ///
    /// This means the same stable item under two different version claims
    /// produces different `OvidHash` values.
    OvidHash
}

/// Structured inputs to [`derive_ovid_hash`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OvidHashInputs {
    stable_item_id: StableItemId,
    version: VersionId,
}

impl OvidHashInputs {
    /// Construct OVID-hash inputs from the stable item identity and version
    /// claim returned by a connector.
    #[inline]
    #[must_use]
    pub const fn new(stable_item_id: StableItemId, version: VersionId) -> Self {
        Self {
            stable_item_id,
            version,
        }
    }

    /// Stable item identity component.
    #[inline]
    #[must_use]
    pub const fn stable_item_id(self) -> StableItemId {
        self.stable_item_id
    }

    /// Version claim component.
    #[inline]
    #[must_use]
    pub const fn version(self) -> VersionId {
        self.version
    }
}

impl CanonicalBytes for OvidHashInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.stable_item_id.write_canonical(h);
        write_version_id_canonical(self.version, h);
    }
}

/// Derive an [`OvidHash`] from stable item identity and version claim.
#[inline]
#[must_use]
pub fn derive_ovid_hash(inputs: &OvidHashInputs) -> OvidHash {
    let mut h = OVID_HASHER.clone();
    inputs.write_canonical(&mut h);
    OvidHash::from_bytes(identity::finalize_32(&h))
}

#[inline]
fn write_version_id_canonical(version: VersionId, h: &mut Hasher) {
    match version {
        VersionId::Strong(vid) => {
            0u8.write_canonical(h);
            vid.write_canonical(h);
        }
        VersionId::Weak(vid) => {
            1u8.write_canonical(h);
            vid.write_canonical(h);
        }
    }
}

// ---------------------------------------------------------------------------
// Done-ledger types
// ---------------------------------------------------------------------------

/// Tenant- and policy-scoped done-ledger key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DoneLedgerKey {
    tenant_id: TenantId,
    policy_hash: PolicyHash,
    ovid_hash: OvidHash,
}

impl DoneLedgerKey {
    /// Construct a done-ledger key.
    #[inline]
    #[must_use]
    pub const fn new(tenant_id: TenantId, policy_hash: PolicyHash, ovid_hash: OvidHash) -> Self {
        Self {
            tenant_id,
            policy_hash,
            ovid_hash,
        }
    }

    /// Tenant namespace.
    #[inline]
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    /// Scan-policy identity.
    #[inline]
    #[must_use]
    pub const fn policy_hash(self) -> PolicyHash {
        self.policy_hash
    }

    /// Object-version identity.
    #[inline]
    #[must_use]
    pub const fn ovid_hash(self) -> OvidHash {
        self.ovid_hash
    }
}

impl CanonicalBytes for DoneLedgerKey {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.tenant_id.write_canonical(h);
        self.policy_hash.write_canonical(h);
        self.ovid_hash.write_canonical(h);
    }
}

/// Monotonic done-ledger result lattice.
///
/// Higher-ranked states dominate lower-ranked ones during merge/upsert.
/// This is the contract backend implementations must preserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DoneLedgerStatus {
    /// Temporary failure; the item may succeed later.
    FailedRetryable = 1,
    /// Terminal failure for the current run/policy combination.
    FailedPermanent = 2,
    /// Intentionally skipped (unsupported, filtered, capped, etc.).
    Skipped = 3,
    /// Successfully scanned and committed with no findings.
    ScannedClean = 10,
    /// Successfully scanned and committed with one or more findings.
    ScannedWithFindings = 11,
}

impl DoneLedgerStatus {
    /// Stable discriminant used for monotonic merge ordering.
    #[inline]
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    /// Returns `true` if the record represents a durable committed scan result.
    #[inline]
    #[must_use]
    pub const fn is_scanned(self) -> bool {
        matches!(self, Self::ScannedClean | Self::ScannedWithFindings)
    }

    /// Returns `true` if the state represents a failure class.
    #[inline]
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::FailedRetryable | Self::FailedPermanent)
    }

    /// Merge two lattice values, returning the dominant status.
    #[inline]
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

impl CanonicalBytes for DoneLedgerStatus {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.rank().write_canonical(h);
    }
}

/// Short structured code associated with a done-ledger skip/failure.
///
/// This is intentionally **not** a free-form message field. It exists for
/// bounded internal values like `HTTP_403`, `TIMEOUT`, `UNSUPPORTED_FORMAT`,
/// etc. Raw connector or source content must never be stored here.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DoneLedgerErrorCode(Box<str>);

impl DoneLedgerErrorCode {
    /// Construct a validated safe code.
    ///
    /// Allowed bytes:
    /// - ASCII letters and digits
    /// - `_`, `-`, `.`, `:`, `/`
    pub fn try_new(code: impl Into<String>) -> Result<Self, PersistenceInputError> {
        let code = code.into();
        if code.is_empty() {
            return Err(PersistenceInputError::Empty {
                field: "DoneLedgerErrorCode",
            });
        }
        if code.len() > MAX_DONE_LEDGER_ERROR_CODE_SIZE {
            return Err(PersistenceInputError::TooLarge {
                field: "DoneLedgerErrorCode",
                size: code.len(),
                max: MAX_DONE_LEDGER_ERROR_CODE_SIZE,
            });
        }
        for (index, byte) in code.bytes().enumerate() {
            let ok = byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/');
            if !ok {
                return Err(PersistenceInputError::InvalidByte {
                    field: "DoneLedgerErrorCode",
                    index,
                    byte,
                });
            }
        }
        Ok(Self(code.into_boxed_str()))
    }

    /// Borrow the code as a string slice.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DoneLedgerErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DoneLedgerErrorCode({:?})", self.0)
    }
}

impl fmt::Display for DoneLedgerErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Provenance fields attached to a done-ledger write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoneLedgerProvenance {
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
    started_at: LogicalTime,
    finished_at: LogicalTime,
}

impl DoneLedgerProvenance {
    /// Construct scan provenance for a done-ledger write.
    #[inline]
    #[must_use]
    pub const fn new(
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        started_at: LogicalTime,
        finished_at: LogicalTime,
    ) -> Self {
        Self {
            run_id,
            shard_id,
            fence_epoch,
            started_at,
            finished_at,
        }
    }

    #[inline]
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    #[inline]
    #[must_use]
    pub const fn shard_id(self) -> ShardId {
        self.shard_id
    }

    #[inline]
    #[must_use]
    pub const fn fence_epoch(self) -> FenceEpoch {
        self.fence_epoch
    }

    #[inline]
    #[must_use]
    pub const fn started_at(self) -> LogicalTime {
        self.started_at
    }

    #[inline]
    #[must_use]
    pub const fn finished_at(self) -> LogicalTime {
        self.finished_at
    }
}

/// Durable done-ledger row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoneLedgerRecord {
    key: DoneLedgerKey,
    status: DoneLedgerStatus,
    bytes_scanned: u64,
    findings_count: u32,
    provenance: DoneLedgerProvenance,
    error_code: Option<DoneLedgerErrorCode>,
}

impl DoneLedgerRecord {
    /// Construct a done-ledger record.
    #[must_use]
    pub fn new(
        key: DoneLedgerKey,
        status: DoneLedgerStatus,
        bytes_scanned: u64,
        findings_count: u32,
        provenance: DoneLedgerProvenance,
        error_code: Option<DoneLedgerErrorCode>,
    ) -> Self {
        Self {
            key,
            status,
            bytes_scanned,
            findings_count,
            provenance,
            error_code,
        }
    }

    #[inline]
    #[must_use]
    pub const fn key(&self) -> DoneLedgerKey {
        self.key
    }

    #[inline]
    #[must_use]
    pub const fn status(&self) -> DoneLedgerStatus {
        self.status
    }

    #[inline]
    #[must_use]
    pub const fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned
    }

    #[inline]
    #[must_use]
    pub const fn findings_count(&self) -> u32 {
        self.findings_count
    }

    #[inline]
    #[must_use]
    pub const fn provenance(&self) -> DoneLedgerProvenance {
        self.provenance
    }

    #[inline]
    #[must_use]
    pub fn error_code(&self) -> Option<&DoneLedgerErrorCode> {
        self.error_code.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Findings / occurrences / observations
// ---------------------------------------------------------------------------

/// Stable finding row.
///
/// This is the policy-independent, version-stable identity layer:
/// `(tenant, stable_item_id, rule_fingerprint, secret_hash)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRecord {
    tenant_id: TenantId,
    finding_id: FindingId,
    stable_item_id: StableItemId,
    rule_fingerprint: RuleFingerprint,
    secret_hash: SecretHash,
}

impl FindingRecord {
    /// Construct a stable finding record.
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

    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[inline]
    #[must_use]
    pub const fn finding_id(&self) -> FindingId {
        self.finding_id
    }

    #[inline]
    #[must_use]
    pub const fn stable_item_id(&self) -> StableItemId {
        self.stable_item_id
    }

    #[inline]
    #[must_use]
    pub const fn rule_fingerprint(&self) -> RuleFingerprint {
        self.rule_fingerprint
    }

    #[inline]
    #[must_use]
    pub const fn secret_hash(&self) -> SecretHash {
        self.secret_hash
    }
}

/// Version-specific occurrence row.
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
    /// Construct an occurrence record with a validated non-zero span length.
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

    /// Construct an occurrence record from a validated non-zero span length.
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

    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[inline]
    #[must_use]
    pub const fn occurrence_id(&self) -> OccurrenceId {
        self.occurrence_id
    }

    #[inline]
    #[must_use]
    pub const fn finding_id(&self) -> FindingId {
        self.finding_id
    }

    #[inline]
    #[must_use]
    pub const fn object_version_id(&self) -> ObjectVersionId {
        self.object_version_id
    }

    #[inline]
    #[must_use]
    pub const fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    #[inline]
    #[must_use]
    pub const fn byte_length(&self) -> NonZeroU64 {
        self.byte_length
    }
}

/// Policy-scoped observation row.
///
/// Observations are the durable “this occurrence was seen under this policy in
/// this run/shard at this time” layer. Safe display fields live here because
/// they are policy/run-local presentation metadata, not stable identity.
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
    /// Construct a policy-scoped observation record.
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

    /// Attach optional safe display metadata.
    #[must_use]
    pub fn with_location(self, location: Location) -> Self {
        Self {
            location: Some(location),
            ..self
        }
    }

    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[inline]
    #[must_use]
    pub const fn observation_id(&self) -> ObservationId {
        self.observation_id
    }

    #[inline]
    #[must_use]
    pub const fn occurrence_id(&self) -> OccurrenceId {
        self.occurrence_id
    }

    #[inline]
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    #[inline]
    #[must_use]
    pub const fn ovid_hash(&self) -> OvidHash {
        self.ovid_hash
    }

    #[inline]
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[inline]
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    #[inline]
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }

    #[inline]
    #[must_use]
    pub const fn seen_at(&self) -> LogicalTime {
        self.seen_at
    }

    #[inline]
    #[must_use]
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }
}

/// Borrowed batch view for findings-sink upserts.
#[derive(Clone, Copy, Debug, Default)]
pub struct FindingsUpsertBatch<'a> {
    findings: &'a [FindingRecord],
    occurrences: &'a [OccurrenceRecord],
    observations: &'a [ObservationRecord],
}

impl<'a> FindingsUpsertBatch<'a> {
    /// Construct a batch view.
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

    /// Stable findings in the batch.
    #[inline]
    #[must_use]
    pub const fn findings(self) -> &'a [FindingRecord] {
        self.findings
    }

    /// Version-specific occurrences in the batch.
    #[inline]
    #[must_use]
    pub const fn occurrences(self) -> &'a [OccurrenceRecord] {
        self.occurrences
    }

    /// Policy-scoped observations in the batch.
    #[inline]
    #[must_use]
    pub const fn observations(self) -> &'a [ObservationRecord] {
        self.observations
    }

    /// Returns `true` if the batch contains no rows.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.findings.is_empty() && self.occurrences.is_empty() && self.observations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Backend-neutral traits
// ---------------------------------------------------------------------------

/// Durable done-ledger store.
///
/// Backends must preserve the monotonic status lattice:
/// - re-upserting the same key is idempotent
/// - higher-ranked statuses dominate lower-ranked statuses
/// - success states must never be downgraded to failure states
pub trait DoneLedger: Send + Sync {
    /// Backend-specific error type.
    type Error: Error + Send + Sync + 'static;

    /// Lookup a page of OVIDs for one tenant and one policy hash.
    ///
    /// Returned vector length must match `ovid_hashes.len()` and preserve input
    /// order. Missing keys are represented as `None`.
    fn batch_get(
        &self,
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        ovid_hashes: &[OvidHash],
    ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error>;

    /// Upsert a batch of done-ledger records.
    ///
    /// Implementations must apply monotonic merge semantics when a key already
    /// exists. Duplicate records for the same key must not produce duplicate
    /// durable rows.
    fn batch_upsert(&self, records: &[DoneLedgerRecord]) -> Result<(), Self::Error>;
}

/// Durable sink for findings, occurrences, and observations.
///
/// Backends must treat this as an idempotent upsert surface. Replaying the same
/// batch (or overlapping batches) must not create duplicates.
pub trait FindingsSink: Send + Sync {
    /// Backend-specific error type.
    type Error: Error + Send + Sync + 'static;

    /// Upsert a batch of findings-layer rows.
    ///
    /// Referential integrity is the backend's responsibility:
    /// - `OccurrenceRecord.finding_id` must reference a persisted or in-batch
    ///   `FindingRecord`
    /// - `ObservationRecord.occurrence_id` must reference a persisted or
    ///   in-batch `OccurrenceRecord`
    fn upsert_batch(&self, batch: FindingsUpsertBatch<'_>) -> Result<(), Self::Error>;
}

// TODO(A5): add backend-agnostic conformance tests covering:
// - idempotent done-ledger upserts
// - monotonic `DoneLedgerStatus` merge semantics
// - no duplicate findings / occurrences / observations under replay
// - `Debug` redaction for secret-derived fields and toxic bytes
