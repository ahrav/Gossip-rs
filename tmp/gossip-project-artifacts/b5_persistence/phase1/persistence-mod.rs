//! Persistence-boundary contracts: durable done-ledger keys/records,
//! findings records, durable commit acknowledgements, and the page-commit
//! typestate machine.
//!
//! This module is intentionally pure and storage-agnostic. It defines the data
//! model and acknowledgement protocol that Phase V backends implement, but does
//! not commit to any backend-specific transaction, queue, or retry mechanism.
//!
//! Scope of **A1**:
//! - durable done-ledger identity (`OvidHash`, `DoneLedgerKey`)
//! - record shapes for stable findings / occurrences / policy-scoped
//!   observations
//! - safe bounded wrappers for persistence-only string fields
//! - backend-neutral traits (`DoneLedger`, `FindingsSink`)
//!
//! Scope of **A2**:
//! - `CommitHandle` / `CommitReceipt` acknowledgement boundary
//! - receipt types proving durable findings / done-ledger / checkpoint writes
//! - `PageCommit<S>` typestate machine enforcing findings → ledger → checkpoint
//!   ordering in caller code
//!
//! Scope of **A3**:
//! - make policy-scoped identity explicit by rooting durable observations in
//!   [`ObservationId`] instead of overloading [`FindingId`]
//! - ensure [`ObservationRecord`] derives and validates its own identity from
//!   `(tenant, policy_hash, occurrence_id)`
//!
//! # Acknowledgement semantics
//!
//! The persistence boundary distinguishes **submission** from **durability**:
//!
//! - A sink method returning `Ok(handle)` means the backend accepted the write
//!   request and promises a later durable answer.
//! - The durable acknowledgement boundary is `handle.wait()`. A caller must not
//!   release worker permits, advance progress, or claim success before it holds
//!   the corresponding receipt.
//!
//! Internal request coalescing is allowed. Early acknowledgement is not.
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
    connector::{Cursor, Location, VersionId},
    identity::{
        self, CanonicalBytes, FenceEpoch, FindingId, LogicalTime, ObservationId,
        ObservationIdInputs, ObjectVersionId, OccurrenceId, PolicyHash, RuleFingerprint, RunId,
        SecretHash, ShardId, StableItemId, TenantId, derive_observation_id,
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
    /// A provided observation id does not match the canonical derived value.
    ObservationIdMismatch {
        expected: ObservationId,
        actual: ObservationId,
    },
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
            Self::ObservationIdMismatch { expected, actual } => write!(
                f,
                "observation_id does not match canonical derivation (expected {expected:?}, got {actual:?})"
            ),
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
    ///
    /// The observation identity is derived canonically from
    /// `(tenant_id, policy_hash, occurrence_id)`. Callers do not provide an
    /// arbitrary `ObservationId`; that would allow the same policy-scoped event
    /// to be mislabeled as a different identity.
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

    /// Reconstruct a policy-scoped observation record from persisted storage
    /// and verify that the stored `observation_id` still matches the canonical
    /// derivation.
    pub fn from_persisted(
        tenant_id: TenantId,
        observation_id: ObservationId,
        occurrence_id: OccurrenceId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        seen_at: LogicalTime,
    ) -> Result<Self, PersistenceInputError> {
        let record = Self::new(
            tenant_id,
            occurrence_id,
            policy_hash,
            ovid_hash,
            run_id,
            shard_id,
            fence_epoch,
            seen_at,
        );

        if record.observation_id != observation_id {
            return Err(PersistenceInputError::ObservationIdMismatch {
                expected: record.observation_id,
                actual: observation_id,
            });
        }

        Ok(record)
    }

    /// Verify that the stored `observation_id` still matches the canonical
    /// `(tenant, policy_hash, occurrence_id)` derivation.
    pub fn validate_identity(&self) -> Result<(), PersistenceInputError> {
        let expected = derive_observation_id(&ObservationIdInputs {
            tenant: self.tenant_id,
            policy: self.policy_hash,
            occurrence: self.occurrence_id,
        });

        if self.observation_id != expected {
            return Err(PersistenceInputError::ObservationIdMismatch {
                expected,
                actual: self.observation_id,
            });
        }

        Ok(())
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

    /// Validate A3 identity invariants that are local to this batch.
    ///
    /// This currently checks that every observation's stored `observation_id`
    /// matches the canonical derivation from `(tenant, policy_hash,
    /// occurrence_id)`.
    pub fn validate(self) -> Result<(), PersistenceInputError> {
        for observation in self.observations {
            observation.validate_identity()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Commit-handle / receipt boundary
// ---------------------------------------------------------------------------

/// Receipt trait for durable persistence acknowledgements.
///
/// The receipt type is the proof object that a caller must hold before it can
/// claim a persistence step succeeded.
pub trait CommitReceipt: Clone + fmt::Debug + Send + Sync + 'static {}

/// Handle returned by persistence sinks for eventual durable acknowledgement.
///
/// `Ok(handle)` from a sink method means the backend accepted the request.
/// Durability is not established until `wait()` returns a receipt.
#[must_use = "durability is not established until wait() returns a receipt"]
pub trait CommitHandle: Send + 'static {
    /// Receipt proving the durable write completed.
    type Receipt: CommitReceipt;
    /// Backend-specific wait error.
    type Error: Error + Send + Sync + 'static;

    /// Wait for the durable acknowledgement.
    ///
    /// Backends may implement this as an immediate return (direct write) or as
    /// a blocking wait on an internally queued/coalesced write.
    fn wait(self) -> Result<Self::Receipt, Self::Error>;
}

/// Immediate already-resolved handle for synchronous backends and tests.
#[must_use = "the contained result must be observed via wait()"]
#[derive(Debug)]
pub struct ReadyCommitHandle<R, E>(Result<R, E>);

impl<R, E> ReadyCommitHandle<R, E> {
    /// Construct a ready successful handle.
    #[inline]
    #[must_use]
    pub fn ok(receipt: R) -> Self {
        Self(Ok(receipt))
    }

    /// Construct a ready failed handle.
    #[inline]
    #[must_use]
    pub fn err(error: E) -> Self {
        Self(Err(error))
    }

    /// Construct from a pre-existing result.
    #[inline]
    #[must_use]
    pub fn from_result(result: Result<R, E>) -> Self {
        Self(result)
    }
}

impl<R, E> CommitHandle for ReadyCommitHandle<R, E>
where
    R: CommitReceipt,
    E: Error + Send + Sync + 'static,
{
    type Receipt = R;
    type Error = E;

    #[inline]
    fn wait(self) -> Result<Self::Receipt, Self::Error> {
        self.0
    }
}

/// Durable acknowledgement for a findings upsert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsCommitReceipt {
    finding_count: u64,
    occurrence_count: u64,
    observation_count: u64,
}

impl FindingsCommitReceipt {
    /// Construct a findings receipt.
    #[inline]
    #[must_use]
    pub const fn new(finding_count: u64, occurrence_count: u64, observation_count: u64) -> Self {
        Self {
            finding_count,
            occurrence_count,
            observation_count,
        }
    }

    #[inline]
    #[must_use]
    pub const fn finding_count(self) -> u64 {
        self.finding_count
    }

    #[inline]
    #[must_use]
    pub const fn occurrence_count(self) -> u64 {
        self.occurrence_count
    }

    #[inline]
    #[must_use]
    pub const fn observation_count(self) -> u64 {
        self.observation_count
    }
}

impl CommitReceipt for FindingsCommitReceipt {}

/// Durable acknowledgement for a done-ledger upsert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoneLedgerCommitReceipt {
    record_count: u64,
    scanned_count: u64,
    findings_count: u64,
}

impl DoneLedgerCommitReceipt {
    /// Construct a done-ledger receipt.
    #[inline]
    #[must_use]
    pub const fn new(record_count: u64, scanned_count: u64, findings_count: u64) -> Self {
        Self {
            record_count,
            scanned_count,
            findings_count,
        }
    }

    /// Number of done-ledger rows durably acknowledged by this receipt.
    #[inline]
    #[must_use]
    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    /// Number of rows whose status was one of the durable scanned states.
    #[inline]
    #[must_use]
    pub const fn scanned_count(self) -> u64 {
        self.scanned_count
    }

    /// Aggregate findings count represented by the committed rows.
    #[inline]
    #[must_use]
    pub const fn findings_count(self) -> u64 {
        self.findings_count
    }
}

impl CommitReceipt for DoneLedgerCommitReceipt {}

/// Durable acknowledgement for a cursor checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointCommitReceipt {
    tenant_id: TenantId,
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
    cursor: Cursor,
    committed_items: u64,
    checkpointed_at: LogicalTime,
}

impl CheckpointCommitReceipt {
    /// Construct a checkpoint receipt.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        cursor: Cursor,
        committed_items: u64,
        checkpointed_at: LogicalTime,
    ) -> Self {
        Self {
            tenant_id,
            run_id,
            shard_id,
            fence_epoch,
            cursor,
            committed_items,
            checkpointed_at,
        }
    }

    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
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
    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }

    #[inline]
    #[must_use]
    pub const fn committed_items(&self) -> u64 {
        self.committed_items
    }

    #[inline]
    #[must_use]
    pub const fn checkpointed_at(&self) -> LogicalTime {
        self.checkpointed_at
    }
}

impl CommitReceipt for CheckpointCommitReceipt {}

/// Composite receipt proving a page's scan results are durably committed.
///
/// Holding this receipt is the contract boundary after which a worker may
/// release scan permits for the page's items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemCommitReceipt {
    scope: PageCommitScope,
    findings: FindingsCommitReceipt,
    done_ledger: DoneLedgerCommitReceipt,
}

impl ItemCommitReceipt {
    #[inline]
    #[must_use]
    const fn new(
        scope: PageCommitScope,
        findings: FindingsCommitReceipt,
        done_ledger: DoneLedgerCommitReceipt,
    ) -> Self {
        Self {
            scope,
            findings,
            done_ledger,
        }
    }

    #[inline]
    #[must_use]
    pub fn scope(&self) -> &PageCommitScope {
        &self.scope
    }

    #[inline]
    #[must_use]
    pub const fn findings(&self) -> FindingsCommitReceipt {
        self.findings
    }

    #[inline]
    #[must_use]
    pub const fn done_ledger(&self) -> DoneLedgerCommitReceipt {
        self.done_ledger
    }
}

impl CommitReceipt for ItemCommitReceipt {}

/// Composite receipt proving a page is durably checkpointed after durable
/// findings + done-ledger commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageCommitReceipt {
    item_commit: ItemCommitReceipt,
    checkpoint: CheckpointCommitReceipt,
}

impl PageCommitReceipt {
    #[inline]
    #[must_use]
    const fn new(item_commit: ItemCommitReceipt, checkpoint: CheckpointCommitReceipt) -> Self {
        Self {
            item_commit,
            checkpoint,
        }
    }

    #[inline]
    #[must_use]
    pub fn item_commit(&self) -> &ItemCommitReceipt {
        &self.item_commit
    }

    #[inline]
    #[must_use]
    pub fn checkpoint(&self) -> &CheckpointCommitReceipt {
        &self.checkpoint
    }
}

impl CommitReceipt for PageCommitReceipt {}

// ---------------------------------------------------------------------------
// Page-commit typestate
// ---------------------------------------------------------------------------

/// Scope for a single page commit.
///
/// A page commit is always scoped to one tenant / run / shard / lease epoch and
/// to one cursor advancement boundary. The runtime constructs this once, then
/// drives the page through findings → ledger → checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageCommitScope {
    tenant_id: TenantId,
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
    committed_items: u64,
    checkpoint_cursor: Cursor,
}

impl PageCommitScope {
    /// Construct the page scope.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        committed_items: u64,
        checkpoint_cursor: Cursor,
    ) -> Self {
        Self {
            tenant_id,
            run_id,
            shard_id,
            fence_epoch,
            committed_items,
            checkpoint_cursor,
        }
    }

    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
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
    pub const fn committed_items(&self) -> u64 {
        self.committed_items
    }

    #[inline]
    #[must_use]
    pub fn checkpoint_cursor(&self) -> &Cursor {
        &self.checkpoint_cursor
    }
}

/// Validation failures when advancing a page commit through its durable stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageCommitValidationError {
    /// The done-ledger receipt covers a different number of items than the page.
    LedgerItemCountMismatch { expected: u64, actual: u64 },
    /// The checkpoint receipt belongs to a different tenant.
    CheckpointTenantMismatch { expected: TenantId, actual: TenantId },
    /// The checkpoint receipt belongs to a different run.
    CheckpointRunMismatch { expected: RunId, actual: RunId },
    /// The checkpoint receipt belongs to a different shard.
    CheckpointShardMismatch { expected: ShardId, actual: ShardId },
    /// The checkpoint receipt belongs to a different fence epoch.
    CheckpointFenceMismatch {
        expected: FenceEpoch,
        actual: FenceEpoch,
    },
    /// The checkpoint receipt covers a different number of items than the page.
    CheckpointItemCountMismatch { expected: u64, actual: u64 },
    /// The checkpoint receipt advanced to a different cursor than expected.
    CheckpointCursorMismatch,
}

impl fmt::Display for PageCommitValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LedgerItemCountMismatch { expected, actual } => write!(
                f,
                "done-ledger receipt item count mismatch: expected {expected}, got {actual}"
            ),
            Self::CheckpointTenantMismatch { .. } => {
                write!(f, "checkpoint receipt tenant does not match page scope")
            }
            Self::CheckpointRunMismatch { .. } => {
                write!(f, "checkpoint receipt run does not match page scope")
            }
            Self::CheckpointShardMismatch { .. } => {
                write!(f, "checkpoint receipt shard does not match page scope")
            }
            Self::CheckpointFenceMismatch { .. } => {
                write!(f, "checkpoint receipt fence epoch does not match page scope")
            }
            Self::CheckpointItemCountMismatch { expected, actual } => write!(
                f,
                "checkpoint receipt item count mismatch: expected {expected}, got {actual}"
            ),
            Self::CheckpointCursorMismatch => {
                write!(f, "checkpoint receipt cursor does not match page scope")
            }
        }
    }
}

impl Error for PageCommitValidationError {}

/// Combined wait/validation error for page-commit state transitions.
#[derive(Debug)]
pub enum CommitAdvanceError<E> {
    /// Waiting for the backend handle failed.
    Wait(E),
    /// The durable receipt did not match the page scope.
    Validation(PageCommitValidationError),
}

impl<E> fmt::Display for CommitAdvanceError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wait(err) => write!(f, "durable wait failed: {err}"),
            Self::Validation(err) => write!(f, "invalid durable receipt: {err}"),
        }
    }
}

impl<E> Error for CommitAdvanceError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wait(err) => Some(err),
            Self::Validation(err) => Some(err),
        }
    }
}

/// Initial page state: no durable findings acknowledgement yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AwaitingFindings;

/// Findings are durably persisted; done-ledger still pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsDurable {
    findings: FindingsCommitReceipt,
}

/// Findings + done-ledger are durably persisted; checkpoint still pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemDurable {
    item_commit: ItemCommitReceipt,
}

/// Full page durable state: findings + ledger + checkpoint all durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointDurable {
    page_commit: PageCommitReceipt,
}

/// Typestate machine for the page-commit protocol.
#[must_use = "page commits must be driven to a durable receipt or explicitly dropped"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageCommit<S> {
    scope: PageCommitScope,
    state: S,
}

impl PageCommit<AwaitingFindings> {
    /// Start a new page commit for `scope`.
    #[inline]
    #[must_use]
    pub fn new(scope: PageCommitScope) -> Self {
        Self {
            scope,
            state: AwaitingFindings,
        }
    }

    /// Advance the page after obtaining a durable findings receipt.
    #[inline]
    #[must_use]
    pub fn record_findings(self, receipt: FindingsCommitReceipt) -> PageCommit<FindingsDurable> {
        PageCommit {
            scope: self.scope,
            state: FindingsDurable { findings: receipt },
        }
    }

    /// Wait on a findings handle and advance on success.
    pub fn wait_findings<H>(self, handle: H) -> Result<PageCommit<FindingsDurable>, H::Error>
    where
        H: CommitHandle<Receipt = FindingsCommitReceipt>,
    {
        let receipt = handle.wait()?;
        Ok(self.record_findings(receipt))
    }
}

impl PageCommit<FindingsDurable> {
    /// Page scope shared across all later states.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &PageCommitScope {
        &self.scope
    }

    /// Durable findings receipt.
    #[inline]
    #[must_use]
    pub const fn findings_receipt(&self) -> FindingsCommitReceipt {
        self.state.findings
    }

    /// Advance the page after obtaining a durable done-ledger receipt.
    pub fn record_done_ledger(
        self,
        receipt: DoneLedgerCommitReceipt,
    ) -> Result<PageCommit<ItemDurable>, PageCommitValidationError> {
        let expected = self.scope.committed_items();
        let actual = receipt.record_count();
        if expected != actual {
            return Err(PageCommitValidationError::LedgerItemCountMismatch { expected, actual });
        }

        let item_commit = ItemCommitReceipt::new(self.scope.clone(), self.state.findings, receipt);
        Ok(PageCommit {
            scope: self.scope,
            state: ItemDurable { item_commit },
        })
    }

    /// Wait on a done-ledger handle and advance on success.
    pub fn wait_done_ledger<H>(
        self,
        handle: H,
    ) -> Result<PageCommit<ItemDurable>, CommitAdvanceError<H::Error>>
    where
        H: CommitHandle<Receipt = DoneLedgerCommitReceipt>,
    {
        let receipt = handle.wait().map_err(CommitAdvanceError::Wait)?;
        self.record_done_ledger(receipt)
            .map_err(CommitAdvanceError::Validation)
    }
}

impl PageCommit<ItemDurable> {
    /// Page scope shared across all later states.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &PageCommitScope {
        &self.scope
    }

    /// Composite item-commit receipt proving durable findings + done-ledger.
    #[inline]
    #[must_use]
    pub fn item_commit_receipt(&self) -> &ItemCommitReceipt {
        &self.state.item_commit
    }

    /// Consume the state into the item-commit receipt.
    #[inline]
    #[must_use]
    pub fn into_item_commit_receipt(self) -> ItemCommitReceipt {
        self.state.item_commit
    }

    /// Advance the page after obtaining a durable checkpoint receipt.
    pub fn record_checkpoint(
        self,
        receipt: CheckpointCommitReceipt,
    ) -> Result<PageCommit<CheckpointDurable>, PageCommitValidationError> {
        if receipt.tenant_id() != self.scope.tenant_id() {
            return Err(PageCommitValidationError::CheckpointTenantMismatch {
                expected: self.scope.tenant_id(),
                actual: receipt.tenant_id(),
            });
        }
        if receipt.run_id() != self.scope.run_id() {
            return Err(PageCommitValidationError::CheckpointRunMismatch {
                expected: self.scope.run_id(),
                actual: receipt.run_id(),
            });
        }
        if receipt.shard_id() != self.scope.shard_id() {
            return Err(PageCommitValidationError::CheckpointShardMismatch {
                expected: self.scope.shard_id(),
                actual: receipt.shard_id(),
            });
        }
        if receipt.fence_epoch() != self.scope.fence_epoch() {
            return Err(PageCommitValidationError::CheckpointFenceMismatch {
                expected: self.scope.fence_epoch(),
                actual: receipt.fence_epoch(),
            });
        }
        if receipt.committed_items() != self.scope.committed_items() {
            return Err(PageCommitValidationError::CheckpointItemCountMismatch {
                expected: self.scope.committed_items(),
                actual: receipt.committed_items(),
            });
        }
        if receipt.cursor() != self.scope.checkpoint_cursor() {
            return Err(PageCommitValidationError::CheckpointCursorMismatch);
        }

        let page_commit = PageCommitReceipt::new(self.state.item_commit, receipt);
        Ok(PageCommit {
            scope: self.scope,
            state: CheckpointDurable { page_commit },
        })
    }

    /// Wait on a checkpoint handle and advance on success.
    pub fn wait_checkpoint<H>(
        self,
        handle: H,
    ) -> Result<PageCommit<CheckpointDurable>, CommitAdvanceError<H::Error>>
    where
        H: CommitHandle<Receipt = CheckpointCommitReceipt>,
    {
        let receipt = handle.wait().map_err(CommitAdvanceError::Wait)?;
        self.record_checkpoint(receipt)
            .map_err(CommitAdvanceError::Validation)
    }
}

impl PageCommit<CheckpointDurable> {
    /// Final durable page receipt.
    #[inline]
    #[must_use]
    pub fn page_commit_receipt(&self) -> &PageCommitReceipt {
        &self.state.page_commit
    }

    /// Consume the state into the final durable page receipt.
    #[inline]
    #[must_use]
    pub fn into_page_commit_receipt(self) -> PageCommitReceipt {
        self.state.page_commit
    }

    /// Page scope shared across all later states.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &PageCommitScope {
        &self.scope
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
///
/// Submission and durability are separated:
/// - `Ok(handle)` means the backend accepted responsibility for the upsert.
/// - `handle.wait()` is the durable acknowledgement boundary.
pub trait DoneLedger: Send + Sync {
    /// Backend-specific immediate/submit error type.
    type Error: Error + Send + Sync + 'static;
    /// Handle returned for done-ledger writes.
    type CommitHandle: CommitHandle<Receipt = DoneLedgerCommitReceipt, Error = Self::Error>;

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

    /// Submit a batch of done-ledger records for durable upsert.
    ///
    /// Implementations must apply monotonic merge semantics when a key already
    /// exists. Duplicate records for the same key must not produce duplicate
    /// durable rows.
    fn batch_upsert(&self, records: &[DoneLedgerRecord]) -> Result<Self::CommitHandle, Self::Error>;
}

/// Durable sink for findings, occurrences, and observations.
///
/// Backends must treat this as an idempotent upsert surface. Replaying the same
/// batch (or overlapping batches) must not create duplicates.
///
/// Submission and durability are separated:
/// - `Ok(handle)` means the backend accepted responsibility for the upsert.
/// - `handle.wait()` is the durable acknowledgement boundary.
pub trait FindingsSink: Send + Sync {
    /// Backend-specific immediate/submit error type.
    type Error: Error + Send + Sync + 'static;
    /// Handle returned for findings-layer writes.
    type CommitHandle: CommitHandle<Receipt = FindingsCommitReceipt, Error = Self::Error>;

    /// Submit a batch of findings-layer rows for durable upsert.
    ///
    /// Referential integrity is the backend's responsibility:
    /// - `OccurrenceRecord.finding_id` must reference a persisted or in-batch
    ///   `FindingRecord`
    /// - `ObservationRecord.occurrence_id` must reference a persisted or
    ///   in-batch `OccurrenceRecord`
    /// - `ObservationRecord.observation_id` must equal the canonical
    ///   derivation from `(tenant_id, policy_hash, occurrence_id)`
    fn upsert_batch(&self, batch: FindingsUpsertBatch<'_>) -> Result<Self::CommitHandle, Self::Error>;
}

// TODO(A4): add in-memory reference implementations with fault injection.
// TODO(A5): add backend-agnostic conformance tests covering:
// - idempotent done-ledger upserts
// - monotonic `DoneLedgerStatus` merge semantics
// - no duplicate findings / occurrences / observations under replay
// - no-early-ACK semantics for `CommitHandle::wait`
// - `PageCommit<S>` ordering and scope validation


#[cfg(any(test, feature = "test-support"))]
mod in_memory;

#[cfg(any(test, feature = "test-support"))]
pub use in_memory::{
    CompletionOrder, InMemoryDoneLedger, InMemoryDoneLedgerHandle, InMemoryFindingsHandle,
    InMemoryFindingsSink, InMemoryPersistenceError, InMemoryStoreKind, PendingWriteId,
};
