//! Done-ledger: deduplication tracking for scanned object-versions.
//!
//! The done-ledger records whether a specific object-version has already been
//! processed under a given tenant and scan policy. Its primary purpose is
//! **at-most-once scan semantics**: before scanning an object, the pipeline
//! checks the done-ledger to avoid redundant work.
//!
//! ## Data model
//!
//! Each row is keyed by [`DoneLedgerKey`] = `(tenant, policy_hash, ovid_hash)`.
//! This triple ensures that:
//! - The same object scanned under different policies produces separate entries.
//! - The same policy applied to different object versions produces separate entries.
//!
//! ## Monotonic status lattice
//!
//! [`DoneLedgerStatus`] forms a join-semilattice ordered by discriminant rank.
//! The merge rule is `max(self.rank(), other.rank())`, which guarantees:
//! - **Idempotence**: merging a value with itself is a no-op.
//! - **Commutativity**: `a.merge(b) == b.merge(a)`.
//! - **Monotonicity**: once an object reaches a scanned state, no failure can
//!   downgrade it.
//!
//! Backend implementations must preserve this lattice during upsert. See the
//! [`DoneLedger`] trait for the full contract.
//!
//! ## Safety boundary
//!
//! Error codes attached to failure/skip entries are restricted to a small
//! ASCII-safe alphabet via [`DoneLedgerErrorCode`]. Raw connector output or
//! user-supplied strings must never be stored in this field.

use std::{error::Error, fmt};

use blake3::Hasher;

use crate::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId,
};

use super::{PersistenceInputError, ovid::OvidHash};

/// Maximum length of a done-ledger error code in bytes.
///
/// This field exists for short structured codes like `HTTP_403`, `TIMEOUT`,
/// or `UNSUPPORTED_FORMAT`, not arbitrary messages.
pub const MAX_DONE_LEDGER_ERROR_CODE_SIZE: usize = 128;

/// Composite key for a done-ledger row: `(tenant, policy, object-version)`.
///
/// Each component serves a distinct scoping role:
/// - [`TenantId`] — isolates data between tenants.
/// - [`PolicyHash`] — ensures re-scanning under a changed policy is not
///   suppressed by a stale done-ledger entry from a previous policy version.
/// - [`OvidHash`] — identifies the exact object-version (stable item identity
///   plus version claim), derived via [`super::derive_ovid_hash`].
///
/// This key implements [`CanonicalBytes`] for content-addressed identity
/// derivation, writing all three fields in a fixed, unambiguous order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DoneLedgerKey {
    tenant_id: TenantId,
    policy_hash: PolicyHash,
    ovid_hash: OvidHash,
}

impl DoneLedgerKey {
    /// Construct a done-ledger key from its three scoping components.
    #[inline]
    #[must_use]
    pub const fn new(tenant_id: TenantId, policy_hash: PolicyHash, ovid_hash: OvidHash) -> Self {
        Self {
            tenant_id,
            policy_hash,
            ovid_hash,
        }
    }

    /// Tenant isolation boundary.
    #[inline]
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    /// Scan-policy version under which this object was processed.
    #[inline]
    #[must_use]
    pub const fn policy_hash(self) -> PolicyHash {
        self.policy_hash
    }

    /// Object-version identity (stable item + version claim hash).
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
/// Discriminant values define the merge ordering: `merge(a, b) = max(a.rank(), b.rank())`.
/// This makes the lattice a join-semilattice with the three required properties
/// (idempotence, commutativity, monotonicity).
///
/// ## Rank design
///
/// There is an intentional gap between `Skipped` (3) and `ScannedClean` (10).
/// This reserves discriminant space for future non-terminal states without
/// changing the relative ordering of existing variants. Backends store
/// [`rank()`](Self::rank) as a `u8`, so adding a variant between 3 and 10
/// is a backwards-compatible schema change.
///
/// ## Practical effect
///
/// Once an object-version reaches `ScannedClean` or `ScannedWithFindings`,
/// no amount of concurrent or replayed failure/skip writes can downgrade it.
/// This is the key property that makes done-ledger deduplication safe under
/// crash-recovery and at-least-once delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DoneLedgerStatus {
    /// Temporary failure; the item may be retried and succeed later.
    FailedRetryable = 1,
    /// Terminal failure for the current tenant + policy + object-version triple.
    FailedPermanent = 2,
    /// Intentionally skipped (unsupported format, filtered by policy, size cap, etc.).
    Skipped = 3,
    /// Successfully scanned and committed; no secrets or findings detected.
    ScannedClean = 10,
    /// Successfully scanned and committed; one or more findings were persisted.
    ScannedWithFindings = 11,
}

impl DoneLedgerStatus {
    /// Numeric discriminant used as the total-order key for lattice merge.
    ///
    /// This value is what backends should persist and compare during upsert.
    /// Use [`from_rank`](Self::from_rank) to reconstitute the enum from a
    /// stored discriminant.
    #[inline]
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    /// Reconstitute a [`DoneLedgerStatus`] from a persisted rank discriminant.
    ///
    /// Returns `None` for values that do not correspond to a known variant.
    /// Backends should treat an unknown rank as a data-corruption signal
    /// rather than silently mapping it to a default.
    #[inline]
    #[must_use]
    pub const fn from_rank(rank: u8) -> Option<Self> {
        match rank {
            1 => Some(Self::FailedRetryable),
            2 => Some(Self::FailedPermanent),
            3 => Some(Self::Skipped),
            10 => Some(Self::ScannedClean),
            11 => Some(Self::ScannedWithFindings),
            _ => None,
        }
    }

    /// Returns `true` for terminal success states (`ScannedClean` or
    /// `ScannedWithFindings`).
    ///
    /// A scanned status means the object-version was fully processed and
    /// its results (or lack thereof) are durably committed.
    #[inline]
    #[must_use]
    pub const fn is_scanned(self) -> bool {
        matches!(self, Self::ScannedClean | Self::ScannedWithFindings)
    }

    /// Returns `true` for failure states (`FailedRetryable` or `FailedPermanent`).
    #[inline]
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::FailedRetryable | Self::FailedPermanent)
    }

    /// Returns `true` for the `Skipped` state.
    #[inline]
    #[must_use]
    pub const fn is_skipped(self) -> bool {
        matches!(self, Self::Skipped)
    }

    /// Lattice join: returns whichever status has the higher rank.
    ///
    /// This is the merge function backends must use during upsert when a
    /// row already exists for the same [`DoneLedgerKey`].
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

/// Short structured code associated with a done-ledger skip or failure.
///
/// This is intentionally not a free-form message field. It exists for bounded
/// internal values like `HTTP_403`, `TIMEOUT`, `UNSUPPORTED FORMAT`, etc. Raw
/// connector or source content must never be stored here.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DoneLedgerErrorCode(Box<str>);

impl DoneLedgerErrorCode {
    /// Construct a validated error code from an ASCII-safe string.
    ///
    /// # Allowed characters
    ///
    /// ASCII alphanumeric plus `' '`, `'_'`, `'-'`, `'.'`, `':'`, `'/'`.
    /// This alphabet covers structured codes like `HTTP_403`, `TIMEOUT`,
    /// and `S3:ACCESS_DENIED` without admitting arbitrary user input.
    ///
    /// # Errors
    ///
    /// - [`PersistenceInputError::Empty`] if `code` is empty.
    /// - [`PersistenceInputError::TooLarge`] if `code` exceeds
    ///   [`MAX_DONE_LEDGER_ERROR_CODE_SIZE`] bytes.
    /// - [`PersistenceInputError::InvalidByte`] if any byte falls outside
    ///   the allowed set.
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
                || matches!(byte, b' ' | b'_' | b'-' | b'.' | b':' | b'/');
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

/// Provenance metadata recording which worker, shard, and time window
/// produced a done-ledger entry.
///
/// Provenance is not part of the deduplication key — it is write-side
/// metadata used for debugging, auditing, and stale-entry diagnostics.
/// When a higher-ranked status overwrites an existing row, the provenance
/// is replaced along with it.
///
/// The `fence_epoch` ties the write to a specific lease epoch, enabling
/// backends to detect and reject writes from stale (pre-fence) workers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoneLedgerProvenance {
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
    started_at: LogicalTime,
    finished_at: LogicalTime,
}

impl DoneLedgerProvenance {
    /// Construct provenance for a done-ledger write.
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

    /// Globally unique run that produced this entry.
    #[inline]
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Shard that was being processed when this entry was written.
    #[inline]
    #[must_use]
    pub const fn shard_id(self) -> ShardId {
        self.shard_id
    }

    /// Lease epoch under which the writing worker held its shard lease.
    #[inline]
    #[must_use]
    pub const fn fence_epoch(self) -> FenceEpoch {
        self.fence_epoch
    }

    /// Logical timestamp when scanning of this object-version began.
    #[inline]
    #[must_use]
    pub const fn started_at(self) -> LogicalTime {
        self.started_at
    }

    /// Logical timestamp when scanning of this object-version completed.
    #[inline]
    #[must_use]
    pub const fn finished_at(self) -> LogicalTime {
        self.finished_at
    }
}

/// Complete done-ledger row combining the deduplication key, lattice status,
/// scan metrics, provenance, and an optional error code.
///
/// This is the unit of persistence for both reads ([`DoneLedger::batch_get`])
/// and writes ([`DoneLedger::batch_upsert`]). During upsert the backend must
/// compare the incoming [`status`](Self::status) against the existing row's
/// status using [`DoneLedgerStatus::merge`] and keep the dominant value.
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
    /// Construct a done-ledger record, validating that `findings_count` is
    /// consistent with `status`.
    ///
    /// # Invariant
    ///
    /// - `ScannedWithFindings` requires `findings_count > 0`.
    /// - `ScannedClean` requires `findings_count == 0`.
    /// - Failure and skip statuses accept any `findings_count`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceInputError::InconsistentFindingsCount`] if the
    /// invariant is violated.
    pub fn try_new(
        key: DoneLedgerKey,
        status: DoneLedgerStatus,
        bytes_scanned: u64,
        findings_count: u32,
        provenance: DoneLedgerProvenance,
        error_code: Option<DoneLedgerErrorCode>,
    ) -> Result<Self, PersistenceInputError> {
        match status {
            DoneLedgerStatus::ScannedWithFindings if findings_count == 0 => {
                return Err(PersistenceInputError::InconsistentFindingsCount {
                    status: "ScannedWithFindings",
                    findings_count,
                });
            }
            DoneLedgerStatus::ScannedClean if findings_count > 0 => {
                return Err(PersistenceInputError::InconsistentFindingsCount {
                    status: "ScannedClean",
                    findings_count,
                });
            }
            _ => {}
        }
        Ok(Self {
            key,
            status,
            bytes_scanned,
            findings_count,
            provenance,
            error_code,
        })
    }

    /// Deduplication key: `(tenant, policy, object-version)`.
    #[inline]
    #[must_use]
    pub const fn key(&self) -> DoneLedgerKey {
        self.key
    }

    /// Lattice status governing merge behavior during upsert.
    #[inline]
    #[must_use]
    pub const fn status(&self) -> DoneLedgerStatus {
        self.status
    }

    /// Total bytes consumed while scanning the object-version.
    #[inline]
    #[must_use]
    pub const fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned
    }

    /// Number of distinct findings detected during the scan.
    #[inline]
    #[must_use]
    pub const fn findings_count(&self) -> u32 {
        self.findings_count
    }

    /// Run/shard/epoch metadata for the worker that produced this entry.
    #[inline]
    #[must_use]
    pub const fn provenance(&self) -> DoneLedgerProvenance {
        self.provenance
    }

    /// Structured error code, conventionally present only for failure or skip
    /// statuses.
    ///
    /// This invariant is **not** enforced at construction. Callers should
    /// set this to `None` when `status.is_scanned()` is `true`.
    /// Observability pipelines may ignore or warn on error codes attached to
    /// terminal success statuses.
    #[inline]
    #[must_use]
    pub fn error_code(&self) -> Option<&DoneLedgerErrorCode> {
        self.error_code.as_ref()
    }
}

/// Backend-neutral trait for a durable done-ledger store.
///
/// # Implementor contract
///
/// 1. **Monotonic lattice merge.** When upserting a key that already exists,
///    the backend must compare incoming and existing statuses via
///    [`DoneLedgerStatus::merge`] and persist only the dominant value.
/// 2. **Idempotent writes.** Re-upserting the same `(key, status)` pair must
///    be a no-op — it must not create duplicate rows or change metrics.
/// 3. **No downgrade.** A scanned status must never be overwritten by a
///    failure or skip status, regardless of write ordering.
/// 4. **Positional batch_get.** The returned `Vec` from [`batch_get`](Self::batch_get)
///    must have exactly the same length as the input `ovid_hashes` slice,
///    with `None` for keys not yet present.
pub trait DoneLedger: Send + Sync {
    /// Backend-specific error type.
    type Error: Error + Send + Sync + 'static;

    /// Look up done-ledger rows for a batch of object-versions within one
    /// tenant and policy.
    ///
    /// Returns a positional `Vec` aligned with `ovid_hashes`: the *i*-th
    /// element is `Some(record)` if the key `(tenant_id, policy_hash,
    /// ovid_hashes[i])` exists, or `None` otherwise.
    fn batch_get(
        &self,
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        ovid_hashes: &[OvidHash],
    ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error>;

    /// Upsert a batch of done-ledger records, applying monotonic merge
    /// semantics for any keys that already exist.
    ///
    /// If the batch contains duplicate keys, the implementation must
    /// merge them (not produce duplicate rows). The final persisted status
    /// for each key must be the lattice join of all incoming and existing
    /// values.
    fn batch_upsert(&self, records: &[DoneLedgerRecord]) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use crate::{
        identity::{PolicyHash, TenantId},
        test_util::canonical_digest,
    };

    use super::*;

    const ALL_STATUSES: [DoneLedgerStatus; 5] = [
        DoneLedgerStatus::FailedRetryable,
        DoneLedgerStatus::FailedPermanent,
        DoneLedgerStatus::Skipped,
        DoneLedgerStatus::ScannedClean,
        DoneLedgerStatus::ScannedWithFindings,
    ];

    fn tenant(seed: u8) -> TenantId {
        TenantId::from_bytes([seed; 32])
    }

    fn policy(seed: u8) -> PolicyHash {
        PolicyHash::from_bytes([seed; 32])
    }

    fn ovid(seed: u8) -> OvidHash {
        OvidHash::from_bytes([seed; 32])
    }

    #[test]
    fn done_ledger_status_merge_is_commutative_idempotent_and_monotonic() {
        for left in ALL_STATUSES {
            assert_eq!(left.merge(left), left, "idempotence failed for {left:?}");

            for right in ALL_STATUSES {
                let merged = left.merge(right);

                assert_eq!(
                    merged,
                    right.merge(left),
                    "commutativity failed for {left:?} and {right:?}"
                );
                assert_eq!(
                    merged.rank(),
                    left.rank().max(right.rank()),
                    "monotonicity failed for {left:?} and {right:?}"
                );
            }
        }
    }

    #[test]
    fn scanned_statuses_do_not_downgrade_to_failures() {
        for scanned in [
            DoneLedgerStatus::ScannedClean,
            DoneLedgerStatus::ScannedWithFindings,
        ] {
            for failure in [
                DoneLedgerStatus::FailedRetryable,
                DoneLedgerStatus::FailedPermanent,
            ] {
                assert_eq!(scanned.merge(failure), scanned);
            }
        }
    }

    #[test]
    fn done_ledger_error_code_accepts_bounded_safe_bytes() {
        let error_code = DoneLedgerErrorCode::try_new("HTTP 403/TIMEOUT:UPSTREAM").unwrap();

        assert_eq!(error_code.as_str(), "HTTP 403/TIMEOUT:UPSTREAM");
    }

    #[test]
    fn done_ledger_error_code_rejects_invalid_inputs() {
        assert_eq!(
            DoneLedgerErrorCode::try_new("").unwrap_err(),
            PersistenceInputError::Empty {
                field: "DoneLedgerErrorCode",
            }
        );

        assert_eq!(
            DoneLedgerErrorCode::try_new("BAD*CODE").unwrap_err(),
            PersistenceInputError::InvalidByte {
                field: "DoneLedgerErrorCode",
                index: 3,
                byte: b'*',
            }
        );

        let oversized = "A".repeat(MAX_DONE_LEDGER_ERROR_CODE_SIZE + 1);
        assert_eq!(
            DoneLedgerErrorCode::try_new(oversized).unwrap_err(),
            PersistenceInputError::TooLarge {
                field: "DoneLedgerErrorCode",
                size: MAX_DONE_LEDGER_ERROR_CODE_SIZE + 1,
                max: MAX_DONE_LEDGER_ERROR_CODE_SIZE,
            }
        );
    }

    #[test]
    fn done_ledger_status_from_rank_round_trips_all_variants() {
        for status in ALL_STATUSES {
            let rank = status.rank();
            let reconstituted = DoneLedgerStatus::from_rank(rank)
                .unwrap_or_else(|| panic!("from_rank({rank}) should reconstitute {status:?}"));
            assert_eq!(reconstituted, status);
        }
    }

    #[test]
    fn done_ledger_status_from_rank_rejects_unknown_discriminants() {
        // Gaps in the rank space and out-of-range values.
        for invalid in [0, 4, 5, 6, 7, 8, 9, 12, 255] {
            assert!(
                DoneLedgerStatus::from_rank(invalid).is_none(),
                "from_rank({invalid}) should return None"
            );
        }
    }

    #[test]
    fn done_ledger_key_canonical_digest_is_stable() {
        let key = DoneLedgerKey::new(tenant(5), policy(7), ovid(11));

        assert_eq!(canonical_digest(&key), canonical_digest(&key));
    }

    fn make_provenance() -> DoneLedgerProvenance {
        use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId};
        DoneLedgerProvenance::new(
            RunId::from_raw(1),
            ShardId::from_raw(2),
            FenceEpoch::from_raw(3),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(200),
        )
    }

    #[test]
    fn rejects_scanned_with_findings_when_findings_count_is_zero() {
        let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
        let result = DoneLedgerRecord::try_new(
            key,
            DoneLedgerStatus::ScannedWithFindings,
            1024,
            0, // contradiction: "with findings" but count is 0
            make_provenance(),
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            PersistenceInputError::InconsistentFindingsCount {
                status: "ScannedWithFindings",
                findings_count: 0,
            }
        );
    }

    #[test]
    fn rejects_scanned_clean_when_findings_count_is_nonzero() {
        let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
        let result = DoneLedgerRecord::try_new(
            key,
            DoneLedgerStatus::ScannedClean,
            1024,
            5, // contradiction: "clean" but count is 5
            make_provenance(),
            None,
        );
        assert!(
            result.is_err(),
            "ScannedClean with findings_count > 0 should be rejected"
        );
    }

    #[test]
    fn accepts_consistent_scanned_with_findings_record() {
        let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
        let record = DoneLedgerRecord::try_new(
            key,
            DoneLedgerStatus::ScannedWithFindings,
            1024,
            3,
            make_provenance(),
            None,
        )
        .expect("consistent ScannedWithFindings should be accepted");
        assert_eq!(record.findings_count(), 3);
    }

    #[test]
    fn accepts_consistent_scanned_clean_record() {
        let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
        let record = DoneLedgerRecord::try_new(
            key,
            DoneLedgerStatus::ScannedClean,
            1024,
            0,
            make_provenance(),
            None,
        )
        .expect("consistent ScannedClean should be accepted");
        assert_eq!(record.findings_count(), 0);
    }

    #[test]
    fn failure_and_skip_statuses_accept_any_findings_count() {
        for status in [
            DoneLedgerStatus::FailedRetryable,
            DoneLedgerStatus::FailedPermanent,
            DoneLedgerStatus::Skipped,
        ] {
            // findings_count is meaningless for non-scanned statuses.
            let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
            DoneLedgerRecord::try_new(key, status, 0, 0, make_provenance(), None)
                .unwrap_or_else(|e| panic!("{status:?} with count 0 should succeed: {e}"));
            let key2 = DoneLedgerKey::new(tenant(1), policy(2), ovid(4));
            DoneLedgerRecord::try_new(key2, status, 0, 5, make_provenance(), None)
                .unwrap_or_else(|e| panic!("{status:?} with count 5 should succeed: {e}"));
        }
    }
}
