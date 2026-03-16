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
//! The merge rule is `max(self.rank(), other.rank())`, which makes
//! [`DoneLedgerStatus`] a join-semilattice satisfying:
//! - **Idempotence**: merging a value with itself is a no-op.
//! - **Commutativity**: `a.merge(b) == b.merge(a)`.
//! - **Associativity**: merge grouping does not affect the result.
//!
//! Monotonicity follows as a consequence: once an object reaches a scanned
//! state, no failure can downgrade it.
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

use super::{
    PersistenceInputError, WriteContext,
    commit::{CommitHandle, DoneLedgerCommitReceipt},
    ovid::OvidHash,
};

#[inline]
pub(crate) fn pg_bigint_bits_sort_key(raw: u64) -> i64 {
    // Bit-pattern reinterpret to signed i64 — PostgreSQL stores RunId/ShardId
    // as signed BIGINT via u64_to_pg_bigint_bits, so the provenance-winner
    // ROW() comparison orders them as signed. This helper replicates that
    // ordering on the Rust side.
    i64::from_ne_bytes(raw.to_ne_bytes())
}

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
/// This makes the lattice a join-semilattice satisfying idempotence,
/// commutativity, and associativity. Monotonicity follows as a consequence.
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

// Compile-time exhaustiveness guard: adding or removing a variant forces
// a compile error here because the match has no wildcard. Update both `ALL`
// and this function whenever the variant set changes.
const _: () = {
    const fn check_exhaustive(s: DoneLedgerStatus) -> u8 {
        match s {
            DoneLedgerStatus::FailedRetryable => 0,
            DoneLedgerStatus::FailedPermanent => 1,
            DoneLedgerStatus::Skipped => 2,
            DoneLedgerStatus::ScannedClean => 3,
            DoneLedgerStatus::ScannedWithFindings => 4,
        }
    }
    // Touch every variant so the match is reachable.
    let _ = check_exhaustive(DoneLedgerStatus::FailedRetryable);
    assert!(DoneLedgerStatus::ALL.len() == 5);
};

impl DoneLedgerStatus {
    /// All status variants in rank order, for exhaustive iteration.
    pub const ALL: [DoneLedgerStatus; 5] = [
        DoneLedgerStatus::FailedRetryable,
        DoneLedgerStatus::FailedPermanent,
        DoneLedgerStatus::Skipped,
        DoneLedgerStatus::ScannedClean,
        DoneLedgerStatus::ScannedWithFindings,
    ];

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
///
/// Allocation tier: WARM — error codes are only attached to failure/skip
/// statuses, which are non-steady-state paths.
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
        let mut all_spaces = true;
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
            if byte != b' ' {
                all_spaces = false;
            }
        }
        if all_spaces {
            return Err(PersistenceInputError::Empty {
                field: "DoneLedgerErrorCode",
            });
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
    ///
    /// # Debug-mode invariant
    ///
    /// `started_at` must not exceed `finished_at`. A violation triggers a
    /// `debug_assert` panic in debug builds but is silently accepted in
    /// release builds.
    #[inline]
    #[must_use]
    pub fn new(
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        started_at: LogicalTime,
        finished_at: LogicalTime,
    ) -> Self {
        debug_assert!(
            started_at.as_raw() <= finished_at.as_raw(),
            "provenance: started_at ({started_at:?}) must not exceed finished_at ({finished_at:?})"
        );
        Self {
            run_id,
            shard_id,
            fence_epoch,
            started_at,
            finished_at,
        }
    }

    /// Construct provenance from a shared write context plus item-local scan
    /// timing.
    ///
    /// `DoneLedgerProvenance` stores only the write-side fields that are not
    /// already captured by [`DoneLedgerKey`]. The tenant and policy live on the
    /// key, so this constructor extracts only `(run_id, shard_id, fence_epoch)`
    /// from the full [`WriteContext`].
    #[inline]
    #[must_use]
    pub fn from_write_context(
        write_context: WriteContext,
        started_at: LogicalTime,
        finished_at: LogicalTime,
    ) -> Self {
        Self::new(
            write_context.run_id(),
            write_context.shard_id(),
            write_context.fence_epoch(),
            started_at,
            finished_at,
        )
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

    /// Reconstruct the shared write context by combining the key's tenant and
    /// policy with the provenance's run, shard, and fence fields.
    #[inline]
    #[must_use]
    pub const fn write_context(&self) -> WriteContext {
        WriteContext::new(
            self.key.tenant_id(),
            self.key.policy_hash(),
            self.provenance.run_id(),
            self.provenance.shard_id(),
            self.provenance.fence_epoch(),
        )
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

    /// Validate cross-field invariants that are intentionally not enforced at
    /// construction (to keep [`try_new`](Self::try_new) flexible for
    /// deserialization).
    ///
    /// Write-path callers should invoke this before persisting a record.
    ///
    /// # Checks
    ///
    /// - `ScannedClean`: `findings_count == 0` **and** `error_code` is `None`.
    /// - `ScannedWithFindings`: `findings_count > 0`.
    /// - `FailedRetryable` / `FailedPermanent` / `Skipped`: `error_code` is `Some`.
    pub fn validate(&self) -> Result<(), PersistenceInputError> {
        let status_name = match self.status {
            DoneLedgerStatus::ScannedClean => "ScannedClean",
            DoneLedgerStatus::ScannedWithFindings => "ScannedWithFindings",
            DoneLedgerStatus::FailedRetryable => "FailedRetryable",
            DoneLedgerStatus::FailedPermanent => "FailedPermanent",
            DoneLedgerStatus::Skipped => "Skipped",
        };

        match self.status {
            DoneLedgerStatus::ScannedClean => {
                if self.findings_count != 0 {
                    return Err(PersistenceInputError::InconsistentFindingsCount {
                        status: status_name,
                        findings_count: self.findings_count,
                    });
                }
                if self.error_code.is_some() {
                    return Err(PersistenceInputError::UnexpectedErrorCode {
                        status: status_name,
                    });
                }
            }
            DoneLedgerStatus::ScannedWithFindings => {
                if self.findings_count == 0 {
                    return Err(PersistenceInputError::InconsistentFindingsCount {
                        status: status_name,
                        findings_count: self.findings_count,
                    });
                }
                if self.error_code.is_some() {
                    return Err(PersistenceInputError::UnexpectedErrorCode {
                        status: status_name,
                    });
                }
            }
            DoneLedgerStatus::FailedRetryable
            | DoneLedgerStatus::FailedPermanent
            | DoneLedgerStatus::Skipped => {
                if self.error_code.is_none() {
                    return Err(PersistenceInputError::MissingErrorCode {
                        status: status_name,
                    });
                }
            }
        }
        Ok(())
    }

    /// Merge two records for the same key using done-ledger lattice rules.
    ///
    /// `self` is the existing record; `incoming` is the new submission.
    ///
    /// # Merge rules
    ///
    /// 1. **Status** — lattice join via [`DoneLedgerStatus::merge`]. Status never
    ///    regresses: `scanned` dominates `skipped`, which dominates `failed`.
    /// 2. **`bytes_scanned`** — non-regressing maximum of both records.
    /// 3. **`findings_count`** — status-aware:
    ///    - `ScannedClean`: forced to 0.
    ///    - `ScannedWithFindings`: `max(existing_swf, incoming_swf)`, clamped
    ///      to `>= 1`. Lower-status rows do not contribute findings once a
    ///      `ScannedWithFindings` result exists.
    ///    - Otherwise: `max(existing, incoming)`.
    /// 4. **Provenance** (`run_id`, `shard_id`, `fence_epoch`, timestamps) —
    ///    winner chosen by the lexicographically greatest
    ///    `(status rank, finished_at, started_at, fence_epoch, run_id,
    ///    shard_id, error_code)` tuple. `run_id` and `shard_id` use the same
    ///    bit-pattern `BIGINT` ordering as the PostgreSQL backend so both
    ///    implementations resolve exact ties identically.
    /// 5. **`error_code`** — cleared when merged status is scanned; otherwise
    ///    taken from the provenance winner, falling back to the loser.
    ///
    /// # Preconditions
    ///
    /// Both operands must pass [`validate()`](Self::validate). Unvalidated
    /// records (e.g., non-scanned status with `error_code = None`) break
    /// associativity because the error_code fallback mechanism can pick
    /// different losers depending on merge grouping.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceInputError::KeyMismatch`] if the two records have
    /// different keys, or any other [`PersistenceInputError`] if either operand
    /// fails [`validate()`](Self::validate) or if the merged fields violate
    /// [`DoneLedgerRecord::try_new`] construction invariants.
    pub fn merge(&self, incoming: &DoneLedgerRecord) -> Result<Self, PersistenceInputError> {
        self.validate()?;
        incoming.validate()?;

        if self.key != incoming.key {
            return Err(PersistenceInputError::KeyMismatch {
                existing: Box::new(self.key),
                incoming: Box::new(incoming.key),
            });
        }

        let merged_status = self.status.merge(incoming.status);
        let bytes_scanned = self.bytes_scanned.max(incoming.bytes_scanned);
        let findings_count = match merged_status {
            DoneLedgerStatus::ScannedClean => 0,
            DoneLedgerStatus::ScannedWithFindings => self
                .swf_findings_count()
                .max(incoming.swf_findings_count())
                .max(1),
            _ => self.findings_count.max(incoming.findings_count),
        };

        let choose_incoming = incoming.provenance_winner_key() > self.provenance_winner_key();

        let chosen = if choose_incoming { incoming } else { self };
        let fallback = if choose_incoming { self } else { incoming };

        let error_code = if merged_status.is_scanned() {
            None
        } else {
            chosen
                .error_code
                .clone()
                .or_else(|| fallback.error_code.clone())
        };

        DoneLedgerRecord::try_new(
            self.key,
            merged_status,
            bytes_scanned,
            findings_count,
            chosen.provenance,
            error_code,
        )
    }

    fn provenance_winner_key(&self) -> (u8, u64, u64, u64, i64, i64, &[u8]) {
        (
            self.status.rank(),
            self.provenance.finished_at().as_raw(),
            self.provenance.started_at().as_raw(),
            self.provenance.fence_epoch().as_raw(),
            pg_bigint_bits_sort_key(self.provenance.run_id().as_raw()),
            pg_bigint_bits_sort_key(self.provenance.shard_id().as_raw()),
            self.error_code
                .as_ref()
                .map_or(&[][..], |code| code.as_str().as_bytes()),
        )
    }

    fn swf_findings_count(&self) -> u32 {
        if self.status == DoneLedgerStatus::ScannedWithFindings {
            self.findings_count
        } else {
            0
        }
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
/// 5. **Submission is not durability.** Returning `Ok(handle)` means the
///    backend accepted the batch; durability is established only when
///    [`CommitHandle::wait`] yields a [`DoneLedgerCommitReceipt`].
pub trait DoneLedger: Send + Sync {
    /// Backend-specific immediate submit or wait error type.
    type Error: Error + Send + Sync + 'static;
    /// Handle returned for eventual durable acknowledgement of submitted rows.
    type CommitHandle: CommitHandle<Receipt = DoneLedgerCommitReceipt, Error = Self::Error>;

    /// Look up done-ledger rows for a batch of object-versions within one
    /// tenant and policy.
    ///
    /// This is a WARM-tier operation (per-batch, not per-item). Callers
    /// SHOULD keep `ovid_hashes` at or below
    /// [`RECOMMENDED_MAX_BATCH_SIZE`](super::RECOMMENDED_MAX_BATCH_SIZE);
    /// backends may impose implementation-specific limits.
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

    /// Submit a batch of done-ledger records for durable upsert, applying
    /// monotonic merge semantics for any keys that already exist.
    ///
    /// Callers SHOULD keep `records` at or below
    /// [`RECOMMENDED_MAX_BATCH_SIZE`](super::RECOMMENDED_MAX_BATCH_SIZE).
    ///
    /// If the batch contains duplicate keys, the implementation must
    /// merge them (not produce duplicate rows). The final persisted status
    /// for each key must be the lattice join of all incoming and existing
    /// values.
    ///
    /// `Ok(handle)` means the backend accepted responsibility for the batch.
    /// The caller must wait on the returned handle before treating the write as
    /// durable.
    fn batch_upsert(&self, records: &[DoneLedgerRecord])
    -> Result<Self::CommitHandle, Self::Error>;
}

#[cfg(test)]
#[path = "done_ledger_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "lattice_property_tests.rs"]
mod lattice_property_tests;
