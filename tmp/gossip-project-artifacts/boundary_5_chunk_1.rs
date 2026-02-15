//! Boundary â‘¤ â€” Persistence Contract: Chunk 1 (DRAFT)
//!
//! Done-Ledger types and trait: the contract that answers "has this item
//! been scanned under this policy, and what was the outcome?"
//!
//! This file is additive to Boundaries â‘ â€“â‘£ (all chunks). It uses
//! `CanonicalBytes`, `define_id_32!`, `domain_hasher`, `finalize_32`,
//! `TenantId`, `PolicyHash`, `ConnectorTag`, `StableItemId`,
//! `ObjectVersionId`, `VersionId`, `FenceEpoch`, and `ShardId`
//! from prior boundaries.
//!
//! ## Problem Statement
//!
//! The scanner instructions Â§3.1 require **effectively exactly-once**
//! processing: at-least-once delivery + idempotent processing. The
//! done-ledger is the persistence-side component that enables skip-scan
//! decisions: "Has this specific versioned object already been scanned
//! under this exact policy?"
//!
//! Without a done-ledger, every scan cycle would rescan every item in
//! every shard â€” O(total_items) work per cycle instead of
//! O(changed_items). For large-scale deployments (millions of items,
//! hundreds of connectors), the done-ledger is the difference between
//! feasible and infeasible cycle times.
//!
//! The done-ledger key must capture exactly the dimensions that determine
//! "do we need to rescan this?":
//!
//! 1. **Tenant isolation** â€” tenant A's scan results don't affect tenant B.
//! 2. **Policy identity** â€” if detection rules change, affected items
//!    must be rescanned.
//! 3. **Object-version identity (OVID)** â€” which specific versioned
//!    object from which connector instance was scanned. This is the
//!    most nuanced component, because:
//!    - The same logical item from different connector instances (e.g.,
//!      two GitHub installations scanning the same repo) must be tracked
//!      independently.
//!    - Different sub-resources of the same item (e.g., file content vs.
//!      commit message) must be tracked independently.
//!    - Version identity determines whether content has changed.
//!
//! ## Design Decisions (locked)
//!
//! D5.1: OVID hash is a single 32-byte content-addressed digest of
//!       `(connector_kind, connector_instance_id, stable_item_id,
//!        version_id, subresource_kind)`.
//!
//!       **Why a hash rather than a composite key?**
//!       The done-ledger key in the persistence layer is
//!       `(tenant_id, policy_hash, ovid_hash)`. Hashing the OVID
//!       components into a fixed-width 32-byte digest:
//!       - Keeps the storage key fixed-width (32 + 32 + 32 = 96 bytes)
//!         regardless of how many OVID components there are.
//!       - Avoids exposing internal structure to the persistence layer.
//!       - Enables efficient batch lookups via fixed-width key comparison.
//!       - Matches the content-addressed pattern used throughout B1.
//!
//!       The tradeoff: OVID hash is not reversible. If you need to know
//!       which item a done-ledger entry refers to, you need the original
//!       OVID inputs (stored in the finding records or reconstructable
//!       from enumeration). This is acceptable because done-ledger
//!       lookups are always keyed by OVID inputs from the current
//!       enumeration â€” you already have the components.
//!
//!       Reference: Git's content-addressed object model; IPFS CID
//!       specification; FoundationDB Record Layer subspace encoding
//!       (Chrysafis et al., 2019).
//!
//! D5.2: `ConnectorInstanceId` is a 32-byte content-addressed identity,
//!       NOT an opaque blob.
//!
//!       **Why**: A connector "instance" represents a specific configured
//!       connection to a source system (e.g., GitHub App installation
//!       #12345 for org "acme"). The same source system may have multiple
//!       installations with overlapping repositories. The done-ledger
//!       must track each independently to avoid "I already scanned repo X
//!       via installation A, so skip it when installation B encounters it."
//!
//!       The connector computes this identity from its configuration
//!       (installation ID, org, endpoint URL, etc.). The contracts crate
//!       defines the type but not the derivation â€” connector config is
//!       connector-internal.
//!
//!       Reference: FoundationDB Record Layer tenant isolation
//!       (Chrysafis et al., 2019) â€” tenant ID appears in every key prefix.
//!
//! D5.3: `SubresourceKind` is a u8 discriminant with a human-readable
//!       Debug representation.
//!
//!       **Why**: A single scan item may have multiple independently
//!       scannable sub-resources. For example, a Git commit has a
//!       commit message AND file diffs â€” both need scanning, but they
//!       have different done-ledger entries because:
//!       - The commit message may change (force push) while files don't.
//!       - Findings in commit messages vs. file content need different
//!         triage workflows.
//!       - Subresource-level tracking enables partial rescans.
//!
//!       `u8` is sufficient (256 kinds) and keeps the canonical encoding
//!       compact. New kinds are added as new discriminant values â€”
//!       existing values MUST NOT be reused.
//!
//! D5.4: Done-ledger status has **monotonic (absorbing) semantics**:
//!       once an entry reaches `Scanned`, it cannot be overwritten by
//!       `Failed`.
//!
//!       **Why**: Workers operate with at-least-once delivery. A worker
//!       may crash after writing findings but before updating the
//!       done-ledger. On retry, a different worker rescans the same item
//!       and succeeds. If the original worker's failure status were to
//!       arrive later (delayed network, slow persistence), it must NOT
//!       overwrite the success.
//!
//!       The ordering is: `Scanned` > `Failed` > `NotSeen`. This is a
//!       join-semilattice where `Scanned` is the absorbing element.
//!
//!       Reference: CRDTs and monotonic join-semilattices â€” Shapiro et
//!       al., "A comprehensive study of Convergent and Commutative
//!       Replicated Data Types" (INRIA, 2011). Specifically, this is
//!       an "observed-remove" pattern: once success is observed, failure
//!       is superseded. Also: Kafka's exactly-once semantics use the
//!       same "highest status wins" approach for transaction markers.
//!
//! D5.5: `batch_get` and `batch_upsert` are the ONLY done-ledger
//!       operations. No single-key operations, no range scans, no
//!       deletes.
//!
//!       **Why**: Batch operations amortize round-trip latency to the
//!       persistence layer. A shard processes items in pages (B4
//!       enumeration), and the runtime checks/updates done-ledger
//!       entries in batch after each page.
//!
//!       No deletes: done-ledger entries are immutable once written
//!       (within a policy generation). A new policy hash creates a new
//!       logical namespace â€” old entries are irrelevant but harmless.
//!       Cleanup is a background compaction concern, not a contract
//!       operation.
//!
//!       No range scans: the done-ledger is a point-lookup store.
//!       Enumeration provides the keys; the done-ledger provides the
//!       statuses. There is no use case for "give me all items scanned
//!       under policy X" in the hot path.
//!
//!       Reference: TigerBeetle's batched API design â€” operations are
//!       always in batches, never single-item, to amortize kernel
//!       boundary crossing and network round-trips.
//!
//! D5.6: Done-ledger operations are **fence-gated**: every mutation
//!       carries a `FenceEpoch` for the shard. The persistence layer
//!       MUST reject writes with an epoch â‰¤ the last accepted epoch
//!       for that shard.
//!
//!       **Why**: A zombie worker (one whose lease has expired but
//!       hasn't realized it) may attempt to write stale done-ledger
//!       entries. The fencing token protocol (B1 `FenceEpoch`, per
//!       Kleppmann 2016) prevents these stale writes from corrupting
//!       the ledger.
//!
//!       Reference: Kleppmann, "How to do distributed locking" (2016);
//!       Gray & Cheriton, "Leases" (SOSP 1989); Hochstein, "Locks,
//!       Leases, Fencing Tokens, FizzBee!" (2025).
//!
//! D5.7: `DoneLedgerEntry` carries metadata beyond bare status:
//!       `scanned_at` timestamp (logical time) and `run_id` for
//!       provenance. These are informational â€” the skip-scan decision
//!       depends only on `status`, but provenance is critical for
//!       debugging and auditing.
//!
//!       **Why `scanned_at` is logical, not wall-clock**: Per scanner
//!       instructions Â§9.2 and Â§9.5, correctness logic must be
//!       clock-independent. The `scanned_at` field uses `LogicalTime`
//!       (B1) for ordering, not `SystemTime`. Wall-clock timestamps
//!       are added by the runtime for human observability but do not
//!       participate in contract decisions.

// Assumes all types from Boundaries â‘ â€“â‘£ are in scope:
// use crate::{
//     CanonicalBytes, Hasher, define_id_32,
//     domain_hasher, finalize_32,
//     TenantId, PolicyHash, ConnectorTag, StableItemId,
//     ObjectVersionId, VersionId, FenceEpoch, ShardId,
//     RunId, LogicalTime,
// };

use core::fmt;
use blake3::Hasher;

// ============================================================================
// Â§ Chunk 1: Done-Ledger Contract
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.1 Domain Separation Constants for Boundary â‘¤
// ---------------------------------------------------------------------------

/// Domain tags for Boundary â‘¤ hash derivations.
///
/// Follow the convention from B1: "gossip/<subsystem>/v<N>/<operation>".
pub mod domain_b5 {
    /// OVID hash derivation â€” Object-Version Identity.
    pub const OVID_V1: &[u8] = b"gossip/persistence/v1/ovid";

    /// Done-ledger key derivation (reserved for future use if we ever
    /// need to hash the full key rather than concatenating components).
    pub const DONE_LEDGER_KEY_V1: &[u8] = b"gossip/persistence/v1/done-key";
}

// ---------------------------------------------------------------------------
// Â§5.2 ConnectorInstanceId â€” specific connector installation identity
// ---------------------------------------------------------------------------

define_id_32! {
    /// Identity of a specific connector installation/configuration.
    ///
    /// A connector "instance" represents a configured connection to a
    /// source system. Examples:
    ///
    /// - GitHub App installation #12345 for organization "acme"
    /// - S3 connector configured for bucket "prod-secrets" in us-east-1
    /// - GitLab instance at `https://gitlab.internal.corp`
    ///
    /// ## Why This Exists
    ///
    /// Two connector instances may enumerate overlapping items. For
    /// example, two GitHub installations may both have access to
    /// `org/shared-repo`. The done-ledger must track them independently:
    ///
    /// - Installation A scans `org/shared-repo/config.yml` â†’ done.
    /// - Installation B enumerates the same file â†’ must NOT skip it
    ///   based on A's done-ledger entry, because B may have different
    ///   access permissions, credential scopes, or version visibility.
    ///
    /// ## Construction
    ///
    /// The connector computes this from its configuration. Example:
    /// ```text
    /// ConnectorInstanceId = blake3("gossip/connector-instance/v1",
    ///     connector_tag || installation_id || org_name || endpoint_url)
    /// ```
    ///
    /// The contracts crate defines the type but NOT the derivation â€”
    /// connector configuration structure is connector-internal.
    ///
    /// ## Invariants
    ///
    /// **Safety (uniqueness)**: Two distinct connector configurations
    /// MUST produce distinct `ConnectorInstanceId` values.
    ///
    /// **Safety (stability)**: The same connector configuration MUST
    /// produce the same `ConnectorInstanceId` across restarts and
    /// across versions of the connector code (unless the configuration
    /// meaningfully changed).
    ///
    /// ## Verification Strategy
    ///
    /// Property-based test: same config â†’ same ID (determinism).
    /// Negative test: different installation IDs â†’ different IDs.
    ConnectorInstanceId
}

// ---------------------------------------------------------------------------
// Â§5.3 SubresourceKind â€” scannable sub-part discriminator
// ---------------------------------------------------------------------------

/// Discriminates independently scannable sub-parts of a single item.
///
/// A single enumerated item (identified by `StableItemId`) may have
/// multiple scannable sub-resources. Each sub-resource gets its own
/// done-ledger entry because:
///
/// 1. Sub-resources may have independent version lifecycles (e.g.,
///    a commit message can change via force-push without changing
///    the file tree).
/// 2. Findings in different sub-resources need different triage
///    workflows (a secret in a commit message vs. in a file).
/// 3. Partial rescan: if only one sub-resource changed, only that
///    sub-resource needs rescanning.
///
/// ## Encoding
///
/// Stored as `u8` for compact canonical encoding. New kinds are added
/// with new discriminant values. Existing values MUST NOT be reused.
///
/// ## Common Kinds
///
/// The contracts crate defines a small set of well-known kinds.
/// Connectors MAY define additional kinds in the 128â€“255 range
/// (connector-specific extension range).
///
/// ## Invariants
///
/// **Safety (discrimination)**: Two different sub-resources of the
/// same item MUST use different `SubresourceKind` values. The
/// combination `(StableItemId, SubresourceKind)` uniquely identifies
/// a scannable unit.
///
/// **Safety (stability)**: A sub-resource kind value MUST NOT change
/// meaning across versions. Value 0 is always "primary content."
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SubresourceKind {
    /// Primary file/blob content. The default for most items.
    /// This is the "obvious" scannable content of the item.
    PrimaryContent = 0,

    /// Commit message text (Git, SVN, etc.).
    CommitMessage = 1,

    /// Pull/merge request description body.
    PrDescription = 2,

    /// Pull/merge request comment body.
    PrComment = 3,

    /// Issue body text.
    IssueBody = 4,

    /// Wiki or documentation page content.
    WikiContent = 5,

    /// CI/CD pipeline configuration.
    PipelineConfig = 6,

    /// Repository/project-level configuration or metadata.
    RepoMetadata = 7,
}

/// Sentinel: start of connector-specific extension range.
///
/// Connector-defined sub-resource kinds MUST use values â‰¥ 128.
/// The 0â€“127 range is reserved for well-known kinds defined in
/// this crate.
pub const SUBRESOURCE_EXTENSION_RANGE_START: u8 = 128;

impl SubresourceKind {
    /// Convert from raw `u8`, returning `None` for unknown values.
    ///
    /// This handles forward compatibility: if a newer version of the
    /// contracts defines additional kinds, older code returns `None`
    /// for unrecognized values.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::PrimaryContent),
            1 => Some(Self::CommitMessage),
            2 => Some(Self::PrDescription),
            3 => Some(Self::PrComment),
            4 => Some(Self::IssueBody),
            5 => Some(Self::WikiContent),
            6 => Some(Self::PipelineConfig),
            7 => Some(Self::RepoMetadata),
            _ => None,
        }
    }

    /// Raw discriminant value for canonical encoding and storage.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for SubresourceKind {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&[self.as_u8()]);
    }
}

/// Wrapper for sub-resource kinds that may be in the extension range.
///
/// Use this when working with connector-defined sub-resource kinds
/// that aren't part of the well-known enum. The done-ledger stores
/// the raw `u8` and doesn't need to interpret the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubresourceKindRaw(pub u8);

impl SubresourceKindRaw {
    /// Construct from a well-known `SubresourceKind`.
    #[inline]
    pub const fn from_known(kind: SubresourceKind) -> Self {
        Self(kind as u8)
    }

    /// Construct a connector-specific extension kind.
    ///
    /// # Panics
    ///
    /// Panics if `value` is in the reserved range (< 128).
    pub const fn extension(value: u8) -> Self {
        assert!(
            value >= SUBRESOURCE_EXTENSION_RANGE_START,
            "extension sub-resource kinds must be >= 128"
        );
        Self(value)
    }

    /// Try to interpret as a well-known kind.
    #[inline]
    pub fn as_known(self) -> Option<SubresourceKind> {
        SubresourceKind::from_u8(self.0)
    }

    /// Raw value for canonical encoding.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Is this a connector-specific extension kind?
    #[inline]
    pub const fn is_extension(self) -> bool {
        self.0 >= SUBRESOURCE_EXTENSION_RANGE_START
    }
}

impl CanonicalBytes for SubresourceKindRaw {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&[self.0]);
    }
}

impl From<SubresourceKind> for SubresourceKindRaw {
    #[inline]
    fn from(kind: SubresourceKind) -> Self {
        Self::from_known(kind)
    }
}

// ---------------------------------------------------------------------------
// Â§5.4 OvidInputs & OvidHash â€” Object-Version Identity
// ---------------------------------------------------------------------------

/// Inputs to OVID (Object-Version Identity) hash derivation.
///
/// OVID captures "which specific versioned object, from which connector
/// instance, in which sub-resource form, was scanned."
///
/// ## Why Each Field
///
/// - `connector_kind` (`ConnectorTag`): Prevents cross-connector
///   collisions. A GitHub file and a GitLab file at the same path
///   are different OVIDs.
///
/// - `connector_instance` (`ConnectorInstanceId`): Prevents
///   cross-installation collisions. Two GitHub installations
///   scanning the same repo produce different OVIDs.
///
/// - `stable_item_id` (`StableItemId`): The item's content-addressed
///   identity. Same item across versions = same `StableItemId`.
///
/// - `version_id` (`ObjectVersionId`): The specific version scanned.
///   Same item at different versions = different OVIDs. Note: we use
///   the raw `ObjectVersionId` here, NOT `VersionId` (which includes
///   strength). Strength is a skip-scan policy concern, not an
///   identity concern â€” the OVID must be the same regardless of
///   whether the version was classified as strong or weak.
///
/// - `subresource_kind` (`SubresourceKindRaw`): Distinguishes
///   independently scannable sub-parts. Same item, same version,
///   different sub-resource = different OVIDs.
///
/// ## Field Widths
///
/// - `ConnectorTag`: 8 bytes (fixed)
/// - `ConnectorInstanceId`: 32 bytes (fixed)
/// - `StableItemId`: 32 bytes (fixed)
/// - `ObjectVersionId`: 32 bytes (fixed)
/// - `SubresourceKindRaw`: 1 byte (fixed)
///
/// Total: 105 bytes, all fixed-width. No length prefixes needed.
///
/// ## Invariants
///
/// **Safety (collision-freedom)**: Distinct OVID input tuples MUST
/// produce distinct `OvidHash` values (cryptographic collision
/// resistance, 2^128 security level via BLAKE3).
///
/// **Safety (determinism)**: Same inputs â†’ same hash, always.
///
/// **Safety (completeness)**: ALL dimensions that affect "should we
/// rescan?" MUST be included. Missing a dimension means the
/// done-ledger will falsely report "already scanned" when it shouldn't.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OvidInputs {
    pub connector_kind: ConnectorTag,
    pub connector_instance: ConnectorInstanceId,
    pub stable_item_id: StableItemId,
    pub version_id: ObjectVersionId,
    pub subresource_kind: SubresourceKindRaw,
}

impl CanonicalBytes for OvidInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        // Fixed-width fields in declaration order.
        // ConnectorTag: 8 bytes
        self.connector_kind.write_canonical(h);
        // ConnectorInstanceId: 32 bytes
        self.connector_instance.write_canonical(h);
        // StableItemId: 32 bytes
        self.stable_item_id.write_canonical(h);
        // ObjectVersionId: 32 bytes
        self.version_id.write_canonical(h);
        // SubresourceKindRaw: 1 byte
        self.subresource_kind.write_canonical(h);
    }
}

define_id_32! {
    /// Content-addressed Object-Version Identity digest.
    ///
    /// Derived as:
    /// ```text
    /// OvidHash = blake3("gossip/persistence/v1/ovid",
    ///     connector_kind || connector_instance || stable_item_id
    ///     || version_id || subresource_kind)
    /// ```
    ///
    /// This is one of the three components of the done-ledger key:
    /// `(TenantId, PolicyHash, OvidHash)`.
    ///
    /// ## Invariants
    ///
    /// **Safety (determinism)**: Pure function of `OvidInputs`.
    ///
    /// **Safety (collision-freedom)**: Cryptographic collision resistance.
    OvidHash
}

/// Derive an `OvidHash` from its inputs.
///
/// Pure function: same inputs â†’ same output, always.
pub fn derive_ovid_hash(inputs: &OvidInputs) -> OvidHash {
    let mut h = domain_hasher(domain_b5::OVID_V1);
    inputs.write_canonical(&mut h);
    OvidHash::from_bytes(finalize_32(&h))
}

// ---------------------------------------------------------------------------
// Â§5.5 DoneLedgerKey â€” the composite lookup key
// ---------------------------------------------------------------------------

/// Composite key for done-ledger lookups.
///
/// Structure: `(tenant_id, policy_hash, ovid_hash)`.
///
/// Each component serves a distinct isolation/identity purpose:
///
/// - **`tenant_id`** (`TenantId`, 32 bytes): Tenant isolation. Tenant A's
///   scan of an item does not satisfy tenant B's requirement to scan it.
///
/// - **`policy_hash`** (`PolicyHash`, 32 bytes): Policy generation. If
///   detection rules change, the policy hash changes, and all items
///   become "not yet scanned under this policy." This is the mechanism
///   for forced rescan on rule updates.
///
/// - **`ovid_hash`** (`OvidHash`, 32 bytes): Object-version identity.
///   Identifies the specific versioned object that was scanned.
///
/// ## Total Key Width
///
/// 32 + 32 + 32 = **96 bytes**, fixed-width. This is compact enough for
/// batch lookups and B-tree storage, while providing full isolation.
///
/// ## Storage Considerations
///
/// The persistence layer may choose to store these as a concatenated
/// 96-byte key, or as separate columns with a composite index. The
/// contract is agnostic to the storage layout â€” it only defines the
/// logical key structure.
///
/// ## Invariants
///
/// **Safety (uniqueness)**: The triple `(tenant, policy, ovid)` uniquely
/// identifies a done-ledger entry. No two entries may share the same key.
///
/// **Safety (tenant isolation)**: Operations on the done-ledger MUST
/// be scoped to a single tenant. Cross-tenant batch operations are
/// a correctness violation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DoneLedgerKey {
    pub tenant: TenantId,
    pub policy: PolicyHash,
    pub ovid: OvidHash,
}

impl DoneLedgerKey {
    /// Construct a done-ledger key.
    #[inline]
    pub fn new(tenant: TenantId, policy: PolicyHash, ovid: OvidHash) -> Self {
        Self { tenant, policy, ovid }
    }

    /// Construct from pre-hashed OVID inputs.
    ///
    /// Convenience: derives the `OvidHash` from inputs, then builds key.
    pub fn from_ovid_inputs(
        tenant: TenantId,
        policy: PolicyHash,
        ovid_inputs: &OvidInputs,
    ) -> Self {
        Self {
            tenant,
            policy,
            ovid: derive_ovid_hash(ovid_inputs),
        }
    }

    /// Returns the 96-byte concatenated key for storage.
    ///
    /// Layout: `[tenant: 32][policy: 32][ovid: 32]`.
    ///
    /// This is a convenience for persistence implementations that
    /// use a flat byte key. The ordering (tenant first) ensures that
    /// tenant-scoped range scans are efficient in ordered stores.
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        buf[0..32].copy_from_slice(self.tenant.as_bytes());
        buf[32..64].copy_from_slice(self.policy.as_bytes());
        buf[64..96].copy_from_slice(self.ovid.as_bytes());
        buf
    }

    /// Parse from a 96-byte concatenated key.
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len() != 96`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 96, "DoneLedgerKey requires exactly 96 bytes");

        let mut tenant_bytes = [0u8; 32];
        let mut policy_bytes = [0u8; 32];
        let mut ovid_bytes = [0u8; 32];

        tenant_bytes.copy_from_slice(&bytes[0..32]);
        policy_bytes.copy_from_slice(&bytes[32..64]);
        ovid_bytes.copy_from_slice(&bytes[64..96]);

        Self {
            tenant: TenantId::from_bytes(tenant_bytes),
            policy: PolicyHash::from_bytes(policy_bytes),
            ovid: OvidHash::from_bytes(ovid_bytes),
        }
    }
}

impl CanonicalBytes for DoneLedgerKey {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.tenant.write_canonical(h);
        self.policy.write_canonical(h);
        self.ovid.write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§5.6 DoneLedgerStatus â€” scan outcome with monotonic semantics
// ---------------------------------------------------------------------------

/// Outcome of scanning a versioned object under a given policy.
///
/// ## Monotonic (Absorbing) Semantics
///
/// Status values form a **join-semilattice** where `Scanned` is the
/// top (absorbing) element:
///
/// ```text
///          Scanned          â† absorbing: once reached, never overwritten
///            â†‘
///          Failed
///            â†‘
///         NotSeen           â† implicit bottom (no entry in store)
/// ```
///
/// The `merge` operation (used by `batch_upsert`) follows:
///
/// | Existing | Incoming | Result   | Why                              |
/// |----------|----------|----------|----------------------------------|
/// | NotSeen  | Scanned  | Scanned  | First successful scan.           |
/// | NotSeen  | Failed   | Failed   | First attempt failed.            |
/// | Failed   | Scanned  | Scanned  | Retry succeeded â†’ promote.       |
/// | Failed   | Failed   | Failed   | Still failing (update metadata).  |
/// | Scanned  | Failed   | Scanned  | **Key rule**: success is sticky.  |
/// | Scanned  | Scanned  | Scanned  | Idempotent re-scan.              |
///
/// The critical row is `(Scanned, Failed) â†’ Scanned`. Without this
/// rule, a delayed failure from a zombie worker could regress a
/// successful scan, causing the item to be rescanned unnecessarily
/// or â€” worse â€” causing findings to be re-reported.
///
/// ## Verification Strategy
///
/// Property-based test: for any sequence of merge operations,
/// if `Scanned` appears at any point, the final status is `Scanned`.
///
/// Property-based test: `merge` is commutative, associative, and
/// idempotent (CRDT lattice properties).
///
/// Reference: Shapiro et al., "A comprehensive study of Convergent
/// and Commutative Replicated Data Types" (INRIA, 2011).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DoneLedgerStatus {
    /// Item has been scanned successfully under this policy.
    /// This is the absorbing state â€” once set, it cannot be overwritten.
    Scanned = 2,

    /// Item scan was attempted but failed (transient error, timeout, etc.).
    /// May be overwritten by `Scanned` on successful retry.
    Failed = 1,
}

impl DoneLedgerStatus {
    /// Merge two statuses following monotonic (absorbing) semantics.
    ///
    /// Returns the "higher" status in the lattice ordering.
    /// `Scanned` always wins.
    ///
    /// This is the join operation of the semilattice:
    /// `merge(a, b) == merge(b, a)` (commutative)
    /// `merge(a, merge(b, c)) == merge(merge(a, b), c)` (associative)
    /// `merge(a, a) == a` (idempotent)
    #[inline]
    pub fn merge(self, other: Self) -> Self {
        // Scanned (2) > Failed (1). Use max on discriminant.
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }

    /// Returns `true` if this status supersedes `other`.
    ///
    /// A status supersedes another if merging them would produce `self`.
    #[inline]
    pub fn supersedes(self, other: Self) -> bool {
        (self as u8) >= (other as u8)
    }

    /// Returns `true` if the item was successfully scanned.
    #[inline]
    pub fn is_scanned(self) -> bool {
        matches!(self, Self::Scanned)
    }

    /// Returns `true` if the item scan failed.
    #[inline]
    pub fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Convert from raw `u8`, returning `None` for unknown values.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            2 => Some(Self::Scanned),
            1 => Some(Self::Failed),
            _ => None,
        }
    }

    /// Raw discriminant for storage encoding.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for DoneLedgerStatus {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&[self.as_u8()]);
    }
}

impl fmt::Display for DoneLedgerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scanned => write!(f, "Scanned"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Â§5.7 DoneLedgerEntry â€” the value stored per key
// ---------------------------------------------------------------------------

/// A single done-ledger record: status + provenance metadata.
///
/// The `status` field is the only field that participates in skip-scan
/// decisions. The remaining fields are provenance metadata for debugging,
/// auditing, and observability.
///
/// ## Provenance Fields
///
/// - `scanned_at`: Logical timestamp when the scan completed. Used for
///   "when was this last scanned?" queries in dashboards, NOT for
///   correctness decisions. Uses `LogicalTime` (B1) per Â§9.5 of the
///   scanner instructions.
///
/// - `run_id`: The `RunId` of the run that produced this entry. Enables
///   "which run scanned this item?" auditing.
///
/// - `shard_id`: The `ShardId` of the shard that processed this item.
///   Enables "which shard handled this?" debugging.
///
/// ## Invariants
///
/// **Safety (monotonicity)**: When upserting, the `status` MUST follow
/// absorbing semantics (Â§5.6). The implementation MUST call
/// `DoneLedgerStatus::merge(existing, incoming)`.
///
/// **Safety (provenance consistency)**: If status is `Scanned`, the
/// provenance fields SHOULD reflect the successful scan (not an earlier
/// failed attempt). The implementation achieves this by only updating
/// provenance when the status actually changes (i.e., the merge
/// produces a different result).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoneLedgerEntry {
    /// Scan outcome. The only field used for skip-scan decisions.
    pub status: DoneLedgerStatus,

    /// Logical time when this status was recorded.
    pub scanned_at: LogicalTime,

    /// The run that produced this entry.
    pub run_id: RunId,

    /// The shard that processed the item.
    pub shard_id: ShardId,
}

impl DoneLedgerEntry {
    /// Create a "scanned successfully" entry.
    pub fn scanned(
        scanned_at: LogicalTime,
        run_id: RunId,
        shard_id: ShardId,
    ) -> Self {
        Self {
            status: DoneLedgerStatus::Scanned,
            scanned_at,
            run_id,
            shard_id,
        }
    }

    /// Create a "scan failed" entry.
    pub fn failed(
        scanned_at: LogicalTime,
        run_id: RunId,
        shard_id: ShardId,
    ) -> Self {
        Self {
            status: DoneLedgerStatus::Failed,
            scanned_at,
            run_id,
            shard_id,
        }
    }

    /// Merge this entry with an incoming entry following monotonic
    /// semantics.
    ///
    /// If the incoming status supersedes ours, adopt the incoming
    /// entry wholesale (including provenance). If not, keep ours.
    ///
    /// ## Why wholesale replacement
    ///
    /// When a higher status arrives, it represents a "more advanced"
    /// scan outcome. Its provenance (run, shard, timestamp) is the
    /// correct provenance for that outcome. Cherry-picking fields
    /// would create an entry where the status says "Scanned" but
    /// the provenance says "this was the failed attempt's run" â€” a
    /// confusing audit trail.
    pub fn merge_with(&self, incoming: &Self) -> Self {
        let merged_status = self.status.merge(incoming.status);
        if merged_status == incoming.status && incoming.status != self.status {
            // Incoming caused a status upgrade â†’ adopt incoming wholesale.
            incoming.clone()
        } else {
            // No upgrade â†’ keep existing (preserves original provenance).
            self.clone()
        }
    }

    /// Returns `true` if this entry indicates successful scan.
    #[inline]
    pub fn is_scanned(&self) -> bool {
        self.status.is_scanned()
    }

    /// Returns `true` if this entry indicates a failed scan.
    #[inline]
    pub fn is_failed(&self) -> bool {
        self.status.is_failed()
    }
}

// ---------------------------------------------------------------------------
// Â§5.8 DoneLedgerLookup â€” batch_get response enum
// ---------------------------------------------------------------------------

/// Result of looking up a single done-ledger key.
///
/// `NotSeen` is the implicit bottom of the lattice â€” it means no
/// entry exists for this key, i.e., the item has never been scanned
/// under this policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoneLedgerLookup {
    /// No entry exists for this key. The item has not been scanned
    /// under this policy.
    NotSeen,

    /// An entry exists with this status and metadata.
    Found(DoneLedgerEntry),
}

impl DoneLedgerLookup {
    /// Returns `true` if the item should be scanned.
    ///
    /// An item needs scanning if:
    /// - It has never been seen (`NotSeen`), OR
    /// - Its previous scan failed (`Found(Failed)`)
    ///
    /// An item can be skipped if:
    /// - It was successfully scanned (`Found(Scanned)`)
    ///
    /// ## Note on Version Strength
    ///
    /// This method does NOT consider version strength (strong vs. weak).
    /// Version-aware skip logic is a higher-level concern owned by the
    /// runtime. The done-ledger reports raw status; the runtime combines
    /// it with `VersionId::is_strong()` to make the final skip decision.
    ///
    /// For weak versions, the runtime may choose to rescan even if the
    /// done-ledger says `Scanned`, because the version token may not be
    /// trustworthy (see D4.1 in B4 chunk 1).
    #[inline]
    pub fn needs_scan(&self) -> bool {
        match self {
            Self::NotSeen => true,
            Self::Found(entry) => entry.is_failed(),
        }
    }

    /// Returns `true` if the item was successfully scanned.
    #[inline]
    pub fn is_scanned(&self) -> bool {
        matches!(self, Self::Found(e) if e.is_scanned())
    }
}

// ---------------------------------------------------------------------------
// Â§5.9 Batch operation types
// ---------------------------------------------------------------------------

/// A batch of done-ledger keys to look up.
///
/// The runtime constructs this from enumeration page results: for each
/// item in the page, compute its `DoneLedgerKey` and add it to the batch.
///
/// ## Size Bounds
///
/// The batch size is bounded by the enumeration page size (`max_items`
/// in `EnumerationBudget`, B4 chunk 1). The runtime MUST NOT construct
/// unbounded batches.
///
/// Reference: Scanner instructions Â§9.4 â€” "Do not use unbounded queues."
#[derive(Clone, Debug)]
pub struct DoneLedgerGetBatch {
    keys: Vec<DoneLedgerKey>,
}

impl DoneLedgerGetBatch {
    /// Construct with a pre-allocated capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is 0.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "batch capacity must be > 0");
        Self {
            keys: Vec::with_capacity(capacity),
        }
    }

    /// Add a key to the batch.
    ///
    /// # Panics
    ///
    /// Panics if the batch exceeds its capacity. This is a programming
    /// error â€” the caller should have allocated sufficient capacity.
    pub fn push(&mut self, key: DoneLedgerKey) {
        assert!(
            self.keys.len() < self.keys.capacity(),
            "DoneLedgerGetBatch exceeded capacity: {} >= {}",
            self.keys.len(),
            self.keys.capacity(),
        );
        self.keys.push(key);
    }

    /// Number of keys in the batch.
    #[inline]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Is the batch empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterate over keys.
    #[inline]
    pub fn keys(&self) -> &[DoneLedgerKey] {
        &self.keys
    }
}

/// Result of a batch get operation.
///
/// Results are returned in the same order as the input keys.
/// `results.len() == batch.len()` is a hard invariant.
#[derive(Clone, Debug)]
pub struct DoneLedgerGetResult {
    results: Vec<DoneLedgerLookup>,
}

impl DoneLedgerGetResult {
    /// Construct from a vec of lookup results.
    ///
    /// # Panics
    ///
    /// Panics if `results` is empty.
    pub fn new(results: Vec<DoneLedgerLookup>) -> Self {
        assert!(!results.is_empty(), "DoneLedgerGetResult must not be empty");
        Self { results }
    }

    /// Get the lookup result at index `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i >= len()`.
    #[inline]
    pub fn get(&self, i: usize) -> &DoneLedgerLookup {
        &self.results[i]
    }

    /// Number of results.
    #[inline]
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Iterate over results.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &DoneLedgerLookup> {
        self.results.iter()
    }

    /// Iterate over (index, result) pairs.
    #[inline]
    pub fn enumerate(&self) -> impl Iterator<Item = (usize, &DoneLedgerLookup)> {
        self.results.iter().enumerate()
    }

    /// Count how many items need scanning.
    pub fn count_needs_scan(&self) -> usize {
        self.results.iter().filter(|r| r.needs_scan()).count()
    }

    /// Count how many items can be skipped.
    pub fn count_skippable(&self) -> usize {
        self.results.iter().filter(|r| r.is_scanned()).count()
    }
}

/// A single entry to upsert into the done-ledger.
#[derive(Clone, Debug)]
pub struct DoneLedgerUpsertItem {
    pub key: DoneLedgerKey,
    pub entry: DoneLedgerEntry,
}

impl DoneLedgerUpsertItem {
    #[inline]
    pub fn new(key: DoneLedgerKey, entry: DoneLedgerEntry) -> Self {
        Self { key, entry }
    }
}

/// A batch of done-ledger entries to upsert.
///
/// The persistence layer applies monotonic merge semantics for each
/// entry: `new_status = merge(existing_status, incoming_status)`.
///
/// ## Ordering Within a Batch
///
/// If the same key appears multiple times in a batch, the persistence
/// layer MUST process them left-to-right (array order) with merging.
/// In practice, the runtime deduplicates keys before batching, so
/// duplicates within a batch indicate a programming error.
#[derive(Clone, Debug)]
pub struct DoneLedgerUpsertBatch {
    items: Vec<DoneLedgerUpsertItem>,
}

impl DoneLedgerUpsertBatch {
    /// Construct with a pre-allocated capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is 0.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "batch capacity must be > 0");
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Add an entry to the batch.
    ///
    /// # Panics
    ///
    /// Panics if the batch exceeds its capacity.
    pub fn push(&mut self, item: DoneLedgerUpsertItem) {
        assert!(
            self.items.len() < self.items.capacity(),
            "DoneLedgerUpsertBatch exceeded capacity: {} >= {}",
            self.items.len(),
            self.items.capacity(),
        );
        self.items.push(item);
    }

    /// Number of items in the batch.
    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Is the batch empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterate over items.
    #[inline]
    pub fn items(&self) -> &[DoneLedgerUpsertItem] {
        &self.items
    }
}

// ---------------------------------------------------------------------------
// Â§5.10 DoneLedger error types
// ---------------------------------------------------------------------------

/// Error type for done-ledger `batch_get` operations.
///
/// Follows B2's pattern of operation-specific error types rather
/// than mega-enums (D2.14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoneLedgerGetError {
    /// The persistence layer is temporarily unavailable.
    /// Caller should retry with backoff.
    Unavailable {
        /// Human-readable reason for observability.
        reason: Box<str>,
    },

    /// The batch size exceeds the persistence layer's limit.
    BatchTooLarge {
        requested: usize,
        max_allowed: usize,
    },

    /// An internal error in the persistence layer.
    /// This is NOT a transient failure â€” it indicates a bug or
    /// corruption that requires investigation.
    Internal {
        reason: Box<str>,
    },
}

impl fmt::Display for DoneLedgerGetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { reason } => {
                write!(f, "done-ledger unavailable: {reason}")
            }
            Self::BatchTooLarge { requested, max_allowed } => {
                write!(
                    f,
                    "batch too large: {requested} keys, max {max_allowed}"
                )
            }
            Self::Internal { reason } => {
                write!(f, "done-ledger internal error: {reason}")
            }
        }
    }
}

/// Error type for done-ledger `batch_upsert` operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoneLedgerUpsertError {
    /// The persistence layer is temporarily unavailable.
    Unavailable {
        reason: Box<str>,
    },

    /// The batch size exceeds the persistence layer's limit.
    BatchTooLarge {
        requested: usize,
        max_allowed: usize,
    },

    /// The write was rejected because the fencing epoch is stale.
    ///
    /// This means a newer worker has taken ownership of the shard.
    /// The current worker MUST stop processing and yield.
    ///
    /// Reference: Kleppmann, "How to do distributed locking" (2016).
    FenceEpochStale {
        /// The epoch the write carried.
        presented: FenceEpoch,
        /// The minimum epoch the persistence layer requires.
        required_minimum: FenceEpoch,
    },

    /// An internal error in the persistence layer.
    Internal {
        reason: Box<str>,
    },
}

impl fmt::Display for DoneLedgerUpsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { reason } => {
                write!(f, "done-ledger unavailable: {reason}")
            }
            Self::BatchTooLarge { requested, max_allowed } => {
                write!(
                    f,
                    "batch too large: {requested} items, max {max_allowed}"
                )
            }
            Self::FenceEpochStale { presented, required_minimum } => {
                write!(
                    f,
                    "fence epoch stale: presented {:?}, required >= {:?}",
                    presented, required_minimum,
                )
            }
            Self::Internal { reason } => {
                write!(f, "done-ledger internal error: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Â§5.11 DoneLedger trait â€” the persistence contract
// ---------------------------------------------------------------------------

/// Persistence contract for the done-ledger.
///
/// The done-ledger is a **point-lookup store** with **monotonic upsert**
/// semantics. It answers: "has this versioned object been scanned under
/// this policy for this tenant?"
///
/// ## Operations
///
/// Two operations only:
///
/// - `batch_get`: Look up statuses for a batch of keys. Used during
///   enumeration to decide which items to skip.
///
/// - `batch_upsert`: Write scan outcomes for a batch of items. The
///   persistence layer applies monotonic merge semantics (Â§5.6).
///
/// No single-key operations, no range scans, no deletes.
///
/// ## Fence-Gated Mutations
///
/// `batch_upsert` carries a `FenceEpoch` and `ShardId`. The persistence
/// layer MUST reject writes where the presented epoch is â‰¤ the last
/// accepted epoch for that shard. This prevents zombie workers from
/// corrupting the ledger.
///
/// Note: `batch_get` does NOT require a fence epoch â€” reads are safe
/// from any worker regardless of lease status. A zombie worker reading
/// stale data will at worst rescan items that were already scanned
/// (covered by idempotency), never skip items that need scanning
/// (because the ledger can only progress forward via monotonic writes).
///
/// ## Synchronous API
///
/// Like B2's `CoordinationBackend` and B4's connector traits, this
/// trait uses synchronous (blocking) methods. The runtime wraps calls
/// in its scheduling model (blocking threads, spawn_blocking, or
/// deterministic simulation).
///
/// ## Time Parameter
///
/// Methods accept `now: LogicalTime` for deterministic simulation
/// testing (D2.13, matching B2 pattern). Real implementations
/// may use this for logging; test implementations use it for
/// deterministic time advancement.
///
/// ## Invariants (implementor obligations)
///
/// **INV-DL-1 (monotonic status)**: `batch_upsert` MUST apply
///   `DoneLedgerStatus::merge(existing, incoming)` for each entry.
///   An incoming `Failed` MUST NOT overwrite an existing `Scanned`.
///
/// **INV-DL-2 (fence rejection)**: `batch_upsert` MUST reject the
///   entire batch if `fence_epoch <= last_accepted_epoch[shard_id]`.
///   Partial application of a fenced batch is a correctness violation.
///
/// **INV-DL-3 (batch atomicity)**: All entries in a `batch_upsert`
///   are applied atomically. Either all succeed or none are persisted.
///   This ensures that the "findings flushed before done-ledger
///   updated" ordering (Â§5, ordering requirement) isn't partially
///   violated.
///
/// **INV-DL-4 (result cardinality)**: `batch_get` MUST return exactly
///   one `DoneLedgerLookup` per input key, in the same order.
///   `result.len() == batch.len()`.
///
/// **INV-DL-5 (durability before ack)**: `batch_upsert` MUST NOT
///   return `Ok(())` until the entries are durable (fsync'd or
///   equivalent). A crash after `Ok(())` MUST recover the written
///   entries.
///
///   Reference: Pillai et al., "All File Systems Are Not Created
///   Equal" (OSDI 2014); Mohan et al., "ARIES" (TODS 1992).
///
/// **INV-DL-6 (tenant isolation)**: The implementation MUST ensure
///   that `batch_get` for tenant A never returns entries written by
///   tenant B, even under concurrent access.
///
/// ## Verification Strategy
///
/// - Deterministic simulation: test with simulated crashes between
///   `batch_upsert` and the caller's next step (finding that the
///   done-ledger was updated but the shard manager doesn't know).
///   The system must recover correctly via re-enumeration and
///   idempotent re-upsert.
///
/// - Property-based test for INV-DL-1: generate random sequences of
///   upserts for the same key and verify final status matches the
///   expected lattice join.
///
/// - Jepsen-style test for INV-DL-2: simulate lease expiry during
///   `batch_upsert` and verify the write is rejected.
///
/// Reference: FoundationDB's atomic operations (apply functions on
/// write), TigerBeetle's batched API design, Stripe's idempotency
/// key pattern.
pub trait DoneLedger {
    /// Look up scan statuses for a batch of done-ledger keys.
    ///
    /// Returns one `DoneLedgerLookup` per input key, in the same order.
    /// Keys not found in the store are returned as `DoneLedgerLookup::NotSeen`.
    ///
    /// ## Concurrency
    ///
    /// `batch_get` is safe to call concurrently from multiple workers.
    /// Reads are not fence-gated â€” any worker may read regardless of
    /// lease status.
    ///
    /// ## Error Semantics
    ///
    /// On error, the entire batch fails. There are no partial results.
    /// The caller should retry the entire batch with backoff.
    fn batch_get(
        &self,
        batch: &DoneLedgerGetBatch,
        now: LogicalTime,
    ) -> Result<DoneLedgerGetResult, DoneLedgerGetError>;

    /// Upsert scan outcomes for a batch of done-ledger entries.
    ///
    /// The persistence layer applies monotonic merge semantics:
    /// for each entry, `new_status = merge(existing_status, incoming_status)`.
    ///
    /// ## Fence-Gating
    ///
    /// The write is gated by `(shard_id, fence_epoch)`. The persistence
    /// layer rejects the write if `fence_epoch <= last_accepted_epoch[shard_id]`.
    ///
    /// ## Atomicity
    ///
    /// All entries in the batch are applied atomically. On success,
    /// all entries are durable. On failure, none are applied.
    ///
    /// ## Ordering Requirement (caller obligation)
    ///
    /// The caller (runtime) MUST ensure that all findings produced by
    /// scanning these items have been durably persisted to the findings
    /// sink BEFORE calling `batch_upsert`. This ordering ensures that:
    ///
    /// 1. If the system crashes after `batch_upsert`, the findings are
    ///    already durable â€” no data loss.
    /// 2. If the system crashes before `batch_upsert`, the items will be
    ///    rescanned on retry â€” findings are re-produced idempotently.
    ///
    /// Violating this ordering can cause a "silent miss": the done-ledger
    /// says "scanned" but the findings aren't persisted.
    ///
    /// Reference: Write-ahead logging principle (ARIES, Mohan et al. 1992)
    /// â€” durable effects before durable commitments.
    fn batch_upsert(
        &self,
        batch: &DoneLedgerUpsertBatch,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        now: LogicalTime,
    ) -> Result<(), DoneLedgerUpsertError>;
}

// ============================================================================
// Â§ Invariant Catalog â€” Boundary â‘¤ Chunk 1
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.12 Invariant Catalog
// ---------------------------------------------------------------------------

/// Invariant catalog for Boundary â‘¤ Chunk 1.
///
/// ## Safety Invariants
///
/// **INV-B5-001**: OvidHash is deterministic.
///   For any `OvidInputs` value `v`, `derive_ovid_hash(v)` always
///   produces the same `OvidHash`.
///
/// **INV-B5-002**: OvidHash is collision-free (cryptographic).
///   For any two distinct `OvidInputs` values `a != b`,
///   `derive_ovid_hash(a) != derive_ovid_hash(b)` with overwhelming
///   probability (BLAKE3 collision resistance, 2^128 security).
///
/// **INV-B5-003**: DoneLedgerKey is deterministic.
///   For the same `(tenant, policy, ovid_inputs)`, constructing the
///   key via `DoneLedgerKey::from_ovid_inputs` always produces the
///   same key.
///
/// **INV-B5-004**: DoneLedgerStatus merge is a join-semilattice.
///   `merge` is commutative, associative, idempotent, and has
///   `Scanned` as its absorbing element.
///
/// **INV-B5-005**: DoneLedgerStatus merge preserves success.
///   If `Scanned` appears at any point in a merge sequence, the
///   final result is `Scanned`. Formally:
///   âˆ€ sâ‚..sâ‚™, if âˆƒ i s.t. sáµ¢ == Scanned,
///   then fold(merge, sâ‚..sâ‚™) == Scanned.
///
/// **INV-B5-006**: DoneLedgerEntry merge updates provenance correctly.
///   If incoming status supersedes existing, provenance is replaced
///   wholesale. If not, existing provenance is preserved.
///
/// **INV-B5-007**: SubresourceKind discriminants are stable.
///   Existing discriminant values (0â€“7) MUST NOT change meaning.
///   New values are appended. The extension range (128â€“255) is
///   reserved for connector-specific kinds.
///
/// ## Implementor Invariants (DoneLedger trait)
///
/// **INV-DL-1**: Monotonic status (see trait doc).
/// **INV-DL-2**: Fence rejection (see trait doc).
/// **INV-DL-3**: Batch atomicity (see trait doc).
/// **INV-DL-4**: Result cardinality (see trait doc).
/// **INV-DL-5**: Durability before ack (see trait doc).
/// **INV-DL-6**: Tenant isolation (see trait doc).
///
/// ## Design Decisions Summary
///
/// | ID    | Decision | Rationale |
/// |-------|----------|-----------|
/// | D5.1  | OVID is a hash | Fixed-width key, storage-agnostic |
/// | D5.2  | ConnectorInstanceId is 32-byte | Cross-installation isolation |
/// | D5.3  | SubresourceKind is u8 | Compact, extensible, stable |
/// | D5.4  | Monotonic status | CRDT lattice, zombie-safe |
/// | D5.5  | Batch-only API | Amortize latency, TigerBeetle style |
/// | D5.6  | Fence-gated writes | Zombie worker protection |
/// | D5.7  | Logical time provenance | Clock-independent correctness |
///
/// ## Cross-Boundary Dependencies
///
/// | This Type | Depends On | Boundary |
/// |-----------|------------|----------|
/// | OvidInputs | ConnectorTag | B1 Â§3.1 |
/// | OvidInputs | StableItemId | B1 Â§3.4 |
/// | OvidInputs | ObjectVersionId | B1 Â§3.2 |
/// | DoneLedgerKey | TenantId | B1 Â§2.2 |
/// | DoneLedgerKey | PolicyHash | B1 Â§2.3 |
/// | DoneLedgerEntry | RunId | B1 Â§2.4 |
/// | DoneLedgerEntry | ShardId | B1 Â§2.2 |
/// | DoneLedgerEntry | LogicalTime | B1 Â§2.2 |
/// | DoneLedger::batch_upsert | FenceEpoch | B1 Â§2.2 |
/// | ConnectorInstanceId | â€” (new type) | B5 Â§5.2 |
/// | SubresourceKind | â€” (new type) | B5 Â§5.3 |
/// | OvidHash | â€” (new type) | B5 Â§5.4 |
#[cfg(doc)]
pub struct _InvariantCatalogB5C1;

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper factories --

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0xAA; 32])
    }

    fn test_policy() -> PolicyHash {
        PolicyHash::from_bytes([0xBB; 32])
    }

    fn test_connector_tag() -> ConnectorTag {
        ConnectorTag::from_ascii(b"github")
    }

    fn test_connector_instance() -> ConnectorInstanceId {
        ConnectorInstanceId::from_bytes([0x11; 32])
    }

    fn test_stable_item_id() -> StableItemId {
        StableItemId::from_bytes([0x22; 32])
    }

    fn test_object_version() -> ObjectVersionId {
        ObjectVersionId::from_bytes([0x33; 32])
    }

    fn test_ovid_inputs() -> OvidInputs {
        OvidInputs {
            connector_kind: test_connector_tag(),
            connector_instance: test_connector_instance(),
            stable_item_id: test_stable_item_id(),
            version_id: test_object_version(),
            subresource_kind: SubresourceKindRaw::from_known(SubresourceKind::PrimaryContent),
        }
    }

    fn test_run_id() -> RunId {
        RunId {
            job: JobId(42),
            policy: test_policy(),
        }
    }

    // -- Â§5.2 ConnectorInstanceId tests --

    #[test]
    fn connector_instance_id_debug_is_hex() {
        let id = ConnectorInstanceId::from_bytes([0xAB; 32]);
        let debug = format!("{:?}", id);
        assert!(debug.starts_with("ConnectorInstanceId("));
    }

    // -- Â§5.3 SubresourceKind tests --

    #[test]
    fn subresource_kind_round_trip() {
        for kind in [
            SubresourceKind::PrimaryContent,
            SubresourceKind::CommitMessage,
            SubresourceKind::PrDescription,
            SubresourceKind::PrComment,
            SubresourceKind::IssueBody,
            SubresourceKind::WikiContent,
            SubresourceKind::PipelineConfig,
            SubresourceKind::RepoMetadata,
        ] {
            let raw = kind.as_u8();
            let back = SubresourceKind::from_u8(raw);
            assert_eq!(back, Some(kind), "round-trip failed for {:?}", kind);
        }
    }

    #[test]
    fn subresource_kind_unknown_returns_none() {
        assert_eq!(SubresourceKind::from_u8(255), None);
        assert_eq!(SubresourceKind::from_u8(128), None);
        assert_eq!(SubresourceKind::from_u8(99), None);
    }

    #[test]
    fn subresource_kind_raw_from_known() {
        let raw = SubresourceKindRaw::from_known(SubresourceKind::CommitMessage);
        assert_eq!(raw.as_u8(), 1);
        assert_eq!(raw.as_known(), Some(SubresourceKind::CommitMessage));
        assert!(!raw.is_extension());
    }

    #[test]
    fn subresource_kind_raw_extension() {
        let raw = SubresourceKindRaw::extension(200);
        assert_eq!(raw.as_u8(), 200);
        assert_eq!(raw.as_known(), None);
        assert!(raw.is_extension());
    }

    #[test]
    #[should_panic(expected = "extension sub-resource kinds must be >= 128")]
    fn subresource_kind_raw_extension_rejects_reserved() {
        let _ = SubresourceKindRaw::extension(5);
    }

    // -- Â§5.4 OvidHash tests --

    #[test]
    fn ovid_hash_deterministic() {
        let inputs = test_ovid_inputs();
        let h1 = derive_ovid_hash(&inputs);
        let h2 = derive_ovid_hash(&inputs);
        assert_eq!(h1, h2, "OVID hash must be deterministic");
    }

    #[test]
    fn ovid_hash_changes_with_connector_kind() {
        let mut inputs = test_ovid_inputs();
        let h1 = derive_ovid_hash(&inputs);

        inputs.connector_kind = ConnectorTag::from_ascii(b"gitlab");
        let h2 = derive_ovid_hash(&inputs);
        assert_ne!(h1, h2, "different connector kind â†’ different OVID");
    }

    #[test]
    fn ovid_hash_changes_with_connector_instance() {
        let mut inputs = test_ovid_inputs();
        let h1 = derive_ovid_hash(&inputs);

        inputs.connector_instance = ConnectorInstanceId::from_bytes([0x99; 32]);
        let h2 = derive_ovid_hash(&inputs);
        assert_ne!(h1, h2, "different connector instance â†’ different OVID");
    }

    #[test]
    fn ovid_hash_changes_with_stable_item_id() {
        let mut inputs = test_ovid_inputs();
        let h1 = derive_ovid_hash(&inputs);

        inputs.stable_item_id = StableItemId::from_bytes([0x99; 32]);
        let h2 = derive_ovid_hash(&inputs);
        assert_ne!(h1, h2, "different item â†’ different OVID");
    }

    #[test]
    fn ovid_hash_changes_with_version() {
        let mut inputs = test_ovid_inputs();
        let h1 = derive_ovid_hash(&inputs);

        inputs.version_id = ObjectVersionId::from_bytes([0x99; 32]);
        let h2 = derive_ovid_hash(&inputs);
        assert_ne!(h1, h2, "different version â†’ different OVID");
    }

    #[test]
    fn ovid_hash_changes_with_subresource_kind() {
        let mut inputs = test_ovid_inputs();
        let h1 = derive_ovid_hash(&inputs);

        inputs.subresource_kind = SubresourceKindRaw::from_known(
            SubresourceKind::CommitMessage,
        );
        let h2 = derive_ovid_hash(&inputs);
        assert_ne!(h1, h2, "different sub-resource â†’ different OVID");
    }

    // -- Â§5.5 DoneLedgerKey tests --

    #[test]
    fn done_ledger_key_round_trip_bytes() {
        let key = DoneLedgerKey::new(
            test_tenant(),
            test_policy(),
            derive_ovid_hash(&test_ovid_inputs()),
        );

        let bytes = key.to_bytes();
        assert_eq!(bytes.len(), 96);

        let recovered = DoneLedgerKey::from_bytes(&bytes);
        assert_eq!(key, recovered, "round-trip failed");
    }

    #[test]
    fn done_ledger_key_from_ovid_inputs() {
        let key = DoneLedgerKey::from_ovid_inputs(
            test_tenant(),
            test_policy(),
            &test_ovid_inputs(),
        );

        let expected_ovid = derive_ovid_hash(&test_ovid_inputs());
        assert_eq!(key.ovid, expected_ovid);
    }

    #[test]
    #[should_panic(expected = "exactly 96 bytes")]
    fn done_ledger_key_from_bytes_wrong_length() {
        DoneLedgerKey::from_bytes(&[0u8; 64]);
    }

    // -- Â§5.6 DoneLedgerStatus tests --

    #[test]
    fn status_merge_is_commutative() {
        let all = [DoneLedgerStatus::Failed, DoneLedgerStatus::Scanned];
        for &a in &all {
            for &b in &all {
                assert_eq!(
                    a.merge(b),
                    b.merge(a),
                    "merge({:?}, {:?}) != merge({:?}, {:?})",
                    a, b, b, a,
                );
            }
        }
    }

    #[test]
    fn status_merge_is_idempotent() {
        let all = [DoneLedgerStatus::Failed, DoneLedgerStatus::Scanned];
        for &a in &all {
            assert_eq!(a.merge(a), a, "merge({:?}, {:?}) != {:?}", a, a, a);
        }
    }

    #[test]
    fn status_merge_scanned_absorbs() {
        let scanned = DoneLedgerStatus::Scanned;
        let failed = DoneLedgerStatus::Failed;

        // Scanned absorbs Failed.
        assert_eq!(scanned.merge(failed), scanned);
        assert_eq!(failed.merge(scanned), scanned);

        // Scanned absorbs Scanned.
        assert_eq!(scanned.merge(scanned), scanned);
    }

    #[test]
    fn status_merge_is_associative() {
        let all = [DoneLedgerStatus::Failed, DoneLedgerStatus::Scanned];
        for &a in &all {
            for &b in &all {
                for &c in &all {
                    let left = a.merge(b).merge(c);
                    let right = a.merge(b.merge(c));
                    assert_eq!(
                        left, right,
                        "associativity: ({:?} âŠ” {:?}) âŠ” {:?} != {:?} âŠ” ({:?} âŠ” {:?})",
                        a, b, c, a, b, c,
                    );
                }
            }
        }
    }

    #[test]
    fn status_supersedes() {
        assert!(DoneLedgerStatus::Scanned.supersedes(DoneLedgerStatus::Failed));
        assert!(DoneLedgerStatus::Scanned.supersedes(DoneLedgerStatus::Scanned));
        assert!(DoneLedgerStatus::Failed.supersedes(DoneLedgerStatus::Failed));
        assert!(!DoneLedgerStatus::Failed.supersedes(DoneLedgerStatus::Scanned));
    }

    #[test]
    fn status_round_trip_u8() {
        for status in [DoneLedgerStatus::Scanned, DoneLedgerStatus::Failed] {
            let raw = status.as_u8();
            let back = DoneLedgerStatus::from_u8(raw);
            assert_eq!(back, Some(status));
        }
    }

    #[test]
    fn status_unknown_u8_returns_none() {
        assert_eq!(DoneLedgerStatus::from_u8(0), None);
        assert_eq!(DoneLedgerStatus::from_u8(3), None);
        assert_eq!(DoneLedgerStatus::from_u8(255), None);
    }

    // -- Â§5.7 DoneLedgerEntry tests --

    #[test]
    fn entry_merge_scanned_absorbs_failed() {
        let scanned = DoneLedgerEntry::scanned(
            LogicalTime(100),
            test_run_id(),
            ShardId(1),
        );
        let failed = DoneLedgerEntry::failed(
            LogicalTime(200), // Later timestamp, but lower status.
            test_run_id(),
            ShardId(1),
        );

        let merged = scanned.merge_with(&failed);
        assert_eq!(merged.status, DoneLedgerStatus::Scanned);
        // Provenance should be from the scanned entry (no upgrade occurred).
        assert_eq!(merged.scanned_at, LogicalTime(100));
    }

    #[test]
    fn entry_merge_failed_promoted_by_scanned() {
        let failed = DoneLedgerEntry::failed(
            LogicalTime(100),
            test_run_id(),
            ShardId(1),
        );
        let scanned = DoneLedgerEntry::scanned(
            LogicalTime(200),
            test_run_id(),
            ShardId(2), // Different shard succeeded.
        );

        let merged = failed.merge_with(&scanned);
        assert_eq!(merged.status, DoneLedgerStatus::Scanned);
        // Provenance should be from the incoming scanned entry.
        assert_eq!(merged.scanned_at, LogicalTime(200));
        assert_eq!(merged.shard_id, ShardId(2));
    }

    #[test]
    fn entry_merge_same_status_keeps_existing() {
        let existing = DoneLedgerEntry::failed(
            LogicalTime(100),
            test_run_id(),
            ShardId(1),
        );
        let incoming = DoneLedgerEntry::failed(
            LogicalTime(200),
            test_run_id(),
            ShardId(2),
        );

        let merged = existing.merge_with(&incoming);
        assert_eq!(merged.status, DoneLedgerStatus::Failed);
        // No status change â†’ keep existing provenance.
        assert_eq!(merged.scanned_at, LogicalTime(100));
        assert_eq!(merged.shard_id, ShardId(1));
    }

    // -- Â§5.8 DoneLedgerLookup tests --

    #[test]
    fn lookup_not_seen_needs_scan() {
        assert!(DoneLedgerLookup::NotSeen.needs_scan());
        assert!(!DoneLedgerLookup::NotSeen.is_scanned());
    }

    #[test]
    fn lookup_scanned_does_not_need_scan() {
        let entry = DoneLedgerEntry::scanned(
            LogicalTime(1),
            test_run_id(),
            ShardId(0),
        );
        let lookup = DoneLedgerLookup::Found(entry);
        assert!(!lookup.needs_scan());
        assert!(lookup.is_scanned());
    }

    #[test]
    fn lookup_failed_needs_scan() {
        let entry = DoneLedgerEntry::failed(
            LogicalTime(1),
            test_run_id(),
            ShardId(0),
        );
        let lookup = DoneLedgerLookup::Found(entry);
        assert!(lookup.needs_scan());
        assert!(!lookup.is_scanned());
    }

    // -- Â§5.9 Batch operation tests --

    #[test]
    fn get_batch_push_and_len() {
        let mut batch = DoneLedgerGetBatch::with_capacity(3);
        assert!(batch.is_empty());

        let key = DoneLedgerKey::from_ovid_inputs(
            test_tenant(),
            test_policy(),
            &test_ovid_inputs(),
        );
        batch.push(key);
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    #[should_panic(expected = "exceeded capacity")]
    fn get_batch_panics_on_overflow() {
        let mut batch = DoneLedgerGetBatch::with_capacity(1);
        let key = DoneLedgerKey::from_ovid_inputs(
            test_tenant(),
            test_policy(),
            &test_ovid_inputs(),
        );
        batch.push(key.clone());
        batch.push(key); // Should panic.
    }

    #[test]
    fn get_result_counts() {
        let results = DoneLedgerGetResult::new(vec![
            DoneLedgerLookup::NotSeen,
            DoneLedgerLookup::Found(DoneLedgerEntry::scanned(
                LogicalTime(1), test_run_id(), ShardId(0),
            )),
            DoneLedgerLookup::Found(DoneLedgerEntry::failed(
                LogicalTime(1), test_run_id(), ShardId(0),
            )),
        ]);

        assert_eq!(results.len(), 3);
        assert_eq!(results.count_needs_scan(), 2); // NotSeen + Failed
        assert_eq!(results.count_skippable(), 1);  // Scanned only
    }

    #[test]
    fn upsert_batch_push_and_len() {
        let mut batch = DoneLedgerUpsertBatch::with_capacity(2);
        assert!(batch.is_empty());

        let key = DoneLedgerKey::from_ovid_inputs(
            test_tenant(),
            test_policy(),
            &test_ovid_inputs(),
        );
        let entry = DoneLedgerEntry::scanned(
            LogicalTime(1),
            test_run_id(),
            ShardId(0),
        );
        batch.push(DoneLedgerUpsertItem::new(key, entry));
        assert_eq!(batch.len(), 1);
    }

    // -- Â§5.10 Error display tests --

    #[test]
    fn error_display() {
        let err = DoneLedgerGetError::Unavailable {
            reason: "connection reset".into(),
        };
        assert!(err.to_string().contains("connection reset"));

        let err = DoneLedgerGetError::BatchTooLarge {
            requested: 1000,
            max_allowed: 500,
        };
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));

        let err = DoneLedgerUpsertError::FenceEpochStale {
            presented: FenceEpoch(5),
            required_minimum: FenceEpoch(10),
        };
        let msg = err.to_string();
        assert!(msg.contains("stale"));
    }

    // -- Property test stubs --

    // TODO: proptest for INV-B5-001 (OVID determinism):
    //   âˆ€ OvidInputs v: derive_ovid_hash(v) == derive_ovid_hash(v)
    //
    // TODO: proptest for INV-B5-002 (OVID collision-freedom):
    //   âˆ€ distinct (a, b): derive_ovid_hash(a) != derive_ovid_hash(b)
    //   (probabilistic â€” test with large sample)
    //
    // TODO: proptest for INV-B5-004 (merge is semilattice):
    //   âˆ€ a, b, c:
    //     merge(a, b) == merge(b, a)              [commutative]
    //     merge(a, merge(b, c)) == merge(merge(a, b), c) [associative]
    //     merge(a, a) == a                        [idempotent]
    //
    // TODO: proptest for INV-B5-005 (Scanned absorbs):
    //   âˆ€ sequence sâ‚..sâ‚™ containing Scanned:
    //     fold(merge, sâ‚..sâ‚™) == Scanned
    //
    // TODO: proptest for DoneLedgerKey byte round-trip:
    //   âˆ€ key: DoneLedgerKey::from_bytes(&key.to_bytes()) == key
    //
    // TODO: proptest for CanonicalBytes determinism:
    //   âˆ€ OvidInputs v: canonical_hash(v) == canonical_hash(v)
}
