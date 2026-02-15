//! Boundary â‘  â€” Identity Spine: Chunks 1 + 2 (DRAFT)
//!
//! This file covers:
//!   Chunk 1: Infrastructure â€” encoding conventions, CanonicalBytes trait, ID macros
//!   Chunk 2: TenantId + coordination ID adjustments
//!
//! Chunks 3â€“5 (scan-object identity, secret/finding identity, PolicyHash v2)
//! will be drafted separately after review.
//!
//! ## Design Decisions (locked)
//!
//! D1: Two-tier ID widths
//!     - Coordination-internal: `u64` (ShardId, OpId, FenceEpoch, WorkerId, LogicalTime, JobId)
//!     - Cross-boundary/content-addressed: `[u8; 32]` (TenantId, PolicyHash, SecretHash,
//!       FindingId, OccurrenceId, RuleFingerprint)
//!
//! D2: TenantId is a separate first-class type above RunId
//!     Hierarchy: TenantId â†’ JobId â†’ RunId â†’ ShardId
//!
//! D3: Both NormHash (unkeyed) and SecretHash (keyed) defined in contracts,
//!     with a keying function. Type-level prevention of accidental persistence.
//!
//! D4: Two-level finding model: FindingId (stable across versions) +
//!     OccurrenceId (version-specific location).

#![forbid(unsafe_code)]

use core::fmt;

use blake3::Hasher;

// ============================================================================
// Â§ Chunk 1: Infrastructure â€” Encoding Conventions
// ============================================================================

// ---------------------------------------------------------------------------
// Â§1.1 Domain Separation Constants
// ---------------------------------------------------------------------------

/// All domain tags are versioned so that hash outputs change if the derivation
/// scheme ever changes. This prevents silent collisions across scheme versions.
///
/// Convention: "gossip/<subsystem>/v<N>/<operation>"
///
/// Reference: BLAKE3 spec Â§2.4 (key derivation context strings);
///            NIST SP 800-185 Â§6.2 (domain separation for extensible outputs).
pub mod domain {
    /// Shard ID derivation during split operations.
    pub const SPLIT_ID_V1: &[u8] = b"gossip/coord/v1/split-id";

    /// Op-log payload hashing for idempotency conflict detection.
    pub const OP_PAYLOAD_V1: &[u8] = b"gossip/coord/v1/op-payload";

    /// FindingId derivation (chunk 4, placeholder).
    pub const FINDING_ID_V1: &[u8] = b"gossip/finding/v1";

    /// OccurrenceId derivation (chunk 4, placeholder).
    pub const OCCURRENCE_ID_V1: &[u8] = b"gossip/occurrence/v1";

    /// SecretHash keying (chunk 4, placeholder).
    pub const SECRET_HASH_V1: &[u8] = b"gossip/secret-hash/v1";
}

// ---------------------------------------------------------------------------
// Â§1.2 CanonicalBytes Trait
// ---------------------------------------------------------------------------

/// Deterministic byte encoding for content-addressed hashing.
///
/// Every type that participates in a content-addressed derivation (FindingId,
/// OccurrenceId, derive_split_shard_id, payload hashes) MUST implement this
/// trait.
///
/// ## Invariants
///
/// **Safety (collision-freedom)**:
///   For any two distinct values `a != b` of the same type,
///   `a.write_canonical(h)` and `b.write_canonical(h)` MUST produce
///   different byte sequences. This means:
///   - Variable-length fields MUST be length-prefixed.
///   - Multi-field types MUST use unambiguous framing (length prefix or
///     fixed-width fields).
///
/// **Safety (determinism)**:
///   The output MUST be identical across platforms, byte orders, and Rust
///   versions. Use fixed-endian encodings (little-endian by convention).
///
/// **Liveness**: Implementations MUST NOT allocate. Feed directly into hasher.
///
/// ## Verification Strategy
///
/// Property-based tests (proptest): for any value `v`, encoding `v` twice
/// into separate hashers produces identical BLAKE3 digests.
///
/// Reference: Git content-addressed object model (Pro Git Book);
///            IPFS CID specification (Protocol Labs).
pub trait CanonicalBytes {
    /// Write this value's canonical byte representation into `hasher`.
    fn write_canonical(&self, hasher: &mut Hasher);
}

// Primitive implementations â€” building blocks for composite types.

impl CanonicalBytes for u8 {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&[*self]);
    }
}

impl CanonicalBytes for u32 {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&self.to_le_bytes());
    }
}

impl CanonicalBytes for u64 {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&self.to_le_bytes());
    }
}

/// Variable-length byte slices: length-prefixed to prevent concatenation
/// ambiguity.
///
/// Example: `[0x41, 0x42]` encodes as `[2, 0, 0, 0, 0x41, 0x42]`
/// (4-byte LE length prefix + payload).
impl CanonicalBytes for [u8] {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        assert!(self.len() <= u32::MAX as usize, "slice too large for canonical encoding");
        (self.len() as u32).write_canonical(h);
        h.update(self);
    }
}

/// Fixed-length 32-byte arrays: no length prefix needed (fixed width).
impl CanonicalBytes for [u8; 32] {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(self);
    }
}

// ---------------------------------------------------------------------------
// Â§1.3 32-Byte ID Newtype Macro
// ---------------------------------------------------------------------------

/// Generates a `[u8; 32]` newtype with:
/// - Safe `Debug` (hex prefix only, configurable)
/// - `Clone`, `Copy`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`
/// - `CanonicalBytes` (fixed-width, no length prefix)
/// - `ZERO` constant
/// - `from_bytes` / `as_bytes` accessors
///
/// The inner field is `pub` for types that are freely constructible from
/// external data. For sensitive types (NormHash, SecretHash) that require
/// controlled construction, use `define_id_32_restricted!` instead.
macro_rules! define_id_32 {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    concat!(stringify!($name), "({:02x}{:02x}{:02x}{:02x}..)"),
                    self.0[0], self.0[1], self.0[2], self.0[3]
                )
            }
        }

        impl $name {
            pub const ZERO: Self = Self([0u8; 32]);

            #[inline]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[inline]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl CanonicalBytes for $name {
            #[inline]
            fn write_canonical(&self, h: &mut Hasher) {
                h.update(&self.0);
            }
        }
    };
}

/// Like `define_id_32!` but with a private inner field and a custom Debug
/// that prints `[redacted]`. Used for types that must only be constructed
/// through controlled derivation functions (NormHash, SecretHash).
macro_rules! define_id_32_restricted {
    (
        $(#[$meta:meta])*
        $name:ident,
        debug_display = $debug:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, $debug)
            }
        }

        impl $name {
            /// Construct from raw bytes. This is `pub(crate)` â€” only the
            /// contracts crate's derivation functions may construct this type.
            #[inline]
            pub(crate) const fn from_bytes_internal(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[inline]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl CanonicalBytes for $name {
            #[inline]
            fn write_canonical(&self, h: &mut Hasher) {
                h.update(&self.0);
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Â§1.4 Canonical Encoding Helpers
// ---------------------------------------------------------------------------

/// Start a domain-separated BLAKE3 hash.
///
/// Returns a `Hasher` pre-fed with the domain tag. Callers feed additional
/// fields via `CanonicalBytes::write_canonical` and finalize.
#[inline]
pub fn domain_hasher(domain: &[u8]) -> Hasher {
    let mut h = Hasher::new();
    h.update(domain);
    h
}

/// Finalize a hasher into a 32-byte ID.
///
/// This is the common tail of all content-addressed derivation functions.
#[inline]
fn finalize_32(h: &Hasher) -> [u8; 32] {
    *h.finalize().as_bytes()
}

/// Finalize a hasher into a truncated 64-bit value.
///
/// Used for payload hashes where 64 bits of collision resistance is
/// sufficient (op-log idempotency guardrails, not cryptographic).
#[inline]
fn finalize_64(h: &Hasher) -> u64 {
    let out = h.finalize();
    let bytes: [u8; 8] = out.as_bytes()[0..8].try_into().expect("8 bytes from 32");
    u64::from_le_bytes(bytes)
}

// ============================================================================
// Â§ Chunk 2: Core Identity Types
// ============================================================================

// ---------------------------------------------------------------------------
// Â§2.1 TenantId â€” Multi-tenant isolation boundary
// ---------------------------------------------------------------------------

define_id_32! {
    /// Stable tenant identity. Top of the isolation hierarchy.
    ///
    /// In production, this is typically derived from an external tenant
    /// identifier (e.g., `blake3(external_tenant_uuid)` to normalize width).
    ///
    /// ## Invariants
    ///
    /// **Safety**: A shard record for tenant A must NEVER be readable or
    /// writable by a request scoped to tenant B. The coordination layer
    /// enforces this by requiring `TenantId` at every API boundary.
    ///
    /// **Safety**: `TenantId` is an input to `SecretHash` keying (via
    /// `TenantSecretKey`), `FindingId` derivation, and `OccurrenceId`
    /// derivation. Changing a tenant's ID invalidates all derived hashes.
    TenantId
}

/// Opaque per-tenant secret key used to derive `SecretHash` from `NormHash`.
///
/// This type exists in the contracts crate solely to define the keying
/// function signature. It MUST NOT be logged, serialized to untrusted
/// storage, or included in Debug output.
///
/// ## Provisioning
///
/// The coordination/persistence layer provisions one key per tenant.
/// Key rotation requires rescan of affected findings (new SecretHash values).
///
/// Reference: RFC 2104 (HMAC); BLAKE3 spec Â§3 (keyed hashing).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantSecretKey([u8; 32]);

impl fmt::Debug for TenantSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TenantSecretKey([redacted])")
    }
}

impl TenantSecretKey {
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// No CanonicalBytes for TenantSecretKey â€” it must never be hashed into
// content-addressed IDs.

// ---------------------------------------------------------------------------
// Â§2.2 Coordination IDs (u64 tier) â€” mostly unchanged from MVP
// ---------------------------------------------------------------------------

/// Logical time used by the in-memory model and deterministic simulator.
///
/// Production backends may map this to wall-clock or monotonic time.
/// Coordination correctness MUST NOT depend on physical clock properties.
///
/// Reference: Â§9 Anti-Pattern #5 â€” "Do not rely on wall-clock timeouts
/// for correctness."
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogicalTime(pub u64);

impl LogicalTime {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn saturating_add(self, delta: u64) -> Self {
        Self(self.0.saturating_add(delta))
    }
}

impl CanonicalBytes for LogicalTime {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.0.write_canonical(h);
    }
}

/// Stable identifier for a scan job within a tenant namespace.
///
/// `JobId` is implicitly tenant-scoped: a `JobId` only makes sense within
/// the context of a `TenantId`. The coordination layer enforces scoping at
/// the API boundary rather than embedding the tenant in the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(pub u64);

impl CanonicalBytes for JobId {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.0.write_canonical(h);
    }
}

/// Stable shard identifier within a run.
///
/// Root shards use small sequential IDs (0..N). Derived shards (from split
/// operations) have the top bit set to avoid collision with root IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(pub u64);

impl CanonicalBytes for ShardId {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.0.write_canonical(h);
    }
}

/// Stable worker instance identity.
///
/// Intentionally opaque; callers map from hostnames + boot UUIDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkerId(pub u64);

impl CanonicalBytes for WorkerId {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.0.write_canonical(h);
    }
}

/// Idempotency key for a single logical request.
///
/// Callers MUST reuse the same `OpId` when retrying an operation.
/// The `OpId` combined with a `payload_hash` detects accidental reuse
/// of the same OpId with different inputs.
///
/// Reference: Stripe idempotency key pattern (Brandur Leach, 2017);
///            IETF Draft: Idempotency-Key HTTP Header Field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId(pub u64);

impl CanonicalBytes for OpId {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.0.write_canonical(h);
    }
}

/// Fence epoch for a shard.
///
/// MUST strictly increase on every ownership transfer. Used to fence
/// "zombie" workers from committing stale writes after reassignment.
///
/// The fencing protocol requires that all external services (persistence
/// sinks) participate: they must reject writes with an epoch â‰¤ the
/// current known epoch.
///
/// Reference: Kleppmann, "How to do distributed locking" (2016) â€”
///            fencing tokens; Gray & Cheriton, "Leases" (SOSP 1989).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FenceEpoch(pub u64);

impl FenceEpoch {
    pub const INITIAL: Self = Self(1);

    /// Produce the next epoch. Saturating to avoid wrapping to 0 (which
    /// would violate the monotonicity invariant).
    #[inline]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl CanonicalBytes for FenceEpoch {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.0.write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§2.3 PolicyHash â€” existing, upgraded with CanonicalBytes
// ---------------------------------------------------------------------------

define_id_32! {
    /// Policy identity â€” cryptographic digest of rules, config, and output
    /// identity semantics.
    ///
    /// `PolicyHash` serves as the join key for skip/dedupe decisions.
    /// It MUST include all inputs that affect detection output identity:
    ///
    /// - `policy_hash_version`: scheme version (for forced rescan on upgrade)
    /// - `id_hash_mode`: keyed vs unkeyed hashing
    /// - `evidence_hash_version`: normalization + input version
    /// - rules and their configurations
    ///
    /// If any of these change, PolicyHash changes â†’ new RunId â†’ forced rescan.
    ///
    /// ## Invariants
    ///
    /// **Safety**: Two runs with the same PolicyHash MUST produce identical
    /// findings for identical input. If the detection semantics change,
    /// PolicyHash MUST change.
    ///
    /// NOTE: The internal structure of PolicyHash (how it's computed from
    /// sub-fields) will be defined in chunk 5 (PolicyHash v2). For now,
    /// it remains an opaque 32-byte digest.
    PolicyHash
}

// ---------------------------------------------------------------------------
// Â§2.4 Composite Keys
// ---------------------------------------------------------------------------

/// `(JobId, PolicyHash)` uniquely identifies a reproducible run.
///
/// A run is "reproducible" in the sense that the same job with the same
/// policy should produce the same findings for the same input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunId {
    pub job: JobId,
    pub policy: PolicyHash,
}

impl CanonicalBytes for RunId {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.job.write_canonical(h);
        self.policy.write_canonical(h);
    }
}

/// `(RunId, ShardId)` identifies a single shard record within a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardKey {
    pub run: RunId,
    pub shard: ShardId,
}

impl CanonicalBytes for ShardKey {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.run.write_canonical(h);
        self.shard.write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§2.5 TenantId threading â€” how TenantId integrates with existing types
// ---------------------------------------------------------------------------

// Design note: TenantId is NOT embedded in RunId or ShardKey.
//
// Rationale: Tenant isolation is a cross-cutting concern enforced at the
// API boundary of the coordination trait, not embedded in composite keys.
// This keeps RunId cheap (no 32-byte overhead in every shard operation)
// and makes the isolation boundary explicit:
//
//     trait CoordinationBackend {
//         fn acquire(&self, tenant: TenantId, run: RunId, ...) -> ...;
//         fn checkpoint(&self, tenant: TenantId, shard: ShardKey, ...) -> ...;
//     }
//
// Every method takes TenantId as its first parameter. The backend asserts:
//     assert_eq!(record.tenant, tenant, "cross-tenant access");
//
// The ShardRecord stores its TenantId for this assertion.

/// Per-run configuration stored in coordination.
///
/// Now includes `tenant` to support the isolation invariant assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunConfig {
    pub tenant: TenantId,
    pub cursor_semantics: CursorSemantics,
    /// Lease duration in logical time units.
    pub lease_duration: u64,
}

/// A lease returned by acquire/extend operations.
///
/// Includes `tenant` for downstream fencing assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub tenant: TenantId,
    pub run: RunId,
    pub shard: ShardId,
    pub owner: WorkerId,
    pub fence: FenceEpoch,
    pub deadline: LogicalTime,
}

// ============================================================================
// Â§ Forward Declarations â€” Types defined in later chunks
// ============================================================================

// These are placeholders showing where chunks 3â€“5 will add types.
// They use the macros and traits defined above.

// Chunk 3: Scan-Object Identity
// define_id_32!{ StableItemId }         // blake3(ItemKey bytes)
// pub struct ItemKey(Box<[u8]>);        // variable-length path/URI
// define_id_32!{ ObjectVersionId }      // version-specific content identity

// Chunk 4: Secret & Finding Identity
// define_id_32_restricted!{ NormHash, debug_display = "NormHash([redacted])" }
// define_id_32_restricted!{ SecretHash, debug_display = "SecretHash({:02x}{:02x}..)" }
// define_id_32!{ RuleFingerprint }
// define_id_32!{ FindingId }
// define_id_32!{ OccurrenceId }
// pub fn key_secret_hash(key: &TenantSecretKey, norm: &NormHash) -> SecretHash;
// pub fn derive_finding_id(...) -> FindingId;
// pub fn derive_occurrence_id(...) -> OccurrenceId;

// Chunk 5: PolicyHash v2
// pub struct PolicyHashInputs { policy_hash_version, id_hash_mode, ... }
// pub fn compute_policy_hash(inputs: &PolicyHashInputs) -> PolicyHash;

// ============================================================================
// Â§ Existing Types â€” Carried Forward (unchanged or minimally adjusted)
// ============================================================================
//
// The following types from the current lib.rs are unchanged in this chunk.
// They're listed here for completeness but not re-defined to keep this
// draft focused. Changes from the MVP:
//
// - CursorSemantics: unchanged
// - ShardStatus: unchanged
// - ParkReason: unchanged
// - ShardSpec: unchanged (opaque bytes)
// - Cursor: unchanged
// - OpKind, OpResult, OpLogEntry: unchanged
// - SplitReplace*, SplitResidual*: unchanged
// - ShardRecord: gains `tenant: TenantId` field
// - ShardSnapshot: gains `tenant: TenantId` field
// - derive_split_shard_id: refactored to use CanonicalBytes internally
// - payload_hash64 + hash_*_payload: refactored to use CanonicalBytes
//
// The ShardRecord change is shown below for clarity:

// Example of how ShardRecord gains TenantId:
//
// pub struct ShardRecord {
//     pub tenant: TenantId,      // â† NEW
//     pub run: RunId,
//     pub shard: ShardId,
//     pub status: ShardStatus,
//     pub spec: ShardSpec,
//     pub cursor: Cursor,
//     pub cursor_semantics: CursorSemantics,
//     pub lease_owner: Option<WorkerId>,
//     pub lease_deadline: Option<LogicalTime>,
//     pub fence_epoch: FenceEpoch,
//     pub parent: Option<ShardId>,
//     pub spawned: Vec<ShardId>,
//     pub op_log: Vec<OpLogEntry>,
// }

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- CanonicalBytes determinism --

    #[test]
    fn canonical_bytes_u64_deterministic() {
        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();
        42u64.write_canonical(&mut h1);
        42u64.write_canonical(&mut h2);
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn canonical_bytes_slice_length_prefixed() {
        // [0x41] and [0x41, 0x00] must produce different hashes.
        let a: &[u8] = &[0x41];
        let b: &[u8] = &[0x41, 0x00];

        let mut ha = Hasher::new();
        let mut hb = Hasher::new();
        a.write_canonical(&mut ha);
        b.write_canonical(&mut hb);

        assert_ne!(ha.finalize(), hb.finalize());
    }

    #[test]
    fn canonical_bytes_concatenation_unambiguous() {
        // Ensure ("ab", "c") != ("a", "bc") for variable-length fields.
        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();

        b"ab".as_slice().write_canonical(&mut h1);
        b"c".as_slice().write_canonical(&mut h1);

        b"a".as_slice().write_canonical(&mut h2);
        b"bc".as_slice().write_canonical(&mut h2);

        assert_ne!(h1.finalize(), h2.finalize());
    }

    // -- ID type properties --

    #[test]
    fn tenant_id_debug_is_safe() {
        let t = TenantId::from_bytes([0xAB; 32]);
        let dbg = format!("{:?}", t);
        assert!(dbg.starts_with("TenantId("));
        assert!(dbg.contains("abababab"));
        // Must NOT contain all 32 bytes.
        assert!(dbg.len() < 80);
    }

    #[test]
    fn tenant_secret_key_debug_is_redacted() {
        let k = TenantSecretKey::from_bytes([0xFF; 32]);
        let dbg = format!("{:?}", k);
        assert_eq!(dbg, "TenantSecretKey([redacted])");
        assert!(!dbg.contains("ff"));
    }

    #[test]
    fn policy_hash_debug_is_safe() {
        let p = PolicyHash::from_bytes([0xDE; 32]);
        let dbg = format!("{:?}", p);
        assert!(dbg.starts_with("PolicyHash("));
        assert!(dbg.contains("dededede"));
        assert!(dbg.len() < 80);
    }

    #[test]
    fn fence_epoch_monotonicity() {
        let e = FenceEpoch::INITIAL;
        assert_eq!(e.0, 1);
        assert!(e.next().0 > e.0);

        // Saturating: u64::MAX doesn't wrap.
        let max = FenceEpoch(u64::MAX);
        assert_eq!(max.next().0, u64::MAX);
    }

    // -- Composite CanonicalBytes --

    #[test]
    fn run_id_canonical_bytes_deterministic() {
        let run = RunId {
            job: JobId(42),
            policy: PolicyHash::from_bytes([7u8; 32]),
        };

        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();
        run.write_canonical(&mut h1);
        run.write_canonical(&mut h2);

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn run_id_different_fields_different_hash() {
        let a = RunId {
            job: JobId(1),
            policy: PolicyHash::from_bytes([0u8; 32]),
        };
        let b = RunId {
            job: JobId(2),
            policy: PolicyHash::from_bytes([0u8; 32]),
        };

        let mut ha = Hasher::new();
        let mut hb = Hasher::new();
        a.write_canonical(&mut ha);
        b.write_canonical(&mut hb);

        assert_ne!(ha.finalize(), hb.finalize());
    }

    // -- TenantId in Lease --

    #[test]
    fn lease_carries_tenant() {
        let lease = Lease {
            tenant: TenantId::from_bytes([1u8; 32]),
            run: RunId {
                job: JobId(10),
                policy: PolicyHash::ZERO,
            },
            shard: ShardId(0),
            owner: WorkerId(1),
            fence: FenceEpoch::INITIAL,
            deadline: LogicalTime::ZERO,
        };
        assert_ne!(lease.tenant, TenantId::ZERO);
    }

    // -- Property-based (proptest) --

    proptest::proptest! {
        #[test]
        fn canonical_bytes_u64_stable(v in proptest::num::u64::ANY) {
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            v.write_canonical(&mut h1);
            v.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn canonical_bytes_slice_stable(
            data in proptest::collection::vec(proptest::num::u8::ANY, 0..256)
        ) {
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            data.as_slice().write_canonical(&mut h1);
            data.as_slice().write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn tenant_id_canonical_bytes_stable(bytes in proptest::array::uniform32(proptest::num::u8::ANY)) {
            let t = TenantId::from_bytes(bytes);
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            t.write_canonical(&mut h1);
            t.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }
    }
}
