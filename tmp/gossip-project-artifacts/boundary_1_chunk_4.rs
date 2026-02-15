//! Boundary â‘  â€” Identity Spine: Chunk 4 (DRAFT)
//!
//! Secret & Finding Identity: the types that answer "what secret was found,"
//! "by which rule," and "where exactly."
//!
//! This file is additive to chunks 1â€“3. It uses `CanonicalBytes`,
//! `define_id_32!`, `define_id_32_restricted!`, `domain_hasher`,
//! `finalize_32`, `TenantId`, `TenantSecretKey`, `StableItemId`,
//! `ObjectVersionId`, and `RuleFingerprint` from prior chunks.
//!
//! ## Design Decisions (locked)
//!
//! D4a: BLAKE3 keyed mode (`new_keyed`) for SecretHash derivation.
//!      One pass, no extra dependencies, spec Â§3 PRF proof.
//!
//! D4b: NormHash::from_digest(pub) â€” engine computes blake3 of normalized
//!      secret bytes internally, contracts crate never sees raw bytes.
//!
//! D4c: u64 for byte_offset and byte_length in OccurrenceId derivation.
//!
//! D4d: Two-level finding model:
//!      FindingId  = blake3(domain, tenant, item, rule, secret_hash)
//!      OccurrenceId = blake3(domain, finding, version, offset, length)

// Assumes these are in scope from chunks 1â€“3:
// use crate::{
//     CanonicalBytes, define_id_32, define_id_32_restricted,
//     domain_hasher, finalize_32,
//     TenantId, TenantSecretKey, StableItemId, ObjectVersionId,
//     Hasher,
// };

// ============================================================================
// Â§ Chunk 4: Secret & Finding Identity
// ============================================================================

// ---------------------------------------------------------------------------
// Â§4.1 NormHash â€” unkeyed, engine-internal secret identity
// ---------------------------------------------------------------------------

define_id_32_restricted! {
    /// Unkeyed BLAKE3 digest of normalized secret bytes.
    ///
    /// This type exists ONLY as an intermediate between the detection engine
    /// and the `key_secret_hash` function. It MUST NOT be:
    /// - Persisted to any durable store
    /// - Sent over the network
    /// - Logged (Debug prints `[redacted]`)
    /// - Included in any serialization format
    ///
    /// ## Construction
    ///
    /// The detection engine computes `blake3(normalized_secret_bytes)` and
    /// wraps the result via `NormHash::from_digest`. The contracts crate
    /// never sees the raw secret bytes.
    ///
    /// ## Normalization
    ///
    /// "Normalized" means the engine has applied deterministic preprocessing
    /// to the raw match bytes (e.g., stripping whitespace, removing known
    /// prefixes, lowercasing). The normalization function is engine-internal
    /// and versioned via `evidence_hash_version` in `PolicyHash`.
    ///
    /// ## Invariants
    ///
    /// **Safety**: NormHash MUST NOT appear in any persisted record.
    /// Type-level enforcement: `Debug` is redacted, no `Serialize` impl,
    /// `from_digest` name signals "pre-computed digest only."
    ///
    /// **Safety (determinism)**: The same normalized secret bytes MUST
    /// always produce the same NormHash.
    NormHash,
    debug_display = "NormHash([redacted])"
}

impl NormHash {
    /// Construct from a pre-computed BLAKE3 digest of normalized secret bytes.
    ///
    /// The caller (detection engine) is responsible for:
    /// 1. Normalizing the raw secret bytes deterministically
    /// 2. Computing `blake3(normalized_bytes)`
    /// 3. Passing the 32-byte digest here
    ///
    /// The contracts crate does NOT verify the input â€” it trusts the
    /// engine to have computed this correctly.
    #[inline]
    pub fn from_digest(bytes: [u8; 32]) -> Self {
        Self::from_bytes_internal(bytes)
    }
}

// ---------------------------------------------------------------------------
// Â§4.2 SecretHash â€” keyed, persistence-safe secret identity
// ---------------------------------------------------------------------------

define_id_32_restricted! {
    /// Tenant-keyed secret identity, safe for persistence and cross-run dedup.
    ///
    /// Derived as `blake3_keyed(tenant_secret_key, domain || norm_hash)`.
    ///
    /// This is the secret identity that appears in `FindingId` derivation
    /// and in persisted finding records. It is NOT reversible to the
    /// original secret bytes without the tenant key.
    ///
    /// ## Invariants
    ///
    /// **Safety**: SecretHash MUST be derived through `key_secret_hash`.
    /// Construction is `pub(crate)` to enforce this.
    ///
    /// **Safety**: SecretHash is tenant-scoped. The same NormHash keyed
    /// with different tenants produces different SecretHash values.
    /// This prevents cross-tenant correlation of secret material.
    ///
    /// **Safety (determinism)**: Same (key, NormHash) pair always produces
    /// the same SecretHash.
    ///
    /// ## Key Rotation
    ///
    /// If a tenant's secret key is rotated, all SecretHash values for that
    /// tenant become invalid. This requires rescanning affected items to
    /// recompute findings with the new key.
    ///
    /// Reference: BLAKE3 spec Â§3 (keyed hashing).
    SecretHash,
    debug_display = "SecretHash([redacted])"
}

/// Derive a persistence-safe `SecretHash` from a tenant key and unkeyed hash.
///
/// This is the keying boundary: the single point where unkeyed engine output
/// becomes persistence-safe tenant-scoped identity.
///
/// ## Construction
///
/// Uses BLAKE3 keyed mode (`new_keyed`):
/// ```text
/// SecretHash = blake3_keyed(tenant_key, "gossip/secret-hash/v1" || norm_hash)
/// ```
///
/// The domain tag is included inside the keyed hash to prevent cross-protocol
/// attacks if the same key were ever (mistakenly) used for another purpose.
///
/// ## Invariants
///
/// **Safety**: This function is the ONLY way to construct a `SecretHash`.
/// The `from_bytes_internal` constructor is `pub(crate)`.
///
/// **Safety (determinism)**: Pure function of (key, norm_hash). No
/// non-determinism sources.
///
/// ## Verification Strategy
///
/// Property-based test: for any (key, norm_hash) pair, calling this
/// function twice produces identical output.
///
/// Negative test: different keys with the same NormHash produce different
/// SecretHash values.
///
/// Reference: BLAKE3 spec Â§3 (keyed hashing); RFC 2104 (HMAC, for
/// comparison of keyed hash security properties).
pub fn key_secret_hash(key: &TenantSecretKey, norm: &NormHash) -> SecretHash {
    let mut h = blake3::Hasher::new_keyed(key.as_bytes());
    h.update(domain::SECRET_HASH_V1);
    h.update(norm.as_bytes());
    SecretHash::from_bytes_internal(finalize_32(&h))
}

// ---------------------------------------------------------------------------
// Â§4.3 RuleFingerprint â€” content-addressed rule identity
// ---------------------------------------------------------------------------

define_id_32! {
    /// Content-addressed identity of a detection rule.
    ///
    /// Derived from the rule's definition (pattern, configuration, version).
    /// If any aspect of a rule changes that would affect detection output,
    /// the fingerprint MUST change.
    ///
    /// ## Construction
    ///
    /// The engine/policy layer computes this. The contracts crate defines
    /// the type but not the derivation â€” rule structure is engine-internal.
    ///
    /// Example derivation (engine-side):
    /// ```text
    /// RuleFingerprint = blake3("gossip/rule/v1",
    ///     rule_name, rule_version, pattern_bytes, config_bytes)
    /// ```
    ///
    /// ## Role in Finding Model
    ///
    /// `RuleFingerprint` enters `FindingId` derivation. If a rule changes
    /// (new pattern, updated config), the fingerprint changes â†’ new
    /// FindingId â†’ the old finding is no longer produced â†’ the new finding
    /// appears as a fresh detection.
    ///
    /// ## Invariants
    ///
    /// **Safety**: Two rule definitions that produce different detection
    /// outputs MUST have different fingerprints.
    ///
    /// **Safety (stability)**: A rule definition that has NOT changed MUST
    /// produce the same fingerprint across engine versions.
    RuleFingerprint
}

// ---------------------------------------------------------------------------
// Â§4.4 FindingId â€” version-stable finding identity
// ---------------------------------------------------------------------------

define_id_32! {
    /// Deterministic, version-stable identity of a finding.
    ///
    /// A finding represents: "Rule R detected secret S in item I for tenant T."
    ///
    /// `FindingId` is stable across versions of the scanned item. If the
    /// same secret appears in v1 and v2 of a file, it produces the same
    /// `FindingId`. This enables:
    /// - Deduplication across rescans
    /// - Stable triage state (dismissed findings stay dismissed)
    /// - Cross-version tracking
    ///
    /// ## Derivation
    ///
    /// ```text
    /// FindingId = blake3("gossip/finding/v1",
    ///     tenant_id || stable_item_id || rule_fingerprint || secret_hash)
    /// ```
    ///
    /// ## Why each input is included
    ///
    /// - `tenant_id`: Tenant isolation. Same secret in same file scanned
    ///   by two tenants = two distinct findings.
    /// - `stable_item_id`: Item identity. Same secret in two different
    ///   files = two distinct findings.
    /// - `rule_fingerprint`: Rule identity. Same secret detected by two
    ///   different rules = two distinct findings (enables per-rule triage).
    /// - `secret_hash`: Secret identity. Two different secrets in the same
    ///   file detected by the same rule = two distinct findings.
    ///
    /// ## What is NOT included
    ///
    /// - `object_version_id`: Excluded for version stability.
    /// - `byte_offset` / `byte_length`: Excluded for location stability
    ///   (secret may move within a file across versions).
    /// - `PolicyHash`: Not directly included. Rule changes are captured
    ///   via `rule_fingerprint`; hash mode changes are captured via
    ///   `secret_hash` (which changes if keying changes).
    ///
    /// ## Invariants
    ///
    /// **Safety (determinism)**: Pure function of inputs. Same inputs â†’
    /// same FindingId, always.
    ///
    /// **Safety (collision-freedom)**: Distinct input tuples MUST produce
    /// distinct FindingId values (with cryptographic collision resistance).
    ///
    /// **Safety (version-stability)**: The same logical finding across
    /// different versions of an item MUST produce the same FindingId.
    FindingId
}

/// Inputs to `FindingId` derivation, gathered as a struct for clarity.
///
/// All fields are fixed-width, so the canonical encoding is unambiguous
/// without length prefixes (4 Ã— 32 bytes = 128 bytes, deterministic layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingIdInputs {
    pub tenant: TenantId,
    pub item: StableItemId,
    pub rule: RuleFingerprint,
    pub secret: SecretHash,
}

impl CanonicalBytes for FindingIdInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.tenant.write_canonical(h);
        self.item.write_canonical(h);
        self.rule.write_canonical(h);
        self.secret.write_canonical(h);
    }
}

/// Derive a deterministic `FindingId` from its inputs.
///
/// This is a pure function: same inputs always produce the same output.
pub fn derive_finding_id(inputs: &FindingIdInputs) -> FindingId {
    let mut h = domain_hasher(domain::FINDING_ID_V1);
    inputs.write_canonical(&mut h);
    FindingId::from_bytes(finalize_32(&h))
}

// ---------------------------------------------------------------------------
// Â§4.5 OccurrenceId â€” version-specific location identity
// ---------------------------------------------------------------------------

define_id_32! {
    /// Deterministic identity of a specific occurrence of a finding.
    ///
    /// An occurrence represents: "Finding F was observed at byte offset O
    /// with length L in version V of the item."
    ///
    /// Multiple occurrences can exist per finding:
    /// - Same secret at different offsets in the same version
    /// - Same secret at (potentially different) offsets across versions
    ///
    /// ## Derivation
    ///
    /// ```text
    /// OccurrenceId = blake3("gossip/occurrence/v1",
    ///     finding_id || object_version_id || byte_offset || byte_length)
    /// ```
    ///
    /// ## Why each input is included
    ///
    /// - `finding_id`: Links to the parent finding. Encodes tenant, item,
    ///   rule, and secret identity transitively.
    /// - `object_version_id`: Version specificity. Same offset in different
    ///   versions = different occurrences.
    /// - `byte_offset`: Position within the version's content.
    /// - `byte_length`: Extent of the match. Distinguishes overlapping
    ///   matches of different lengths at the same offset (possible with
    ///   regex-based rules).
    ///
    /// ## Invariants
    ///
    /// **Safety (determinism)**: Pure function of inputs.
    ///
    /// **Safety (collision-freedom)**: Distinct input tuples MUST produce
    /// distinct OccurrenceId values (with cryptographic collision resistance).
    OccurrenceId
}

/// Inputs to `OccurrenceId` derivation.
///
/// Mixed-width fields: two `[u8; 32]` (fixed) + two `u64` (fixed).
/// Total: 80 bytes, all fixed-width, no length prefixes needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OccurrenceIdInputs {
    pub finding: FindingId,
    pub version: ObjectVersionId,
    pub byte_offset: u64,
    pub byte_length: u64,
}

impl CanonicalBytes for OccurrenceIdInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.finding.write_canonical(h);
        self.version.write_canonical(h);
        self.byte_offset.write_canonical(h);
        self.byte_length.write_canonical(h);
    }
}

/// Derive a deterministic `OccurrenceId` from its inputs.
///
/// This is a pure function: same inputs always produce the same output.
pub fn derive_occurrence_id(inputs: &OccurrenceIdInputs) -> OccurrenceId {
    let mut h = domain_hasher(domain::OCCURRENCE_ID_V1);
    inputs.write_canonical(&mut h);
    OccurrenceId::from_bytes(finalize_32(&h))
}

// ---------------------------------------------------------------------------
// Â§4.6 Domain constant additions
// ---------------------------------------------------------------------------

// Add to the `domain` module from chunks 1+3:
pub mod domain {
    // ... existing constants from chunks 1+3 ...

    // SECRET_HASH_V1 already declared in chunk 1 as a placeholder.
    // Repeated here for clarity â€” in the real crate this is one module.

    /// SecretHash keying domain tag.
    pub const SECRET_HASH_V1: &[u8] = b"gossip/secret-hash/v1";

    /// FindingId derivation.
    pub const FINDING_ID_V1: &[u8] = b"gossip/finding/v1";

    /// OccurrenceId derivation.
    pub const OCCURRENCE_ID_V1: &[u8] = b"gossip/occurrence/v1";

    /// RuleFingerprint derivation (engine-side, domain tag provided here
    /// for consistency).
    pub const RULE_FINGERPRINT_V1: &[u8] = b"gossip/rule/v1";
}

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test fixtures --

    fn test_tenant_key() -> TenantSecretKey {
        TenantSecretKey::from_bytes([0xAA; 32])
    }

    fn test_tenant_key_alt() -> TenantSecretKey {
        TenantSecretKey::from_bytes([0xBB; 32])
    }

    fn test_norm_hash() -> NormHash {
        NormHash::from_digest([0x11; 32])
    }

    fn test_norm_hash_alt() -> NormHash {
        NormHash::from_digest([0x22; 32])
    }

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_item() -> StableItemId {
        StableItemId::from_bytes([0x02; 32])
    }

    fn test_rule() -> RuleFingerprint {
        RuleFingerprint::from_bytes([0x03; 32])
    }

    fn test_version() -> ObjectVersionId {
        ObjectVersionId::from_bytes([0x04; 32])
    }

    // -- NormHash --

    #[test]
    fn norm_hash_debug_is_redacted() {
        let nh = NormHash::from_digest([0xFF; 32]);
        let dbg = format!("{:?}", nh);
        assert_eq!(dbg, "NormHash([redacted])");
        assert!(!dbg.contains("ff"));
    }

    #[test]
    fn norm_hash_equality() {
        let a = NormHash::from_digest([1u8; 32]);
        let b = NormHash::from_digest([1u8; 32]);
        let c = NormHash::from_digest([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -- SecretHash --

    #[test]
    fn secret_hash_debug_is_redacted() {
        let sh = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let dbg = format!("{:?}", sh);
        assert_eq!(dbg, "SecretHash([redacted])");
    }

    #[test]
    fn secret_hash_deterministic() {
        let key = test_tenant_key();
        let norm = test_norm_hash();
        let h1 = key_secret_hash(&key, &norm);
        let h2 = key_secret_hash(&key, &norm);
        assert_eq!(h1, h2);
    }

    #[test]
    fn secret_hash_different_keys_different_output() {
        let norm = test_norm_hash();
        let h1 = key_secret_hash(&test_tenant_key(), &norm);
        let h2 = key_secret_hash(&test_tenant_key_alt(), &norm);
        assert_ne!(h1, h2);
    }

    #[test]
    fn secret_hash_different_norms_different_output() {
        let key = test_tenant_key();
        let h1 = key_secret_hash(&key, &test_norm_hash());
        let h2 = key_secret_hash(&key, &test_norm_hash_alt());
        assert_ne!(h1, h2);
    }

    // -- RuleFingerprint --

    #[test]
    fn rule_fingerprint_debug_is_safe() {
        let rf = RuleFingerprint::from_bytes([0xDE; 32]);
        let dbg = format!("{:?}", rf);
        assert!(dbg.starts_with("RuleFingerprint("));
        assert!(dbg.contains("dededede"));
        assert!(dbg.len() < 80);
    }

    // -- FindingId --

    #[test]
    fn finding_id_deterministic() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let inputs = FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret,
        };
        let id1 = derive_finding_id(&inputs);
        let id2 = derive_finding_id(&inputs);
        assert_eq!(id1, id2);
    }

    #[test]
    fn finding_id_different_tenant_different_id() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let a = derive_finding_id(&FindingIdInputs {
            tenant: TenantId::from_bytes([0x01; 32]),
            item: test_item(),
            rule: test_rule(),
            secret,
        });
        let b = derive_finding_id(&FindingIdInputs {
            tenant: TenantId::from_bytes([0xFF; 32]),
            item: test_item(),
            rule: test_rule(),
            secret,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_different_item_different_id() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let a = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: StableItemId::from_bytes([0x10; 32]),
            rule: test_rule(),
            secret,
        });
        let b = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: StableItemId::from_bytes([0x20; 32]),
            rule: test_rule(),
            secret,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_different_rule_different_id() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let a = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: RuleFingerprint::from_bytes([0x30; 32]),
            secret,
        });
        let b = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: RuleFingerprint::from_bytes([0x40; 32]),
            secret,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_different_secret_different_id() {
        let s1 = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let s2 = key_secret_hash(&test_tenant_key(), &test_norm_hash_alt());
        let a = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret: s1,
        });
        let b = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret: s2,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_debug_is_safe() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let id = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret,
        });
        let dbg = format!("{:?}", id);
        assert!(dbg.starts_with("FindingId("));
        assert!(dbg.len() < 80);
    }

    // -- OccurrenceId --

    #[test]
    fn occurrence_id_deterministic() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let finding = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret,
        });
        let inputs = OccurrenceIdInputs {
            finding,
            version: test_version(),
            byte_offset: 1024,
            byte_length: 40,
        };
        let id1 = derive_occurrence_id(&inputs);
        let id2 = derive_occurrence_id(&inputs);
        assert_eq!(id1, id2);
    }

    #[test]
    fn occurrence_id_different_version_different_id() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let finding = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret,
        });
        let a = derive_occurrence_id(&OccurrenceIdInputs {
            finding,
            version: ObjectVersionId::from_bytes([0x10; 32]),
            byte_offset: 1024,
            byte_length: 40,
        });
        let b = derive_occurrence_id(&OccurrenceIdInputs {
            finding,
            version: ObjectVersionId::from_bytes([0x20; 32]),
            byte_offset: 1024,
            byte_length: 40,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn occurrence_id_different_offset_different_id() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let finding = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret,
        });
        let a = derive_occurrence_id(&OccurrenceIdInputs {
            finding,
            version: test_version(),
            byte_offset: 100,
            byte_length: 40,
        });
        let b = derive_occurrence_id(&OccurrenceIdInputs {
            finding,
            version: test_version(),
            byte_offset: 200,
            byte_length: 40,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn occurrence_id_different_length_different_id() {
        let secret = key_secret_hash(&test_tenant_key(), &test_norm_hash());
        let finding = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_item(),
            rule: test_rule(),
            secret,
        });
        let a = derive_occurrence_id(&OccurrenceIdInputs {
            finding,
            version: test_version(),
            byte_offset: 1024,
            byte_length: 40,
        });
        let b = derive_occurrence_id(&OccurrenceIdInputs {
            finding,
            version: test_version(),
            byte_offset: 1024,
            byte_length: 80,
        });
        assert_ne!(a, b);
    }

    // -- End-to-end: full derivation chain --

    #[test]
    fn full_derivation_chain_deterministic() {
        // Engine produces NormHash
        let norm = NormHash::from_digest([0x99; 32]);

        // Keying boundary
        let key = TenantSecretKey::from_bytes([0xAA; 32]);
        let secret = key_secret_hash(&key, &norm);

        // Finding derivation
        let finding = derive_finding_id(&FindingIdInputs {
            tenant: TenantId::from_bytes([0x01; 32]),
            item: StableItemId::from_bytes([0x02; 32]),
            rule: RuleFingerprint::from_bytes([0x03; 32]),
            secret,
        });

        // Occurrence derivation
        let occurrence = derive_occurrence_id(&OccurrenceIdInputs {
            finding,
            version: ObjectVersionId::from_bytes([0x04; 32]),
            byte_offset: 512,
            byte_length: 36,
        });

        // Repeat entire chain â€” must be identical.
        let norm2 = NormHash::from_digest([0x99; 32]);
        let secret2 = key_secret_hash(&key, &norm2);
        let finding2 = derive_finding_id(&FindingIdInputs {
            tenant: TenantId::from_bytes([0x01; 32]),
            item: StableItemId::from_bytes([0x02; 32]),
            rule: RuleFingerprint::from_bytes([0x03; 32]),
            secret: secret2,
        });
        let occurrence2 = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding2,
            version: ObjectVersionId::from_bytes([0x04; 32]),
            byte_offset: 512,
            byte_length: 36,
        });

        assert_eq!(secret, secret2);
        assert_eq!(finding, finding2);
        assert_eq!(occurrence, occurrence2);
    }

    // -- Property-based --

    proptest::proptest! {
        #[test]
        fn key_secret_hash_is_pure(
            key_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
            norm_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let key = TenantSecretKey::from_bytes(key_bytes);
            let norm = NormHash::from_digest(norm_bytes);
            let h1 = key_secret_hash(&key, &norm);
            let h2 = key_secret_hash(&key, &norm);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn finding_id_is_pure(
            tenant_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
            item_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
            rule_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
            secret_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let inputs = FindingIdInputs {
                tenant: TenantId::from_bytes(tenant_bytes),
                item: StableItemId::from_bytes(item_bytes),
                rule: RuleFingerprint::from_bytes(rule_bytes),
                secret: SecretHash::from_bytes_internal(secret_bytes),
            };
            let id1 = derive_finding_id(&inputs);
            let id2 = derive_finding_id(&inputs);
            prop_assert_eq!(id1, id2);
        }

        #[test]
        fn occurrence_id_is_pure(
            finding_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
            version_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
            offset in proptest::num::u64::ANY,
            length in proptest::num::u64::ANY,
        ) {
            let inputs = OccurrenceIdInputs {
                finding: FindingId::from_bytes(finding_bytes),
                version: ObjectVersionId::from_bytes(version_bytes),
                byte_offset: offset,
                byte_length: length,
            };
            let id1 = derive_occurrence_id(&inputs);
            let id2 = derive_occurrence_id(&inputs);
            prop_assert_eq!(id1, id2);
        }
    }
}
