//! Secret, finding, and occurrence identity: the types that answer
//! "what secret was found", "where was it found", and "in which version."
//!
//! # Type overview
//!
//! | Type | Width | Construction | Purpose |
//! |------|-------|-------------|---------|
//! | [`NormHash`] | 32 B | `from_digest` (pub) | Normalized secret digest from engine |
//! | [`SecretHash`] | 32 B | `key_secret_hash` | Tenant-scoped secret identity |
//! | [`RuleFingerprint`] | 32 B | `from_bytes` (pub) | Detection rule identity |
//! | [`FindingId`] | 32 B | `derive_finding_id` | Version-stable finding identity |
//! | [`OccurrenceId`] | 32 B | `derive_occurrence_id` | Version-specific occurrence location |
//!
//! # Derivation chain
//!
//! ```text
//! NormHash ─────────┐
//!                   ├─ key_secret_hash ──► SecretHash ──┐
//! TenantSecretKey ──┘                                   │
//!                                                       ├─ derive_finding_id ──► FindingId ──┐
//! TenantId ─────────────────────────────────────────────┤                                    │
//! StableItemId ─────────────────────────────────────────┤                                    │
//! RuleFingerprint ──────────────────────────────────────┘                                    │
//!                                                                                            │
//!                                                       ├─ derive_occurrence_id ──► OccurrenceId
//! ObjectVersionId ──────────────────────────────────────┤
//! byte_offset + byte_length ────────────────────────────┘
//! ```
//!
//! # Construction boundary
//!
//! Types that hold security-sensitive material (`NormHash`, `SecretHash`) use
//! [`define_id_32_restricted!`](crate::define_id_32_restricted) — their constructor is
//! `pub(crate)`, so only derivation functions inside this crate can produce them.
//! All other types use [`define_id_32!`](crate::define_id_32) with a public `from_bytes`
//! constructor.

use blake3::Hasher;

use super::canonical::CanonicalBytes;
use super::domain;
use super::hashing::{FINDING_HASHER, OCCURRENCE_HASHER, derive_from_cached, finalize_32};
use super::item::{ObjectVersionId, StableItemId};
use super::types::{TenantId, TenantSecretKey};

// ---------------------------------------------------------------------------
// NormHash — normalized secret digest
// ---------------------------------------------------------------------------

crate::define_id_32_restricted! {
    /// Digest of the normalized (whitespace-stripped, case-folded) secret
    /// value, computed by the detection engine.
    ///
    /// `NormHash` is the engine's output — it captures *what* was found
    /// before tenant-scoped keying is applied. The engine crate constructs
    /// these via [`NormHash::from_digest`].
    ///
    /// # Invariants
    ///
    /// **Safety**: Two secrets that are semantically identical after
    /// normalization MUST produce the same `NormHash`. Two semantically
    /// different secrets MUST produce different `NormHash` values (with
    /// cryptographic collision resistance).
    NormHash,
    debug_display = "NormHash([redacted])"
}

/// `from_digest` is intentionally `pub` despite `define_id_32_restricted!`
/// hiding the default constructor. The restricted macro's primary value is
/// the redacted `Debug` impl — it prevents accidental logging of
/// security-sensitive material. Public construction via `from_digest` is
/// required because the engine crate is the sole legitimate producer of
/// `NormHash` values and must be able to build them from raw digests.
impl NormHash {
    /// Construct a `NormHash` from a pre-computed 32-byte digest.
    ///
    /// The caller (detection engine) is responsible for computing the
    /// digest from the normalized secret value. This function performs
    /// no additional hashing.
    #[inline]
    pub fn from_digest(bytes: [u8; 32]) -> Self {
        Self::from_bytes_internal(bytes)
    }
}

// ---------------------------------------------------------------------------
// SecretHash — tenant-scoped secret identity
// ---------------------------------------------------------------------------

crate::define_id_32_restricted! {
    /// Tenant-scoped secret identity, derived by keying a [`NormHash`] with
    /// a [`TenantSecretKey`].
    ///
    /// `SecretHash` is what enters [`FindingId`] derivation. Because it is
    /// keyed, the same normalized secret produces different `SecretHash`
    /// values for different tenants — preventing cross-tenant correlation
    /// of secret values.
    ///
    /// # Invariants
    ///
    /// **Safety**: `SecretHash` MUST be a pure function of
    /// `(TenantSecretKey, NormHash)`. Same inputs → same output.
    ///
    /// **Safety**: Different `(key, norm)` pairs MUST produce different
    /// `SecretHash` values (with cryptographic collision resistance).
    SecretHash,
    debug_display = "SecretHash([redacted])"
}

// ---------------------------------------------------------------------------
// RuleFingerprint — detection rule identity
// ---------------------------------------------------------------------------

crate::define_id_32! {
    /// Identity of a detection rule.
    ///
    /// The engine/policy layer computes rule fingerprints externally and
    /// passes them into finding derivation. The contracts crate treats
    /// the value as opaque.
    ///
    /// # Invariants
    ///
    /// **Safety**: The same rule definition MUST always produce the same
    /// `RuleFingerprint`. If a rule's detection semantics change, its
    /// fingerprint MUST change.
    RuleFingerprint
}

// ---------------------------------------------------------------------------
// FindingId — version-stable finding identity
// ---------------------------------------------------------------------------

crate::define_id_32! {
    /// Version-stable finding identity.
    ///
    /// Derived from `(tenant, item, rule, secret_hash)`. Because
    /// `ObjectVersionId` is NOT an input, the same finding persists across
    /// versions of the scanned item — enabling stable triage state.
    ///
    /// # Invariants
    ///
    /// **Safety**: `FindingId` MUST be a pure function of
    /// [`FindingIdInputs`]. Same inputs → same output.
    ///
    /// **Safety**: Distinct inputs MUST produce distinct `FindingId` values
    /// (with cryptographic collision resistance).
    FindingId
}

// ---------------------------------------------------------------------------
// OccurrenceId — version-specific occurrence location
// ---------------------------------------------------------------------------

crate::define_id_32! {
    /// Version-specific occurrence of a finding at a particular location.
    ///
    /// Derived from `(finding, version, byte_offset, byte_length)`. This
    /// ties a [`FindingId`] to a specific version and byte range within
    /// the scanned content.
    ///
    /// # Invariants
    ///
    /// **Safety**: `OccurrenceId` MUST be a pure function of
    /// [`OccurrenceIdInputs`]. Same inputs → same output.
    ///
    /// **Safety**: Distinct inputs MUST produce distinct `OccurrenceId`
    /// values (with cryptographic collision resistance).
    OccurrenceId
}

// ---------------------------------------------------------------------------
// FindingIdInputs
// ---------------------------------------------------------------------------

/// Inputs to [`derive_finding_id`].
///
/// All fields are fixed-width (4 × 32 = 128 bytes), so the canonical
/// encoding writes them sequentially with no length prefixes.
///
/// # Field-ordering invariant
///
/// The [`CanonicalBytes`] impl feeds fields to BLAKE3 in **struct
/// declaration order**.  Reordering fields without updating
/// `write_canonical` silently changes every derived `FindingId` and
/// breaks the golden vectors in `golden.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingIdInputs {
    /// Tenant that owns the scanned item.
    pub tenant: TenantId,
    /// Version-stable identity of the scanned item (repo, bucket, etc.).
    pub item: StableItemId,
    /// Detection rule that matched.
    pub rule: RuleFingerprint,
    /// Tenant-keyed secret identity (post-[`key_secret_hash`], not raw `NormHash`).
    pub secret: SecretHash,
}

impl CanonicalBytes for FindingIdInputs {
    /// Feeds all four 32-byte fields sequentially (128 bytes total, no length
    /// prefixes).
    ///
    /// Field order must match struct declaration order — reordering fields
    /// without updating this impl silently changes all derived IDs and breaks
    /// the golden vectors in `golden.rs`.
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.tenant.write_canonical(h);
        self.item.write_canonical(h);
        self.rule.write_canonical(h);
        self.secret.write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// OccurrenceIdInputs
// ---------------------------------------------------------------------------

/// Inputs to [`derive_occurrence_id`].
///
/// Mixed-width fields (2 × 32 + 2 × 8 = 80 bytes). All fixed-width,
/// so the canonical encoding writes them sequentially with no length
/// prefixes.
///
/// # Field-ordering invariant
///
/// The [`CanonicalBytes`] impl feeds fields to BLAKE3 in **struct
/// declaration order**.  Reordering fields without updating
/// `write_canonical` silently changes every derived `OccurrenceId` and
/// breaks the golden vectors in `golden.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OccurrenceIdInputs {
    /// The version-stable finding this occurrence belongs to.
    pub finding: FindingId,
    /// Specific version of the scanned object (commit SHA, object etag, etc.).
    pub version: ObjectVersionId,
    /// Byte offset of the secret within the scanned content.
    pub byte_offset: u64,
    /// Byte length of the secret within the scanned content.
    pub byte_length: u64,
}

impl CanonicalBytes for OccurrenceIdInputs {
    /// Feeds two 32-byte fields and two 8-byte LE integers (80 bytes total,
    /// no length prefixes).
    ///
    /// Field order must match struct declaration order — reordering fields
    /// without updating this impl silently changes all derived IDs and breaks
    /// the golden vectors in `golden.rs`.
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.finding.write_canonical(h);
        self.version.write_canonical(h);
        self.byte_offset.write_canonical(h);
        self.byte_length.write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Derivation functions
// ---------------------------------------------------------------------------

/// Derive a tenant-scoped [`SecretHash`] from a [`NormHash`] using
/// BLAKE3 keyed mode.
///
/// This is the only derivation that uses keyed mode rather than
/// derive-key mode. The tenant's secret key prevents cross-tenant
/// correlation of normalized secret values.
///
/// # Examples
///
/// ```
/// use gossip_contracts::identity::{TenantSecretKey, NormHash, key_secret_hash};
///
/// let tenant_key = TenantSecretKey::from_bytes([0x42; 32]);
/// let norm = NormHash::from_digest([0xAB; 32]);
/// let secret_hash = key_secret_hash(&tenant_key, &norm);
/// ```
pub fn key_secret_hash(key: &TenantSecretKey, norm: &NormHash) -> SecretHash {
    let mut h = Hasher::new_keyed(key.as_bytes());
    // Domain tag is fed as *data* (not a derive-key context) because the
    // hasher is already in keyed mode. This acts as a context prefix that
    // separates this derivation from any other use of the same tenant key.
    h.update(domain::SECRET_HASH_V1.as_bytes());
    h.update(norm.as_bytes());
    SecretHash::from_bytes_internal(finalize_32(&h))
}

/// Derive a version-stable [`FindingId`] from its inputs.
///
/// Uses BLAKE3 derive-key mode with [`domain::FINDING_ID_V1`].
///
/// # Examples
///
/// ```
/// use gossip_contracts::identity::{
///     TenantId, StableItemId, RuleFingerprint, TenantSecretKey,
///     NormHash, FindingIdInputs, derive_finding_id, key_secret_hash,
/// };
///
/// let secret = key_secret_hash(
///     &TenantSecretKey::from_bytes([0x42; 32]),
///     &NormHash::from_digest([0xAB; 32]),
/// );
/// let inputs = FindingIdInputs {
///     tenant: TenantId::from_bytes([0x01; 32]),
///     item: StableItemId::from_bytes([0x02; 32]),
///     rule: RuleFingerprint::from_bytes([0x03; 32]),
///     secret,
/// };
/// let finding_id = derive_finding_id(&inputs);
/// ```
pub fn derive_finding_id(inputs: &FindingIdInputs) -> FindingId {
    FindingId::from_bytes(derive_from_cached(&FINDING_HASHER, inputs))
}

/// Derive a version-specific [`OccurrenceId`] from its inputs.
///
/// Uses BLAKE3 derive-key mode with [`domain::OCCURRENCE_ID_V1`].
///
/// # Examples
///
/// ```
/// use gossip_contracts::identity::{
///     FindingId, ObjectVersionId, OccurrenceIdInputs, derive_occurrence_id,
/// };
///
/// let inputs = OccurrenceIdInputs {
///     finding: FindingId::from_bytes([0x01; 32]),
///     version: ObjectVersionId::from_bytes([0x02; 32]),
///     byte_offset: 1024,
///     byte_length: 256,
/// };
/// let occurrence_id = derive_occurrence_id(&inputs);
/// ```
pub fn derive_occurrence_id(inputs: &OccurrenceIdInputs) -> OccurrenceId {
    OccurrenceId::from_bytes(derive_from_cached(&OCCURRENCE_HASHER, inputs))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    // -- Debug format safety --

    #[rstest]
    #[case::norm_hash_redacted(format!("{:?}", NormHash::from_digest([0xFF; 32])), "NormHash([redacted])")]
    #[case::secret_hash_redacted(format!("{:?}", SecretHash::from_bytes_internal([0xFF; 32])), "SecretHash([redacted])")]
    fn restricted_types_debug_is_redacted(#[case] actual: String, #[case] expected: &str) {
        assert_eq!(actual, expected);
        assert!(
            !actual.contains("ff"),
            "restricted Debug must not leak hex bytes: {actual}"
        );
    }

    #[rstest]
    #[case::rule_fingerprint(format!("{:?}", RuleFingerprint::from_bytes([0xAB; 32])), "RuleFingerprint")]
    #[case::finding_id(format!("{:?}", FindingId::from_bytes([0xCD; 32])), "FindingId")]
    #[case::occurrence_id(format!("{:?}", OccurrenceId::from_bytes([0xEF; 32])), "OccurrenceId")]
    fn public_types_debug_is_safe(#[case] dbg: String, #[case] name: &str) {
        assert!(
            dbg.starts_with(name),
            "{name} Debug should start with type name, got: {dbg}"
        );
        assert!(
            dbg.len() < 80,
            "{name} Debug too long ({} chars): {dbg}",
            dbg.len()
        );
        assert!(
            dbg.contains(|c: char| c.is_ascii_hexdigit()),
            "{name} Debug should contain hex: {dbg}"
        );
    }

    // -- Property-based --

    proptest::proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        // Cluster 5: Purity

        #[test]
        fn key_secret_hash_is_pure(
            key_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
            norm_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let key = TenantSecretKey::from_bytes(key_bytes);
            let norm = NormHash::from_digest(norm_bytes);
            let a = key_secret_hash(&key, &norm);
            let b = key_secret_hash(&key, &norm);
            proptest::prop_assert_eq!(a, b);
        }

        #[test]
        fn finding_id_is_pure(
            t in proptest::array::uniform32(proptest::num::u8::ANY),
            i in proptest::array::uniform32(proptest::num::u8::ANY),
            r in proptest::array::uniform32(proptest::num::u8::ANY),
            s in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let inputs = FindingIdInputs {
                tenant: TenantId::from_bytes(t),
                item: StableItemId::from_bytes(i),
                rule: RuleFingerprint::from_bytes(r),
                secret: SecretHash::from_bytes_internal(s),
            };
            let a = derive_finding_id(&inputs);
            let b = derive_finding_id(&inputs);
            proptest::prop_assert_eq!(a, b);
        }

        #[test]
        fn occurrence_id_is_pure(
            f in proptest::array::uniform32(proptest::num::u8::ANY),
            v in proptest::array::uniform32(proptest::num::u8::ANY),
            offset in proptest::num::u64::ANY,
            length in proptest::num::u64::ANY,
        ) {
            let inputs = OccurrenceIdInputs {
                finding: FindingId::from_bytes(f),
                version: ObjectVersionId::from_bytes(v),
                byte_offset: offset,
                byte_length: length,
            };
            let a = derive_occurrence_id(&inputs);
            let b = derive_occurrence_id(&inputs);
            proptest::prop_assert_eq!(a, b);
        }

        // Cluster 3: Collision-freedom

        #[test]
        fn secret_hash_collision_free(
            key1 in proptest::array::uniform32(proptest::num::u8::ANY),
            norm1 in proptest::array::uniform32(proptest::num::u8::ANY),
            key2 in proptest::array::uniform32(proptest::num::u8::ANY),
            norm2 in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(key1 != key2 || norm1 != norm2);
            let a = key_secret_hash(
                &TenantSecretKey::from_bytes(key1),
                &NormHash::from_digest(norm1),
            );
            let b = key_secret_hash(
                &TenantSecretKey::from_bytes(key2),
                &NormHash::from_digest(norm2),
            );
            proptest::prop_assert_ne!(a, b);
        }

        #[test]
        fn finding_id_collision_free(
            t1 in proptest::array::uniform32(proptest::num::u8::ANY),
            i1 in proptest::array::uniform32(proptest::num::u8::ANY),
            r1 in proptest::array::uniform32(proptest::num::u8::ANY),
            s1 in proptest::array::uniform32(proptest::num::u8::ANY),
            t2 in proptest::array::uniform32(proptest::num::u8::ANY),
            i2 in proptest::array::uniform32(proptest::num::u8::ANY),
            r2 in proptest::array::uniform32(proptest::num::u8::ANY),
            s2 in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(t1 != t2 || i1 != i2 || r1 != r2 || s1 != s2);
            let a = derive_finding_id(&FindingIdInputs {
                tenant: TenantId::from_bytes(t1),
                item: StableItemId::from_bytes(i1),
                rule: RuleFingerprint::from_bytes(r1),
                secret: SecretHash::from_bytes_internal(s1),
            });
            let b = derive_finding_id(&FindingIdInputs {
                tenant: TenantId::from_bytes(t2),
                item: StableItemId::from_bytes(i2),
                rule: RuleFingerprint::from_bytes(r2),
                secret: SecretHash::from_bytes_internal(s2),
            });
            proptest::prop_assert_ne!(a, b);
        }

        #[test]
        fn occurrence_id_collision_free(
            f1 in proptest::array::uniform32(proptest::num::u8::ANY),
            v1 in proptest::array::uniform32(proptest::num::u8::ANY),
            off1 in proptest::num::u64::ANY,
            len1 in proptest::num::u64::ANY,
            f2 in proptest::array::uniform32(proptest::num::u8::ANY),
            v2 in proptest::array::uniform32(proptest::num::u8::ANY),
            off2 in proptest::num::u64::ANY,
            len2 in proptest::num::u64::ANY,
        ) {
            proptest::prop_assume!(f1 != f2 || v1 != v2 || off1 != off2 || len1 != len2);
            let a = derive_occurrence_id(&OccurrenceIdInputs {
                finding: FindingId::from_bytes(f1),
                version: ObjectVersionId::from_bytes(v1),
                byte_offset: off1,
                byte_length: len1,
            });
            let b = derive_occurrence_id(&OccurrenceIdInputs {
                finding: FindingId::from_bytes(f2),
                version: ObjectVersionId::from_bytes(v2),
                byte_offset: off2,
                byte_length: len2,
            });
            proptest::prop_assert_ne!(a, b);
        }
    }

    // -- Field sensitivity --

    proptest::proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        // FindingId: each field independently affects the output.

        #[test]
        fn finding_id_tenant_field_sensitivity(
            tenant_a in proptest::array::uniform32(proptest::num::u8::ANY),
            tenant_b in proptest::array::uniform32(proptest::num::u8::ANY),
            item in proptest::array::uniform32(proptest::num::u8::ANY),
            rule in proptest::array::uniform32(proptest::num::u8::ANY),
            secret in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(tenant_a != tenant_b);
            let base = FindingIdInputs {
                tenant: TenantId::from_bytes(tenant_a),
                item: StableItemId::from_bytes(item),
                rule: RuleFingerprint::from_bytes(rule),
                secret: SecretHash::from_bytes_internal(secret),
            };
            let varied = FindingIdInputs {
                tenant: TenantId::from_bytes(tenant_b),
                ..base
            };
            proptest::prop_assert_ne!(
                derive_finding_id(&base),
                derive_finding_id(&varied),
            );
        }

        #[test]
        fn finding_id_item_field_sensitivity(
            tenant in proptest::array::uniform32(proptest::num::u8::ANY),
            item_a in proptest::array::uniform32(proptest::num::u8::ANY),
            item_b in proptest::array::uniform32(proptest::num::u8::ANY),
            rule in proptest::array::uniform32(proptest::num::u8::ANY),
            secret in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(item_a != item_b);
            let base = FindingIdInputs {
                tenant: TenantId::from_bytes(tenant),
                item: StableItemId::from_bytes(item_a),
                rule: RuleFingerprint::from_bytes(rule),
                secret: SecretHash::from_bytes_internal(secret),
            };
            let varied = FindingIdInputs {
                item: StableItemId::from_bytes(item_b),
                ..base
            };
            proptest::prop_assert_ne!(
                derive_finding_id(&base),
                derive_finding_id(&varied),
            );
        }

        #[test]
        fn finding_id_rule_field_sensitivity(
            tenant in proptest::array::uniform32(proptest::num::u8::ANY),
            item in proptest::array::uniform32(proptest::num::u8::ANY),
            rule_a in proptest::array::uniform32(proptest::num::u8::ANY),
            rule_b in proptest::array::uniform32(proptest::num::u8::ANY),
            secret in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(rule_a != rule_b);
            let base = FindingIdInputs {
                tenant: TenantId::from_bytes(tenant),
                item: StableItemId::from_bytes(item),
                rule: RuleFingerprint::from_bytes(rule_a),
                secret: SecretHash::from_bytes_internal(secret),
            };
            let varied = FindingIdInputs {
                rule: RuleFingerprint::from_bytes(rule_b),
                ..base
            };
            proptest::prop_assert_ne!(
                derive_finding_id(&base),
                derive_finding_id(&varied),
            );
        }

        #[test]
        fn finding_id_secret_field_sensitivity(
            tenant in proptest::array::uniform32(proptest::num::u8::ANY),
            item in proptest::array::uniform32(proptest::num::u8::ANY),
            rule in proptest::array::uniform32(proptest::num::u8::ANY),
            secret_a in proptest::array::uniform32(proptest::num::u8::ANY),
            secret_b in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(secret_a != secret_b);
            let base = FindingIdInputs {
                tenant: TenantId::from_bytes(tenant),
                item: StableItemId::from_bytes(item),
                rule: RuleFingerprint::from_bytes(rule),
                secret: SecretHash::from_bytes_internal(secret_a),
            };
            let varied = FindingIdInputs {
                secret: SecretHash::from_bytes_internal(secret_b),
                ..base
            };
            proptest::prop_assert_ne!(
                derive_finding_id(&base),
                derive_finding_id(&varied),
            );
        }

        // SecretHash (key_secret_hash): each input independently affects the output.

        #[test]
        fn key_secret_hash_key_sensitivity(
            key_a in proptest::array::uniform32(proptest::num::u8::ANY),
            key_b in proptest::array::uniform32(proptest::num::u8::ANY),
            norm in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(key_a != key_b);
            let a = key_secret_hash(
                &TenantSecretKey::from_bytes(key_a),
                &NormHash::from_digest(norm),
            );
            let b = key_secret_hash(
                &TenantSecretKey::from_bytes(key_b),
                &NormHash::from_digest(norm),
            );
            proptest::prop_assert_ne!(a, b);
        }

        #[test]
        fn key_secret_hash_norm_sensitivity(
            key in proptest::array::uniform32(proptest::num::u8::ANY),
            norm_a in proptest::array::uniform32(proptest::num::u8::ANY),
            norm_b in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(norm_a != norm_b);
            let a = key_secret_hash(
                &TenantSecretKey::from_bytes(key),
                &NormHash::from_digest(norm_a),
            );
            let b = key_secret_hash(
                &TenantSecretKey::from_bytes(key),
                &NormHash::from_digest(norm_b),
            );
            proptest::prop_assert_ne!(a, b);
        }

        // OccurrenceId: each field independently affects the output.

        #[test]
        fn occurrence_id_finding_field_sensitivity(
            finding_a in proptest::array::uniform32(proptest::num::u8::ANY),
            finding_b in proptest::array::uniform32(proptest::num::u8::ANY),
            version in proptest::array::uniform32(proptest::num::u8::ANY),
            offset in proptest::num::u64::ANY,
            length in proptest::num::u64::ANY,
        ) {
            proptest::prop_assume!(finding_a != finding_b);
            let base = OccurrenceIdInputs {
                finding: FindingId::from_bytes(finding_a),
                version: ObjectVersionId::from_bytes(version),
                byte_offset: offset,
                byte_length: length,
            };
            let varied = OccurrenceIdInputs {
                finding: FindingId::from_bytes(finding_b),
                ..base
            };
            proptest::prop_assert_ne!(
                derive_occurrence_id(&base),
                derive_occurrence_id(&varied),
            );
        }

        #[test]
        fn occurrence_id_version_field_sensitivity(
            finding in proptest::array::uniform32(proptest::num::u8::ANY),
            version_a in proptest::array::uniform32(proptest::num::u8::ANY),
            version_b in proptest::array::uniform32(proptest::num::u8::ANY),
            offset in proptest::num::u64::ANY,
            length in proptest::num::u64::ANY,
        ) {
            proptest::prop_assume!(version_a != version_b);
            let base = OccurrenceIdInputs {
                finding: FindingId::from_bytes(finding),
                version: ObjectVersionId::from_bytes(version_a),
                byte_offset: offset,
                byte_length: length,
            };
            let varied = OccurrenceIdInputs {
                version: ObjectVersionId::from_bytes(version_b),
                ..base
            };
            proptest::prop_assert_ne!(
                derive_occurrence_id(&base),
                derive_occurrence_id(&varied),
            );
        }

        #[test]
        fn occurrence_id_offset_field_sensitivity(
            finding in proptest::array::uniform32(proptest::num::u8::ANY),
            version in proptest::array::uniform32(proptest::num::u8::ANY),
            offset_a in proptest::num::u64::ANY,
            offset_b in proptest::num::u64::ANY,
            length in proptest::num::u64::ANY,
        ) {
            proptest::prop_assume!(offset_a != offset_b);
            let base = OccurrenceIdInputs {
                finding: FindingId::from_bytes(finding),
                version: ObjectVersionId::from_bytes(version),
                byte_offset: offset_a,
                byte_length: length,
            };
            let varied = OccurrenceIdInputs {
                byte_offset: offset_b,
                ..base
            };
            proptest::prop_assert_ne!(
                derive_occurrence_id(&base),
                derive_occurrence_id(&varied),
            );
        }

        #[test]
        fn occurrence_id_length_field_sensitivity(
            finding in proptest::array::uniform32(proptest::num::u8::ANY),
            version in proptest::array::uniform32(proptest::num::u8::ANY),
            offset in proptest::num::u64::ANY,
            length_a in proptest::num::u64::ANY,
            length_b in proptest::num::u64::ANY,
        ) {
            proptest::prop_assume!(length_a != length_b);
            let base = OccurrenceIdInputs {
                finding: FindingId::from_bytes(finding),
                version: ObjectVersionId::from_bytes(version),
                byte_offset: offset,
                byte_length: length_a,
            };
            let varied = OccurrenceIdInputs {
                byte_length: length_b,
                ..base
            };
            proptest::prop_assert_ne!(
                derive_occurrence_id(&base),
                derive_occurrence_id(&varied),
            );
        }
    }

    // -- Field-order swap tests --
    //
    // These catch bugs where two same-width fields are swapped in
    // `write_canonical` without changing the struct declaration order.
    // With uniform fill bytes, a swap silently produces the same hash;
    // with distinct fill bytes per field, a swap changes the hash.

    #[test]
    fn finding_id_inputs_field_order_matters() {
        let inputs_a = FindingIdInputs {
            tenant: TenantId::from_bytes([0x11; 32]),
            item: StableItemId::from_bytes([0x22; 32]),
            rule: RuleFingerprint::from_bytes([0x33; 32]),
            secret: SecretHash::from_bytes_internal([0x44; 32]),
        };
        let inputs_b = FindingIdInputs {
            tenant: TenantId::from_bytes([0x22; 32]),   // was item
            item: StableItemId::from_bytes([0x11; 32]), // was tenant
            rule: RuleFingerprint::from_bytes([0x33; 32]),
            secret: SecretHash::from_bytes_internal([0x44; 32]),
        };
        assert_ne!(derive_finding_id(&inputs_a), derive_finding_id(&inputs_b));
    }

    #[test]
    fn occurrence_id_inputs_field_order_matters() {
        let inputs_a = OccurrenceIdInputs {
            finding: FindingId::from_bytes([0x55; 32]),
            version: ObjectVersionId::from_bytes([0x66; 32]),
            byte_offset: 100,
            byte_length: 200,
        };
        let inputs_b = OccurrenceIdInputs {
            finding: FindingId::from_bytes([0x55; 32]),
            version: ObjectVersionId::from_bytes([0x66; 32]),
            byte_offset: 200, // swapped
            byte_length: 100, // swapped
        };
        assert_ne!(
            derive_occurrence_id(&inputs_a),
            derive_occurrence_id(&inputs_b)
        );
    }
}
