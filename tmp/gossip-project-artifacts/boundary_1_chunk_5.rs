//! Boundary â‘  â€” Identity Spine: Chunk 5 (DRAFT)
//!
//! PolicyHash v2: structured inputs that determine when a rescan is forced.
//!
//! This file is additive to chunks 1â€“4. It uses `CanonicalBytes`,
//! `define_id_32!`, `domain_hasher`, `finalize_32`, and `PolicyHash`
//! from prior chunks.
//!
//! ## Design Decisions (locked)
//!
//! D5a: Rule set represented as a single `rules_digest: [u8; 32]`
//!      computed externally by the engine/policy layer. Contracts crate
//!      does not interpret rule structure.
//!
//! D5b: `id_hash_mode` is a `u8` discriminant (0=unkeyed, 1=keyed_v1),
//!      extensible for future modes.
//!
//! D5c: PolicyHash is tenant-independent. Tenant isolation is enforced
//!      at the query boundary, not embedded in the policy digest.
//!
//! D5d: `policy_hash_version` starts at 1. Bumping it forces global
//!      rescan â€” the nuclear option for scheme changes.
//!
//! ## Key Invariant
//!
//! **Safety**: Two runs with the same PolicyHash MUST produce identical
//! findings for identical input. Equivalently: if any input that affects
//! detection output identity changes, PolicyHash MUST change.
//!
//! The conservative direction is safe: if PolicyHash changes when it
//! didn't need to, we rescan unnecessarily. If PolicyHash fails to
//! change when it should, we skip items that need rescanning â€” a
//! correctness violation.
//!
//! Reference: Â§1.2 â€” Correctness Over Performance.

// Assumes these are in scope from prior chunks:
// use crate::{CanonicalBytes, domain_hasher, finalize_32, PolicyHash, Hasher};

// ============================================================================
// Â§ Chunk 5: PolicyHash v2
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.1 IdHashMode â€” keyed vs unkeyed secret hashing discriminant
// ---------------------------------------------------------------------------

/// Discriminant for how secret identity hashes are computed.
///
/// This enters `PolicyHash` derivation to ensure that a change in hashing
/// mode forces rescan. Without this, switching from unkeyed to keyed
/// hashing would leave stale findings that can't be correlated with new
/// ones (different `SecretHash` values for the same secret).
///
/// ## Encoding
///
/// Stored as a `u8` for compact canonical encoding. New modes are added
/// as new discriminant values â€” existing values MUST NOT be reused or
/// reordered.
///
/// ## Invariants
///
/// **Safety**: If the hashing mode changes, `PolicyHash` MUST change.
/// This type is the mechanism that ensures it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IdHashMode {
    /// Unkeyed: `SecretHash = blake3(normalized_secret_bytes)`.
    /// No tenant isolation in the hash. Suitable for single-tenant
    /// deployments or development.
    Unkeyed = 0,

    /// Keyed v1: `SecretHash = blake3_keyed(tenant_key, domain || norm_hash)`.
    /// Per-tenant isolation via BLAKE3 keyed mode.
    /// Reference: BLAKE3 spec Â§3.
    KeyedV1 = 1,
}

impl IdHashMode {
    /// Convert from raw `u8`, returning `None` for unknown discriminants.
    ///
    /// This is used during deserialization. Unknown modes are treated as
    /// a schema evolution signal â€” the caller must decide whether to
    /// reject or handle gracefully.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unkeyed),
            1 => Some(Self::KeyedV1),
            _ => None,
        }
    }

    /// The raw discriminant value.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for IdHashMode {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_u8().write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§5.2 PolicyHashInputs â€” structured inputs to PolicyHash derivation
// ---------------------------------------------------------------------------

/// All inputs that affect detection output identity, gathered into a
/// single struct for PolicyHash derivation.
///
/// ## Field Semantics
///
/// Every field answers: "if this changes, would the same input produce
/// different findings?" If yes, it MUST be included. If unsure, include
/// it â€” unnecessary rescans are safe, missed rescans are not.
///
/// ## CanonicalBytes Encoding
///
/// Fields are encoded in declaration order:
/// ```text
/// policy_hash_version : u32  (4 bytes, LE)
/// id_hash_mode        : u8   (1 byte)
/// evidence_hash_version : u32  (4 bytes, LE)
/// rules_digest        : [u8; 32] (32 bytes, fixed)
/// ```
/// Total: 41 bytes, all fixed-width, no length prefixes needed.
///
/// ## Invariants
///
/// **Safety (completeness)**: This struct MUST include every input that
/// affects whether two runs produce the same findings for the same input.
/// Missing an input here means PolicyHash won't change when it should,
/// leading to incorrect skip decisions.
///
/// **Safety (determinism)**: `compute_policy_hash` is a pure function
/// of these inputs. Same inputs â†’ same PolicyHash, always.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyHashInputs {
    /// Version of the PolicyHash derivation scheme itself.
    ///
    /// Bump this to force global rescan when the derivation changes
    /// (e.g., adding a new field, changing encoding order). This is
    /// the nuclear option â€” use sparingly.
    ///
    /// Starting value: `1`.
    pub policy_hash_version: u32,

    /// How secret identity hashes are computed (keyed vs unkeyed).
    ///
    /// Changing this forces rescan because `SecretHash` values for the
    /// same secret will differ under different modes, making old
    /// findings non-reconstructible.
    pub id_hash_mode: IdHashMode,

    /// Version of the evidence normalization and hashing pipeline.
    ///
    /// The engine normalizes raw secret bytes before hashing (strip
    /// whitespace, remove prefixes, lowercase, etc.). If the
    /// normalization logic changes, `NormHash` values change for the
    /// same raw secret â†’ `SecretHash` changes â†’ findings change.
    ///
    /// Bump this when:
    /// - The normalization function changes
    /// - The set of inputs to NormHash changes
    /// - The hashing algorithm for NormHash changes (unlikely â€” BLAKE3)
    ///
    /// Starting value: `1`.
    pub evidence_hash_version: u32,

    /// Content-addressed digest of the complete rule set and configuration.
    ///
    /// Computed by the engine/policy layer as:
    /// ```text
    /// rules_digest = blake3("gossip/rules-digest/v1",
    ///     for each rule sorted by fingerprint:
    ///         rule_fingerprint || rule_config_bytes)
    /// ```
    ///
    /// The contracts crate does NOT interpret this â€” it's an opaque
    /// 32-byte digest. The engine is responsible for:
    /// - Including all rules that affect detection output
    /// - Sorting rules deterministically (by fingerprint) before hashing
    /// - Including rule configuration that affects output
    ///
    /// If any rule is added, removed, or reconfigured, this digest
    /// changes â†’ PolicyHash changes â†’ rescan.
    pub rules_digest: [u8; 32],
}

impl PolicyHashInputs {
    /// Current policy hash version. Bump on scheme changes.
    pub const CURRENT_VERSION: u32 = 1;

    /// Current evidence hash version. Bump on normalization changes.
    pub const CURRENT_EVIDENCE_VERSION: u32 = 1;
}

impl CanonicalBytes for PolicyHashInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.policy_hash_version.write_canonical(h);
        self.id_hash_mode.write_canonical(h);
        self.evidence_hash_version.write_canonical(h);
        self.rules_digest.write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§5.3 PolicyHash derivation function
// ---------------------------------------------------------------------------

/// Domain tag for PolicyHash v2 derivation.
pub mod domain {
    // ... existing constants from chunks 1, 3, 4 ...

    /// PolicyHash derivation from PolicyHashInputs.
    pub const POLICY_HASH_V2: &[u8] = b"gossip/policy-hash/v2";

    /// Rules digest derivation (engine-side, domain tag provided here
    /// for consistency).
    pub const RULES_DIGEST_V1: &[u8] = b"gossip/rules-digest/v1";
}

/// Derive a `PolicyHash` from structured inputs.
///
/// This is a pure function: same inputs always produce the same output.
///
/// ## When to call
///
/// Called once at the start of a scan job to compute the policy identity.
/// The result is stored in `RunId` and used for all skip/dedupe decisions
/// throughout the job's lifetime.
///
/// ## Invariants
///
/// **Safety (determinism)**: Pure function of `PolicyHashInputs`.
///
/// **Safety (collision-freedom)**: Distinct inputs MUST produce distinct
/// PolicyHash values (with cryptographic collision resistance).
///
/// ## Verification Strategy
///
/// - Property-based: same inputs â†’ same output (purity).
/// - Negative tests: changing any single field â†’ different output.
/// - Golden test: pin a known input â†’ known output to detect accidental
///   encoding changes across versions.
pub fn compute_policy_hash(inputs: &PolicyHashInputs) -> PolicyHash {
    let mut h = domain_hasher(domain::POLICY_HASH_V2);
    inputs.write_canonical(&mut h);
    PolicyHash::from_bytes(finalize_32(&h))
}

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test fixtures --

    fn base_inputs() -> PolicyHashInputs {
        PolicyHashInputs {
            policy_hash_version: PolicyHashInputs::CURRENT_VERSION,
            id_hash_mode: IdHashMode::KeyedV1,
            evidence_hash_version: PolicyHashInputs::CURRENT_EVIDENCE_VERSION,
            rules_digest: [0xAA; 32],
        }
    }

    // -- IdHashMode --

    #[test]
    fn id_hash_mode_roundtrip() {
        assert_eq!(IdHashMode::from_u8(0), Some(IdHashMode::Unkeyed));
        assert_eq!(IdHashMode::from_u8(1), Some(IdHashMode::KeyedV1));
        assert_eq!(IdHashMode::from_u8(2), None);
        assert_eq!(IdHashMode::from_u8(255), None);
    }

    #[test]
    fn id_hash_mode_discriminants_are_stable() {
        // These values are persisted â€” they must never change.
        assert_eq!(IdHashMode::Unkeyed.as_u8(), 0);
        assert_eq!(IdHashMode::KeyedV1.as_u8(), 1);
    }

    #[test]
    fn id_hash_mode_canonical_bytes_distinct() {
        let mut h_unkeyed = Hasher::new();
        let mut h_keyed = Hasher::new();
        IdHashMode::Unkeyed.write_canonical(&mut h_unkeyed);
        IdHashMode::KeyedV1.write_canonical(&mut h_keyed);
        assert_ne!(h_unkeyed.finalize(), h_keyed.finalize());
    }

    // -- PolicyHash derivation: determinism --

    #[test]
    fn policy_hash_deterministic() {
        let inputs = base_inputs();
        let h1 = compute_policy_hash(&inputs);
        let h2 = compute_policy_hash(&inputs);
        assert_eq!(h1, h2);
    }

    // -- PolicyHash derivation: sensitivity to each field --

    #[test]
    fn policy_hash_sensitive_to_version() {
        let a = compute_policy_hash(&PolicyHashInputs {
            policy_hash_version: 1,
            ..base_inputs()
        });
        let b = compute_policy_hash(&PolicyHashInputs {
            policy_hash_version: 2,
            ..base_inputs()
        });
        assert_ne!(a, b);
    }

    #[test]
    fn policy_hash_sensitive_to_hash_mode() {
        let a = compute_policy_hash(&PolicyHashInputs {
            id_hash_mode: IdHashMode::Unkeyed,
            ..base_inputs()
        });
        let b = compute_policy_hash(&PolicyHashInputs {
            id_hash_mode: IdHashMode::KeyedV1,
            ..base_inputs()
        });
        assert_ne!(a, b);
    }

    #[test]
    fn policy_hash_sensitive_to_evidence_version() {
        let a = compute_policy_hash(&PolicyHashInputs {
            evidence_hash_version: 1,
            ..base_inputs()
        });
        let b = compute_policy_hash(&PolicyHashInputs {
            evidence_hash_version: 2,
            ..base_inputs()
        });
        assert_ne!(a, b);
    }

    #[test]
    fn policy_hash_sensitive_to_rules_digest() {
        let a = compute_policy_hash(&PolicyHashInputs {
            rules_digest: [0xAA; 32],
            ..base_inputs()
        });
        let b = compute_policy_hash(&PolicyHashInputs {
            rules_digest: [0xBB; 32],
            ..base_inputs()
        });
        assert_ne!(a, b);
    }

    // -- Golden test: detect accidental encoding changes --

    #[test]
    fn policy_hash_golden_value() {
        // Pin a specific input to a specific output. If this test fails,
        // the encoding has changed â€” either intentionally (bump
        // policy_hash_version) or accidentally (fix the bug).
        let inputs = PolicyHashInputs {
            policy_hash_version: 1,
            id_hash_mode: IdHashMode::KeyedV1,
            evidence_hash_version: 1,
            rules_digest: [0u8; 32],
        };
        let hash = compute_policy_hash(&inputs);

        // This value was computed once and pinned. If the derivation
        // function changes, this test catches it.
        //
        // To regenerate after an intentional change:
        //   let hash = compute_policy_hash(&inputs);
        //   eprintln!("new golden: {:02x?}", hash.as_bytes());
        //
        // NOTE: The actual golden value must be filled in after the
        // first run. Placeholder assertion checks non-zero output.
        assert_ne!(*hash.as_bytes(), [0u8; 32], "derivation produced zero hash");

        // TODO: Replace with pinned value after first run:
        // assert_eq!(hash.as_bytes(), &[...]);
    }

    // -- PolicyHashInputs CanonicalBytes --

    #[test]
    fn policy_hash_inputs_canonical_bytes_deterministic() {
        let inputs = base_inputs();
        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();
        inputs.write_canonical(&mut h1);
        inputs.write_canonical(&mut h2);
        assert_eq!(h1.finalize(), h2.finalize());
    }

    // -- Property-based --

    proptest::proptest! {
        #[test]
        fn policy_hash_is_pure(
            version in proptest::num::u32::ANY,
            mode_byte in 0u8..=1,
            evidence_version in proptest::num::u32::ANY,
            rules in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let mode = IdHashMode::from_u8(mode_byte).unwrap();
            let inputs = PolicyHashInputs {
                policy_hash_version: version,
                id_hash_mode: mode,
                evidence_hash_version: evidence_version,
                rules_digest: rules,
            };
            let h1 = compute_policy_hash(&inputs);
            let h2 = compute_policy_hash(&inputs);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn policy_hash_inputs_canonical_bytes_stable(
            version in proptest::num::u32::ANY,
            mode_byte in 0u8..=1,
            evidence_version in proptest::num::u32::ANY,
            rules in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let mode = IdHashMode::from_u8(mode_byte).unwrap();
            let inputs = PolicyHashInputs {
                policy_hash_version: version,
                id_hash_mode: mode,
                evidence_hash_version: evidence_version,
                rules_digest: rules,
            };
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            inputs.write_canonical(&mut h1);
            inputs.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }
    }
}
