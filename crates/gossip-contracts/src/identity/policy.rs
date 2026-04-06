//! Policy-hash derivation: the mechanism that answers "do I need to rescan
//! this item?"
//!
//! A `PolicyHash` is a cryptographic digest of every input that affects
//! detection output identity. If any input changes, the hash changes, and a
//! rescan is required.
//!
//! # Type overview
//!
//! | Type | Width | Construction | Purpose |
//! |------|-------|-------------|---------|
//! | [`IdHashMode`] | 1 B | `from_u8` / variant literal | Keyed vs. unkeyed hashing selector |
//! | [`PolicyHashInputs`] | 41 B | struct literal | Structured inputs to the derivation |
//!
//! # Derivation
//!
//! ```text
//! policy_hash_version (u32) ──┐
//! id_hash_mode (u8)        ───┤
//! evidence_hash_version (u32) ┤── compute_policy_hash ──► PolicyHash
//! rules_digest ([u8; 32])  ───┘
//! ```

use blake3::Hasher;

use super::canonical::CanonicalBytes;
use super::hashing::{POLICY_HASH_HASHER, derive_from_cached};
use super::types::PolicyHash;

/// Selects the identity-hashing mode for secret derivation.
///
/// `Unkeyed` uses a single global hash (no tenant isolation); `KeyedV1` uses
/// per-tenant keyed hashing via [`TenantSecretKey`](super::types::TenantSecretKey).
///
/// The `#[repr(u8)]` layout with explicit discriminants guarantees stable
/// wire encoding. Adding a new variant requires a new discriminant — the
/// compiler prevents duplicate values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IdHashMode {
    /// No tenant-scoped keying. All tenants share one hash domain.
    Unkeyed = 0,
    /// Per-tenant keyed hashing (BLAKE3 keyed mode with `TenantSecretKey`).
    KeyedV1 = 1,
}

impl IdHashMode {
    /// Convert from a raw `u8` discriminant, returning `None` for unknown
    /// values.  Currently only `0` ([`Unkeyed`](Self::Unkeyed)) and `1`
    /// ([`KeyedV1`](Self::KeyedV1)) are recognized; all other values
    /// return `None`.
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unkeyed),
            1 => Some(Self::KeyedV1),
            _ => None,
        }
    }

    /// Return the stable `u8` discriminant.
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for IdHashMode {
    /// Encodes as a single byte (the `#[repr(u8)]` discriminant), which is
    /// self-framing and needs no length prefix.
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_u8().write_canonical(h);
    }
}

/// Current schema version for [`PolicyHashInputs`].
///
/// Bumping this value changes every derived `PolicyHash`, which in turn
/// invalidates all existing skip/dedupe decisions and forces a full rescan
/// across all tenants.  Only bump when the derivation algorithm itself
/// changes (not when individual rules change -- that is captured by
/// `rules_digest`).
pub const CURRENT_VERSION: u32 = 1;

/// Current evidence-hash version.
///
/// Bump this when the normalization or input pipeline changes in a way
/// that affects hash output (e.g., changing how whitespace is
/// canonicalized before hashing).  Like [`CURRENT_VERSION`], bumping
/// this invalidates all derived `PolicyHash` values and forces rescans.
pub const CURRENT_EVIDENCE_VERSION: u32 = 1;

super::macros::define_canonical_input! {
    /// Structured inputs to [`compute_policy_hash`].
    ///
    /// The canonical encoding is 41 bytes: `u32` (4) + `u8` (1) + `u32` (4) +
    /// `[u8; 32]` (32). All fields are fixed-width, so no length prefixes are
    /// needed.
    ///
    /// # Field-ordering invariant
    ///
    /// The [`CanonicalBytes`](crate::identity::CanonicalBytes) impl is
    /// generated from this declaration, so hash order follows **struct
    /// declaration order** automatically. Reordering fields is therefore a
    /// breaking change: it changes every derived `PolicyHash` and breaks the
    /// golden vectors in `golden.rs`.
    pub struct PolicyHashInputs {
        /// Schema version of the policy-hash derivation itself.
        pub policy_hash_version: u32,
        /// Keyed vs. unkeyed hashing mode.
        pub id_hash_mode: IdHashMode,
        /// Version of the evidence normalization / input pipeline.
        pub evidence_hash_version: u32,
        /// Content-addressed digest of the full rule set.
        pub rules_digest: [u8; 32],
    }
}

/// Derive a [`PolicyHash`] from its structured inputs.
///
/// Uses BLAKE3 derive-key mode with [`super::domain::POLICY_HASH_V2`].
/// Internally clones a cached hasher (`hashing::POLICY_HASH_HASHER`)
/// to avoid re-running the BLAKE3 key-schedule setup on every call.
///
/// # Invariants
///
/// **Purity**: `compute_policy_hash` is a pure function of `inputs`.
/// Same inputs always produce the same output.
///
/// **Collision resistance**: Distinct `PolicyHashInputs` produce distinct
/// `PolicyHash` values (with cryptographic collision resistance from BLAKE3).
///
/// # Examples
///
/// ```
/// use gossip_contracts::identity::{
///     compute_policy_hash, PolicyHashInputs, IdHashMode,
///     CURRENT_VERSION, CURRENT_EVIDENCE_VERSION,
/// };
///
/// let inputs = PolicyHashInputs {
///     policy_hash_version: CURRENT_VERSION,
///     id_hash_mode: IdHashMode::KeyedV1,
///     evidence_hash_version: CURRENT_EVIDENCE_VERSION,
///     rules_digest: [0xAA; 32],
/// };
/// let hash = compute_policy_hash(&inputs);
/// ```
pub fn compute_policy_hash(inputs: &PolicyHashInputs) -> PolicyHash {
    PolicyHash::from_bytes(derive_from_cached(&POLICY_HASH_HASHER, inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- IdHashMode discriminant stability --

    #[test]
    fn id_hash_mode_discriminants_are_stable() {
        assert_eq!(IdHashMode::Unkeyed.as_u8(), 0);
        assert_eq!(IdHashMode::KeyedV1.as_u8(), 1);
    }

    #[test]
    fn id_hash_mode_roundtrip() {
        for v in 0u8..=1 {
            let mode = IdHashMode::from_u8(v).unwrap();
            assert_eq!(mode.as_u8(), v);
        }
    }

    #[test]
    fn id_hash_mode_unknown_returns_none() {
        for v in 2u8..=255 {
            assert!(
                IdHashMode::from_u8(v).is_none(),
                "from_u8({v}) should be None"
            );
        }
    }

    // -- Property-based --

    proptest::proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        // Purity: same inputs → same output.
        #[test]
        fn compute_policy_hash_is_pure(
            version in proptest::num::u32::ANY,
            mode_byte in 0u8..=1u8,
            ev_version in proptest::num::u32::ANY,
            digest in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let inputs = PolicyHashInputs {
                policy_hash_version: version,
                id_hash_mode: IdHashMode::from_u8(mode_byte).unwrap(),
                evidence_hash_version: ev_version,
                rules_digest: digest,
            };
            let a = compute_policy_hash(&inputs);
            let b = compute_policy_hash(&inputs);
            proptest::prop_assert_eq!(a, b);
        }

        // Field sensitivity: flipping any single field changes the output.
        #[test]
        fn policy_hash_version_field_sensitivity(
            version_a in proptest::num::u32::ANY,
            version_b in proptest::num::u32::ANY,
            digest in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(version_a != version_b);
            let base = PolicyHashInputs {
                policy_hash_version: version_a,
                id_hash_mode: IdHashMode::KeyedV1,
                evidence_hash_version: 1,
                rules_digest: digest,
            };
            let varied = PolicyHashInputs {
                policy_hash_version: version_b,
                ..base
            };
            proptest::prop_assert_ne!(
                compute_policy_hash(&base),
                compute_policy_hash(&varied)
            );
        }

        #[test]
        fn id_hash_mode_field_sensitivity(
            digest in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let base = PolicyHashInputs {
                policy_hash_version: 1,
                id_hash_mode: IdHashMode::Unkeyed,
                evidence_hash_version: 1,
                rules_digest: digest,
            };
            let varied = PolicyHashInputs {
                id_hash_mode: IdHashMode::KeyedV1,
                ..base
            };
            proptest::prop_assert_ne!(
                compute_policy_hash(&base),
                compute_policy_hash(&varied)
            );
        }

        #[test]
        fn evidence_hash_version_field_sensitivity(
            ev_a in proptest::num::u32::ANY,
            ev_b in proptest::num::u32::ANY,
            digest in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(ev_a != ev_b);
            let base = PolicyHashInputs {
                policy_hash_version: 1,
                id_hash_mode: IdHashMode::KeyedV1,
                evidence_hash_version: ev_a,
                rules_digest: digest,
            };
            let varied = PolicyHashInputs {
                evidence_hash_version: ev_b,
                ..base
            };
            proptest::prop_assert_ne!(
                compute_policy_hash(&base),
                compute_policy_hash(&varied)
            );
        }

        #[test]
        fn rules_digest_field_sensitivity(
            digest_a in proptest::array::uniform32(proptest::num::u8::ANY),
            digest_b in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(digest_a != digest_b);
            let base = PolicyHashInputs {
                policy_hash_version: 1,
                id_hash_mode: IdHashMode::KeyedV1,
                evidence_hash_version: 1,
                rules_digest: digest_a,
            };
            let varied = PolicyHashInputs {
                rules_digest: digest_b,
                ..base
            };
            proptest::prop_assert_ne!(
                compute_policy_hash(&base),
                compute_policy_hash(&varied)
            );
        }

        // Collision-freedom: distinct inputs → distinct outputs.
        // Weaker than the per-field sensitivity tests above: requires only that
        // *some* field differs, not that *each individual* field is sensitive.
        #[test]
        fn policy_hash_collision_free(
            ver_a in proptest::num::u32::ANY,
            mode_a in 0u8..=1u8,
            ev_a in proptest::num::u32::ANY,
            dig_a in proptest::array::uniform32(proptest::num::u8::ANY),
            ver_b in proptest::num::u32::ANY,
            mode_b in 0u8..=1u8,
            ev_b in proptest::num::u32::ANY,
            dig_b in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            proptest::prop_assume!(ver_a != ver_b || mode_a != mode_b || ev_a != ev_b || dig_a != dig_b);
            let a = compute_policy_hash(&PolicyHashInputs {
                policy_hash_version: ver_a,
                id_hash_mode: IdHashMode::from_u8(mode_a).unwrap(),
                evidence_hash_version: ev_a,
                rules_digest: dig_a,
            });
            let b = compute_policy_hash(&PolicyHashInputs {
                policy_hash_version: ver_b,
                id_hash_mode: IdHashMode::from_u8(mode_b).unwrap(),
                evidence_hash_version: ev_b,
                rules_digest: dig_b,
            });
            proptest::prop_assert_ne!(a, b);
        }
    }

    // -- Field-order swap test --

    #[test]
    fn policy_hash_inputs_field_order_matters() {
        let inputs_a = PolicyHashInputs {
            policy_hash_version: 1,
            id_hash_mode: IdHashMode::KeyedV1,
            evidence_hash_version: 2,
            rules_digest: [0xAA; 32],
        };
        let inputs_b = PolicyHashInputs {
            policy_hash_version: 2,
            id_hash_mode: IdHashMode::KeyedV1,
            evidence_hash_version: 1,
            rules_digest: [0xAA; 32],
        };
        assert_ne!(
            compute_policy_hash(&inputs_a),
            compute_policy_hash(&inputs_b)
        );
    }
}
