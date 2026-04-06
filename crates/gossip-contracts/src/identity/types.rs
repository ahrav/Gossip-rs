//! Core identity primitives: `TenantId`, `PolicyHash`, and `TenantSecretKey`.
//!
//! # Purpose
//! These three types form the root of the identity type hierarchy. All other
//! identity types (items, findings, occurrences, policy hashes) depend on at
//! least one of them. They provide multi-tenant isolation, cryptographic policy
//! digesting, and per-tenant secret keying.
//!
//! | Type | Width | Construction | `CanonicalBytes` | Use case |
//! |------|-------|-------------|-----------------|----------|
//! | [`TenantId`] | 32 B | public | yes | Multi-tenant isolation boundary |
//! | [`PolicyHash`] | 32 B | public | yes | Cryptographic policy digest |
//! | [`TenantSecretKey`] | 32 B | public | **no** | Per-tenant secret for keyed hashing |
//!
//! # Invariants
//! * Tenant boundaries are cryptographically enforced by `TenantSecretKey` during `SecretHash` derivation.
//! * Identity stability requires that semantic changes to rules must result in a `PolicyHash` change.
//!
//! # Algorithm
//! Primitive structures wrap raw byte arrays and expose only the minimal trait surface area required.
//! `TenantId` and `PolicyHash` inherit structural traits, while `TenantSecretKey` uses constant-time equality comparisons.
//!
//! # Design Trade-offs
//! * `TenantSecretKey` deliberately omits `Ord`, `Hash`, and `CanonicalBytes` to prevent accidental misuse in sorted collections, map keys, or content-addressed IDs.
//! * `TenantSecretKey` implements `Copy` instead of `Zeroize` on drop. This avoids borrow-lifetime entanglement at the cost of stack copies persisting, which is acceptable because the key is tenant-scoped and re-provisionable rather than a global root secret, and process-memory threats are out-of-scope for this defense depth.

crate::define_id_32! {
    /// Stable tenant identity. Top of the isolation hierarchy.
    ///
    /// # Purpose
    /// Serves as the primary multi-tenant isolation boundary. In production, this is typically derived from an external tenant identifier (e.g., `blake3(external_tenant_uuid)` to normalize width).
    ///
    /// # Invariants
    /// * **Safety**: A shard record for tenant A must never be readable or writable by a request scoped to tenant B. The coordination layer enforces this by requiring `TenantId` at every API boundary.
    /// * **Safety**: `TenantId` is an input to `SecretHash` keying (via `TenantSecretKey`) and `FindingId` derivation. It enters `OccurrenceId` derivation transitively through `FindingId`. Changing a tenant's ID invalidates all derived hashes.
    TenantId
}

crate::define_id_32! {
    /// Cryptographic digest of rules, configuration, and output identity semantics.
    ///
    /// # Purpose
    /// Serves as the join key for skip/dedupe decisions across detection runs.
    /// It must include all inputs that affect detection output identity:
    ///
    /// - `policy_hash_version`: scheme version (for forced rescan on upgrade)
    /// - `id_hash_mode`: keyed vs unkeyed hashing
    /// - `evidence_hash_version`: normalization + input version
    /// - rules and their configurations
    ///
    /// # Invariants
    /// * **Safety**: Two runs with the same `PolicyHash` must produce identical findings for identical input. If the detection semantics change, `PolicyHash` must change.
    PolicyHash
}

/// Opaque per-tenant secret key used to derive `SecretHash` from `NormHash`.
///
/// # Purpose
/// Provides secret material for keyed hashing. It must not be logged, serialized to untrusted storage, or included in `Debug` output.
/// The coordination/persistence layer provisions one key per tenant. Key rotation requires rescan of affected findings (new `SecretHash` values).
///
/// # Invariants
/// * Must not be logged or debug-formatted with actual key material.
/// * Must never be ordered, hashed, or used as a map key.
///
/// # Design Trade-offs
/// * Omits `CanonicalBytes` to make accidental inclusion in content-addressed IDs a compile-time error.
/// * Omits `Ord` and `Hash` to prevent accidental misuse in sorted collections or hash maps.
/// * Uses `Copy` instead of `Zeroize` for ergonomics across derivation functions; stack copies may persist.
#[derive(Clone, Copy)]
pub struct TenantSecretKey([u8; 32]);

impl PartialEq for TenantSecretKey {
    /// Checks equality using constant-time comparison to prevent timing side-channels.
    ///
    /// # Complexity
    /// O(1) in the size of the key (fixed 32 bytes).
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for TenantSecretKey {}

impl ::core::fmt::Debug for TenantSecretKey {
    /// Formats the key safely by redacting its contents.
    ///
    /// # Guarantees
    /// Key material is never included in the output.
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "TenantSecretKey([redacted])")
    }
}

impl TenantSecretKey {
    /// Constructs a secret key from raw bytes.
    ///
    /// # Preconditions
    /// None.
    ///
    /// # Guarantees
    /// Performs no validation (as this is a `const fn`); the key must be validated separately via [`is_valid`](Self::is_valid).
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the inner 32-byte array.
    ///
    /// # Guarantees
    /// Returns exactly 32 bytes of the underlying secret.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Validates that the key has non-trivial entropy.
    ///
    /// # Purpose
    /// Rejects all-zero keys which provide no isolation.
    ///
    /// # Guarantees
    /// Returns `true` if at least one byte is non-zero.
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.0.iter().all(|&b| b == 0)
    }
}

// Omit CanonicalBytes to ensure TenantSecretKey is never hashed into content-addressed IDs.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CanonicalBytes;
    use blake3::Hasher;
    use proptest::prelude::*;

    // Enforce trait bounds at compile-time to prevent accidental regressions.
    fn assert_full_id_traits<
        T: Clone + Copy + PartialEq + Eq + PartialOrd + Ord + core::hash::Hash,
    >() {
    }

    fn assert_secret_key_traits<T: Clone + Copy + PartialEq + Eq>() {}

    #[test]
    fn tenant_id_implements_required_traits() {
        assert_full_id_traits::<TenantId>();
    }

    #[test]
    fn policy_hash_implements_required_traits() {
        assert_full_id_traits::<PolicyHash>();
    }

    #[test]
    fn tenant_secret_key_implements_required_traits() {
        assert_secret_key_traits::<TenantSecretKey>();
    }

    // TenantSecretKey intentionally does not implement Ord or Hash to cause compile failures on sorting or map iteration.

    // Validate that IDs survive byte conversion without mutation.

    #[test]
    fn tenant_id_from_bytes_roundtrip() {
        let bytes = [0xAB; 32];
        let id = TenantId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn policy_hash_from_bytes_roundtrip() {
        let bytes = [0xCD; 32];
        let id = PolicyHash::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn tenant_secret_key_from_bytes_roundtrip() {
        let bytes = [0xEF; 32];
        let key = TenantSecretKey::from_bytes(bytes);
        assert_eq!(*key.as_bytes(), bytes);
    }

    // Prevent accidental key leakage via format strings.

    #[test]
    fn tenant_id_debug_is_safe() {
        let t = TenantId::from_bytes([0xAB; 32]);
        let dbg = format!("{t:?}");
        assert!(dbg.starts_with("TenantId("));
        assert!(dbg.contains("abababab"));
        assert!(dbg.len() < 80);
    }

    #[test]
    fn policy_hash_debug_is_safe() {
        let p = PolicyHash::from_bytes([0xDE; 32]);
        let dbg = format!("{p:?}");
        assert!(dbg.starts_with("PolicyHash("));
        assert!(dbg.contains("dededede"));
        assert!(dbg.len() < 80);
    }

    #[test]
    fn tenant_secret_key_debug_is_redacted() {
        let k = TenantSecretKey::from_bytes([0xFF; 32]);
        let dbg = format!("{k:?}");
        assert_eq!(dbg, "TenantSecretKey([redacted])");
        assert!(!dbg.contains("ff"));
    }

    // Ensure deterministic serialization for content-addressing.

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]
        #[test]
        fn tenant_id_canonical_bytes_stable(bytes in proptest::array::uniform32(any::<u8>())) {
            let id = TenantId::from_bytes(bytes);
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            id.write_canonical(&mut h1);
            id.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn policy_hash_canonical_bytes_stable(bytes in proptest::array::uniform32(any::<u8>())) {
            let id = PolicyHash::from_bytes(bytes);
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            id.write_canonical(&mut h1);
            id.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]
        #[test]
        fn tenant_id_canonical_bytes_collision_free(
            a in proptest::array::uniform32(any::<u8>()),
            b in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(a != b);
            let id_a = TenantId::from_bytes(a);
            let id_b = TenantId::from_bytes(b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            id_a.write_canonical(&mut ha);
            id_b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }

        #[test]
        fn policy_hash_canonical_bytes_collision_free(
            a in proptest::array::uniform32(any::<u8>()),
            b in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(a != b);
            let id_a = PolicyHash::from_bytes(a);
            let id_b = PolicyHash::from_bytes(b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            id_a.write_canonical(&mut ha);
            id_b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }
    }
}
