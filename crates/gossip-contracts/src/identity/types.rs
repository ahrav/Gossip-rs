//! Core identity primitives: `TenantId`, `PolicyHash`, and `TenantSecretKey`.
//!
//! These are the first concrete identity types for the Boundary 1 (Identity &
//! Hashing Spine) epic. All downstream B1 tasks depend on these three types.
//!
//! # Type overview
//!
//! | Type | Width | Construction | `CanonicalBytes` | Use case |
//! |------|-------|-------------|-----------------|----------|
//! | [`TenantId`] | 32 B | public | yes | Multi-tenant isolation boundary |
//! | [`PolicyHash`] | 32 B | public | yes | Cryptographic policy digest |
//! | [`TenantSecretKey`] | 32 B | public | **no** | Per-tenant secret for keyed hashing |
//!
//! `TenantId` and `PolicyHash` are generated via [`define_id_32!`] and inherit
//! the standard trait set (`Clone`, `Copy`, `Eq`, `Ord`, `Hash`,
//! `CanonicalBytes`).
//!
//! `TenantSecretKey` is hand-rolled: it deliberately omits `Ord`, `Hash`, and
//! `CanonicalBytes` because secret keys must never be ordered, used as map
//! keys, or hashed into content-addressed IDs.

crate::define_id_32! {
    /// Stable tenant identity. Top of the isolation hierarchy.
    ///
    /// Typically derived from an external tenant identifier
    /// (e.g., `blake3(external_tenant_uuid)` to normalize width).
    ///
    /// # Invariants
    ///
    /// **Safety**: A shard record for tenant A must never be readable or
    /// writable by a request scoped to tenant B. The coordination layer
    /// enforces this by requiring `TenantId` at every API boundary.
    ///
    /// **Safety**: `TenantId` is an input to `SecretHash` keying (via
    /// `TenantSecretKey`), `FindingId` derivation, and `OccurrenceId`
    /// derivation. Changing a tenant's ID invalidates all derived hashes.
    TenantId
}

crate::define_id_32! {
    /// Policy identity — cryptographic digest of rules, config, and output
    /// identity semantics.
    ///
    /// `PolicyHash` serves as the join key for skip/dedupe decisions.
    /// It must include all inputs that affect detection output identity:
    ///
    /// - `policy_hash_version`: scheme version (for forced rescan on upgrade)
    /// - `id_hash_mode`: keyed vs unkeyed hashing
    /// - `evidence_hash_version`: normalization + input version
    /// - rules and their configurations
    ///
    /// If any of these change, `PolicyHash` changes → new `RunId` → forced rescan.
    ///
    /// # Invariants
    ///
    /// **Safety**: Two runs with the same `PolicyHash` must produce identical
    /// findings for identical input. If the detection semantics change,
    /// `PolicyHash` must change.
    PolicyHash
}

/// Opaque per-tenant secret key used to derive `SecretHash` from `NormHash`.
///
/// This type exists in the contracts crate solely to define the keying
/// function signature. It must not be logged, serialized to untrusted
/// storage, or included in `Debug` output.
///
/// # Provisioning
///
/// The coordination/persistence layer provisions one key per tenant.
/// Key rotation requires rescan of affected findings (new `SecretHash` values).
///
/// # Why no `CanonicalBytes`?
///
/// Secret keys must never be hashed into content-addressed IDs. Omitting the
/// impl makes accidental inclusion a compile-time error.
///
/// # Why no `Ord` / `Hash`?
///
/// Secret keys are not ordered and should not be used as map keys. Omitting
/// these traits prevents accidental misuse in sorted collections or hash maps.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantSecretKey([u8; 32]);

impl ::core::fmt::Debug for TenantSecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "TenantSecretKey([redacted])")
    }
}

impl TenantSecretKey {
    /// Construct from raw bytes.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner 32-byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time trait assertion: TenantSecretKey implements exactly
    // Clone + Copy + PartialEq + Eq, and deliberately omits Ord + Hash.
    // The omission of Ord/Hash is enforced at compile time — any code
    // that tries to sort or hash-map a TenantSecretKey will fail to compile.
    fn assert_secret_key_traits<T: Clone + Copy + PartialEq + Eq>() {}

    #[test]
    fn tenant_secret_key_implements_required_traits() {
        assert_secret_key_traits::<TenantSecretKey>();
    }

    #[test]
    fn tenant_secret_key_from_bytes_roundtrip() {
        let bytes = [0xEF; 32];
        let key = TenantSecretKey::from_bytes(bytes);
        assert_eq!(*key.as_bytes(), bytes);
    }

    #[test]
    fn tenant_secret_key_debug_is_redacted() {
        let k = TenantSecretKey::from_bytes([0xFF; 32]);
        let dbg = format!("{k:?}");
        assert_eq!(dbg, "TenantSecretKey([redacted])");
        assert!(!dbg.contains("ff"));
    }
}
