//! Shared contract types, encodings, and invariants for the gossip-rs distributed
//! secret scanner.
//!
//! This crate defines the shared data model that all runtime crates depend on.
//!
//! It contains:
//!
//! - **Identity primitives** — canonical encoding (`CanonicalBytes`),
//!   domain-separated hashing helpers, ID newtype macros, and the domain-tag
//!   registry.
//! - **Coordination data model** — shard spec, cursor, pooled wrappers,
//!   split-replace planning core, manifest validation, and split capacity
//!   constants. Protocol traits and the in-memory backend live in
//!   `gossip-coordination`.
//! - **Connector boundary** — enumeration/read traits and connector
//!   registration.
//! - **Persistence boundary** — done-ledger/findings-sink traits and commit
//!   protocol typestate.
//!
//! Ownership boundary: this crate provides contracts, canonical encodings,
//! and pure validation logic. It does not implement coordinator state
//! transitions, lease/fence semantics, or storage backends.
//!
//! # Design principles
//!
//! 1. **No unsafe code.** This crate is pure computation — no FFI, no raw
//!    pointers.
//! 2. **Narrow runtime surface.** Runtime dependencies are intentionally
//!    limited to shared primitives (`blake3`, `subtle`, `gossip-stdx`).
//! 3. **Boundary isolation.** Modules mirror the boundary decomposition.
//! 4. **Backend neutrality.** Public APIs avoid backend-specific sequencing or
//!    storage assumptions.
//!
//! # Feature flags
//!
//! | Flag | Default | Purpose |
//! |------|---------|---------|
//! | `test-support` | off | Enables test doubles and helpers for downstream crate tests. |

#![forbid(unsafe_code)]

/// Re-export used by macro expansions (`$crate::blake3::Hasher`).
///
/// This is part of macro hygiene rather than the intended end-user API.
#[doc(hidden)]
pub use blake3;

// ---------------------------------------------------------------------------
// Boundary modules.
// ---------------------------------------------------------------------------

pub mod connector;
pub mod coordination;
pub mod identity;
pub mod persistence;

#[cfg(any(test, feature = "test-support"))]
pub mod test_util;

#[cfg(test)]
mod tests {
    /// Smoke test: blake3 is importable and functional.
    #[test]
    fn blake3_available() {
        let hasher = blake3::Hasher::new();
        let hash = hasher.finalize();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    /// Smoke test: proptest macros are usable in test context.
    #[test]
    fn proptest_available() {
        use proptest::prelude::*;

        proptest!(crate::test_util::miri_proptest_config(), |(x: u64)| {
            // Verify blake3 produces deterministic output.
            let h1 = blake3::hash(&x.to_le_bytes());
            let h2 = blake3::hash(&x.to_le_bytes());
            prop_assert_eq!(h1, h2);
        });
    }

    /// Smoke test: test-support feature gate compiles in both configurations.
    #[test]
    fn test_support_feature_gate() {
        // This test verifies the feature flag plumbing exists.
        #[cfg(feature = "test-support")]
        {}
    }
}
