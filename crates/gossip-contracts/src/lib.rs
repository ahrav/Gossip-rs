//! Shared contract types, encodings, and invariants for the gossip-rs distributed
//! secret scanner.
//!
//! This crate defines the boundary-oriented API surface that all runtime crates
//! depend on.
//!
//! It contains:
//!
//! - **Identity primitives** — canonical encoding (`CanonicalBytes`),
//!   domain-separated hashing helpers, ID newtype macros, and the domain-tag
//!   registry.
//! - **Coordination boundary** — shard lifecycle, lease management, and the
//!   `CoordinationBackend` trait.
//! - **Shard boundary** — key encoding schemas, range arithmetic, and split
//!   computation.
//! - **Connector boundary** — enumeration/read traits and connector
//!   registration.
//! - **Persistence boundary** — done-ledger/findings-sink traits and commit
//!   protocol typestate.
//!
//! # Design principles
//!
//! 1. **No unsafe code.** This crate is pure computation — no FFI, no raw
//!    pointers.
//! 2. **Minimal dependencies.** Only `blake3` at runtime.
//! 3. **Boundary isolation.** Modules mirror the five-boundary decomposition
//!    and follow an acyclic dependency direction:
//!    `identity → coordination → shard → connector → persistence`.
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
//
// Dependency direction is:
// `identity -> coordination -> shard -> connector -> persistence`.
// Declarations below do not imply or enforce dependency order; each module's
// docs define what it may reference.
// ---------------------------------------------------------------------------

pub mod connector;
pub mod coordination;
pub mod identity;
pub mod persistence;
pub mod shard;

#[cfg(test)]
mod test_util;

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
