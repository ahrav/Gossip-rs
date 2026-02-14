//! Shared contract types, encodings, and invariants for the gossip-rs distributed
//! secret scanner.
//!
//! This crate defines the boundary-oriented API surface that all runtime crates
//! depend on. It contains:
//!
//! - **Identity types** — content-addressed IDs (`TenantId`, `FindingId`, …),
//!   encoding infrastructure (`CanonicalBytes`), and domain-separated hashing.
//! - **Coordination contracts** — shard lifecycle, lease management, and the
//!   `CoordinationBackend` trait.
//! - **Shard algebra** — key encoding schemas, range arithmetic, and split
//!   computation.
//! - **Connector contracts** — enumeration/read traits and connector
//!   registration.
//! - **Persistence contracts** — done-ledger, findings-sink traits, and the
//!   commit protocol typestate machine.
//!
//! # Design principles
//!
//! 1. **No unsafe code.** This crate is pure computation — no FFI, no raw
//!    pointers.
//! 2. **Minimal dependencies.** Only `blake3` at runtime.
//! 3. **Boundary isolation.** Modules mirror the five-boundary decomposition
//!    and follow an acyclic dependency direction:
//!    `identity → coordination → shard → connector → persistence`.

#![forbid(unsafe_code)]

// Re-export blake3 for internal use across modules.
pub use blake3;

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

        proptest!(|(x: u64)| {
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
        // Code gated behind `test-support` will be added in later phases.
        #[cfg(feature = "test-support")]
        {
            // Placeholder: test-support-gated code will live here.
        }
    }
}
