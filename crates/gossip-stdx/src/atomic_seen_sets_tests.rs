//! Kani bounded model checking proofs and property tests for
//! [`AtomicSeenSets`].
//!
//! Verifies:
//! - `mark_*` / `is_*_seen` roundtrip correctness
//! - Bitset independence across all three sets
//! - `clear` correctness
//! - Sequential model equivalence against three `HashSet`s

use super::AtomicSeenSets;

// ============================================
// Kani Bounded Model Checking Proofs
// ============================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const MAX_CAP: usize = 65;

    /// mark_tree → is_tree_seen roundtrip.
    #[kani::proof]
    #[kani::unwind(3)]
    fn verify_mark_tree_roundtrip() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let idx: usize = kani::any();
        kani::assume(idx < cap);

        let seen = AtomicSeenSets::new(cap, 1);
        seen.mark_tree(idx);

        kani::assert(
            seen.is_tree_seen(idx),
            "mark_tree must make is_tree_seen return true",
        );
    }

    /// mark_blob → is_blob_seen roundtrip.
    #[kani::proof]
    #[kani::unwind(3)]
    fn verify_mark_blob_roundtrip() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let idx: usize = kani::any();
        kani::assume(idx < cap);

        let seen = AtomicSeenSets::new(1, cap);
        seen.mark_blob(idx);

        kani::assert(
            seen.is_blob_seen(idx),
            "mark_blob must make is_blob_seen return true",
        );
    }

    /// mark_blob_excluded → is_blob_excluded roundtrip.
    #[kani::proof]
    #[kani::unwind(3)]
    fn verify_mark_blob_excluded_roundtrip() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let idx: usize = kani::any();
        kani::assume(idx < cap);

        let seen = AtomicSeenSets::new(1, cap);
        seen.mark_blob_excluded(idx);

        kani::assert(
            seen.is_blob_excluded(idx),
            "mark_blob_excluded must make is_blob_excluded return true",
        );
    }

    /// Bitset independence: marking tree does not affect blob or excluded.
    #[kani::proof]
    #[kani::unwind(3)]
    fn verify_bitset_independence() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let idx: usize = kani::any();
        kani::assume(idx < cap);

        let seen = AtomicSeenSets::new(cap, cap);
        seen.mark_tree(idx);

        kani::assert(!seen.is_blob_seen(idx), "marking tree must not affect blob");
        kani::assert(
            !seen.is_blob_excluded(idx),
            "marking tree must not affect excluded",
        );
    }

    /// Clear resets all three bitsets.
    #[kani::proof]
    #[kani::unwind(3)]
    fn verify_clear_resets_all() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let idx: usize = kani::any();
        kani::assume(idx < cap);

        let seen = AtomicSeenSets::new(cap, cap);
        seen.mark_tree(idx);
        seen.mark_blob(idx);
        seen.mark_blob_excluded(idx);

        seen.clear();

        kani::assert(!seen.is_tree_seen(idx), "clear must reset trees");
        kani::assert(!seen.is_blob_seen(idx), "clear must reset blobs");
        kani::assert(!seen.is_blob_excluded(idx), "clear must reset excluded");
    }
}

// ============================================
// Property-Based Tests
// ============================================

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    /// Under Miri, disables file-based failure persistence (which calls
    /// `getcwd`, blocked by isolation) and reduces cases.
    fn miri_proptest_config() -> proptest::test_runner::Config {
        if cfg!(miri) {
            proptest::test_runner::Config {
                failure_persistence: None,
                cases: 16,
                ..Default::default()
            }
        } else {
            proptest::test_runner::Config {
                cases: 16,
                ..Default::default()
            }
        }
    }

    proptest! {
        #![proptest_config(miri_proptest_config())]

        /// mark + is_seen roundtrip for all three bitsets.
        #[test]
        fn mark_is_seen_roundtrip(cap in 1usize..256, idx_factor in 0.0f64..1.0) {
            let idx = ((cap - 1) as f64 * idx_factor) as usize;
            let seen = AtomicSeenSets::new(cap, cap);

            seen.mark_tree(idx);
            prop_assert!(seen.is_tree_seen(idx));

            seen.mark_blob(idx);
            prop_assert!(seen.is_blob_seen(idx));

            seen.mark_blob_excluded(idx);
            prop_assert!(seen.is_blob_excluded(idx));
        }

        /// Second mark returns false for all three bitsets.
        #[test]
        fn mark_idempotency(cap in 1usize..256, idx_factor in 0.0f64..1.0) {
            let idx = ((cap - 1) as f64 * idx_factor) as usize;
            let seen = AtomicSeenSets::new(cap, cap);

            prop_assert!(seen.mark_tree(idx));
            prop_assert!(!seen.mark_tree(idx));

            prop_assert!(seen.mark_blob(idx));
            prop_assert!(!seen.mark_blob(idx));

            prop_assert!(seen.mark_blob_excluded(idx));
            prop_assert!(!seen.mark_blob_excluded(idx));
        }

        /// Marking one bitset does not affect the others.
        #[test]
        fn bitset_independence(cap in 1usize..256, idx_factor in 0.0f64..1.0) {
            let idx = ((cap - 1) as f64 * idx_factor) as usize;
            let seen = AtomicSeenSets::new(cap, cap);

            seen.mark_tree(idx);
            prop_assert!(!seen.is_blob_seen(idx));
            prop_assert!(!seen.is_blob_excluded(idx));

            seen.mark_blob(idx);
            prop_assert!(!seen.is_blob_excluded(idx));
        }

        /// Clear resets all three.
        #[test]
        fn clear_resets_all(
            cap in 1usize..256,
            indices in prop::collection::vec(0usize..256, 1..32),
        ) {
            let seen = AtomicSeenSets::new(cap, cap);
            for &idx in &indices {
                if idx < cap {
                    seen.mark_tree(idx);
                    seen.mark_blob(idx);
                    seen.mark_blob_excluded(idx);
                }
            }

            seen.clear();

            for &idx in &indices {
                if idx < cap {
                    prop_assert!(!seen.is_tree_seen(idx));
                    prop_assert!(!seen.is_blob_seen(idx));
                    prop_assert!(!seen.is_blob_excluded(idx));
                }
            }
        }

        /// Reference model: three HashSets track the same operations.
        #[test]
        fn reference_model_equivalence(
            cap in 1usize..128,
            ops in prop::collection::vec((0u8..9, 0usize..128), 1..64),
        ) {
            let seen = AtomicSeenSets::new(cap, cap);
            let mut model_trees = HashSet::new();
            let mut model_blobs = HashSet::new();
            let mut model_excluded = HashSet::new();

            for (op, idx) in ops {
                if idx >= cap {
                    continue;
                }
                match op {
                    // mark_tree
                    0 => {
                        let was_new = seen.mark_tree(idx);
                        let model_new = model_trees.insert(idx);
                        prop_assert_eq!(was_new, model_new, "mark_tree({}) mismatch", idx);
                    }
                    // mark_blob
                    1 => {
                        let was_new = seen.mark_blob(idx);
                        let model_new = model_blobs.insert(idx);
                        prop_assert_eq!(was_new, model_new, "mark_blob({}) mismatch", idx);
                    }
                    // mark_blob_excluded
                    2 => {
                        let was_new = seen.mark_blob_excluded(idx);
                        let model_new = model_excluded.insert(idx);
                        prop_assert_eq!(was_new, model_new, "mark_blob_excluded({}) mismatch", idx);
                    }
                    // is_tree_seen
                    3 => {
                        prop_assert_eq!(
                            seen.is_tree_seen(idx),
                            model_trees.contains(&idx),
                            "is_tree_seen({}) mismatch", idx
                        );
                    }
                    // is_blob_seen
                    4 => {
                        prop_assert_eq!(
                            seen.is_blob_seen(idx),
                            model_blobs.contains(&idx),
                            "is_blob_seen({}) mismatch", idx
                        );
                    }
                    // is_blob_excluded
                    5 => {
                        prop_assert_eq!(
                            seen.is_blob_excluded(idx),
                            model_excluded.contains(&idx),
                            "is_blob_excluded({}) mismatch", idx
                        );
                    }
                    // clear
                    _ => {
                        seen.clear();
                        model_trees.clear();
                        model_blobs.clear();
                        model_excluded.clear();
                    }
                }
            }
        }
    }
}
