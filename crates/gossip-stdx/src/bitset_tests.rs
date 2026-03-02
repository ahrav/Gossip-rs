//! Kani bounded model checking proofs and property tests for DynamicBitSet.
//!
//! These proofs verify the correctness of core operations on `DynamicBitSet`,
//! with a focus on:
//! - Roundtrip correctness (set/unset/is_set)
//! - Padding invariant preservation
//! - Aggregate operation correctness (count, clear, toggle_all)
//! - Iterator consistency

use super::DynamicBitSet;

#[cfg(test)]
use super::words_for_bits;

// ============================================
// Kani Bounded Model Checking Proofs
// ============================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // Maximum bit_length for bounded verification.
    // 129 bits = 3 words, enough to test multi-word edge cases.
    const MAX_BIT_LEN: usize = 129;

    // --------------------------------------------
    // Core Operations (3 proofs)
    // --------------------------------------------

    /// Verifies that setting a bit and then checking it returns true.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_set_roundtrip() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.set(idx);

        kani::assert(bs.is_set(idx), "set() must make is_set() return true");
    }

    /// Verifies that unsetting a bit clears it.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_unset_roundtrip() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.set(idx);
        bs.unset(idx);

        kani::assert(!bs.is_set(idx), "unset() must make is_set() return false");
    }

    /// Verifies that set() then unset() returns to original state.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_set_unset_identity() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let bs_original = DynamicBitSet::empty(bit_len);
        let mut bs = bs_original.clone();

        bs.set(idx);
        bs.unset(idx);

        kani::assert(
            bs == bs_original,
            "set() then unset() must return to original state",
        );
    }

    // --------------------------------------------
    // Invariant Preservation (4 proofs)
    // --------------------------------------------

    /// Verifies that empty() creates a bitset with valid padding invariant.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_empty_preserves_invariant() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len <= MAX_BIT_LEN);

        let bs = DynamicBitSet::empty(bit_len);

        kani::assert(
            bs.padding_invariant_holds(),
            "empty() must create bitset with valid padding invariant",
        );
    }

    /// Verifies that set() preserves the padding invariant.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_set_preserves_invariant() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.set(idx);

        kani::assert(
            bs.padding_invariant_holds(),
            "set() must preserve padding invariant",
        );
    }

    /// Verifies that unset() preserves the padding invariant.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_unset_preserves_invariant() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.set(idx);
        bs.unset(idx);

        kani::assert(
            bs.padding_invariant_holds(),
            "unset() must preserve padding invariant",
        );
    }

    /// Verifies that toggle_all() preserves the padding invariant.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_toggle_all_preserves_invariant() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len <= MAX_BIT_LEN);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.toggle_all();

        kani::assert(
            bs.padding_invariant_holds(),
            "toggle_all() must preserve padding invariant",
        );
    }

    // --------------------------------------------
    // Aggregate Operations (3 proofs)
    // --------------------------------------------

    /// Verifies that count() returns the correct popcount of valid bits.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_count_correct() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        kani::assert(bs.count() == 0, "empty bitset must have count 0");

        bs.set(idx);
        kani::assert(bs.count() == 1, "bitset with one bit set must have count 1");
    }

    /// Verifies that count() correctly masks padding bits (defensive check).
    /// Even if padding bits were somehow set, count() should ignore them.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_count_defensive() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let bs = DynamicBitSet::empty(bit_len);
        let count = bs.count();

        kani::assert(count <= bit_len, "count() must never exceed bit_length");
    }

    /// Verifies that clear() resets all bits to zero.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_clear_resets_all() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.set(idx);
        bs.clear();

        kani::assert(bs.count() == 0, "clear() must reset count to 0");
        kani::assert(!bs.is_set(idx), "clear() must unset all bits");
        kani::assert(
            bs.padding_invariant_holds(),
            "clear() must preserve padding invariant",
        );
    }

    // --------------------------------------------
    // Iterator (2 proofs)
    // --------------------------------------------

    /// Verifies that iterator only yields set bits.
    #[kani::proof]
    #[kani::unwind(132)]
    fn verify_iter_yields_set_bits() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.set(idx);

        let mut found = false;
        for i in bs.iter_set() {
            if i == idx {
                found = true;
            }
            kani::assert(bs.is_set(i), "iterator must only yield set bits");
        }

        kani::assert(found, "iterator must yield the set bit");
    }

    /// Verifies that iter_set().count() equals count().
    #[kani::proof]
    #[kani::unwind(132)]
    fn verify_iter_count_matches() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let mut bs = DynamicBitSet::empty(bit_len);
        bs.set(idx);

        let iter_count = bs.iter_set().count();
        let direct_count = bs.count();

        kani::assert(
            iter_count == direct_count,
            "iter_set().count() must equal count()",
        );
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

    const PROPTEST_CASES: u32 = 16;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            PROPTEST_CASES
        ))]

        #[test]
        fn set_is_idempotent(bit_len in 1usize..128, idx_factor in 0.0f64..1.0) {
            let idx = ((bit_len - 1) as f64 * idx_factor) as usize;
            let mut b1 = DynamicBitSet::empty(bit_len);
            let mut b2 = DynamicBitSet::empty(bit_len);

            b1.set(idx);
            b2.set(idx);
            b2.set(idx); // set again

            prop_assert_eq!(b1.count(), 1);
            prop_assert_eq!(b1, b2);
        }

        #[test]
        fn count_equals_iter_len(bit_len in 1usize..128, indices in prop::collection::vec(0usize..128, 0..64)) {
            let mut b = DynamicBitSet::empty(bit_len);
            for &idx in &indices {
                if idx < bit_len {
                    b.set(idx);
                }
            }

            let count = b.count();
            let iter_len = b.iter_set().count();
            prop_assert_eq!(count, iter_len);
        }

        #[test]
        fn set_unset_is_identity(bit_len in 1usize..128, idx_factor in 0.0f64..1.0) {
            let idx = ((bit_len - 1) as f64 * idx_factor) as usize;
            let mut b = DynamicBitSet::empty(bit_len);
            let original = b.clone();

            b.set(idx);
            b.unset(idx);

            prop_assert_eq!(b.count(), 0);
            prop_assert_eq!(b, original);
        }

        #[test]
        fn iter_roundtrip(bit_len in 1usize..128, indices in prop::collection::hash_set(0usize..128, 0..64)) {
            let valid_indices: HashSet<usize> = indices.into_iter().filter(|&i| i < bit_len).collect();
            let mut b1 = DynamicBitSet::empty(bit_len);
            for &idx in &valid_indices {
                b1.set(idx);
            }

            let mut b2 = DynamicBitSet::empty(bit_len);
            for idx in b1.iter_set() {
                b2.set(idx);
            }

            let collected: HashSet<usize> = b1.iter_set().collect();
            prop_assert_eq!(collected, valid_indices);
            prop_assert_eq!(b1, b2);
        }

        #[test]
        fn toggle_all_preserves_bit_length(bit_len in 1usize..128) {
            let mut b = DynamicBitSet::empty(bit_len);
            b.toggle_all();

            prop_assert_eq!(b.count(), bit_len);
            prop_assert!(b.padding_invariant_holds());

            b.toggle_all();
            prop_assert_eq!(b.count(), 0);
            prop_assert!(b.padding_invariant_holds());
        }

        #[test]
        fn clear_resets_all(bit_len in 1usize..128, indices in prop::collection::vec(0usize..128, 1..64)) {
            let mut b = DynamicBitSet::empty(bit_len);
            for &idx in &indices {
                if idx < bit_len {
                    b.set(idx);
                }
            }

            b.clear();
            prop_assert_eq!(b.count(), 0);
            prop_assert!(b.padding_invariant_holds());
        }
    }
}

// ============================================
// Unit Tests
// ============================================

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn toggle_all_preserves_invariant_non_multiple_of_64() {
        let mut b = DynamicBitSet::empty(10);
        b.toggle_all();

        assert_eq!(b.count(), 10);
        assert!(b.padding_invariant_holds());
    }

    #[test]
    fn iter_set_empty() {
        let b = DynamicBitSet::empty(64);
        let indices: Vec<usize> = b.iter_set().collect();
        assert!(indices.is_empty());
    }

    #[test]
    fn capacity_edge_cases() {
        // 63 bits (partial word)
        let mut b63 = DynamicBitSet::empty(63);
        b63.set(62);
        assert_eq!(b63.count(), 1);
        assert!(b63.padding_invariant_holds());

        // 64 bits (exact word)
        let mut b64 = DynamicBitSet::empty(64);
        b64.set(63);
        assert_eq!(b64.count(), 1);
        assert!(b64.padding_invariant_holds());

        // 65 bits (word boundary crossing)
        let mut b65 = DynamicBitSet::empty(65);
        b65.set(64);
        assert_eq!(b65.count(), 1);
        assert!(b65.padding_invariant_holds());
    }

    #[test]
    fn words_for_bits_calculation() {
        assert_eq!(words_for_bits(0), 0);
        assert_eq!(words_for_bits(1), 1);
        assert_eq!(words_for_bits(63), 1);
        assert_eq!(words_for_bits(64), 1);
        assert_eq!(words_for_bits(65), 2);
        assert_eq!(words_for_bits(128), 2);
        assert_eq!(words_for_bits(129), 3);
    }
}
