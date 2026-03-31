//! Kani bounded model checking proofs, property tests, and unit tests for
//! [`AtomicBitSet`].
//!
//! Verifies:
//! - Roundtrip correctness (`test_and_set` / `is_set`)
//! - Idempotency of `test_and_set`
//! - Bit independence across word boundaries
//! - `count` consistency
//! - `clear` correctness
//! - Sequential model equivalence against [`DynamicBitSet`]

use super::AtomicBitSet;

// ============================================
// Kani Bounded Model Checking Proofs
// ============================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // 129 bits = 3 words, enough to test multi-word edge cases.
    const MAX_BIT_LEN: usize = 129;

    // --------------------------------------------
    // Core Operations
    // --------------------------------------------

    /// test_and_set(idx) → is_set(idx) must be true.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_test_and_set_roundtrip() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let bs = AtomicBitSet::empty(bit_len);
        bs.test_and_set(idx);

        kani::assert(
            bs.is_set(idx),
            "test_and_set() must make is_set() return true",
        );
    }

    /// Second test_and_set on the same bit must return false.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_test_and_set_returns_false_on_repeat() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let bs = AtomicBitSet::empty(bit_len);
        let first = bs.test_and_set(idx);
        let second = bs.test_and_set(idx);

        kani::assert(first, "first test_and_set must return true");
        kani::assert(!second, "second test_and_set must return false");
    }

    /// Setting bit i must not affect bit j (i != j).
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_bit_independence() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 1 && bit_len <= MAX_BIT_LEN);

        let i: usize = kani::any();
        let j: usize = kani::any();
        kani::assume(i < bit_len && j < bit_len && i != j);

        let bs = AtomicBitSet::empty(bit_len);
        bs.test_and_set(i);

        kani::assert(!bs.is_set(j), "setting bit i must not affect bit j");
    }

    // --------------------------------------------
    // Aggregate Operations
    // --------------------------------------------

    /// count goes from 0 to 1 after a single set.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_count_after_single_set() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let bs = AtomicBitSet::empty(bit_len);
        kani::assert(bs.count() == 0, "empty bitset must have count 0");

        bs.test_and_set(idx);
        kani::assert(bs.count() == 1, "bitset with one bit set must have count 1");
    }

    /// count() must never exceed bit_length.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_count_never_exceeds_bit_length() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let bs = AtomicBitSet::empty(bit_len);
        kani::assert(
            bs.count() <= bit_len,
            "count() must never exceed bit_length",
        );

        // Set one bit and check again.
        let idx: usize = kani::any();
        kani::assume(idx < bit_len);
        bs.test_and_set(idx);
        kani::assert(
            bs.count() <= bit_len,
            "count() must never exceed bit_length after set",
        );
    }

    /// After set + clear, count == 0 and is_set == false.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_clear_resets_all() {
        let bit_len: usize = kani::any();
        kani::assume(bit_len > 0 && bit_len <= MAX_BIT_LEN);

        let idx: usize = kani::any();
        kani::assume(idx < bit_len);

        let bs = AtomicBitSet::empty(bit_len);
        bs.test_and_set(idx);
        bs.clear();

        kani::assert(bs.count() == 0, "clear() must reset count to 0");
        kani::assert(!bs.is_set(idx), "clear() must unset all bits");
    }
}

// ============================================
// Property-Based Tests
// ============================================

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use crate::bitset::DynamicBitSet;
    use proptest::prelude::*;
    use std::collections::HashSet;

    proptest! {
        #![proptest_config(crate::test_support::miri_proptest_config(16))]

        /// Second test_and_set returns false, count unchanged.
        #[test]
        fn test_and_set_is_idempotent(bit_len in 1usize..256, idx_factor in 0.0f64..1.0) {
            let idx = ((bit_len - 1) as f64 * idx_factor) as usize;
            let bs = AtomicBitSet::empty(bit_len);

            let first = bs.test_and_set(idx);
            let count_after_first = bs.count();
            let second = bs.test_and_set(idx);
            let count_after_second = bs.count();

            prop_assert!(first, "first test_and_set must return true");
            prop_assert!(!second, "second test_and_set must return false");
            prop_assert_eq!(count_after_first, count_after_second);
        }

        /// count equals the number of unique valid indices set.
        #[test]
        fn count_matches_unique_indices(
            bit_len in 1usize..256,
            indices in prop::collection::vec(0usize..256, 0..64),
        ) {
            let bs = AtomicBitSet::empty(bit_len);
            let mut unique = HashSet::new();

            for &idx in &indices {
                if idx < bit_len {
                    bs.test_and_set(idx);
                    unique.insert(idx);
                }
            }

            prop_assert_eq!(bs.count(), unique.len());
        }

        /// After clear, count == 0.
        #[test]
        fn clear_resets_to_zero(
            bit_len in 1usize..256,
            indices in prop::collection::vec(0usize..256, 1..64),
        ) {
            let bs = AtomicBitSet::empty(bit_len);
            for &idx in &indices {
                if idx < bit_len {
                    bs.test_and_set(idx);
                }
            }

            bs.clear();
            prop_assert_eq!(bs.count(), 0);
        }

        /// Setting one bit doesn't affect another.
        #[test]
        fn bit_independence_property(
            bit_len in 2usize..256,
            i_factor in 0.0f64..1.0,
            j_factor in 0.0f64..1.0,
        ) {
            let i = ((bit_len - 1) as f64 * i_factor) as usize;
            let j = ((bit_len - 1) as f64 * j_factor) as usize;
            if i == j { return Ok(()); }

            let bs = AtomicBitSet::empty(bit_len);
            bs.test_and_set(i);

            prop_assert!(!bs.is_set(j), "setting bit {i} must not affect bit {j}");
        }

        /// Operation sequence on AtomicBitSet matches DynamicBitSet reference model.
        #[test]
        fn sequential_model_equivalence(
            bit_len in 1usize..128,
            ops in prop::collection::vec((0u8..3, 0usize..128), 1..32),
        ) {
            let atomic = AtomicBitSet::empty(bit_len);
            let mut model = DynamicBitSet::empty(bit_len);

            for (op, idx) in ops {
                match op {
                    // test_and_set
                    0 => {
                        if idx < bit_len {
                            let was_unset_atomic = atomic.test_and_set(idx);
                            let was_unset_model = !model.is_set(idx);
                            model.set(idx);
                            prop_assert_eq!(
                                was_unset_atomic, was_unset_model,
                                "test_and_set({}) mismatch", idx
                            );
                        }
                    }
                    // is_set
                    1 => {
                        if idx < bit_len {
                            prop_assert_eq!(
                                atomic.is_set(idx), model.is_set(idx),
                                "is_set({}) mismatch", idx
                            );
                        }
                    }
                    // clear
                    _ => {
                        atomic.clear();
                        model.clear();
                    }
                }
            }

            prop_assert_eq!(atomic.count(), model.count(), "count mismatch after ops");
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
    fn word_boundary_bits() {
        let bs = AtomicBitSet::empty(128);
        // Bit 0: first bit of word 0
        assert!(bs.test_and_set(0));
        // Bit 63: last bit of word 0
        assert!(bs.test_and_set(63));
        // Bit 64: first bit of word 1
        assert!(bs.test_and_set(64));
        // Bit 127: last bit of word 1
        assert!(bs.test_and_set(127));

        assert!(bs.is_set(0));
        assert!(bs.is_set(63));
        assert!(bs.is_set(64));
        assert!(bs.is_set(127));
        assert_eq!(bs.count(), 4);
    }

    #[test]
    fn capacity_edge_cases() {
        // 63 bits (partial word)
        let bs63 = AtomicBitSet::empty(63);
        assert!(bs63.test_and_set(62));
        assert_eq!(bs63.count(), 1);

        // 64 bits (exact word)
        let bs64 = AtomicBitSet::empty(64);
        assert!(bs64.test_and_set(63));
        assert_eq!(bs64.count(), 1);

        // 65 bits (word boundary crossing)
        let bs65 = AtomicBitSet::empty(65);
        assert!(bs65.test_and_set(64));
        assert_eq!(bs65.count(), 1);
    }

    #[test]
    fn single_bit_bitset() {
        let bs = AtomicBitSet::empty(1);
        assert_eq!(bs.bit_length(), 1);
        assert_eq!(bs.count(), 0);
        assert!(!bs.is_set(0));

        assert!(bs.test_and_set(0));
        assert!(bs.is_set(0));
        assert_eq!(bs.count(), 1);

        assert!(!bs.test_and_set(0));
        assert_eq!(bs.count(), 1);
    }

    #[test]
    #[should_panic(expected = "AtomicBitSet requires bit_length > 0")]
    fn zero_capacity_panics() {
        AtomicBitSet::empty(0);
    }
}
