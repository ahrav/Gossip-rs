//! Fixed-capacity dedupe sets with O(1) reset via generation counters.
//!
//! The key trick is "epoch tagging": each slot stores a generation number
//! indicating when it was last written. Reset is just `cur += 1`, so the table
//! becomes logically empty without clearing memory. On rare wraparound, we pay
//! a full clear once to re-establish the invariant.
//!
//! # Invariants
//! - `slots.len()` is a power of two and `mask == slots.len() - 1`.
//! - `cur != 0`; `slot.epoch == cur` means the slot is live for the current epoch.
//!
//! # Algorithm
//! - Open addressing with linear probing.
//! - Initial probe uses the upper 64 bits for better distribution when low bits
//!   have patterns.
//! - Reset advances `cur` so all prior generations become logically empty.
//!
//! # Design Notes
//! - Reset is O(1) in the common case; wraparound triggers one full clear.
//! - When the table is full, inserts are best-effort: new keys may not be stored.

/// Interleaved slot for cache-friendly random access.
///
/// Using AoS (Array of Structs) instead of SoA (Struct of Arrays) because:
/// - Hash table access is random, not sequential iteration.
/// - Each probe needs both `key` and `epoch` for the same slot.
/// - Keeping the fields adjacent favors single-line fetches in practice.
/// - Layout is 32 bytes per slot under `repr(C)` (16-byte key + 4-byte epoch
///   + 12 bytes padding from `u128` alignment).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Slot128 {
    key: u128,  // 16 bytes
    epoch: u32, // 4 bytes
    _pad: u32, // 4 bytes — explicit fill; struct is 32 bytes total (8 bytes trailing padding from u128 alignment)
}

/// Fixed-capacity hash set for deduplication (128-bit keys).
///
/// # Guarantees
/// - Reset is O(1) in the common case by advancing a generation counter.
/// - Insert returns `false` for keys already present in the current epoch.
///
/// # Invariants
/// - `cur` is never zero; `slot.epoch == cur` implies the slot is occupied.
/// - `mask` is `slots.len() - 1`, so indexing wraps via `& mask`.
///
/// # Behavior When Full
/// - If the table is full and the key is not present, `insert` returns `true`
///   but does not store the key. A later insert of the same key may return
///   `true` again.
///
/// # Performance
/// - Expected O(1) inserts with linear probing; worst-case O(n).
///
/// # Examples
/// ```
/// use gossip_stdx::FixedSet128;
///
/// let mut set = FixedSet128::with_pow2(8);
/// assert!(set.insert(42));
/// assert!(!set.insert(42));
/// set.reset();
/// assert!(set.insert(42));
/// ```
pub struct FixedSet128 {
    slots: Vec<Slot128>,
    cur: u32,
    mask: usize,
}

impl FixedSet128 {
    /// Creates a new set with a power-of-two number of slots.
    ///
    /// # Preconditions
    /// - `cap_pow2` must be a power of two and greater than zero.
    ///
    /// # Panics
    /// - Panics if `cap_pow2` is not a power of two.
    pub fn with_pow2(cap_pow2: usize) -> Self {
        assert!(cap_pow2.is_power_of_two());
        Self {
            slots: vec![Slot128::default(); cap_pow2],
            cur: 1,
            mask: cap_pow2 - 1,
        }
    }

    /// Logically clears the set by advancing the generation counter.
    ///
    /// # Effects
    /// - All existing keys become invisible to `insert`.
    /// - On rare `u32` wraparound, a full clear restores the invariant.
    ///
    /// # Complexity
    /// - O(1) normally; O(n) on wraparound.
    pub fn reset(&mut self) {
        self.cur = self.cur.wrapping_add(1);
        if self.cur == 0 {
            // Rare wrap: pay full clear once.
            for slot in &mut self.slots {
                slot.epoch = 0;
            }
            self.cur = 1;
        }
    }

    /// Inserts `key` into the set if space permits.
    ///
    /// # Effects
    /// - Returns `false` if the key is already present in the current epoch.
    /// - Returns `true` if the key is newly inserted.
    /// - If the table is full and the key is absent, returns `true` but does not
    ///   store the key (best-effort dedupe).
    ///
    /// # Complexity
    /// - Expected O(1); worst-case O(n) probes.
    pub fn insert(&mut self, key: u128) -> bool {
        // Use upper 64 bits for initial slot selection (better distribution).
        let mut i = ((key >> 64) as usize) & self.mask;
        for _ in 0..=self.mask {
            let slot = &mut self.slots[i];
            if slot.epoch != self.cur {
                slot.epoch = self.cur;
                slot.key = key;
                return true;
            }
            if slot.key == key {
                return false;
            }
            i = (i + 1) & self.mask;
        }
        // Table full: dedupe is best-effort only.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::FixedSet128;

    #[test]
    fn fixed_set_128_wrap_resets_gen_table() {
        let mut set = FixedSet128::with_pow2(8);
        for slot in &mut set.slots {
            slot.epoch = 123;
        }
        set.cur = u32::MAX;
        set.reset();
        assert_eq!(set.cur, 1);
        assert!(set.slots.iter().all(|slot| slot.epoch == 0));
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::FixedSet128;
    use proptest::prelude::*;
    use std::collections::HashSet;

    const CAP: usize = 64;

    #[derive(Clone, Debug)]
    enum Op128 {
        Insert(u128),
        Reset,
    }

    fn op128_strategy() -> impl Strategy<Value = Op128> {
        prop_oneof![any::<u128>().prop_map(Op128::Insert), Just(Op128::Reset),]
    }

    proptest! {
        #![proptest_config(crate::test_support::miri_proptest_config(16))]

        // FixedSet128 proptests

        #[test]
        fn insert_duplicates_report_false_128(keys in proptest::collection::vec(any::<u128>(), 0..32)) {
            let mut set = FixedSet128::with_pow2(CAP);
            let mut seen = std::collections::HashSet::new();

            for key in keys {
                let inserted = set.insert(key);
                if seen.contains(&key) {
                    prop_assert!(!inserted);
                } else {
                    prop_assert!(inserted);
                    seen.insert(key);
                }
            }
        }

        #[test]
        fn reset_forgets_prior_keys_128(keys in proptest::collection::vec(any::<u128>(), 0..32)) {
            let mut set = FixedSet128::with_pow2(CAP);

            for key in &keys {
                let _ = set.insert(*key);
            }

            set.reset();

            for key in keys {
                prop_assert!(set.insert(key));
            }
        }

        #[test]
        fn op_sequence_matches_model_128(
            cap_exp in 0usize..7,
            ops in proptest::collection::vec(op128_strategy(), 0..128),
        ) {
            let cap = 1usize << cap_exp;
            let mut set = FixedSet128::with_pow2(cap);
            let mut model: HashSet<u128> = HashSet::new();

            for op in ops {
                match op {
                    Op128::Insert(key) => {
                        let inserted = set.insert(key);
                        let expected = !model.contains(&key);
                        prop_assert_eq!(inserted, expected);
                        if expected && model.len() < cap {
                            model.insert(key);
                        }
                    }
                    Op128::Reset => {
                        set.reset();
                        model.clear();
                    }
                }
            }
        }

        #[test]
        fn linear_probing_handles_collisions_128(
            high in any::<u64>(),
            lows in proptest::collection::vec(any::<u64>(), 0..=CAP),
        ) {
            let mut set = FixedSet128::with_pow2(CAP);
            let mut seen: HashSet<u128> = HashSet::new();
            let high_bits = (high as u128) << 64;

            for low in lows {
                let key = high_bits | low as u128;
                let inserted = set.insert(key);
                let expected = seen.insert(key);
                prop_assert_eq!(inserted, expected);
            }
        }

        #[test]
        fn full_table_reports_duplicates_128(
            keys in proptest::collection::hash_set(any::<u128>(), CAP..=CAP),
            probes in proptest::collection::vec(any::<u128>(), 0..64),
        ) {
            let mut set = FixedSet128::with_pow2(CAP);

            for key in &keys {
                prop_assert!(set.insert(*key));
            }
            for key in &keys {
                prop_assert!(!set.insert(*key));
            }

            for key in probes {
                let inserted = set.insert(key);
                let expected = !keys.contains(&key);
                prop_assert_eq!(inserted, expected);
            }
        }
    }
}
