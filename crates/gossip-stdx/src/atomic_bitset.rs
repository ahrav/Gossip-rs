//! Lock-free [`AtomicBitSet`] with atomic test-and-set for concurrent dedup.
//!
//! # Invariants
//! - Bits are stored in `AtomicU64` words; padding bits beyond the logical
//!   capacity are zero (maintained by never setting them).
//! - `words.len() == words_for_bits(bit_length)`.
//!
//! # Ordering
//! All atomic operations use `Relaxed` ordering. This is sufficient because:
//! - `fetch_or` atomicity guarantees exactly one caller sees "was-zero" per bit.
//! - No dependent data requires acquire/release synchronization.
//! - `clear` requires external synchronization (see its doc comment).
//!
//! # Performance
//! - `test_and_set`, `is_set` are O(1).
//! - `count`, `clear` are O(WORDS).

#[cfg(loom)]
use loom::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU64, Ordering};

use super::bitset::words_for_bits;

/// Lock-free bitset backed by `Vec<AtomicU64>`.
///
/// Designed for concurrent deduplication where multiple threads race to
/// claim bits via [`test_and_set`](Self::test_and_set). The atomic
/// `fetch_or` guarantees exactly one caller observes `true` (was-unset)
/// per bit, making it suitable for "first writer wins" patterns.
///
/// # Examples
///
/// ```
/// use gossip_stdx::atomic_bitset::AtomicBitSet;
///
/// let bits = AtomicBitSet::empty(128);
/// assert!(bits.test_and_set(42));   // first caller wins
/// assert!(!bits.test_and_set(42));  // second caller loses
/// assert!(bits.is_set(42));
/// ```
pub struct AtomicBitSet {
    words: Vec<AtomicU64>,
    bit_length: usize,
}

// SAFETY: AtomicU64 is Send+Sync; Vec<AtomicU64> is Send+Sync.
// The struct contains no raw pointers or non-atomic interior mutability.
unsafe impl Send for AtomicBitSet {}
// SAFETY: Same reasoning — all fields are Sync-safe atomics.
unsafe impl Sync for AtomicBitSet {}

impl std::fmt::Debug for AtomicBitSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomicBitSet")
            .field("bit_length", &self.bit_length)
            .field("words_len", &self.words.len())
            .finish()
    }
}

impl AtomicBitSet {
    /// Creates an empty bitset with capacity for `bit_length` bits, all
    /// initialized to zero.
    ///
    /// # Panics
    ///
    /// Panics if `bit_length` is zero (a zero-capacity bitset has no
    /// valid indices and is always a bug at the call site).
    pub fn empty(bit_length: usize) -> Self {
        assert!(bit_length > 0, "AtomicBitSet requires bit_length > 0");
        let num_words = words_for_bits(bit_length);
        let mut words = Vec::with_capacity(num_words);
        for _ in 0..num_words {
            words.push(AtomicU64::new(0));
        }
        Self { words, bit_length }
    }

    /// Atomically sets bit `idx` and returns `true` if it was previously unset.
    ///
    /// This is the core dedup primitive: exactly one concurrent caller per bit
    /// will observe `true`.
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx >= bit_length`.
    #[inline(always)]
    pub fn test_and_set(&self, idx: usize) -> bool {
        debug_assert!(idx < self.bit_length, "bit index out of bounds");
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        let mask = 1u64 << bit_idx;
        let prev = self.words[word_idx].fetch_or(mask, Ordering::Relaxed);
        (prev & mask) == 0
    }

    /// Returns whether bit `idx` is set.
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx >= bit_length`.
    #[inline(always)]
    pub fn is_set(&self, idx: usize) -> bool {
        debug_assert!(idx < self.bit_length, "bit index out of bounds");
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        let mask = 1u64 << bit_idx;
        (self.words[word_idx].load(Ordering::Relaxed) & mask) != 0
    }

    /// Resets all bits to zero.
    ///
    /// # Safety contract (not `unsafe`, but important)
    ///
    /// Callers must ensure no concurrent `test_and_set` calls are in-flight
    /// when `clear` executes. Typically this means joining all worker threads
    /// before clearing, then distributing work again. Violating this is not UB
    /// but makes `test_and_set` return values unreliable during the clear window.
    pub fn clear(&self) {
        for word in &self.words {
            word.store(0, Ordering::Relaxed);
        }
    }

    /// Returns the number of addressable bits.
    #[inline]
    pub fn bit_length(&self) -> usize {
        self.bit_length
    }

    /// Counts the number of set bits.
    ///
    /// Because loads are `Relaxed`, the result is a snapshot — concurrent
    /// `test_and_set` calls may or may not be reflected.
    #[inline]
    pub fn count(&self) -> usize {
        let len = self.words.len();
        let mut total = 0usize;

        // All words except the last — no masking needed.
        for word in &self.words[..len - 1] {
            total += word.load(Ordering::Relaxed).count_ones() as usize;
        }

        // Last word: mask off padding bits.
        let remaining_bits = self.bit_length % 64;
        let last_mask = if remaining_bits == 0 {
            u64::MAX
        } else {
            (1u64 << remaining_bits) - 1
        };
        total += (self.words[len - 1].load(Ordering::Relaxed) & last_mask).count_ones() as usize;
        total
    }
}

// ---------------------------------------------------------------------------
// Test module includes
// ---------------------------------------------------------------------------

#[cfg(any(all(test, feature = "stdx-proptest"), kani))]
#[path = "atomic_bitset_tests.rs"]
mod atomic_bitset_tests;

// ---------------------------------------------------------------------------
// Loom concurrency tests
// ---------------------------------------------------------------------------

#[cfg(loom)]
mod loom_tests {
    use super::*;
    use loom::thread;

    /// Two threads race on the same bit — exactly one must win.
    #[test]
    fn test_concurrent_dedup() {
        loom::model(|| {
            let bs = std::sync::Arc::new(AtomicBitSet::empty(64));
            let bs2 = bs.clone();

            let h = thread::spawn(move || bs2.test_and_set(0));

            let won_main = bs.test_and_set(0);
            let won_thread = h.join().unwrap();

            // Exactly one winner (XOR).
            assert!(
                won_main ^ won_thread,
                "exactly one caller must win: main={won_main}, thread={won_thread}"
            );
            assert!(bs.is_set(0));
        });
    }

    /// Two threads set different bits in the same word — both must be visible.
    #[test]
    fn no_lost_updates_same_word() {
        loom::model(|| {
            let bs = std::sync::Arc::new(AtomicBitSet::empty(64));
            let bs2 = bs.clone();

            let h = thread::spawn(move || {
                assert!(bs2.test_and_set(1));
            });

            assert!(bs.test_and_set(0));
            h.join().unwrap();

            assert!(bs.is_set(0));
            assert!(bs.is_set(1));
            assert_eq!(bs.count(), 2);
        });
    }

    /// Three threads set three distinct bits — all return true, count == 3.
    #[test]
    fn three_threads_three_bits() {
        loom::model(|| {
            let bs = std::sync::Arc::new(AtomicBitSet::empty(64));
            let bs1 = bs.clone();
            let bs2 = bs.clone();

            let h1 = thread::spawn(move || bs1.test_and_set(1));
            let h2 = thread::spawn(move || bs2.test_and_set(2));

            let r0 = bs.test_and_set(0);
            let r1 = h1.join().unwrap();
            let r2 = h2.join().unwrap();

            assert!(r0, "bit 0 must be freshly set");
            assert!(r1, "bit 1 must be freshly set");
            assert!(r2, "bit 2 must be freshly set");
            assert_eq!(bs.count(), 3);
        });
    }
}

// ---------------------------------------------------------------------------
// Concurrent smoke tests (also valid under Miri / cargo miri test)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod concurrent_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Basic single-threaded ops — validates allocation, indexing,
    /// and atomic ops.
    #[test]
    fn single_thread_ops() {
        let bs = AtomicBitSet::empty(128);
        assert!(bs.test_and_set(0));
        assert!(bs.test_and_set(63));
        assert!(bs.test_and_set(64));
        assert!(bs.test_and_set(127));
        assert!(bs.is_set(0));
        assert!(bs.is_set(127));
        assert!(!bs.is_set(1));
        assert_eq!(bs.count(), 4);

        bs.clear();
        assert_eq!(bs.count(), 0);
        assert!(!bs.is_set(0));
    }

    /// 4 threads race on overlapping bits — no lost updates.
    #[test]
    fn concurrent_test_and_set() {
        let bs = Arc::new(AtomicBitSet::empty(64));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let bs = bs.clone();
                thread::spawn(move || {
                    // Each thread sets bits 0..8; overlapping is intentional.
                    for i in 0..8 {
                        bs.test_and_set((t * 4 + i) % 64);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        // All targeted bits should be set.
        assert!(bs.count() > 0);
    }

    /// Threads target different words — no lost updates across words.
    #[test]
    fn concurrent_different_words() {
        let bs = Arc::new(AtomicBitSet::empty(256));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let bs = bs.clone();
                thread::spawn(move || {
                    // Each thread works on a different 64-bit word.
                    let base = t * 64;
                    for i in 0..16 {
                        bs.test_and_set(base + i);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(bs.count(), 64); // 4 threads × 16 bits
    }

    /// Set bits from threads, join, then clear — validates clear after concurrent sets.
    #[test]
    fn clear_after_concurrent_sets() {
        let bs = Arc::new(AtomicBitSet::empty(128));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let bs = bs.clone();
                thread::spawn(move || {
                    for i in 0..8 {
                        bs.test_and_set(t * 8 + i);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(bs.count(), 32);

        bs.clear();
        assert_eq!(bs.count(), 0);
    }

    /// Small bitset (8 bits) with 4 threads doing many ops — stress test.
    #[test]
    fn stress_small() {
        let bs = Arc::new(AtomicBitSet::empty(8));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let bs = bs.clone();
                thread::spawn(move || {
                    for i in 0..8 {
                        bs.test_and_set(i);
                        bs.is_set(i);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        // All 8 bits must be set.
        assert_eq!(bs.count(), 8);
    }
}
