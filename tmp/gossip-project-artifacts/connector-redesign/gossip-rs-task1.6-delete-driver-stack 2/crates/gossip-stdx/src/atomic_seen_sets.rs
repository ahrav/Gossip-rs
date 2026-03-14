//! Composite concurrent dedup tracker for git object traversal.
//!
//! [`AtomicSeenSets`] wraps three [`AtomicBitSet`] instances — one each for
//! trees, blobs, and excluded-blobs — behind a domain-specific API. Each
//! `mark_*` method returns `true` on first call per index (first-writer-wins),
//! powered by the underlying atomic `fetch_or`.
//!
//! # Thread safety
//!
//! All operations are lock-free and safe to call from multiple threads
//! concurrently. `Send` and `Sync` are auto-derived from `AtomicBitSet`.
//!
//! # Contract
//!
//! - The three bitsets are fully independent: marking a tree at index `i`
//!   does not affect blobs or excluded-blobs at the same index.
//! - `clear` requires external synchronization (no concurrent `mark_*` calls
//!   in-flight), same as [`AtomicBitSet::clear`].

use super::atomic_bitset::AtomicBitSet;

/// Concurrent dedup tracker for git object traversal.
///
/// Wraps three [`AtomicBitSet`] instances (trees, blobs, excluded-blobs) to
/// track which git objects have already been visited during a scan. Each
/// `mark_*` method atomically sets the bit and returns `true` only on the
/// first call for that index, enabling first-writer-wins deduplication.
///
/// # Examples
///
/// ```
/// use gossip_stdx::atomic_seen_sets::AtomicSeenSets;
///
/// let seen = AtomicSeenSets::new(1024, 2048);
/// assert!(seen.mark_tree(42));        // first caller wins
/// assert!(!seen.mark_tree(42));       // already seen
/// assert!(seen.mark_blob(42));        // independent bitset
/// assert!(seen.mark_blob_excluded(42)); // also independent
/// ```
#[derive(Debug)]
pub struct AtomicSeenSets {
    trees: AtomicBitSet,
    blobs: AtomicBitSet,
    blobs_excluded: AtomicBitSet,
}

impl AtomicSeenSets {
    /// Creates a new tracker with the given capacities.
    ///
    /// `tree_capacity` sets the number of addressable tree indices.
    /// `blob_capacity` sets the number of addressable blob and excluded-blob
    /// indices (both blob bitsets share the same capacity).
    ///
    /// # Panics
    ///
    /// Panics if either capacity is zero.
    pub fn new(tree_capacity: usize, blob_capacity: usize) -> Self {
        Self {
            trees: AtomicBitSet::empty(tree_capacity),
            blobs: AtomicBitSet::empty(blob_capacity),
            blobs_excluded: AtomicBitSet::empty(blob_capacity),
        }
    }

    /// Marks a tree index as seen. Returns `true` if this is the first time
    /// (first-writer-wins).
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx` is out of bounds.
    #[inline(always)]
    pub fn mark_tree(&self, idx: usize) -> bool {
        self.trees.test_and_set(idx)
    }

    /// Marks a blob index as seen. Returns `true` if this is the first time.
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx` is out of bounds.
    #[inline(always)]
    pub fn mark_blob(&self, idx: usize) -> bool {
        self.blobs.test_and_set(idx)
    }

    /// Marks a blob index as excluded. Returns `true` if this is the first time.
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx` is out of bounds.
    #[inline(always)]
    pub fn mark_blob_excluded(&self, idx: usize) -> bool {
        self.blobs_excluded.test_and_set(idx)
    }

    /// Returns whether the tree at `idx` has been marked.
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx` is out of bounds.
    #[inline(always)]
    pub fn is_tree_seen(&self, idx: usize) -> bool {
        self.trees.is_set(idx)
    }

    /// Returns whether the blob at `idx` has been marked.
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx` is out of bounds.
    #[inline(always)]
    pub fn is_blob_seen(&self, idx: usize) -> bool {
        self.blobs.is_set(idx)
    }

    /// Returns whether the blob at `idx` has been marked as excluded.
    ///
    /// # Panics
    ///
    /// Panics (debug) if `idx` is out of bounds.
    #[inline(always)]
    pub fn is_blob_excluded(&self, idx: usize) -> bool {
        self.blobs_excluded.is_set(idx)
    }

    /// Resets all three bitsets to zero.
    ///
    /// # Safety contract (not `unsafe`, but important)
    ///
    /// Callers must ensure no concurrent `mark_*` calls are in-flight.
    /// See [`AtomicBitSet::clear`] for details.
    pub fn clear(&self) {
        self.trees.clear();
        self.blobs.clear();
        self.blobs_excluded.clear();
    }
}

// ---------------------------------------------------------------------------
// Test module includes
// ---------------------------------------------------------------------------

#[cfg(any(all(test, feature = "stdx-proptest"), kani))]
#[path = "atomic_seen_sets_tests.rs"]
mod atomic_seen_sets_tests;

// ---------------------------------------------------------------------------
// Loom concurrency tests
// ---------------------------------------------------------------------------

#[cfg(loom)]
mod loom_tests {
    use super::*;
    use loom::thread;

    /// Two threads race on the same tree index — exactly one wins.
    #[test]
    fn tree_dedup_exactly_one_wins() {
        loom::model(|| {
            let seen = std::sync::Arc::new(AtomicSeenSets::new(64, 64));
            let seen2 = seen.clone();

            let h = thread::spawn(move || seen2.mark_tree(0));

            let won_main = seen.mark_tree(0);
            let won_thread = h.join().unwrap();

            assert!(
                won_main ^ won_thread,
                "exactly one caller must win: main={won_main}, thread={won_thread}"
            );
            assert!(seen.is_tree_seen(0));
        });
    }

    /// Two threads race on the same blob index — exactly one wins.
    #[test]
    fn blob_dedup_exactly_one_wins() {
        loom::model(|| {
            let seen = std::sync::Arc::new(AtomicSeenSets::new(64, 64));
            let seen2 = seen.clone();

            let h = thread::spawn(move || seen2.mark_blob(0));

            let won_main = seen.mark_blob(0);
            let won_thread = h.join().unwrap();

            assert!(
                won_main ^ won_thread,
                "exactly one caller must win: main={won_main}, thread={won_thread}"
            );
            assert!(seen.is_blob_seen(0));
        });
    }

    /// One thread marks tree, another marks blob at same index — both win
    /// (independent bitsets).
    #[test]
    fn tree_and_blob_independent() {
        loom::model(|| {
            let seen = std::sync::Arc::new(AtomicSeenSets::new(64, 64));
            let seen2 = seen.clone();

            let h = thread::spawn(move || seen2.mark_blob(0));

            let won_tree = seen.mark_tree(0);
            let won_blob = h.join().unwrap();

            assert!(won_tree, "tree mark must succeed");
            assert!(won_blob, "blob mark must succeed (independent bitset)");
            assert!(seen.is_tree_seen(0));
            assert!(seen.is_blob_seen(0));
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

    /// 4 threads concurrently marking all three bitsets.
    #[test]
    fn concurrent_all_three_bitsets() {
        let seen = Arc::new(AtomicSeenSets::new(64, 64));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let seen = seen.clone();
                thread::spawn(move || {
                    for i in 0..8 {
                        let idx = (t * 4 + i) % 64;
                        seen.mark_tree(idx);
                        seen.mark_blob(idx);
                        seen.mark_blob_excluded(idx);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        // All targeted indices should be set across all three bitsets.
        assert!(seen.is_tree_seen(0));
        assert!(seen.is_blob_seen(0));
        assert!(seen.is_blob_excluded(0));
    }

    /// Threads targeting different bitsets (trees vs blobs).
    #[test]
    fn threads_target_different_bitsets() {
        let seen = Arc::new(AtomicSeenSets::new(64, 64));
        let seen2 = seen.clone();
        let seen3 = seen.clone();

        let h1 = thread::spawn(move || {
            for i in 0..16 {
                seen2.mark_tree(i);
            }
        });
        let h2 = thread::spawn(move || {
            for i in 0..16 {
                seen3.mark_blob(i);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        for i in 0..16 {
            assert!(seen.is_tree_seen(i));
            assert!(seen.is_blob_seen(i));
        }
    }

    /// Threads targeting same bitset with overlapping indices.
    #[test]
    fn overlapping_indices_same_bitset() {
        let seen = Arc::new(AtomicSeenSets::new(16, 16));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let seen = seen.clone();
                thread::spawn(move || {
                    for i in 0..16 {
                        seen.mark_tree(i);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        for i in 0..16 {
            assert!(seen.is_tree_seen(i));
        }
    }

    /// Clear after concurrent sets.
    #[test]
    fn clear_after_concurrent_sets() {
        let seen = Arc::new(AtomicSeenSets::new(64, 64));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let seen = seen.clone();
                thread::spawn(move || {
                    for i in 0..8 {
                        seen.mark_tree(t * 8 + i);
                        seen.mark_blob(t * 8 + i);
                        seen.mark_blob_excluded(t * 8 + i);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        seen.clear();

        for i in 0..32 {
            assert!(!seen.is_tree_seen(i));
            assert!(!seen.is_blob_seen(i));
            assert!(!seen.is_blob_excluded(i));
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn construction_various_capacities() {
        let s1 = AtomicSeenSets::new(1, 1);
        assert!(!s1.is_tree_seen(0));

        let s2 = AtomicSeenSets::new(64, 128);
        assert!(!s2.is_tree_seen(63));
        assert!(!s2.is_blob_seen(127));

        let s3 = AtomicSeenSets::new(1000, 2000);
        assert!(!s3.is_tree_seen(999));
        assert!(!s3.is_blob_seen(1999));
    }

    #[test]
    fn different_tree_and_blob_capacity() {
        let seen = AtomicSeenSets::new(32, 256);

        assert!(seen.mark_tree(31));
        assert!(seen.mark_blob(255));
        assert!(seen.mark_blob_excluded(255));

        assert!(seen.is_tree_seen(31));
        assert!(seen.is_blob_seen(255));
        assert!(seen.is_blob_excluded(255));
    }

    #[test]
    fn debug_format() {
        let seen = AtomicSeenSets::new(64, 128);
        seen.mark_tree(0);
        seen.mark_blob(1);
        let dbg = format!("{:?}", seen);
        assert!(dbg.contains("AtomicSeenSets"));
        assert!(dbg.contains("AtomicBitSet"));
    }
}
