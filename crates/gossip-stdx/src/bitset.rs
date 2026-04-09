//! Heap-allocated [`DynamicBitSet`] for runtime-determined sizes.
//!
//! # Invariants
//! - Bits are stored in `u64` words; padding bits beyond the logical capacity are zero.
//! - `words.len() == words_for_bits(bit_length)`.
//!
//! Keeping padding bits zero avoids "phantom" set bits when iterating or counting
//! and makes the bitset safe to serialize or hash without masking.
//!
//! # Performance
//! - `is_set`, `set`, `unset` are O(1).
//! - `count` is O(WORDS).
//! - Iteration is O(WORDS + set bits).

/// Computes the number of `u64` words needed to store `n` bits.
///
/// Rounds up to the next word boundary; returns 0 when `n == 0`.
pub const fn words_for_bits(n: usize) -> usize {
    n.div_ceil(64)
}

/// Runtime-sized bitset backed by a `Vec<u64>`.
///
/// Unlike a fixed-size bitset with compile-time capacity, `DynamicBitSet`
/// allows the capacity to be determined at runtime. It is useful when the number
/// of bits is not known at compile time or varies per instance.
///
/// # Invariants
/// - `words.len() == words_for_bits(bit_length)`.
/// - Padding bits in the last word (if any) are always zero.
///
/// The implementation ensures that unused bits in the last word (if `bit_length`
/// is not a multiple of 64) are always zero. This invariant is critical for
/// `PartialEq` correctness, as it relies on slice equality.
///
/// All indexing operations debug-assert that `idx < bit_length` (elided in
/// release builds; see individual methods). Use [`iter_set`](Self::iter_set)
/// to traverse set bits in ascending order.
///
/// # Examples
///
/// ```
/// use gossip_stdx::bitset::DynamicBitSet;
///
/// let mut bits = DynamicBitSet::empty(100);
/// bits.set(1);
/// bits.set(50);
/// bits.set(99);
/// assert_eq!(bits.iter_set().collect::<Vec<_>>(), vec![1, 50, 99]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicBitSet {
    words: Vec<u64>,
    bit_length: usize,
}

impl DynamicBitSet {
    /// Creates an empty bitset with capacity for `bit_length` bits, all initialized to zero.
    ///
    /// # Arguments
    ///
    /// * `bit_length` - The number of addressable bits. May be zero.
    pub fn empty(bit_length: usize) -> Self {
        let words = vec![0u64; words_for_bits(bit_length)];
        Self { words, bit_length }
    }

    /// Returns the number of addressable bits.
    #[inline]
    pub fn bit_length(&self) -> usize {
        self.bit_length
    }

    #[inline]
    fn last_word_mask(&self) -> u64 {
        let remaining_bits = self.bit_length % 64;
        if remaining_bits == 0 {
            u64::MAX
        } else {
            (1u64 << remaining_bits) - 1
        }
    }

    /// Counts set bits; never exceeds `bit_length`.
    ///
    /// Optimized: splits the loop to avoid per-iteration branch on last word.
    #[inline]
    pub fn count(&self) -> usize {
        if self.words.is_empty() {
            return 0;
        }

        let len = self.words.len();
        let mut total = 0usize;

        // Process all words except the last one - no masking needed
        for &word in &self.words[..len - 1] {
            total += word.count_ones() as usize;
        }

        // Process the last word with mask
        total += (self.words[len - 1] & self.last_word_mask()).count_ones() as usize;
        total
    }

    /// Returns whether `idx` is set.
    ///
    /// Debug-asserts that `idx < bit_length`.
    #[inline]
    pub fn is_set(&self, idx: usize) -> bool {
        debug_assert!(idx < self.bit_length, "bit index out of bounds");
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        (self.words[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Sets the bit at `idx`.
    ///
    /// Debug-asserts that `idx < bit_length`.
    #[inline]
    pub fn set(&mut self, idx: usize) {
        debug_assert!(idx < self.bit_length, "bit index out of bounds");
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        self.words[word_idx] |= 1u64 << bit_idx;
    }

    /// Clears the bit at `idx`.
    ///
    /// Debug-asserts that `idx < bit_length`.
    #[inline]
    pub fn unset(&mut self, idx: usize) {
        debug_assert!(idx < self.bit_length, "bit index out of bounds");
        let word_idx = idx / 64;
        let bit_idx = idx % 64;
        self.words[word_idx] &= !(1u64 << bit_idx);
    }

    /// Returns a shared reference to the underlying word storage.
    #[inline]
    pub fn as_words(&self) -> &[u64] {
        &self.words
    }

    /// Constructs a bitset from a pre-existing word vector.
    ///
    /// # Preconditions
    ///
    /// The caller **must** ensure both invariants hold before calling:
    /// 1. `words.len() == words_for_bits(bit_length)`
    /// 2. Padding bits in the last word are zero.
    ///
    /// Both are debug-asserted but not enforced in release builds. Violating
    /// either invariant causes logical incorrectness (`PartialEq`, `count`,
    /// `iter_set` may return wrong results) but not memory unsafety.
    ///
    /// Prefer [`DynamicBitSet::empty`] when constructing from scratch. This
    /// constructor exists for deserialization paths that have already validated
    /// the word buffer externally.
    pub fn from_words(words: Vec<u64>, bit_length: usize) -> Self {
        debug_assert_eq!(
            words.len(),
            words_for_bits(bit_length),
            "word count does not match bit_length"
        );
        let bs = Self { words, bit_length };
        debug_assert!(
            bs.words.is_empty() || {
                let mask = !bs.last_word_mask();
                (bs.words[bs.words.len() - 1] & mask) == 0
            },
            "padding bits in last word must be zero"
        );
        bs
    }

    /// Clears all bits.
    #[inline]
    pub fn clear(&mut self) {
        self.words.fill(0);
    }

    /// Inverts all bits in the bitset.
    #[inline]
    pub fn toggle_all(&mut self) {
        for word in &mut self.words {
            *word = !*word;
        }

        // We must clear any bits in the last word that are beyond `bit_length`.
        // If we don't, `PartialEq` (which checks the full `Vec`) would fail against
        // a clean bitset, as the padding bits would become 1s after inversion.
        if !self.words.is_empty() {
            let last = self.words.len() - 1;
            let mask = self.last_word_mask();
            self.words[last] &= mask;
        }
    }

    /// Returns an iterator over set bit indices in ascending order.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_stdx::bitset::DynamicBitSet;
    ///
    /// let mut bits = DynamicBitSet::empty(64);
    /// bits.set(5);
    /// bits.set(10);
    ///
    /// for idx in bits.iter_set() {
    ///     println!("Bit {} is set", idx);
    /// }
    /// ```
    #[inline]
    pub fn iter_set(&self) -> DynamicBitSetIterator<'_> {
        DynamicBitSetIterator::new(self)
    }
}

/// Test helper for verifying the padding invariant.
#[cfg(any(all(test, feature = "stdx-proptest"), kani))]
impl DynamicBitSet {
    /// Returns `true` if the padding bits in the last word are all zero.
    ///
    /// This invariant is critical for correctness of `PartialEq` and safe
    /// serialization/hashing. `count()` and `iter_set()` mask the last word
    /// defensively but rely on the invariant as a secondary guarantee.
    pub(crate) fn padding_invariant_holds(&self) -> bool {
        if self.words.is_empty() {
            return true;
        }
        let padding_mask = !self.last_word_mask();
        (self.words[self.words.len() - 1] & padding_mask) == 0
    }
}

/// Iterator over set bit indices in ascending order, produced by [`DynamicBitSet::iter_set`].
///
/// Yields each index where the corresponding bit is set, from lowest to highest.
/// Padding bits in the final word are masked out.
pub struct DynamicBitSetIterator<'a> {
    words: &'a [u64],
    word_idx: usize,
    current_word: u64,
    last_word_idx: usize,
    last_word_mask: u64,
}

impl<'a> DynamicBitSetIterator<'a> {
    fn new(bit_set: &'a DynamicBitSet) -> Self {
        let words = &bit_set.words;
        let last_word_idx = words.len().saturating_sub(1);
        let last_word_mask = if words.is_empty() {
            0
        } else {
            bit_set.last_word_mask()
        };
        let mut current_word = if words.is_empty() { 0 } else { words[0] };
        if !words.is_empty() && last_word_idx == 0 {
            current_word &= last_word_mask;
        }
        Self {
            words,
            word_idx: 0,
            current_word,
            last_word_idx,
            last_word_mask,
        }
    }
}

impl<'a> Iterator for DynamicBitSetIterator<'a> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        loop {
            if self.current_word != 0 {
                let bit_idx = self.current_word.trailing_zeros() as usize;
                let idx = self.word_idx * 64 + bit_idx;
                self.current_word &= self.current_word.wrapping_sub(1);
                return Some(idx);
            }

            self.word_idx += 1;
            if self.word_idx >= self.words.len() {
                return None;
            }
            self.current_word = self.words[self.word_idx];
            if self.word_idx == self.last_word_idx {
                self.current_word &= self.last_word_mask;
            }
        }
    }
}

#[cfg(any(all(test, feature = "stdx-proptest"), kani))]
#[path = "bitset_tests.rs"]
mod bitset_tests;
