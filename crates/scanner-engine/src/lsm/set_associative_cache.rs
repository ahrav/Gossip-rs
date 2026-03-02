//! Set-associative cache with CLOCK Nth-Chance eviction.
//!
//! Purpose: provide a compact, cache-line-friendly cache for LSM hot data.
//!
//! Invariants and safety rules:
//! - `WAYS` is in {2, 4, 16} and is a power of two.
//! - `TagT::BITS` is 8 or 16.
//! - `CLOCK_BITS` is 1, 2, or 4 (counts fit in a `u8`).
//! - `CACHE_LINE_SIZE` is a power of two; value alignment is a power of two
//!   (`VALUE_ALIGNMENT == 0` uses the value type's alignment).
//! - `CLOCK_HAND_BITS == log2(WAYS)`.
//! - `value_count_max` is a multiple of `WAYS` and `VALUE_COUNT_MAX_MULTIPLE`.
//! - Slots are occupied iff their count is non-zero; tags may be stale.
//! - Values are `Copy` and are not dropped; storage is reused without destructors.
//! - This cache is not thread-safe; callers must synchronize shared access.
//!
//! High-level algorithm:
//! 1. Hash the key to 64-bit entropy.
//! 2. Select a set with `fast_range` and derive a tag with `Tag::truncate`.
//! 3. On lookup, match tags, then confirm keys for occupied slots.
//! 4. On insert, scan from the clock hand, decrementing counts until a zero slot
//!    is found, then insert and advance the hand.
//!
//! Design choices:
//! - Tags are stored separately to keep hot metadata compact.
//! - Counts and clock hands are packed into 64-bit words to reduce overhead.
//! - Values are stored in an aligned buffer so each set is contiguous.
use std::{
    alloc::{Layout as AllocLayout, alloc, dealloc},
    cell::{Cell, UnsafeCell},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::NonNull,
};

use crate::stdx::fastrange::fast_range;

/// Indicates whether an upsert operation updated an existing entry or inserted a new one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateOrInsert {
    /// An existing entry with the same key was found and its value was replaced.
    Update,
    /// No existing entry matched the key, so a new entry was created.
    Insert,
}

/// A short, partial hash of a key, stored alongside cached values.
///
/// Because the tag is small, collisions are possible: `tag(k1) == tag(k2)` does not
/// imply `k1 == k2`. However, most of the time, where the tag differs, a full key
/// comparison can be avoided. Since tags are 16-32x smaller than keys, they can also
/// be kept hot in cache.
///
/// Guarantees / invariants:
/// - `truncate` must be deterministic for a given entropy value.
/// - This cache only accepts tags with `BITS` of 8 or 16 (enforced at init).
pub trait Tag: Copy + Eq + PartialEq + Default {
    /// The number of bits in this tag type.
    const BITS: usize;

    /// Extracts a tag from hash entropy by truncating to the tag width.
    fn truncate(entropy: u64) -> Self;
}

/// 8-bit tag implementation.
impl Tag for u8 {
    const BITS: usize = 8;

    #[inline]
    fn truncate(entropy: u64) -> Self {
        entropy as u8
    }
}

/// 16-bit tag implementation.
impl Tag for u16 {
    const BITS: usize = 16;

    #[inline]
    fn truncate(entropy: u64) -> Self {
        entropy as u16
    }
}

/// Defines the key/value types and operations required by a set-associative cache.
///
/// This mirrors Zig's comptime `key_from_value` and `hash` parameters.
///
/// Guarantees / invariants:
/// - `key_from_value` must return the same key used to hash the value.
/// - `hash` must be deterministic and equal for equal keys.
/// - A well-distributed hash improves set balance and hit rate.
pub trait SetAssociativeCacheContext {
    /// The key type used for lookups.
    type Key: Copy + Eq;

    /// The value type stored in the cache.
    type Value: Copy;

    /// Extracts the key from a cached value.
    fn key_from_value(value: &Self::Value) -> Self::Key;

    /// Computes a hash of the given key.
    fn hash(key: Self::Key) -> u64;
}

/// Tracks cache performance statistics using interior mutability.
///
/// Notes:
/// - Not thread-safe; counters are updated with `Cell` and can race under sharing.
/// - Counters can overflow (debug builds panic; release builds wrap).
#[derive(Debug)]
pub struct Metrics {
    /// Count of cache lookups that found the requested key.
    hits: Cell<u64>,
    /// Count of cache lookups that did not find the requested key.
    misses: Cell<u64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            hits: Cell::new(0),
            misses: Cell::new(0),
        }
    }
}

impl Metrics {
    /// Resets all counters to zero.
    #[inline]
    pub fn reset(&self) {
        self.hits.set(0);
        self.misses.set(0);
    }

    /// Returns the number of cache hits since the last reset.
    #[inline]
    pub fn hits(&self) -> u64 {
        self.hits.get()
    }

    /// Returns the number of cache misses since the last reset.
    #[inline]
    pub fn misses(&self) -> u64 {
        self.misses.get()
    }
}

/// Packed unsigned integers stored in little-endian 64-bit words.
///
/// A little simpler than `PackedIntArray` in the standard library, restricted to
/// little-endian 64-bit words and using words exactly without padding.
///
/// Guarantees / invariants:
/// - `BITS` is a power of two less than 8.
/// - Values are stored densely without padding.
///
/// Complexity:
/// - `get`/`set` are O(1).
#[derive(Debug)]
pub struct PackedUnsignedIntegerArray<const BITS: usize> {
    words: Box<[u64]>,
}

impl<const BITS: usize> PackedUnsignedIntegerArray<BITS> {
    const WORD_BITS: usize = 64;

    #[inline]
    const fn uints_per_word() -> usize {
        Self::WORD_BITS / BITS
    }

    #[inline]
    const fn mask_value() -> u64 {
        (1u64 << BITS) - 1
    }

    /// Returns the number of 64-bit words needed to store `len` values.
    #[inline]
    pub const fn words_for_len(len: usize) -> usize {
        let bits = len * BITS;
        bits.div_ceil(Self::WORD_BITS)
    }

    /// Allocates a zeroed array with `words_len` 64-bit words.
    ///
    /// # Panics
    ///
    /// Panics if `BITS` is invalid for packing (not power of two, >= 8) or if
    /// the platform endianness is not little-endian.
    pub fn new_zeroed(words_len: usize) -> Self {
        const { assert!(cfg!(target_endian = "little")) };
        assert!(BITS < 8);
        assert!(BITS.is_power_of_two());
        assert!(Self::WORD_BITS.is_multiple_of(BITS));
        Self {
            words: vec![0u64; words_len].into_boxed_slice(),
        }
    }

    /// Wraps an existing word buffer without copying.
    ///
    /// # Panics
    ///
    /// Panics if `BITS` is invalid for packing (not power of two, >= 8) or if
    /// the platform endianness is not little-endian.
    pub fn from_words(words: Vec<u64>) -> Self {
        const { assert!(cfg!(target_endian = "little")) };
        assert!(BITS < 8);
        assert!(BITS.is_power_of_two());
        assert!(Self::WORD_BITS.is_multiple_of(BITS));
        Self {
            words: words.into_boxed_slice(),
        }
    }

    /// Returns the backing storage as 64-bit words.
    #[inline]
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// Returns the backing storage as mutable 64-bit words.
    #[inline]
    pub fn words_mut(&mut self) -> &mut [u64] {
        &mut self.words
    }

    /// Returns the packed unsigned integer at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn get(&self, index: u64) -> u8 {
        let uints_per_word = Self::uints_per_word() as u64;
        let word_index = index / uints_per_word;
        let within = index % uints_per_word;
        let shift = (within as usize) * BITS;
        debug_assert!(word_index < self.words.len() as u64);
        let word = self.words[word_index as usize];
        ((word >> shift) & Self::mask_value()) as u8
    }

    /// Sets the packed unsigned integer at `index` to `value`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `index` is out of bounds or if `value` does not fit in `BITS`.
    /// In release builds, bounds are checked via the slice indexing.
    #[inline]
    pub fn set(&mut self, index: u64, value: u8) {
        debug_assert!((value as u64) <= Self::mask_value());
        let uints_per_word = Self::uints_per_word() as u64;
        let word_index = index / uints_per_word;
        let within = index % uints_per_word;
        let shift = (within as usize) * BITS;
        let mask = Self::mask_value() << shift;
        debug_assert!(word_index < self.words.len() as u64);
        let w = &mut self.words[word_index as usize];
        *w = (*w & !mask) | ((value as u64) << shift);
    }
}

/// A heap-allocated buffer with custom alignment for cache-line-aligned storage.
///
/// Elements are stored as `MaybeUninit<T>`; callers must track initialization state.
/// `Drop` deallocates memory but does NOT run element destructors, so this is
/// intended for `Copy` types or manual drop management.
///
/// Invariants:
/// - `len > 0`.
/// - `alignment` is a power of two and `alignment >= align_of::<T>()`.
/// - `size_of::<T>()` is a multiple of `alignment` so each element is aligned.
#[derive(Debug)]
#[allow(clippy::len_without_is_empty)] // Buffer is never empty (len > 0 enforced at construction)
pub struct AlignedBuf<T> {
    ptr: NonNull<MaybeUninit<T>>,
    len: usize,
    layout: AllocLayout,
    _marker: PhantomData<T>,
}

impl<T> AlignedBuf<T> {
    /// Allocates an uninitialized buffer with the specified length and alignment.
    ///
    /// # Panics
    ///
    /// Panics if `len == 0`, `alignment < align_of::<T>()`, `alignment` is not a power of two,
    /// `size_of::<T>()` is not a multiple of `alignment`, or allocation fails.
    pub fn new_uninit(len: usize, alignment: usize) -> Self {
        assert!(len > 0);
        assert!(alignment >= align_of::<T>());
        assert!(alignment.is_power_of_two());
        assert!(size_of::<T>().is_multiple_of(alignment));

        let bytes = len.checked_mul(size_of::<T>()).expect("size overflow");

        let layout = AllocLayout::from_size_align(bytes, alignment).expect("bad layout");

        // SAFETY: Layout is valid (size > 0, alignment is power of two, size fits in isize).
        // We check for null below.
        let raw = unsafe { alloc(layout) } as *mut MaybeUninit<T>;
        let ptr = NonNull::new(raw).expect("oom");

        Self {
            ptr,
            len,
            layout,
            _marker: PhantomData,
        }
    }

    /// Returns the number of elements in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns a raw pointer to the buffer's first element.
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr() as *const T
    }

    /// Returns a mutable raw pointer to the buffer's first element.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr() as *mut T
    }

    /// Returns a mutable pointer to the element at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index >= len`.
    #[inline]
    pub fn get_ptr(&self, index: usize) -> *mut T {
        assert!(index < self.len);
        self.ptr.as_ptr().wrapping_add(index) as *mut T
    }

    /// Returns a reference to the element at `index`.
    ///
    /// # Safety
    ///
    /// The slot at `index` must have been initialized via [`write`](Self::write).
    ///
    /// # Panics
    ///
    /// Panics if `index >= len`.
    #[inline]
    pub unsafe fn get_ref(&self, index: usize) -> &T {
        assert!(index < self.len);
        // SAFETY: Caller guarantees the slot is initialized. Pointer is valid and aligned.
        unsafe { (&*self.ptr.as_ptr().add(index)).assume_init_ref() }
    }

    /// Reads a copy of the element at `index`.
    ///
    /// # Safety
    ///
    /// The slot at `index` must have been initialized via [`write`](Self::write).
    ///
    /// # Panics
    ///
    /// Panics if `index >= len`.
    #[inline]
    pub unsafe fn read_copy(&self, index: usize) -> T
    where
        T: Copy,
    {
        assert!(index < self.len);
        // SAFETY: Caller guarantees the slot is initialized. T: Copy prevents double-drop.
        unsafe { (&*self.ptr.as_ptr().add(index)).assume_init_read() }
    }

    /// Writes a value to the slot at `index`, initializing it.
    ///
    /// # Panics
    ///
    /// Panics if `index >= len`.
    #[inline]
    pub fn write(&mut self, index: usize, value: T) {
        assert!(index < self.len);
        // SAFETY: Index is bounds-checked. Pointer is valid and properly aligned.
        unsafe {
            self.ptr.as_ptr().add(index).write(MaybeUninit::new(value));
        }
    }

    /// Marks the slot at `index` as uninitialized.
    ///
    /// # Panics
    ///
    /// Panics if `index >= len`.
    #[inline]
    pub fn write_uninit(&mut self, index: usize) {
        assert!(index < self.len);
        // SAFETY: Index is bounds-checked. Pointer is valid and properly aligned.
        unsafe {
            self.ptr.as_ptr().add(index).write(MaybeUninit::uninit());
        }
    }
}

impl<T> Drop for AlignedBuf<T> {
    fn drop(&mut self) {
        // SAFETY: Layout matches the one used in new_uninit. Pointer is valid.
        // Note: Element destructors are NOT run—this is intentional for Copy types.
        unsafe {
            dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
        }
    }
}

/// Configuration options for initializing a cache instance.
pub struct Options<'a> {
    /// Human-readable name used for diagnostics.
    pub name: &'a str,
}

/// Result of inserting or updating a cache entry.
pub struct UpsertResult<V> {
    /// Index of the slot written within the cache storage.
    pub index: usize,
    /// Whether the operation replaced an existing entry or inserted a new one.
    pub updated: UpdateOrInsert,
    /// The evicted value, if an insertion displaced an older entry.
    pub evicted: Option<V>,
}

/// Per-set view used during lookups and insertions.
///
/// Each key maps to a set of `WAYS` consecutive slots; this bundles the derived
/// tag and pointers into the backing tag/value arrays for that set. The
/// `offset` is the base index used to address the set's ways.
#[derive(Clone, Copy)]
struct Set<TagT, ValueT, const WAYS: usize> {
    /// Tag derived from the lookup key's hash entropy.
    tag: TagT,
    /// Base index for this set in the tag/value arrays.
    offset: u64,
    /// Tag storage for the `WAYS` slots in this set.
    tags: *mut [TagT; WAYS],
    /// Value storage for the `WAYS` slots in this set.
    values: *mut [ValueT; WAYS],
}

/// N-way set-associative cache with CLOCK Nth-Chance eviction.
///
/// Each key maps to one set of `WAYS` consecutive slots that may contain its
/// value. Tags provide a compact hash prefix to avoid full key comparisons on
/// most misses, while counts/clocks drive the replacement policy.
///
/// Guarantees / invariants:
/// - A slot is occupied iff its count is non-zero; tags may be stale when empty.
/// - Tag matches are advisory; a full key comparison is authoritative.
///
/// Eviction:
/// - CLOCK Nth-Chance; counts saturate on hit and are decremented on miss.
/// - Insert scans from the per-set clock hand and advances it after placement.
///
/// Layout:
/// - Tags, values, counts, and clock hands are sized to align to cache lines.
///
/// Concurrency:
/// - Not thread-safe; interior mutability is used without synchronization.
pub struct SetAssociativeCache<
    'a,
    C,
    TagT,
    const WAYS: usize,
    const CLOCK_BITS: usize,
    const CACHE_LINE_SIZE: usize,
    const VALUE_ALIGNMENT: usize,
    const CLOCK_HAND_BITS: usize,
> where
    C: SetAssociativeCacheContext,
    TagT: Tag,
{
    /// Human-readable cache name for diagnostics.
    name: &'a str,
    /// Number of sets in the cache.
    sets: u64,

    /// Hit/miss counters stored behind interior mutability.
    metrics: Box<UnsafeCell<Metrics>>,

    /// Short, partial hashes of keys stored alongside cached values.
    ///
    /// Because the tag is small, collisions are possible: `tag(k1) == tag(k2)`
    /// does not imply `k1 == k2`. However, most of the time, where the tag
    /// differs, a full key comparison can be avoided. Since tags are 16-32x
    /// smaller than keys, they can also be kept hot in cache.
    tags: Vec<TagT>,

    /// Cache values; a slot is present when its count is non-zero.
    values: AlignedBuf<C::Value>,

    /// Per-slot access counts, tracking recent reads.
    ///
    /// * A count is incremented when a value is accessed by `get`.
    /// * A count is decremented when a cache write to the value's set misses.
    /// * A value is evicted when its count reaches zero.
    counts: UnsafeCell<PackedUnsignedIntegerArray<CLOCK_BITS>>,

    /// Per-set clock hand that rotates across ways to find eviction candidates.
    ///
    /// On cache write, entries are checked for occupancy (or eviction) beginning
    /// from the clock's position, wrapping around. The algorithm implemented is
    /// CLOCK Nth-Chance, where each way has more than one bit to give entries
    /// multiple chances before eviction. A similar algorithm called "RRIParoo"
    /// is described in "Kangaroo: Caching Billions of Tiny Objects on Flash".
    /// For general background, see:
    /// https://en.wikipedia.org/wiki/Page_replacement_algorithm.
    clocks: UnsafeCell<PackedUnsignedIntegerArray<CLOCK_HAND_BITS>>,

    /// Marker for the cache context's key/value types.
    _marker: PhantomData<C>,
}

impl<
    'a,
    C,
    TagT,
    const WAYS: usize,
    const CLOCK_BITS: usize,
    const CACHE_LINE_SIZE: usize,
    const VALUE_ALIGNMENT: usize,
    const CLOCK_HAND_BITS: usize,
>
    SetAssociativeCache<
        'a,
        C,
        TagT,
        WAYS,
        CLOCK_BITS,
        CACHE_LINE_SIZE,
        VALUE_ALIGNMENT,
        CLOCK_HAND_BITS,
    >
where
    C: SetAssociativeCacheContext,
    TagT: Tag,
{
    /// Smallest multiple required for `value_count_max` to keep all arrays aligned.
    pub const VALUE_COUNT_MAX_MULTIPLE: u64 = {
        const fn max_u(a: u64, b: u64) -> u64 {
            if a > b { a } else { b }
        }

        const fn min_u(a: u64, b: u64) -> u64 {
            if a < b { a } else { b }
        }

        let value_size = size_of::<C::Value>() as u64;
        let cache_line = CACHE_LINE_SIZE as u64;
        let ways = WAYS as u64;
        let values_term = (max_u(value_size, cache_line) / min_u(value_size, cache_line)) * ways;
        let counts_term = (cache_line * 8) / CLOCK_BITS as u64;
        max_u(values_term, counts_term)
    };

    #[inline]
    fn value_alignment() -> usize {
        if VALUE_ALIGNMENT == 0 {
            align_of::<C::Value>()
        } else {
            VALUE_ALIGNMENT
        }
    }

    #[inline]
    fn max_count() -> u8 {
        debug_assert!(CLOCK_BITS <= 8);
        ((1u16 << CLOCK_BITS) - 1) as u8
    }

    #[inline]
    fn wrap_way(way: usize) -> usize {
        way & (WAYS - 1)
    }

    #[inline]
    fn metric_ref(&self) -> &Metrics {
        // SAFETY: Single-threaded access; no mutable aliases exist.
        unsafe { &*self.metrics.as_ref().get() }
    }

    #[inline]
    fn index_usize(index: u64) -> usize {
        let idx = index as usize;
        debug_assert_eq!(idx as u64, index);
        idx
    }

    /// Initializes a cache sized for `value_count_max` values.
    ///
    /// `value_count_max` must be a multiple of `WAYS` and `VALUE_COUNT_MAX_MULTIPLE` so that
    /// tags, values, counts, and clocks stay cache-line aligned. This allocates the backing
    /// arrays and zeroes the tag/count/clock state via `reset`.
    ///
    /// Guarantees / invariants:
    /// - Tag, count, and clock storage are sized to be cache-line aligned.
    /// - Tags are reset to `TagT::default`, counts/clocks are zeroed, and metrics reset.
    ///
    /// # Panics
    ///
    /// Panics if any layout invariant is violated (ways/tag bits/clock bits, cache-line or value
    /// alignment constraints) or if computed sizes overflow.
    pub fn init(value_count_max: u64, options: Options<'a>) -> Self {
        assert!(size_of::<C::Key>().is_power_of_two());
        assert!(size_of::<C::Value>().is_power_of_two());

        match WAYS {
            2 | 4 | 16 => {}
            _ => panic!("Invalid number of ways"),
        }

        match TagT::BITS {
            8 | 16 => {}
            _ => panic!("tag bits must be 8 or 16"),
        }

        match CLOCK_BITS {
            1 | 2 | 4 => {}
            _ => panic!("CLOCK_BITS must be 1, 2, or 4"),
        }

        let value_alignment = Self::value_alignment();
        assert!(value_alignment >= align_of::<C::Value>());
        assert!(size_of::<C::Value>().is_multiple_of(value_alignment));

        assert!(WAYS.is_power_of_two());
        assert!(TagT::BITS.is_power_of_two());
        assert!(CLOCK_BITS.is_power_of_two());
        assert!(CACHE_LINE_SIZE.is_power_of_two());

        assert!(size_of::<C::Key>() <= size_of::<C::Value>());
        assert!(size_of::<C::Key>() < CACHE_LINE_SIZE);
        assert!(CACHE_LINE_SIZE.is_multiple_of(size_of::<C::Key>()));

        if CACHE_LINE_SIZE > size_of::<C::Value>() {
            assert!(CACHE_LINE_SIZE.is_multiple_of(size_of::<C::Value>()));
        } else {
            assert!(size_of::<C::Value>().is_multiple_of(CACHE_LINE_SIZE));
        }

        assert!(CLOCK_HAND_BITS.is_power_of_two());
        assert_eq!((1usize << CLOCK_HAND_BITS), WAYS);

        let ways_u64 = WAYS as u64;
        let cache_line_u64 = CACHE_LINE_SIZE as u64;
        let tag_bits_u64 = TagT::BITS as u64;
        let clock_bits_u64 = CLOCK_BITS as u64;
        let clock_hand_bits = CLOCK_HAND_BITS as u64;

        let tags_divisor = ways_u64 * tag_bits_u64;
        assert!(tags_divisor > 0);
        assert_eq!((cache_line_u64 * 8) % tags_divisor, 0);
        let _tags_per_line = (cache_line_u64 * 8) / tags_divisor;
        assert!(_tags_per_line > 0);

        let clock_divisor = ways_u64 * clock_bits_u64;
        assert!(clock_divisor > 0);
        assert_eq!((cache_line_u64 * 8) % clock_divisor, 0);
        let _clocks_per_line = (cache_line_u64 * 8) / clock_divisor;
        assert!(_clocks_per_line > 0);

        assert_eq!((cache_line_u64 * 8) % clock_bits_u64, 0);
        let _clock_hand_per_line = (cache_line_u64 * 8) / clock_hand_bits;
        assert!(_clock_hand_per_line > 0);

        assert!(value_count_max > 0);
        assert!(value_count_max >= ways_u64);
        assert_eq!(value_count_max % ways_u64, 0);

        let sets = value_count_max / ways_u64;

        let value_size = size_of::<C::Value>() as u64;
        let values_size_max = value_count_max
            .checked_mul(value_size)
            .expect("values_size_max overflow");
        assert!(values_size_max >= cache_line_u64);
        assert_eq!(values_size_max % cache_line_u64, 0);

        let counts_bits = value_count_max
            .checked_mul(clock_bits_u64)
            .expect("counts_bits overflow");
        assert_eq!(counts_bits % 8, 0);
        let counts_size = counts_bits / 8;
        assert!(counts_size >= cache_line_u64);
        assert_eq!(counts_size % cache_line_u64, 0);
        assert_eq!(counts_size % 8, 0);
        let counts_words_len = counts_size / 8;

        let clocks_bits = sets
            .checked_mul(clock_hand_bits)
            .expect("clocks_bits overflow");
        assert_eq!(clocks_bits % 8, 0);
        let clocks_size = clocks_bits / 8;
        let _ = clocks_size;
        let clocks_words_len = clocks_bits.div_ceil(64);

        assert_eq!(value_count_max % Self::VALUE_COUNT_MAX_MULTIPLE, 0);
        assert!(value_count_max <= usize::MAX as u64);
        let value_count_max_usize =
            usize::try_from(value_count_max).expect("value_count_max overflow usize");
        let counts_words_len_usize =
            usize::try_from(counts_words_len).expect("counts_words_len overflow usize");
        let clocks_words_len_usize =
            usize::try_from(clocks_words_len).expect("clocks_words_len overflow usize");

        let tags = vec![TagT::default(); value_count_max_usize];
        let values = AlignedBuf::<C::Value>::new_uninit(value_count_max_usize, value_alignment);
        let counts = PackedUnsignedIntegerArray::<CLOCK_BITS>::new_zeroed(counts_words_len_usize);
        let clocks =
            PackedUnsignedIntegerArray::<CLOCK_HAND_BITS>::new_zeroed(clocks_words_len_usize);

        let mut sac = Self {
            name: options.name,
            sets,
            metrics: Box::new(UnsafeCell::new(Metrics::default())),
            tags,
            values,
            counts: UnsafeCell::new(counts),
            clocks: UnsafeCell::new(clocks),
            _marker: PhantomData,
        };

        sac.reset();
        sac
    }

    /// Clears tags, counts, clocks, and metrics.
    ///
    /// Note: values are left untouched; counts determine occupancy.
    pub fn reset(&mut self) {
        self.tags.fill(TagT::default());
        // SAFETY: Exclusive `&mut self` guarantees no concurrent access to counts/clocks.
        unsafe {
            (*self.counts.get()).words_mut().fill(0);
            (*self.clocks.get()).words_mut().fill(0);
        }
        self.metric_ref().reset();
    }

    /// Returns the cache name for diagnostics.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Looks up `key` and returns its slot index, updating counters on hit/miss.
    pub fn get_index(&self, key: C::Key) -> Option<usize> {
        let metrics_enabled = cfg!(all(feature = "perf-stats", debug_assertions));
        let set = self.associate(key);
        if let Some(way) = self.search(set, key) {
            if metrics_enabled {
                let metrics = self.metric_ref();
                metrics.hits.set(metrics.hits.get() + 1);
            }

            let idx = set.offset + way as u64;
            let count = self.counts_get(idx);
            let next = count.saturating_add(1).min(Self::max_count());
            self.counts_set(idx, next);
            Some(Self::index_usize(idx))
        } else {
            if metrics_enabled {
                let metrics = self.metric_ref();
                metrics.misses.set(metrics.misses.get() + 1);
            }
            None
        }
    }

    /// Looks up `key` and returns a pointer to the cached value, if present.
    ///
    /// The returned pointer is valid until the entry is evicted, removed, or the
    /// cache is reset.
    pub fn get(&self, key: C::Key) -> Option<*mut C::Value> {
        let index = self.get_index(key)?;
        Some(self.values.get_ptr(index))
    }

    /// Removes `key` from the cache if present, returning the removed value.
    ///
    /// The tag is not cleared; occupancy is tracked by the count.
    pub fn remove(&mut self, key: C::Key) -> Option<C::Value> {
        let set = self.associate(key);
        let way = self.search(set, key)?;

        let idx = set.offset + way as u64;
        let idx_usize = Self::index_usize(idx);
        // SAFETY: Slot is occupied (search found it), so the value is initialized.
        let removed = unsafe { self.values.read_copy(idx_usize) };
        self.counts_set(idx, 0);
        self.values.write_uninit(idx_usize);
        Some(removed)
    }

    /// Hints that `key` is less likely to be accessed without removing it.
    pub fn demote(&mut self, key: C::Key) {
        let set = self.associate(key);
        let Some(way) = self.search(set, key) else {
            return;
        };
        let idx = set.offset + way as u64;
        self.counts_set(idx, 1);
    }

    /// Inserts or updates `value`, evicting an older entry if needed.
    ///
    /// On update, the existing entry is replaced and its count is reset to 1. On
    /// insert, the CLOCK Nth-Chance scan starts at the set's clock hand, walking
    /// ways until a zero-count slot is found (or becomes zero after decrement).
    /// The clock hand advances to the next way after insertion.
    pub fn upsert(&mut self, value: &C::Value) -> UpsertResult<C::Value> {
        let key = C::key_from_value(value);
        let set = self.associate(key);
        let offset_usize = Self::index_usize(set.offset);

        if let Some(way) = self.search(set, key) {
            let way_usize = way as usize;
            let idx = set.offset + way as u64;
            let idx_usize = offset_usize + way_usize;
            self.counts_set(idx, 1);
            // SAFETY: Slot is occupied (search matched), so the value is initialized.
            let evicted = unsafe { self.values.read_copy(idx_usize) };
            self.values.write(idx_usize, *value);
            return UpsertResult {
                index: idx_usize,
                updated: UpdateOrInsert::Update,
                evicted: Some(evicted),
            };
        }

        let clock_index = set.offset / WAYS as u64;
        let mut way = self.clocks_get(clock_index) as usize;
        debug_assert!(way < WAYS);

        let max_count = Self::max_count() as usize;
        // Worst-case: decrement each way (max_count - 1) times before reaching zero.
        let clock_iterations_max = WAYS * (max_count.saturating_sub(1));

        let mut evicted: Option<C::Value> = None;
        let mut safety_count: usize = 0;

        while safety_count <= clock_iterations_max {
            let idx = set.offset + way as u64;
            let idx_usize = offset_usize + way;
            let mut count = self.counts_get(idx) as usize;
            if count == 0 {
                break;
            }

            count -= 1;
            self.counts_set(idx, count as u8);
            if count == 0 {
                // SAFETY: Count was non-zero before decrement, so the slot was occupied and initialized.
                evicted = Some(unsafe { self.values.read_copy(idx_usize) });
                break;
            }

            safety_count += 1;
            way = Self::wrap_way(way + 1);
        }
        if safety_count > clock_iterations_max {
            unreachable!("clock eviction exceeded maximum iterations");
        }

        assert_eq!(self.counts_get(set.offset + way as u64), 0);

        self.tags[offset_usize + way] = set.tag;
        self.values.write(offset_usize + way, *value);
        self.counts_set(set.offset + way as u64, 1);
        self.clocks_set(clock_index, Self::wrap_way(way + 1) as u8);

        UpsertResult {
            index: offset_usize + way,
            updated: UpdateOrInsert::Insert,
            evicted,
        }
    }

    // ----- Internals -----

    /// Computes the set metadata for `key` (tag, offset, and set-local pointers).
    #[inline]
    fn associate(&self, key: C::Key) -> Set<TagT, C::Value, WAYS> {
        let entropy = C::hash(key);
        let tag = TagT::truncate(entropy);
        let index = fast_range(entropy, self.sets);
        let offset = index * WAYS as u64;

        let offset_usize = Self::index_usize(offset);
        debug_assert!(offset_usize + WAYS <= self.tags.len());
        debug_assert!(offset_usize + WAYS <= self.values.len());

        // SAFETY: offset_usize + WAYS is bounds-checked by debug_asserts above; pointer
        // arithmetic stays within the allocated tags buffer.
        let tags = unsafe { self.tags.as_ptr().add(offset_usize) as *mut [TagT; WAYS] };
        // SAFETY: Same bounds check applies; pointer stays within the allocated values buffer.
        let values = unsafe { self.values.as_ptr().add(offset_usize) as *mut [C::Value; WAYS] };

        Set {
            tag,
            offset,
            tags,
            values,
        }
    }

    /// If the key is present in the set, returns the way index; otherwise `None`.
    ///
    /// Uses trailing_zeros iteration for sparse bitmasks, avoiding unnecessary
    /// iterations when few tags match.
    #[inline]
    fn search(&self, set: Set<TagT, C::Value, WAYS>, key: C::Key) -> Option<u16> {
        // SAFETY: `set.tags` was derived from a valid in-bounds pointer in `associate`.
        let tags = unsafe { &*set.tags };
        let mut ways_mask = Self::search_tags(tags, set.tag);
        if ways_mask == 0 {
            return None;
        }

        // Iterate only over set bits using trailing_zeros.
        // This is more efficient for sparse masks (typical case: 1-2 matches).
        while ways_mask != 0 {
            let way = ways_mask.trailing_zeros() as usize;
            ways_mask &= ways_mask - 1; // Clear lowest set bit (Kernighan's trick)

            if self.counts_get(set.offset + way as u64) > 0 {
                // SAFETY: `set.values` points to a valid in-bounds array; `way` < WAYS and count > 0 confirms initialization.
                let v = unsafe { &(*set.values)[way] };
                if C::key_from_value(v) == key {
                    return Some(way as u16);
                }
            }
        }
        None
    }

    /// Bitmask of ways whose tag matches `tag` (bit i corresponds to way i).
    /// Under Miri, we always use the scalar fallback since SIMD intrinsics
    /// are not supported by the Miri interpreter.
    #[cfg(miri)]
    #[inline]
    fn search_tags(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        let mut bits = 0u16;
        for (i, &t) in tags.iter().enumerate() {
            if t == tag {
                bits |= 1u16 << i;
            }
        }
        bits
    }

    /// Bitmask of ways whose tag matches `tag` (bit i corresponds to way i).
    #[cfg(all(not(miri), target_arch = "aarch64"))]
    #[inline]
    fn search_tags(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        // SAFETY: NEON intrinsics are available on all aarch64 targets.
        unsafe { Self::search_tags_neon(tags, tag) }
    }

    /// Bitmask of ways whose tag matches `tag` (bit i corresponds to way i).
    #[cfg(all(not(miri), target_arch = "x86_64"))]
    #[inline]
    fn search_tags(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: guarded by runtime feature detection.
            return unsafe { Self::search_tags_avx2(tags, tag) };
        }
        // SAFETY: SSE2 is baseline on x86_64.
        unsafe { Self::search_tags_sse2(tags, tag) }
    }

    /// Bitmask of ways whose tag matches `tag` (bit i corresponds to way i).
    #[cfg(all(not(miri), target_arch = "x86"))]
    #[inline]
    fn search_tags(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        if std::is_x86_feature_detected!("sse2") {
            // SAFETY: guarded by runtime feature detection.
            return unsafe { Self::search_tags_sse2(tags, tag) };
        }

        let mut bits = 0u16;
        for (i, &t) in tags.iter().enumerate() {
            if t == tag {
                bits |= 1u16 << i;
            }
        }
        bits
    }

    /// Bitmask of ways whose tag matches `tag` (bit i corresponds to way i).
    #[cfg(not(any(
        miri,
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "x86"
    )))]
    #[inline]
    fn search_tags(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        let mut bits = 0u16;
        for (i, &t) in tags.iter().enumerate() {
            if t == tag {
                bits |= 1u16 << i;
            }
        }
        bits
    }

    /// Compresses a byte-wise movemask into one bit per u16 lane (128-bit / 8 lanes).
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[inline(always)]
    fn compress_u16_mask(mask: u16) -> u16 {
        // Keep even bits (lane LSBs), then pack them into the low 8 bits.
        let mut m = mask & 0x5555;
        m = (m | (m >> 1)) & 0x3333;
        m = (m | (m >> 2)) & 0x0F0F;
        m = (m | (m >> 4)) & 0x00FF;
        m
    }

    /// Compresses a byte-wise movemask from a 256-bit u16 compare into one bit per lane.
    ///
    /// `_mm256_movemask_epi8` on a `_mm256_cmpeq_epi16` result yields 32 bits where
    /// each matching u16 lane sets two consecutive bits. This extracts the low bit of
    /// each pair and packs them into the low 16 bits.
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn compress_u16_mask_avx2(mask: u32) -> u16 {
        let mut m = mask & 0x5555_5555;
        m = (m | (m >> 1)) & 0x3333_3333;
        m = (m | (m >> 2)) & 0x0F0F_0F0F;
        m = (m | (m >> 4)) & 0x00FF_00FF;
        m = (m | (m >> 8)) & 0x0000_FFFF;
        m as u16
    }

    /// Bitmask of ways whose tag matches `tag` (bit i corresponds to way i).
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn search_tags_neon(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        if TagT::BITS == 8 {
            let tag_u8: u8 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u8;
            // SAFETY: Caller guaranteed NEON is available; tags_ptr is valid for WAYS elements.
            unsafe { Self::search_tags_u8_neon::<WAYS>(tags_ptr, tag_u8) }
        } else {
            let tag_u16: u16 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u16;
            // SAFETY: Caller guaranteed NEON is available; tags_ptr is valid for WAYS elements.
            unsafe { Self::search_tags_u16_neon::<WAYS>(tags_ptr, tag_u16) }
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn search_tags_u8_neon<const N: usize>(tags: *const u8, tag: u8) -> u16 {
        use core::arch::aarch64::*;

        if N == 16 {
            let vec = vld1q_u8(tags);
            let needle = vdupq_n_u8(tag);
            let eq = vceqq_u8(vec, needle);
            let mut lanes = [0u8; 16];
            vst1q_u8(lanes.as_mut_ptr(), eq);
            let mut bits = 0u16;
            for (i, lane) in lanes.iter().enumerate() {
                if *lane != 0 {
                    bits |= 1u16 << i;
                }
            }
            return bits;
        }

        let filler = tag.wrapping_add(1);
        let mut tmp = [filler; 8];
        for (i, slot) in tmp.iter_mut().enumerate().take(N) {
            *slot = *tags.add(i);
        }
        let vec = vld1_u8(tmp.as_ptr());
        let needle = vdup_n_u8(tag);
        let eq = vceq_u8(vec, needle);
        let mut lanes = [0u8; 8];
        vst1_u8(lanes.as_mut_ptr(), eq);
        let mut bits = 0u16;
        for (i, lane) in lanes.iter().enumerate().take(N) {
            if *lane != 0 {
                bits |= 1u16 << i;
            }
        }
        bits
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn search_tags_u16_neon<const N: usize>(tags: *const u16, tag: u16) -> u16 {
        use core::arch::aarch64::*;

        if N == 16 {
            let vec0 = vld1q_u16(tags);
            let vec1 = vld1q_u16(tags.add(8));
            let needle = vdupq_n_u16(tag);
            let eq0 = vceqq_u16(vec0, needle);
            let eq1 = vceqq_u16(vec1, needle);
            let mut lanes0 = [0u16; 8];
            let mut lanes1 = [0u16; 8];
            vst1q_u16(lanes0.as_mut_ptr(), eq0);
            vst1q_u16(lanes1.as_mut_ptr(), eq1);
            let mut bits = 0u16;
            for (i, lane) in lanes0.iter().enumerate() {
                if *lane != 0 {
                    bits |= 1u16 << i;
                }
            }
            for (i, lane) in lanes1.iter().enumerate() {
                if *lane != 0 {
                    bits |= 1u16 << (i + 8);
                }
            }
            return bits;
        }

        let filler = tag.wrapping_add(1);
        let mut tmp = [filler; 8];
        for (i, slot) in tmp.iter_mut().enumerate().take(N) {
            *slot = *tags.add(i);
        }
        let vec = vld1q_u16(tmp.as_ptr());
        let needle = vdupq_n_u16(tag);
        let eq = vceqq_u16(vec, needle);
        let mut lanes = [0u16; 8];
        vst1q_u16(lanes.as_mut_ptr(), eq);
        let mut bits = 0u16;
        for (i, lane) in lanes.iter().enumerate().take(N) {
            if *lane != 0 {
                bits |= 1u16 << i;
            }
        }
        bits
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn search_tags_sse2(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        if TagT::BITS == 8 {
            let tag_u8: u8 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u8;
            // SAFETY: Caller guaranteed SSE2 is available; tags_ptr is valid for WAYS elements.
            unsafe { Self::search_tags_u8_sse2::<WAYS>(tags_ptr, tag_u8) }
        } else {
            let tag_u16: u16 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u16;
            // SAFETY: Caller guaranteed SSE2 is available; tags_ptr is valid for WAYS elements.
            unsafe { Self::search_tags_u16_sse2::<WAYS>(tags_ptr, tag_u16) }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn search_tags_u8_sse2<const N: usize>(tags: *const u8, tag: u8) -> u16 {
        use core::arch::x86_64::*;

        if N == 16 {
            let vec = _mm_loadu_si128(tags as *const __m128i);
            let needle = _mm_set1_epi8(tag as i8);
            let eq = _mm_cmpeq_epi8(vec, needle);
            return _mm_movemask_epi8(eq) as u16;
        }

        let filler = tag.wrapping_add(1);
        let mut tmp = [filler; 16];
        for (i, slot) in tmp.iter_mut().enumerate().take(N) {
            *slot = *tags.add(i);
        }
        let vec = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
        let needle = _mm_set1_epi8(tag as i8);
        let eq = _mm_cmpeq_epi8(vec, needle);
        let mask = _mm_movemask_epi8(eq) as u16;
        if N < 16 {
            mask & ((1u16 << N) - 1)
        } else {
            mask
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn search_tags_u16_sse2<const N: usize>(tags: *const u16, tag: u16) -> u16 {
        use core::arch::x86_64::*;

        if N == 16 {
            let vec0 = _mm_loadu_si128(tags as *const __m128i);
            let vec1 = _mm_loadu_si128(tags.add(8) as *const __m128i);
            let needle = _mm_set1_epi16(tag as i16);
            let eq0 = _mm_cmpeq_epi16(vec0, needle);
            let eq1 = _mm_cmpeq_epi16(vec1, needle);
            let mask0 = _mm_movemask_epi8(eq0) as u16;
            let mask1 = _mm_movemask_epi8(eq1) as u16;
            let lanes0 = Self::compress_u16_mask(mask0);
            let lanes1 = Self::compress_u16_mask(mask1);
            return lanes0 | (lanes1 << 8);
        }

        let filler = tag.wrapping_add(1);
        let mut tmp = [filler; 8];
        for (i, slot) in tmp.iter_mut().enumerate().take(N) {
            *slot = *tags.add(i);
        }
        let vec = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
        let needle = _mm_set1_epi16(tag as i16);
        let eq = _mm_cmpeq_epi16(vec, needle);
        let mask = _mm_movemask_epi8(eq) as u16;
        let lanes = Self::compress_u16_mask(mask);
        if N < 8 {
            lanes & ((1u16 << N) - 1)
        } else {
            lanes
        }
    }

    /// AVX2 entry point: dispatches to u8 (SSE2, already optimal) or u16 (AVX2).
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn search_tags_avx2(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        if TagT::BITS == 8 {
            // u8 tags fit in a single 128-bit register for WAYS ≤ 16; SSE2 is optimal.
            let tag_u8: u8 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u8;
            // SAFETY: tags_ptr is derived from a valid &[TagT; WAYS] and tag_u8 is
            // transmute_copy'd from a TagT whose BITS == 8. The caller has verified
            // that the avx2 target feature is available.
            unsafe { Self::search_tags_u8_sse2::<WAYS>(tags_ptr, tag_u8) }
        } else {
            let tag_u16: u16 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u16;
            // SAFETY: tags_ptr is derived from a valid &[TagT; WAYS] and tag_u16 is
            // transmute_copy'd from a TagT whose BITS == 16. The avx2 target feature
            // is enabled on this function.
            unsafe { Self::search_tags_u16_avx2::<WAYS>(tags_ptr, tag_u16) }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn search_tags_u16_avx2<const N: usize>(tags: *const u16, tag: u16) -> u16 {
        use core::arch::x86_64::*;

        if N == 16 {
            // SAFETY: N == 16 guarantees 32 bytes (16 × u16) are readable from `tags`.
            // `_mm256_loadu_si256` handles unaligned pointers.
            let vec = _mm256_loadu_si256(tags as *const __m256i);
            let needle = _mm256_set1_epi16(tag as i16);
            let eq = _mm256_cmpeq_epi16(vec, needle);
            let mask = _mm256_movemask_epi8(eq) as u32;
            return Self::compress_u16_mask_avx2(mask);
        }

        // For WAYS < 16, tags fit in one 128-bit register; delegate to SSE2.
        Self::search_tags_u16_sse2::<N>(tags, tag)
    }

    #[cfg(target_arch = "x86")]
    #[target_feature(enable = "sse2")]
    unsafe fn search_tags_sse2(tags: &[TagT; WAYS], tag: TagT) -> u16 {
        if TagT::BITS == 8 {
            let tag_u8: u8 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u8;
            // SAFETY: Caller guaranteed SSE2 is available; tags_ptr is valid for WAYS elements.
            unsafe { Self::search_tags_u8_sse2::<WAYS>(tags_ptr, tag_u8) }
        } else {
            let tag_u16: u16 = core::mem::transmute_copy(&tag);
            let tags_ptr = tags.as_ptr() as *const u16;
            // SAFETY: Caller guaranteed SSE2 is available; tags_ptr is valid for WAYS elements.
            unsafe { Self::search_tags_u16_sse2::<WAYS>(tags_ptr, tag_u16) }
        }
    }

    #[cfg(target_arch = "x86")]
    #[target_feature(enable = "sse2")]
    unsafe fn search_tags_u8_sse2<const N: usize>(tags: *const u8, tag: u8) -> u16 {
        use core::arch::x86::*;

        if N == 16 {
            let vec = _mm_loadu_si128(tags as *const __m128i);
            let needle = _mm_set1_epi8(tag as i8);
            let eq = _mm_cmpeq_epi8(vec, needle);
            return _mm_movemask_epi8(eq) as u16;
        }

        let filler = tag.wrapping_add(1);
        let mut tmp = [filler; 16];
        for (i, slot) in tmp.iter_mut().enumerate().take(N) {
            *slot = *tags.add(i);
        }
        let vec = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
        let needle = _mm_set1_epi8(tag as i8);
        let eq = _mm_cmpeq_epi8(vec, needle);
        let mask = _mm_movemask_epi8(eq) as u16;
        if N < 16 {
            mask & ((1u16 << N) - 1)
        } else {
            mask
        }
    }

    #[cfg(target_arch = "x86")]
    #[target_feature(enable = "sse2")]
    unsafe fn search_tags_u16_sse2<const N: usize>(tags: *const u16, tag: u16) -> u16 {
        use core::arch::x86::*;

        if N == 16 {
            let vec0 = _mm_loadu_si128(tags as *const __m128i);
            let vec1 = _mm_loadu_si128(tags.add(8) as *const __m128i);
            let needle = _mm_set1_epi16(tag as i16);
            let eq0 = _mm_cmpeq_epi16(vec0, needle);
            let eq1 = _mm_cmpeq_epi16(vec1, needle);
            let mask0 = _mm_movemask_epi8(eq0) as u16;
            let mask1 = _mm_movemask_epi8(eq1) as u16;
            let lanes0 = Self::compress_u16_mask(mask0);
            let lanes1 = Self::compress_u16_mask(mask1);
            return lanes0 | (lanes1 << 8);
        }

        let filler = tag.wrapping_add(1);
        let mut tmp = [filler; 8];
        for (i, slot) in tmp.iter_mut().enumerate().take(N) {
            *slot = *tags.add(i);
        }
        let vec = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
        let needle = _mm_set1_epi16(tag as i16);
        let eq = _mm_cmpeq_epi16(vec, needle);
        let mask = _mm_movemask_epi8(eq) as u16;
        let lanes = Self::compress_u16_mask(mask);
        if N < 8 {
            lanes & ((1u16 << N) - 1)
        } else {
            lanes
        }
    }

    /// Reads the CLOCK count for a slot at `index`.
    #[inline]
    fn counts_get(&self, index: u64) -> u8 {
        // SAFETY: Single-threaded access; no mutable aliases to `counts` exist.
        unsafe { (*self.counts.get()).get(index) }
    }

    /// Writes the CLOCK count for a slot at `index`.
    #[inline]
    fn counts_set(&self, index: u64, value: u8) {
        // SAFETY: Single-threaded access; no other references to `counts` exist.
        unsafe {
            (*self.counts.get()).set(index, value);
        }
    }

    /// Reads the clock hand value for the set at `index`.
    #[inline]
    fn clocks_get(&self, index: u64) -> u8 {
        // SAFETY: Single-threaded access; no mutable aliases to `clocks` exist.
        unsafe { (*self.clocks.get()).get(index) }
    }

    /// Writes the clock hand value for the set at `index`.
    #[inline]
    fn clocks_set(&self, index: u64, value: u8) {
        // SAFETY: Single-threaded access; no other references to `clocks` exist.
        unsafe {
            (*self.clocks.get()).set(index, value);
        }
    }
}

#[cfg(test)]
#[path = "set_associative_cache_tests.rs"]
mod tests;
