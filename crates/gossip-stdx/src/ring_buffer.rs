//! Fixed-capacity ring buffer with stack-allocated storage and `MaybeUninit<T>`.
//!
//! # Invariants
//! - `N <= u32::MAX / 2` (validated at compile time). The half-u32 limit
//!   ensures `head + len` never overflows.
//! - `head < capacity` and `len <= capacity`.
//! - Slots in the logical range `[head, head + len)` (wrapping by mask) are
//!   initialized; all other slots are uninitialized.
//!
//! # Threading
//! This type is not synchronized; it assumes single-threaded usage.

use std::mem::MaybeUninit;

// Compile-time proof that u32 -> usize is safe on this platform.
// This fails to compile on 16-bit platforms.
const _: () = assert!(
    std::mem::size_of::<usize>() >= std::mem::size_of::<u32>(),
    "Platform must have at least 32-bit addressing"
);

/// Converts a `u32` slot index to `usize` for array indexing.
///
/// This is always lossless because the compile-time assertion above guarantees
/// `usize >= u32`. Exists as a named function to document the truncation-free
/// cast at each call site.
#[inline(always)]
fn index(i: u32) -> usize {
    i as usize
}

/// Fixed-capacity ring buffer backed by stack-allocated storage.
///
/// Design intent:
/// - Explicit, compile-time capacity so backpressure is deterministic.
/// - Zero heap allocations in the hot path (storage is `[MaybeUninit<T>; N]`).
/// - Simple head/len bookkeeping so operations are branch-light and predictable.
///
/// **Performance note**: Capacity `N` must be a power of 2. This enables
/// single-cycle bitwise AND for index calculation instead of expensive
/// division/modulo operations.
///
/// This is a single-producer/single-consumer style queue in the pipeline, but
/// the implementation itself is not synchronized; it relies on single-threaded
/// usage. `push_back` returns `Err(value)` on overflow; `push_back_overwrite`
/// evicts the oldest element; `push_back_assume_capacity` is `pub(crate)` and
/// assumes the caller has checked capacity.
///
/// # Invariants
/// - `head` always indexes the logical front.
/// - `len` tracks the number of initialized elements.
/// - The element at logical index `i` lives at `(head + i) & MASK`.
pub struct RingBuffer<T, const N: usize> {
    buf: [MaybeUninit<T>; N],
    head: u32,
    len: u32,
}

/// Creates an uninitialized `[MaybeUninit<T>; N]` without running any constructors.
///
/// Sound because `MaybeUninit<T>` is explicitly designed to hold uninitialized
/// data. An array of `MaybeUninit<T>` requires no initialization for validity.
fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized MaybeUninit<T> is valid.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

impl<T, const N: usize> RingBuffer<T, N> {
    /// Compile-time validated capacity as `u32`.
    ///
    /// Asserts three properties:
    /// - `N > 0` (an empty ring buffer is nonsensical).
    /// - `N` is a power of 2 (enables bitwise AND for wrapping instead of modulo).
    /// - `N <= u32::MAX / 2` (prevents `head + len` from overflowing `u32`).
    const CAPACITY: u32 = {
        assert!(N > 0, "RingBuffer capacity must be > 0");
        assert!(N & (N - 1) == 0, "RingBuffer capacity must be power of 2");
        assert!(
            N <= u32::MAX as usize / 2,
            "N must fit in u32 and not risk overflow"
        );
        N as u32
    };

    /// Bitmask for power-of-2 wrapping: `(head + offset) & MASK` is equivalent
    /// to `(head + offset) % CAPACITY` but compiles to a single AND instruction.
    const MASK: u32 = Self::CAPACITY - 1;

    /// Constructs an empty ring buffer with capacity `N` without heap allocation.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_stdx::RingBuffer;
    ///
    /// let ring = RingBuffer::<u32, 4>::new();
    /// assert!(ring.is_empty());
    /// assert_eq!(ring.capacity(), 4);
    /// ```
    pub fn new() -> Self {
        let _ = Self::CAPACITY;

        let ring = Self {
            buf: uninit_array(),
            head: 0,
            len: 0,
        };

        debug_assert!(ring.len == 0);
        debug_assert!(ring.head == 0);

        ring
    }

    /// Returns the number of elements currently stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns the compile-time capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    /// Returns true when no elements are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true when `len == capacity`.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == Self::CAPACITY
    }

    /// Returns a reference to the element at logical index `index`, or `None`
    /// if the index is out of bounds.
    ///
    /// Logical index 0 is the oldest (front) element.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_stdx::RingBuffer;
    ///
    /// let mut ring = RingBuffer::<u32, 4>::new();
    /// ring.push_back(10).unwrap();
    /// ring.push_back(20).unwrap();
    /// ring.push_back(30).unwrap();
    ///
    /// assert_eq!(ring.get(0), Some(&10)); // oldest element
    /// assert_eq!(ring.get(2), Some(&30)); // newest element
    /// assert_eq!(ring.get(3), None);      // out of bounds
    /// ```
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len as usize {
            return None;
        }
        // `index as u32` cannot truncate: index < len <= CAPACITY <= u32::MAX/2.
        let physical = (self.head + index as u32) & Self::MASK;
        // SAFETY: physical < CAPACITY by mask. The element is initialized
        // because index < len and slots [head, head+len) are initialized.
        Some(unsafe { self.buf.get_unchecked(physical as usize).assume_init_ref() })
    }

    /// Attempts to append `value`, returning `Err(value)` if the buffer is
    /// already full.
    ///
    /// This keeps ownership with the caller on overflow instead of dropping
    /// silently.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_stdx::RingBuffer;
    ///
    /// let mut ring = RingBuffer::<u32, 2>::new();
    /// assert!(ring.push_back(10).is_ok());
    /// assert!(ring.push_back(20).is_ok());
    /// assert_eq!(ring.push_back(30), Err(30)); // full
    /// ```
    #[inline]
    pub fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.is_full() {
            return Err(value);
        }
        self.push_back_assume_capacity(value);
        Ok(())
    }

    /// Appends `value` assuming spare capacity exists.
    ///
    /// # Panics
    ///
    /// Panics if `self.is_full()`. The assertion is unconditional (not
    /// debug-only) so that callers cannot silently corrupt the buffer.
    #[inline]
    pub(crate) fn push_back_assume_capacity(&mut self, value: T) {
        assert!(
            self.len < Self::CAPACITY,
            "push_back_assume_capacity called on full buffer"
        );
        debug_assert!(self.head < Self::CAPACITY, "head out of bounds");

        // PERF: Uses bitwise AND instead of modulo for power-of-2 capacity.
        // This compiles to a single AND instruction vs expensive div/mul sequence.
        let tail = (self.head + self.len) & Self::MASK;

        debug_assert!(tail < Self::CAPACITY, "tail out of bounds");

        // SAFETY: tail < CAPACITY by mask. The slot at `tail` is uninitialized
        // because len < CAPACITY ensures tail falls outside [head, head+len).
        unsafe { self.buf.get_unchecked_mut(index(tail)).write(value) };
        self.len += 1;

        debug_assert!(self.len <= Self::CAPACITY);
    }

    /// Appends `value`, evicting and returning the oldest element if at capacity.
    ///
    /// Returns `Some(evicted)` if an element was evicted, `None` if there was
    /// spare capacity. This is the O(1) replacement for the
    /// `if full { remove(0) } push()` pattern.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_stdx::RingBuffer;
    ///
    /// let mut ring = RingBuffer::<u32, 2>::new();
    /// assert_eq!(ring.push_back_overwrite(10), None);
    /// assert_eq!(ring.push_back_overwrite(20), None);
    /// assert_eq!(ring.push_back_overwrite(30), Some(10)); // 10 evicted
    /// assert_eq!(ring.pop_front(), Some(20));
    /// ```
    #[inline]
    pub fn push_back_overwrite(&mut self, value: T) -> Option<T> {
        let evicted = if self.is_full() {
            self.pop_front()
        } else {
            None
        };
        self.push_back_assume_capacity(value);
        evicted
    }

    /// Removes and returns the oldest element, or `None` when empty.
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        debug_assert!(self.len > 0);
        debug_assert!(self.head < Self::CAPACITY, "head out of bounds");

        let idx = self.head;

        // SAFETY: idx < CAPACITY proven by invariant, element initialized because len > 0
        let value = unsafe { self.buf.get_unchecked(index(idx)).as_ptr().read() };

        // PERF: Uses bitwise AND instead of modulo.
        self.head = (self.head + 1) & Self::MASK;
        self.len -= 1;

        debug_assert!(self.head < Self::CAPACITY);

        Some(value)
    }

    /// Removes all elements, dropping them in FIFO order.
    ///
    /// Buffer remains usable afterwards without reallocating. Delegates to
    /// `pop_front()` so that `head` and `len` are updated *before* each
    /// element is dropped. This guarantees that if `T::drop()` panics, the
    /// `Drop` impl during unwinding sees correct bookkeeping and will not
    /// double-drop already-freed elements.
    pub fn clear(&mut self) {
        while self.pop_front().is_some() {}
    }

    /// Returns an iterator over references to the elements in FIFO order.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_stdx::RingBuffer;
    ///
    /// let mut ring = RingBuffer::<u32, 4>::new();
    /// ring.push_back(10).unwrap();
    /// ring.push_back(20).unwrap();
    /// ring.push_back(30).unwrap();
    ///
    /// let vals: Vec<_> = ring.iter().copied().collect();
    /// assert_eq!(vals, [10, 20, 30]);
    ///
    /// // Reverse iteration to find the last element divisible by 10:
    /// let last_div10 = ring.iter().rev().find(|&&x| x % 10 == 0);
    /// assert_eq!(last_div10, Some(&30));
    /// ```
    pub fn iter(&self) -> Iter<'_, T, N> {
        Iter {
            ring: self,
            front: 0,
            back: self.len as usize,
        }
    }
}

impl<T, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for RingBuffer<T, N> {
    /// Drops all remaining elements via [`clear`](RingBuffer::clear).
    ///
    /// Delegates to `clear()` rather than a separate loop so that panic-safety
    /// is handled in one place: `clear` pops elements one at a time, keeping
    /// `head` and `len` consistent even if `T::drop()` panics.
    fn drop(&mut self) {
        self.clear();
        debug_assert!(self.len == 0);
    }
}

impl<T: Clone, const N: usize> Clone for RingBuffer<T, N> {
    /// Clones all elements into a fresh ring buffer.
    ///
    /// The clone always starts with `head = 0`, so physical layout may differ
    /// from the source even though logical element order is preserved. This is
    /// semantically correct because `PartialEq` compares by logical order, not
    /// physical slot positions.
    ///
    /// # Panic safety
    ///
    /// Uses `push_back_assume_capacity` which updates `len` after each write.
    /// If `T::clone()` panics mid-iteration, `RingBuffer::drop` on the
    /// partially-built clone drops only the already-written elements.
    fn clone(&self) -> Self {
        let mut new = Self::new();
        for i in 0..self.len as usize {
            let physical = (self.head + i as u32) & Self::MASK;
            // SAFETY: physical < CAPACITY by mask. Element is initialized
            // because i < len.
            let val = unsafe { self.buf.get_unchecked(index(physical)).assume_init_ref() };
            // Loop invariant: new.len() == i < self.len <= CAPACITY.
            new.push_back_assume_capacity(val.clone());
        }
        new
    }
}

impl<T: std::fmt::Debug, const N: usize> std::fmt::Debug for RingBuffer<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: PartialEq, const N: usize> PartialEq for RingBuffer<T, N> {
    /// Compares by logical element order, not physical slot positions.
    ///
    /// Two ring buffers are equal iff they contain the same elements in the
    /// same FIFO order, regardless of where `head` happens to point in each.
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl<T: Eq, const N: usize> Eq for RingBuffer<T, N> {}

// Compile-time proof that RingBuffer is Send+Sync when T is.
// Closure-in-const pattern (from static_assertions) avoids dead_code warnings.
const _: fn() = || {
    fn assert_impl<T: Send + Sync>() {}
    assert_impl::<RingBuffer<u8, 1>>();
};

impl<T, const N: usize> FromIterator<T> for RingBuffer<T, N> {
    /// Collects items into a `RingBuffer`.
    ///
    /// # Panics
    ///
    /// Panics if the iterator yields more than `N` items.
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut ring = Self::new();
        for item in iter {
            ring.push_back(item)
                .unwrap_or_else(|_| panic!("FromIterator: too many items for RingBuffer<_, {N}>"));
        }
        ring
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a RingBuffer<T, N> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// ============================================================================
// Iter
// ============================================================================

/// Iterator over references to elements in a [`RingBuffer`], in FIFO order.
///
/// Supports both forward and reverse traversal via [`DoubleEndedIterator`].
/// `front` and `back` are logical offsets into the ring's initialized range,
/// not physical buffer indices. The physical index is computed on each access
/// via `(head + logical) & MASK`.
pub struct Iter<'a, T, const N: usize> {
    ring: &'a RingBuffer<T, N>,
    /// Logical offset from the front (0 = oldest element).
    front: usize,
    /// Logical offset from the front marking the exclusive back boundary.
    back: usize,
}

impl<'a, T, const N: usize> Iter<'a, T, N> {
    /// Returns a reference to the element at logical offset `logical`.
    ///
    /// # Safety
    ///
    /// `logical` must be less than `self.ring.len`, ensuring the slot is initialized.
    #[inline]
    unsafe fn get_unchecked(&self, logical: usize) -> &'a T {
        // Truncation safe: logical < len <= CAPACITY <= u32::MAX/2.
        let physical = (self.ring.head + logical as u32) & RingBuffer::<T, N>::MASK;
        // SAFETY: physical < CAPACITY by mask. Element is initialized per caller contract.
        unsafe {
            self.ring
                .buf
                .get_unchecked(index(physical))
                .assume_init_ref()
        }
    }
}

impl<'a, T, const N: usize> Iterator for Iter<'a, T, N> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        // SAFETY: front < back <= len, so the slot is initialized.
        let val = unsafe { self.get_unchecked(self.front) };
        self.front += 1;
        Some(val)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.back - self.front;
        (remaining, Some(remaining))
    }
}

impl<'a, T, const N: usize> DoubleEndedIterator for Iter<'a, T, N> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        self.back -= 1;
        // SAFETY: back was > front and back <= len, so the slot is initialized.
        Some(unsafe { self.get_unchecked(self.back) })
    }
}

impl<T, const N: usize> ExactSizeIterator for Iter<'_, T, N> {}

impl<T, const N: usize> std::iter::FusedIterator for Iter<'_, T, N> {}

// ============================================================================
// IntoIter (consuming)
// ============================================================================

/// Consuming iterator over a [`RingBuffer`], yielding owned elements in FIFO order.
///
/// Created by [`RingBuffer::into_iter`]. When dropped before exhaustion,
/// any remaining elements are dropped via `RingBuffer::drop` (which calls
/// `clear`), so no elements are leaked.
pub struct IntoIter<T, const N: usize> {
    ring: RingBuffer<T, N>,
}

impl<T, const N: usize> Iterator for IntoIter<T, N> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.ring.pop_front()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.ring.len();
        (len, Some(len))
    }
}

impl<T, const N: usize> ExactSizeIterator for IntoIter<T, N> {}

impl<T, const N: usize> std::iter::FusedIterator for IntoIter<T, N> {}

impl<T, const N: usize> IntoIterator for RingBuffer<T, N> {
    type Item = T;
    type IntoIter = IntoIter<T, N>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter { ring: self }
    }
}

#[cfg(test)]
#[path = "ring_buffer_tests.rs"]
mod tests;

// ============================================================================
// Kani formal verification proofs
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    //! Kani formal verification proofs for `RingBuffer`.
    //!
    //! Each proof targets one or more `unsafe` operations, verifying that
    //! wrapping index arithmetic and `MaybeUninit` access are sound for all
    //! valid inputs (symbolic, not sampled). Together the 10 proofs cover
    //! all 8 `unsafe {}` blocks and the one `unsafe fn` declaration in
    //! `RingBuffer`.
    //!
    //! Key difference from `InlineVec` proofs: RingBuffer uses wrapping
    //! index arithmetic `(head + offset) & MASK`. Most proofs construct
    //! non-zero `head` positions via push/pop warmup so that elements span
    //! the wrap boundary, exercising the `& MASK` logic that a `head = 0`
    //! test would miss.
    //!
    //! Proofs use `CAP = 4` and `u32` elements for tractable SAT solving.
    //!
    //! Coverage by unsafe operation:
    //! - `uninit_array`: MaybeUninit array construction is trivially sound
    //! - `push_back_assume_capacity`: write lands at correct wrapped tail index
    //! - `get`: read at wrapped physical index returns initialized data only
    //! - `pop_front`: read at wrapped head returns initialized data, FIFO order
    //! - `clone`: read across wrap boundary produces element-wise equal ring
    //! - `clear`/`drop`: memory-safe traversal of all initialized slots
    //! - `Iter::next`: forward traversal across wrap boundary in FIFO order
    //! - `DoubleEndedIterator::next_back`: reverse traversal across wrap boundary
    //! - push/pop rotation: interleaved operations preserve element values
    //! - `push_back_overwrite`: evict-then-write sequence is sound at all head positions

    use super::*;

    const CAP: usize = 4;

    /// Rotates `head` to position `offset` by pushing then popping.
    ///
    /// After this call the ring is empty with `head == offset`.
    /// Callers use a symbolic `offset` with `kani::assume(offset < CAP)`
    /// so Kani explores all head positions.
    fn rotate_head(ring: &mut RingBuffer<u32, CAP>, offset: u32) {
        for _ in 0..offset {
            ring.push_back(0).unwrap();
        }
        for _ in 0..offset {
            assert_eq!(ring.pop_front(), Some(0));
        }
        // Postcondition: ring is empty with head advanced to `offset`.
        // Guards against future changes that might normalize head to 0
        // on empty, which would silently defeat wrap-boundary coverage.
        assert!(ring.is_empty());
        assert_eq!(ring.head, offset);
    }

    // `uninit_array` produces a valid `[MaybeUninit<T>; N]` for both sized
    // types and ZSTs.
    #[kani::proof]
    fn uninit_array_is_valid() {
        let _arr = uninit_array::<u32, CAP>();
        let _arr_zst = uninit_array::<(), CAP>();
    }

    // `push_back_assume_capacity` writes within bounds for all head
    // positions and fill levels.
    // Covers the `get_unchecked_mut(tail).write(value)` unsafe in
    // `push_back_assume_capacity`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn push_back_within_capacity_is_safe() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for _ in 0..n {
            ring.push_back(kani::any()).unwrap();
        }
        assert_eq!(ring.len(), n);
    }

    // `get` returns initialized references only, for all head positions
    // and logical indices. Out-of-bounds returns None.
    // Covers the `get_unchecked(physical).assume_init_ref()` unsafe in `get`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn get_returns_initialized_only() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for i in 0..n {
            ring.push_back(i as u32).unwrap();
        }

        // Valid index: dereference must succeed and return the correct value.
        if n > 0 {
            let idx: usize = kani::any();
            kani::assume(idx < n);
            let val = ring.get(idx);
            assert!(val.is_some());
            assert_eq!(*val.unwrap(), idx as u32);
        }

        // Out-of-bounds index: must return None.
        assert!(ring.get(n).is_none());
    }

    // `pop_front` reads only initialized memory, for all head positions.
    // After popping all elements, the ring is empty.
    // Covers the `get_unchecked(idx).as_ptr().read()` unsafe in `pop_front`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn pop_front_reads_initialized() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for i in 0..n {
            ring.push_back(i as u32).unwrap();
        }

        // Pop all elements and verify FIFO order.
        for i in 0..n {
            let val = ring.pop_front();
            assert_eq!(val, Some(i as u32));
        }
        assert!(ring.is_empty());
        assert!(ring.pop_front().is_none());
    }

    // `clone` reads only initialized slots across the wrap boundary and
    // produces an equal ring buffer.
    // Covers the `get_unchecked(physical).assume_init_ref()` unsafe in `clone`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn clone_is_sound() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for i in 0..n {
            ring.push_back(i as u32).unwrap();
        }

        let cloned = ring.clone();
        assert_eq!(cloned.len(), ring.len());

        // Verify element-by-element equality across the wrap boundary.
        for i in 0..n {
            assert_eq!(cloned.get(i), ring.get(i));
        }
    }

    // `Drop` (via `clear` -> `pop_front`) accesses only initialized memory
    // for all head positions, including wrapped layouts. Uses `u32` elements
    // (trivial Drop), so this verifies memory safety of the traversal, not
    // that exactly `n` destructors ran.
    // Covers `pop_front` unsafe transitively through `clear`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn drop_clear_is_memory_safe() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for _ in 0..n {
            ring.push_back(kani::any()).unwrap();
        }
        assert_eq!(ring.len(), n);
        drop(ring); // Kani verifies all pop_front reads are in-bounds.
    }

    // Forward iteration via `Iter::next` traverses exactly the initialized
    // elements across the wrap boundary in FIFO order.
    // Covers the `get_unchecked` -> `assume_init_ref` unsafe in
    // `Iter::get_unchecked` and `Iter::next`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn iter_forward_is_sound() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for i in 0..n {
            ring.push_back(i as u32).unwrap();
        }

        let mut count = 0usize;
        let mut expected = 0u32;
        for val in ring.iter() {
            assert_eq!(*val, expected);
            expected += 1;
            count += 1;
        }
        assert_eq!(count, n);
    }

    // Reverse iteration via `DoubleEndedIterator::next_back` traverses
    // elements in reverse FIFO order across the wrap boundary.
    // Covers the `get_unchecked` -> `assume_init_ref` unsafe in
    // `Iter::get_unchecked` and `Iter::next_back`.
    #[kani::proof]
    #[kani::unwind(7)]
    fn iter_reverse_is_sound() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for i in 0..n {
            ring.push_back(i as u32).unwrap();
        }

        let mut count = 0usize;
        let mut expected = if n > 0 { n as u32 - 1 } else { 0 };
        for val in ring.iter().rev() {
            assert_eq!(*val, expected);
            expected = expected.wrapping_sub(1);
            count += 1;
        }
        assert_eq!(count, n);
    }

    // Interleaved push/pop rotation preserves element values. Exercises
    // both the write unsafe in `push_back_assume_capacity` and the read
    // unsafe in `pop_front` with head advancing through all positions
    // modulo CAPACITY.
    #[kani::proof]
    #[kani::unwind(7)]
    fn push_pop_rotate_preserves_elements() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        // Fill the ring.
        let n: usize = kani::any();
        kani::assume(n > 0 && n <= CAP);
        for i in 0..n {
            ring.push_back(i as u32).unwrap();
        }

        // Pop one element and push a new one, rotating head.
        let front = ring.pop_front();
        assert_eq!(front, Some(0));
        ring.push_back(n as u32).unwrap();
        assert_eq!(ring.len(), n);

        // Verify all remaining elements are correct.
        for i in 0..n {
            assert_eq!(ring.get(i), Some(&((i + 1) as u32)));
        }
    }

    // Repeated `push_back_overwrite` exercises the most wrapping-intensive
    // single operation. It delegates to `pop_front` + `push_back_assume_capacity`,
    // covering both unsafe blocks transitively with head AND tail wrapping
    // simultaneously.
    #[kani::proof]
    #[kani::unwind(7)]
    fn push_back_overwrite_sequence_is_sound() {
        let mut ring = RingBuffer::<u32, CAP>::new();
        let offset: u32 = kani::any();
        kani::assume(offset < CAP as u32);
        rotate_head(&mut ring, offset);

        // Fill the ring to capacity.
        for i in 0..CAP {
            ring.push_back(i as u32).unwrap();
        }
        assert!(ring.is_full());

        // Overwrite all elements with new values, rotating the entire ring.
        for i in 0..CAP {
            let evicted = ring.push_back_overwrite((CAP + i) as u32);
            assert_eq!(evicted, Some(i as u32));
        }
        assert!(ring.is_full());

        // Verify the ring contains only the new values in order.
        for i in 0..CAP {
            assert_eq!(ring.get(i), Some(&((CAP + i) as u32)));
        }
    }
}
