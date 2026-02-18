//! Fixed-capacity ring buffer with stack-allocated storage and `MaybeUninit<T>`.
//!
//! # Invariants
//! - `N` is a power of 2 and fits in `u32` (validated at compile time).
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
/// usage. Insertion past capacity is a logic error unless handled via `push_back`.
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

/// Create an uninitialized `[MaybeUninit<T>; N]` without running any constructors.
fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized MaybeUninit<T> is valid.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

impl<T, const N: usize> RingBuffer<T, N> {
    const CAPACITY: u32 = {
        assert!(N > 0, "RingBuffer capacity must be > 0");
        assert!(N & (N - 1) == 0, "RingBuffer capacity must be power of 2");
        assert!(
            N <= u32::MAX as usize / 2,
            "N must fit in u32 and not risk overflow"
        );
        N as u32
    };

    /// Bitmask for power-of-2 modulo: (head + len) & MASK == (head + len) % CAPACITY
    const MASK: u32 = Self::CAPACITY - 1;

    /// Constructs an empty ring buffer with capacity `N` without heap allocation.
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
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len as usize {
            return None;
        }
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
    /// Panics in debug builds if the buffer is full. Use `push_back` when the
    /// caller cannot guarantee capacity.
    #[inline]
    pub fn push_back_assume_capacity(&mut self, value: T) {
        debug_assert!(
            self.len < Self::CAPACITY,
            "push_back_assume_capacity called on full buffer"
        );
        debug_assert!(self.head < Self::CAPACITY, "head out of bounds");

        // PERF: Uses bitwise AND instead of modulo for power-of-2 capacity.
        // This compiles to a single AND instruction vs expensive div/mul sequence.
        let tail = (self.head + self.len) & Self::MASK;

        debug_assert!(tail < Self::CAPACITY, "tail out of bounds");

        // SAFETY: tail < CAPACITY guaranteed by mask operation on power-of-2 capacity.
        // The mask ensures the result is always in [0, CAPACITY).
        unsafe { self.buf.get_unchecked_mut(index(tail)).write(value) };
        self.len += 1;

        debug_assert!(self.len <= Self::CAPACITY);
    }

    /// Appends `value`, evicting and returning the oldest element if at capacity.
    ///
    /// Returns `Some(evicted)` if an element was evicted, `None` if there was
    /// spare capacity. This is the O(1) replacement for the
    /// `if full { remove(0) } push()` pattern.
    #[inline]
    pub fn push_back_overwrite(&mut self, value: T) -> Option<T> {
        if self.is_full() {
            let evicted = self.pop_front();
            self.push_back_assume_capacity(value);
            evicted
        } else {
            self.push_back_assume_capacity(value);
            None
        }
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
    /// Buffer remains usable afterwards without reallocating. The drop path
    /// walks either one contiguous region or two wrapped regions to preserve
    /// FIFO order.
    pub fn clear(&mut self) {
        if self.len == 0 {
            return;
        }

        let head = self.head as usize;
        let len = self.len as usize;

        if head + len <= N {
            // Contiguous region: [head..head+len]
            for i in head..head + len {
                // SAFETY: All elements in [head, head+len) are initialized.
                unsafe { self.buf.get_unchecked_mut(i).assume_init_drop() };
            }
        } else {
            // Wrapped region: [head..N] + [0..wrap_len]
            let wrap_len = (head + len) - N;

            for i in head..N {
                // SAFETY: Elements in [head, N) are initialized.
                unsafe { self.buf.get_unchecked_mut(i).assume_init_drop() };
            }
            for i in 0..wrap_len {
                // SAFETY: Elements in [0, wrap_len) are initialized.
                unsafe { self.buf.get_unchecked_mut(i).assume_init_drop() };
            }
        }

        self.head = 0;
        self.len = 0;

        debug_assert!(self.is_empty());
    }

    /// Returns an iterator over references to the elements in FIFO order.
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
    fn drop(&mut self) {
        self.clear();
        debug_assert!(self.len == 0);
    }
}

impl<T: Clone, const N: usize> Clone for RingBuffer<T, N> {
    fn clone(&self) -> Self {
        let mut new = Self::new();
        for i in 0..self.len as usize {
            let physical = (self.head + i as u32) & Self::MASK;
            // SAFETY: physical < CAPACITY by mask. Element is initialized
            // because i < len.
            let val = unsafe { self.buf.get_unchecked(index(physical)).assume_init_ref() };
            new.push_back(val.clone())
                .unwrap_or_else(|_| unreachable!("clone: capacity mismatch"));
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
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl<T: Eq, const N: usize> Eq for RingBuffer<T, N> {}

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
pub struct Iter<'a, T, const N: usize> {
    ring: &'a RingBuffer<T, N>,
    /// Logical offset from the front (0 = oldest element).
    front: usize,
    /// Logical offset from the front marking the exclusive back boundary.
    back: usize,
}

impl<'a, T, const N: usize> Iterator for Iter<'a, T, N> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        let physical = (self.ring.head + self.front as u32) & RingBuffer::<T, N>::MASK;
        self.front += 1;
        // SAFETY: physical < CAPACITY by mask. Element is initialized because
        // front < back <= len, and slots [head, head+len) are initialized.
        Some(unsafe {
            self.ring
                .buf
                .get_unchecked(index(physical))
                .assume_init_ref()
        })
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
        let physical = (self.ring.head + self.back as u32) & RingBuffer::<T, N>::MASK;
        // SAFETY: physical < CAPACITY by mask. Element is initialized because
        // back was > front and back <= len.
        Some(unsafe {
            self.ring
                .buf
                .get_unchecked(index(physical))
                .assume_init_ref()
        })
    }
}

impl<T, const N: usize> ExactSizeIterator for Iter<'_, T, N> {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------------
    // Drop tracker -- detects double-drop, leak, and use-after-free under Miri.
    // -----------------------------------------------------------------------
    #[derive(Debug)]
    struct DropTracker(Arc<AtomicUsize>);

    impl Drop for DropTracker {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Clone for DropTracker {
        fn clone(&self) -> Self {
            DropTracker(self.0.clone())
        }
    }

    impl PartialEq for DropTracker {
        fn eq(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.0, &other.0)
        }
    }

    fn dt(c: &Arc<AtomicUsize>) -> DropTracker {
        DropTracker(c.clone())
    }

    // -----------------------------------------------------------------------
    // Basic push/pop -- exercises get_unchecked write + as_ptr().read().
    // -----------------------------------------------------------------------

    #[test]
    fn empty_pop_returns_none() {
        let mut ring = RingBuffer::<u32, 4>::new();
        assert_eq!(ring.pop_front(), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn push_then_pop() {
        let mut ring = RingBuffer::<u32, 4>::new();
        assert!(ring.push_back(42).is_ok());
        assert_eq!(ring.pop_front(), Some(42));
        assert!(ring.is_empty());
    }

    #[test]
    fn fifo_ordering() {
        let mut ring = RingBuffer::<u32, 4>::new();
        for i in 0..4 {
            assert!(ring.push_back(i).is_ok());
        }
        assert!(ring.is_full());
        for i in 0..4 {
            assert_eq!(ring.pop_front(), Some(i));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn push_when_full_returns_err() {
        let mut ring = RingBuffer::<u32, 2>::new();
        assert!(ring.push_back(1).is_ok());
        assert!(ring.push_back(2).is_ok());
        assert_eq!(ring.push_back(3), Err(3));
    }

    // -----------------------------------------------------------------------
    // Wraparound -- exercises index masking across the buffer boundary.
    // -----------------------------------------------------------------------

    #[test]
    fn wraparound_correctness() {
        let mut ring = RingBuffer::<u32, 4>::new();
        // Fill and drain multiple times to force head past capacity.
        for round in 0..10u32 {
            let base = round * 4;
            for i in 0..4 {
                assert!(ring.push_back(base + i).is_ok());
            }
            for i in 0..4 {
                assert_eq!(ring.pop_front(), Some(base + i));
            }
        }
    }

    #[test]
    fn partial_fill_drain_wraparound() {
        let mut ring = RingBuffer::<u32, 4>::new();
        // Push 3, pop 2 -- head advances to 2.
        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        assert_eq!(ring.pop_front(), Some(10));
        assert_eq!(ring.pop_front(), Some(20));

        // Push 3 more -- tail wraps around: slots [2,3,0] used.
        ring.push_back(40).unwrap();
        ring.push_back(50).unwrap();
        ring.push_back(60).unwrap();
        assert!(ring.is_full());

        // Drain in order.
        assert_eq!(ring.pop_front(), Some(30));
        assert_eq!(ring.pop_front(), Some(40));
        assert_eq!(ring.pop_front(), Some(50));
        assert_eq!(ring.pop_front(), Some(60));
        assert!(ring.is_empty());
    }

    // -----------------------------------------------------------------------
    // Drop -- exercises the contiguous and wrapped drop paths.
    // -----------------------------------------------------------------------

    #[test]
    fn drop_contiguous_elements() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut ring = RingBuffer::<DropTracker, 4>::new();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            // head=0, len=3 -> contiguous region [0,1,2].
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn drop_wrapped_elements() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut ring = RingBuffer::<DropTracker, 4>::new();
            // Fill and pop 2 to advance head to 2.
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            assert!(ring.pop_front().is_some());
            assert!(ring.pop_front().is_some());
            assert_eq!(drops.load(Ordering::Relaxed), 2); // 2 popped

            // Fill 4 more -- wraps: head=2, slots [2,3,0,1].
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            assert!(ring.is_full());
            // Drop with wrapped region: [2..4) + [0..2).
        }
        // 2 popped + 4 dropped by Drop = 6 total.
        assert_eq!(drops.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn drop_empty_is_noop() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let _ring = RingBuffer::<DropTracker, 4>::new();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    // -----------------------------------------------------------------------
    // Clear -- exercises both contiguous and wrapped clear paths + reuse.
    // -----------------------------------------------------------------------

    #[test]
    fn clear_contiguous() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut ring = RingBuffer::<DropTracker, 4>::new();
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn clear_wrapped() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut ring = RingBuffer::<DropTracker, 4>::new();
        // Advance head to 3.
        for _ in 0..3 {
            ring.push_back(dt(&drops)).unwrap();
            ring.pop_front();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);

        // Now push 4 -- wraps: head=3, slots [3,0,1,2].
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        ring.clear();
        // 3 from pops + 4 from clear = 7.
        assert_eq!(drops.load(Ordering::Relaxed), 7);
        assert!(ring.is_empty());
    }

    #[test]
    fn clear_then_reuse() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.clear();

        // Reuse after clear.
        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        assert_eq!(ring.pop_front(), Some(10));
        assert_eq!(ring.pop_front(), Some(20));
        assert_eq!(ring.pop_front(), Some(30));
    }

    #[test]
    fn clear_empty_is_noop() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.clear(); // should not panic or UB.
        assert!(ring.is_empty());
    }

    // -----------------------------------------------------------------------
    // push_back_assume_capacity -- exercises the unchecked fast path.
    // -----------------------------------------------------------------------

    #[test]
    fn push_back_assume_capacity_fifo() {
        let mut ring = RingBuffer::<u64, 8>::new();
        for i in 0..8 {
            ring.push_back_assume_capacity(i);
        }
        for i in 0..8 {
            assert_eq!(ring.pop_front(), Some(i));
        }
    }

    // -----------------------------------------------------------------------
    // len() / capacity()
    // -----------------------------------------------------------------------

    #[test]
    fn len_and_capacity_basic() {
        let mut ring = RingBuffer::<u32, 4>::new();
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.capacity(), 4);

        ring.push_back(1).unwrap();
        assert_eq!(ring.len(), 1);

        ring.push_back(2).unwrap();
        ring.push_back(3).unwrap();
        ring.push_back(4).unwrap();
        assert_eq!(ring.len(), 4);
        assert!(ring.is_full());

        ring.pop_front();
        assert_eq!(ring.len(), 3);

        ring.clear();
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.capacity(), 4);
    }

    // -----------------------------------------------------------------------
    // get()
    // -----------------------------------------------------------------------

    #[test]
    fn get_basic() {
        let mut ring = RingBuffer::<u32, 4>::new();
        assert_eq!(ring.get(0), None);

        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        assert_eq!(ring.get(0), Some(&10));
        assert_eq!(ring.get(1), Some(&20));
        assert_eq!(ring.get(2), Some(&30));
        assert_eq!(ring.get(3), None);
    }

    #[test]
    fn get_with_wraparound() {
        let mut ring = RingBuffer::<u32, 4>::new();
        // Advance head to 2.
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.pop_front();
        ring.pop_front();
        // head=2, push 4 elements to wrap.
        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        ring.push_back(40).unwrap();
        assert!(ring.is_full());
        // Logical order: 10, 20, 30, 40.
        assert_eq!(ring.get(0), Some(&10));
        assert_eq!(ring.get(1), Some(&20));
        assert_eq!(ring.get(2), Some(&30));
        assert_eq!(ring.get(3), Some(&40));
        assert_eq!(ring.get(4), None);
    }

    // -----------------------------------------------------------------------
    // push_back_overwrite()
    // -----------------------------------------------------------------------

    #[test]
    fn push_back_overwrite_no_eviction() {
        let mut ring = RingBuffer::<u32, 4>::new();
        assert_eq!(ring.push_back_overwrite(10), None);
        assert_eq!(ring.push_back_overwrite(20), None);
        assert_eq!(ring.len(), 2);
    }

    #[test]
    fn push_back_overwrite_evicts_oldest() {
        let mut ring = RingBuffer::<u32, 4>::new();
        for i in 0..4 {
            ring.push_back(i).unwrap();
        }
        assert_eq!(ring.push_back_overwrite(99), Some(0));
        assert_eq!(ring.get(0), Some(&1));
        assert_eq!(ring.get(3), Some(&99));
        assert_eq!(ring.len(), 4);
    }

    #[test]
    fn push_back_overwrite_drops_evicted() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut ring = RingBuffer::<DropTracker, 2>::new();
        ring.push_back(dt(&drops)).unwrap();
        ring.push_back(dt(&drops)).unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        let evicted = ring.push_back_overwrite(dt(&drops));
        // The evicted value is returned, not dropped yet.
        assert!(evicted.is_some());
        // Drop it explicitly.
        drop(evicted);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    // -----------------------------------------------------------------------
    // iter()
    // -----------------------------------------------------------------------

    #[test]
    fn iter_empty() {
        let ring = RingBuffer::<u32, 4>::new();
        assert_eq!(ring.iter().count(), 0);
    }

    #[test]
    fn iter_partial() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        let v: Vec<_> = ring.iter().copied().collect();
        assert_eq!(v, vec![10, 20, 30]);
    }

    #[test]
    fn iter_full_with_wraparound() {
        let mut ring = RingBuffer::<u32, 4>::new();
        // Advance head to 2.
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.pop_front();
        ring.pop_front();
        // Fill: 10, 20, 30, 40 wrapping.
        for v in [10, 20, 30, 40] {
            ring.push_back(v).unwrap();
        }
        let v: Vec<_> = ring.iter().copied().collect();
        assert_eq!(v, vec![10, 20, 30, 40]);
    }

    #[test]
    fn iter_rev() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(10).unwrap();
        ring.push_back(20).unwrap();
        ring.push_back(30).unwrap();
        let v: Vec<_> = ring.iter().rev().copied().collect();
        assert_eq!(v, vec![30, 20, 10]);
    }

    #[test]
    fn iter_rev_with_wraparound() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.pop_front();
        ring.pop_front();
        for v in [10, 20, 30, 40] {
            ring.push_back(v).unwrap();
        }
        let v: Vec<_> = ring.iter().rev().copied().collect();
        assert_eq!(v, vec![40, 30, 20, 10]);
    }

    #[test]
    fn iter_exact_size() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.push_back(3).unwrap();
        let iter = ring.iter();
        assert_eq!(iter.len(), 3);
    }

    #[test]
    fn iter_rev_find() {
        let mut ring = RingBuffer::<u32, 8>::new();
        for i in 0..8 {
            ring.push_back(i).unwrap();
        }
        // Find the last element divisible by 3 (should be 6).
        let found = ring.iter().rev().find(|&&x| x % 3 == 0);
        assert_eq!(found, Some(&6));
    }

    #[test]
    fn for_in_reference() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.push_back(3).unwrap();
        let mut sum = 0;
        for &val in &ring {
            sum += val;
        }
        assert_eq!(sum, 6);
    }

    // -----------------------------------------------------------------------
    // Clone
    // -----------------------------------------------------------------------

    #[test]
    fn clone_produces_independent_copy() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.push_back(3).unwrap();
        let cloned = ring.clone();

        assert_eq!(ring, cloned);

        // Mutate original, clone is independent.
        ring.push_back(4).unwrap();
        assert_ne!(ring, cloned);
    }

    #[test]
    fn clone_drops_independently() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut ring = RingBuffer::<DropTracker, 4>::new();
            ring.push_back(dt(&drops)).unwrap();
            ring.push_back(dt(&drops)).unwrap();
            {
                let _cloned = ring.clone();
                // Clone creates 2 new DropTrackers (via Clone trait).
            }
            // _cloned dropped: 2 drops.
            assert_eq!(drops.load(Ordering::Relaxed), 2);
        }
        // ring dropped: 2 more drops.
        assert_eq!(drops.load(Ordering::Relaxed), 4);
    }

    // -----------------------------------------------------------------------
    // PartialEq
    // -----------------------------------------------------------------------

    #[test]
    fn eq_same_content() {
        let mut a = RingBuffer::<u32, 4>::new();
        let mut b = RingBuffer::<u32, 4>::new();
        a.push_back(1).unwrap();
        a.push_back(2).unwrap();
        b.push_back(1).unwrap();
        b.push_back(2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn eq_different_head_same_content() {
        let mut a = RingBuffer::<u32, 4>::new();
        a.push_back(1).unwrap();
        a.push_back(2).unwrap();

        // b has head offset.
        let mut b = RingBuffer::<u32, 4>::new();
        b.push_back(99).unwrap();
        b.pop_front();
        b.push_back(1).unwrap();
        b.push_back(2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ne_different_length() {
        let mut a = RingBuffer::<u32, 4>::new();
        let b = RingBuffer::<u32, 4>::new();
        a.push_back(1).unwrap();
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // FromIterator
    // -----------------------------------------------------------------------

    #[test]
    fn from_iter_basic() {
        let ring: RingBuffer<u32, 4> = vec![1, 2, 3].into_iter().collect();
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.get(0), Some(&1));
        assert_eq!(ring.get(2), Some(&3));
    }

    #[test]
    fn from_iter_exact_capacity() {
        let ring: RingBuffer<u32, 4> = (0..4).collect();
        assert_eq!(ring.len(), 4);
        assert!(ring.is_full());
    }

    #[test]
    #[should_panic(expected = "too many items")]
    fn from_iter_overflow_panics() {
        let _: RingBuffer<u32, 4> = (0..5).collect();
    }

    // -----------------------------------------------------------------------
    // Debug
    // -----------------------------------------------------------------------

    #[test]
    fn debug_format() {
        let mut ring = RingBuffer::<u32, 4>::new();
        ring.push_back(1).unwrap();
        ring.push_back(2).unwrap();
        ring.push_back(3).unwrap();
        let debug = format!("{ring:?}");
        assert_eq!(debug, "[1, 2, 3]");
    }

    // -----------------------------------------------------------------------
    // Property tests
    // -----------------------------------------------------------------------

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// FIFO ordering is preserved under arbitrary push_back_overwrite sequences.
            #[test]
            fn push_back_overwrite_preserves_fifo(values in proptest::collection::vec(0u32..1000, 0..200)) {
                // Use a VecDeque as the reference model.
                let mut model = std::collections::VecDeque::with_capacity(8);
                let mut ring = RingBuffer::<u32, 8>::new();
                for v in &values {
                    if model.len() == 8 {
                        model.pop_front();
                    }
                    model.push_back(*v);
                    ring.push_back_overwrite(*v);
                }
                let ring_vals: Vec<_> = ring.iter().copied().collect();
                let model_vals: Vec<_> = model.iter().copied().collect();
                prop_assert_eq!(ring_vals, model_vals);
            }

            /// len() is always consistent after push/pop operations.
            #[test]
            fn len_consistent_after_operations(ops in proptest::collection::vec(prop_oneof![Just(true), Just(false)], 0..100)) {
                let mut ring = RingBuffer::<u32, 4>::new();
                let mut expected_len = 0usize;
                for (i, &is_push) in ops.iter().enumerate() {
                    if is_push && expected_len < 4 {
                        ring.push_back(i as u32).unwrap();
                        expected_len += 1;
                    } else if !is_push && expected_len > 0 {
                        ring.pop_front();
                        expected_len -= 1;
                    }
                    prop_assert_eq!(ring.len(), expected_len);
                }
            }
        }
    }
}
