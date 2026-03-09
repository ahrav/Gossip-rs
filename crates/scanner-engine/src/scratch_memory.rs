//! Page-aligned, fixed-capacity scratch storage for hot paths.
//!
//! # Scope
//! This module makes allocation behavior explicit and predictable in tight
//! loops. Regular `Vec` growth can allocate at unpredictable points, so we
//! provide `ScratchVec`: a fixed-capacity vector that never reallocates.
//!
//! The goal is not general-purpose convenience. It is deterministic memory
//! usage with clear failure modes when capacity is exceeded.
//!
//! # Invariants
//! - `ScratchVec` has a hard capacity; exceeding it is a logic error and will
//!   panic in debug builds.
//! - Memory is page-aligned (minimum 4 KiB) to keep alignment predictable.
//!
//! # Failure modes
//! - Capacity overruns are treated as bugs (debug assertions).
//! - Allocation failures and invalid layouts are reported via
//!   `ScratchMemoryError`.

use std::alloc::{Layout, alloc, dealloc};
use std::mem::{MaybeUninit, align_of, size_of};
use std::ptr::NonNull;

/// Minimum alignment for scratch allocations.
///
/// Page alignment (4 KiB) keeps buffers SIMD-friendly and avoids alignment
/// faults when scratch buffers are reused for vectorised byte operations.
/// This is a conservative lower bound; the actual OS page size may be larger.
const PAGE_SIZE_MIN: usize = 4096;

/// Errors returned by scratch allocators.
#[derive(Debug)]
pub enum ScratchMemoryError {
    /// Element type is a ZST (`size_of::<T>() == 0`) and a non-zero capacity
    /// was requested. Zero-sized types are not supported.
    SizeZero,
    /// The requested layout was invalid (overflow or bad alignment).
    InvalidLayout,
    /// The allocator returned null.
    OutOfMemory,
}

/// Fixed-capacity scratch vector backed by page-aligned storage.
///
/// This is a `Vec`-like API with a hard capacity. It never reallocates, so
/// once constructed it is safe to use in hot loops without risking
/// allocations.
///
/// # Invariants
/// - `len <= cap` at all times.
/// - Elements in `0..len` are initialized; elements in `len..cap` are not.
///
/// Capacity overruns are treated as bugs and only checked in debug builds.
pub struct ScratchVec<T> {
    ptr: NonNull<MaybeUninit<T>>,
    len: u32,
    cap: u32,
}

impl<T> ScratchVec<T> {
    /// Recompute the deallocation layout from stored capacity.
    ///
    /// Only called in `drop()` for non-zero-capacity vectors. The layout is
    /// guaranteed valid because `with_capacity` already validated `cap *
    /// size_of::<T>()` does not overflow, `size_of::<T>() > 0`, and alignment
    /// is a power of two — so `from_size_align_unchecked` is sound for any
    /// capacity that passed construction.
    fn dealloc_layout(cap: u32) -> Layout {
        let align = PAGE_SIZE_MIN.max(align_of::<T>());
        let cap = cap as usize;
        let size = cap * size_of::<T>();
        debug_assert!(size > 0, "scratch vec dealloc size must be non-zero");
        debug_assert!(
            align.is_power_of_two(),
            "scratch vec alignment must be power-of-two"
        );
        // SAFETY: this was validated at construction time — size_of::<T>() > 0
        // and cap * size_of::<T>() did not overflow; `align` is a power of two.
        unsafe { Layout::from_size_align_unchecked(size, align) }
    }

    /// Allocate a fixed-capacity scratch vector.
    ///
    /// # Errors
    /// - `SizeZero` if `T` is a ZST (`size_of::<T>() == 0`) and `cap > 0`.
    /// - `InvalidLayout` if `cap` exceeds `u32::MAX`, `cap * size_of::<T>()`
    ///   overflows, or the resulting layout is invalid.
    /// - `OutOfMemory` if allocation fails.
    ///
    /// # Notes
    /// - `cap == 0` returns a dangling allocation with zero length/capacity.
    ///   Pushing into a zero-capacity vector is a logic error.
    pub fn with_capacity(cap: usize) -> Result<Self, ScratchMemoryError> {
        if cap == 0 {
            return Ok(Self {
                ptr: NonNull::dangling(),
                len: 0,
                cap: 0,
            });
        }

        let elem_size = size_of::<T>();
        if elem_size == 0 {
            return Err(ScratchMemoryError::SizeZero);
        }
        if cap > u32::MAX as usize {
            return Err(ScratchMemoryError::InvalidLayout);
        }

        let size = cap
            .checked_mul(elem_size)
            .ok_or(ScratchMemoryError::InvalidLayout)?;
        // Page alignment keeps allocations predictable and makes it safe to
        // reuse scratch buffers for SIMD-friendly workloads without worrying
        // about alignment faults.
        let align = PAGE_SIZE_MIN.max(align_of::<T>());
        let layout =
            Layout::from_size_align(size, align).map_err(|_| ScratchMemoryError::InvalidLayout)?;

        // SAFETY: layout is valid and has non-zero size.
        let raw = unsafe { alloc(layout) };
        let ptr = NonNull::new(raw).ok_or(ScratchMemoryError::OutOfMemory)?;

        Ok(Self {
            ptr: ptr.cast(),
            len: 0,
            cap: cap as u32,
        })
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn capacity(&self) -> usize {
        self.cap as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Push a value onto the end of the vector.
    ///
    /// # Panics (debug builds)
    /// Panics if `self.len() == self.capacity()`. In release builds this is a
    /// logic error that can write out of bounds.
    pub fn push(&mut self, value: T) {
        debug_assert!(self.len < self.cap, "scratch vec capacity exceeded");
        // SAFETY: `len < cap` (asserted above in debug, caller invariant in
        // release), so `ptr + len` is within the allocated region. The slot at
        // `len` is uninitialized and we write a valid `MaybeUninit<T>`.
        unsafe {
            self.ptr
                .as_ptr()
                .add(self.len())
                .write(MaybeUninit::new(value));
        }
        self.len += 1;
    }

    /// Shorten the vector to `new_len`, dropping elements above the new length.
    ///
    /// # Panics (debug builds)
    /// Panics if `new_len > self.len()`. In release builds this is a logic
    /// error that can leave the vector with uninitialized elements.
    pub fn truncate(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.len(), "scratch vec truncate out of bounds");
        let old_len = self.len as usize;
        // SAFETY: Elements `new_len..self.len` are initialized (invariant: all
        // elements in `0..len` are initialized). We drop each in-place and then
        // lower `len`, which leaves no dangling initialized memory.
        unsafe {
            for i in new_len..old_len {
                std::ptr::drop_in_place(self.ptr.as_ptr().add(i).cast::<T>());
            }
        }
        // `self.len <= self.cap` is an invariant and `cap` is stored as `u32`.
        self.len = new_len as u32;
    }

    pub fn as_slice(&self) -> &[T] {
        // SAFETY: `ptr` is valid for `cap` elements, `len <= cap`, and all
        // elements in `0..len` are initialized. The `&self` borrow ensures no
        // concurrent mutation.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast::<T>(), self.len()) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: Same as `as_slice`; `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<T>(), self.len()) }
    }

    /// Appends all elements from `slice` to the vector.
    ///
    /// This is the fixed-capacity equivalent of `Vec::extend_from_slice`. Unlike
    /// `Vec`, this method debug-asserts if the resulting length would exceed
    /// capacity, making capacity overruns immediately visible during development.
    ///
    /// # Panics (debug builds)
    ///
    /// Panics if `self.len() + slice.len() > self.capacity()`. In release builds
    /// this is a logic error that can write out of bounds.
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Copy,
    {
        let len = self.len as usize;
        let new_len = len.saturating_add(slice.len());
        debug_assert!(
            new_len <= self.cap as usize,
            "scratch vec capacity exceeded on extend_from_slice"
        );
        // SAFETY: `new_len <= cap` (debug-asserted), so `ptr + len` through
        // `ptr + new_len - 1` is within bounds. Source and destination do not
        // overlap because `slice` is an external reference and the destination
        // is the uninitialized tail of our allocation. `T: Copy` means no
        // drop glue and bitwise copy is sufficient.
        unsafe {
            std::ptr::copy_nonoverlapping(
                slice.as_ptr(),
                self.ptr.as_ptr().add(len).cast::<T>(),
                slice.len(),
            );
        }
        // `new_len <= cap` is debug-asserted above and `cap` is `u32`-backed.
        self.len = new_len as u32;
    }

    /// Appends a range from this vector's existing contents.
    ///
    /// This is useful for building new data from previous bytes without
    /// allocating intermediate buffers. The preconditions guarantee that the
    /// source range is disjoint from the destination; `ptr::copy` (memmove
    /// semantics) is used defensively but overlap cannot occur when the
    /// contract is upheld.
    ///
    /// # Panics (debug builds)
    ///
    /// Panics if `start + len` exceeds the current length or if the new
    /// length would exceed capacity. In release builds, violating these
    /// preconditions can corrupt memory.
    pub fn extend_from_self_range(&mut self, start: usize, len: usize)
    where
        T: Copy,
    {
        let cur_len = self.len as usize;
        debug_assert!(start <= cur_len, "scratch vec range start out of bounds");
        debug_assert!(
            start.saturating_add(len) <= cur_len,
            "scratch vec range end out of bounds"
        );
        let new_len = cur_len.saturating_add(len);
        debug_assert!(
            new_len <= self.cap as usize,
            "scratch vec capacity exceeded on extend_from_self_range"
        );
        // SAFETY: Source range `start..start+len` is within `0..self.len`
        // (debug-asserted) and destination starts at `self.len`. Because
        // `start + len <= self.len`, the source ends before the destination
        // begins, so the regions are always disjoint. `copy` (memmove) is
        // used defensively; `copy_nonoverlapping` would also be sound here.
        unsafe {
            std::ptr::copy(
                self.ptr.as_ptr().add(start).cast::<T>(),
                self.ptr.as_ptr().add(cur_len).cast::<T>(),
                len,
            );
        }
        // `new_len <= cap` is debug-asserted above and `cap` is `u32`-backed.
        self.len = new_len as u32;
    }

    /// Removes and returns the last element, or `None` if empty.
    ///
    /// This is the fixed-capacity equivalent of `Vec::pop`. The capacity remains
    /// unchanged; only the logical length decreases.
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        self.len -= 1;
        // SAFETY: `self.len` (post-decrement) was the last valid index. The
        // element is initialized. `read()` performs a bitwise copy without
        // dropping the source — ownership transfers to the caller. The slot
        // is now logically uninitialized and excluded by the lowered `len`.
        unsafe { Some(self.ptr.as_ptr().add(self.len()).cast::<T>().read()) }
    }

    /// Returns a reference to the element at `index`, or `None` if out of bounds.
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len() {
            // SAFETY: `index < len <= cap`, so the pointer arithmetic is in
            // bounds and the element is initialized. The `&self` borrow prevents
            // concurrent mutation.
            unsafe { Some(&*self.ptr.as_ptr().add(index).cast::<T>()) }
        } else {
            None
        }
    }

    /// Returns a reference to the element at `index` without bounds checking.
    ///
    /// For a safe alternative, see [`get`](Self::get).
    ///
    /// # Safety
    ///
    /// Calling this method with an `index` that is greater than or equal to
    /// `self.len()` is *undefined behavior*, even if the resulting reference
    /// is not used.
    ///
    /// # Debug assertions
    ///
    /// In debug builds, an out-of-bounds index panics with a descriptive
    /// message. This check is elided in release builds.
    #[inline(always)]
    pub(crate) unsafe fn get_unchecked(&self, index: usize) -> &T {
        debug_assert!(index < self.len(), "get_unchecked: index out of bounds");
        // SAFETY: caller guarantees `index < self.len()`, which means
        // `index < self.cap` and the element at `index` is initialized.
        unsafe { &*self.ptr.as_ptr().add(index).cast::<T>() }
    }

    /// Returns a mutable reference to the element at `index`, or `None` if out of bounds.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.len() {
            // SAFETY: Same as `get`; `&mut self` guarantees exclusive access.
            unsafe { Some(&mut *self.ptr.as_ptr().add(index).cast::<T>()) }
        } else {
            None
        }
    }

    /// Creates a draining iterator that removes and yields elements in order.
    ///
    /// After the iterator is dropped (or fully consumed), the vector is empty.
    /// This is the fixed-capacity equivalent of `Vec::drain(..)`.
    ///
    /// # Ownership
    /// Length is set to 0 *before* creating the iterator, transferring
    /// ownership of all `len` elements to `Drain`. This ensures the vector
    /// is in a consistent (empty) state even if the caller leaks the `Drain`.
    pub fn drain(&mut self) -> Drain<'_, T> {
        let len = self.len();
        self.len = 0;
        Drain {
            ptr: self.ptr.cast::<T>(),
            idx: 0,
            len,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Draining iterator for [`ScratchVec`].
///
/// Yields elements by value and drops any remaining elements when the iterator
/// is dropped. After iteration completes (or the iterator is dropped), the
/// source `ScratchVec` is empty.
///
/// # Design
/// The parent `ScratchVec::len` is set to 0 *before* creating `Drain`. This
/// means the `Drain` owns all `len` elements and is solely responsible for
/// either yielding or dropping them — there is no double-drop risk even if
/// the consumer panics mid-iteration (the `Drop` impl handles the tail).
///
/// # Safety
/// `ptr` points into the parent's allocation, which remains valid for `'a`.
/// The `PhantomData<&'a mut T>` ties the iterator's lifetime to the parent's
/// exclusive borrow, preventing use-after-free and aliased mutation.
pub struct Drain<'a, T> {
    ptr: NonNull<T>,
    idx: usize,
    len: usize,
    _marker: std::marker::PhantomData<&'a mut T>,
}

impl<'a, T> Iterator for Drain<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.len {
            return None;
        }
        // SAFETY: `idx < len` and each index is yielded exactly once (idx is
        // monotonically incremented). `read()` transfers ownership to the caller
        // without running drop on the source; the `Drop` impl skips yielded indices.
        let val = unsafe { self.ptr.as_ptr().add(self.idx).read() };
        self.idx += 1;
        Some(val)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len.saturating_sub(self.idx);
        (remaining, Some(remaining))
    }
}

impl<'a, T> ExactSizeIterator for Drain<'a, T> {}

impl<'a, T> Drop for Drain<'a, T> {
    fn drop(&mut self) {
        // Drop any remaining elements that were not yielded.
        for i in self.idx..self.len {
            // SAFETY: `self.ptr` points to a valid `ScratchVec` allocation with
            // `self.len` initialized elements; indices `self.idx..self.len` have
            // not been yielded and must be dropped exactly once.
            unsafe {
                std::ptr::drop_in_place(self.ptr.as_ptr().add(i));
            }
        }
    }
}

impl<T> std::ops::Index<usize> for ScratchVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T> std::ops::IndexMut<usize> for ScratchVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut_slice()[index]
    }
}

impl<T> Drop for ScratchVec<T> {
    fn drop(&mut self) {
        // Drop all initialized elements first.
        self.truncate(0);
        if self.cap == 0 {
            return;
        }
        // SAFETY: `ptr` was allocated with the same layout computed by
        // `dealloc_layout(cap)`. All elements have been dropped by `truncate(0)`
        // above, so we only free the backing memory.
        unsafe {
            dealloc(
                self.ptr.as_ptr().cast::<u8>(),
                Self::dealloc_layout(self.cap),
            );
        }
    }
}

// SAFETY: `ScratchVec<T>` exclusively owns its allocation (no shared or aliased
// pointers). When `T: Send`, transferring the vector to another thread is safe
// because all owned data moves with it — identical reasoning to `Vec<T>: Send`.
// Note: we intentionally do *not* implement `Sync` because the type is designed
// for single-threaded scratch use within one scan — there is no need for shared
// references across threads, and omitting `Sync` encodes that intent at the
// type level.
unsafe impl<T: Send> Send for ScratchVec<T> {}

// Compile-time size guard: `ScratchVec<u8>` should remain pointer + 2x u32
// (no padding on common targets). This catches accidental field additions.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<ScratchVec<u8>>() == 16);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(size_of::<ScratchVec<u8>>() == 12);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_vec_basic() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        assert_eq!(vec.as_slice(), &[10, 20]);
        vec.truncate(1);
        assert_eq!(vec.as_slice(), &[10]);
        vec.clear();
        assert!(vec.is_empty());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "scratch vec capacity exceeded")]
    fn scratch_vec_push_overflow_panics() {
        let mut vec = ScratchVec::<u8>::with_capacity(1).unwrap();
        vec.push(1);
        vec.push(2);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "scratch vec capacity exceeded")]
    fn scratch_vec_extend_from_slice_overflow() {
        let mut vec = ScratchVec::<u8>::with_capacity(3).unwrap();
        vec.extend_from_slice(&[1, 2, 3, 4]);
    }

    #[test]
    fn scratch_vec_get() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        assert_eq!(vec.get(0), Some(&10));
        assert_eq!(vec.get(1), Some(&20));
        assert_eq!(vec.get(2), None);
        assert_eq!(vec.get(100), None);
    }

    #[test]
    fn scratch_vec_get_mut() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        if let Some(v) = vec.get_mut(0) {
            *v = 100;
        }
        assert_eq!(vec.as_slice(), &[100, 20]);
        assert!(vec.get_mut(5).is_none());
    }

    #[test]
    fn scratch_vec_drain_partial() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(1);
        vec.push(2);
        vec.push(3);

        {
            let mut drain = vec.drain();
            assert_eq!(drain.next(), Some(1));
            // Drop without consuming all - remaining should be dropped
        }

        assert!(vec.is_empty());
    }

    #[test]
    fn with_capacity_beyond_u32_max_returns_err() {
        let result = ScratchVec::<u8>::with_capacity(u32::MAX as usize + 1);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Miri-targeted: drop tracking for unsafe paths.
    // -----------------------------------------------------------------------
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct DropTracker(Arc<AtomicUsize>);

    impl Drop for DropTracker {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dt(c: &Arc<AtomicUsize>) -> DropTracker {
        DropTracker(c.clone())
    }

    #[test]
    fn truncate_drops_correct_count() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut vec = ScratchVec::<DropTracker>::with_capacity(8).unwrap();
        for _ in 0..5 {
            vec.push(dt(&drops));
        }
        vec.truncate(2);
        // 3 elements should be dropped by truncate.
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        assert_eq!(vec.len(), 2);
        drop(vec);
        // Remaining 2 dropped.
        assert_eq!(drops.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn drain_full_drops_all() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut vec = ScratchVec::<DropTracker>::with_capacity(4).unwrap();
        for _ in 0..4 {
            vec.push(dt(&drops));
        }
        let collected: Vec<DropTracker> = vec.drain().collect();
        // Drain transferred ownership; no drops yet from drain itself.
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(collected);
        assert_eq!(drops.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn drain_partial_drops_remainder() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut vec = ScratchVec::<DropTracker>::with_capacity(4).unwrap();
        for _ in 0..4 {
            vec.push(dt(&drops));
        }
        {
            let mut drain = vec.drain();
            let _first = drain.next(); // takes ownership of 1
            // Drain::drop should drop the remaining 3.
        }
        // 1 still alive in _first? No, _first is dropped at end of block too.
        assert_eq!(drops.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn drain_zero_consumed_drops_all() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut vec = ScratchVec::<DropTracker>::with_capacity(4).unwrap();
        for _ in 0..3 {
            vec.push(dt(&drops));
        }
        {
            let _drain = vec.drain(); // consume none, drop all 3
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn extend_from_self_range_non_overlapping() {
        let mut vec = ScratchVec::<u8>::with_capacity(16).unwrap();
        vec.extend_from_slice(&[10, 20, 30, 40]);
        vec.extend_from_self_range(1, 2); // copy [20, 30] to end
        assert_eq!(vec.as_slice(), &[10, 20, 30, 40, 20, 30]);
    }

    #[test]
    fn extend_from_self_range_adjacent() {
        let mut vec = ScratchVec::<u8>::with_capacity(16).unwrap();
        vec.extend_from_slice(&[1, 2, 3, 4]);
        // Source range ends exactly at current len — destination starts at len.
        vec.extend_from_self_range(2, 2); // copy [3, 4]
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 3, 4]);
    }

    #[test]
    fn push_pop_reuse_slots() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut vec = ScratchVec::<DropTracker>::with_capacity(4).unwrap();
        // Push 4, pop 4, push 4 again — reuse the same allocation.
        for _ in 0..4 {
            vec.push(dt(&drops));
        }
        for _ in 0..4 {
            vec.pop();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 4);

        for _ in 0..4 {
            vec.push(dt(&drops));
        }
        drop(vec);
        assert_eq!(drops.load(Ordering::Relaxed), 8);
    }

    #[test]
    fn zero_capacity_is_safe() {
        let vec = ScratchVec::<u32>::with_capacity(0).unwrap();
        assert_eq!(vec.len(), 0);
        assert_eq!(vec.capacity(), 0);
        assert!(vec.is_empty());
        // Drop should be safe on zero-capacity.
    }

    #[test]
    fn index_and_index_mut() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        assert_eq!(vec[0], 10);
        assert_eq!(vec[1], 20);
        vec[0] = 100;
        assert_eq!(vec[0], 100);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "get_unchecked: index out of bounds")]
    fn get_unchecked_oob_debug_panics() {
        let vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        // vec is empty, so index 0 is out of bounds.
        // SAFETY: intentionally OOB to test the debug_assert panic.
        unsafe {
            vec.get_unchecked(0);
        }
    }

    #[test]
    fn miri_get_unchecked_boundary_values() {
        let mut vec = ScratchVec::<u32>::with_capacity(4).unwrap();
        vec.push(10);
        vec.push(20);
        vec.push(30);

        // Valid indices: first, middle, last.
        // SAFETY: indices 0, 1, 2 are all in bounds (vec.len() == 3).
        unsafe {
            assert_eq!(*vec.get_unchecked(0), 10);
            assert_eq!(*vec.get_unchecked(1), 20);
            assert_eq!(*vec.get_unchecked(2), 30);
        }

        // After pop, last valid index shrinks.
        vec.pop();
        // SAFETY: indices 0, 1 are in bounds (vec.len() == 2).
        unsafe {
            assert_eq!(*vec.get_unchecked(0), 10);
            assert_eq!(*vec.get_unchecked(1), 20);
        }

        // After clear + refill, indices are fresh.
        vec.clear();
        vec.push(99);
        // SAFETY: index 0 is in bounds (vec.len() == 1).
        unsafe {
            assert_eq!(*vec.get_unchecked(0), 99);
        }
    }
}

// ============================================================================
// Kani Bounded Model Checking Proofs
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Bounded capacity for Kani proofs. Small to keep state space manageable.
    const MAX_CAP: usize = 4;

    /// Proves push never writes beyond capacity.
    /// For any valid capacity and sequence of pushes up to that capacity,
    /// `len` never exceeds `cap` and `as_slice` returns the correct values.
    #[kani::proof]
    #[kani::unwind(6)] // MAX_CAP + 2 for loop unrolling
    fn verify_push_never_exceeds_capacity() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let mut vec = ScratchVec::<u8>::with_capacity(cap).unwrap();

        let n: usize = kani::any();
        kani::assume(n <= cap);

        for i in 0..n {
            let val: u8 = kani::any();
            vec.push(val);
            kani::assert(vec.len() == i + 1, "len must match push count");
            kani::assert(vec.len() <= vec.capacity(), "len must not exceed cap");
        }
    }

    /// Proves truncate leaves exactly `new_len` elements.
    #[kani::proof]
    #[kani::unwind(6)]
    fn verify_truncate_bounds() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let mut vec = ScratchVec::<u8>::with_capacity(cap).unwrap();

        let fill: usize = kani::any();
        kani::assume(fill <= cap);
        for _ in 0..fill {
            vec.push(kani::any());
        }

        let new_len: usize = kani::any();
        kani::assume(new_len <= fill);
        vec.truncate(new_len);

        kani::assert(vec.len() == new_len, "truncate must set len to new_len");
    }

    /// Proves pop returns the last pushed value and decrements len.
    #[kani::proof]
    #[kani::unwind(6)]
    fn verify_pop_returns_last() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let mut vec = ScratchVec::<u8>::with_capacity(cap).unwrap();

        let fill: usize = kani::any();
        kani::assume(fill > 0 && fill <= cap);

        let mut last = 0u8;
        for _ in 0..fill {
            last = kani::any();
            vec.push(last);
        }

        let popped = vec.pop();
        kani::assert(popped == Some(last), "pop must return last pushed value");
        kani::assert(vec.len() == fill - 1, "pop must decrement len");
    }

    /// Proves extend_from_slice bounds: new_len == old_len + slice.len() <= cap.
    #[kani::proof]
    #[kani::unwind(6)]
    fn verify_extend_from_slice_bounds() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let mut vec = ScratchVec::<u8>::with_capacity(cap).unwrap();

        let fill: usize = kani::any();
        kani::assume(fill <= cap);
        for _ in 0..fill {
            vec.push(kani::any());
        }

        let ext_len: usize = kani::any();
        kani::assume(ext_len <= cap - fill);
        // Build a small stack buffer to extend from.
        let mut buf = [0u8; MAX_CAP];
        for i in 0..ext_len {
            buf[i] = kani::any();
        }

        vec.extend_from_slice(&buf[..ext_len]);
        kani::assert(
            vec.len() == fill + ext_len,
            "extend must add exactly ext_len elements",
        );
        kani::assert(vec.len() <= vec.capacity(), "len must not exceed cap");
    }

    /// Proves `get_unchecked` returns the same value as `get` for any valid index.
    #[kani::proof]
    #[kani::unwind(6)]
    fn verify_get_unchecked_matches_get() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let mut vec = ScratchVec::<u8>::with_capacity(cap).unwrap();

        let fill: usize = kani::any();
        kani::assume(fill > 0 && fill <= cap);
        for _ in 0..fill {
            vec.push(kani::any());
        }

        let idx: usize = kani::any();
        kani::assume(idx < fill);

        let safe_val = vec.get(idx).copied();
        let unchecked_val = unsafe { *vec.get_unchecked(idx) };
        kani::assert(
            safe_val == Some(unchecked_val),
            "get_unchecked must match get for valid indices",
        );
    }

    /// Proves drain yields exactly `len` elements and leaves vec empty.
    #[kani::proof]
    #[kani::unwind(6)]
    fn verify_drain_yields_all() {
        let cap: usize = kani::any();
        kani::assume(cap > 0 && cap <= MAX_CAP);

        let mut vec = ScratchVec::<u8>::with_capacity(cap).unwrap();

        let fill: usize = kani::any();
        kani::assume(fill <= cap);
        for _ in 0..fill {
            vec.push(kani::any());
        }

        let mut count = 0usize;
        for _ in vec.drain() {
            count += 1;
        }

        kani::assert(count == fill, "drain must yield exactly len elements");
        kani::assert(vec.is_empty(), "vec must be empty after full drain");
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 32;

    #[derive(Clone, Debug)]
    enum Op {
        Push(u32),
        Pop,
        Truncate(usize),
        Clear,
        ExtendFromSlice(Vec<u32>),
        Drain,
        GetUnchecked(usize),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            any::<u32>().prop_map(Op::Push),
            Just(Op::Pop),
            (0usize..128).prop_map(Op::Truncate),
            Just(Op::Clear),
            prop::collection::vec(any::<u32>(), 0..8).prop_map(Op::ExtendFromSlice),
            Just(Op::Drain),
            (0usize..128).prop_map(Op::GetUnchecked),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn prop_scratch_vec_matches_vec(
            cap in 0usize..32,
            ops in prop::collection::vec(op_strategy(), 0..128)
        ) {
            let mut scratch = ScratchVec::<u32>::with_capacity(cap).unwrap();
            let mut shadow = Vec::new();

            for op in ops {
                match op {
                    Op::Push(v) => {
                        if scratch.len() < scratch.capacity() {
                            scratch.push(v);
                            shadow.push(v);
                        }
                    }
                    Op::Pop => {
                        let s = scratch.pop();
                        let v = shadow.pop();
                        prop_assert_eq!(s, v);
                    }
                    Op::Truncate(n) => {
                        let new_len = n.min(scratch.len());
                        scratch.truncate(new_len);
                        shadow.truncate(new_len);
                    }
                    Op::Clear => {
                        scratch.clear();
                        shadow.clear();
                    }
                    Op::ExtendFromSlice(slice) => {
                        if scratch.len().saturating_add(slice.len()) <= scratch.capacity() {
                            scratch.extend_from_slice(&slice);
                            shadow.extend_from_slice(&slice);
                        }
                    }
                    Op::Drain => {
                        let s: Vec<_> = scratch.drain().collect();
                        let v: Vec<_> = std::mem::take(&mut shadow);
                        prop_assert_eq!(s, v);
                    }
                    Op::GetUnchecked(idx) => {
                        if idx < scratch.len() {
                            // SAFETY: `idx < scratch.len()` is checked on the line above.
                            let unchecked = unsafe { *scratch.get_unchecked(idx) };
                            prop_assert_eq!(unchecked, shadow[idx]);
                        }
                    }
                }

                prop_assert_eq!(scratch.as_slice(), shadow.as_slice());
            }
        }
    }
}
