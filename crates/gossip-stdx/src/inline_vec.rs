//! Inline-first small vector: stores up to `N` elements on the stack,
//! spilling to a heap-allocated `Vec<T>` only when capacity is exceeded.
//!
//! # Motivation
//!
//! 99%+ of shards have 0–2 spawned children. A `Vec<ShardId>` always
//! heap-allocates, even when empty (on first push). `InlineVec<ShardId, 8>`
//! keeps up to 8 elements in a stack-resident `[MaybeUninit<T>; N]` buffer,
//! eliminating one allocation per shard creation in the common case.
//!
//! # Invariants
//!
//! - `N > 0` and `N <= u32::MAX / 2` (compile-time assertions).
//! - In `Repr::Inline`: slots `0..len` are initialized; slots `len..N`
//!   are uninitialized.
//! - In `Repr::Heap`: the inner `Vec<T>` owns all elements.
//! - `Repr` does **not** implement `Drop`. All cleanup is handled by
//!   `InlineVec::drop`, which is critical for the `mem::replace` spill
//!   path to avoid double-free.
//!
//! # Threading
//!
//! This type has no internal synchronization.
//!
//! Auto-traits follow `T`: `InlineVec<T, N>` is `Send` when `T: Send`,
//! and `Sync` when `T: Sync`. Concurrent mutation still requires external
//! synchronization (as with any `&mut`-based API).

use std::mem::{self, MaybeUninit};

/// Inline-first small vector backed by `[MaybeUninit<T>; N]`.
///
/// Stores up to `N` elements inline (stack-allocated). When the `N+1`th
/// element is pushed, all inline elements are moved to a heap `Vec<T>`
/// and the representation switches permanently to heap mode.
///
/// The spill is one-way: once on the heap, the vector stays on the heap.
/// This avoids pathological oscillation at the boundary.
pub struct InlineVec<T, const N: usize> {
    repr: Repr<T, N>,
}

/// Internal representation. **No `Drop` impl** — `InlineVec` handles all
/// cleanup. This is critical: the `push` spill path uses `mem::replace`
/// to extract the old `Repr`, and a `Drop` on `Repr` would double-free
/// the inline elements that were already moved to the new `Vec`.
enum Repr<T, const N: usize> {
    Inline { buf: [MaybeUninit<T>; N], len: u32 },
    Heap(Vec<T>),
}

// Compile-time proof that u32 -> usize is safe on this platform.
const _: () = assert!(
    std::mem::size_of::<usize>() >= std::mem::size_of::<u32>(),
    "Platform must have at least 32-bit addressing"
);

impl<T, const N: usize> InlineVec<T, N> {
    /// Compile-time capacity validation.
    const VALIDATED_CAP: u32 = {
        assert!(N > 0, "InlineVec capacity must be > 0");
        assert!(
            N <= u32::MAX as usize / 2,
            "N must fit in u32 and not risk overflow"
        );
        N as u32
    };

    /// Constructs an empty `InlineVec` with zero elements in inline mode.
    ///
    /// No heap allocation occurs.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_stdx::InlineVec;
    ///
    /// let v = InlineVec::<u32, 8>::new();
    /// assert!(v.is_empty());
    /// assert_eq!(v.len(), 0);
    /// ```
    #[inline]
    pub fn new() -> Self {
        // Force compile-time validation.
        let _ = Self::VALIDATED_CAP;

        Self {
            repr: Repr::Inline {
                buf: uninit_array(),
                len: 0,
            },
        }
    }

    /// Returns the number of elements.
    #[inline]
    pub fn len(&self) -> usize {
        match &self.repr {
            Repr::Inline { len, .. } => *len as usize,
            Repr::Heap(v) => v.len(),
        }
    }

    /// Returns `true` when no elements are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends a single element.
    ///
    /// If the inline buffer is full, all inline elements are moved to a
    /// heap `Vec` and the new element is appended there. This spill is
    /// one-way: once on the heap, the vector stays on the heap.
    #[inline]
    pub fn push(&mut self, value: T) {
        match &mut self.repr {
            Repr::Inline { len, .. } if (*len as usize) < N => {
                let idx = *len as usize;
                // Re-match rationale: the outer `match &mut self.repr` with a
                // guard extends the borrow's lifetime through the arm body.
                // We need a fresh mutable reborrow of `buf` and `len` to
                // write, so we re-match inside the arm.
                if let Repr::Inline { buf, len } = &mut self.repr {
                    // SAFETY: idx < N, so buf[idx] is in bounds. The slot is
                    // uninitialized (idx == len, which is past the last
                    // initialized slot). We write a valid T into it and
                    // increment len to maintain the invariant that slots
                    // 0..len are initialized.
                    unsafe { buf.get_unchecked_mut(idx).write(value) };
                    *len += 1;
                }
            }
            Repr::Inline { .. } => {
                // Spill: inline buffer is full. Move all elements to Vec.
                self.spill_and_push(value);
            }
            Repr::Heap(v) => {
                v.push(value);
            }
        }
    }

    /// Cold path: move inline elements to heap mode and reserve `additional`
    /// future slots.
    ///
    /// Marked `#[cold]` / `#[inline(never)]` to keep the spill machinery out of
    /// the hot `push` path. The compiler will not inline or speculate this code
    /// into the fast inline branch, keeping instruction-cache pressure low for
    /// the common case.
    ///
    /// Pre-reserving `additional` capacity lets both `push` and
    /// `extend_from_slice` pay spill allocation cost once in the common case.
    ///
    /// Uses bulk `copy_nonoverlapping` instead of per-element moves because
    /// ownership is being *transferred*, not cloned: the source `MaybeUninit`
    /// slots are bitwise-copied and then forgotten (no destructors run on them),
    /// while the destination `Vec` takes ownership of the initialized bytes.
    #[cold]
    #[inline(never)]
    fn spill_inline_to_heap_with_additional(&mut self, additional: usize) {
        let count = match &self.repr {
            Repr::Inline { len, .. } => *len as usize,
            Repr::Heap(_) => return,
        };

        // Prefer one-shot allocation for existing + additional elements.
        // If the sum overflows, defer overflow handling to Vec::reserve.
        let mut vec = match count.checked_add(additional) {
            Some(total) => Vec::with_capacity(total),
            None => {
                let mut vec = Vec::with_capacity(count);
                vec.reserve(additional);
                vec
            }
        };

        // Extract the inline buffer only after allocation succeeds so a
        // capacity panic cannot discard already-initialized inline elements.
        let old = mem::replace(&mut self.repr, Repr::Heap(Vec::new()));
        if let Repr::Inline { buf, len } = old {
            debug_assert_eq!(len as usize, count);
            // SAFETY: buf[0..count] are initialized per the inline invariant.
            // MaybeUninit<T> has the same layout as T. vec has at least count
            // spare slots by construction.
            unsafe {
                std::ptr::copy_nonoverlapping(buf.as_ptr().cast::<T>(), vec.as_mut_ptr(), count);
                vec.set_len(count);
            }
        }

        self.repr = Repr::Heap(vec);
    }

    #[cold]
    #[inline(never)]
    fn spill_and_push(&mut self, value: T) {
        self.spill_inline_to_heap_with_additional(1);
        match &mut self.repr {
            Repr::Heap(v) => v.push(value),
            Repr::Inline { .. } => unreachable!("spill path must leave InlineVec in heap mode"),
        }
    }

    /// Returns whether `additional` elements can be appended inline.
    ///
    /// Uses subtraction-based capacity math to avoid any `len + additional`
    /// overflow while preserving the original fit semantics.
    #[inline]
    fn inline_extend_fits(len: usize, additional: usize) -> bool {
        len <= N && additional <= N - len
    }

    /// Appends all elements from a slice by cloning each one.
    ///
    /// If the combined length exceeds inline capacity, spills to heap.
    ///
    /// # Fast path (inline, all elements fit)
    ///
    /// When all cloned elements fit in the remaining inline capacity, the
    /// guard check fires once and the loop writes directly into `buf` —
    /// avoiding per-element `match` dispatch and repeated capacity checks
    /// that `push` would perform.
    ///
    /// # Panic safety
    ///
    /// `len` is incremented after each successful `clone()` + write, not
    /// after the whole loop. This ensures that if `T::clone()` panics
    /// mid-iteration, `InlineVec::drop` sees the correct count and drops
    /// only the already-written elements. No elements are leaked.
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Clone,
    {
        if let Repr::Inline { buf, len } = &mut self.repr
            && Self::inline_extend_fits(*len as usize, slice.len())
        {
            let start = *len as usize;
            for (i, item) in slice.iter().enumerate() {
                // SAFETY: start + i < start + slice.len() <= N, so
                // buf[start + i] is in bounds. The slot is uninitialized
                // (past the last initialized slot). We write a valid T
                // then immediately increment len for panic safety (see
                // function-level doc).
                unsafe { buf.get_unchecked_mut(start + i).write(item.clone()) };
                *len += 1;
            }
            return;
        }

        match &mut self.repr {
            Repr::Heap(v) => {
                // Reserve once, then clone-extend in bulk.
                v.reserve(slice.len());
                v.extend_from_slice(slice);
            }
            Repr::Inline { .. } => {
                // Crossing the inline boundary: spill once with enough room,
                // then bulk clone into the heap representation.
                self.spill_inline_to_heap_with_additional(slice.len());
                match &mut self.repr {
                    Repr::Heap(v) => v.extend_from_slice(slice),
                    Repr::Inline { .. } => {
                        unreachable!("spill path must leave InlineVec in heap mode")
                    }
                }
            }
        }
    }

    /// Returns a slice view of all elements.
    ///
    /// For the inline path, this constructs a slice from the
    /// `MaybeUninit` buffer. For the heap path, delegates to `Vec::as_slice`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        match &self.repr {
            Repr::Inline { buf, len } => {
                let len = *len as usize;
                // SAFETY: buf[0..len] are all initialized per the inline
                // invariant. MaybeUninit<T> has the same layout as T, and
                // the buffer is contiguous, so from_raw_parts on the cast
                // pointer is valid for len elements.
                unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<T>(), len) }
            }
            Repr::Heap(v) => v.as_slice(),
        }
    }

    /// Returns an iterator over references to the elements.
    ///
    /// Delegates to `as_slice().iter()`.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.as_slice().iter()
    }

    /// Constructs an `InlineVec` from a slice of `Copy` types.
    ///
    /// If the slice fits in `N` slots, stores inline via bulk
    /// `copy_nonoverlapping` (a single `memcpy`). Otherwise, delegates to
    /// `slice.to_vec()` for a heap allocation.
    ///
    /// Requires `T: Copy` (not just `Clone`) because the inline path uses
    /// a raw pointer copy. `Copy` guarantees bitwise duplication is
    /// semantically correct and there is no `Drop` glue to run, so no
    /// panic-safety bookkeeping is needed.
    ///
    /// Evaluates `VALIDATED_CAP` to trigger the compile-time assertion that
    /// `N` is in range.
    #[inline]
    pub fn from_slice(slice: &[T]) -> Self
    where
        T: Copy,
    {
        let _ = Self::VALIDATED_CAP;
        if slice.len() <= N {
            let mut buf = uninit_array::<T, N>();
            // SAFETY: slice.len() <= N, so the copy stays within buf bounds.
            // MaybeUninit<T> has the same layout as T, so the cast is valid.
            // All copied slots become initialized.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    slice.as_ptr(),
                    buf.as_mut_ptr().cast::<T>(),
                    slice.len(),
                );
            }
            Self {
                repr: Repr::Inline {
                    buf,
                    len: slice.len() as u32,
                },
            }
        } else {
            Self {
                repr: Repr::Heap(slice.to_vec()),
            }
        }
    }
}

/// Create an uninitialized `[MaybeUninit<T>; N]` without running any constructors.
fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized MaybeUninit<T> is valid by definition.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

// ============================================================================
// Trait impls
// ============================================================================

impl<T, const N: usize> Default for InlineVec<T, N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for InlineVec<T, N> {
    fn drop(&mut self) {
        match &mut self.repr {
            Repr::Inline { buf, len } => {
                let count = *len as usize;
                // Drop initialized elements in order.
                for i in 0..count {
                    // SAFETY: i < len, so buf[i] is initialized.
                    unsafe { buf.get_unchecked_mut(i).assume_init_drop() };
                }
            }
            Repr::Heap(_) => {
                // Vec's own Drop handles cleanup.
            }
        }
    }
}

impl<T: Clone, const N: usize> Clone for InlineVec<T, N> {
    /// Clones all elements into a new `InlineVec` with the same representation.
    ///
    /// # Panic safety
    ///
    /// Uses push-based construction so that `InlineVec::drop` runs on the
    /// partially-built clone if `T::clone()` panics. All successfully cloned
    /// elements are dropped; nothing is leaked.
    #[inline]
    fn clone(&self) -> Self {
        match &self.repr {
            Repr::Inline { buf, len } => {
                let count = *len as usize;
                let mut cloned = Self::new();
                for i in 0..count {
                    // SAFETY: i < len, so buf[i] is initialized.
                    let val = unsafe { buf.get_unchecked(i).assume_init_ref() };
                    cloned.push(val.clone());
                }
                cloned
            }
            Repr::Heap(v) => Self {
                repr: Repr::Heap(v.clone()),
            },
        }
    }
}

impl<T: std::fmt::Debug, const N: usize> std::fmt::Debug for InlineVec<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl<T: PartialEq, const N: usize> PartialEq for InlineVec<T, N> {
    /// Compares by element content only. The internal representation (inline
    /// vs heap) is irrelevant — two `InlineVec`s are equal iff their elements
    /// are equal in the same order, regardless of whether either has spilled.
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq, const N: usize> Eq for InlineVec<T, N> {}

impl<T, const N: usize> From<Vec<T>> for InlineVec<T, N> {
    /// Converts from a `Vec<T>`, moving elements inline if they fit.
    ///
    /// When `v.len() <= N`, elements are moved out via `into_iter()` which
    /// consumes the `Vec` and its heap allocation (the allocator frees it).
    /// When `v.len() > N`, the `Vec` is adopted directly with no reallocation.
    ///
    /// Uses `into_iter()` rather than `ptr::copy_nonoverlapping` because `T`
    /// is not required to be `Copy`. The iterator yields owned values one at
    /// a time, transferring ownership without cloning.
    ///
    /// Evaluates `VALIDATED_CAP` to trigger the compile-time assertion that
    /// `N` is in range.
    #[inline]
    fn from(v: Vec<T>) -> Self {
        let _ = Self::VALIDATED_CAP;
        if v.len() <= N {
            let mut buf = uninit_array::<T, N>();
            let len = v.len() as u32;
            // Move elements out of the Vec without dropping them via Vec.
            // We use into_iter() which yields owned T values.
            for (i, item) in v.into_iter().enumerate() {
                // SAFETY: i < original len <= N, so buf[i] is in bounds.
                unsafe { buf.get_unchecked_mut(i).write(item) };
            }
            Self {
                repr: Repr::Inline { buf, len },
            }
        } else {
            Self {
                repr: Repr::Heap(v),
            }
        }
    }
}

impl<T, const N: usize> FromIterator<T> for InlineVec<T, N> {
    /// Collects an iterator into an `InlineVec`.
    ///
    /// Uses `size_hint()` to decide the strategy up front:
    ///
    /// - **lower bound > N**: the iterator guarantees more elements than
    ///   inline capacity, so we skip inline entirely and delegate to
    ///   a heap `Vec`. In this heap path, we preallocate from the upper
    ///   bound when available (falling back to the lower bound otherwise)
    ///   to reduce growth churn during collection. This may over-allocate
    ///   when an iterator reports a loose upper bound.
    ///
    /// - **lower bound <= N**: we push element-by-element. If the actual
    ///   count stays within N, everything remains inline. If it exceeds N,
    ///   the normal `push` spill path handles the transition.
    ///
    /// Iterators that underestimate (e.g., `size_hint().0 == 0`) still
    /// land inline when the true count fits, because `push` stays inline
    /// until N is exceeded.
    #[inline]
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let (lower, upper) = iter.size_hint();
        if lower > N {
            let prealloc = upper.unwrap_or(lower).max(lower);
            let mut heap = Vec::with_capacity(prealloc);
            heap.extend(iter);
            return Self {
                repr: Repr::Heap(heap),
            };
        }
        let mut v = Self::new();
        for item in iter {
            v.push(item);
        }
        v
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a InlineVec<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// Compile-time proof that InlineVec inherits Send/Sync from T.
#[allow(dead_code)]
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn check<T: Send + Sync>() {
        assert_send::<InlineVec<T, 1>>();
        assert_sync::<InlineVec<T, 1>>();
    }
};

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
    // Basic operations
    // -----------------------------------------------------------------------

    #[test]
    fn new_is_empty() {
        let v = InlineVec::<u32, 8>::new();
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
        assert_eq!(v.as_slice(), &[]);
    }

    #[test]
    fn push_and_as_slice() {
        let mut v = InlineVec::<u32, 4>::new();
        v.push(10);
        v.push(20);
        v.push(30);
        assert_eq!(v.len(), 3);
        assert_eq!(v.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn push_exactly_n() {
        let mut v = InlineVec::<u32, 4>::new();
        for i in 0..4 {
            v.push(i);
        }
        assert_eq!(v.len(), 4);
        assert_eq!(v.as_slice(), &[0, 1, 2, 3]);
        // Should still be inline.
        assert!(matches!(v.repr, Repr::Inline { .. }));
    }

    #[test]
    fn push_spills_at_n_plus_1() {
        let mut v = InlineVec::<u32, 4>::new();
        for i in 0..5 {
            v.push(i);
        }
        assert_eq!(v.len(), 5);
        assert_eq!(v.as_slice(), &[0, 1, 2, 3, 4]);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    #[test]
    fn extend_from_slice_inline() {
        let mut v = InlineVec::<u32, 8>::new();
        v.extend_from_slice(&[1, 2, 3]);
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert!(matches!(v.repr, Repr::Inline { .. }));
    }

    #[test]
    fn extend_from_slice_spills() {
        let mut v = InlineVec::<u32, 2>::new();
        v.push(1);
        v.extend_from_slice(&[2, 3, 4]);
        assert_eq!(v.as_slice(), &[1, 2, 3, 4]);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    #[test]
    fn extend_from_slice_inline_guard_exact_remaining_capacity() {
        assert!(InlineVec::<u32, 8>::inline_extend_fits(5, 3));
        assert!(!InlineVec::<u32, 8>::inline_extend_fits(5, 4));
    }

    #[test]
    fn extend_from_slice_inline_guard_rejects_overflowing_addition() {
        assert!(!InlineVec::<u32, 8>::inline_extend_fits(1, usize::MAX));
        assert!(!InlineVec::<u32, 8>::inline_extend_fits(9, 0));
    }

    #[test]
    fn iter_delegates_to_slice() {
        let mut v = InlineVec::<u32, 4>::new();
        v.push(10);
        v.push(20);
        v.push(30);
        let collected: Vec<_> = v.iter().copied().collect();
        assert_eq!(collected, vec![10, 20, 30]);
    }

    #[test]
    fn from_slice_inline() {
        let v = InlineVec::<u32, 4>::from_slice(&[1, 2, 3]);
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert!(matches!(v.repr, Repr::Inline { .. }));
    }

    #[test]
    fn from_slice_exactly_n() {
        let v = InlineVec::<u32, 4>::from_slice(&[1, 2, 3, 4]);
        assert_eq!(v.as_slice(), &[1, 2, 3, 4]);
        assert!(matches!(v.repr, Repr::Inline { .. }));
    }

    #[test]
    fn from_slice_spills() {
        let v = InlineVec::<u32, 2>::from_slice(&[1, 2, 3]);
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    #[test]
    fn from_vec_inline() {
        let v: InlineVec<u32, 4> = vec![1, 2, 3].into();
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert!(matches!(v.repr, Repr::Inline { .. }));
    }

    #[test]
    fn from_vec_spills() {
        let v: InlineVec<u32, 2> = vec![1, 2, 3].into();
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    #[test]
    fn from_iter_basic() {
        let v: InlineVec<u32, 4> = (0..3).collect();
        assert_eq!(v.as_slice(), &[0, 1, 2]);
    }

    #[test]
    fn for_in_reference() {
        let mut v = InlineVec::<u32, 4>::new();
        v.push(1);
        v.push(2);
        v.push(3);
        let mut sum = 0;
        for &val in &v {
            sum += val;
        }
        assert_eq!(sum, 6);
    }

    #[test]
    fn extend_empty_slice_is_noop() {
        let mut v = InlineVec::<u32, 4>::new();
        v.push(1);
        v.extend_from_slice(&[]);
        assert_eq!(v.as_slice(), &[1]);
    }

    // -----------------------------------------------------------------------
    // Drop tracking
    // -----------------------------------------------------------------------

    #[test]
    fn drop_inline_elements() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut v = InlineVec::<DropTracker, 4>::new();
            v.push(dt(&drops));
            v.push(dt(&drops));
            v.push(dt(&drops));
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn drop_heap_elements() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut v = InlineVec::<DropTracker, 2>::new();
            v.push(dt(&drops));
            v.push(dt(&drops));
            v.push(dt(&drops)); // spills
        }
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn drop_empty_is_noop() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let _v = InlineVec::<DropTracker, 4>::new();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn spill_does_not_double_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut v = InlineVec::<DropTracker, 2>::new();
            v.push(dt(&drops));
            v.push(dt(&drops));
            // At this point, 2 elements inline, 0 drops.
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            // Spill: moves 2 inline elements to Vec, pushes 3rd.
            v.push(dt(&drops));
            // After spill: still 0 drops (elements were moved, not dropped).
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
        // All 3 dropped on InlineVec drop.
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    // -----------------------------------------------------------------------
    // Clone
    // -----------------------------------------------------------------------

    #[test]
    fn clone_inline() {
        let mut v = InlineVec::<u32, 4>::new();
        v.push(1);
        v.push(2);
        let cloned = v.clone();
        assert_eq!(v, cloned);
        assert!(matches!(cloned.repr, Repr::Inline { .. }));
    }

    #[test]
    fn clone_heap() {
        let mut v = InlineVec::<u32, 2>::new();
        v.push(1);
        v.push(2);
        v.push(3); // spill
        let cloned = v.clone();
        assert_eq!(v, cloned);
        assert!(matches!(cloned.repr, Repr::Heap(_)));
    }

    #[test]
    fn clone_drops_independently() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut v = InlineVec::<DropTracker, 4>::new();
            v.push(dt(&drops));
            v.push(dt(&drops));
            {
                let _cloned = v.clone();
            }
            // Cloned's 2 elements dropped.
            assert_eq!(drops.load(Ordering::Relaxed), 2);
        }
        // Original's 2 elements dropped.
        assert_eq!(drops.load(Ordering::Relaxed), 4);
    }

    // -----------------------------------------------------------------------
    // Equality
    // -----------------------------------------------------------------------

    #[test]
    fn eq_same_content_same_repr() {
        let mut a = InlineVec::<u32, 4>::new();
        let mut b = InlineVec::<u32, 4>::new();
        a.push(1);
        a.push(2);
        b.push(1);
        b.push(2);
        assert_eq!(a, b);
    }

    #[test]
    fn eq_same_content_different_repr() {
        // Both values are inline here; equality is content-based regardless
        // of representation.
        let a = InlineVec::<u32, 4>::from_slice(&[1, 2, 3]);
        let b: InlineVec<u32, 4> = vec![1, 2, 3, 4, 5]
            .into_iter()
            .take(3)
            .collect::<Vec<_>>()
            .into();
        // b was built from a 3-element vec, so it also fits inline.
        assert_eq!(a, b);
    }

    #[test]
    fn ne_different_content() {
        let mut a = InlineVec::<u32, 4>::new();
        let mut b = InlineVec::<u32, 4>::new();
        a.push(1);
        b.push(2);
        assert_ne!(a, b);
    }

    #[test]
    fn ne_different_length() {
        let mut a = InlineVec::<u32, 4>::new();
        let b = InlineVec::<u32, 4>::new();
        a.push(1);
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Edge cases: N=1
    // -----------------------------------------------------------------------

    #[test]
    fn n1_push_one_stays_inline() {
        let mut v = InlineVec::<u32, 1>::new();
        v.push(42);
        assert_eq!(v.as_slice(), &[42]);
        assert!(matches!(v.repr, Repr::Inline { .. }));
    }

    #[test]
    fn n1_push_two_spills() {
        let mut v = InlineVec::<u32, 1>::new();
        v.push(1);
        v.push(2);
        assert_eq!(v.as_slice(), &[1, 2]);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    #[test]
    fn n1_drop_tracking() {
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let mut v = InlineVec::<DropTracker, 1>::new();
            v.push(dt(&drops));
            // Spill to heap.
            v.push(dt(&drops));
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    // -----------------------------------------------------------------------
    // Debug format
    // -----------------------------------------------------------------------

    #[test]
    fn debug_format() {
        let mut v = InlineVec::<u32, 4>::new();
        v.push(1);
        v.push(2);
        v.push(3);
        assert_eq!(format!("{v:?}"), "[1, 2, 3]");
    }

    // -----------------------------------------------------------------------
    // ZST, clone-panic, from_iter spill, large N
    // -----------------------------------------------------------------------

    #[test]
    fn zst_inline_and_spill() {
        let mut v = InlineVec::<(), 4>::new();
        for _ in 0..4 {
            v.push(());
        }
        assert_eq!(v.len(), 4);
        assert!(matches!(v.repr, Repr::Inline { .. }));
        v.push(());
        assert_eq!(v.len(), 5);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    #[test]
    fn clone_panic_does_not_cause_ub() {
        use std::cell::Cell;
        use std::panic;

        thread_local! { static COUNT: Cell<usize> = const { Cell::new(0) }; }

        #[derive(Debug)]
        struct PanicOnThird(u32);
        impl Clone for PanicOnThird {
            fn clone(&self) -> Self {
                COUNT.with(|c| {
                    let n = c.get() + 1;
                    c.set(n);
                    if n == 3 {
                        panic!("deliberate clone panic");
                    }
                });
                PanicOnThird(self.0)
            }
        }

        let mut v = InlineVec::<PanicOnThird, 4>::new();
        v.push(PanicOnThird(1));
        v.push(PanicOnThird(2));
        v.push(PanicOnThird(3));

        COUNT.with(|c| c.set(0));
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| v.clone()));
        assert!(result.is_err()); // panicked — no UB, partial clones dropped during unwinding
    }

    /// Verify that partial clones are properly dropped when T::clone() panics.
    ///
    /// Creates 3 elements with drop tracking and a clone that panics on the
    /// 3rd call. After the panic, the 2 successfully cloned elements should
    /// be cleaned up (not leaked).
    #[test]
    fn clone_panic_drops_partial_clones() {
        use std::cell::Cell;
        use std::panic;

        thread_local! { static CLONE_CTR: Cell<usize> = const { Cell::new(0) }; }

        #[derive(Debug)]
        struct TrackDrop {
            drops: Arc<AtomicUsize>,
        }
        impl Clone for TrackDrop {
            fn clone(&self) -> Self {
                CLONE_CTR.with(|c| {
                    let n = c.get() + 1;
                    c.set(n);
                    if n == 3 {
                        panic!("deliberate clone panic at element 3");
                    }
                });
                TrackDrop {
                    drops: self.drops.clone(),
                }
            }
        }
        impl Drop for TrackDrop {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let mut v = InlineVec::<TrackDrop, 4>::new();
        v.push(TrackDrop {
            drops: drops.clone(),
        });
        v.push(TrackDrop {
            drops: drops.clone(),
        });
        v.push(TrackDrop {
            drops: drops.clone(),
        });

        CLONE_CTR.with(|c| c.set(0));
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| v.clone()));
        assert!(result.is_err());

        // The 2 successfully cloned elements should be dropped by the guard.
        // (Original 3 elements are still alive in `v`.)
        let partial_drops = drops.load(Ordering::Relaxed);
        assert_eq!(
            partial_drops, 2,
            "partial clones should be dropped on panic, not leaked"
        );
    }

    /// Verify that extend_from_slice tracks partial clones when T::clone() panics.
    ///
    /// Starts with 1 element, extends with a 3-element slice where the 2nd
    /// clone panics. After the panic, `v` survives (via `catch_unwind`).
    /// The successfully cloned element should be tracked in `len` so that
    /// dropping `v` cleans it up — no leak.
    #[test]
    fn extend_from_slice_panic_drops_partial_clones() {
        use std::cell::Cell;
        use std::panic;

        thread_local! { static EXT_CTR: Cell<usize> = const { Cell::new(0) }; }

        #[derive(Debug)]
        struct TrackDropExt {
            drops: Arc<AtomicUsize>,
        }
        impl Clone for TrackDropExt {
            fn clone(&self) -> Self {
                EXT_CTR.with(|c| {
                    let n = c.get() + 1;
                    c.set(n);
                    if n == 2 {
                        panic!("deliberate clone panic in extend_from_slice");
                    }
                });
                TrackDropExt {
                    drops: self.drops.clone(),
                }
            }
        }
        impl Drop for TrackDropExt {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let mut v = InlineVec::<TrackDropExt, 8>::new();
        v.push(TrackDropExt {
            drops: drops.clone(),
        });

        let source = [
            TrackDropExt {
                drops: drops.clone(),
            },
            TrackDropExt {
                drops: drops.clone(),
            },
            TrackDropExt {
                drops: drops.clone(),
            },
        ];

        EXT_CTR.with(|c| c.set(0));
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            v.extend_from_slice(&source);
        }));

        // Drop source (3 elements).
        drop(source);
        let after_source = drops.load(Ordering::Relaxed);
        assert_eq!(after_source, 3);

        // Drop v. With the fix, v has 2 elements (1 original + 1 clone) → 2 drops.
        // Without the fix, v has 1 element (clone leaked) → 1 drop.
        drop(v);
        let total = drops.load(Ordering::Relaxed);
        assert_eq!(
            total, 5,
            "v should drop original + successfully cloned element (no leak)"
        );
    }

    /// Verify that FromIterator stays inline when size_hint underestimates.
    #[test]
    fn from_iter_underestimate_stays_inline() {
        struct BadHint(std::vec::IntoIter<u32>);
        impl Iterator for BadHint {
            type Item = u32;
            fn next(&mut self) -> Option<u32> {
                self.0.next()
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                (0, None)
            }
        }

        let v: InlineVec<u32, 4> = BadHint(vec![10, 20, 30].into_iter()).collect();
        assert_eq!(v.as_slice(), &[10, 20, 30]);
        assert!(
            matches!(v.repr, Repr::Inline { .. }),
            "should stay inline despite underestimate"
        );
    }

    #[test]
    fn from_iter_heap_uses_upper_bound_preallocation() {
        struct WideUpperHint(std::vec::IntoIter<u32>);
        impl Iterator for WideUpperHint {
            type Item = u32;
            fn next(&mut self) -> Option<u32> {
                self.0.next()
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                (5, Some(64))
            }
        }

        let v: InlineVec<u32, 4> = WideUpperHint(vec![1, 2, 3, 4, 5].into_iter()).collect();
        assert_eq!(v.as_slice(), &[1, 2, 3, 4, 5]);
        match &v.repr {
            Repr::Heap(heap) => assert!(
                heap.capacity() >= 64,
                "heap path should preallocate using size_hint upper bound"
            ),
            Repr::Inline { .. } => {
                panic!("should use heap path when size_hint lower bound exceeds inline capacity")
            }
        }
    }

    #[test]
    fn from_iter_spills() {
        let v: InlineVec<u32, 2> = (0..5).collect();
        assert_eq!(v.as_slice(), &[0, 1, 2, 3, 4]);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    #[test]
    fn large_n_basic() {
        let mut v = InlineVec::<u32, 64>::new();
        for i in 0..64 {
            v.push(i);
        }
        assert_eq!(v.len(), 64);
        assert!(matches!(v.repr, Repr::Inline { .. }));
        v.push(64);
        assert_eq!(v.len(), 65);
        assert!(matches!(v.repr, Repr::Heap(_)));
    }

    // -----------------------------------------------------------------------
    // Property tests (Vec oracle)
    // -----------------------------------------------------------------------

    /// Returns a [`proptest::test_runner::Config`] tuned for the current environment.
    ///
    /// Under Miri, disables file-based failure persistence and reduces cases
    /// from the proptest default of 256 to 32.
    fn miri_proptest_config() -> proptest::test_runner::Config {
        if cfg!(miri) {
            proptest::test_runner::Config {
                failure_persistence: None,
                cases: 32,
                ..Default::default()
            }
        } else {
            proptest::test_runner::Config::default()
        }
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(super::miri_proptest_config())]

            /// State machine: random Push/ExtendFromSlice/Clone/AsSlice/FromVec/FromSlice
            /// ops, assert InlineVec matches Vec after every operation.
            #[test]
            fn state_machine_oracle(
                ops in proptest::collection::vec(
                    prop_oneof![
                        (0u32..1000).prop_map(|v| (0u8, v, vec![])),   // Push
                        proptest::collection::vec(0u32..1000, 0..8)
                            .prop_map(|vs| (1u8, 0, vs)),              // ExtendFromSlice
                        Just((2u8, 0u32, vec![])),                      // Clone
                        Just((3u8, 0u32, vec![])),                      // AsSlice
                        proptest::collection::vec(0u32..1000, 0..8)
                            .prop_map(|vs| (4u8, 0, vs)),              // FromVec
                        proptest::collection::vec(0u32..1000, 0..8)
                            .prop_map(|vs| (5u8, 0, vs)),              // FromSlice
                    ],
                    0..200,
                )
            ) {
                let mut iv = InlineVec::<u32, 4>::new();
                let mut model = Vec::new();

                for (op, val, vals) in &ops {
                    match op {
                        0 => {
                            // Push
                            iv.push(*val);
                            model.push(*val);
                        }
                        1 => {
                            // ExtendFromSlice
                            iv.extend_from_slice(vals);
                            model.extend_from_slice(vals);
                        }
                        2 => {
                            // Clone
                            let cloned = iv.clone();
                            prop_assert_eq!(cloned.as_slice(), model.as_slice());
                        }
                        3 => {
                            // AsSlice
                            prop_assert_eq!(iv.as_slice(), model.as_slice());
                        }
                        4 => {
                            // FromVec: construct a fresh InlineVec from Vec, verify it
                            let fresh: InlineVec<u32, 4> = vals.clone().into();
                            prop_assert_eq!(fresh.as_slice(), vals.as_slice());
                        }
                        5 => {
                            // FromSlice: construct a fresh InlineVec from slice, verify it
                            let fresh = InlineVec::<u32, 4>::from_slice(vals);
                            prop_assert_eq!(fresh.as_slice(), vals.as_slice());
                        }
                        _ => unreachable!(),
                    }

                    // After every operation: length and contents must match.
                    prop_assert_eq!(iv.len(), model.len());
                    prop_assert_eq!(iv.as_slice(), model.as_slice());
                }
            }
        }
    }
}

// ============================================================================
// Kani formal verification proofs
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    //! Kani formal verification proofs for `InlineVec`.
    //!
    //! Each proof targets one unsafe operation or invariant, verifying it
    //! holds for all valid inputs (symbolic, not sampled). Together they
    //! cover 8 of the 9 `unsafe` blocks in `InlineVec`; the remaining
    //! block in `extend_from_slice` uses analogous bounds reasoning to
    //! `push` but is not independently proven.
    //!
    //! Proofs use `CAP = 4` and bounded unwind depths; Kani explores all
    //! reachable states within those bounds exhaustively.
    //!
    //! Coverage:
    //! - Proofs 1, 2, 9: `push` and `spill_and_push` (write bounds, spill
    //!   correctness, element preservation across the inline-to-heap transition)
    //! - Proof 3: `as_slice` (only initialized slots are exposed)
    //! - Proof 4: `drop` (visits exactly `len` elements, no over-read)
    //! - Proof 5: `clone` (reads/writes stay within initialized region)
    //! - Proof 6: `from_slice` (bulk memcpy stays in bounds)
    //! - Proof 7: `From<Vec>` (per-element move stays in bounds)
    //! - Proof 8: `uninit_array` (trivially sound for sized and ZST types)

    use super::*;

    // Verifies that `push` never writes past the inline buffer.
    // Symbolic `n` in [0, CAP] covers all fill levels.
    #[kani::proof]
    #[kani::unwind(7)]
    fn push_within_capacity_is_safe() {
        const CAP: usize = 4;
        let mut v = InlineVec::<u32, CAP>::new();
        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for _ in 0..n {
            v.push(kani::any());
        }
        assert_eq!(v.len(), n);
    }

    // Verifies that `spill_and_push` reads only the initialized portion
    // of the inline buffer during the bulk `copy_nonoverlapping`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn spill_reads_only_initialized() {
        const CAP: usize = 4;
        let mut v = InlineVec::<u32, CAP>::new();
        for _ in 0..CAP {
            v.push(kani::any());
        }
        v.push(kani::any());
        assert_eq!(v.len(), CAP + 1);
        assert!(matches!(&v.repr, Repr::Heap(_)));
    }

    // Verifies that `as_slice` returns a slice whose length matches the
    // initialized count and whose elements are all dereferenceable.
    #[kani::proof]
    #[kani::unwind(7)]
    fn as_slice_covers_initialized_only() {
        const CAP: usize = 4;
        let mut v = InlineVec::<u32, CAP>::new();
        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for _ in 0..n {
            v.push(kani::any());
        }
        let s = v.as_slice();
        assert_eq!(s.len(), n);
        if n > 0 {
            let idx: usize = kani::any();
            kani::assume(idx < n);
            let _ = s[idx]; // Kani verifies this dereference is valid
        }
    }

    // Verifies that `Drop` visits exactly `len` elements — no fewer
    // (leak) and no more (reading uninitialized memory).
    #[kani::proof]
    #[kani::unwind(7)]
    fn drop_visits_correct_count() {
        const CAP: usize = 4;
        let mut v = InlineVec::<u32, CAP>::new();
        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for _ in 0..n {
            v.push(kani::any());
        }
        assert_eq!(v.len(), n);
        drop(v); // Kani verifies all assume_init_drop calls are in-bounds
    }

    // Verifies that the push-based `clone` only reads initialized source
    // slots and writes within the destination's inline capacity.
    #[kani::proof]
    #[kani::unwind(7)]
    fn clone_inline_is_sound() {
        const CAP: usize = 4;
        let mut v = InlineVec::<u32, CAP>::new();
        let n: usize = kani::any();
        kani::assume(n <= CAP);
        for _ in 0..n {
            v.push(kani::any());
        }
        let cloned = v.clone();
        assert_eq!(cloned.len(), v.len());
        assert_eq!(cloned.as_slice(), v.as_slice());
    }

    // Verifies that `from_slice`'s bulk `copy_nonoverlapping` never
    // reads past the source slice or writes past the inline buffer.
    #[kani::proof]
    #[kani::unwind(6)]
    fn from_slice_bounds_are_sound() {
        const CAP: usize = 4;
        let backing: [u32; 4] = [kani::any(), kani::any(), kani::any(), kani::any()];
        let len: usize = kani::any();
        kani::assume(len <= CAP);
        let v = InlineVec::<u32, CAP>::from_slice(&backing[..len]);
        assert_eq!(v.len(), len);
        assert_eq!(v.as_slice(), &backing[..len]);
    }

    // Verifies that `From<Vec>` writes each element within the inline
    // buffer and preserves element values after the move.
    #[kani::proof]
    #[kani::unwind(6)]
    fn from_vec_inline_is_sound() {
        const CAP: usize = 4;
        let len: usize = kani::any();
        kani::assume(len <= CAP);
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(kani::any::<u32>());
        }
        let snapshot: Vec<u32> = vec.clone();
        let v: InlineVec<u32, CAP> = vec.into();
        assert_eq!(v.len(), len);
        assert!(matches!(&v.repr, Repr::Inline { .. }));
        for i in 0..len {
            assert_eq!(v.as_slice()[i], snapshot[i]);
        }
    }

    // Verifies that `uninit_array` produces a valid array for both
    // sized types and ZSTs (no panic, no UB).
    #[kani::proof]
    fn uninit_array_is_valid() {
        let _arr = uninit_array::<u32, 4>();
        let _arr_zst = uninit_array::<(), 4>();
        // MaybeUninit<T> is valid uninitialized by definition.
        // Kani verifies no panic or UB.
    }

    // Verifies that spilling preserves all elements in their original
    // order. Uses concrete symbolic values so Kani can check each
    // position independently.
    #[kani::proof]
    #[kani::unwind(8)]
    fn spill_conserves_elements() {
        const CAP: usize = 4;
        let mut v = InlineVec::<u32, CAP>::new();
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        let c: u32 = kani::any();
        let d: u32 = kani::any();
        let e: u32 = kani::any();
        v.push(a);
        v.push(b);
        v.push(c);
        v.push(d);
        assert_eq!(v.as_slice(), &[a, b, c, d]);
        v.push(e); // spill
        assert_eq!(v.as_slice(), &[a, b, c, d, e]);
    }
}
