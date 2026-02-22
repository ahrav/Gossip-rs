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
//! This type is not synchronized; it assumes single-threaded usage.

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
    pub fn push(&mut self, value: T) {
        match &mut self.repr {
            Repr::Inline { len, .. } if (*len as usize) < N => {
                let idx = *len as usize;
                // SAFETY: idx < N, so buf[idx] is in bounds. The slot is
                // uninitialized (idx == len, which is past the last initialized
                // slot). We write a valid T into it and increment len to
                // maintain the invariant that slots 0..len are initialized.
                //
                // Re-match rationale: the outer `match` borrows `self.repr`
                // immutably (the guard reads `len`). We need a *mutable*
                // borrow of `buf` and `len` to write, so we re-match inside
                // the arm to start a fresh mutable borrow.
                if let Repr::Inline { buf, len } = &mut self.repr {
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

    /// Cold path: move inline elements to a Vec and push the new value.
    #[cold]
    #[inline(never)]
    fn spill_and_push(&mut self, value: T) {
        // Extract the old Repr via mem::replace. The replacement is a
        // dummy Heap(empty vec) that will be overwritten immediately.
        // Repr has no Drop, so no double-free occurs.
        let old = mem::replace(
            &mut self.repr,
            Repr::Heap(Vec::new()), // temporary placeholder
        );

        let mut vec = Vec::with_capacity(N + 1);

        if let Repr::Inline { buf, len } = old {
            for i in 0..len as usize {
                // SAFETY: i < len, so buf[i] is initialized per the
                // inline invariant. We read each element exactly once
                // (consuming it) and push it into the Vec. The old Repr
                // has no Drop, so the now-uninitialized slots are never
                // double-freed.
                let elem = unsafe { buf.get_unchecked(i).assume_init_read() };
                vec.push(elem);
            }
            // buf (array of MaybeUninit) is dropped here. MaybeUninit's
            // drop is a no-op, so the moved-from slots are safe.
        }

        vec.push(value);
        self.repr = Repr::Heap(vec);
    }

    /// Appends all elements from a slice by cloning each one individually.
    ///
    /// If the combined length exceeds inline capacity, spills to heap.
    /// Runs in O(n) time where n is `slice.len()`. Each element is cloned
    /// via `T::clone()` and pushed one at a time; there is no bulk `memcpy`
    /// optimization even for `Copy` types.
    pub fn extend_from_slice(&mut self, slice: &[T])
    where
        T: Clone,
    {
        for item in slice {
            self.push(item.clone());
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

    /// Constructs an `InlineVec` from a slice.
    ///
    /// If the slice fits in `N` slots, stores inline. Otherwise, copies
    /// to a heap `Vec`.
    pub fn from_slice(slice: &[T]) -> Self
    where
        T: Copy,
    {
        if slice.len() <= N {
            let mut buf = uninit_array::<T, N>();
            for (i, item) in slice.iter().enumerate() {
                // SAFETY: i < slice.len() <= N, so buf[i] is in bounds.
                unsafe { buf.get_unchecked_mut(i).write(*item) };
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
    /// If `T::clone()` panics while cloning the inline path, the partially
    /// constructed `new_buf` is dropped. Because `new_buf` is
    /// `[MaybeUninit<T>; N]` (which has no `Drop` glue), the already-written
    /// slots are leaked rather than double-freed. This is safe — it does not
    /// violate memory safety — though it does mean a panic mid-clone can leak
    /// the already-cloned elements.
    fn clone(&self) -> Self {
        match &self.repr {
            Repr::Inline { buf, len } => {
                let count = *len as usize;
                let mut new_buf = uninit_array::<T, N>();
                for i in 0..count {
                    // SAFETY: i < len, so buf[i] is initialized.
                    let val = unsafe { buf.get_unchecked(i).assume_init_ref() };
                    // SAFETY: i < N, so new_buf[i] is in bounds.
                    unsafe { new_buf.get_unchecked_mut(i).write(val.clone()) };
                }
                Self {
                    repr: Repr::Inline {
                        buf: new_buf,
                        len: *len,
                    },
                }
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
    fn from(v: Vec<T>) -> Self {
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
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
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

// Compile-time proof that InlineVec is Send+Sync when T is.
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
        // a: inline, b: heap — same content should still be equal.
        let a = InlineVec::<u32, 4>::from_slice(&[1, 2, 3]);
        let b: InlineVec<u32, 4> = vec![1, 2, 3, 4, 5]
            .into_iter()
            .take(3)
            .collect::<Vec<_>>()
            .into();
        // b was built from a 3-element vec so it fits inline.
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

            /// State machine: random Push/ExtendFromSlice/Clone/AsSlice ops,
            /// assert InlineVec matches Vec after every operation.
            #[test]
            fn state_machine_oracle(
                ops in proptest::collection::vec(
                    prop_oneof![
                        (0u32..1000).prop_map(|v| (0u8, v, vec![])),   // Push
                        proptest::collection::vec(0u32..1000, 0..8)
                            .prop_map(|vs| (1u8, 0, vs)),              // ExtendFromSlice
                        Just((2u8, 0u32, vec![])),                      // Clone
                        Just((3u8, 0u32, vec![])),                      // AsSlice
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
