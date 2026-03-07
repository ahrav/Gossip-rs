use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
fn as_mut_slice_inline() {
    let mut v = InlineVec::<u32, 4>::new();
    v.push(30);
    v.push(10);
    v.push(20);
    v.as_mut_slice().sort();
    assert_eq!(v.as_slice(), &[10, 20, 30]);
}

#[test]
fn as_mut_slice_heap() {
    let mut v = InlineVec::<u32, 2>::new();
    v.push(3);
    v.push(1);
    v.push(2); // spills to heap
    assert!(matches!(v.repr, Repr::Heap(_)));
    v.as_mut_slice().sort();
    assert_eq!(v.as_slice(), &[1, 2, 3]);
}

#[test]
fn as_mut_slice_empty() {
    let mut v = InlineVec::<u32, 4>::new();
    assert_eq!(v.as_mut_slice(), &mut []);
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

    // Drop v. Correct behavior: v has 2 elements (1 original + 1 clone) → 2 drops.
    // If extend_from_slice leaks a cloned element, v would have only 1 → 1 drop.
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
