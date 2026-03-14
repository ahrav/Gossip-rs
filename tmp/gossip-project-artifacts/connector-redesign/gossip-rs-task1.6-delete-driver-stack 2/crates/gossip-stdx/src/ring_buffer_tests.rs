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
// Drop -- exercises drop with different buffer layouts.
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
// Clear -- exercises clear with different buffer layouts + reuse.
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
#[should_panic(expected = "push_back_assume_capacity called on full buffer")]
fn push_back_assume_capacity_panics_when_full() {
    let mut ring = RingBuffer::<u32, 4>::new();
    for i in 0..4 {
        ring.push_back(i).unwrap();
    }
    assert!(ring.is_full());
    // Must panic in ALL build profiles — not just debug.
    ring.push_back_assume_capacity(99);
}

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
// Capacity-1 edge case
// -----------------------------------------------------------------------

#[test]
fn capacity_one_push_pop_overwrite() {
    // N=1 where MASK=0 and head/tail always alias slot 0.
    let mut ring = RingBuffer::<u32, 1>::new();
    assert_eq!(ring.capacity(), 1);
    assert!(ring.push_back(1).is_ok());
    assert!(ring.is_full());
    assert_eq!(ring.push_back(2), Err(2));
    assert_eq!(ring.push_back_overwrite(99), Some(1));
    assert_eq!(ring.pop_front(), Some(99));
    assert!(ring.is_empty());
}

#[test]
fn capacity_one_drop_tracking() {
    let drops = Arc::new(AtomicUsize::new(0));
    {
        let mut ring = RingBuffer::<DropTracker, 1>::new();
        ring.push_back(dt(&drops)).unwrap();
        let evicted = ring.push_back_overwrite(dt(&drops));
        assert!(evicted.is_some());
        drop(evicted);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    assert_eq!(drops.load(Ordering::Relaxed), 2);
}

// -----------------------------------------------------------------------
// Clone of wrapped buffer
// -----------------------------------------------------------------------

#[test]
fn clone_wrapped_buffer() {
    let mut ring = RingBuffer::<u32, 4>::new();
    // Advance head to 2.
    ring.push_back(99).unwrap();
    ring.push_back(99).unwrap();
    ring.pop_front();
    ring.pop_front();
    // Fill 4 elements, wrapping: physical slots [2,3,0,1].
    for v in [10, 20, 30, 40] {
        ring.push_back(v).unwrap();
    }
    assert!(ring.is_full());
    let cloned = ring.clone();
    assert_eq!(ring, cloned);
    let vals: Vec<_> = cloned.iter().copied().collect();
    assert_eq!(vals, vec![10, 20, 30, 40]);
}

// -----------------------------------------------------------------------
// Drop ordering
// -----------------------------------------------------------------------

#[test]
fn drop_fifo_ordering() {
    use std::sync::Mutex;
    let order = Arc::new(Mutex::new(Vec::new()));

    #[derive(Debug)]
    struct OrderedDrop {
        id: u32,
        order: Arc<Mutex<Vec<u32>>>,
    }
    impl Drop for OrderedDrop {
        fn drop(&mut self) {
            self.order.lock().unwrap().push(self.id);
        }
    }

    {
        let mut ring = RingBuffer::<OrderedDrop, 4>::new();
        // Advance head to 2 to force wrapping.
        ring.push_back(OrderedDrop {
            id: 100,
            order: order.clone(),
        })
        .unwrap();
        ring.push_back(OrderedDrop {
            id: 101,
            order: order.clone(),
        })
        .unwrap();
        ring.pop_front();
        ring.pop_front();
        order.lock().unwrap().clear(); // Reset after warmup pops.

        // Fill 4 elements wrapping: physical [2,3,0,1], logical [10,20,30,40].
        for id in [10, 20, 30, 40] {
            ring.push_back(OrderedDrop {
                id,
                order: order.clone(),
            })
            .unwrap();
        }
    }
    // Drop should happen in FIFO (logical) order.
    assert_eq!(*order.lock().unwrap(), vec![10, 20, 30, 40]);
}

// -----------------------------------------------------------------------
// Additional iterator edge cases
// -----------------------------------------------------------------------

#[test]
fn iter_interleaved_next_next_back() {
    let mut ring = RingBuffer::<u32, 4>::new();
    for v in [10, 20, 30, 40] {
        ring.push_back(v).unwrap();
    }
    let mut iter = ring.iter();
    assert_eq!(iter.next(), Some(&10));
    assert_eq!(iter.next_back(), Some(&40));
    assert_eq!(iter.next(), Some(&20));
    assert_eq!(iter.next_back(), Some(&30));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);
}

#[test]
fn from_iter_empty() {
    let ring: RingBuffer<u32, 4> = std::iter::empty().collect();
    assert!(ring.is_empty());
    assert_eq!(ring.len(), 0);
}

// -----------------------------------------------------------------------
// Multi-cycle overwrite drop tracking
// -----------------------------------------------------------------------

#[test]
fn multi_cycle_overwrite_drops() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut ring = RingBuffer::<DropTracker, 2>::new();
    // Fill.
    ring.push_back(dt(&drops)).unwrap();
    ring.push_back(dt(&drops)).unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 0);

    // Overwrite 10 times — each evicts one.
    for _ in 0..10 {
        let evicted = ring.push_back_overwrite(dt(&drops));
        drop(evicted);
    }
    // 10 evictions dropped + 0 still alive = 10.
    assert_eq!(drops.load(Ordering::Relaxed), 10);
    drop(ring);
    // 10 evicted + 2 remaining = 12.
    assert_eq!(drops.load(Ordering::Relaxed), 12);
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
// IntoIter (consuming)
// -----------------------------------------------------------------------

#[test]
fn into_iter_empty() {
    let ring = RingBuffer::<u32, 4>::new();
    let v: Vec<_> = ring.into_iter().collect();
    assert!(v.is_empty());
}

#[test]
fn into_iter_partial() {
    let mut ring = RingBuffer::<u32, 4>::new();
    ring.push_back(10).unwrap();
    ring.push_back(20).unwrap();
    ring.push_back(30).unwrap();
    let v: Vec<_> = ring.into_iter().collect();
    assert_eq!(v, vec![10, 20, 30]);
}

#[test]
fn into_iter_full() {
    let ring: RingBuffer<u32, 4> = (0..4).collect();
    let v: Vec<_> = ring.into_iter().collect();
    assert_eq!(v, vec![0, 1, 2, 3]);
}

#[test]
fn into_iter_drops_remaining_on_abandon() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut ring = RingBuffer::<DropTracker, 4>::new();
    ring.push_back(dt(&drops)).unwrap();
    ring.push_back(dt(&drops)).unwrap();
    ring.push_back(dt(&drops)).unwrap();
    ring.push_back(dt(&drops)).unwrap();

    let mut iter = ring.into_iter();
    // Consume 2, abandon 2.
    let _ = iter.next();
    let _ = iter.next();
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    drop(iter);
    // Remaining 2 dropped via RingBuffer::drop inside IntoIter.
    assert_eq!(drops.load(Ordering::Relaxed), 4);
}

#[test]
fn into_iter_exact_size() {
    let ring: RingBuffer<u32, 4> = (0..3).collect();
    let iter = ring.into_iter();
    assert_eq!(iter.len(), 3);
}

// -----------------------------------------------------------------------
// Property tests
// -----------------------------------------------------------------------

/// Returns a [`proptest::test_runner::Config`] tuned for the current environment.
///
/// Under Miri, disables file-based failure persistence (filesystem I/O is
/// blocked by Miri's default isolation mode) and reduces cases from the
/// proptest default of 256 to 32, since Miri interpretation is far slower
/// than native execution.
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

        /// State-machine test: VecDeque oracle verifies all operations.
        ///
        /// Operations: PushBack, PushBackOverwrite, PopFront, Clear, Get, Clone.
        /// After each operation, ring buffer state is compared against VecDeque.
        #[test]
        fn state_machine_oracle(
            ops in proptest::collection::vec(
                prop_oneof![
                    (0u32..1000).prop_map(|v| (0u8, v)),  // PushBack
                    (0u32..1000).prop_map(|v| (1u8, v)),  // PushBackOverwrite
                    Just((2u8, 0u32)),                      // PopFront
                    Just((3u8, 0u32)),                      // Clear
                    (0u32..8).prop_map(|v| (4u8, v)),      // Get(index)
                    Just((5u8, 0u32)),                      // Clone
                ],
                0..200,
            )
        ) {
            let mut ring = RingBuffer::<u32, 4>::new();
            let mut model = std::collections::VecDeque::with_capacity(4);

            for (op, val) in &ops {
                match op {
                    0 => {
                        // PushBack
                        let ring_result = ring.push_back(*val);
                        if model.len() < 4 {
                            model.push_back(*val);
                            prop_assert!(ring_result.is_ok());
                        } else {
                            prop_assert_eq!(ring_result, Err(*val));
                        }
                    }
                    1 => {
                        // PushBackOverwrite
                        let ring_evicted = ring.push_back_overwrite(*val);
                        let model_evicted = if model.len() == 4 {
                            model.pop_front()
                        } else {
                            None
                        };
                        model.push_back(*val);
                        prop_assert_eq!(ring_evicted, model_evicted);
                    }
                    2 => {
                        // PopFront
                        prop_assert_eq!(ring.pop_front(), model.pop_front());
                    }
                    3 => {
                        // Clear
                        ring.clear();
                        model.clear();
                    }
                    4 => {
                        // Get
                        let idx = *val as usize;
                        prop_assert_eq!(ring.get(idx), model.get(idx));
                    }
                    5 => {
                        // Clone
                        let cloned = ring.clone();
                        let ring_vals: Vec<_> = cloned.iter().copied().collect();
                        let model_vals: Vec<_> = model.iter().copied().collect();
                        prop_assert_eq!(ring_vals, model_vals);
                    }
                    _ => unreachable!(),
                }

                // After every operation, verify len and contents match.
                prop_assert_eq!(ring.len(), model.len());
                let ring_vals: Vec<_> = ring.iter().copied().collect();
                let model_vals: Vec<_> = model.iter().copied().collect();
                prop_assert_eq!(ring_vals, model_vals);
            }
        }
    }
}
