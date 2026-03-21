//! Wait-free SPSC (Single-Producer, Single-Consumer) bounded ring buffer.
//!
//! # Design
//!
//! Based on [Rigtorp's SPSCQueue](https://github.com/rigtorp/SPSCQueue) (MIT,
//! Erik Rigtorp), the canonical wait-free SPSC ring used as reference by rtrb,
//! Folly (Facebook), and DPDK. Adapted for Rust with `MaybeUninit<T>` storage
//! from our existing [`RingBuffer`](super::ring_buffer::RingBuffer).
//!
//! # Key properties
//!
//! - **Wait-free**: Both `try_push` and `try_pop` complete in bounded steps.
//! - **No CAS**: Uses only `Acquire`/`Release` loads and stores.
//!   On x86-64 TSO these compile to plain `MOV` (no `MFENCE`, no `LOCK` prefix).
//! - **Cached remote index**: Producer caches consumer's `head` locally; only
//!   reloads on apparent-full. Consumer caches producer's `tail` locally; only
//!   reloads on apparent-empty. This reduces cache-coherence traffic.
//! - **Cache-line padded**: Head and tail indices live on separate cache lines
//!   to prevent false sharing between producer and consumer threads.
//! - **Power-of-2 capacity**: Bitwise AND masking for O(1) index calculation.
//! - **Single heap allocation**: One `Box`-allocated ring shared via `Arc`.
//!
//! # Wait strategy
//!
//! The ring itself is non-blocking (`try_push`/`try_pop`). Callers implement
//! their own wait strategy. For the sharded FS scanner, we use brief spin
//! (16-32 iterations with `core::hint::spin_loop()`) then `thread::yield_now()`.
//!
//! # Ordering rationale
//!
//! ```text
//! Producer writes slot, then Release-stores tail  →  consumer Acquire-loads tail, then reads slot
//! Consumer reads slot, then Release-stores head   →  producer Acquire-loads head, then writes slot
//! ```
//!
//! This establishes happens-before between slot write and slot read in both
//! directions. On x86-64 TSO, all stores are Release and all loads are Acquire
//! by default, so these compile to plain `MOV` instructions.
//!
//! # Safety
//!
//! Uses `unsafe` for `MaybeUninit` slot access and `ptr::write`/`ptr::read`.
//! Invariants are documented per operation. Run under Miri to validate.

#[cfg(not(loom))]
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(loom)]
use loom::sync::atomic::{AtomicU32, Ordering};

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

use crossbeam_utils::CachePadded;

// Compile-time proof that u32 -> usize is safe on this platform.
const _: () = assert!(
    std::mem::size_of::<usize>() >= std::mem::size_of::<u32>(),
    "Platform must have at least 32-bit addressing"
);

/// Create an uninitialized `[MaybeUninit<T>; N]` without running any constructors.
fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
    // SAFETY: An uninitialized MaybeUninit<T> is valid by definition.
    unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
}

// ============================================================================
// Shared Ring Storage
// ============================================================================

/// Shared storage backing the SPSC ring buffer.
///
/// # Invariants
///
/// - `N` is a power of 2 and fits in `u32` (validated at compile time).
/// - `head` and `tail` are monotonically increasing indices (they wrap via
///   the `MASK` in the accessor, not in the atomic itself). This avoids the
///   ABA problem on index values.
/// - Slots in the logical range `[head, tail)` (modulo capacity via mask) are
///   initialized; all other slots are uninitialized.
/// - Only the producer thread writes to `tail` and reads `head`.
/// - Only the consumer thread writes to `head` and reads `tail`.
struct SpscRing<T, const N: usize> {
    /// Slot storage — `N` slots, power-of-2 capacity.
    /// Wrapped in `UnsafeCell` because producer writes and consumer reads
    /// different slots concurrently. Safety is ensured by the SPSC protocol:
    /// a slot is only written after it's confirmed empty (via head) and only
    /// read after it's confirmed full (via tail).
    buf: UnsafeCell<[MaybeUninit<T>; N]>,

    /// Consumer's read index. Only the consumer advances this (Release store);
    /// the producer reads it (Acquire load) to detect space.
    head: CachePadded<AtomicU32>,

    /// Producer's write index. Only the producer advances this (Release store);
    /// the consumer reads it (Acquire load) to detect data.
    tail: CachePadded<AtomicU32>,
}

impl<T, const N: usize> SpscRing<T, N> {
    const CAPACITY: u32 = {
        assert!(N > 0, "SPSC capacity must be > 0");
        assert!(N & (N - 1) == 0, "SPSC capacity must be power of 2");
        assert!(
            N <= u32::MAX as usize / 2,
            "N must fit in u32 and not risk overflow"
        );
        N as u32
    };

    /// Bitmask for power-of-2 modulo: `index & MASK == index % CAPACITY`.
    const MASK: u32 = Self::CAPACITY - 1;

    fn new() -> Self {
        // Force compile-time validation of CAPACITY.
        let _ = Self::CAPACITY;

        Self {
            buf: UnsafeCell::new(uninit_array()),
            head: CachePadded::new(AtomicU32::new(0)),
            tail: CachePadded::new(AtomicU32::new(0)),
        }
    }
}

// SAFETY: The SPSC protocol ensures that producer and consumer access
// disjoint slots. `UnsafeCell<[MaybeUninit<T>; N]>` is safe to share
// because the atomic head/tail indices enforce the access discipline.
unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}
// SAFETY: `SpscRing` owns its buffered items and is `Send` when `T: Send`.
unsafe impl<T: Send, const N: usize> Send for SpscRing<T, N> {}

impl<T, const N: usize> Drop for SpscRing<T, N> {
    fn drop(&mut self) {
        // Drop any items remaining in the ring.
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        let buf = self.buf.get_mut();

        let mut idx = head;
        while idx != tail {
            let slot = (idx & Self::MASK) as usize;
            // SAFETY: Slots in [head, tail) are initialized.
            unsafe { buf[slot].assume_init_drop() };
            idx = idx.wrapping_add(1);
        }
    }
}

// ============================================================================
// Producer
// ============================================================================

/// Producer handle for the SPSC ring buffer.
///
/// Holds a reference to the shared ring and a cached copy of the consumer's
/// `head` index. The cached head is only refreshed when the ring appears full,
/// reducing cross-core cache-coherence traffic.
pub struct SpscProducer<T, const N: usize> {
    /// Raw pointer to the shared ring. Using a raw pointer instead of a reference
    /// avoids Stacked Borrows conflicts when producer and consumer access
    /// disjoint slots concurrently from different threads.
    ring: *const SpscRing<T, N>,
    /// Cached snapshot of consumer's `head`. Only refreshed when the ring
    /// appears full (tail - cached_head >= capacity). This avoids loading
    /// the consumer's cache line on every push.
    cached_head: u32,
}

// SAFETY: SpscProducer accesses the ring via raw pointer and the SPSC protocol
// ensures exclusive write access to producer-side indices. The ring is valid
// for the lifetime of the producer (enforced by the owning Arc in OwnedSpscProducer).
unsafe impl<T: Send, const N: usize> Send for SpscProducer<T, N> {}

impl<T, const N: usize> SpscProducer<T, N> {
    /// Attempt to push `value` into the ring.
    ///
    /// Returns `Ok(())` if successful, `Err(value)` if the ring is full.
    ///
    /// # Ordering
    ///
    /// 1. Read current `tail` (Relaxed — we're the only writer).
    /// 2. Check space: if `tail - cached_head >= capacity`, reload `head`
    ///    with Acquire to get fresh consumer progress.
    /// 3. Write value into slot at `tail & MASK`.
    /// 4. Release-store `tail + 1` to publish the slot to the consumer.
    #[inline(always)]
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        // SAFETY: `self.ring` is valid for the producer's lifetime (guaranteed
        // by the owning Arc in OwnedSpscProducer). All field accesses go through
        // raw pointer deref to avoid creating a shared reference to the ring,
        // which would conflict under Stacked Borrows with the consumer.
        unsafe {
            let ring = self.ring;
            let tail = (*ring).tail.load(Ordering::Relaxed);

            // Check if ring appears full using cached head.
            if tail.wrapping_sub(self.cached_head) >= SpscRing::<T, N>::CAPACITY {
                // Refresh cached head from consumer's actual head.
                self.cached_head = (*ring).head.load(Ordering::Acquire);
                if tail.wrapping_sub(self.cached_head) >= SpscRing::<T, N>::CAPACITY {
                    return Err(value);
                }
            }

            let slot = (tail & SpscRing::<T, N>::MASK) as usize;
            let slot_ptr = (*ring).buf.get().cast::<MaybeUninit<T>>().add(slot);
            slot_ptr.write(MaybeUninit::new(value));

            // Release-store tail to make the written slot visible to consumer.
            (*ring).tail.store(tail.wrapping_add(1), Ordering::Release);

            Ok(())
        }
    }
}

// ============================================================================
// Consumer
// ============================================================================

/// Consumer handle for the SPSC ring buffer.
///
/// Holds a reference to the shared ring and a cached copy of the producer's
/// `tail` index. The cached tail is only refreshed when the ring appears empty,
/// reducing cross-core cache-coherence traffic.
pub struct SpscConsumer<T, const N: usize> {
    /// Raw pointer to the shared ring. See `SpscProducer::ring` for rationale.
    ring: *const SpscRing<T, N>,
    /// Cached snapshot of producer's `tail`. Only refreshed when the ring
    /// appears empty (head == cached_tail). This avoids loading the producer's
    /// cache line on every pop.
    cached_tail: u32,
}

// SAFETY: SpscConsumer accesses the ring via raw pointer and the SPSC protocol
// ensures exclusive write access to consumer-side indices. The ring is valid
// for the lifetime of the consumer (enforced by the owning Arc in OwnedSpscConsumer).
unsafe impl<T: Send, const N: usize> Send for SpscConsumer<T, N> {}

impl<T, const N: usize> SpscConsumer<T, N> {
    /// Attempt to pop a value from the ring.
    ///
    /// Returns `Some(value)` if successful, `None` if the ring is empty.
    ///
    /// # Ordering
    ///
    /// 1. Read current `head` (Relaxed — we're the only writer).
    /// 2. Check data: if `head == cached_tail`, reload `tail` with Acquire
    ///    to get fresh producer progress.
    /// 3. Read value from slot at `head & MASK`.
    /// 4. Release-store `head + 1` to free the slot for the producer.
    #[inline(always)]
    pub fn try_pop(&mut self) -> Option<T> {
        // SAFETY: `self.ring` is valid for the consumer's lifetime. All field
        // accesses go through raw pointer deref (see SpscProducer for rationale).
        unsafe {
            let ring = self.ring;
            let head = (*ring).head.load(Ordering::Relaxed);

            // Check if ring appears empty using cached tail.
            if head == self.cached_tail {
                // Refresh cached tail from producer's actual tail.
                self.cached_tail = (*ring).tail.load(Ordering::Acquire);
                if head == self.cached_tail {
                    return None;
                }
            }

            let slot = (head & SpscRing::<T, N>::MASK) as usize;
            let slot_ptr = (*ring).buf.get().cast::<MaybeUninit<T>>().add(slot);
            let value = (*slot_ptr).as_ptr().read();

            // Release-store head to free the slot for the producer.
            (*ring).head.store(head.wrapping_add(1), Ordering::Release);

            Some(value)
        }
    }

    /// Attempt to pop up to `out.len()` values from the ring in batch.
    ///
    /// Returns the number of values actually popped (0 if ring is empty).
    /// Values are written into `out[0..n]`.
    ///
    /// The output slice uses `MaybeUninit<T>` to avoid requiring `T: Default`
    /// for pre-initialization. Callers must `assume_init` only the first `n`
    /// returned elements.
    ///
    /// More efficient than repeated `try_pop` when draining: refreshes the
    /// cached tail once, then reads all available slots before advancing head.
    #[inline]
    pub fn try_pop_batch(&mut self, out: &mut [MaybeUninit<T>]) -> usize {
        if out.is_empty() {
            return 0;
        }

        // SAFETY: `self.ring` is valid for the consumer's lifetime.
        unsafe {
            let ring = self.ring;
            let head = (*ring).head.load(Ordering::Relaxed);

            // Always refresh tail for batch — we want to drain as much as possible.
            self.cached_tail = (*ring).tail.load(Ordering::Acquire);

            let available = self.cached_tail.wrapping_sub(head) as usize;
            if available == 0 {
                return 0;
            }

            let count = available.min(out.len());

            let base = (*ring).buf.get().cast::<MaybeUninit<T>>();
            for (i, slot_out) in out[..count].iter_mut().enumerate() {
                let slot = (head.wrapping_add(i as u32) & SpscRing::<T, N>::MASK) as usize;
                *slot_out = MaybeUninit::new((*base.add(slot)).as_ptr().read());
            }

            // Advance head past all consumed slots.
            (*ring)
                .head
                .store(head.wrapping_add(count as u32), Ordering::Release);

            count
        }
    }
}

// ============================================================================
// Constructor
// ============================================================================

/// Create a new SPSC ring buffer with capacity `N` (must be power of 2).
///
/// Returns a `(SpscProducer, SpscConsumer)` pair. The producer and consumer
/// may be sent to different threads (they implement `Send`).
///
/// The returned handles share an `Arc<OwnedSpscInner>`-managed ring.
/// The ring is reclaimed when both handles are dropped.
///
/// # Panics
///
/// Compile-time panic if `N` is not a power of 2, is zero, or exceeds `u32::MAX / 2`.
///
/// # Example
///
/// ```ignore
/// let (mut tx, mut rx) = spsc_channel::<u64, 8>();
/// tx.try_push(42).unwrap();
/// assert_eq!(rx.try_pop(), Some(42));
/// ```
pub fn spsc_channel<T: Send + 'static, const N: usize>()
-> (OwnedSpscProducer<T, N>, OwnedSpscConsumer<T, N>) {
    // Force compile-time capacity check.
    let _ = SpscRing::<T, N>::CAPACITY;

    let ring = Box::into_raw(Box::new(SpscRing::<T, N>::new()));

    // SAFETY: `ring` is a valid, heap-allocated SpscRing. We split ownership
    // between producer and consumer. The ring is freed when both are dropped
    // (tracked via a shared atomic counter in OwnedSpscInner).
    let inner = std::sync::Arc::new(OwnedSpscInner { ring });

    let producer = OwnedSpscProducer {
        inner: SpscProducer {
            ring,
            cached_head: 0,
        },
        _owner: inner.clone(),
    };

    let consumer = OwnedSpscConsumer {
        inner: SpscConsumer {
            ring,
            cached_tail: 0,
        },
        _owner: inner,
    };

    (producer, consumer)
}

/// Internal shared ownership tracker for the heap-allocated ring.
struct OwnedSpscInner<T, const N: usize> {
    ring: *mut SpscRing<T, N>,
}

// SAFETY: The ring pointer is valid and the SPSC protocol ensures safe access.
unsafe impl<T: Send, const N: usize> Send for OwnedSpscInner<T, N> {}
// SAFETY: The ring pointer is valid and the SPSC protocol ensures safe access.
unsafe impl<T: Send, const N: usize> Sync for OwnedSpscInner<T, N> {}

impl<T, const N: usize> Drop for OwnedSpscInner<T, N> {
    fn drop(&mut self) {
        // SAFETY: We are the last owner (Arc refcount hit 0). The ring was
        // allocated via Box::into_raw and is valid.
        unsafe {
            drop(Box::from_raw(self.ring));
        }
    }
}

/// Owning producer handle. Frees the ring when both producer and consumer are dropped.
///
/// `Send + !Sync` by design: the producer must be used from exactly one thread
/// at a time (enforced by `&mut self` on `try_push`). It can be *moved* to
/// another thread but must not be shared via `&OwnedSpscProducer`.
pub struct OwnedSpscProducer<T: Send + 'static, const N: usize> {
    inner: SpscProducer<T, N>,
    _owner: std::sync::Arc<OwnedSpscInner<T, N>>,
}

impl<T: Send + 'static, const N: usize> OwnedSpscProducer<T, N> {
    /// Attempt to push `value` into the ring.
    ///
    /// Returns `Ok(())` on success, `Err(value)` if the ring is full.
    #[inline(always)]
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        self.inner.try_push(value)
    }
}

// SAFETY: Only one thread should use the producer at a time (enforced by &mut).
unsafe impl<T: Send, const N: usize> Send for OwnedSpscProducer<T, N> {}

/// Owning consumer handle. Frees the ring when both producer and consumer are dropped.
///
/// `Send + !Sync` by design: the consumer must be used from exactly one thread
/// at a time (enforced by `&mut self` on `try_pop`). It can be *moved* to
/// another thread but must not be shared via `&OwnedSpscConsumer`.
pub struct OwnedSpscConsumer<T: Send + 'static, const N: usize> {
    inner: SpscConsumer<T, N>,
    _owner: std::sync::Arc<OwnedSpscInner<T, N>>,
}

impl<T: Send + 'static, const N: usize> OwnedSpscConsumer<T, N> {
    /// Attempt to pop a value from the ring.
    ///
    /// Returns `Some(value)` on success, `None` if the ring is empty.
    #[inline(always)]
    pub fn try_pop(&mut self) -> Option<T> {
        self.inner.try_pop()
    }

    /// Attempt to pop up to `out.len()` values in batch.
    ///
    /// Returns the number of values popped (written into `out[0..n]`).
    #[inline]
    pub fn try_pop_batch(&mut self, out: &mut [MaybeUninit<T>]) -> usize {
        self.inner.try_pop_batch(out)
    }
}

// SAFETY: Only one thread should use the consumer at a time (enforced by &mut).
unsafe impl<T: Send, const N: usize> Send for OwnedSpscConsumer<T, N> {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pop_returns_none() {
        let (_, mut rx) = spsc_channel::<u64, 4>();
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn push_then_pop() {
        let (mut tx, mut rx) = spsc_channel::<u64, 4>();
        assert!(tx.try_push(42).is_ok());
        assert_eq!(rx.try_pop(), Some(42));
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn push_to_capacity_then_full() {
        let (mut tx, mut rx) = spsc_channel::<u64, 4>();
        for i in 0..4u64 {
            assert!(tx.try_push(i).is_ok());
        }
        // Ring is full — push should fail and return the value.
        assert_eq!(tx.try_push(99), Err(99));

        // Pop all and verify order.
        for i in 0..4u64 {
            assert_eq!(rx.try_pop(), Some(i));
        }
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn wraparound_correctness() {
        let (mut tx, mut rx) = spsc_channel::<u64, 4>();

        // Fill and drain multiple times to exercise index wrapping.
        for round in 0..10u64 {
            let base = round * 4;
            for i in 0..4 {
                assert!(tx.try_push(base + i).is_ok());
            }
            for i in 0..4 {
                assert_eq!(rx.try_pop(), Some(base + i));
            }
            assert_eq!(rx.try_pop(), None);
        }
    }

    #[test]
    fn partial_fill_and_drain() {
        let (mut tx, mut rx) = spsc_channel::<u64, 8>();

        // Push 3, pop 2, push 3 more, pop 4 — tests non-aligned access patterns.
        assert!(tx.try_push(1).is_ok());
        assert!(tx.try_push(2).is_ok());
        assert!(tx.try_push(3).is_ok());

        assert_eq!(rx.try_pop(), Some(1));
        assert_eq!(rx.try_pop(), Some(2));

        assert!(tx.try_push(4).is_ok());
        assert!(tx.try_push(5).is_ok());
        assert!(tx.try_push(6).is_ok());

        assert_eq!(rx.try_pop(), Some(3));
        assert_eq!(rx.try_pop(), Some(4));
        assert_eq!(rx.try_pop(), Some(5));
        assert_eq!(rx.try_pop(), Some(6));
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn try_pop_batch_drains() {
        let (mut tx, mut rx) = spsc_channel::<u64, 8>();

        for i in 0..5u64 {
            assert!(tx.try_push(i).is_ok());
        }

        let mut out = [MaybeUninit::uninit(); 8];
        let n = rx.try_pop_batch(&mut out);
        assert_eq!(n, 5);

        for (i, slot) in out[..5].iter().enumerate() {
            // SAFETY: We know out[0..5] was written by try_pop_batch.
            let val = unsafe { slot.assume_init() };
            assert_eq!(val, i as u64);
        }

        // Ring should be empty now.
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn try_pop_batch_partial() {
        let (mut tx, mut rx) = spsc_channel::<u64, 8>();

        for i in 0..5u64 {
            assert!(tx.try_push(i).is_ok());
        }

        // Only drain 3 of the 5.
        let mut out = [MaybeUninit::uninit(); 3];
        let n = rx.try_pop_batch(&mut out);
        assert_eq!(n, 3);

        for (i, slot) in out[..3].iter().enumerate() {
            // SAFETY: `try_pop_batch` returned 3, so `out[0..3]` are fully initialized.
            let val = unsafe { slot.assume_init() };
            assert_eq!(val, i as u64);
        }

        // 2 remaining.
        assert_eq!(rx.try_pop(), Some(3));
        assert_eq!(rx.try_pop(), Some(4));
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn try_pop_batch_empty() {
        let (_, mut rx) = spsc_channel::<u64, 4>();
        let mut out = [MaybeUninit::uninit(); 4];
        let n = rx.try_pop_batch(&mut out);
        assert_eq!(n, 0);
    }

    #[test]
    fn drop_remaining_items() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let drop_count = Arc::new(AtomicUsize::new(0));

        struct DropTracker(Arc<AtomicUsize>);
        impl Drop for DropTracker {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        {
            let (mut tx, _rx) = spsc_channel::<DropTracker, 4>();
            assert!(tx.try_push(DropTracker(drop_count.clone())).is_ok());
            assert!(tx.try_push(DropTracker(drop_count.clone())).is_ok());
            assert!(tx.try_push(DropTracker(drop_count.clone())).is_ok());
            // Drop producer and consumer with 3 items still in ring.
        }

        assert_eq!(drop_count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn cross_thread_fifo() {
        let (mut tx, mut rx) = spsc_channel::<u64, 4>();
        // Small count for Miri — enough to wrap the ring and exercise ordering.
        let count = if cfg!(miri) { 16u64 } else { 200u64 };

        let producer = std::thread::spawn(move || {
            for i in 0..count {
                loop {
                    match tx.try_push(i) {
                        Ok(()) => break,
                        Err(_) => std::thread::yield_now(),
                    }
                }
            }
        });

        let consumer = std::thread::spawn(move || {
            let mut received = Vec::with_capacity(count as usize);
            while received.len() < count as usize {
                if let Some(v) = rx.try_pop() {
                    received.push(v);
                } else {
                    std::thread::yield_now();
                }
            }
            received
        });

        producer.join().unwrap();
        let received = consumer.join().unwrap();

        assert_eq!(received.len(), count as usize);
        for (i, &v) in received.iter().enumerate() {
            assert_eq!(v, i as u64, "FIFO violation at index {i}");
        }
    }

    /// Drop semantics under cross-thread ownership transfer.
    /// The producer pushes DropTrackers, consumer pops some, then both handles
    /// are dropped — verifying no leak or double-drop.
    #[test]
    fn cross_thread_drop_tracking() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Dt(Arc<AtomicUsize>);
        impl Drop for Dt {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let count = if cfg!(miri) { 8usize } else { 100usize };
        let (mut tx, mut rx) = spsc_channel::<Dt, 4>();

        let drops_p = drops.clone();
        let producer = std::thread::spawn(move || {
            for _ in 0..count {
                // Create the tracker once per item; retry pushes the same instance.
                let mut item = Some(Dt(drops_p.clone()));
                loop {
                    match tx.try_push(item.take().unwrap()) {
                        Ok(()) => break,
                        Err(returned) => {
                            item = Some(returned);
                            std::thread::yield_now();
                        }
                    }
                }
            }
        });

        let consumer = std::thread::spawn(move || {
            let mut popped = 0;
            while popped < count {
                if let Some(_v) = rx.try_pop() {
                    popped += 1;
                    // _v dropped here.
                } else {
                    std::thread::yield_now();
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();

        assert_eq!(drops.load(Ordering::Relaxed), count);
    }

    /// Verify full detection works when indices are near u32::MAX.
    #[test]
    fn full_detected_near_u32_max_boundary() {
        let ring = SpscRing::<u64, 4>::new();
        let start = u32::MAX - 2; // 0xFFFF_FFFD

        ring.head.store(start, Ordering::Relaxed);
        ring.tail.store(start, Ordering::Relaxed);

        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: start,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: start,
        };

        // Fill to capacity — indices wrap through 0.
        for i in 0..4u64 {
            assert!(prod.try_push(i).is_ok(), "push {i} should succeed");
        }
        // Must detect full.
        assert_eq!(prod.try_push(99), Err(99), "ring should be full");

        // Pop all — FIFO must hold across the wrap.
        for i in 0..4u64 {
            assert_eq!(cons.try_pop(), Some(i), "FIFO violation at {i}");
        }
        assert_eq!(cons.try_pop(), None);
    }

    /// Verify empty detection works when indices are near u32::MAX.
    #[test]
    fn empty_detected_near_u32_max_boundary() {
        let ring = SpscRing::<u64, 4>::new();
        let start = u32::MAX - 1; // 0xFFFF_FFFE

        ring.head.store(start, Ordering::Relaxed);
        ring.tail.store(start, Ordering::Relaxed);

        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: start,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: start,
        };

        // Empty ring at near-MAX indices.
        assert_eq!(cons.try_pop(), None, "empty ring should return None");

        // Push one, pop one — crossing the u32 wrap boundary.
        assert!(prod.try_push(42).is_ok());
        assert_eq!(cons.try_pop(), Some(42));
        assert_eq!(cons.try_pop(), None, "should be empty again");
    }

    /// Verify the cached-head staleness scenario cannot cause overwrite.
    #[test]
    fn stale_cached_head_still_detects_full() {
        let ring = SpscRing::<u64, 4>::new();
        let start = u32::MAX - 5;

        ring.head.store(start, Ordering::Relaxed);
        ring.tail.store(start, Ordering::Relaxed);

        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: start,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: start,
        };

        // Fill to capacity.
        for i in 0..4u64 {
            assert!(prod.try_push(i).is_ok());
        }
        // cached_head = start, actual head = start, tail = start+4

        // Consumer drains all 4 — head advances to start+4, but
        // producer's cached_head is still `start` (maximally stale).
        for i in 0..4u64 {
            assert_eq!(cons.try_pop(), Some(i));
        }

        // Fill again — tail goes to start+8, cached_head still = start.
        // wrapping_sub(start+8, start) = 8 >= 4, so refresh triggers.
        // After refresh, cached_head = start+4, and push succeeds.
        for i in 10..14u64 {
            assert!(
                prod.try_push(i).is_ok(),
                "push {i} should succeed after refresh"
            );
        }

        // Must detect full again.
        assert_eq!(
            prod.try_push(99),
            Err(99),
            "should be full after second fill"
        );

        // FIFO preserved.
        for i in 10..14u64 {
            assert_eq!(cons.try_pop(), Some(i));
        }
    }
}

// ============================================================================
// Property Tests
// ============================================================================

#[cfg(all(test, feature = "stdx-proptest"))]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    /// Operations we can perform on the ring.
    #[derive(Debug, Clone)]
    enum Op {
        Push(u64),
        Pop,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![any::<u64>().prop_map(Op::Push), Just(Op::Pop),]
    }

    proptest! {
        /// Random interleaving of push/pop on single thread preserves FIFO.
        #[test]
        fn fifo_invariant(ops in proptest::collection::vec(op_strategy(), 0..500)) {
            let (mut tx, mut rx) = spsc_channel::<u64, 8>();
            let mut expected = std::collections::VecDeque::new();
            let mut pushed = 0u64;
            let mut popped = 0u64;

            for op in &ops {
                match op {
                    Op::Push(v) => {
                        match tx.try_push(*v) {
                            Ok(()) => {
                                expected.push_back(*v);
                                pushed += 1;
                            }
                            Err(_) => {
                                // Ring full — count invariant should hold.
                                prop_assert_eq!((pushed - popped) as usize, 8);
                            }
                        }
                    }
                    Op::Pop => {
                        match rx.try_pop() {
                            Some(v) => {
                                let exp = expected.pop_front().unwrap();
                                prop_assert_eq!(v, exp, "FIFO ordering violated");
                                popped += 1;
                            }
                            None => {
                                prop_assert!(expected.is_empty());
                                prop_assert_eq!(pushed, popped);
                            }
                        }
                    }
                }
            }

            // Count invariant.
            prop_assert_eq!((pushed - popped) as usize, expected.len());
        }
    }
}

// ============================================================================
// Loom Tests
// ============================================================================

#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use loom::thread;

    /// Verify FIFO ordering with loom's exhaustive scheduler.
    ///
    /// Producer pushes K items, consumer pops until K received.
    /// Loom explores all possible thread interleavings.
    #[test]
    fn loom_spsc_fifo() {
        // Use small K so loom can exhaust interleavings.
        const K: u32 = 3;

        loom::model(|| {
            // Manually create shared ring for loom (no Box::into_raw with loom).
            let ring = loom::sync::Arc::new(SpscRing::<u32, 4>::new());

            let ring_p = ring.clone();
            let ring_c = ring.clone();

            let producer = thread::spawn(move || {
                let mut prod = SpscProducer {
                    ring: &*ring_p,
                    cached_head: 0,
                };
                for i in 0..K {
                    loop {
                        match prod.try_push(i) {
                            Ok(()) => break,
                            Err(_) => loom::thread::yield_now(),
                        }
                    }
                }
            });

            let consumer = thread::spawn(move || {
                let mut cons = SpscConsumer {
                    ring: &*ring_c,
                    cached_tail: 0,
                };
                let mut received = Vec::new();
                while received.len() < K as usize {
                    match cons.try_pop() {
                        Some(v) => received.push(v),
                        None => loom::thread::yield_now(),
                    }
                }
                received
            });

            producer.join().unwrap();
            let received = consumer.join().unwrap();

            assert_eq!(received.len(), K as usize);
            for (i, &v) in received.iter().enumerate() {
                assert_eq!(v, i as u32);
            }
        });
    }

    /// Verify ring handles full condition correctly under loom.
    #[test]
    fn loom_spsc_full_retry() {
        loom::model(|| {
            let ring = loom::sync::Arc::new(SpscRing::<u32, 2>::new());

            let ring_p = ring.clone();
            let ring_c = ring.clone();

            let producer = thread::spawn(move || {
                let mut prod = SpscProducer {
                    ring: &*ring_p,
                    cached_head: 0,
                };
                // Push 4 items into a capacity-2 ring — requires consumer drain.
                for i in 0..4u32 {
                    loop {
                        match prod.try_push(i) {
                            Ok(()) => break,
                            Err(_) => loom::thread::yield_now(),
                        }
                    }
                }
            });

            let consumer = thread::spawn(move || {
                let mut cons = SpscConsumer {
                    ring: &*ring_c,
                    cached_tail: 0,
                };
                let mut received = Vec::new();
                while received.len() < 4 {
                    match cons.try_pop() {
                        Some(v) => received.push(v),
                        None => loom::thread::yield_now(),
                    }
                }
                received
            });

            producer.join().unwrap();
            let received = consumer.join().unwrap();

            assert_eq!(received, vec![0, 1, 2, 3]);
        });
    }

    /// Verify `try_pop_batch` preserves FIFO ordering across all interleavings.
    ///
    /// Producer pushes K items, consumer drains with `try_pop_batch` into a
    /// buffer larger than K. Loom explores all scheduling points between the
    /// producer's Release-store of tail and the consumer's Acquire-load + batch
    /// read + Release-store of head.
    #[test]
    fn loom_spsc_try_pop_batch() {
        const K: u32 = 3;

        loom::model(|| {
            let ring = loom::sync::Arc::new(SpscRing::<u32, 4>::new());

            let ring_p = ring.clone();
            let ring_c = ring.clone();

            let producer = thread::spawn(move || {
                let mut prod = SpscProducer {
                    ring: &*ring_p,
                    cached_head: 0,
                };
                for i in 0..K {
                    loop {
                        match prod.try_push(i) {
                            Ok(()) => break,
                            Err(_) => loom::thread::yield_now(),
                        }
                    }
                }
            });

            let consumer = thread::spawn(move || {
                let mut cons = SpscConsumer {
                    ring: &*ring_c,
                    cached_tail: 0,
                };
                let mut received = Vec::new();
                let mut buf = [MaybeUninit::uninit(); 4];

                while received.len() < K as usize {
                    let n = cons.try_pop_batch(&mut buf);
                    for slot in &buf[..n] {
                        // SAFETY: `try_pop_batch` guarantees `buf[0..n]` are initialized.
                        received.push(unsafe { slot.assume_init_read() });
                    }
                    if n == 0 {
                        loom::thread::yield_now();
                    }
                }
                received
            });

            producer.join().unwrap();
            let received = consumer.join().unwrap();

            assert_eq!(received.len(), K as usize, "all items must be received");
            for (i, &v) in received.iter().enumerate() {
                assert_eq!(v, i as u32, "FIFO violated at index {i}");
            }
        });
    }

    /// Verify `try_pop_batch` under backpressure: producer pushes more items
    /// than capacity, requiring the consumer to batch-drain mid-way.
    ///
    /// Mirrors `loom_spsc_full_retry` but uses `try_pop_batch` instead of
    /// `try_pop`. Verifies no data loss and strict FIFO ordering when the
    /// ring wraps under concurrent push/batch-pop.
    #[test]
    fn loom_spsc_batch_backpressure() {
        loom::model(|| {
            let ring = loom::sync::Arc::new(SpscRing::<u32, 2>::new());

            let ring_p = ring.clone();
            let ring_c = ring.clone();

            // Push 4 items into a capacity-2 ring — requires consumer drain.
            let producer = thread::spawn(move || {
                let mut prod = SpscProducer {
                    ring: &*ring_p,
                    cached_head: 0,
                };
                for i in 0..4u32 {
                    loop {
                        match prod.try_push(i) {
                            Ok(()) => break,
                            Err(_) => loom::thread::yield_now(),
                        }
                    }
                }
            });

            let consumer = thread::spawn(move || {
                let mut cons = SpscConsumer {
                    ring: &*ring_c,
                    cached_tail: 0,
                };
                let mut received = Vec::new();
                let mut buf = [MaybeUninit::uninit(); 2];

                while received.len() < 4 {
                    let n = cons.try_pop_batch(&mut buf);
                    for slot in &buf[..n] {
                        // SAFETY: `try_pop_batch` guarantees `buf[0..n]` are initialized.
                        received.push(unsafe { slot.assume_init_read() });
                    }
                    if n == 0 {
                        loom::thread::yield_now();
                    }
                }
                received
            });

            producer.join().unwrap();
            let received = consumer.join().unwrap();

            assert_eq!(
                received,
                vec![0, 1, 2, 3],
                "FIFO with no data loss under backpressure"
            );
        });
    }
}

// ============================================================================
// Kani Formal Verification Proofs
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    //! Kani formal verification proofs for the SPSC ring buffer.
    //!
    //! Each proof targets one safety-critical property of the ring,
    //! verifying it holds for **all** valid inputs (symbolic, not sampled).
    //!
    //! Proofs use `CAP = 4` with bounded operation counts. Kani explores
    //! all reachable states within those bounds exhaustively.
    //!
    //! Coverage:
    //! - Proof 1: `try_push` slot index never exceeds capacity
    //! - Proof 2: `try_pop` slot index never exceeds capacity
    //! - Proof 3: FIFO ordering preserved across push/pop sequences
    //! - Proof 4: Full detection — push fails exactly at capacity
    //! - Proof 5: Empty detection — pop fails exactly when empty
    //! - Proof 6: `try_pop_batch` count never exceeds available items
    //! - Proof 7: Wrapping arithmetic correctness near u32::MAX boundary
    //! - Proof 8: Drop visits exactly the initialized slot range

    use super::*;

    // ── Proof 1: push slot index stays in bounds ──────────────────────
    //
    // Verifies that `tail & MASK` always produces a valid slot index
    // (0..CAPACITY) for any symbolic sequence of pushes.

    #[kani::proof]
    #[kani::unwind(7)]
    fn push_slot_index_within_bounds() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();
        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: 0,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: 0,
        };

        let n: usize = kani::any();
        kani::assume(n <= CAP);

        for _ in 0..n {
            let val: u32 = kani::any();
            let result = prod.try_push(val);
            assert!(result.is_ok());
        }

        // Verify we can read them all back (proves slots were valid).
        for _ in 0..n {
            assert!(cons.try_pop().is_some());
        }
        assert!(cons.try_pop().is_none());
    }

    // ── Proof 2: pop slot index stays in bounds ──────────────────────
    //
    // Verifies that `head & MASK` always produces a valid slot index
    // and the read value matches what was written.

    #[kani::proof]
    #[kani::unwind(7)]
    fn pop_reads_written_values() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();
        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: 0,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: 0,
        };

        let a: u32 = kani::any();
        let b: u32 = kani::any();

        assert!(prod.try_push(a).is_ok());
        assert!(prod.try_push(b).is_ok());

        assert_eq!(cons.try_pop(), Some(a));
        assert_eq!(cons.try_pop(), Some(b));
        assert_eq!(cons.try_pop(), None);
    }

    // ── Proof 3: FIFO ordering with interleaved push/pop ─────────────
    //
    // Verifies that push-pop-push-pop sequences preserve insertion order
    // even when the ring wraps around internal slot boundaries.

    #[kani::proof]
    #[kani::unwind(9)]
    fn fifo_ordering_across_wrap() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();
        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: 0,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: 0,
        };

        let vals: [u32; 6] = [
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        ];

        // Fill to capacity.
        for i in 0..CAP {
            assert!(prod.try_push(vals[i]).is_ok());
        }

        // Drain 2, push 2 more — forces wrap-around.
        assert_eq!(cons.try_pop(), Some(vals[0]));
        assert_eq!(cons.try_pop(), Some(vals[1]));
        assert!(prod.try_push(vals[4]).is_ok());
        assert!(prod.try_push(vals[5]).is_ok());

        // Drain remaining 4 in FIFO order.
        assert_eq!(cons.try_pop(), Some(vals[2]));
        assert_eq!(cons.try_pop(), Some(vals[3]));
        assert_eq!(cons.try_pop(), Some(vals[4]));
        assert_eq!(cons.try_pop(), Some(vals[5]));
        assert_eq!(cons.try_pop(), None);
    }

    // ── Proof 4: full detection is exact ─────────────────────────────
    //
    // Verifies that push succeeds for exactly CAPACITY items and fails
    // on the (CAPACITY+1)th, returning the rejected value.

    #[kani::proof]
    #[kani::unwind(7)]
    fn full_detection_is_exact() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();
        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: 0,
        };

        for _ in 0..CAP {
            assert!(prod.try_push(kani::any()).is_ok());
        }

        let overflow: u32 = kani::any();
        assert_eq!(prod.try_push(overflow), Err(overflow));
    }

    // ── Proof 5: empty detection is exact ────────────────────────────
    //
    // Verifies that pop returns None on an empty ring, Some after a push,
    // and None again after draining.

    #[kani::proof]
    #[kani::unwind(4)]
    fn empty_detection_is_exact() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();
        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: 0,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: 0,
        };

        // Empty ring.
        assert_eq!(cons.try_pop(), None);

        // Push one, pop one.
        let val: u32 = kani::any();
        assert!(prod.try_push(val).is_ok());
        assert_eq!(cons.try_pop(), Some(val));

        // Empty again.
        assert_eq!(cons.try_pop(), None);
    }

    // ── Proof 6: batch-pop count never exceeds available ─────────────
    //
    // Verifies that `try_pop_batch` returns at most the number of items
    // in the ring, and each returned value matches FIFO order.

    #[kani::proof]
    #[kani::unwind(7)]
    fn batch_pop_count_bounded() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();
        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: 0,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: 0,
        };

        let n: usize = kani::any();
        kani::assume(n <= CAP);

        let mut pushed = [0u32; 4];
        for i in 0..n {
            pushed[i] = kani::any();
            assert!(prod.try_push(pushed[i]).is_ok());
        }

        let mut out = [MaybeUninit::uninit(); 4];
        let count = cons.try_pop_batch(&mut out);
        assert_eq!(count, n);

        for i in 0..count {
            // SAFETY: try_pop_batch guarantees out[0..count] is initialized.
            let val = unsafe { out[i].assume_init() };
            assert_eq!(val, pushed[i]);
        }
    }

    // ── Proof 7: wrapping arithmetic near u32::MAX ───────────────────
    //
    // Verifies that the ring operates correctly when indices start near
    // the u32::MAX boundary and wrap through zero. This directly targets
    // the class of bug the PR reviewer was concerned about.
    //
    // We construct a ring with head and tail pre-set near u32::MAX, then
    // push and pop across the wrap boundary and verify FIFO + count.

    #[kani::proof]
    #[kani::unwind(7)]
    fn wrapping_near_u32_max_is_correct() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();

        // Pre-advance indices to just below u32::MAX.
        // This simulates ~4 billion operations of history.
        let start: u32 = u32::MAX - 2; // 0xFFFF_FFFD

        ring.head.store(start, Ordering::Relaxed);
        ring.tail.store(start, Ordering::Relaxed);

        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: start,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: start,
        };

        // Push CAP items — indices will wrap from 0xFFFF_FFFD through 0x0000_0001.
        let vals: [u32; 4] = [kani::any(), kani::any(), kani::any(), kani::any()];
        for i in 0..CAP {
            assert!(prod.try_push(vals[i]).is_ok());
        }

        // Ring should be full.
        let overflow: u32 = kani::any();
        assert_eq!(prod.try_push(overflow), Err(overflow));

        // Pop all — FIFO order must hold across the wrap.
        for i in 0..CAP {
            assert_eq!(cons.try_pop(), Some(vals[i]));
        }
        assert_eq!(cons.try_pop(), None);
    }

    // ── Proof 8: drop visits exactly initialized slots ───────────────
    //
    // Verifies that SpscRing::drop iterates exactly from head to tail
    // (the initialized range) using wrapping arithmetic, so no slots
    // are leaked and no uninitialized slots are dropped.

    #[kani::proof]
    #[kani::unwind(7)]
    fn drop_covers_initialized_range() {
        const CAP: usize = 4;
        let ring = SpscRing::<u32, CAP>::new();
        let mut prod = SpscProducer {
            ring: &ring,
            cached_head: 0,
        };
        let mut cons = SpscConsumer {
            ring: &ring,
            cached_tail: 0,
        };

        let n: usize = kani::any();
        kani::assume(n <= CAP);

        // Push n items.
        for _ in 0..n {
            assert!(prod.try_push(kani::any()).is_ok());
        }

        // Pop a symbolic prefix — remaining items stay in the ring.
        let pop_count: usize = kani::any();
        kani::assume(pop_count <= n);
        for _ in 0..pop_count {
            assert!(cons.try_pop().is_some());
        }

        // Verify the ring's view of remaining count.
        let head = ring.head.load(Ordering::Relaxed);
        let tail = ring.tail.load(Ordering::Relaxed);
        let remaining = tail.wrapping_sub(head) as usize;
        assert_eq!(remaining, n - pop_count);

        // Drop happens here — Kani verifies all assume_init_drop calls
        // are in-bounds and exactly `remaining` slots are visited.
        drop(ring);
    }
}
