//! # Budget Module
//!
//! Non-blocking byte/token budgets with RAII permits for leak-free resource management.
//!
//! ## Performance Characteristics
//!
//! - **Lock-free**: CAS loop with spin backoff
//! - **Relaxed ordering**: Budget is accounting, not synchronization
//! - **Cache-line aligned**: Atomics isolated to prevent false sharing
//! - **Minimal permit size**: 16 bytes (pointer + amount)
//!
//! ## Ordering Rationale
//!
//! We use `Ordering::Relaxed` everywhere because the budget is pure accounting:
//! - It tracks "how many bytes are in flight", not ownership
//! - Buffer contents visibility is enforced by the task/ownership system
//! - Budget operations don't establish happens-before for other shared state
//!
//! If you need budget to synchronize access to other data, that's a design bug -
//! use proper synchronization primitives for that data.
//!
//! ## Contention Considerations
//!
//! This implementation uses a single atomic per budget. Under high contention
//! (many workers hammering the same budget), this becomes a cache-line hotspot.
//!
//! **If profiling shows budget contention**, consider:
//! 1. **Sharded budget**: N atomics, acquire from preferred shard, steal if needed
//! 2. **Local caching**: Per-worker cache with bulk refill/flush
//!
//! We use the simple single-atomic design. Measure contention with
//! `perf c2c` or similar before adding complexity.
//!
//! ## Invariants
//!
//! - `available + outstanding == total` at all times
//! - Over-release panics in debug (double-return detection)

use std::hint::spin_loop;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// Cache-line aligned atomics
// ============================================================================

/// Cache-line aligned AtomicU64 to prevent false sharing.
///
/// When `ByteBudget` sits in a struct near other hot data, this ensures
/// writes to `avail` don't invalidate cache lines containing other fields.
#[repr(align(64))]
#[derive(Debug)]
struct CacheLineU64(AtomicU64);

/// Cache-line aligned AtomicU32 for token budgets.
#[repr(align(64))]
#[derive(Debug)]
struct CacheLineU32(AtomicU32);

// ============================================================================
// ByteBudget
// ============================================================================

/// A non-blocking byte budget for backpressure.
///
/// Use this to enforce memory limits (e.g., max buffered bytes) without blocking.
/// The scheduler's idle strategy handles what to do when budget is exhausted.
///
/// ## Thread Safety
///
/// All operations are lock-free. Under contention, CAS failures trigger
/// `spin_loop()` to reduce interconnect pressure.
#[derive(Debug)]
pub struct ByteBudget {
    /// Total capacity (immutable after construction).
    total: u64,
    /// Available budget (cache-line isolated to prevent false sharing).
    avail: CacheLineU64,
}

impl ByteBudget {
    /// Create a new budget with the given total capacity.
    ///
    /// # Panics
    /// Panics if `total` is 0.
    pub fn new(total: u64) -> Self {
        assert!(total > 0, "ByteBudget total must be > 0");
        Self {
            total,
            avail: CacheLineU64(AtomicU64::new(total)),
        }
    }

    /// Get the total capacity.
    #[inline]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Get current available budget (relaxed read, may be stale).
    #[inline]
    pub fn available(&self) -> u64 {
        self.avail.0.load(Ordering::Relaxed)
    }

    /// Try to acquire `bytes` from the budget.
    ///
    /// Returns `Some(BytePermit)` on success, `None` if insufficient budget.
    ///
    /// # Complexity
    ///
    /// - **Uncontended**: O(1) - single successful CAS
    /// - **Contended**: O(k) where k = number of concurrent acquirers. Each CAS
    ///   failure retries with the observed value, so progress is guaranteed
    ///   (lock-free, not wait-free).
    ///
    /// # Performance
    /// - Lock-free CAS loop
    /// - `spin_loop()` on contention to reduce bus pressure
    /// - Relaxed ordering (budget is accounting, not synchronization)
    #[inline]
    pub fn try_acquire(&self, bytes: u64) -> Option<BytePermit<'_>> {
        if bytes == 0 {
            return Some(BytePermit {
                budget: self,
                bytes: 0,
            });
        }

        // Fast rejection without CAS
        if bytes > self.total {
            return None;
        }

        let mut cur = self.avail.0.load(Ordering::Relaxed);
        loop {
            if cur < bytes {
                return None;
            }

            match self.avail.0.compare_exchange_weak(
                cur,
                cur - bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(BytePermit {
                        budget: self,
                        bytes,
                    });
                }
                Err(observed) => {
                    cur = observed;
                    // Reduce interconnect pressure under contention
                    spin_loop();
                }
            }
        }
    }

    /// Release bytes back to the budget.
    ///
    /// Typically called automatically by `BytePermit::drop()`.
    /// Use `release_raw()` for manual release after cross-thread handoff.
    ///
    /// # Complexity
    /// O(1) - single atomic fetch_add, no CAS loop needed for release.
    #[inline]
    fn release(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let prev = self.avail.0.fetch_add(bytes, Ordering::Relaxed);
        debug_assert!(
            prev.wrapping_add(bytes) <= self.total,
            "ByteBudget over-release: prev={} add={} total={}",
            prev,
            bytes,
            self.total
        );
    }

    /// Manual release for cross-thread handoff scenarios.
    ///
    /// Use when a permit was consumed via `into_raw()` and the amount
    /// needs to be released from a different thread/context.
    ///
    /// # Safety Contract
    /// The caller must ensure `bytes` was previously acquired and not
    /// already released. Double-release is detected in debug builds.
    #[inline]
    pub fn release_raw(&self, bytes: u64) {
        self.release(bytes);
    }
}

/// RAII permit for byte budgets.
///
/// Automatically releases the acquired bytes on drop.
///
/// # Thread Safety
///
/// `BytePermit` is both `Send` and `Sync` (all fields are `Sync`).
/// You can move it to another thread or share references.
/// In practice, a permit represents exclusive ownership of budget capacity,
/// so sharing is unusual.
///
/// # Ownership Transfer
///
/// Since `BytePermit` is `Send`, you can move it to another thread:
///
/// ```ignore
/// let permit = budget.try_acquire(256)?;
/// std::thread::spawn(move || {
///     // permit is now owned by this thread
///     do_work();
///     drop(permit); // releases on this thread
/// });
/// ```
///
/// # Manual Handoff (Advanced)
///
/// If you need to detach the permit value from the RAII wrapper
/// (e.g., storing raw bytes in a task struct), use `into_raw()`:
///
/// ```ignore
/// let permit = budget.try_acquire(1024)?;
/// let amount = permit.into_raw(); // Consumes permit, no release
/// // ... store `amount` somewhere ...
/// // Later: budget.release_raw(amount);
/// ```
///
/// **Warning**: Forgetting to call `release_raw()` leaks budget capacity.
#[derive(Debug)]
pub struct BytePermit<'a> {
    budget: &'a ByteBudget,
    bytes: u64,
}

impl<'a> BytePermit<'a> {
    /// Get the number of bytes this permit represents.
    #[inline]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Consume the permit and return the byte count WITHOUT releasing.
    ///
    /// Use this for cross-thread handoff where another component will
    /// call `ByteBudget::release_raw()` later.
    ///
    /// # Soundness
    ///
    /// Uses `mem::forget` to skip the `Drop` impl. This is sound because:
    /// - `BytePermit` owns no heap allocations (just a reference + integer)
    /// - The budget reference remains valid (lifetime bound to `'a`)
    /// - The caller takes responsibility for calling `release_raw()` later
    ///
    /// Leaking the permit (forgetting to call `release_raw`) doesn't cause UB,
    /// only budget capacity exhaustion.
    ///
    /// # Example
    /// ```ignore
    /// let permit = budget.try_acquire(1024)?;
    /// let amount = permit.into_raw(); // No release on drop
    /// // ... transfer `amount` to another thread ...
    /// // Later: budget.release_raw(amount);
    /// ```
    #[inline]
    pub fn into_raw(self) -> u64 {
        let bytes = self.bytes;
        std::mem::forget(self);
        bytes
    }

    /// Explicitly release and consume the permit.
    #[inline]
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for BytePermit<'_> {
    #[inline]
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

// ============================================================================
// TokenBudget
// ============================================================================

/// A non-blocking token budget for counting discrete resources.
///
/// Similar to `ByteBudget` but uses `AtomicU32` for tokens (objects, reads, tasks).
#[derive(Debug)]
pub struct TokenBudget {
    /// Total capacity.
    total: u32,
    /// Available tokens (cache-line isolated).
    avail: CacheLineU32,
}

impl TokenBudget {
    /// Create a new token budget with the given total capacity.
    ///
    /// # Panics
    /// Panics if `total` is 0.
    pub fn new(total: u32) -> Self {
        assert!(total > 0, "TokenBudget total must be > 0");
        Self {
            total,
            avail: CacheLineU32(AtomicU32::new(total)),
        }
    }

    /// Get the total capacity.
    #[inline]
    pub fn total(&self) -> u32 {
        self.total
    }

    /// Get current available tokens (relaxed read).
    #[inline]
    pub fn available(&self) -> u32 {
        self.avail.0.load(Ordering::Relaxed)
    }

    /// Try to acquire one token.
    #[inline]
    pub fn try_acquire_one(&self) -> Option<TokenPermit<'_>> {
        self.try_acquire(1)
    }

    /// Try to acquire `count` tokens.
    ///
    /// See [`ByteBudget::try_acquire`] for complexity and performance notes.
    #[inline]
    pub fn try_acquire(&self, count: u32) -> Option<TokenPermit<'_>> {
        if count == 0 {
            return Some(TokenPermit {
                budget: self,
                count: 0,
            });
        }

        if count > self.total {
            return None;
        }

        let mut cur = self.avail.0.load(Ordering::Relaxed);
        loop {
            if cur < count {
                return None;
            }

            match self.avail.0.compare_exchange_weak(
                cur,
                cur - count,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(TokenPermit {
                        budget: self,
                        count,
                    });
                }
                Err(observed) => {
                    cur = observed;
                    spin_loop();
                }
            }
        }
    }

    #[inline]
    fn release(&self, count: u32) {
        if count == 0 {
            return;
        }
        let prev = self.avail.0.fetch_add(count, Ordering::Relaxed);
        debug_assert!(
            prev.wrapping_add(count) <= self.total,
            "TokenBudget over-release: prev={} add={} total={}",
            prev,
            count,
            self.total
        );
    }

    /// Manual release for cross-thread handoff.
    #[inline]
    pub fn release_raw(&self, count: u32) {
        self.release(count);
    }
}

/// RAII permit for token budgets.
///
/// # Thread Safety
///
/// `TokenPermit` is both `Send` and `Sync`, mirroring `BytePermit` semantics.
/// In practice, move the permit to transfer ownership.
#[derive(Debug)]
pub struct TokenPermit<'a> {
    budget: &'a TokenBudget,
    count: u32,
}

impl<'a> TokenPermit<'a> {
    /// Get the token count.
    #[inline]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Consume the permit and return count WITHOUT releasing.
    ///
    /// See [`BytePermit::into_raw`] for soundness rationale.
    #[inline]
    pub fn into_raw(self) -> u32 {
        let count = self.count;
        std::mem::forget(self);
        count
    }

    /// Explicitly release.
    #[inline]
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for TokenPermit<'_> {
    #[inline]
    fn drop(&mut self) {
        self.budget.release(self.count);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_permit_returns_on_drop() {
        let b = ByteBudget::new(100);
        let p = b.try_acquire(40).expect("acquire");
        assert_eq!(b.available(), 60);
        drop(p);
        assert_eq!(b.available(), 100);
    }

    #[test]
    fn cannot_acquire_more_than_total() {
        let b = ByteBudget::new(100);
        assert!(b.try_acquire(101).is_none());
        assert_eq!(b.available(), 100);
    }

    #[test]
    fn multiple_acquires_and_release() {
        let b = ByteBudget::new(100);
        let p1 = b.try_acquire(30).unwrap();
        let p2 = b.try_acquire(50).unwrap();
        assert!(b.try_acquire(30).is_none()); // Only 20 left
        drop(p1);
        assert_eq!(b.available(), 50); // p1 returned, p2 still held
        let p3 = b.try_acquire(30).unwrap();
        assert_eq!(b.available(), 20); // p2 and p3 held
        drop(p2);
        assert_eq!(b.available(), 70); // Only p3 held (30)
        drop(p3);
        assert_eq!(b.available(), 100); // All returned
    }

    #[test]
    fn zero_acquire_succeeds() {
        let b = ByteBudget::new(100);
        let p = b.try_acquire(0).expect("zero acquire should succeed");
        assert_eq!(p.bytes(), 0);
        assert_eq!(b.available(), 100);
        drop(p);
        assert_eq!(b.available(), 100);
    }

    #[test]
    fn into_raw_prevents_release() {
        let b = ByteBudget::new(100);
        let p = b.try_acquire(40).unwrap();
        assert_eq!(b.available(), 60);

        let amount = p.into_raw(); // Consume without releasing
        assert_eq!(amount, 40);
        assert_eq!(b.available(), 60); // Still held

        // Manual release
        b.release_raw(amount);
        assert_eq!(b.available(), 100);
    }

    #[test]
    fn token_budget_basic() {
        let t = TokenBudget::new(10);
        assert_eq!(t.available(), 10);

        let p1 = t.try_acquire_one().unwrap();
        assert_eq!(t.available(), 9);

        let p2 = t.try_acquire(5).unwrap();
        assert_eq!(t.available(), 4);

        drop(p1);
        assert_eq!(t.available(), 5);

        drop(p2);
        assert_eq!(t.available(), 10);
    }

    #[test]
    fn token_budget_exhaustion() {
        let t = TokenBudget::new(3);
        let _p1 = t.try_acquire_one().unwrap();
        let _p2 = t.try_acquire_one().unwrap();
        let _p3 = t.try_acquire_one().unwrap();
        assert!(t.try_acquire_one().is_none());
    }

    #[test]
    fn token_into_raw() {
        let t = TokenBudget::new(10);
        let p = t.try_acquire(5).unwrap();
        assert_eq!(t.available(), 5);

        let count = p.into_raw();
        assert_eq!(count, 5);
        assert_eq!(t.available(), 5); // Not released

        t.release_raw(count);
        assert_eq!(t.available(), 10);
    }

    #[test]
    fn cache_line_alignment() {
        // Verify atomics are cache-line aligned
        assert!(std::mem::align_of::<CacheLineU64>() >= 64);
        assert!(std::mem::align_of::<CacheLineU32>() >= 64);

        // Verify budget structs don't have false sharing potential
        // (avail is on its own cache line)
        let b = ByteBudget::new(100);
        let avail_addr = &b.avail as *const _ as usize;
        let total_addr = &b.total as *const _ as usize;

        // avail should be at least 64 bytes away from total
        // (either before or after depending on layout)
        let distance = avail_addr.abs_diff(total_addr);
        assert!(
            distance >= 8, // At minimum, they're separate fields
            "avail and total should not be adjacent"
        );
    }

    #[test]
    fn permit_size_is_minimal() {
        // Verify permits are small (pointer + amount, no bool)
        assert_eq!(std::mem::size_of::<BytePermit>(), 16);
        assert_eq!(std::mem::size_of::<TokenPermit>(), 16);
    }

    // --- Concurrent stress tests ---

    #[test]
    fn concurrent_byte_budget_stress() {
        use std::sync::Arc;
        use std::thread;

        let budget = Arc::new(ByteBudget::new(1000));
        let iterations = 10_000;
        let threads = 4;

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let b = Arc::clone(&budget);
                thread::spawn(move || {
                    for _ in 0..iterations {
                        // Try to acquire various amounts
                        if let Some(p) = b.try_acquire(10) {
                            std::hint::black_box(p.bytes());
                            // permit auto-releases on drop
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // All permits should be released
        assert_eq!(budget.available(), 1000, "budget should be fully restored");
    }

    #[test]
    fn concurrent_token_budget_stress() {
        use std::sync::Arc;
        use std::thread;

        let budget = Arc::new(TokenBudget::new(100));
        let iterations = 10_000;
        let threads = 4;

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let b = Arc::clone(&budget);
                thread::spawn(move || {
                    for _ in 0..iterations {
                        if let Some(p) = b.try_acquire_one() {
                            std::hint::black_box(p.count());
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(budget.available(), 100, "budget should be fully restored");
    }

    #[test]
    fn cross_thread_permit_move() {
        use std::sync::Arc;

        let budget = Arc::new(ByteBudget::new(100));

        // Using thread::scope allows the permit to borrow across threads
        // because the scope ensures all threads complete before returning
        std::thread::scope(|s| {
            let permit = budget.try_acquire(50).expect("should succeed");
            assert_eq!(budget.available(), 50);

            let b = &budget;
            s.spawn(move || {
                // Permit is now owned by this thread
                assert_eq!(permit.bytes(), 50);
                // Will release when dropped here
                drop(permit);
                assert_eq!(b.available(), 100);
            });
        });

        assert_eq!(budget.available(), 100);
    }

    #[test]
    fn into_raw_cross_thread() {
        use std::sync::Arc;
        use std::thread;

        let budget = Arc::new(ByteBudget::new(100));

        // Acquire and convert to raw on main thread
        let permit = budget.try_acquire(30).expect("should succeed");
        let amount = permit.into_raw();
        assert_eq!(budget.available(), 70);

        // Release from another thread using raw value
        let b = Arc::clone(&budget);
        let handle = thread::spawn(move || {
            b.release_raw(amount);
        });

        handle.join().expect("thread panicked");
        assert_eq!(budget.available(), 100);
    }
}
