//! Allocation tracking for detecting hot-path allocations.
//!
//! # Purpose
//!
//! This module provides:
//! - Global allocation counting (allocs, deallocs, reallocs, bytes)
//! - `AllocGuard` for asserting regions are allocation-free
//! - Snapshot-based delta measurement
//!
//! # Usage
//!
//! ```rust,ignore
//! // In main.rs or lib.rs, enable the counting allocator:
//! #[global_allocator]
//! static ALLOC: scheduler::alloc::CountingAllocator = scheduler::alloc::CountingAllocator;
//!
//! // In hot paths:
//! let guard = AllocGuard::new();
//! // ... hot path code ...
//! guard.assert_no_alloc(); // Panics if any allocations occurred
//! ```
//!
//! # Multi-threaded Limitation
//!
//! **WARNING**: Statistics are global, not per-thread. In multi-threaded code,
//! allocations from *any* thread will be counted. This means:
//!
//! - `AllocGuard::assert_no_alloc()` may false-positive if other threads allocate
//! - For accurate hot-path measurement, ensure the measured region is single-threaded
//!   or accept cross-thread noise
//!
//! For multi-threaded schedulers, use this for:
//! - Coarse "did we allocate way more than expected?" checks
//! - Single-threaded microbenchmarks of isolated components
//! - NOT for precise "this exact code path allocated zero bytes"
//!
//! # Performance
//!
//! The counting allocator adds ~10-50ns overhead per allocation in single-threaded
//! code. Under heavy multi-threaded contention, this can increase significantly
//! due to cache-line bouncing. Counters are cache-padded to reduce false sharing.
//!
//! This module is intended for debugging and benchmarking, not production use.
//! It is compiled unconditionally; callers opt in by setting the
//! `CountingAllocator` as the global allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Cache-padded atomics to prevent false sharing
// ============================================================================

/// Cache-line padded atomic to prevent false sharing.
///
/// # Why a Wrapper?
///
/// Rust's `#[repr(align)]` cannot be applied directly to type aliases, and
/// `AtomicU64` itself is only 8-byte aligned. This wrapper forces 64-byte
/// alignment so each counter occupies its own cache line.
///
/// On most x86_64 systems, cache lines are 64 bytes. Padding ensures each
/// counter gets its own cache line, eliminating cross-core contention.
#[repr(align(64))]
struct PaddedAtomicU64(AtomicU64);

impl PaddedAtomicU64 {
    const fn new(v: u64) -> Self {
        Self(AtomicU64::new(v))
    }

    #[inline]
    fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    #[inline]
    fn fetch_add(&self, val: u64, order: Ordering) -> u64 {
        self.0.fetch_add(val, order)
    }

    #[inline]
    fn fetch_sub(&self, val: u64, order: Ordering) -> u64 {
        self.0.fetch_sub(val, order)
    }

    #[inline]
    fn fetch_max(&self, val: u64, order: Ordering) -> u64 {
        self.0.fetch_max(val, order)
    }
}

// ============================================================================
// Global allocation counters
// ============================================================================

/// Number of allocations since program start.
static ALLOC_COUNT: PaddedAtomicU64 = PaddedAtomicU64::new(0);

/// Number of deallocations since program start.
static DEALLOC_COUNT: PaddedAtomicU64 = PaddedAtomicU64::new(0);

/// Number of reallocations since program start.
static REALLOC_COUNT: PaddedAtomicU64 = PaddedAtomicU64::new(0);

/// Bytes added to live allocation total (grows on alloc, shrinks on dealloc).
///
/// Combined with `DEALLOC_BYTES`, approximates current heap usage:
/// `live_bytes â‰ˆ alloc_bytes - dealloc_bytes`
///
/// Note: This is a ledger, not a cumulative total. Realloc adjusts the
/// difference, not both sides.
static ALLOC_BYTES: PaddedAtomicU64 = PaddedAtomicU64::new(0);

/// Bytes removed from live allocation total.
///
/// See `ALLOC_BYTES` for semantics.
static DEALLOC_BYTES: PaddedAtomicU64 = PaddedAtomicU64::new(0);

/// Current number of live allocations (allocs - deallocs).
///
/// # Concurrency Note
///
/// Uses wrapping arithmetic (`fetch_sub`), so under heavy concurrent access
/// this counter may temporarily wrap to a large value if deallocs race ahead
/// of allocs. Consumers should use `alloc_count - dealloc_count` from a
/// snapshot for reliable values, or accept that `live_allocs` is approximate.
static LIVE_ALLOCS: PaddedAtomicU64 = PaddedAtomicU64::new(0);

/// Peak number of simultaneous live allocations observed.
static PEAK_LIVE_ALLOCS: PaddedAtomicU64 = PaddedAtomicU64::new(0);

// ============================================================================
// Statistics snapshot
// ============================================================================

/// Snapshot of allocation statistics at a point in time.
///
/// # Consistency
///
/// Fields are read independently with relaxed ordering. Under concurrent
/// allocation, values may be mutually inconsistent (e.g., `dealloc_count`
/// might briefly exceed `alloc_count`). For accurate measurements, ensure
/// the measured region is single-threaded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocStats {
    /// Total allocation calls.
    pub alloc_count: u64,
    /// Total deallocation calls.
    pub dealloc_count: u64,
    /// Total reallocation calls.
    pub realloc_count: u64,
    /// Bytes added to live allocation ledger.
    pub alloc_bytes: u64,
    /// Bytes removed from live allocation ledger.
    pub dealloc_bytes: u64,
    /// Current live allocation count (approximate).
    pub live_allocs: u64,
    /// Peak live allocations observed.
    pub peak_live_allocs: u64,
}

impl AllocStats {
    /// Approximate current live bytes (alloc_bytes - dealloc_bytes).
    ///
    /// Uses saturating subtraction to handle concurrent race conditions.
    #[inline]
    pub fn live_bytes(&self) -> u64 {
        self.alloc_bytes.saturating_sub(self.dealloc_bytes)
    }

    /// Computes the delta from a previous snapshot to this one.
    pub fn since(&self, earlier: &AllocStats) -> AllocStatsDelta {
        AllocStatsDelta {
            allocs: self.alloc_count.saturating_sub(earlier.alloc_count),
            deallocs: self.dealloc_count.saturating_sub(earlier.dealloc_count),
            reallocs: self.realloc_count.saturating_sub(earlier.realloc_count),
            bytes_allocated: self.alloc_bytes.saturating_sub(earlier.alloc_bytes),
            bytes_deallocated: self.dealloc_bytes.saturating_sub(earlier.dealloc_bytes),
        }
    }
}

/// Returns current global allocation statistics.
///
/// # Consistency Note
///
/// Statistics are read with relaxed ordering and may be mutually inconsistent
/// under concurrent allocation. For accurate measurements, ensure the measured
/// code path is single-threaded or use external synchronization.
pub fn alloc_stats() -> AllocStats {
    AllocStats {
        alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
        realloc_count: REALLOC_COUNT.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_bytes: DEALLOC_BYTES.load(Ordering::Relaxed),
        live_allocs: LIVE_ALLOCS.load(Ordering::Relaxed),
        peak_live_allocs: PEAK_LIVE_ALLOCS.load(Ordering::Relaxed),
    }
}

// NOTE: reset_alloc_stats() has been intentionally removed.
//
// Resetting global counters while allocations exist causes:
// - LIVE_ALLOCS underflow on subsequent deallocs
// - Corrupted live_bytes calculations
// - Meaningless peak values
//
// Use snapshot deltas instead: `alloc_stats().since(&earlier_snapshot)`

// ============================================================================
// Statistics delta
// ============================================================================

/// Change in allocation statistics between two snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocStatsDelta {
    /// New allocations in this period.
    pub allocs: u64,
    /// Deallocations in this period.
    pub deallocs: u64,
    /// Reallocations in this period.
    pub reallocs: u64,
    /// Bytes added to ledger in this period.
    pub bytes_allocated: u64,
    /// Bytes removed from ledger in this period.
    pub bytes_deallocated: u64,
}

impl AllocStatsDelta {
    /// Returns true if no new allocations occurred.
    ///
    /// Note: This ignores deallocations. Use `is_heap_op_free()` to detect
    /// any allocator traffic (alloc, dealloc, or realloc).
    #[inline]
    pub fn is_allocation_free(&self) -> bool {
        self.allocs == 0 && self.reallocs == 0
    }

    /// Returns true if no allocator operations occurred at all.
    ///
    /// This is stricter than `is_allocation_free()` - it also requires
    /// zero deallocations. Use this when you want to verify a hot path
    /// has zero allocator traffic (for throughput stability).
    #[inline]
    pub fn is_heap_op_free(&self) -> bool {
        self.allocs == 0 && self.deallocs == 0 && self.reallocs == 0
    }

    /// Net change in live bytes (may be negative if more freed than allocated).
    #[inline]
    pub fn net_bytes(&self) -> i64 {
        self.bytes_allocated as i64 - self.bytes_deallocated as i64
    }
}

impl std::fmt::Display for AllocStatsDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "allocs={} deallocs={} reallocs={} bytes=+{}/-{}",
            self.allocs, self.deallocs, self.reallocs, self.bytes_allocated, self.bytes_deallocated
        )
    }
}

// ============================================================================
// Scoped allocation guard
// ============================================================================

/// RAII guard for detecting allocations in a code region.
///
/// # Behavior
///
/// - On creation, captures current allocation stats
/// - On `assert_no_alloc()`, panics if any allocations occurred
/// - On drop (if not consumed), panics if allocations occurred
///
/// # Multi-threaded Warning
///
/// This uses global counters. Allocations from *any* thread will trigger
/// the assertion, not just the guarded thread. For multi-threaded code,
/// either accept this limitation or ensure other threads are idle.
///
/// # Example
///
/// ```rust,ignore
/// let guard = AllocGuard::new();
/// // Hot path that should not allocate
/// process_chunk(&data);
/// guard.assert_no_alloc(); // Panics if allocations detected
/// ```
pub struct AllocGuard {
    start: AllocStats,
    consumed: bool,
}

impl AllocGuard {
    /// Creates a new guard, capturing current allocation stats.
    pub fn new() -> Self {
        Self {
            start: alloc_stats(),
            consumed: false,
        }
    }

    /// Returns the allocation delta since guard creation.
    ///
    /// Consumes the guard (prevents panic on drop).
    pub fn finish(mut self) -> AllocStatsDelta {
        self.consumed = true;
        alloc_stats().since(&self.start)
    }

    /// Asserts that no allocations occurred since guard creation.
    ///
    /// # Panics
    ///
    /// Panics if any allocations or reallocations occurred.
    pub fn assert_no_alloc(mut self) {
        self.consumed = true;
        let delta = alloc_stats().since(&self.start);
        assert!(
            delta.is_allocation_free(),
            "Hot path violated: allocation detected! {}",
            delta
        );
    }

    /// Asserts that no allocator operations occurred (alloc, dealloc, or realloc).
    ///
    /// Stricter than `assert_no_alloc()`.
    pub fn assert_no_heap_ops(mut self) {
        self.consumed = true;
        let delta = alloc_stats().since(&self.start);
        assert!(
            delta.is_heap_op_free(),
            "Hot path violated: heap operation detected! {}",
            delta
        );
    }
}

impl Default for AllocGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AllocGuard {
    fn drop(&mut self) {
        // Don't panic if we're already panicking (avoid double panic)
        if self.consumed || std::thread::panicking() {
            return;
        }

        let delta = alloc_stats().since(&self.start);
        if !delta.is_allocation_free() {
            // Panic to fail the test/benchmark
            panic!(
                "AllocGuard dropped without checking - allocations detected! {}",
                delta
            );
        }
    }
}

// ============================================================================
// Counting allocator
// ============================================================================

/// A wrapper around the system allocator that counts allocations.
///
/// # Usage
///
/// ```rust,ignore
/// #[global_allocator]
/// static ALLOC: CountingAllocator = CountingAllocator;
/// ```
///
/// # Performance Warning
///
/// This adds overhead to every allocation:
/// - ~10-50ns in single-threaded code
/// - Higher under multi-threaded contention (cache-line bouncing)
///
/// Counters are cache-padded to reduce false sharing, but global atomics
/// still serialize under high contention.
///
/// Use only for debugging and benchmarking, not production.
pub struct CountingAllocator;

/// Updates peak live allocations using atomic fetch_max.
#[inline]
fn update_peak(current: u64) {
    PEAK_LIVE_ALLOCS.fetch_max(current, Ordering::Relaxed);
}

// SAFETY DOCUMENTATION FOR GlobalAlloc IMPLEMENTATION
//
// # Safety Invariants
//
// The `GlobalAlloc` trait requires:
// 1. `alloc` returns either null (on failure) or a valid, aligned pointer
// 2. `dealloc` is only called with pointers previously returned by `alloc`
// 3. `realloc` is only called with pointers previously returned by `alloc`
//
// This implementation delegates to `System` which upholds these invariants.
// The atomic counter operations are safe because:
// - All counters use relaxed ordering (no synchronization guarantees needed)
// - Counter updates are performed after successful allocation/after deallocation
// - Wrapping/overflow is handled gracefully (counters are monotonic or approximate)
//
// # Why No `# Safety` on Methods?
// SAFETY: Delegates all allocation to `System` which upholds `GlobalAlloc` invariants.
// SAFETY: All methods delegate to `System` (the default global allocator),
// only adding atomic counter updates. The `unsafe` is on the trait impl,
// not individual methods.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            let live = LIVE_ALLOCS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            update_peak(live);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        debug_assert!(!ptr.is_null(), "dealloc called with null pointer");

        System.dealloc(ptr, layout);
        DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // Wrapping sub; may temporarily produce large values under concurrent access
        LIVE_ALLOCS.fetch_sub(1, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            REALLOC_COUNT.fetch_add(1, Ordering::Relaxed);

            let old_size = layout.size() as u64;
            let new_size_u64 = new_size as u64;

            // Track net change in bytes (realloc doesn't change alloc count)
            if new_size_u64 > old_size {
                ALLOC_BYTES.fetch_add(new_size_u64 - old_size, Ordering::Relaxed);
            } else {
                DEALLOC_BYTES.fetch_add(old_size - new_size_u64, Ordering::Relaxed);
            }
        }
        new_ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            let live = LIVE_ALLOCS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            update_peak(live);
        }
        ptr
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize tests that touch global state
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn alloc_stats_returns_valid_snapshot() {
        let stats = alloc_stats();
        // Basic sanity: counts should be non-negative (they're u64)
        // and peak should be >= current live
        assert!(stats.peak_live_allocs >= stats.live_allocs);
    }

    #[test]
    fn alloc_stats_delta_basic() {
        let earlier = AllocStats {
            alloc_count: 10,
            dealloc_count: 5,
            realloc_count: 2,
            alloc_bytes: 1000,
            dealloc_bytes: 500,
            live_allocs: 5,
            peak_live_allocs: 8,
        };

        let later = AllocStats {
            alloc_count: 15,
            dealloc_count: 8,
            realloc_count: 3,
            alloc_bytes: 1500,
            dealloc_bytes: 800,
            live_allocs: 7,
            peak_live_allocs: 10,
        };

        let delta = later.since(&earlier);
        assert_eq!(delta.allocs, 5);
        assert_eq!(delta.deallocs, 3);
        assert_eq!(delta.reallocs, 1);
        assert_eq!(delta.bytes_allocated, 500);
        assert_eq!(delta.bytes_deallocated, 300);
        assert_eq!(delta.net_bytes(), 200);
    }

    #[test]
    fn alloc_stats_delta_saturates_on_underflow() {
        let later = AllocStats::default();
        let earlier = AllocStats {
            alloc_count: 100,
            ..Default::default()
        };

        // If somehow later < earlier (concurrent race), saturate to 0
        let delta = later.since(&earlier);
        assert_eq!(delta.allocs, 0);
    }

    #[test]
    fn alloc_stats_delta_is_allocation_free() {
        let delta = AllocStatsDelta {
            allocs: 0,
            deallocs: 5, // deallocs don't count
            reallocs: 0,
            bytes_allocated: 0,
            bytes_deallocated: 100,
        };
        assert!(delta.is_allocation_free());

        let delta_with_alloc = AllocStatsDelta {
            allocs: 1,
            ..Default::default()
        };
        assert!(!delta_with_alloc.is_allocation_free());

        let delta_with_realloc = AllocStatsDelta {
            reallocs: 1,
            ..Default::default()
        };
        assert!(!delta_with_realloc.is_allocation_free());
    }

    #[test]
    fn alloc_stats_delta_is_heap_op_free() {
        let delta = AllocStatsDelta::default();
        assert!(delta.is_heap_op_free());

        // Any operation makes it not free
        let delta_alloc = AllocStatsDelta {
            allocs: 1,
            ..Default::default()
        };
        assert!(!delta_alloc.is_heap_op_free());

        let delta_dealloc = AllocStatsDelta {
            deallocs: 1,
            ..Default::default()
        };
        assert!(!delta_dealloc.is_heap_op_free());

        let delta_realloc = AllocStatsDelta {
            reallocs: 1,
            ..Default::default()
        };
        assert!(!delta_realloc.is_heap_op_free());
    }

    #[test]
    fn alloc_stats_delta_display() {
        let delta = AllocStatsDelta {
            allocs: 10,
            deallocs: 5,
            reallocs: 2,
            bytes_allocated: 1000,
            bytes_deallocated: 500,
        };
        let s = format!("{}", delta);
        assert!(s.contains("allocs=10"));
        assert!(s.contains("deallocs=5"));
        assert!(s.contains("reallocs=2"));
        assert!(s.contains("+1000"));
        assert!(s.contains("-500"));
    }

    #[test]
    fn alloc_stats_live_bytes() {
        let stats = AllocStats {
            alloc_bytes: 1000,
            dealloc_bytes: 300,
            ..Default::default()
        };
        assert_eq!(stats.live_bytes(), 700);
    }

    #[test]
    fn alloc_stats_live_bytes_saturates() {
        let stats = AllocStats {
            alloc_bytes: 100,
            dealloc_bytes: 200, // More freed than allocated (race condition)
            ..Default::default()
        };
        assert_eq!(stats.live_bytes(), 0); // Saturates, doesn't wrap
    }

    #[test]
    fn alloc_guard_finish_returns_delta() {
        let _lock = TEST_LOCK.lock().unwrap();

        let guard = AllocGuard::new();
        let delta = guard.finish();
        // Delta should be valid (specific values depend on test runner allocations)
        // delta.allocs is u64, so always >= 0; just verify finish() returns something usable
        let _ = delta.allocs;
    }

    #[test]
    fn alloc_guard_consumed_does_not_panic_on_drop() {
        let _lock = TEST_LOCK.lock().unwrap();

        let guard = AllocGuard::new();
        let _ = guard.finish(); // Consumes the guard
                                // Drop happens here - should not panic
    }

    #[test]
    fn padded_atomic_is_cache_line_sized() {
        // Verify our cache padding works
        assert_eq!(std::mem::align_of::<PaddedAtomicU64>(), 64);
        assert!(std::mem::size_of::<PaddedAtomicU64>() >= 64);
    }

    #[test]
    fn padded_atomics_are_separate_cache_lines() {
        // Verify counters don't share cache lines
        let alloc_addr = &ALLOC_COUNT as *const _ as usize;
        let dealloc_addr = &DEALLOC_COUNT as *const _ as usize;

        // They should be at least 64 bytes apart
        let diff = alloc_addr.abs_diff(dealloc_addr);
        assert!(diff >= 64, "Counters share cache line: diff={}", diff);
    }

    // Test that verifies AllocGuard panics on drop if not consumed
    // This is tricky to test without actually panicking, so we verify the logic
    #[test]
    fn alloc_guard_default_impl() {
        let guard = AllocGuard::default();
        assert!(!guard.consumed);
        let _ = guard.finish(); // Consume to avoid panic
    }
}
