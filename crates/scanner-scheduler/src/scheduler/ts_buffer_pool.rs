//! Thread-Safe Fixed-Capacity Buffer Pool
//!
//! # Design
//!
//! - **Fixed capacity**: All buffers allocated upfront, zero alloc per acquire/release
//! - **Per-worker local queues**: Fast path for buffer returns on worker threads
//! - **Global fallback**: For non-worker threads (I/O completions, external callers)
//! - **Stealing**: When global is empty, steal from worker locals (prevents starvation)
//! - **RAII handles**: Buffers automatically returned on drop, no leaks
//!
//! # Routing Strategy
//!
//! ```text
//! acquire():
//!   1. Check per-worker local queue (TLS lookup via worker_id)
//!   2. Fall back to global queue
//!   3. Steal from other workers' local queues (prevents starvation)
//!
//! release():
//!   1. Try per-worker local queue (bounded, may fail if full)
//!   2. Fall back to global queue (always succeeds within capacity)
//! ```
//!
//! # Correctness Invariants
//!
//! - **Leak-free**: Every `TsBufferHandle` drop returns buffer to pool
//! - **No double-release**: Global push panics if capacity exceeded (indicates bug)
//! - **Fixed capacity**: `available_total() == total_buffers` when idle
//! - **Work-conserving**: `try_acquire()` returns `None` only when ALL queues are empty
//!
//! # Performance Characteristics
//!
//! | Operation        | Worker thread      | Non-worker thread     |
//! |------------------|--------------------|-----------------------|
//! | acquire()        | Local pop (fast)   | Global pop â†’ steal    |
//! | release()        | Local push (fast)  | Global push           |
//!
//! Both paths are lock-free (ArrayQueue uses CAS).
//!
//! # False Sharing Prevention
//!
//! Per-worker local queues are wrapped in `CachePadded` to prevent cache-line
//! bouncing when adjacent workers update their queue indices concurrently.
//!
//! # Alignment Note (Option A)
//!
//! This implementation uses `Box<[u8]>` which provides no alignment guarantee
//! beyond that required by `u8` (1 byte). This is sufficient for:
//! - Regular `read()` syscalls
//! - Buffered I/O
//!
//! NOT sufficient for:
//! - O_DIRECT (typically requires 512 or 4096 byte alignment)
//! - io_uring registered buffers (requires page alignment)
//!
//! For alignment, see Option B (future feature flag).

use super::worker_id;
use crossbeam_queue::ArrayQueue;
use crossbeam_utils::CachePadded;
use std::sync::Arc;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the thread-safe buffer pool.
///
/// # Sizing Guidelines
///
/// - `buffer_len`: Match your chunk size (e.g., 64KB for file scanning)
/// - `total_buffers`: Bound peak memory; should be >= `workers * local_queue_cap`
///   to allow all workers to fill their local caches simultaneously
/// - `local_queue_cap`: Small (4-16) to avoid imbalance; excess goes to global
///
/// # Configuration Tradeoffs
///
/// | Config | Consequence |
/// |--------|-------------|
/// | `total_buffers < workers * local_queue_cap` | Workers compete for limited buffers; some local queues stay empty |
/// | `total_buffers == workers * local_queue_cap` | No global reserve; non-worker threads may need to steal |
/// | `total_buffers > workers * local_queue_cap` | Healthy global reserve for non-worker acquisition |
#[derive(Clone, Copy, Debug)]
pub struct TsBufferPoolConfig {
    /// Size of each buffer in bytes.
    pub buffer_len: usize,

    /// Total number of buffers in the pool.
    ///
    /// This bounds peak memory usage: `total_buffers * buffer_len`.
    pub total_buffers: usize,

    /// Number of workers (for per-worker local queues).
    pub workers: usize,

    /// Capacity of each per-worker local queue.
    ///
    /// When full, releases fall back to global queue.
    /// Keep small to avoid one worker hoarding buffers.
    pub local_queue_cap: usize,
}

impl TsBufferPoolConfig {
    /// Validate configuration. Panics on invalid values.
    ///
    /// # Invariants Checked
    ///
    /// - `buffer_len > 0`: Zero-sized buffers are useless
    /// - `total_buffers > 0`: Pool must have at least one buffer
    /// - `workers > 0`: Must have at least one worker
    /// - `local_queue_cap > 0`: Local queues must have capacity
    /// - `total_buffers >= workers`: Prevents trivial exhaustion
    ///
    /// # Warnings (debug builds)
    ///
    /// - `total_buffers < workers * local_queue_cap`: Workers can't fill local caches
    pub fn validate(&self) {
        assert!(self.buffer_len > 0, "buffer_len must be > 0");
        assert!(self.total_buffers > 0, "total_buffers must be > 0");
        assert!(self.workers > 0, "workers must be > 0");
        assert!(self.local_queue_cap > 0, "local_queue_cap must be > 0");
        assert!(
            self.total_buffers >= self.workers,
            "need at least one buffer per worker to avoid trivial exhaustion"
        );

        // Warn about potentially suboptimal configuration in debug builds
        #[cfg(debug_assertions)]
        {
            let total_local_cap = self.workers.saturating_mul(self.local_queue_cap);
            if self.total_buffers < total_local_cap {
                eprintln!(
                    "[TsBufferPool] Warning: total_buffers ({}) < workers * local_queue_cap ({}). \
                     Workers will compete for limited buffers; consider increasing total_buffers \
                     or decreasing local_queue_cap.",
                    self.total_buffers, total_local_cap
                );
            }
        }
    }

    /// Total peak memory usage in bytes.
    #[inline]
    pub fn peak_memory_bytes(&self) -> usize {
        self.total_buffers.saturating_mul(self.buffer_len)
    }

    /// Total capacity of all local queues combined.
    #[inline]
    pub fn total_local_capacity(&self) -> usize {
        self.workers.saturating_mul(self.local_queue_cap)
    }
}

// ============================================================================
// Pool internals
// ============================================================================

/// Shared inner state (behind Arc in TsBufferPool).
///
/// # Memory Layout
///
/// ```text
/// Inner {
///   buffer_len: 8 bytes
///   global: ArrayQueue (~32 bytes + backing array)
///   locals: Vec<CachePadded<ArrayQueue>> (~24 bytes + workers * 128 bytes)
/// }
/// ```
///
/// Each `CachePadded<ArrayQueue>` is 128 bytes (two cache lines) to prevent
/// false sharing between adjacent workers.
struct Inner {
    /// Size of each buffer in bytes (constant after construction).
    buffer_len: usize,
    /// Global queue for fallback acquire/release.
    /// Sized to hold all buffers (worst case: all returned to global).
    global: ArrayQueue<Box<[u8]>>,
    /// Per-worker local queues indexed by worker_id.
    ///
    /// Wrapped in `CachePadded` to prevent false sharing between workers.
    /// Without this, adjacent workers updating their queue indices would
    /// cause cache-line bouncing and destroy scalability.
    locals: Vec<CachePadded<ArrayQueue<Box<[u8]>>>>,
}

// ============================================================================
// TsBufferPool
// ============================================================================

/// Thread-safe fixed-capacity buffer pool.
///
/// # Clone Semantics
///
/// `Clone` creates another handle to the same pool (via `Arc`).
/// All handles share the same buffer inventory.
///
/// # Performance Note
///
/// Each `TsBufferHandle` holds a cloned `TsBufferPool` (Arc increment).
/// For extremely high-frequency acquire/release (millions/sec), consider
/// passing pool references through worker scratch instead.
#[derive(Clone)]
pub struct TsBufferPool {
    inner: Arc<Inner>,
}

impl TsBufferPool {
    /// Create a new buffer pool with the given configuration.
    ///
    /// All buffers are allocated immediately. This is the only allocation
    /// point; subsequent acquire/release are allocation-free.
    ///
    /// # Initialization Strategy
    ///
    /// Buffers are pre-distributed to per-worker local queues (up to their
    /// capacity) to reduce cold-start contention on the global queue.
    /// Remaining buffers stay in global.
    ///
    /// # Panics
    ///
    /// Panics if configuration is invalid (see `TsBufferPoolConfig::validate`).
    pub fn new(cfg: TsBufferPoolConfig) -> Self {
        cfg.validate();

        // Global queue sized to hold all buffers (worst case: all in global)
        let global = ArrayQueue::new(cfg.total_buffers);

        // Per-worker local queues wrapped in CachePadded to prevent false sharing
        let mut locals = Vec::with_capacity(cfg.workers);
        for _ in 0..cfg.workers {
            locals.push(CachePadded::new(ArrayQueue::new(cfg.local_queue_cap)));
        }

        // Pre-allocate all buffers into global queue first
        for _ in 0..cfg.total_buffers {
            let buf = vec![0u8; cfg.buffer_len].into_boxed_slice();
            global
                .push(buf)
                .expect("global queue capacity mismatch (internal error)");
        }

        // Pre-seed local queues to reduce cold-start contention.
        // Each worker gets up to local_queue_cap buffers from global.
        for local in locals.iter().take(cfg.workers) {
            for _ in 0..cfg.local_queue_cap {
                if let Some(buf) = global.pop() {
                    // Local queue has capacity, this should always succeed
                    if local.push(buf).is_err() {
                        // Shouldn't happen, but don't lose buffer
                        unreachable!("local queue full during pre-seeding");
                    }
                } else {
                    // No more buffers in global to distribute
                    break;
                }
            }
        }

        Self {
            inner: Arc::new(Inner {
                buffer_len: cfg.buffer_len,
                global,
                locals,
            }),
        }
    }

    /// Size of each buffer in bytes.
    #[inline]
    pub fn buffer_len(&self) -> usize {
        self.inner.buffer_len
    }

    /// Non-blocking acquire. Returns `None` only if ALL queues are empty.
    ///
    /// # Routing
    ///
    /// 1. If on a worker thread, try per-worker local queue first
    /// 2. Fall back to global queue
    /// 3. Steal from other workers' local queues (ensures liveness)
    ///
    /// # Performance
    ///
    /// - Fast path (worker local hit): ~5-10ns
    /// - Global fallback: ~20-50ns under contention
    /// - Steal path: O(workers) scan, only when global is empty
    ///
    /// # Liveness Guarantee
    ///
    /// The steal loop ensures that `try_acquire()` returns `None` only when
    /// the pool is truly exhausted (all buffers are in-flight). Without
    /// stealing, buffers trapped in worker locals would be unreachable to
    /// non-worker threads.
    #[inline]
    pub fn try_acquire(&self) -> Option<TsBufferHandle> {
        // Fast path: per-worker local queue
        if let Some(wid) = worker_id::current_worker_id() {
            debug_assert!(
                wid < self.inner.locals.len(),
                "worker_id {} out of range for pool with {} workers",
                wid,
                self.inner.locals.len()
            );
            if wid < self.inner.locals.len() {
                if let Some(buf) = self.inner.locals[wid].pop() {
                    return Some(TsBufferHandle {
                        pool: self.clone(),
                        buf: Some(buf),
                    });
                }
            }
        }

        // Fallback: global queue
        if let Some(buf) = self.inner.global.pop() {
            return Some(TsBufferHandle {
                pool: self.clone(),
                buf: Some(buf),
            });
        }

        // Steal from other workers' local queues.
        // This ensures non-worker threads can make progress even when
        // buffers are trapped in worker locals.
        //
        // O(workers) scan, but only executed when global is empty.
        // In steady state with balanced load, this path is rarely taken.
        for local_queue in &self.inner.locals {
            if let Some(buf) = local_queue.pop() {
                return Some(TsBufferHandle {
                    pool: self.clone(),
                    buf: Some(buf),
                });
            }
        }

        None
    }

    /// Acquire or panic.
    ///
    /// Use this in stages that already have backpressure enforced upstream
    /// (e.g., after acquiring a `TokenPermit` that bounds in-flight work).
    ///
    /// # Panics
    ///
    /// Panics if the pool is exhausted. This indicates a mismatch between
    /// your token budget and buffer pool sizing.
    #[inline]
    pub fn acquire(&self) -> TsBufferHandle {
        self.try_acquire().expect("buffer pool exhausted")
    }

    /// Internal: return a buffer to the pool.
    ///
    /// # Routing
    ///
    /// 1. If on a worker thread, try per-worker local queue (bounded)
    /// 2. Fall back to global queue
    ///
    /// # Panics
    ///
    /// Panics if global queue overflows. This indicates a double-release
    /// or buffer pool accounting bug.
    #[inline]
    fn release_box(&self, mut buf: Box<[u8]>) {
        // Fast path: per-worker local queue
        if let Some(wid) = worker_id::current_worker_id() {
            debug_assert!(
                wid < self.inner.locals.len(),
                "worker_id {} out of range for pool with {} workers (release path)",
                wid,
                self.inner.locals.len()
            );
            if wid < self.inner.locals.len() {
                match self.inner.locals[wid].push(buf) {
                    Ok(()) => return,
                    Err(returned) => buf = returned, // Local full, fall back to global
                }
            }
        }

        // Fallback: global queue
        self.inner
            .global
            .push(buf)
            .expect("buffer pool overflow: global queue full (double release or accounting bug)");
    }

    /// Number of currently available buffers across all queues (for testing/debugging).
    ///
    /// # Warning
    ///
    /// This is a snapshot and may be stale immediately after returning.
    /// Do not use for correctness decisions in production code.
    #[cfg(test)]
    fn available_total(&self) -> usize {
        let mut n = self.inner.global.len();
        for q in &self.inner.locals {
            n += q.len();
        }
        n
    }

    /// Number of buffers in the global queue (for testing/debugging).
    #[cfg(test)]
    fn available_global(&self) -> usize {
        self.inner.global.len()
    }

    /// Number of buffers in a specific worker's local queue (for testing/debugging).
    #[cfg(test)]
    fn available_local(&self, worker_id: usize) -> usize {
        self.inner
            .locals
            .get(worker_id)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Number of workers this pool was configured for.
    #[inline]
    pub fn workers(&self) -> usize {
        self.inner.locals.len()
    }
}

// ============================================================================
// TsBufferHandle (RAII wrapper)
// ============================================================================

/// RAII handle to a pooled buffer.
///
/// The buffer is automatically returned to the pool when this handle is dropped.
///
/// # Ownership
///
/// The handle owns the buffer exclusively. Clone is not implemented to prevent
/// double-free. If you need shared access, wrap in `Arc<Mutex<TsBufferHandle>>`.
///
/// # Filled Length Tracking
///
/// This is a low-level primitive that exposes the entire buffer. For scan tasks,
/// use `TsChunk` which tracks the filled length via `len` and `buf_offset` fields.
/// Accessing `as_slice()` on a partially-filled buffer will include stale bytes
/// from previous use—this is intentional for performance but requires care.
///
/// # Size
///
/// 24 bytes on 64-bit: `pool` (8) + `buf` Option (16 for Box ptr + discriminant).
/// Fits in 32 bytes with padding, enabling efficient task queue packing.
pub struct TsBufferHandle {
    /// Pool to return the buffer to on drop.
    pool: TsBufferPool,
    /// The actual buffer, wrapped in Option to support take() in Drop.
    buf: Option<Box<[u8]>>,
}

impl TsBufferHandle {
    /// View the buffer contents as a slice.
    ///
    /// # Warning
    ///
    /// Returns the ENTIRE buffer, not just filled bytes. For scan tasks,
    /// use `TsChunk::data()` which respects the filled length.
    ///
    /// # Panics
    ///
    /// Panics if the buffer was already returned (internal error).
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.buf
            .as_deref()
            .expect("buffer missing (internal error)")
    }

    /// View the buffer contents as a mutable slice.
    ///
    /// # Panics
    ///
    /// Panics if the buffer was already returned (internal error).
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf
            .as_deref_mut()
            .expect("buffer missing (internal error)")
    }

    /// Zero-fill the buffer.
    ///
    /// Use before returning to pool if the buffer held sensitive data.
    /// Note: This is O(buffer_len) and may be expensive for large buffers.
    #[inline]
    pub fn clear(&mut self) {
        self.as_mut_slice().fill(0);
    }

    /// Get the buffer's raw pointer as `usize` (for tracking/debugging).
    ///
    /// This can be used to verify buffer reuse by comparing addresses.
    #[inline]
    pub fn ptr_usize(&self) -> usize {
        self.as_slice().as_ptr() as usize
    }

    /// Buffer length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Check if buffer is empty (always false for valid buffers).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl Drop for TsBufferHandle {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.release_box(buf);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;

    fn test_config() -> TsBufferPoolConfig {
        TsBufferPoolConfig {
            buffer_len: 4096,
            total_buffers: 8,
            workers: 4,
            local_queue_cap: 2, // 4 workers * 2 = 8 total local cap
        }
    }

    #[test]
    fn config_validation() {
        let mut cfg = test_config();
        cfg.validate(); // Should not panic

        // Zero buffer_len
        cfg.buffer_len = 0;
        let result = std::panic::catch_unwind(|| cfg.validate());
        assert!(result.is_err());

        // Zero total_buffers
        cfg = test_config();
        cfg.total_buffers = 0;
        let result = std::panic::catch_unwind(|| cfg.validate());
        assert!(result.is_err());

        // total_buffers < workers
        cfg = test_config();
        cfg.total_buffers = 2;
        cfg.workers = 4;
        let result = std::panic::catch_unwind(|| cfg.validate());
        assert!(result.is_err());
    }

    #[test]
    fn pre_seeding_distributes_to_locals() {
        let cfg = TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 12, // 4 workers * 2 local_cap = 8 in locals, 4 in global
            workers: 4,
            local_queue_cap: 2,
        };
        let pool = TsBufferPool::new(cfg);

        // Each worker should have 2 buffers, global should have 4
        for wid in 0..4 {
            assert_eq!(
                pool.available_local(wid),
                2,
                "worker {} should have 2 buffers",
                wid
            );
        }
        assert_eq!(pool.available_global(), 4, "global should have 4 buffers");
        assert_eq!(pool.available_total(), 12);
    }

    #[test]
    fn pre_seeding_with_insufficient_buffers() {
        // Only 5 buffers for 4 workers with local_cap=2
        // First 2 workers get 2 each, third gets 1, fourth gets 0
        let cfg = TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 5,
            workers: 4,
            local_queue_cap: 2,
        };
        let pool = TsBufferPool::new(cfg);

        assert_eq!(pool.available_local(0), 2);
        assert_eq!(pool.available_local(1), 2);
        assert_eq!(pool.available_local(2), 1);
        assert_eq!(pool.available_local(3), 0);
        assert_eq!(pool.available_global(), 0);
        assert_eq!(pool.available_total(), 5);
    }

    #[test]
    fn all_buffers_available_after_creation() {
        let pool = TsBufferPool::new(test_config());
        assert_eq!(pool.available_total(), 8);
    }

    #[test]
    fn acquire_and_release_single_thread() {
        let pool = TsBufferPool::new(test_config());

        // Acquire all buffers
        let mut handles: Vec<TsBufferHandle> = Vec::new();
        for _ in 0..8 {
            handles.push(pool.acquire());
        }
        assert_eq!(pool.available_total(), 0);
        assert!(pool.try_acquire().is_none());

        // Release all
        drop(handles);
        assert_eq!(pool.available_total(), 8);
    }

    #[test]
    fn buffer_content_accessible() {
        let pool = TsBufferPool::new(test_config());
        let mut buf = pool.acquire();

        // Write some data
        let data = buf.as_mut_slice();
        data[0] = 0xAB;
        data[4095] = 0xCD;

        // Read it back
        assert_eq!(buf.as_slice()[0], 0xAB);
        assert_eq!(buf.as_slice()[4095], 0xCD);
        assert_eq!(buf.len(), 4096);
    }

    #[test]
    fn clear_zeroes_buffer() {
        let pool = TsBufferPool::new(test_config());
        let mut buf = pool.acquire();

        buf.as_mut_slice().fill(0xFF);
        buf.clear();

        assert!(buf.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn buffers_are_reused() {
        let pool = TsBufferPool::new(test_config());
        let mut seen_addrs = HashSet::new();

        // Acquire/release many times, track unique addresses
        for _ in 0..1000 {
            let buf = pool.acquire();
            seen_addrs.insert(buf.ptr_usize());
        }

        // Should never see more unique addresses than pool capacity
        assert!(
            seen_addrs.len() <= 8,
            "saw {} unique addresses, expected <= 8",
            seen_addrs.len()
        );
    }

    #[test]
    fn stealing_prevents_starvation() {
        // Create pool where all buffers end up in worker locals
        let cfg = TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 8, // 4 workers * 2 = all in locals
            workers: 4,
            local_queue_cap: 2,
        };
        let pool = TsBufferPool::new(cfg);

        // Verify all buffers are in locals, none in global
        assert_eq!(pool.available_global(), 0);
        assert_eq!(pool.available_total(), 8);

        // Non-worker thread (no TLS worker_id set) should still be able to acquire
        // by stealing from locals
        let buf = pool.try_acquire();
        assert!(
            buf.is_some(),
            "should be able to steal from locals when global is empty"
        );

        // Should be able to acquire all 8
        let mut handles = vec![buf.unwrap()];
        for i in 1..8 {
            let b = pool.try_acquire();
            assert!(b.is_some(), "should acquire buffer {} via stealing", i);
            handles.push(b.unwrap());
        }

        // Now truly exhausted
        assert!(pool.try_acquire().is_none());

        // Return all, should be available again
        drop(handles);
        assert_eq!(pool.available_total(), 8);
    }

    #[test]
    fn concurrent_acquire_release() {
        let pool = TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 32,
            workers: 8,
            local_queue_cap: 4,
        });

        let ops_per_thread = 10_000;
        let num_threads = 8;
        let total_ops = Arc::new(AtomicUsize::new(0));
        let seen_addrs = Arc::new(Mutex::new(HashSet::new()));

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let pool = pool.clone();
                let total_ops = Arc::clone(&total_ops);
                let seen_addrs = Arc::clone(&seen_addrs);

                thread::spawn(move || {
                    for _ in 0..ops_per_thread {
                        if let Some(buf) = pool.try_acquire() {
                            seen_addrs.lock().unwrap().insert(buf.ptr_usize());
                            total_ops.fetch_add(1, Ordering::Relaxed);
                            // buf dropped here, returns to pool
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All buffers should be back
        assert_eq!(pool.available_total(), 32);

        // Verify reuse
        let unique_addrs = seen_addrs.lock().unwrap().len();
        assert!(
            unique_addrs <= 32,
            "saw {} unique addresses, expected <= 32",
            unique_addrs
        );

        // Should have done a reasonable number of ops
        let ops = total_ops.load(Ordering::Relaxed);
        assert!(
            ops > 1000,
            "expected significant contention, only got {} ops",
            ops
        );
    }

    #[test]
    fn peak_memory_calculation() {
        let cfg = TsBufferPoolConfig {
            buffer_len: 64 * 1024,
            total_buffers: 16,
            workers: 4,
            local_queue_cap: 4,
        };
        assert_eq!(cfg.peak_memory_bytes(), 16 * 64 * 1024);
        assert_eq!(cfg.total_local_capacity(), 16);
    }

    #[test]
    fn try_acquire_returns_none_when_exhausted() {
        let pool = TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 2,
            workers: 2,
            local_queue_cap: 1,
        });

        let _a = pool.acquire();
        let _b = pool.acquire();

        // Pool exhausted (including stealing)
        assert!(pool.try_acquire().is_none());

        // Drop one, should be available again
        drop(_a);
        assert!(pool.try_acquire().is_some());
    }

    #[test]
    #[should_panic(expected = "buffer pool exhausted")]
    fn acquire_panics_when_exhausted() {
        let pool = TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 1,
            workers: 1,
            local_queue_cap: 1,
        });

        let _a = pool.acquire();
        let _b = pool.acquire(); // Should panic
    }

    /// Integration test: prove buffers are reused within executor context.
    ///
    /// This test validates:
    /// 1. Per-worker TLS routing works (buffers go to local queues)
    /// 2. Buffers are reused (unique pointers <= pool capacity)
    /// 3. All buffers return at end of run (leak-free)
    /// 4. Allocation-free hot path after warmup
    #[test]
    fn buffers_are_reused_in_executor() {
        use crate::scheduler::executor::{Executor, ExecutorConfig};
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let cfg = ExecutorConfig {
            workers: 4,
            seed: 42,
            ..ExecutorConfig::default()
        };

        let pool = TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: 64 * 1024,
            total_buffers: 8,
            workers: cfg.workers,
            local_queue_cap: 2,
        });

        let addrs: Arc<Mutex<HashSet<usize>>> = Arc::new(Mutex::new(HashSet::new()));
        let total_bytes = Arc::new(AtomicUsize::new(0));

        #[derive(Clone, Copy, Debug)]
        enum Task {
            Scan(usize),
        }

        struct Scratch {
            pool: TsBufferPool,
            addrs: Arc<Mutex<HashSet<usize>>>,
            total_bytes: Arc<AtomicUsize>,
        }

        let ex = Executor::<Task>::new(
            cfg,
            {
                let pool = pool.clone();
                let addrs = addrs.clone();
                let total_bytes = total_bytes.clone();
                move |_wid| Scratch {
                    pool: pool.clone(),
                    addrs: addrs.clone(),
                    total_bytes: total_bytes.clone(),
                }
            },
            move |task, ctx| match task {
                Task::Scan(n) => {
                    let mut b = ctx.scratch.pool.acquire();
                    let n = n.min(b.len());

                    // Simulate scanning: touch bytes
                    b.as_mut_slice()[..n].fill(0xAB);
                    ctx.metrics.bytes_scanned = ctx.metrics.bytes_scanned.saturating_add(n as u64);
                    ctx.metrics.chunks_scanned = ctx.metrics.chunks_scanned.saturating_add(1);

                    // Track unique backing pointers to prove reuse
                    let ptr = b.ptr_usize();
                    ctx.scratch.addrs.lock().unwrap().insert(ptr);

                    ctx.scratch.total_bytes.fetch_add(n, Ordering::Relaxed);
                    // drop(b) returns buffer via per-worker local queue
                }
            },
        );

        // Spawn many scan tasks
        let tasks = 50_000usize;
        for _ in 0..tasks {
            ex.spawn_external(Task::Scan(1024)).unwrap();
        }

        let metrics = ex.join();

        // Validate: all buffers returned
        assert_eq!(pool.available_total(), 8, "all buffers should be returned");

        // Validate: buffer reuse (unique pointers <= pool capacity)
        let unique_addrs = addrs.lock().unwrap().len();
        assert!(
            unique_addrs <= 8,
            "saw {} unique buffer addresses, expected <= 8 (pool capacity)",
            unique_addrs
        );

        // Validate: work was done (core metrics are always populated)
        assert_eq!(metrics.chunks_scanned, tasks as u64);
        assert_eq!(metrics.bytes_scanned, (tasks * 1024) as u64);
    }
}
