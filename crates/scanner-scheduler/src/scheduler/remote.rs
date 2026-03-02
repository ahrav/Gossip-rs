//! Remote Fetch Pipeline
//!
//! # Architecture
//!
//! ```text
//! Discovery Thread       I/O Threads (N)         CPU Workers (M)
//! â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//!    list_page()             â†“
//!        â†“              ObjectWork recv
//!    bounded chan  â”€â”€â”€â”€â”€â†’   â†“
//!                       fetch_range()
//!                       retry/backoff
//!                            â†“
//!                       ScanChunk task  â”€â”€â”€â”€â†’  scan_chunk_into()
//!                       (buffer handoff)       drop_prefix_findings()
//!                                              emit findings
//!                                              release buffer
//! ```
//!
//! # Key Design Decisions
//!
//! 1. **Separate I/O and CPU threads**: Network latency doesn't block scanning
//! 2. **GlobalOnly buffer pool**: I/O threads acquire, CPU workers release
//! 3. **Bounded object queue**: Discovery backpressure via channel capacity
//! 4. **CountBudget for objects**: Caps discovered-but-not-complete objects
//! 5. **ObjectToken via Arc**: Permit released when all chunks complete
//!
//! # Backpressure Chain
//!
//! ```text
//! Discovery â†’ object_queue_cap â†’ I/O threads â†’ pool_buffers â†’ CPU executor
//!          â†‘                                  â†‘
//!    CountBudget                        TsBufferPool
//! ```
//!
//! # Retry Policy
//!
//! - Exponential backoff with jitter
//! - Configurable max attempts
//! - Optional per-object time budget
//! - Error classification: Retryable vs Permanent

use super::count_budget::{CountBudget, CountPermit};
use super::engine_trait::{EngineScratch as _, FindingWithHash};
use super::executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
use super::metrics::MetricsSnapshot;
use super::rng::XorShift64;
use super::scan_helpers::{
    account_effective_dropped_findings, apply_cross_rule_dedupe,
    emit_findings as shared_emit_findings,
};
use super::ts_buffer_pool::{TsBufferHandle, TsBufferPool, TsBufferPoolConfig};
use crate::perf_stats;
use crate::scheduler::engine_stub::{FileId, FindingRec, MockEngine, ScanScratch, BUFFER_LEN_MAX};
use crate::unified::events::EventSink;

use crossbeam_channel as chan;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Error Classification
// ============================================================================

/// Classification of backend errors for retry decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient error - worth retrying (network timeout, 503, rate limit)
    Retryable,
    /// Permanent error - don't retry (404, auth failure, invalid response)
    Permanent,
}

// ============================================================================
// Retry Policy
// ============================================================================

/// Configuration for retry behavior.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Maximum attempts per fetch (including initial attempt).
    pub max_attempts: u32,
    /// Base delay before first retry.
    pub base_delay: Duration,
    /// Maximum delay between retries (caps exponential growth).
    pub max_delay: Duration,
    /// Jitter as percentage of computed delay (0-100).
    /// Jitter helps avoid thundering herd when multiple fetches fail.
    pub jitter_pct: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
            jitter_pct: 20,
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for remote scanning pipeline.
#[derive(Clone, Debug)]
pub struct RemoteConfig {
    /// Number of CPU worker threads for scanning.
    pub cpu_workers: usize,

    /// Number of dedicated I/O threads for fetching.
    pub io_threads: usize,

    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,

    /// Hard cap on discovered-but-not-fully-processed objects.
    /// Controls memory for object metadata (paths, handles, permits).
    pub max_in_flight_objects: usize,

    /// Bounded queue depth between discovery and I/O threads.
    /// Smaller = tighter backpressure, less memory for queued work.
    pub object_queue_cap: usize,

    /// How many objects to request per list_page call.
    pub discover_batch: usize,

    /// Total buffers in the global pool.
    /// Caps: buffered bytes + queued scan tasks.
    /// Rule of thumb: `pool_buffers >= io_threads + cpu_workers`
    pub pool_buffers: usize,

    /// Retry policy for transient failures.
    pub retry: RetryPolicy,

    /// Abort an object if total time exceeds this (including retries).
    /// `None` means no time budget.
    pub max_object_time: Option<Duration>,

    /// Seed for deterministic retry jitter.
    pub seed: u64,

    /// If true, deduplicate findings within each chunk using the shared
    /// `apply_cross_rule_dedupe` helper (same tie-breaker as the local file-system
    /// path) so we emit at most one finding per span/hash pair before emitting
    /// events. When false, the raw findings path is used to avoid the hash-wrapper
    /// overhead.
    pub dedupe_within_chunk: bool,

    /// Pin worker and I/O threads to CPU cores (Linux only, no-op elsewhere).
    pub pin_threads: bool,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            cpu_workers: 8,
            io_threads: 8,
            chunk_size: 256 * 1024,
            max_in_flight_objects: 512,
            object_queue_cap: 256,
            discover_batch: 256,
            pool_buffers: 64,
            retry: RetryPolicy::default(),
            max_object_time: Some(Duration::from_secs(30)),
            seed: 1,
            dedupe_within_chunk: true,
            pin_threads: super::affinity::default_pin_threads(),
        }
    }
}

impl RemoteConfig {
    /// Validate configuration against engine constraints.
    ///
    /// # Panics
    ///
    /// Panics if configuration violates invariants.
    pub fn validate(&self, engine: &MockEngine) {
        assert!(self.cpu_workers > 0, "cpu_workers must be > 0");
        assert!(self.io_threads > 0, "io_threads must be > 0");
        assert!(self.chunk_size > 0, "chunk_size must be > 0");
        assert!(
            self.max_in_flight_objects > 0,
            "max_in_flight_objects must be > 0"
        );
        assert!(self.object_queue_cap > 0, "object_queue_cap must be > 0");
        assert!(self.discover_batch > 0, "discover_batch must be > 0");
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        assert!(self.retry.max_attempts > 0, "max_attempts must be > 0");
        assert!(self.retry.jitter_pct <= 100, "jitter_pct must be <= 100");

        let overlap = engine.required_overlap();
        let buf_len = overlap.saturating_add(self.chunk_size);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size ({}) + overlap ({}) = {} exceeds BUFFER_LEN_MAX ({})",
            self.chunk_size,
            overlap,
            buf_len,
            BUFFER_LEN_MAX
        );
    }
}

// ============================================================================
// Remote Object
// ============================================================================

/// A single remote object to scan.
#[derive(Clone, Debug)]
pub struct RemoteObject<H> {
    /// Backend-specific handle for fetching.
    pub handle: H,
    /// Object size in bytes.
    pub size: u64,
    /// Display bytes for output (path/key). Can be non-UTF8.
    pub display: Vec<u8>,
}

// ============================================================================
// Remote Backend Trait
// ============================================================================

/// Contract for remote data sources.
///
/// Implementations handle the actual network/API calls.
/// The scheduler handles threading, retry, backpressure.
///
/// # Blocking vs Async
///
/// This trait uses blocking calls executed on dedicated I/O threads.
/// This is simpler than async and works well for moderate concurrency.
/// For very high concurrency (1000+ concurrent fetches), consider
/// an async backend with tokio/async-std.
pub trait RemoteBackend: Send + Sync + 'static {
    /// Backend-specific object handle (e.g., S3 key, HTTP URL).
    type Object: Send + 'static;

    /// Pagination cursor for list operations.
    type Cursor: Default + Send + 'static;

    /// Backend-specific error type.
    type Error: std::fmt::Debug + Send + Sync + 'static;

    /// List up to `max` objects starting from cursor.
    ///
    /// Returns empty vec when enumeration is complete.
    /// Updates cursor for next page.
    fn list_page(
        &self,
        cursor: &mut Self::Cursor,
        max: usize,
    ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error>;

    /// Fetch exactly `dst.len()` bytes from object starting at `start`.
    ///
    /// # Contract (IMPORTANT)
    ///
    /// On success, returns number of bytes written:
    /// - If `start + dst.len() <= object_size`: MUST return `dst.len()` (exact fill)
    /// - If `start >= object_size`: MUST return `0` (EOF)
    /// - If `start < object_size < start + dst.len()`: MUST return `object_size - start` (final partial)
    ///
    /// **Partial reads within range are NOT allowed.** If the backend cannot fill
    /// the entire requested range (e.g., network timeout mid-read), it MUST return
    /// an error (classified as `Retryable` or `Permanent`).
    ///
    /// # Rationale
    ///
    /// This simplifies the scheduler: it doesn't need to loop on partial reads.
    /// S3, HTTP, and GCS backends can trivially implement "fill exactly" by
    /// looping internally on their underlying read calls.
    ///
    /// # Example Implementation
    ///
    /// ```ignore
    /// fn fetch_range(&self, obj: &Key, start: u64, dst: &mut [u8]) -> Result<usize, Error> {
    ///     let mut filled = 0;
    ///     while filled < dst.len() {
    ///         match self.inner_read(obj, start + filled as u64, &mut dst[filled..])? {
    ///             0 => break, // EOF
    ///             n => filled += n,
    ///         }
    ///     }
    ///     Ok(filled)
    /// }
    /// ```
    fn fetch_range(
        &self,
        obj: &Self::Object,
        start: u64,
        dst: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// Classify error for retry decisions.
    fn classify_error(&self, err: &Self::Error) -> ErrorClass;
}

// ============================================================================
// Statistics
// ============================================================================

/// I/O thread statistics (per-thread, merged at end).
#[derive(Clone, Copy, Debug, Default)]
pub struct IoStats {
    pub objects_started: u64,
    pub objects_completed: u64,
    pub objects_failed: u64,

    pub chunks_fetched: u64,
    /// Payload bytes fetched (excludes overlap).
    pub payload_bytes_fetched: u64,

    pub retryable_errors: u64,
    pub permanent_errors: u64,
    pub retries: u64,
}

impl IoStats {
    fn merge(&mut self, other: IoStats) {
        perf_stats::sat_add_u64(&mut self.objects_started, other.objects_started);
        perf_stats::sat_add_u64(&mut self.objects_completed, other.objects_completed);
        perf_stats::sat_add_u64(&mut self.objects_failed, other.objects_failed);
        perf_stats::sat_add_u64(&mut self.chunks_fetched, other.chunks_fetched);
        perf_stats::sat_add_u64(&mut self.payload_bytes_fetched, other.payload_bytes_fetched);
        perf_stats::sat_add_u64(&mut self.retryable_errors, other.retryable_errors);
        perf_stats::sat_add_u64(&mut self.permanent_errors, other.permanent_errors);
        perf_stats::sat_add_u64(&mut self.retries, other.retries);
    }
}

/// Discovery thread statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoteStats {
    /// Objects returned by `list_page` calls.
    pub objects_discovered: u64,
    /// Objects sent to the I/O channel (may be fewer if pipeline stops
    /// mid-discovery).
    pub objects_enqueued: u64,
}

/// End-of-run report.
#[derive(Debug, Default)]
pub struct RemoteRunReport {
    /// Discovery-side stats (listing).
    pub remote: RemoteStats,
    /// I/O-thread-side stats (fetch, retry, scan).
    pub io: IoStats,
}

// ============================================================================
// Run Errors
// ============================================================================

/// Errors that can occur during remote scanning.
#[derive(Debug)]
pub enum RemoteRunError<E> {
    /// Error during object listing.
    List(E),
    /// An I/O thread panicked.
    IoThreadPanicked,
}

// ============================================================================
// Internal Types
// ============================================================================

/// Token holding the in-flight object permit.
///
/// The permit is released when the last Arc<ObjectToken> is dropped,
/// which happens after all chunk tasks for the object complete.
struct ObjectToken {
    _permit: CountPermit,
    file_id: FileId,
    display: Arc<[u8]>,
}

/// Work item sent from discovery to I/O threads.
struct ObjectWork<H> {
    handle: H,
    size: u64,
    token: Arc<ObjectToken>,
}

/// Task sent from I/O threads to CPU executor.
enum CpuTask {
    ScanChunk {
        /// Shared token for this object (permit released when all chunks done).
        token: Arc<ObjectToken>,
        /// Absolute offset of buffer[0] in the object.
        base_offset: u64,
        /// Overlap prefix length (bytes to skip for dedup).
        prefix_len: u32,
        /// Total valid bytes in buffer.
        len: u32,
        /// Buffer with data to scan.
        buf: TsBufferHandle,
    },
}

/// Per-CPU-worker scratch space.
struct CpuScratch {
    engine: Arc<MockEngine>,
    event_sink: Arc<dyn EventSink>,

    scratch: ScanScratch,
    pending: Vec<FindingRec>,
    pending_hashed: Vec<FindingWithHash<FindingRec>>,

    dedupe_within_chunk: bool,
}

// ============================================================================
// CPU Worker Logic
// ============================================================================

/// Executes a single scan-chunk task on a CPU worker thread.
fn cpu_runner(task: CpuTask, ctx: &mut WorkerCtx<CpuTask, CpuScratch>) {
    match task {
        CpuTask::ScanChunk {
            token,
            base_offset,
            prefix_len,
            len,
            buf,
        } => {
            let engine = ctx.scratch.engine.as_ref();
            let data = &buf.as_slice()[..(len as usize)];

            engine.scan_chunk_into(data, token.file_id, base_offset, &mut ctx.scratch.scratch);
            let engine_dropped = ctx.scratch.scratch.dropped_findings();

            // Drop findings fully contained in the prefix
            let new_bytes_start = base_offset + prefix_len as u64;
            let before_prefix = ctx.scratch.scratch.pending_findings_len();
            ctx.scratch.scratch.drop_prefix_findings(new_bytes_start);
            let after_prefix = ctx.scratch.scratch.pending_findings_len();

            let dedupe_removed = if ctx.scratch.dedupe_within_chunk {
                ctx.scratch.pending_hashed.clear();
                <ScanScratch as super::engine_trait::EngineScratch>::drain_findings_into(
                    &mut ctx.scratch.scratch,
                    &mut ctx.scratch.pending_hashed,
                );

                let dedupe_removed =
                    apply_cross_rule_dedupe(&mut ctx.scratch.pending_hashed, &*ctx.scratch.engine);
                shared_emit_findings(
                    engine,
                    &*ctx.scratch.event_sink,
                    &token.display,
                    &ctx.scratch.pending_hashed,
                );
                dedupe_removed
            } else {
                // Keep the no-dedupe path on raw findings to avoid hash-wrapper overhead.
                ctx.scratch.pending.clear();
                ctx.scratch
                    .scratch
                    .drain_findings_into(&mut ctx.scratch.pending);
                shared_emit_findings(
                    engine,
                    &*ctx.scratch.event_sink,
                    &token.display,
                    &ctx.scratch.pending,
                );
                0
            };

            let scheduler_pruned = before_prefix
                .saturating_sub(after_prefix)
                .saturating_add(dedupe_removed);
            account_effective_dropped_findings(&mut ctx.metrics, engine_dropped, scheduler_pruned);

            // Metrics: count payload bytes only
            let payload = (len as u64).saturating_sub(prefix_len as u64);
            ctx.metrics.chunks_scanned = ctx.metrics.chunks_scanned.saturating_add(1);
            ctx.metrics.bytes_scanned = ctx.metrics.bytes_scanned.saturating_add(payload);

            // Buffer returned to pool on drop
            drop(buf);
        }
    }
}

// ============================================================================
// Retry Logic
// ============================================================================

/// Computes exponential backoff with jitter.
///
/// `attempt` is 1-based (1 = first retry). Delay is
/// `base_delay * 2^(attempt-1)`, capped at `max_delay`, then jittered
/// by `+/- jitter_pct%` uniform.
fn compute_backoff(attempt: u32, policy: RetryPolicy, rng: &mut XorShift64) -> Duration {
    // attempt starts at 1 for the first try
    let exp = attempt.saturating_sub(1).min(30);
    let mut d = policy.base_delay.saturating_mul(1u32 << exp);
    if d > policy.max_delay {
        d = policy.max_delay;
    }

    let jitter_pct = policy.jitter_pct.min(100) as u64;
    if jitter_pct == 0 {
        return d;
    }

    let jitter_ns = (d.as_nanos() as u64).saturating_mul(jitter_pct) / 100;
    let span = jitter_ns.saturating_mul(2);
    if span == 0 {
        return d;
    }

    // Uniform in [d - jitter, d + jitter]
    let r = rng.next_u64() % (span + 1);
    let offset = r as i128 - jitter_ns as i128;
    let base = d.as_nanos() as i128;
    let out = (base + offset).max(0) as u128;

    Duration::from_nanos(out.min(u64::MAX as u128) as u64)
}

// ============================================================================
// I/O Thread Logic
// ============================================================================

/// Blocking buffer acquire for I/O threads.
///
/// I/O threads are not the hot path, so we use a simple spin-then-park loop.
///
/// # Why spin-then-park instead of a proper blocking semaphore?
///
/// 1. Simplicity: no additional synchronization primitives needed
/// 2. Typical case: buffers available immediately (CPU workers release fast)
/// 3. Fallback: short park avoids busy-wait while remaining responsive to `stop`
///
/// The 200-spin threshold is tuned for ~200ns of spinning before yielding.
fn acquire_buffer_blocking(pool: &TsBufferPool, stop: &AtomicBool) -> Option<TsBufferHandle> {
    let mut spins: u32 = 0;
    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        if let Some(h) = pool.try_acquire() {
            return Some(h);
        }

        if spins < 200 {
            spins += 1;
            std::hint::spin_loop();
        } else {
            std::thread::park_timeout(Duration::from_micros(200));
            spins = 0;
        }
    }
}

/// I/O worker loop: fetch chunks from remote backend, enqueue scan tasks.
///
/// # Buffer Lifecycle
///
/// Buffers are acquired just-in-time (after computing what to fetch) and
/// released immediately on error. This ensures:
/// 1. No buffer held during backoff sleep (would starve other workers)
/// 2. Failed fetches release buffers for retry or other files
///
/// # Retry Strategy
///
/// Each chunk fetch is retried independently. If a chunk fails permanently,
/// the entire object is marked failed (no partial results).
#[allow(clippy::too_many_arguments)]
fn io_worker_loop<B: RemoteBackend>(
    wid: usize,
    backend: Arc<B>,
    rx: chan::Receiver<ObjectWork<B::Object>>,
    pool: TsBufferPool,
    cpu: ExecutorHandle<CpuTask>,
    cfg: RemoteConfig,
    overlap: usize,
    stop: Arc<AtomicBool>,
) -> IoStats {
    let mut stats = IoStats::default();
    let mut rng = XorShift64::new(cfg.seed ^ ((wid as u64).wrapping_mul(0xD1B54A32D192ED03)));

    while let Ok(work) = rx.recv() {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        perf_stats::sat_add_u64(&mut stats.objects_started, 1);
        let started = Instant::now();

        let size = work.size;
        let chunk = cfg.chunk_size as u64;

        // Offset of new bytes (payload start)
        let mut offset: u64 = 0;
        let mut failed = false;

        'chunk_loop: while offset < size {
            if stop.load(Ordering::Relaxed) {
                failed = true;
                break;
            }

            // Check object time budget before starting chunk
            let time_remaining = if let Some(limit) = cfg.max_object_time {
                let elapsed = started.elapsed();
                if elapsed >= limit {
                    failed = true;
                    break;
                }
                Some(limit - elapsed)
            } else {
                None
            };

            // Range calculation: [base_offset, base_offset + prefix_len + payload_len)
            let base_offset = offset.saturating_sub(overlap as u64);
            let prefix_len = (offset - base_offset) as usize;
            let payload_len = (size - offset).min(chunk) as usize;
            let request_len = prefix_len + payload_len;

            // Retry loop - buffer acquired INSIDE, dropped before sleep
            let mut attempt: u32 = 0;

            loop {
                attempt += 1;

                // Check stop before each attempt
                if stop.load(Ordering::Relaxed) {
                    failed = true;
                    break 'chunk_loop;
                }

                // Acquire buffer just-in-time (not held during backoff sleep)
                let mut buf = match acquire_buffer_blocking(&pool, &stop) {
                    Some(b) => b,
                    None => {
                        failed = true;
                        break 'chunk_loop;
                    }
                };

                let dst = &mut buf.as_mut_slice()[..request_len];

                match backend.fetch_range(&work.handle, base_offset, dst) {
                    Ok(fetched) => {
                        // Validate fetch result per contract:
                        // - fetched == request_len: normal case (got all requested bytes)
                        // - fetched < request_len: only valid if we reached actual EOF
                        // - fetched == 0: unexpected (we calculated request based on size)

                        if fetched == 0 {
                            // Unexpected EOF before expected position
                            failed = true;
                            drop(buf);
                            break 'chunk_loop;
                        }

                        // Check for partial reads
                        if fetched < request_len {
                            // Partial read - only valid if we've reached actual EOF
                            let end_offset = base_offset + fetched as u64;
                            if end_offset != size {
                                // Partial read that doesn't reach EOF = contract violation
                                // Backend should have either filled exactly or returned error
                                perf_stats::sat_add_u64(&mut stats.permanent_errors, 1);
                                failed = true;
                                drop(buf);
                                break 'chunk_loop;
                            }
                            // else: valid final partial (reached EOF)
                        }

                        // Calculate actual payload (may be less than planned on final chunk)
                        let actual_payload = fetched.saturating_sub(prefix_len);

                        // Enqueue scan task (buffer ownership transfers to CPU side)
                        if cpu
                            .spawn(CpuTask::ScanChunk {
                                token: Arc::clone(&work.token),
                                base_offset,
                                prefix_len: prefix_len as u32,
                                len: fetched as u32,
                                buf,
                            })
                            .is_err()
                        {
                            // Executor closed
                            stop.store(true, Ordering::Relaxed);
                            failed = true;
                            break 'chunk_loop;
                        }

                        perf_stats::sat_add_u64(&mut stats.chunks_fetched, 1);
                        perf_stats::sat_add_u64(
                            &mut stats.payload_bytes_fetched,
                            actual_payload as u64,
                        );

                        // Advance by actual payload, not planned
                        offset = offset.saturating_add(actual_payload as u64);
                        break; // Success, exit retry loop
                    }
                    Err(err) => {
                        // Drop buffer BEFORE sleeping or breaking
                        drop(buf);

                        match backend.classify_error(&err) {
                            ErrorClass::Permanent => {
                                perf_stats::sat_add_u64(&mut stats.permanent_errors, 1);
                                failed = true;
                                break 'chunk_loop;
                            }
                            ErrorClass::Retryable => {
                                perf_stats::sat_add_u64(&mut stats.retryable_errors, 1);
                                if attempt >= cfg.retry.max_attempts {
                                    failed = true;
                                    break 'chunk_loop;
                                }

                                // Compute backoff
                                let backoff = compute_backoff(attempt, cfg.retry, &mut rng);

                                // Check if sleeping would exceed time budget
                                if let Some(remaining) = time_remaining {
                                    let elapsed_since_chunk_start = started
                                        .elapsed()
                                        .saturating_sub(cfg.max_object_time.unwrap() - remaining);
                                    if elapsed_since_chunk_start + backoff > remaining {
                                        // Would exceed budget; fail now
                                        failed = true;
                                        break 'chunk_loop;
                                    }
                                }

                                perf_stats::sat_add_u64(&mut stats.retries, 1);
                                std::thread::sleep(backoff);
                                continue; // Retry (will re-acquire buffer)
                            }
                        }
                    }
                }
            }
        }

        if failed {
            perf_stats::sat_add_u64(&mut stats.objects_failed, 1);
            // work.token dropped here; permit releases when all enqueued chunks finish
        } else {
            perf_stats::sat_add_u64(&mut stats.objects_completed, 1);
        }
    }

    stats
}

// ============================================================================
// Entry Point
// ============================================================================

/// Run remote scanning pipeline.
///
/// # Arguments
///
/// - `engine`: Detection engine (determines overlap, provides scan logic)
/// - `backend`: Remote data source implementation
/// - `cfg`: Pipeline configuration
/// - `out`: Output sink for findings
///
/// # Returns
///
/// `(RemoteRunReport, MetricsSnapshot)` on success.
///
/// # Errors
///
/// - `RemoteRunError::List(e)`: Error during object listing
/// - `RemoteRunError::IoThreadPanicked`: An I/O thread panicked
///
/// # Example
///
/// ```ignore
/// let engine = Arc::new(MockEngine::new(rules, 16));
/// let backend = Arc::new(MyS3Backend::new(bucket));
/// let sink = Arc::new(scanner_rs::unified::events::VecEventSink::new());
///
/// let (report, metrics) = scan_remote(engine, backend, RemoteConfig::default(), sink)?;
/// ```
pub fn scan_remote<B: RemoteBackend>(
    engine: Arc<MockEngine>,
    backend: Arc<B>,
    cfg: RemoteConfig,
    event_sink: Arc<dyn EventSink>,
) -> Result<(RemoteRunReport, MetricsSnapshot), RemoteRunError<B::Error>> {
    cfg.validate(&engine);

    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    // Buffer pool shared between CPU workers and I/O threads.
    // Use minimal worker config (workers=1, local_queue_cap=1) since I/O
    // threads use global queue directly - the pool primarily tracks
    // buffer lifecycle rather than worker-local caching.
    let pool = TsBufferPool::new(TsBufferPoolConfig {
        buffer_len: buf_len,
        total_buffers: cfg.pool_buffers,
        workers: 1,
        local_queue_cap: 1,
    });

    let object_budget = Arc::new(CountBudget::new(cfg.max_in_flight_objects));

    // CPU executor for scanning
    let ex = Executor::<CpuTask>::new(
        ExecutorConfig {
            workers: cfg.cpu_workers,
            seed: cfg.seed,
            pin_threads: cfg.pin_threads,
            ..ExecutorConfig::default()
        },
        {
            let engine = Arc::clone(&engine);
            let event_sink = Arc::clone(&event_sink);
            let dedupe = cfg.dedupe_within_chunk;
            move |_wid| CpuScratch {
                engine: Arc::clone(&engine),
                event_sink: Arc::clone(&event_sink),
                scratch: engine.new_scratch(),
                pending: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
                pending_hashed: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
                dedupe_within_chunk: dedupe,
            }
        },
        cpu_runner,
    );

    let cpu_handle = ex.handle();

    // Bounded channel for discovery â†’ I/O backpressure
    let (tx, rx) = chan::bounded::<ObjectWork<B::Object>>(cfg.object_queue_cap);
    let stop = Arc::new(AtomicBool::new(false));

    // Spawn I/O threads
    let io_assigner = if cfg.pin_threads {
        super::affinity::CoreAssigner::with_offset(cfg.cpu_workers).map(Arc::new)
    } else {
        None
    };
    let mut io_threads = Vec::with_capacity(cfg.io_threads);
    for wid in 0..cfg.io_threads {
        let backend = Arc::clone(&backend);
        let rx = rx.clone();
        let pool = pool.clone();
        let cpu = cpu_handle.clone();
        let cfg2 = cfg.clone();
        let stop2 = Arc::clone(&stop);
        let io_assigner_clone = io_assigner.clone();

        io_threads.push(
            thread::Builder::new()
                .name(format!("remote-io-{wid}"))
                .spawn(move || {
                    if let Some(ref a) = io_assigner_clone {
                        a.pin_current_thread();
                    }
                    io_worker_loop(wid, backend, rx, pool, cpu, cfg2, overlap, stop2)
                })
                .expect("failed to spawn remote I/O thread"),
        );
    }
    drop(rx); // Close our receiver; only I/O threads hold receivers now

    // Discovery loop (single thread for now)
    let mut report = RemoteRunReport::default();
    let mut cursor = B::Cursor::default();
    let mut next_file_id: u32 = 0;

    'discovery: loop {
        // Check stop before listing
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let page = backend
            .list_page(&mut cursor, cfg.discover_batch)
            .map_err(RemoteRunError::List)?;

        if page.is_empty() {
            break;
        }

        for obj in page {
            perf_stats::sat_add_u64(&mut report.remote.objects_discovered, 1);

            // Check stop flag before acquiring permit
            if stop.load(Ordering::Relaxed) {
                break 'discovery;
            }

            // Acquire in-flight permit (blocks if at limit)
            let permit = object_budget.acquire(1);

            let file_id = FileId(next_file_id);
            next_file_id = next_file_id.checked_add(1).expect("FileId overflow");

            let token = Arc::new(ObjectToken {
                _permit: permit,
                file_id,
                display: obj.display.into_boxed_slice().into(),
            });

            let mut work = Some(ObjectWork {
                handle: obj.handle,
                size: obj.size,
                token,
            });

            // Send with timeout loop to check stop while waiting
            // This prevents deadlock if I/O threads exit while queue is full
            loop {
                if stop.load(Ordering::Relaxed) {
                    break 'discovery;
                }

                // Take the work item for this send attempt
                let w = work.take().expect("work already sent");

                match tx.send_timeout(w, Duration::from_millis(100)) {
                    Ok(()) => {
                        perf_stats::sat_add_u64(&mut report.remote.objects_enqueued, 1);
                        break; // Success, exit send loop
                    }
                    Err(chan::SendTimeoutError::Timeout(returned)) => {
                        // Queue full, put work back and retry after checking stop
                        work = Some(returned);
                        continue;
                    }
                    Err(chan::SendTimeoutError::Disconnected(_)) => {
                        // I/O threads have all exited (channel disconnected)
                        // This is not necessarily an error - could be stop triggered
                        break 'discovery;
                    }
                }
            }
        }
    }

    // Close sender to signal I/O threads to drain and exit
    drop(tx);

    // Join I/O threads and merge stats
    for t in io_threads {
        let s = t.join().map_err(|_| RemoteRunError::IoThreadPanicked)?;
        report.io.merge(s);
    }

    // All I/O work done; join CPU executor
    let cpu_metrics = ex.join();

    event_sink.flush();

    Ok((report, cpu_metrics))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
