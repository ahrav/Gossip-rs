//! Local Filesystem Scanner with io_uring
//!
//! # Architecture
//!
//! ```text
//!  ┌────────────────┐     ┌───────────────────┐     ┌───────────────────────┐
//!  │   Discovery    │     │  I/O Threads       │     │   CPU Executor        │
//!  │  (main thread) │     │  (io_uring rings)  │     │  (work-stealing pool) │
//!  │                │     │                    │     │                       │
//!  │  walk dirs     │────►│  open / stat       │     │  ┌─────────────────┐  │
//!  │  route archives│     │  read chunks       │────►│  │ ScanChunk tasks │  │
//!  │  backpressure  │     │  classify content  │     │  └─────────────────┘  │
//!  └────────────────┘     │  carry overlap     │     │                       │
//!         │               └───────────────────┘     └───────────────────────┘
//!         │                        │                          │
//!         ▼                        ▼                          ▼
//!  ┌────────────────┐     ┌───────────────────┐     ┌───────────────────────┐
//!  │ Archive Workers│     │ Extract Workers    │     │   EventOutput           │
//!  │  (dedicated)   │     │  (dedicated)       │     │   (findings output)   │
//!  └────────────────┘     └───────────────────┘     └───────────────────────┘
//! ```
//!
//! - **I/O threads** use io_uring for async reads with batched syscalls.
//! - **CPU threads** run the work-stealing executor for scanning (never block on I/O).
//! - **Buffer ownership transfers**: I/O thread acquires from [`FixedBufferPool`],
//!   CPU thread releases on scan completion — no copying between threads.
//! - **Overlap bytes** are carried in-memory between chunks via `ReadState::overlap_buf`,
//!   so disk reads are payload-only (no overlap re-reads).
//!
//! # Why io_uring?
//!
//! - High concurrency on cold storage (NVMe, network mounts)
//! - Batched syscalls reduce kernel transition overhead
//! - CPU workers never block on I/O
//! - Open/stat can be async (when kernel supports `IORING_OP_OPENAT` + `IORING_OP_STATX`)
//!
//! # Correctness Guarantees
//!
//! - **Work-conserving**: Backpressure delays discovery, never drops files
//! - **Chunk overlap**: `engine.required_overlap()` bytes overlap between chunks
//! - **Budget bounded**: `max_in_flight_files` limits discovered-but-not-complete files
//! - **Buffer bounded**: `pool_buffers` limits peak memory
//! - **Exactly-once per chunk**: No duplicate scans (single in-flight op per file)
//! - **Drain-before-return**: All in-flight io_uring ops complete before any thread
//!   returns, preventing the kernel from writing to freed memory
//!
//! # When to Use
//!
//! Profile first! io_uring may be slower than blocking reads when:
//! - Everything is in page cache (kernel readahead is already optimal)
//! - Files are tiny (syscall overhead dominates over I/O latency)
//!
//! io_uring tends to win on:
//! - Cold cache workloads (where I/O latency dominates)
//! - High-latency storage (network mounts, slow NVMe)
//! - Many concurrent files (high SQ depth amortizes syscall cost)
//!
//! # Platform
//!
//! Linux-only. Compiled unconditionally on `target_os = "linux"`.

use super::count_budget::{CountBudget, CountPermit};
use super::engine_stub::BUFFER_LEN_MAX;
use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
use super::file_id_alloc::FileIdAllocator;
use super::metrics::MetricsSnapshot;
use super::scan_helpers::{apply_cross_rule_dedupe, emit_findings as shared_emit_findings};
use super::shared_core::scan_chunk_postprocess;
use crate::api::FileId;
use crate::archive::detect::detect_kind_from_path;
use crate::archive::scan::{
    scan_bzip2_stream, scan_gzip_stream, scan_tar_stream, scan_tarbz2_stream, scan_targz_stream,
    scan_zip_source, ArchiveEntrySink, ArchiveScratch, EntryChunk, EntryMeta,
};
use crate::archive::{ArchiveConfig, ArchiveKind, ArchiveStats};
use crate::content_policy::{self, ContentVerdict};
use crate::events::EventOutput;
use crate::perf_stats;

use crossbeam_channel as chan;
use crossbeam_queue::ArrayQueue;

use io_uring::{opcode, types, IoUring, Probe};

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

// ============================================================================
// Configuration
// ============================================================================

/// Open/stat execution mode for io_uring file setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum OpenStatMode {
    /// Default: use io_uring open/stat when supported, otherwise fallback.
    #[default]
    UringPreferred,
    /// Force blocking open + fstat path (parity/debug).
    BlockingOnly,
    /// Require io_uring open/stat; error if unsupported.
    UringRequired,
}

/// Path resolution policy for openat2 when available.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum ResolvePolicy {
    /// Default: no path resolution constraints (match current behavior).
    #[default]
    Default,
    /// Disallow symlink traversal in all components (opt-in).
    NoSymlinks,
    /// Restrict traversal beneath dirfd root (currently uses `AT_FDCWD`).
    BeneathRoot,
}

/// Configuration for local FS scanning using io_uring I/O threads + CPU executor scan threads.
#[derive(Clone, Debug)]
pub struct LocalFsUringConfig {
    /// Number of CPU worker threads for scanning.
    pub cpu_workers: usize,

    /// Number of I/O threads running io_uring.
    pub io_threads: usize,

    /// Number of SQ/CQ entries per io_uring.
    pub ring_entries: u32,

    /// Max in-flight ops per I/O thread (reads + open/stat).
    /// Must be <= ring_entries - 1.
    pub io_depth: usize,

    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,

    /// Hard cap on in-flight files (discovered, queued, or scanning).
    pub max_in_flight_files: usize,

    /// Bounded queue from discovery -> I/O threads.
    pub file_queue_cap: usize,

    /// Total buffers in the global pool.
    ///
    /// This bounds:
    /// - in-flight reads (each holds a buffer)
    /// - queued scan tasks (each holds a buffer)
    pub pool_buffers: usize,

    /// Use io_uring registered buffers (`READ_FIXED`) for reads.
    ///
    /// This can reduce per-op overhead for high-IOPS workloads, but requires
    /// registering all buffers up-front and limits the pool size to `u16::MAX`.
    pub use_registered_buffers: bool,

    /// Open/stat execution mode for io_uring file setup.
    pub open_stat_mode: OpenStatMode,

    /// Path resolution policy for openat2 (ignored when unsupported).
    pub resolve_policy: ResolvePolicy,

    /// Follow symbolic links during discovery.
    pub follow_symlinks: bool,

    /// Skip files larger than this (None = no limit).
    pub max_file_size: Option<u64>,

    /// Seed for deterministic executor behavior.
    pub seed: u64,

    /// Deduplicate findings within each chunk.
    pub dedupe_within_chunk: bool,

    /// Pin worker and I/O threads to CPU cores (Linux only, no-op elsewhere).
    pub pin_threads: bool,

    /// When `true`, skip files that appear to be binary (NUL byte heuristic).
    pub skip_binary: bool,

    /// Archive scanning configuration (gzip, tar, zip expansion).
    pub archive: ArchiveConfig,
}

impl Default for LocalFsUringConfig {
    fn default() -> Self {
        Self {
            cpu_workers: 8,
            io_threads: 4,
            ring_entries: 256,
            io_depth: 128,
            chunk_size: 256 * 1024,
            max_in_flight_files: 512,
            file_queue_cap: 256,
            pool_buffers: 256,
            use_registered_buffers: false,
            open_stat_mode: OpenStatMode::default(),
            resolve_policy: ResolvePolicy::default(),
            follow_symlinks: false,
            max_file_size: None,
            seed: 1,
            dedupe_within_chunk: true,
            pin_threads: super::affinity::default_pin_threads(),
            skip_binary: true,
            archive: ArchiveConfig::default(),
        }
    }
}

impl LocalFsUringConfig {
    /// Validate configuration against engine requirements.
    ///
    /// # Panics
    ///
    /// Panics if configuration is invalid.
    pub fn validate<E: ScanEngine>(&self, engine: &E) {
        assert!(self.cpu_workers > 0, "cpu_workers must be > 0");
        assert!(self.io_threads > 0, "io_threads must be > 0");
        assert!(self.ring_entries >= 8, "ring_entries must be >= 8");
        assert!(self.chunk_size > 0, "chunk_size must be > 0");
        assert!(
            self.max_in_flight_files > 0,
            "max_in_flight_files must be > 0"
        );
        assert!(self.file_queue_cap > 0, "file_queue_cap must be > 0");
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        if self.use_registered_buffers {
            assert!(
                self.pool_buffers <= u16::MAX as usize,
                "pool_buffers ({}) must be <= u16::MAX for registered buffers",
                self.pool_buffers
            );
        }

        let overlap = engine.required_overlap();
        let buf_len = overlap.saturating_add(self.chunk_size);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size + overlap ({}) exceeds BUFFER_LEN_MAX ({})",
            buf_len,
            BUFFER_LEN_MAX
        );

        let max_depth = (self.ring_entries as usize).saturating_sub(1);
        assert!(self.io_depth > 0, "io_depth must be > 0");
        assert!(
            self.io_depth <= max_depth,
            "io_depth ({}) must be <= ring_entries - 1 ({})",
            self.io_depth,
            max_depth
        );

        // Buffer pool must be large enough to not guarantee starvation.
        // Minimum: each I/O thread can saturate io_depth.
        // Additional headroom for CPU task pipeline recommended but not required.
        let min_pool = self.io_threads.saturating_mul(self.io_depth);
        assert!(
            self.pool_buffers >= min_pool,
            "pool_buffers ({}) must be >= io_threads * io_depth ({}) to avoid starvation",
            self.pool_buffers,
            min_pool
        );
    }
}

// ============================================================================
// Summary Counters
// ============================================================================

/// Discovery and I/O counters for a complete io_uring scan run.
///
/// File paths and content are intentionally excluded to avoid leaking
/// sensitive data through log/metric channels.
///
/// Populated by the discovery walker and merged from I/O/archive/extraction
/// worker stats after join. `open_errors` and `read_errors` are aggregated
/// across all worker types.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalFsSummary {
    /// Files observed during directory walking (before any filtering).
    pub files_seen: u64,
    /// Files accepted and sent to I/O threads or archive workers.
    pub files_enqueued: u64,
    /// Directory read or entry metadata failures during discovery.
    pub walk_errors: u64,
    /// Files that failed to open (aggregated from I/O + archive workers).
    pub open_errors: u64,
    /// Files that failed during read or decompression.
    pub read_errors: u64,
    /// Files skipped because they exceeded `max_file_size`.
    pub files_skipped_size: u64,
    /// Files routed to archive workers based on extension detection.
    pub archives_routed: u64,
    /// Files skipped because they were classified as binary.
    pub binary_skipped: u64,
}

/// Per-I/O-thread operational counters, merged across threads after join.
///
/// Tracks each phase of the file lifecycle within the I/O worker:
/// open → stat → read → classify → dispatch. Useful for diagnosing
/// bottlenecks (e.g., high `open_stat_fallbacks` indicates kernel opcode
/// gaps, high `short_reads` indicates file truncation or race conditions).
#[derive(Clone, Copy, Debug, Default)]
pub struct UringIoStats {
    /// Files received from discovery and entered into the I/O state machine.
    pub files_started: u64,
    /// Files that could not be opened (open syscall or io_uring CQE error).
    pub files_open_failed: u64,
    /// io_uring openat/openat2 SQEs submitted.
    pub open_ops_submitted: u64,
    /// io_uring openat/openat2 CQEs reaped (success or failure).
    pub open_ops_completed: u64,
    /// io_uring statx SQEs submitted.
    pub stat_ops_submitted: u64,
    /// io_uring statx CQEs reaped (success or failure).
    pub stat_ops_completed: u64,
    /// Open ops that completed with an error CQE result.
    pub open_failures: u64,
    /// Stat ops that completed with an error CQE result.
    pub stat_failures: u64,
    /// Open/stat ops that fell back to blocking syscalls (unsupported opcode).
    pub open_stat_fallbacks: u64,
    /// Read SQEs submitted to io_uring.
    pub reads_submitted: u64,
    /// Read CQEs reaped (success or failure).
    pub reads_completed: u64,
    /// Read ops that returned a negative result (kernel error).
    pub read_errors: u64,
    /// Reads that returned fewer bytes than requested (file truncation).
    pub short_reads: u64,
    /// Files classified as binary and skipped on first-chunk content probe.
    pub binary_skipped: u64,
    /// Files rerouted to archive workers after magic-byte sniffing.
    pub archives_sniffed: u64,
    /// Archive sends that failed because the archive channel was closed.
    pub archives_send_failed: u64,
    /// Files routed to extraction workers (binary-extractable formats).
    pub extractions_routed: u64,
    /// Total authoritative file bytes (from statx) across all ready files.
    pub bytes_enqueued: u64,
}

// ============================================================================
// Fixed Buffer Pool (io_uring READ_FIXED)
// ============================================================================

/// Fixed buffer pool backed by a stable `Box<[u8]>` table.
///
/// Each buffer is individually heap-allocated in a `Box<[u8]>` and stored in
/// a `Vec<Box<[u8]>>`. The `Vec` stores *pointers*, so growing or shrinking
/// it would not move the backing allocations — but the pool is never resized
/// after construction. This address stability is required for safe
/// `register_buffers` with io_uring: the kernel retains pointers to these
/// buffers for DMA and writes directly into them on read completion. Moving
/// or deallocating the backing storage while operations are in-flight would
/// corrupt memory.
///
/// Concurrency model: a lock-free `ArrayQueue` tracks free buffer indices.
/// `try_acquire` pops an index (exclusive ownership), and `Drop` on the
/// returned [`FixedBufferHandle`] pushes the index back. This makes acquire
/// and release O(1) without locks, which matters because I/O threads acquire
/// under tight completion-processing loops.
struct FixedBufferPool {
    buffers: Vec<Box<[u8]>>,
    free: ArrayQueue<usize>,
}

impl FixedBufferPool {
    fn new(buffer_len: usize, total: usize) -> Arc<Self> {
        let mut buffers = Vec::with_capacity(total);
        for _ in 0..total {
            buffers.push(vec![0u8; buffer_len].into_boxed_slice());
        }

        let free = ArrayQueue::new(total);
        for idx in 0..total {
            free.push(idx).expect("fixed buffer free queue overflow");
        }

        Arc::new(Self { buffers, free })
    }

    #[inline]
    fn try_acquire(self: &Arc<Self>) -> Option<FixedBufferHandle> {
        self.free.pop().map(|index| FixedBufferHandle {
            pool: Arc::clone(self),
            index,
        })
    }

    /// Builds iovec list for `register_buffers`.
    ///
    /// The returned iovecs borrow the pool's heap buffers. The pool
    /// must outlive the io_uring registration (call `unregister_buffers`
    /// before dropping the pool).
    fn iovecs(&self) -> Vec<libc::iovec> {
        self.buffers
            .iter()
            .map(|buf| libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect()
    }

    #[inline]
    fn buf_ptr(&self, index: usize) -> *mut u8 {
        self.buffers[index].as_ptr() as *mut u8
    }

    #[inline]
    fn buf_len(&self, index: usize) -> usize {
        self.buffers[index].len()
    }
}

/// RAII handle to a single buffer in a [`FixedBufferPool`].
///
/// Ownership is exclusive: the free queue guarantees at most one handle exists
/// per buffer index at any time. Dropping the handle returns the buffer to the
/// pool's free queue, making it available for the next `try_acquire`.
///
/// # Lifetime coupling with io_uring
///
/// When a read op is in flight, the handle must live in the `ops[]` slab until
/// the CQE is reaped. The kernel writes directly into the buffer's memory, so
/// dropping the handle (and freeing the index) before completion would allow
/// another thread to acquire the same buffer and observe torn data.
struct FixedBufferHandle {
    pool: Arc<FixedBufferPool>,
    index: usize,
}

impl FixedBufferHandle {
    #[inline]
    fn buf_index(&self) -> u16 {
        self.index as u16
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.pool.buffers[self.index]
    }

    /// Mutable slice of the buffer.
    ///
    /// # Safety
    ///
    /// This uses `unsafe` to create a mutable slice from pooled storage.
    /// It is sound because each buffer index is owned by exactly one handle
    /// at a time (enforced by the free queue), and `&mut self` guarantees
    /// exclusive access to this handle.
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        let ptr = self.pool.buf_ptr(self.index);
        let len = self.pool.buf_len(self.index);
        // SAFETY: `buf_ptr` returns a valid pointer into the pool's heap-allocated
        // buffer for this buffer index, and `buf_len` returns its exact length. Each
        // buffer index is owned by exactly one handle at a time (enforced by the free
        // queue), and `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }
}

impl Drop for FixedBufferHandle {
    fn drop(&mut self) {
        self.pool
            .free
            .push(self.index)
            .expect("fixed buffer free queue overflow");
    }
}

impl UringIoStats {
    fn merge(&mut self, other: UringIoStats) {
        self.files_started += other.files_started;
        self.files_open_failed += other.files_open_failed;
        self.open_ops_submitted += other.open_ops_submitted;
        self.open_ops_completed += other.open_ops_completed;
        self.stat_ops_submitted += other.stat_ops_submitted;
        self.stat_ops_completed += other.stat_ops_completed;
        self.open_failures += other.open_failures;
        self.stat_failures += other.stat_failures;
        self.open_stat_fallbacks += other.open_stat_fallbacks;
        self.reads_submitted += other.reads_submitted;
        self.reads_completed += other.reads_completed;
        self.read_errors += other.read_errors;
        self.short_reads += other.short_reads;
        self.binary_skipped += other.binary_skipped;
        self.archives_sniffed += other.archives_sniffed;
        self.archives_send_failed += other.archives_send_failed;
        self.extractions_routed += other.extractions_routed;
        self.bytes_enqueued += other.bytes_enqueued;
    }
}

// ============================================================================
// Internal Types
// ============================================================================

/// Probed io_uring opcode capabilities for the current kernel.
///
/// Queried once per ring via `register_probe`. The result determines whether
/// the I/O thread uses io_uring open/stat or falls back to blocking syscalls.
#[derive(Clone, Copy, Debug)]
struct OpenStatCaps {
    /// IORING_OP_OPENAT supported.
    openat: bool,
    /// IORING_OP_OPENAT2 supported (needed for resolve policy flags).
    openat2: bool,
    /// IORING_OP_STATX supported.
    statx: bool,
    /// Kernel guarantees submit-time parameter stability (`IORING_FEAT_SUBMIT_STABLE`).
    submit_stable: bool,
}

impl OpenStatCaps {
    #[inline]
    fn supports_open_stat(&self) -> bool {
        (self.openat || self.openat2) && self.statx
    }
}

/// Map [`ResolvePolicy`] to `openat2(2)` resolve flags.
///
/// These flags restrict path traversal at the kernel level. Ignored when
/// the kernel doesn't support `IORING_OP_OPENAT2`.
fn resolve_bits(policy: ResolvePolicy) -> u64 {
    match policy {
        ResolvePolicy::Default => 0,
        ResolvePolicy::NoSymlinks => libc::RESOLVE_NO_SYMLINKS,
        ResolvePolicy::BeneathRoot => libc::RESOLVE_BENEATH,
    }
}

/// Probe the io_uring instance for supported opcodes and features.
///
/// Called once per I/O thread during ring setup. The result is used to decide
/// between io_uring-based open/stat and blocking fallback paths.
fn probe_uring_caps(ring: &IoUring) -> io::Result<OpenStatCaps> {
    let mut probe = Probe::new();
    ring.submitter().register_probe(&mut probe)?;

    Ok(OpenStatCaps {
        openat: probe.is_supported(opcode::OpenAt::CODE),
        openat2: probe.is_supported(opcode::OpenAt2::CODE),
        statx: probe.is_supported(opcode::Statx::CODE),
        submit_stable: ring.params().is_feature_submit_stable(),
    })
}

/// Per-file lifecycle token that ties a [`CountPermit`] to scan completion.
///
/// Shared via `Arc` among the I/O thread and all CPU tasks spawned for this
/// file's chunks. The permit is released when the last `Arc<FileToken>` drops,
/// which signals `CountBudget` that one in-flight file slot is free for
/// discovery to fill. This is the backpressure mechanism that bounds
/// `max_in_flight_files`.
struct FileToken {
    _permit: CountPermit,
    file_id: FileId,
    /// Path bytes for output (no heap allocation per finding).
    display: Arc<[u8]>,
}

/// Work item sent from discovery to I/O threads via the bounded file channel.
///
/// The token's permit keeps backpressure: discovery blocks when
/// `max_in_flight_files` is reached, and the permit releases when all chunks
/// of this file have been scanned (or the file is skipped/failed).
struct FileWork {
    path: PathBuf,
    token: Arc<FileToken>,
}

/// Work item sent to archive worker threads.
///
/// Routed in two ways: extension-based (from discovery walker) or
/// magic-byte sniffing (from I/O thread first-chunk classification).
/// Archive workers open the file themselves, so no fd is carried here.
struct ArchiveWork {
    path: PathBuf,
    kind: ArchiveKind,
    token: Arc<FileToken>,
}

/// Work item sent to binary-extraction worker threads.
///
/// Routed from I/O threads when `skip_binary` is true and the first chunk
/// is classified as `BinaryExtractable` (e.g., `.ipynb`, `.class`, `.jar`,
/// `.war`, `.pyc`). The already-open file descriptor is transferred so
/// extraction avoids an extra open syscall and preserves open-time snapshot
/// semantics.
struct ExtractWork {
    file: File,
    file_size: u64,
    fmt: crate::content_policy::ExtractableFormat,
    token: Arc<FileToken>,
}

/// Task dispatched from I/O threads to the work-stealing CPU executor.
///
/// Currently a single-variant enum. The enum wrapper exists for forward
/// compatibility if additional task types are needed (e.g., finalization
/// tasks, metadata extraction). Each variant carries all data needed for
/// scanning with no shared mutable state — the executor can run tasks on
/// any worker thread without locking.
enum CpuTask {
    /// Scan a single chunk of a file.
    ///
    /// The buffer contains `prefix_len` bytes of overlap from the previous
    /// chunk (copied in-memory by the I/O thread, not re-read from disk)
    /// followed by fresh payload bytes. `base_offset` is the file offset
    /// of byte 0 in the buffer (i.e., `read_offset - prefix_len`). `len`
    /// is the total number of valid bytes (`prefix_len + payload`).
    ///
    /// The `token` keeps the file's `CountPermit` alive. When the last
    /// `Arc<FileToken>` for a file drops (all chunks scanned), the permit
    /// is released and discovery can fill the freed slot.
    ScanChunk {
        token: Arc<FileToken>,
        base_offset: u64,
        prefix_len: u32,
        len: u32,
        buf: FixedBufferHandle,
    },
}

/// Per-CPU-worker scratch space, owned by exactly one executor thread.
///
/// Holds the engine scratch buffer, a reusable findings vec, and references
/// to shared immutable state. Each executor worker gets its own instance
/// at startup; nothing is shared across workers.
///
/// The `pending` vec is cleared by `scan_chunk_postprocess` before each
/// chunk's `drain_findings_into` to avoid cross-chunk finding accumulation.
struct CpuScratch<E: ScanEngine> {
    engine: Arc<E>,
    event_sink: Arc<dyn EventOutput>,
    scratch: E::Scratch,
    pending: Vec<<E::Scratch as EngineScratch>::Finding>,
}

// ============================================================================
// CPU Task Runner
// ============================================================================

/// Executor callback: scans one chunk and emits findings.
///
/// Pipeline: `scan_chunk_into` → `drop_prefix_findings` → `drain` → dedupe → emit.
///
/// Prefix findings (those fully contained within the overlap region) are
/// dropped to avoid double-counting across consecutive chunks. Metrics track
/// only new-payload bytes to give an accurate throughput measure.
fn cpu_runner<E: ScanEngine>(task: CpuTask, ctx: &mut WorkerCtx<CpuTask, CpuScratch<E>>) {
    match task {
        CpuTask::ScanChunk {
            token,
            base_offset,
            prefix_len,
            len,
            buf,
        } => {
            let engine = ctx.scratch.engine.as_ref();

            let len_usize = len as usize;
            let data = &buf.as_slice()[..len_usize];

            scan_chunk_postprocess(
                engine,
                &mut ctx.scratch.scratch,
                &mut ctx.scratch.pending,
                token.file_id,
                base_offset,
                prefix_len as usize,
                data,
                &mut ctx.metrics,
            );

            shared_emit_findings(
                engine,
                &*ctx.scratch.event_sink,
                &token.display,
                &ctx.scratch.pending,
            );

            // Buffer returns to pool on drop (RAII).
            drop(buf);
        }
    }
}

// ============================================================================
// Archive Sink + Worker
// ============================================================================

/// Sink that forwards archive entry chunks to the scan engine.
///
/// Implements `ArchiveEntrySink` following the same pattern as `cpu_runner`:
/// scan_chunk_into → drop_prefix_findings → drain → dedupe → emit.
struct UringArchiveSink<'a, E: ScanEngine> {
    engine: &'a E,
    scratch: &'a mut E::Scratch,
    pending: &'a mut Vec<<E::Scratch as EngineScratch>::Finding>,
    event_sink: &'a dyn EventOutput,
    display: Vec<u8>,
    container_file_id: FileId,
    next_entry_index: u32,
    file_ids: Arc<FileIdAllocator>,
    file_id: FileId,
    bytes_scanned: u64,
    chunks_scanned: u64,
    findings_emitted: u64,
    findings_dropped: u64,
}

impl<E: ScanEngine> ArchiveEntrySink for UringArchiveSink<'_, E> {
    type Error = ();

    fn on_entry_start(&mut self, meta: &EntryMeta<'_>) -> Result<(), Self::Error> {
        self.display.clear();
        self.display.extend_from_slice(meta.display_path);
        // Use a run-global allocator so archive entries never reuse ids from
        // neighboring archives or regular files.
        self.file_id = self
            .file_ids
            .next_archive_entry_file_id(self.container_file_id, &mut self.next_entry_index)
            .ok_or(())?;
        Ok(())
    }

    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error> {
        self.engine
            .scan_chunk_into(chunk.data, self.file_id, chunk.base_offset, self.scratch);
        let engine_dropped = self.scratch.dropped_findings();
        let before_prefix = self.scratch.pending_findings_len();
        self.scratch.drop_prefix_findings(chunk.new_bytes_start);
        let after_prefix = self.scratch.pending_findings_len();

        self.pending.clear();
        self.scratch.drain_findings_into(self.pending);

        let dedupe_removed = apply_cross_rule_dedupe(self.pending, self.engine);
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(dedupe_removed);
        let effective_dropped = engine_dropped.saturating_sub(scheduler_pruned as u64);
        self.findings_dropped = self.findings_dropped.saturating_add(effective_dropped);

        self.findings_emitted += self.pending.len() as u64;
        shared_emit_findings(self.engine, self.event_sink, &self.display, self.pending);

        self.bytes_scanned += chunk.new_bytes_len as u64;
        self.chunks_scanned += 1;
        Ok(())
    }

    fn on_entry_end(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Aggregate stats from a single archive worker thread, merged into
/// [`MetricsSnapshot`] after the worker joins.
struct ArchiveWorkerStats {
    bytes_scanned: u64,
    chunks_scanned: u64,
    findings_emitted: u64,
    findings_dropped: u64,
    archives_open_failed: u64,
    archives_scan_errors: u64,
    archive_stats: ArchiveStats,
}

/// Per-archive-worker loop: drains [`ArchiveWork`] from the channel and
/// dispatches each item to the appropriate archive scanner.
///
/// Runs on a dedicated thread. Returns aggregate stats when the channel
/// closes (all senders dropped). Each archive is opened, decompressed/parsed,
/// and its entries scanned via [`UringArchiveSink`] using the same
/// scan → dedupe → emit pipeline as regular chunks.
fn archive_worker_loop<E: ScanEngine>(
    rx: chan::Receiver<ArchiveWork>,
    engine: Arc<E>,
    event_sink: Arc<dyn EventOutput>,
    file_ids: Arc<FileIdAllocator>,
    cfg: ArchiveConfig,
) -> ArchiveWorkerStats {
    let overlap = engine.required_overlap();
    let chunk_size = 256 * 1024; // Match ARCHIVE_STREAM_READ_MAX ceiling.

    let mut scratch = engine.new_scratch();
    let mut pending = Vec::with_capacity(4096);
    let mut archive_scratch: ArchiveScratch<File> = ArchiveScratch::new(&cfg, chunk_size, overlap);
    let mut archive_stats = ArchiveStats::default();
    let mut total_bytes = 0u64;
    let mut total_chunks = 0u64;
    let mut total_findings = 0u64;
    let mut total_dropped = 0u64;

    let mut archives_open_failed = 0u64;
    let mut archives_scan_errors = 0u64;

    for work in rx {
        let display = &*work.token.display;
        let file = match File::open(&work.path) {
            Ok(f) => f,
            Err(_e) => {
                archives_open_failed += 1;
                #[cfg(debug_assertions)]
                eprintln!(
                    "[uring-archive] Failed to open archive {:?}: {}",
                    work.path, _e
                );
                continue;
            }
        };

        let mut sink = UringArchiveSink {
            engine: engine.as_ref(),
            scratch: &mut scratch,
            pending: &mut pending,
            event_sink: &*event_sink,
            display: Vec::new(),
            container_file_id: work.token.file_id,
            next_entry_index: 0,
            file_ids: Arc::clone(&file_ids),
            file_id: work.token.file_id,
            bytes_scanned: 0,
            chunks_scanned: 0,
            findings_emitted: 0,
            findings_dropped: 0,
        };

        let scan_result = match work.kind {
            ArchiveKind::Gzip => scan_gzip_stream(
                file,
                display,
                &cfg,
                &mut archive_scratch,
                &mut sink,
                &mut archive_stats,
            ),
            ArchiveKind::Bzip2 => scan_bzip2_stream(
                file,
                display,
                &cfg,
                &mut archive_scratch,
                &mut sink,
                &mut archive_stats,
            ),
            ArchiveKind::Tar => {
                let mut file = file;
                scan_tar_stream(
                    &mut file,
                    display,
                    &cfg,
                    &mut archive_scratch,
                    &mut sink,
                    &mut archive_stats,
                    false,
                )
            }
            ArchiveKind::TarGz => scan_targz_stream(
                file,
                display,
                &cfg,
                &mut archive_scratch,
                &mut sink,
                &mut archive_stats,
            ),
            ArchiveKind::TarBz2 => scan_tarbz2_stream(
                file,
                display,
                &cfg,
                &mut archive_scratch,
                &mut sink,
                &mut archive_stats,
            ),
            ArchiveKind::Zip => scan_zip_source(
                file,
                display,
                &cfg,
                &mut archive_scratch,
                &mut sink,
                &mut archive_stats,
            ),
        };

        if let Err(_e) = scan_result {
            archives_scan_errors += 1;
            #[cfg(debug_assertions)]
            eprintln!("[uring-archive] Scan failed for {:?}: {:?}", work.path, _e);
        }

        total_bytes += sink.bytes_scanned;
        total_chunks += sink.chunks_scanned;
        total_findings += sink.findings_emitted;
        total_dropped += sink.findings_dropped;

        // Token drop releases the CountPermit, unblocking discovery.
        drop(work.token);
    }

    ArchiveWorkerStats {
        bytes_scanned: total_bytes,
        chunks_scanned: total_chunks,
        findings_emitted: total_findings,
        findings_dropped: total_dropped,
        archives_open_failed,
        archives_scan_errors,
        archive_stats,
    }
}

// ============================================================================
// Extraction Workers
// ============================================================================

/// Aggregate stats from a single extraction worker thread, merged into
/// [`MetricsSnapshot`] after the worker joins.
struct ExtractWorkerStats {
    bytes_scanned: u64,
    chunks_scanned: u64,
    findings_emitted: u64,
    findings_dropped: u64,
    files_extracted: u64,
    io_errors: u64,
}

/// Per-extraction-worker loop: drains [`ExtractWork`] from the channel,
/// reads each already-open file descriptor, extracts scannable text (capped at
/// 64 MiB input), and
/// scans the extracted content as a single chunk.
///
/// Runs on a dedicated thread. Returns aggregate stats when the channel
/// closes. Unlike the archive worker, extraction produces at most one
/// chunk per file (no streaming), so there is no overlap handling.
fn extract_worker_loop<E: ScanEngine>(
    rx: chan::Receiver<ExtractWork>,
    engine: Arc<E>,
    event_sink: Arc<dyn EventOutput>,
) -> ExtractWorkerStats {
    use crate::content_policy::extract::{
        extract_content, ExtractResult, EXTRACT_INPUT_CAP, EXTRACT_OUTPUT_CAP, JAR_ENTRY_CAP,
    };
    use std::io::Read as _;

    let mut scratch = engine.new_scratch();
    let mut pending = Vec::with_capacity(4096);
    let mut input_buf = Vec::with_capacity(EXTRACT_INPUT_CAP);
    let mut output_buf = Vec::with_capacity(EXTRACT_OUTPUT_CAP);
    let mut extract_scratch = Vec::with_capacity(JAR_ENTRY_CAP);

    let mut total_bytes = 0u64;
    let mut total_chunks = 0u64;
    let mut total_findings = 0u64;
    let mut total_dropped = 0u64;
    let mut files_extracted = 0u64;
    let mut io_errors = 0u64;

    for work in rx {
        let display = &*work.token.display;

        // Read entire file (capped at 64 MiB).
        let read_limit = work.file_size.min(64 * 1024 * 1024u64) as usize;
        input_buf.clear();
        input_buf.reserve(read_limit.min(4096));
        if work
            .file
            .take(read_limit as u64)
            .read_to_end(&mut input_buf)
            .is_err()
        {
            io_errors = io_errors.saturating_add(1);
            continue;
        }

        let result = extract_content(work.fmt, &input_buf, &mut output_buf, &mut extract_scratch);

        if result != ExtractResult::Ok || output_buf.is_empty() {
            continue;
        }

        files_extracted += 1;

        // Scan extracted text as a single chunk.
        engine.scan_chunk_into(&output_buf, work.token.file_id, 0, &mut scratch);
        let engine_dropped = scratch.dropped_findings();
        let before_prefix = scratch.pending_findings_len();
        scratch.drop_prefix_findings(0);
        let after_prefix = scratch.pending_findings_len();

        pending.clear();
        scratch.drain_findings_into(&mut pending);

        let dedupe_removed = apply_cross_rule_dedupe(&mut pending, engine.as_ref());
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(dedupe_removed);
        let effective_dropped = engine_dropped.saturating_sub(scheduler_pruned as u64);
        total_dropped = total_dropped.saturating_add(effective_dropped);

        total_findings += pending.len() as u64;
        shared_emit_findings(engine.as_ref(), &*event_sink, display, &pending);

        total_bytes += output_buf.len() as u64;
        total_chunks += 1;

        // Token drop releases the CountPermit, unblocking discovery.
        drop(work.token);
    }

    ExtractWorkerStats {
        bytes_scanned: total_bytes,
        chunks_scanned: total_chunks,
        findings_emitted: total_findings,
        findings_dropped: total_dropped,
        files_extracted,
        io_errors,
    }
}

// ============================================================================
// I/O Worker State
// ============================================================================

/// Per-file state tracked by I/O worker.
///
/// # Invariants
///
/// - `in_flight` is 0 or 1 (single op in-flight per file)
/// - `done` is monotonic: once true, never reset to false
/// - `failed` is monotonic: once true, never reset to false
/// - `phase` only moves forward: PendingOpen → PendingStat → Ready
///   (blocking fallback may skip PendingStat)
struct FileState {
    phase: FilePhase,
    in_flight: u32,
    done: bool,
    failed: bool,
    token: Arc<FileToken>,
}

/// State machine phase for a file being processed by an I/O thread.
///
/// Transitions are forward-only: `PendingOpen → PendingStat → Ready`.
/// When blocking fallback is used (open failure with EINVAL/EOPNOTSUPP,
/// or `BlockingOnly` mode), `PendingStat` may be skipped entirely.
/// Each transition is driven by a CQE completion (or blocking fallback).
/// The I/O thread enforces at most one in-flight op per file at any phase.
enum FilePhase {
    /// Path queued for open via io_uring (or fallback).
    PendingOpen { path: PathBuf },
    /// File opened; waiting on statx for size snapshot.
    /// `file` is `Some` until consumed by the transition to `Ready`.
    PendingStat { file: Option<File> },
    /// File sized and ready for chunked reads. Holds mutable read progress.
    Ready(ReadState),
}

/// Mutable progress for chunked reads of a single file.
///
/// `next_offset` advances by `payload_len` (at most `chunk_size`) after each read
/// submission. `overlap_buf` carries the tail bytes of the previous chunk so
/// the next read's buffer can be prefixed without re-reading from disk.
struct ReadState {
    /// Open file descriptor for this slot. `None` only after ownership is
    /// transferred to extraction workers for `BinaryExtractable` files.
    file: Option<File>,
    /// Authoritative file size from fstat/statx at open time.
    size: u64,
    /// Byte offset of the next payload read (not counting overlap prefix).
    next_offset: u64,
    /// Tail bytes from the previous chunk, copied into the next buffer's prefix.
    overlap_buf: Box<[u8]>,
    /// Number of valid bytes in `overlap_buf` (0 for the first chunk).
    overlap_len: usize,
}

/// Per-op state for completion matching.
///
/// # Lifetime Coupling
///
/// - `Open`: path + open_how must live until CQE is reaped
/// - `Stat`: statx buffer must live until CQE is reaped
/// - `Read`: buffer must live until CQE is reaped
enum Op {
    Open(OpenOp),
    Stat(StatOp),
    Read(ReadOp),
}

/// State for an in-flight openat/openat2 op.
///
/// `path` and `open_how` are kept alive here because the kernel may read them
/// asynchronously between SQE submission and CQE completion. Dropping them
/// early would be use-after-free.
struct OpenOp {
    file_slot: usize,
    _path: CString,
    _open_how: Option<Box<types::OpenHow>>,
}

/// State for an in-flight statx op.
///
/// `statx_buf` is written to by the kernel on completion; it must not be
/// moved or dropped until the CQE is reaped.
struct StatOp {
    file_slot: usize,
    statx_buf: Box<libc::statx>,
}

/// State for an in-flight read op.
///
/// `buf` holds the target memory for the kernel read. `prefix_len` bytes at
/// the front are overlap copied from the previous chunk (already filled before
/// submission). `payload_len` is the number of new bytes requested from disk.
struct ReadOp {
    file_slot: usize,
    /// File offset corresponding to byte 0 of `buf` (i.e., start of overlap).
    base_offset: u64,
    prefix_len: usize,
    payload_len: usize,
    buf: FixedBufferHandle,
}

// ============================================================================
// I/O Worker Loop
// ============================================================================

/// Drain all in-flight operations before returning.
///
/// Waits for every outstanding CQE and disposes of the associated `Op`.
/// For `Read` ops the `FixedBufferHandle` is dropped, returning it to the
/// pool. For `Open` ops with a successful result the returned fd is closed
/// to prevent leaks. No scan tasks are spawned — this is a shutdown path.
///
/// # Safety requirement
///
/// This MUST be called before dropping the ring/ops if any operations
/// are in-flight, otherwise the kernel may write to freed memory.
fn drain_in_flight(
    ring: &mut IoUring,
    ops: &mut [Option<Op>],
    in_flight_ops: &mut usize,
    stats: &mut UringIoStats,
) -> io::Result<()> {
    while *in_flight_ops > 0 {
        ring.submit_and_wait(1)?;

        for cqe in ring.completion() {
            let op_slot = cqe.user_data() as usize;

            if let Some(op) = ops.get_mut(op_slot).and_then(|o| o.take()) {
                let res = cqe.result();
                *in_flight_ops = in_flight_ops.saturating_sub(1);

                match op {
                    Op::Read(op) => {
                        // Buffer dropped here, returned to pool
                        drop(op.buf);
                        perf_stats::sat_add_u64(&mut stats.reads_completed, 1);
                        if res < 0 {
                            stats.read_errors = stats.read_errors.saturating_add(1);
                        }
                    }
                    Op::Open(_op) => {
                        perf_stats::sat_add_u64(&mut stats.open_ops_completed, 1);
                        if res < 0 {
                            perf_stats::sat_add_u64(&mut stats.open_failures, 1);
                        } else {
                            // Prevent fd leak on shutdown path.
                            // SAFETY: `res` is a valid fd returned by the kernel
                            // via io_uring openat/openat2. We own it exclusively
                            // (no File wrapper created on this drain path).
                            unsafe {
                                libc::close(res);
                            }
                        }
                    }
                    Op::Stat(_op) => {
                        perf_stats::sat_add_u64(&mut stats.stat_ops_completed, 1);
                        if res < 0 {
                            perf_stats::sat_add_u64(&mut stats.stat_failures, 1);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Open a file read-only with optional `O_NOFOLLOW` for symlink safety.
///
/// When `follow_symlinks` is false, `O_NOFOLLOW` causes the open to fail with
/// `ELOOP` if the final path component is a symlink. This prevents TOCTOU
/// attacks where a regular file is replaced with a symlink between discovery
/// and open.
#[cfg(unix)]
fn open_file_safe(path: &Path, follow_symlinks: bool) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.read(true);

    if !follow_symlinks {
        // O_NOFOLLOW: fail if path is a symlink (prevents TOCTOU)
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    opts.open(path)
}

/// Main I/O worker loop using io_uring.
///
/// # Correctness
///
/// - **Single-chunk-in-flight per file**: We only allow one outstanding read
///   per file to ensure prefix-drop deduplication logic is valid (no gaps from
///   failed earlier chunks).
/// - **Open/stat staging**: Each file advances `PendingOpen → PendingStat → Ready`
///   (or directly to `Ready` via blocking fallback) before any reads are submitted.
/// - **Drain before return**: All in-flight ops MUST complete before we return,
///   otherwise the kernel may write to freed memory.
/// - **Buffer lifetime**: Buffers live in `ops[]` until CQE is reaped.
/// - **Fallback safety**: Unsupported open/stat opcodes fall back to blocking
///   open + fstat unless `open_stat_mode = UringRequired`.
///
/// # Shutdown
///
/// On `stop` signal or channel close, we stop accepting new work but drain
/// all in-flight operations to completion.
#[allow(clippy::too_many_arguments)]
fn io_worker_loop<E: ScanEngine>(
    _wid: usize,
    rx: chan::Receiver<FileWork>,
    pool: Arc<FixedBufferPool>,
    cpu: ExecutorHandle<CpuTask>,
    engine: Arc<E>,
    cfg: LocalFsUringConfig,
    stop: Arc<AtomicBool>,
    archive_tx: Option<chan::Sender<ArchiveWork>>,
    extract_tx: Option<chan::Sender<ExtractWork>>,
) -> io::Result<UringIoStats> {
    let overlap = engine.required_overlap();
    let chunk_size = cfg.chunk_size;
    let buf_len = overlap.saturating_add(chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    let mut ring = IoUring::new(cfg.ring_entries)?;
    let mut stats = UringIoStats::default();
    let mut registered_buffers = false;

    // Probe once per ring to decide open/stat eligibility and record fallback.
    let mut open_stat_fallback = false;
    let open_stat_caps = match cfg.open_stat_mode {
        OpenStatMode::BlockingOnly => None,
        _ => match probe_uring_caps(&ring) {
            Ok(caps) => Some(caps),
            Err(err) => {
                if cfg.open_stat_mode == OpenStatMode::UringRequired {
                    return Err(err);
                }
                open_stat_fallback = true;
                None
            }
        },
    };

    let open_stat_supported = open_stat_caps
        .as_ref()
        .is_some_and(|caps| caps.supports_open_stat());
    let _submit_stable = open_stat_caps
        .as_ref()
        .is_some_and(|caps| caps.submit_stable);

    match cfg.open_stat_mode {
        OpenStatMode::BlockingOnly => {}
        OpenStatMode::UringPreferred => {
            if !open_stat_supported {
                open_stat_fallback = true;
            }
        }
        OpenStatMode::UringRequired => {
            if !open_stat_supported {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "io_uring open/stat opcodes unsupported",
                ));
            }
        }
    }

    if open_stat_fallback {
        perf_stats::sat_add_u64(&mut stats.open_stat_fallbacks, 1);
    }

    if cfg.use_registered_buffers {
        let bufs = pool.iovecs();
        // SAFETY: Buffers are owned by the pool and live for the lifetime
        // of the ring. We unregister after draining completions.
        unsafe {
            ring.submitter().register_buffers(&bufs)?;
        }
        registered_buffers = true;
    }

    // File slab + per-phase queues for files ready to submit (not in-flight).
    let mut files: Vec<Option<FileState>> = Vec::new();
    let mut free_file_slots: Vec<usize> = Vec::new();
    // CORRECTNESS: Files in ready queues have in_flight == 0.
    let mut open_ready: VecDeque<usize> = VecDeque::new();
    let mut stat_ready: VecDeque<usize> = VecDeque::new();
    let mut read_ready: VecDeque<usize> = VecDeque::new();

    // Op slots keyed by user_data.
    let slots = cfg.ring_entries as usize;
    let mut ops: Vec<Option<Op>> = (0..slots).map(|_| None).collect();
    let mut free_ops: Vec<usize> = (0..slots).rev().collect();

    let mut in_flight_ops: usize = 0;
    let mut stopping = false;
    let mut channel_closed = false;

    /// Result of blocking open + fstat for files when io_uring open/stat
    /// ops are unsupported or the mode is `BlockingOnly`.
    enum BlockingOutcome {
        /// File opened and sized; ready for read submissions.
        Ready(ReadState),
        /// File skipped (empty or exceeds `max_file_size`).
        Skipped,
        /// Open or fstat failed.
        Failed,
    }

    let blocking_open = |path: &Path, stats: &mut UringIoStats| -> BlockingOutcome {
        // Use O_NOFOLLOW when follow_symlinks is false to prevent TOCTOU attacks.
        let file = match open_file_safe(path, cfg.follow_symlinks) {
            Ok(f) => f,
            Err(_) => {
                stats.files_open_failed = stats.files_open_failed.saturating_add(1);
                return BlockingOutcome::Failed;
            }
        };

        // Use actual file size from fstat, not discovery-time size.
        // This handles files that grew or shrank between discovery and open.
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => {
                stats.files_open_failed = stats.files_open_failed.saturating_add(1);
                return BlockingOutcome::Failed;
            }
        };

        if let Some(max_sz) = cfg.max_file_size {
            if size > max_sz {
                return BlockingOutcome::Skipped;
            }
        }

        if size == 0 {
            return BlockingOutcome::Skipped;
        }

        BlockingOutcome::Ready(ReadState {
            file: Some(file),
            size,
            next_offset: 0,
            overlap_buf: vec![0u8; overlap].into_boxed_slice(),
            overlap_len: 0,
        })
    };

    // Helper: add file work to tracking.
    let add_file = |w: FileWork,
                    stats: &mut UringIoStats,
                    files: &mut Vec<Option<FileState>>,
                    free_file_slots: &mut Vec<usize>,
                    open_ready: &mut VecDeque<usize>,
                    read_ready: &mut VecDeque<usize>| {
        perf_stats::sat_add_u64(&mut stats.files_started, 1);

        if open_stat_supported {
            let slot = free_file_slots.pop().unwrap_or_else(|| {
                files.push(None);
                files.len() - 1
            });

            files[slot] = Some(FileState {
                phase: FilePhase::PendingOpen { path: w.path },
                in_flight: 0,
                done: false,
                failed: false,
                token: w.token,
            });

            open_ready.push_back(slot);
            return;
        }

        // Blocking fallback: open + fstat to build read state.
        let read_state = match blocking_open(&w.path, stats) {
            BlockingOutcome::Ready(state) => state,
            BlockingOutcome::Skipped => {
                drop(w.token);
                return;
            }
            BlockingOutcome::Failed => {
                drop(w.token);
                return;
            }
        };

        perf_stats::sat_add_u64(&mut stats.bytes_enqueued, read_state.size);

        let slot = free_file_slots.pop().unwrap_or_else(|| {
            files.push(None);
            files.len() - 1
        });

        files[slot] = Some(FileState {
            phase: FilePhase::Ready(read_state),
            in_flight: 0,
            done: false,
            failed: false,
            token: w.token,
        });

        read_ready.push_back(slot);
    };

    loop {
        // Check stop flag - but don't exit immediately, must drain first.
        if stop.load(Ordering::Relaxed) {
            stopping = true;
        }

        // If stopping, don't accept new files.
        if !stopping && !channel_closed {
            // Pull new files opportunistically (batch up to 64).
            for _ in 0..64 {
                match rx.try_recv() {
                    Ok(w) => add_file(
                        w,
                        &mut stats,
                        &mut files,
                        &mut free_file_slots,
                        &mut open_ready,
                        &mut read_ready,
                    ),
                    Err(chan::TryRecvError::Empty) => break,
                    Err(chan::TryRecvError::Disconnected) => {
                        channel_closed = true;
                        break;
                    }
                }
            }
        }

        // Track SQEs queued this iteration for batched submission.
        let mut submitted_this_round = 0;

        // Fill submissions up to io_depth.
        // CORRECTNESS: Only one op in-flight per file at a time.
        while in_flight_ops < cfg.io_depth && !stopping {
            if free_ops.is_empty() {
                break;
            }

            let mut scheduled = false;

            // Prefer reads (buffered) to keep throughput high.
            if let Some(file_slot) = read_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    // Stale slot.
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                match &mut st.phase {
                    FilePhase::Ready(rs) => {
                        // INVARIANT: Files in read queue should have in_flight == 0.
                        debug_assert_eq!(
                            st.in_flight, 0,
                            "file in read queue should not have in-flight ops"
                        );

                        if rs.next_offset >= rs.size {
                            st.done = true;
                            files[file_slot] = None;
                            free_file_slots.push(file_slot);
                            continue;
                        }

                        if let Some(mut buf) = pool.try_acquire() {
                            let offset = rs.next_offset;
                            let prefix_len = rs.overlap_len;

                            let payload_len = (rs.size - offset).min(chunk_size as u64) as usize;

                            debug_assert!(prefix_len + payload_len <= buf_len);

                            // Copy overlap bytes from the previous chunk into the buffer so we
                            // only read the payload from disk (no overlap re-reads).
                            if prefix_len > 0 {
                                buf.as_mut_slice()[..prefix_len]
                                    .copy_from_slice(&rs.overlap_buf[..prefix_len]);
                            }

                            let Some(file) = rs.file.as_ref() else {
                                st.failed = true;
                                st.done = true;
                                drop(buf);
                                files[file_slot] = None;
                                free_file_slots.push(file_slot);
                                continue;
                            };

                            let op_slot = free_ops.pop().unwrap();
                            let fd = file.as_raw_fd();
                            // SAFETY: `prefix_len < buffer_len` (clamped above), so
                            // `add(prefix_len)` stays within the buffer allocation.
                            let ptr = unsafe { buf.as_mut_slice().as_mut_ptr().add(prefix_len) };

                            let entry = if cfg.use_registered_buffers {
                                opcode::ReadFixed::new(
                                    types::Fd(fd),
                                    ptr,
                                    payload_len as u32,
                                    buf.buf_index(),
                                )
                                .offset(offset)
                                .build()
                            } else {
                                opcode::Read::new(types::Fd(fd), ptr, payload_len as u32)
                                    .offset(offset)
                                    .build()
                            }
                            .user_data(op_slot as u64);

                            // SAFETY:
                            // - `buf` lives in `ops[op_slot]` until completion
                            // - `rs.file` lives until file cleanup
                            // - We drain all in-flight ops before returning
                            unsafe {
                                let mut sq = ring.submission();
                                if sq.push(&entry).is_err() {
                                    // SQ unexpectedly full - return resources and break.
                                    drop(buf);
                                    free_ops.push(op_slot);
                                    read_ready.push_front(file_slot);
                                    break;
                                }
                            }

                            let base_offset = offset.saturating_sub(prefix_len as u64);

                            ops[op_slot] = Some(Op::Read(ReadOp {
                                file_slot,
                                base_offset,
                                prefix_len,
                                payload_len,
                                buf,
                            }));

                            in_flight_ops += 1;
                            submitted_this_round += 1;
                            perf_stats::sat_add_u64(&mut stats.reads_submitted, 1);

                            st.in_flight = 1; // Exactly 1 - single in-flight per file
                            rs.next_offset = rs.next_offset.saturating_add(payload_len as u64);
                            scheduled = true;
                        } else {
                            // No buffer: re-queue and allow open/stat to proceed.
                            read_ready.push_back(file_slot);
                        }
                    }
                    FilePhase::PendingOpen { .. } => {
                        open_ready.push_back(file_slot);
                    }
                    FilePhase::PendingStat { .. } => {
                        stat_ready.push_back(file_slot);
                    }
                }
            }

            if scheduled {
                continue;
            }

            if let Some(file_slot) = stat_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                let FilePhase::PendingStat { file } = &st.phase else {
                    // Phase drift: re-queue based on actual phase.
                    match &st.phase {
                        FilePhase::PendingOpen { .. } => open_ready.push_back(file_slot),
                        FilePhase::Ready(_) => read_ready.push_back(file_slot),
                        FilePhase::PendingStat { .. } => {}
                    }
                    continue;
                };

                let Some(file) = file.as_ref() else {
                    // Already moved; mark failed to avoid spin.
                    st.failed = true;
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                };

                debug_assert_eq!(
                    st.in_flight, 0,
                    "file in stat queue should not have in-flight ops"
                );

                // SAFETY: `libc::statx` is a C struct where all-zeros is a valid
                // representation. The kernel overwrites the fields we need.
                let mut statx_buf = Box::new(unsafe { std::mem::zeroed::<libc::statx>() });
                let statx_ptr = statx_buf.as_mut() as *mut libc::statx as *mut types::statx;
                let empty_path = b"\0";

                let entry = opcode::Statx::new(
                    types::Fd(file.as_raw_fd()),
                    empty_path.as_ptr() as *const _,
                    statx_ptr,
                )
                .flags(libc::AT_EMPTY_PATH)
                .mask(libc::STATX_SIZE | libc::STATX_TYPE | libc::STATX_MODE)
                .build();

                let op_slot = free_ops.pop().unwrap();
                let entry = entry.user_data(op_slot as u64);

                // SAFETY: `entry` is a fully-built statx SQE whose fd, path pointer,
                // and statx buffer all remain valid until the CQE is reaped. The
                // op_slot user_data ensures we can match the completion.
                unsafe {
                    let mut sq = ring.submission();
                    if sq.push(&entry).is_err() {
                        free_ops.push(op_slot);
                        stat_ready.push_front(file_slot);
                        break;
                    }
                }

                ops[op_slot] = Some(Op::Stat(StatOp {
                    file_slot,
                    statx_buf,
                }));

                in_flight_ops += 1;
                submitted_this_round += 1;
                perf_stats::sat_add_u64(&mut stats.stat_ops_submitted, 1);
                st.in_flight = 1;
                scheduled = true;
            }

            if scheduled {
                continue;
            }

            if let Some(file_slot) = open_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                let FilePhase::PendingOpen { path } = &st.phase else {
                    match &st.phase {
                        FilePhase::PendingStat { .. } => stat_ready.push_back(file_slot),
                        FilePhase::Ready(_) => read_ready.push_back(file_slot),
                        FilePhase::PendingOpen { .. } => {}
                    }
                    continue;
                };

                debug_assert_eq!(
                    st.in_flight, 0,
                    "file in open queue should not have in-flight ops"
                );

                let flags = libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | if cfg.follow_symlinks {
                        0
                    } else {
                        libc::O_NOFOLLOW
                    };
                let use_openat2 = open_stat_caps.as_ref().is_some_and(|caps| caps.openat2);

                let path_cstr = match CString::new(path.as_os_str().as_bytes()) {
                    Ok(s) => s,
                    Err(_) => {
                        stats.files_open_failed = stats.files_open_failed.saturating_add(1);
                        perf_stats::sat_add_u64(&mut stats.open_failures, 1);
                        st.failed = true;
                        st.done = true;
                        files[file_slot] = None;
                        free_file_slots.push(file_slot);
                        continue;
                    }
                };

                let open_how = if use_openat2 {
                    let resolve = resolve_bits(cfg.resolve_policy);
                    Some(Box::new(
                        types::OpenHow::new().flags(flags as u64).resolve(resolve),
                    ))
                } else {
                    None
                };

                let op_slot = free_ops.pop().unwrap();
                let entry = if use_openat2 {
                    let how = open_how.as_ref().expect("open_how missing");
                    opcode::OpenAt2::new(
                        types::Fd(libc::AT_FDCWD),
                        path_cstr.as_ptr(),
                        how.as_ref(),
                    )
                    .build()
                } else {
                    opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), path_cstr.as_ptr())
                        .flags(flags)
                        .mode(0)
                        .build()
                }
                .user_data(op_slot as u64);

                // SAFETY: `entry` is a fully-built openat SQE. The path CString
                // (`_path`) is kept alive in the Op::Open variant until the CQE is
                // reaped, so the pointer remains valid for the kernel's lifetime.
                unsafe {
                    let mut sq = ring.submission();
                    if sq.push(&entry).is_err() {
                        free_ops.push(op_slot);
                        open_ready.push_front(file_slot);
                        break;
                    }
                }

                ops[op_slot] = Some(Op::Open(OpenOp {
                    file_slot,
                    _path: path_cstr,
                    _open_how: open_how,
                }));

                in_flight_ops += 1;
                submitted_this_round += 1;
                perf_stats::sat_add_u64(&mut stats.open_ops_submitted, 1);
                st.in_flight = 1;
                scheduled = true;
            }

            if !scheduled {
                break;
            }
        }

        // Batch submit if we queued anything.
        if submitted_this_round > 0 {
            ring.submit()?;
        }

        // Decide what to do based on current state.
        if in_flight_ops == 0 {
            if stopping {
                // Clean shutdown: nothing in flight, stop requested.
                break;
            }

            let has_work =
                !open_ready.is_empty() || !stat_ready.is_empty() || !read_ready.is_empty();

            if !has_work {
                if channel_closed {
                    // No work, no more incoming, no in-flight. Done.
                    break;
                }
                // Block on channel for new work.
                match rx.recv() {
                    Ok(w) => {
                        add_file(
                            w,
                            &mut stats,
                            &mut files,
                            &mut free_file_slots,
                            &mut open_ready,
                            &mut read_ready,
                        );
                        continue;
                    }
                    Err(_) => {
                        channel_closed = true;
                        // Check if we have any ready files to process.
                        if !has_work {
                            break;
                        }
                        // Else continue to try submitting.
                        continue;
                    }
                }
            } else {
                // Work queued but resources unavailable (likely buffers).
                // Yield to let CPU workers release buffers, then retry.
                // This avoids busy-spin while waiting for pool.
                std::thread::yield_now();
                continue;
            }
        }

        // We have ops in flight - wait for at least one completion.
        // Drain CQ before waiting to avoid a syscall if completions are ready.
        let cq_empty = {
            let cq = ring.completion();
            cq.is_empty()
        };
        if cq_empty {
            // Only use submit_and_wait if we didn't submit this round.
            if submitted_this_round == 0 {
                ring.submit_and_wait(1)?;
            } else if in_flight_ops >= cfg.io_depth {
                // At capacity, must wait for completions before submitting more.
                ring.submit_and_wait(1)?;
            }
            // else: we submitted and have room, check completions opportunistically
        }

        // Drain completions.
        for cqe in ring.completion() {
            let op_slot = cqe.user_data() as usize;
            let res = cqe.result();

            // CRITICAL: Unknown user_data indicates internal accounting bug.
            let op = ops
                .get_mut(op_slot)
                .and_then(|o| o.take())
                .unwrap_or_else(|| {
                    panic!(
                        "io_uring CQE with unknown user_data {} (max slot: {})",
                        op_slot,
                        slots - 1
                    );
                });

            free_ops.push(op_slot);
            in_flight_ops = in_flight_ops.saturating_sub(1);
            match op {
                Op::Read(op) => {
                    perf_stats::sat_add_u64(&mut stats.reads_completed, 1);
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        // File already cleaned up (shouldn't happen with 1-in-flight).
                        drop(op.buf);
                        continue;
                    };

                    st.in_flight = 0;

                    let FilePhase::Ready(rs) = &mut st.phase else {
                        drop(op.buf);
                        continue;
                    };

                    if res < 0 {
                        // Read syscall failed.
                        stats.read_errors = stats.read_errors.saturating_add(1);
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "[uring-io] read failed errno={} file={:?}",
                            -res,
                            std::str::from_utf8(&st.token.display).unwrap_or("<non-utf8>"),
                        );
                        st.failed = true;
                        st.done = true;
                        drop(op.buf);
                    } else {
                        let n = res as usize;
                        if n == 0 {
                            // Unexpected EOF (empty read).
                            stats.read_errors = stats.read_errors.saturating_add(1);
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "[uring-io] unexpected EOF file={:?}",
                                std::str::from_utf8(&st.token.display).unwrap_or("<non-utf8>"),
                            );
                            st.failed = true;
                            st.done = true;
                            drop(op.buf);
                        } else {
                            if n < op.payload_len {
                                // Short read: file likely shrank. Treat as truncation.
                                // We scan what we got, but mark file done since we can't
                                // trust our offset calculations for subsequent chunks.
                                perf_stats::sat_add_u64(&mut stats.short_reads, 1);
                                st.done = true;
                            }

                            let total_len = op.prefix_len.saturating_add(n);

                            // First-chunk classification: sniff archive magic and
                            // classify binary vs text. Only on first read (no
                            // overlap prefix) to avoid re-classifying later chunks.
                            if op.base_offset == 0 && op.prefix_len == 0 {
                                let sniff_len = total_len.min(512);
                                let sniff_data = &op.buf.as_slice()[..sniff_len];

                                // Archive magic sniffing: route to archive workers
                                // if file content looks like an archive despite not
                                // having a recognized extension.
                                if let Some(ref atx) = archive_tx {
                                    if let Some(kind) =
                                        crate::archive::detect::sniff_kind_from_header(sniff_data)
                                    {
                                        stats.archives_sniffed =
                                            stats.archives_sniffed.saturating_add(1);
                                        // SAFETY: display bytes originate from
                                        // `Path::as_os_str().as_bytes()` on Unix,
                                        // so they are valid OS string bytes.
                                        let path = PathBuf::from(unsafe {
                                            std::ffi::OsStr::from_encoded_bytes_unchecked(
                                                &st.token.display,
                                            )
                                        });
                                        let aw = ArchiveWork {
                                            path,
                                            kind,
                                            token: Arc::clone(&st.token),
                                        };
                                        if atx.send(aw).is_err() {
                                            perf_stats::sat_add_u64(
                                                &mut stats.archives_send_failed,
                                                1,
                                            );
                                            #[cfg(debug_assertions)]
                                            eprintln!(
                                                "[uring-io] archive channel closed, \
                                                 dropping sniffed archive {:?}",
                                                &st.token.display,
                                            );
                                        }
                                        st.done = true;
                                        drop(op.buf);

                                        if st.in_flight == 0 {
                                            files[op.file_slot] = None;
                                            free_file_slots.push(op.file_slot);
                                        }
                                        continue;
                                    }
                                }

                                // Binary classification: skip files with NUL bytes
                                // in the first CHECK_LEN bytes.
                                if cfg.skip_binary {
                                    let check_len = total_len.min(content_policy::CHECK_LEN);
                                    let verdict = content_policy::classify_content(
                                        &op.buf.as_slice()[..check_len],
                                        &st.token.display,
                                        content_policy::CHECK_LEN,
                                    );
                                    match verdict {
                                        ContentVerdict::Binary => {
                                            stats.binary_skipped =
                                                stats.binary_skipped.saturating_add(1);
                                            st.done = true;
                                            drop(op.buf);

                                            if st.in_flight == 0 {
                                                files[op.file_slot] = None;
                                                free_file_slots.push(op.file_slot);
                                            }
                                            continue;
                                        }
                                        ContentVerdict::BinaryExtractable(fmt) => {
                                            if let Some(ref etx) = extract_tx {
                                                // Transfer the already-open fd to extraction
                                                // workers. This avoids a second open syscall and
                                                // keeps extraction consistent with the snapshot
                                                // captured by open/stat in this I/O worker.
                                                if let Some(file) = rs.file.take() {
                                                    let ew = ExtractWork {
                                                        file,
                                                        file_size: rs.size,
                                                        fmt,
                                                        token: Arc::clone(&st.token),
                                                    };
                                                    if etx.send(ew).is_ok() {
                                                        stats.extractions_routed = stats
                                                            .extractions_routed
                                                            .saturating_add(1);
                                                    } else {
                                                        // Channel closed; fall back to skip.
                                                        stats.binary_skipped =
                                                            stats.binary_skipped.saturating_add(1);
                                                    }
                                                } else {
                                                    // File handle missing unexpectedly.
                                                    stats.binary_skipped =
                                                        stats.binary_skipped.saturating_add(1);
                                                }
                                            } else {
                                                stats.binary_skipped =
                                                    stats.binary_skipped.saturating_add(1);
                                            }
                                            st.done = true;
                                            drop(op.buf);

                                            if st.in_flight == 0 {
                                                files[op.file_slot] = None;
                                                free_file_slots.push(op.file_slot);
                                            }
                                            continue;
                                        }
                                        ContentVerdict::Text => { /* fall through to scan */ }
                                    }
                                }
                            }

                            let len = total_len as u32;

                            if overlap > 0 {
                                let overlap_len = overlap.min(total_len);
                                if overlap_len > 0 {
                                    let start = total_len - overlap_len;
                                    rs.overlap_buf[..overlap_len].copy_from_slice(
                                        &op.buf.as_slice()[start..start + overlap_len],
                                    );
                                }
                                rs.overlap_len = overlap_len;
                            }

                            let task = CpuTask::ScanChunk {
                                token: Arc::clone(&st.token),
                                base_offset: op.base_offset,
                                prefix_len: op.prefix_len as u32,
                                len,
                                buf: op.buf,
                            };

                            if cpu.spawn(task).is_err() {
                                // CPU executor shut down. Start stopping.
                                #[cfg(debug_assertions)]
                                eprintln!("[uring-io] CPU executor closed, stopping I/O worker");
                                stopping = true;
                                st.failed = true;
                                st.done = true;
                            } else {
                                // Successfully spawned. If file has more data, re-queue.
                                if !st.done && !st.failed && rs.next_offset < rs.size {
                                    read_ready.push_back(op.file_slot);
                                } else {
                                    st.done = true;
                                }
                            }
                        }
                    }

                    // Cleanup file if done and no more in-flight.
                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
                Op::Open(op) => {
                    perf_stats::sat_add_u64(&mut stats.open_ops_completed, 1);
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        if res >= 0 {
                            // SAFETY: `res` is a valid fd from io_uring openat.
                            // The FileState was cleaned up, so we must close the
                            // fd to prevent a leak. No other code path owns it.
                            unsafe {
                                libc::close(res);
                            }
                        }
                        continue;
                    };

                    st.in_flight = 0;

                    if res < 0 {
                        perf_stats::sat_add_u64(&mut stats.open_failures, 1);
                        let errno = -res;
                        let can_fallback = cfg.open_stat_mode != OpenStatMode::UringRequired
                            && (errno == libc::EINVAL || errno == libc::EOPNOTSUPP);

                        if can_fallback {
                            perf_stats::sat_add_u64(&mut stats.open_stat_fallbacks, 1);
                            let path = match &mut st.phase {
                                FilePhase::PendingOpen { path } => std::mem::take(path),
                                _ => {
                                    debug_assert!(
                                        false,
                                        "Op::Open completion with non-PendingOpen phase"
                                    );
                                    st.failed = true;
                                    st.done = true;
                                    if st.in_flight == 0 {
                                        files[op.file_slot] = None;
                                        free_file_slots.push(op.file_slot);
                                    }
                                    continue;
                                }
                            };

                            match blocking_open(&path, &mut stats) {
                                BlockingOutcome::Ready(read_state) => {
                                    perf_stats::sat_add_u64(
                                        &mut stats.bytes_enqueued,
                                        read_state.size,
                                    );
                                    st.phase = FilePhase::Ready(read_state);
                                    read_ready.push_back(op.file_slot);
                                }
                                BlockingOutcome::Skipped => {
                                    st.done = true;
                                }
                                BlockingOutcome::Failed => {
                                    st.failed = true;
                                    st.done = true;
                                }
                            }
                        } else {
                            stats.files_open_failed = stats.files_open_failed.saturating_add(1);
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "[uring-io] open failed errno={} file={:?}",
                                -res,
                                std::str::from_utf8(&st.token.display).unwrap_or("<non-utf8>"),
                            );
                            st.failed = true;
                            st.done = true;
                        }
                    } else {
                        let fd = res;
                        // SAFETY: fd came from io_uring openat/openat2 and is owned by us now.
                        let file = unsafe { File::from_raw_fd(fd) };
                        st.phase = FilePhase::PendingStat { file: Some(file) };
                        stat_ready.push_back(op.file_slot);
                    }

                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
                Op::Stat(op) => {
                    perf_stats::sat_add_u64(&mut stats.stat_ops_completed, 1);
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        continue;
                    };

                    st.in_flight = 0;

                    if res < 0 {
                        perf_stats::sat_add_u64(&mut stats.stat_failures, 1);
                        let errno = -res;
                        let can_fallback = cfg.open_stat_mode != OpenStatMode::UringRequired
                            && (errno == libc::EINVAL || errno == libc::EOPNOTSUPP);

                        if can_fallback {
                            perf_stats::sat_add_u64(&mut stats.open_stat_fallbacks, 1);
                            let file = match &mut st.phase {
                                FilePhase::PendingStat { file } => file.as_ref(),
                                _ => None,
                            };

                            if let Some(file) = file {
                                match file.metadata() {
                                    Ok(m) => {
                                        let size = m.len();
                                        if let Some(max_sz) = cfg.max_file_size {
                                            if size > max_sz {
                                                st.done = true;
                                                if st.done && st.in_flight == 0 {
                                                    files[op.file_slot] = None;
                                                    free_file_slots.push(op.file_slot);
                                                }
                                                continue;
                                            }
                                        }
                                        if size == 0 {
                                            st.done = true;
                                            if st.done && st.in_flight == 0 {
                                                files[op.file_slot] = None;
                                                free_file_slots.push(op.file_slot);
                                            }
                                            continue;
                                        }

                                        let file = match &mut st.phase {
                                            FilePhase::PendingStat { file } => {
                                                file.take().expect("file missing in PendingStat")
                                            }
                                            _ => {
                                                st.failed = true;
                                                st.done = true;
                                                if st.done && st.in_flight == 0 {
                                                    files[op.file_slot] = None;
                                                    free_file_slots.push(op.file_slot);
                                                }
                                                continue;
                                            }
                                        };

                                        st.phase = FilePhase::Ready(ReadState {
                                            file: Some(file),
                                            size,
                                            next_offset: 0,
                                            overlap_buf: vec![0u8; overlap].into_boxed_slice(),
                                            overlap_len: 0,
                                        });
                                        read_ready.push_back(op.file_slot);
                                    }
                                    Err(_) => {
                                        st.failed = true;
                                        st.done = true;
                                    }
                                }
                            } else {
                                st.failed = true;
                                st.done = true;
                            }
                        } else {
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "[uring-io] stat failed errno={} file={:?}",
                                -res,
                                std::str::from_utf8(&st.token.display).unwrap_or("<non-utf8>"),
                            );
                            st.failed = true;
                            st.done = true;
                        }
                    } else {
                        let statx = &*op.statx_buf;
                        let size = statx.stx_size;

                        if let Some(max_sz) = cfg.max_file_size {
                            if size > max_sz {
                                st.done = true;
                            }
                        }

                        if !st.done {
                            if size == 0 {
                                st.done = true;
                            } else {
                                let file = match &mut st.phase {
                                    FilePhase::PendingStat { file } => {
                                        file.take().expect("file missing in PendingStat")
                                    }
                                    _ => {
                                        st.failed = true;
                                        st.done = true;
                                        if st.done && st.in_flight == 0 {
                                            files[op.file_slot] = None;
                                            free_file_slots.push(op.file_slot);
                                        }
                                        continue;
                                    }
                                };

                                perf_stats::sat_add_u64(&mut stats.bytes_enqueued, size);
                                st.phase = FilePhase::Ready(ReadState {
                                    file: Some(file),
                                    size,
                                    next_offset: 0,
                                    overlap_buf: vec![0u8; overlap].into_boxed_slice(),
                                    overlap_len: 0,
                                });
                                read_ready.push_back(op.file_slot);
                            }
                        }
                    }

                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
            }
        }
    }

    // SAFETY: Drain any remaining in-flight ops before returning.
    // This ensures the kernel finishes writing before we drop buffers.
    if in_flight_ops > 0 {
        drain_in_flight(&mut ring, &mut ops, &mut in_flight_ops, &mut stats)?;
    }

    if registered_buffers {
        // Ignore unregister errors; ring teardown will clean up in worst case.
        let _ = ring.submitter().unregister_buffers();
    }

    Ok(stats)
}

// ============================================================================
// Discovery Walker
// ============================================================================

/// Depth-first recursive directory walk that feeds files to I/O threads.
///
/// # Design choices
///
/// - **Stack-based DFS** (not `WalkDir`): avoids per-entry `stat` calls.
///   `DirEntry::file_type()` uses `d_type` from `getdents64` on Linux (no
///   extra syscall on ext4/xfs/btrfs). Size filtering is deferred to the
///   I/O thread's async `statx`, which is already required for TOCTOU safety.
///
/// - **Archive short-circuit**: files with recognized archive extensions are
///   routed directly to archive workers (bypassing I/O threads), since archive
///   scanning opens files itself and does not benefit from io_uring reads.
///
/// - **Backpressure**: uses `CountBudget::acquire` (blocks when
///   `max_in_flight_files` is reached) and bounded channel send (blocks when
///   `file_queue_cap` is full). This keeps memory bounded regardless of
///   directory tree depth or breadth.
///
/// # Symlink handling
///
/// When `cfg.follow_symlinks` is false, symlinks are skipped during walk.
/// When true, symlink targets are resolved via `fs::metadata` to determine
/// if the target is a file or directory.
fn walk_and_send_files(
    root: &Path,
    cfg: &LocalFsUringConfig,
    budget: &Arc<CountBudget>,
    tx: &chan::Sender<FileWork>,
    archive_tx: &Option<chan::Sender<ArchiveWork>>,
    file_ids: &FileIdAllocator,
    summary: &mut LocalFsSummary,
) -> io::Result<()> {
    // Use a directory-entry stack instead of a path stack. DirEntry::file_type()
    // uses `d_type` from getdents64 on Linux (no syscall), avoiding the per-file
    // symlink_metadata/statx that was the #1 bottleneck in cold-cache discovery.
    // Size filtering is deferred to the I/O thread's statx, which runs async
    // via io_uring and is already required for correctness (TOCTOU).
    let mut dir_stack: Vec<PathBuf> = Vec::with_capacity(1024);
    dir_stack.push(root.to_path_buf());

    while let Some(dir_path) = dir_stack.pop() {
        let rd = match fs::read_dir(&dir_path) {
            Ok(rd) => rd,
            Err(_) => {
                summary.walk_errors = summary.walk_errors.saturating_add(1);
                continue;
            }
        };

        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    summary.walk_errors = summary.walk_errors.saturating_add(1);
                    continue;
                }
            };

            // DirEntry::file_type() uses d_type from getdents64 (no syscall on
            // ext4/xfs/btrfs). Falls back to symlink_metadata only if d_type is
            // DT_UNKNOWN (rare: some network filesystems).
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => {
                    summary.walk_errors = summary.walk_errors.saturating_add(1);
                    continue;
                }
            };

            if ft.is_dir() {
                dir_stack.push(entry.path());
                continue;
            }

            if !cfg.follow_symlinks && ft.is_symlink() {
                continue;
            }

            if !ft.is_file() {
                // Symlinks when following: resolve via metadata to check target type.
                if cfg.follow_symlinks && ft.is_symlink() {
                    match fs::metadata(entry.path()) {
                        Ok(m) if m.is_file() => { /* fall through to enqueue */ }
                        Ok(m) if m.is_dir() => {
                            dir_stack.push(entry.path());
                            continue;
                        }
                        _ => continue,
                    }
                } else {
                    continue;
                }
            }

            summary.files_seen = summary.files_seen.saturating_add(1);

            let path = entry.path();

            // Extension-based archive routing: if the path has a recognized
            // archive extension, route directly to archive workers (no io_uring
            // read needed — archive scanning opens the file itself).
            if let Some(archive_tx) = archive_tx.as_ref() {
                if let Some(kind) = detect_kind_from_path(&path) {
                    let permit = budget.acquire(1);
                    let file_id = file_ids
                        .next_root_file_id()
                        .ok_or_else(|| io::Error::other("FileId overflow"))?;
                    let display: Arc<[u8]> = path
                        .as_os_str()
                        .as_bytes()
                        .to_vec()
                        .into_boxed_slice()
                        .into();
                    let token = Arc::new(FileToken {
                        _permit: permit,
                        file_id,
                        display,
                    });
                    if archive_tx.send(ArchiveWork { path, kind, token }).is_err() {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "archive workers stopped",
                        ));
                    }
                    summary.archives_routed = summary.archives_routed.saturating_add(1);
                    summary.files_enqueued = summary.files_enqueued.saturating_add(1);
                    continue;
                }
            }

            // Skip discovery-time size filtering: the I/O thread's statx (via
            // io_uring) provides the authoritative size and handles max_file_size.

            // Backpressure: blocks until permit available.
            let permit = budget.acquire(1);

            let file_id = file_ids
                .next_root_file_id()
                .ok_or_else(|| io::Error::other("FileId overflow"))?;

            let display: Arc<[u8]> = path
                .as_os_str()
                .as_bytes()
                .to_vec()
                .into_boxed_slice()
                .into();

            let token = Arc::new(FileToken {
                _permit: permit,
                file_id,
                display,
            });

            // Backpressure: bounded channel send blocks here.
            tx.send(FileWork { path, token })
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "io threads stopped"))?;

            summary.files_enqueued = summary.files_enqueued.saturating_add(1);
        }
    }

    Ok(())
}

// ============================================================================
// Entry Point
// ============================================================================

/// Scan local filesystem using io_uring.
///
/// This is the top-level entry point for the io_uring-based scanner. It
/// orchestrates the full lifecycle described in the module-level architecture
/// diagram: discovery → I/O threads → CPU executor → findings.
///
/// # Thread structure
///
/// The function spawns and joins all threads internally:
/// - **1 main thread** (the caller): runs `walk_and_send_files` for discovery.
/// - **`cfg.io_threads` I/O threads**: each owns an `IoUring` instance.
/// - **`cfg.cpu_workers` CPU threads**: work-stealing executor for chunk scanning.
/// - **`cpu_workers/4` archive threads** (if archives enabled): dedicated workers
///   for archive decompression and scanning.
/// - **`cpu_workers/4` extraction threads** (if `skip_binary`): dedicated workers
///   for binary-extractable format scanning (`.jar`, `.class`, etc.).
///
/// All threads are joined before this function returns; no background work
/// persists after the call.
///
/// # Arguments
///
/// - `engine`: Detection engine implementing [`ScanEngine`] (shared across all threads).
/// - `roots`: Root directories to scan (walked depth-first).
/// - `cfg`: Configuration (validated via [`LocalFsUringConfig::validate`]).
/// - `event_sink`: Event sink for findings (thread-safe, shared across all threads).
///
/// # Returns
///
/// `(LocalFsSummary, UringIoStats, MetricsSnapshot)` where:
/// - `LocalFsSummary`: discovery-level counters (files seen, enqueued, errors).
/// - `UringIoStats`: aggregated I/O thread counters (ops submitted/completed).
/// - `MetricsSnapshot`: CPU-side metrics (bytes scanned, findings emitted),
///   including merged archive and extraction worker stats.
///
/// # Errors
///
/// Returns `io::Error` if io_uring initialization fails, an I/O thread panics,
/// or `FileId` allocation overflows.
pub fn scan_local_fs_uring<E: ScanEngine>(
    engine: Arc<E>,
    roots: &[PathBuf],
    cfg: LocalFsUringConfig,
    event_sink: Arc<dyn EventOutput>,
) -> io::Result<(LocalFsSummary, UringIoStats, MetricsSnapshot)> {
    cfg.validate(engine.as_ref());

    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    // Global-only pool because I/O threads acquire and CPU threads release.
    let pool = FixedBufferPool::new(buf_len, cfg.pool_buffers);

    let file_budget = Arc::new(CountBudget::new(cfg.max_in_flight_files));
    let file_ids = Arc::new(FileIdAllocator::new(0));

    // CPU executor for scanning.
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
            move |_wid| CpuScratch {
                engine: Arc::clone(&engine),
                event_sink: Arc::clone(&event_sink),
                scratch: engine.new_scratch(),
                // Match the local scan default: avoid steady-state allocs without
                // relying on engine-specific tuning details.
                pending: Vec::with_capacity(4096),
            }
        },
        cpu_runner::<E>,
    );

    let cpu = ex.handle();

    let (tx, rx) = chan::bounded::<FileWork>(cfg.file_queue_cap);

    let stop = Arc::new(AtomicBool::new(false));

    // Archive channel + workers (if archives enabled).
    let archive_enabled = cfg.archive.enabled;
    let (archive_tx, archive_rx) = if archive_enabled {
        let (tx, rx) = chan::bounded::<ArchiveWork>(cfg.file_queue_cap);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let archive_worker_count = if archive_enabled {
        (cfg.cpu_workers / 4).max(1)
    } else {
        0
    };
    let mut archive_threads = Vec::with_capacity(archive_worker_count);
    if let Some(ref arx) = archive_rx {
        for wid in 0..archive_worker_count {
            let rx = arx.clone();
            let engine = Arc::clone(&engine);
            let event_sink = Arc::clone(&event_sink);
            let file_ids = Arc::clone(&file_ids);
            let archive_cfg = cfg.archive.clone();

            archive_threads.push(
                thread::Builder::new()
                    .name(format!("uring-archive-{wid}"))
                    .spawn(move || {
                        archive_worker_loop(rx, engine, event_sink, file_ids, archive_cfg)
                    })
                    .expect("failed to spawn archive worker thread"),
            );
        }
    }
    // Drop the extra rx clone so only worker threads hold receivers.
    drop(archive_rx);

    // Extraction channel + workers (when skip_binary is true, extractable
    // binary files are routed here with already-open file descriptors instead
    // of being silently skipped or re-opened by path).
    let (extract_tx, extract_rx) = if cfg.skip_binary {
        let (tx, rx) = chan::bounded::<ExtractWork>(cfg.file_queue_cap);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let extract_worker_count = if cfg.skip_binary {
        (cfg.cpu_workers / 4).max(1)
    } else {
        0
    };
    let mut extract_threads = Vec::with_capacity(extract_worker_count);
    if let Some(ref erx) = extract_rx {
        for wid in 0..extract_worker_count {
            let rx = erx.clone();
            let engine = Arc::clone(&engine);
            let event_sink = Arc::clone(&event_sink);

            extract_threads.push(
                thread::Builder::new()
                    .name(format!("uring-extract-{wid}"))
                    .spawn(move || extract_worker_loop(rx, engine, event_sink))
                    .expect("failed to spawn extraction worker thread"),
            );
        }
    }
    drop(extract_rx);

    // Spawn I/O threads.
    let io_assigner = if cfg.pin_threads {
        super::affinity::CoreAssigner::with_offset(cfg.cpu_workers).map(Arc::new)
    } else {
        None
    };
    let mut io_threads = Vec::with_capacity(cfg.io_threads);
    for wid in 0..cfg.io_threads {
        let rx = rx.clone();
        let pool = pool.clone();
        let cpu = cpu.clone();
        let engine = Arc::clone(&engine);
        let cfg2 = cfg.clone();
        let stop2 = Arc::clone(&stop);
        let io_assigner_clone = io_assigner.clone();
        let atx = archive_tx.clone();
        let etx = extract_tx.clone();

        io_threads.push(
            thread::Builder::new()
                .name(format!("uring-io-{wid}"))
                .spawn(move || {
                    if let Some(ref a) = io_assigner_clone {
                        a.pin_current_thread();
                    }
                    io_worker_loop(wid, rx, pool, cpu, engine, cfg2, stop2, atx, etx)
                })
                .expect("failed to spawn uring I/O thread"),
        );
    }
    drop(rx);

    // Discovery walk: DFS, bounded by file_budget + bounded channel.
    let mut summary = LocalFsSummary::default();

    for root in roots {
        walk_and_send_files(
            root,
            &cfg,
            &file_budget,
            &tx,
            &archive_tx,
            &file_ids,
            &mut summary,
        )?;
        if stop.load(Ordering::Relaxed) {
            break;
        }
    }

    // Close discovery → I/O channel, then close archive and extraction
    // channels so workers drain remaining work and exit.
    drop(tx);
    drop(archive_tx);
    drop(extract_tx);

    // Join I/O threads and merge stats.
    let mut io_stats = UringIoStats::default();
    for t in io_threads {
        match t.join() {
            Ok(Ok(s)) => io_stats.merge(s),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::other("io thread panicked")),
        }
    }

    // Join archive workers and merge stats into MetricsSnapshot.
    let mut archive_bytes = 0u64;
    let mut archive_chunks = 0u64;
    let mut archive_findings = 0u64;
    let mut archive_dropped_findings = 0u64;
    let mut archive_open_errors = 0u64;
    let mut archive_scan_errors = 0u64;
    let mut total_archive_stats = ArchiveStats::default();
    for t in archive_threads {
        match t.join() {
            Ok(ws) => {
                archive_bytes += ws.bytes_scanned;
                archive_chunks += ws.chunks_scanned;
                archive_findings += ws.findings_emitted;
                archive_dropped_findings += ws.findings_dropped;
                archive_open_errors += ws.archives_open_failed;
                archive_scan_errors += ws.archives_scan_errors;
                total_archive_stats.merge_from(&ws.archive_stats);
            }
            Err(_) => return Err(io::Error::other("archive worker panicked")),
        }
    }

    // Join extraction workers and merge stats.
    let mut extract_bytes = 0u64;
    let mut extract_chunks = 0u64;
    let mut extract_findings = 0u64;
    let mut extract_dropped_findings = 0u64;
    let mut extract_io_errors = 0u64;
    let mut total_extracted = 0u64;
    for t in extract_threads {
        match t.join() {
            Ok(ws) => {
                extract_bytes += ws.bytes_scanned;
                extract_chunks += ws.chunks_scanned;
                extract_findings += ws.findings_emitted;
                extract_dropped_findings += ws.findings_dropped;
                extract_io_errors += ws.io_errors;
                total_extracted += ws.files_extracted;
            }
            Err(_) => return Err(io::Error::other("extraction worker panicked")),
        }
    }

    summary.open_errors = io_stats.files_open_failed + archive_open_errors;
    summary.read_errors = io_stats.read_errors + archive_scan_errors + extract_io_errors;
    summary.binary_skipped = io_stats.binary_skipped;

    // Join CPU executor.
    let mut cpu_metrics = ex.join();

    // Merge archive worker stats into the CPU metrics snapshot so the
    // orchestrator sees a single unified view of bytes/chunks/findings.
    cpu_metrics.bytes_scanned = cpu_metrics.bytes_scanned.wrapping_add(archive_bytes);
    cpu_metrics.chunks_scanned = cpu_metrics.chunks_scanned.wrapping_add(archive_chunks);
    cpu_metrics.findings_emitted = cpu_metrics.findings_emitted.wrapping_add(archive_findings);
    cpu_metrics.findings_dropped = cpu_metrics
        .findings_dropped
        .wrapping_add(archive_dropped_findings);
    cpu_metrics.binary_skipped = cpu_metrics
        .binary_skipped
        .wrapping_add(io_stats.binary_skipped);
    cpu_metrics.archive.merge_from(&total_archive_stats);

    // Merge extraction worker stats.
    cpu_metrics.binary_extracted = cpu_metrics.binary_extracted.wrapping_add(total_extracted);
    cpu_metrics.bytes_scanned = cpu_metrics.bytes_scanned.wrapping_add(extract_bytes);
    cpu_metrics.chunks_scanned = cpu_metrics.chunks_scanned.wrapping_add(extract_chunks);
    cpu_metrics.findings_emitted = cpu_metrics.findings_emitted.wrapping_add(extract_findings);
    cpu_metrics.findings_dropped = cpu_metrics
        .findings_dropped
        .wrapping_add(extract_dropped_findings);
    cpu_metrics.io_errors = cpu_metrics.io_errors.wrapping_add(extract_io_errors);

    event_sink.flush();

    Ok((summary, io_stats, cpu_metrics))
}

#[cfg(test)]
#[path = "local_fs_uring_tests.rs"]
mod tests;
