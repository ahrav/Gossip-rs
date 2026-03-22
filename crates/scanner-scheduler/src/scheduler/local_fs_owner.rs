//! Canonical Local Filesystem Scanner
//!
//! # Architecture
//!
//! - CPU workers do both I/O and scan (no separate I/O threads)
//! - Uses `TsBufferPool` (per-worker local queues with global fallback and stealing)
//! - Sequential reads with overlap carry (no seeks, no re-reading overlap)
//! - Discovery thread enqueues files; workers process entire files
//!
//! # Module Role
//!
//! This is the primary local-filesystem scan path used by the scheduler
//! (an io_uring variant exists in `local_fs_uring.rs`). All local scan
//! entry points (`scan_local`, `LocalConfig`, `LocalFile`) live here.
//!
//! # Why Blocking Reads First?
//!
//! 1. **Strong baseline**: Kernel page cache is highly optimized; often hits memory
//! 2. **Minimal complexity**: No async runtime, no completion queues
//! 3. **Measureable**: Establish baseline before adding io_uring complexity
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: Every discovered file is scanned (`CountBudget` backpressure ensures buffer availability)
//! - **Chunk overlap**: `engine.required_overlap()` bytes overlap between chunks
//! - **Budget bounded**: `max_in_flight_objects` limits discovered-but-not-complete files
//! - **Buffer bounded**: `pool_buffers` limits peak memory
//! - **Snapshot semantics**: File size taken at open time (consistent point-in-time)
//!
//! # Performance Characteristics
//!
//! | Workload | Expected Behavior |
//! |----------|-------------------|
//! | Hot cache (small files) | CPU-bound, near memory bandwidth |
//! | Cold cache (SSD) | I/O-bound, ~3-5 GB/s with good SSD |
//! | Cold cache (HDD) | I/O-bound, ~150-200 MB/s sequential |
//!
//! # I/O Pattern: Overlap Carry
//!
//! Instead of seeking back for each chunk's overlap:
//! 1. Acquire ONE buffer per file (panics if exhausted; `CountBudget` prevents this)
//! 2. Read sequentially, carry overlap bytes forward via `copy_within`
//! 3. Eliminates: seeks, re-reading overlap from kernel, per-chunk pool churn
//!
//! ```text
//! Iteration 1:                    Iteration 2:
//! ┌─────────────────────────┐     ┌─────────────────────────┐
//! │      payload bytes      │     │overlap│  new payload    │
//! │      (from read)        │     │(copy) │  (from read)    │
//! └─────────────────────────┘     └─────────────────────────┘
//!                           │            ▲
//!                           └────────────┘
//!                         copy_within(tail → head)
//! ```
//!
//! # When to Consider io_uring
//!
//! Profile first. If workers show significant idle time waiting on reads
//! (visible in `perf` as time in `read` syscall), io_uring may help.
//! For page-cache-hot workloads, blocking reads are competitive.

use super::count_budget::CountBudget;
use super::engine_trait::{EngineScratch, FindingWithHashRecord, ScanEngine};
use super::executor::{Executor, ExecutorConfig, WorkerCtx};
use super::local_fs_archive_ctx::{ArchiveEnd, dispatch_archive_scan};
use super::local_fs_extract::extract_and_scan_file;
use super::metrics::{MetricsSnapshot, WorkerMetricsLocal};
use super::shared_core::{carry_overlap_prefix, scan_chunk_postprocess};
use super::ts_buffer_pool::{TsBufferPool, TsBufferPoolConfig};
use crate::api::FileId;
use crate::archive::formats::{TarCursor, ZipCursor, tar::TAR_BLOCK_LEN};
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, DEFAULT_MAX_COMPONENTS, EntryPathCanonicalizer,
    VirtualPathBuilder, detect_kind_from_path, sniff_kind_from_header,
};
use crate::scheduler::engine_stub::BUFFER_LEN_MAX;
use crate::store::{FsFindingBatch, FsFindingRecord, FsRunLoss, StoreProducer};

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for local filesystem scanning.
///
/// # Sizing Guidelines
///
/// - `chunk_size`: 64-256 KiB typical. Larger = fewer syscalls, more memory per file.
/// - `pool_buffers`: Bound peak memory. Should be >= `workers` to avoid starvation.
/// - `max_in_flight_objects`: Bound discovery depth. Too high = memory for paths/metadata.
/// - `max_file_size`: Open-time size cap; oversized files are skipped.
#[derive(Clone)]
pub struct LocalConfig {
    /// Number of CPU worker threads.
    pub workers: usize,

    /// Payload bytes per chunk (excluding overlap).
    ///
    /// Actual buffer size = `chunk_size + engine.required_overlap()`.
    pub chunk_size: usize,

    /// Total buffers in the pool.
    ///
    /// Bounds peak memory: `pool_buffers * (chunk_size + overlap)`.
    pub pool_buffers: usize,

    /// Per-worker local queue capacity in buffer pool.
    pub local_queue_cap: usize,

    /// Max discovered-but-not-complete files.
    ///
    /// Controls discovery backpressure. Higher = more path metadata in memory.
    pub max_in_flight_objects: usize,

    /// Maximum file size in bytes to scan.
    ///
    /// Files larger than this are skipped after `open()` based on the
    /// snapshot size from `metadata().len()`.
    pub max_file_size: u64,

    /// Seed for deterministic executor behavior.
    pub seed: u64,

    /// Pin worker threads to CPU cores (Linux only, no-op elsewhere).
    pub pin_threads: bool,

    /// If true, deduplicate findings within each chunk.
    ///
    /// This is a defense-in-depth measure for engines that might emit
    /// duplicate findings for the same match (e.g., overlapping patterns).
    /// Cross-chunk deduplication is handled separately by `drop_prefix_findings`.
    pub dedupe_within_chunk: bool,

    /// Archive scanning configuration.
    pub archive: ArchiveConfig,

    /// When `true`, skip files that appear to be binary (NUL byte heuristic).
    /// Defaults to `true`. Set to `false` via `--scan-binary` to scan everything.
    pub skip_binary: bool,

    /// Structured event sink for finding output.
    ///
    /// All findings are emitted as `CoreEvent::Finding` through this sink.
    pub event_sink: Arc<dyn crate::events::EventOutput>,

    /// Optional persistence producer for post-dedupe FS finding batches.
    pub store_producer: Option<Arc<dyn StoreProducer>>,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            workers: 8,
            chunk_size: 64 * 1024, // 64 KiB
            pool_buffers: 32,
            local_queue_cap: 4,
            max_in_flight_objects: 256,
            max_file_size: u64::MAX,
            seed: 0x853c49e6748fea9b,
            pin_threads: super::affinity::default_pin_threads(),
            dedupe_within_chunk: true,
            archive: ArchiveConfig::default(),
            skip_binary: true,
            event_sink: Arc::new(crate::events::NullEventOutput),
            store_producer: None,
        }
    }
}

impl std::fmt::Debug for LocalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalConfig")
            .field("workers", &self.workers)
            .field("chunk_size", &self.chunk_size)
            .field("pool_buffers", &self.pool_buffers)
            .field("local_queue_cap", &self.local_queue_cap)
            .field("max_in_flight_objects", &self.max_in_flight_objects)
            .field("max_file_size", &self.max_file_size)
            .field("seed", &self.seed)
            .field("pin_threads", &self.pin_threads)
            .field("dedupe_within_chunk", &self.dedupe_within_chunk)
            .field("archive", &self.archive)
            .field("skip_binary", &self.skip_binary)
            .field("event_sink", &"<dyn EventOutput>")
            .field(
                "store_producer",
                &self.store_producer.as_ref().map(|_| "<dyn StoreProducer>"),
            )
            .finish()
    }
}

impl LocalConfig {
    /// Validate configuration against engine constraints.
    ///
    /// # Panics
    ///
    /// Panics if configuration violates invariants.
    pub fn validate<E: ScanEngine>(&self, engine: &E) {
        assert!(self.workers > 0, "workers must be > 0");
        assert!(self.chunk_size > 0, "chunk_size must be > 0");
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        assert!(self.local_queue_cap > 0, "local_queue_cap must be > 0");
        assert!(
            self.max_in_flight_objects > 0,
            "max_in_flight_objects must be > 0"
        );
        if let Err(err) = self.archive.validate() {
            panic!("archive config invalid: {err}");
        }

        let overlap = engine.required_overlap();
        let buf_len = self.chunk_size.saturating_add(overlap);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size ({}) + overlap ({}) = {} exceeds BUFFER_LEN_MAX ({})",
            self.chunk_size,
            overlap,
            buf_len,
            BUFFER_LEN_MAX
        );

        // Warn if pool is undersized
        #[cfg(debug_assertions)]
        if self.pool_buffers < self.workers {
            eprintln!(
                "[LocalConfig] Warning: pool_buffers ({}) < workers ({}). \
                 Workers may contend heavily for buffers.",
                self.pool_buffers, self.workers
            );
        }
    }

    /// Compute buffer length including overlap.
    pub fn buffer_len<E: ScanEngine>(&self, engine: &E) -> usize {
        self.chunk_size.saturating_add(engine.required_overlap())
    }

    /// Compute peak memory usage for buffers.
    pub fn peak_buffer_memory<E: ScanEngine>(&self, engine: &E) -> usize {
        self.pool_buffers.saturating_mul(self.buffer_len(engine))
    }
}

// ============================================================================
// Local File Discovery
// ============================================================================

/// A file to be scanned.
#[derive(Debug, Clone)]
pub struct LocalFile {
    /// Path to the file.
    pub path: PathBuf,
    /// File size hint in bytes.
    ///
    /// Discovery may skip per-file metadata for performance, so this can be 0.
    /// Open-time metadata determines the actual size and enforcement.
    pub size: u64,
}

/// Iterator over files to scan.
///
/// This is a minimal trait; real implementations would walk directories,
/// filter by extension, respect gitignore, etc.
pub trait FileSource: Send + 'static {
    /// Get the next file to scan, if any.
    fn next_file(&mut self) -> Option<LocalFile>;
}

/// Simple file source from a list of paths.
#[derive(Debug)]
pub struct VecFileSource {
    files: std::vec::IntoIter<LocalFile>,
}

impl VecFileSource {
    pub fn new(files: Vec<LocalFile>) -> Self {
        Self {
            files: files.into_iter(),
        }
    }

    /// Create from an Arc slice by cloning the inner data.
    ///
    /// This allows multiple iterations over the same file list without
    /// modifying the original data. The clone happens at source creation
    /// time, not during iteration.
    pub fn from_arc(files: std::sync::Arc<[LocalFile]>) -> Self {
        Self::new(files.to_vec())
    }
}

impl FileSource for VecFileSource {
    fn next_file(&mut self) -> Option<LocalFile> {
        self.files.next()
    }
}

// ============================================================================
// Task Types
// ============================================================================

/// A file task for the executor.
#[derive(Debug)]
pub(super) struct FileTask {
    /// Run-scoped file ID.
    pub(super) file_id: FileId,
    /// Path to open.
    pub(super) path: PathBuf,
    /// In-flight permit (released when task completes).
    pub(super) _permit: super::count_budget::CountPermit,
}

impl FileTask {
    /// Discovery-order sequence number from the sorted-path file walk.
    /// Used to reorder commit batches into discovery order downstream.
    pub(super) fn discovery_sequence(&self) -> u32 {
        self.file_id.0
    }
}

// ============================================================================
// Per-Worker Scratch
// ============================================================================

/// Per-worker scratch state for local scanning.
///
/// Each executor worker owns exactly one `LocalScratch`. It bundles the engine
/// scratch, all reusable buffers for archive scanning, and configuration
/// references. Nothing in this struct is shared across threads.
///
/// # Invariants
///
/// - All buffers are preallocated at worker init and reused to avoid per-chunk
///   allocations. `pending` and `persist_batch` are sized to
///   `max_findings_per_chunk` and must not grow.
/// - Per-depth vectors (`vpaths`, `tar_cursors`, `path_budget_used`) are sized
///   to `max_archive_depth + 2` and indexed by nesting depth. The `+2`
///   accommodates the root archive plus one level of format overhead.
/// - `next_virtual_file_id` stays in the high-bit namespace (`0x8000_0000..`)
///   to avoid collisions with real file IDs allocated by the discovery loop.
/// - `budgets` is reset at the start of each archive scan via
///   `ArchiveBudgets::begin_archive` — it is not per-entry state.
pub(super) struct LocalScratch<E: ScanEngine> {
    pub(super) engine: Arc<E>,
    pub(super) pool: TsBufferPool,

    /// Per-worker engine scratch.
    pub(super) scan_scratch: E::Scratch,
    /// Per-worker findings buffer (avoids alloc per chunk).
    pub(super) pending: Vec<<E::Scratch as EngineScratch>::Finding>,
    /// Per-worker persistence batch buffer (avoids alloc per chunk).
    pub(super) persist_batch: Vec<FsFindingRecord>,

    /// Archive path canonicalization scratch.
    pub(super) canon: EntryPathCanonicalizer,
    /// Preallocated virtual path builders (depth 0..max_depth+1).
    pub(super) vpaths: Vec<VirtualPathBuilder>,
    /// Per-depth path budget usage counters.
    pub(super) path_budget_used: Vec<usize>,
    /// Reused archive budgets (no per-archive allocation).
    pub(super) budgets: ArchiveBudgets,
    /// Per-depth TAR cursors (one per nested depth).
    pub(super) tar_cursors: Vec<TarCursor>,
    /// Reused ZIP cursor with preallocated buffers.
    pub(super) zip_cursor: ZipCursor<File>,
    /// Scratch buffer for entry display bytes when we need to append a hash suffix.
    pub(super) entry_display_buf: Vec<u8>,
    /// Scratch buffer for gzip header peeking (bounded).
    pub(super) gzip_header_buf: Vec<u8>,
    /// Scratch buffer for gzip header filename (bounded).
    pub(super) gzip_name_buf: Vec<u8>,
    /// Monotonic virtual `FileId` generator for archive entries.
    pub(super) next_virtual_file_id: u32,
    /// Shared abort flag set when `FailRun` policy triggers.
    pub(super) abort_run: Arc<AtomicBool>,

    /// Structured event sink for finding output.
    pub(super) event_sink: Arc<dyn crate::events::EventOutput>,
    /// Optional persistence producer for post-dedupe findings.
    pub(super) store_producer: Option<Arc<dyn StoreProducer>>,

    /// Configuration flags.
    pub(super) chunk_size: usize,
    pub(super) max_file_size: u64,
    pub(super) archive: ArchiveConfig,
    /// When `true`, skip files that appear to be binary.
    pub(super) skip_binary: bool,
    /// Reusable buffer for reading extractable binary files (input).
    pub(super) extract_buf: Vec<u8>,
    /// Reusable buffer for extraction output.
    pub(super) extract_out_buf: Vec<u8>,
    /// Temporary workspace for extractors (e.g. per-entry reads in JARs).
    pub(super) extract_scratch: Vec<u8>,
}

// ============================================================================
// Run Statistics
// ============================================================================

/// Statistics from a local scan run.
///
/// Core counters (`files_enqueued`, `bytes_enqueued`, `io_errors`) are always
/// populated regardless of build configuration. Persistence-loss counters are
/// populated when FS persistence plumbing is enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalStats {
    /// Files discovered and enqueued.
    pub files_enqueued: u64,
    /// Total bytes across all enqueued files (hint-based).
    ///
    /// If discovery skipped metadata, this may undercount and should not be
    /// treated as authoritative for throughput calculations.
    pub bytes_enqueued: u64,
    /// Files that failed to process due to I/O errors.
    ///
    /// This includes file open failures, metadata read failures, and
    /// read errors during scanning. Aggregated from worker metrics.
    pub io_errors: u64,
    /// Findings dropped by engine max-findings caps.
    pub dropped_findings: u64,
    /// Persistence batch emission failures observed during scan loops.
    pub persistence_emit_failures: u64,
    /// Whether run-loss counters indicate an incomplete persistence run.
    pub persistence_incomplete: bool,
}

/// Complete report from a local scan.
///
/// Core metrics in `metrics` (`bytes_scanned`, `chunks_scanned`, `io_errors`,
/// `findings_emitted`) are always aggregated from worker threads.
/// Perf-only metrics require `all(feature = "perf-stats", debug_assertions)`.
/// `stats.io_errors` is derived from `metrics.io_errors` for convenience.
#[derive(Debug, Default)]
pub struct LocalReport {
    pub stats: LocalStats,
    pub metrics: MetricsSnapshot,
}

/// Streaming progress counters for local scan scheduling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalProgress {
    pub files_enqueued: u64,
    pub bytes_enqueued: u64,
}

/// Progress callback surface for local scans.
pub trait LocalProgressSink: Send + Sync + 'static {
    fn on_progress(&self, progress: LocalProgress);
}

#[derive(Default)]
struct NullLocalProgressSink;

impl LocalProgressSink for NullLocalProgressSink {
    #[inline]
    fn on_progress(&self, _progress: LocalProgress) {}
}

// ============================================================================
// Helpers
// ============================================================================

/// Fixed-capacity stack buffer for diagnostic messages (no heap allocation).
///
/// Used in error-reporting paths where allocating a `String` could fail or
/// add unwanted latency. Implements [`fmt::Write`] so it can be used with
/// `write!()`. Output beyond `N` bytes is silently truncated at a UTF-8
/// character boundary to guarantee `as_str()` always returns valid UTF-8.
struct StackMsg<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackMsg<N> {
    #[inline]
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    #[inline]
    fn as_str(&self) -> &str {
        // SAFETY: `write_str` only copies bytes from valid `&str` slices,
        // and truncation is rounded down to a UTF-8 character boundary
        // (see `is_char_boundary` check in `write_str`). The buffer
        // therefore always contains a valid UTF-8 prefix.
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<const N: usize> std::fmt::Write for StackMsg<N> {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = N - self.len;
        let mut n = bytes.len().min(remaining);
        // Truncate at a UTF-8 character boundary so `as_str()` never
        // observes a partial multi-byte sequence.
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

// Scan helpers are now in `super::scan_helpers`. Re-exported here so that
// `local_fs_owner_tests.rs` (which uses `use super::*`) and any internal
// callers within this module continue to compile without changes.
#[allow(unused_imports)]
// dedupe_findings_cross_rule used by local_fs_owner_tests via `use super::*`.
pub(super) use super::scan_helpers::{
    account_effective_dropped_findings, apply_cross_rule_dedupe, dedupe_findings_cross_rule,
    emit_findings,
};

/// Convert engine-typed findings into the flat [`FsFindingRecord`] format
/// expected by the persistence layer.
///
/// `out` is cleared and repopulated. It is pre-sized to
/// `max_findings_per_chunk` at worker init, so no reallocation occurs.
#[inline]
fn build_persistence_batch<F: FindingWithHashRecord>(
    findings: &[F],
    out: &mut Vec<FsFindingRecord>,
) {
    out.clear();
    // `out` is `persist_batch`, pre-sized to max_findings_per_chunk at
    // worker init. After `clear()`, capacity is guaranteed sufficient.
    debug_assert!(
        out.capacity() >= findings.len(),
        "persist_batch capacity ({}) < findings count ({})",
        out.capacity(),
        findings.len(),
    );
    for finding in findings {
        out.push(FsFindingRecord {
            rule_id: finding.rule_id(),
            root_hint_start: finding.root_hint_start(),
            root_hint_end: finding.root_hint_end(),
            span_start: finding.span_start(),
            span_end: finding.span_end(),
            norm_hash: *finding.norm_hash(),
            confidence_score: finding.confidence_score(),
        });
    }
}

/// Build and emit a persistence batch for post-dedupe findings.
///
/// No-ops when `store_producer` is `None`. Accepts empty findings slices
/// so the downstream pipeline can record a "scanned clean" done-ledger
/// entry for objects with zero matches. Callers control emission frequency:
/// for plain files, per-chunk when findings are present plus once per file
/// for clean files; for archive entries, per-chunk unconditionally.
///
/// # Fail-soft design
///
/// On emit failure, increments `persistence_emit_failures` and emits a
/// diagnostic event, but does **not** abort the scan. Persistence errors
/// are treated as recoverable per batch: the scan continues scanning
/// subsequent chunks/files. At run end, if `persistence_emit_failures > 0`,
/// the [`LocalStats::persistence_incomplete`] flag is set so callers know
/// the persisted result set is potentially incomplete.
#[inline]
pub(super) fn emit_persistence_batch<F: FindingWithHashRecord>(
    store_producer: Option<&dyn StoreProducer>,
    event_sink: &dyn crate::events::EventOutput,
    path: &[u8],
    findings: &[F],
    persist_batch: &mut Vec<FsFindingRecord>,
    metrics: &mut WorkerMetricsLocal,
    discovery_sequence: u32,
) {
    let Some(producer) = store_producer else {
        return;
    };

    // Handles empty findings slices: callers pass empty batches for clean
    // files so the downstream pipeline can record a "scanned, nothing
    // found" done-ledger entry.
    build_persistence_batch(findings, persist_batch);

    #[cfg(all(feature = "perf-stats", debug_assertions))]
    let persist_t0 = std::time::Instant::now();

    let emit_result = producer.emit_fs_batch(FsFindingBatch {
        object_path: path,
        findings: persist_batch.as_slice(),
        discovery_sequence,
    });

    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        metrics.persist_ns = metrics
            .persist_ns
            .saturating_add(persist_t0.elapsed().as_nanos() as u64);
    }

    if let Err(err) = emit_result {
        metrics.persistence_emit_failures = metrics.persistence_emit_failures.saturating_add(1);
        let mut msg = StackMsg::<256>::new();
        let _ = std::fmt::Write::write_fmt(
            &mut msg,
            format_args!("fs persistence batch emit failed: {}", err.detail()),
        );
        event_sink.emit_core(crate::events::CoreEvent::Diagnostic(
            crate::events::DiagnosticEvent {
                level: "error",
                message: msg.as_str(),
            },
        ));
    }
}

// Archive scanning (gzip, bzip2, tar, zip) is in:
//   local_fs_archive_ctx.rs — shared types, budget helpers, dispatch
//   local_fs_bzip2.rs       — bzip2 scanning
//   local_fs_gzip.rs        — gzip scanning
//   local_fs_tar.rs         — tar/tar.gz/tar.bz2 scanning
//   local_fs_zip.rs         — zip scanning
// Binary extraction is in:
//   local_fs_extract.rs     — extract_and_scan_file

/// Process a single file: open, classify, chunk-scan, close.
///
/// This is the per-task entry point called by each executor worker. The flow:
/// 1. Check abort flag.
/// 2. Detect archive format by extension, then by header magic.
/// 3. If archive: dispatch to `dispatch_archive_scan` and return.
/// 4. Pre-open extension/lock skip: if binary-skip enabled, reject files
///    whose extension is in the binary skip set or whose filename matches
///    the lock-file table — without opening the file.
/// 5. Open the file, read metadata.
/// 6. If binary-skip enabled: probe first bytes for NUL / extractable format.
/// 7. Otherwise: sequential chunk+overlap scan via the buffer pool.
///
/// # Design: Sequential Read with Overlap Carry
///
/// Instead of seeking back for each chunk's overlap, we:
/// 1. Acquire ONE buffer for the entire file (panics if exhausted; `CountBudget` prevents this)
/// 2. Read sequentially, carrying overlap bytes forward via `copy_within`
/// 3. No seeks, no re-reading overlap from kernel, no per-chunk pool churn
///
/// # File Size Semantics
///
/// Uses file size from metadata after open (not discovery hint).
/// This gives point-in-time snapshot semantics:
/// - Truncated files: we stop at actual EOF
/// - Growing files: we stop at size-at-open (consistent snapshot)
///
/// # Chunk Processing Loop
///
/// ```text
/// ┌────────────────────────────────────────────────────────────────────┐
/// │                        process_file() flow                         │
/// └────────────────────────────────────────────────────────────────────┘
///
/// ext/lock skip? ──skip──► return (ext_skipped++ / lock_skipped++)
///       │
///      pass
///       ▼
/// open(path) ─► metadata.len() ─► acquire_buffer()
///                    │
///                    ▼
///     ┌─────────────────────────────────────────┐
///     │     for each chunk:                     │◄──────────┐
///     │  1. copy_within(overlap)                │           │
///     │  2. read(new_bytes)                     │           │
///     │  3. scan_chunk_into()                   │           │
///     │  4. drop_prefix_findings()              │           │
///     │  5. drain + apply_cross_rule_dedupe()   │           │
///     │  6. if findings: emit_persistence_batch()│          │
///     │  7. emit_findings()                     │           │
///     └──────────────┬──────────────────────────┘           │
///                    │                                      │
///                    ▼                                      │
///            offset < file_size? ───yes─────────────────────┘
///                    │
///                    no (scan_completed)
///                    ▼
///     scan_completed && !file_had_findings?
///            │                │
///           yes               no
///            ▼                ▼
///     emit_persistence_batch  (skip — already
///       (empty batch;          emitted per-chunk)
///        done-ledger marks
///        file as "clean")
///            │                │
///            └───────┬────────┘
///                    ▼
///             release_buffer()
/// ```
///
/// # Error Handling
///
/// I/O errors are logged (debug builds) but do not propagate — fail-soft
/// per file. The executor continues with remaining files.
fn process_file<E: ScanEngine>(task: FileTask, ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>) {
    if ctx.scratch.abort_run.load(Ordering::Relaxed) {
        return;
    }
    let scratch = &mut ctx.scratch;
    let engine = &scratch.engine;
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size;
    let skip_binary = scratch.skip_binary;
    let path_bytes = task.path.as_os_str().as_encoded_bytes();
    let ext_kind = if scratch.archive.enabled {
        detect_kind_from_path(&task.path)
    } else {
        None
    };

    if let Some(kind) = ext_kind {
        ctx.metrics.archive.record_archive_seen();
        let outcome = dispatch_archive_scan(&task, ctx, kind);
        match outcome {
            ArchiveEnd::Scanned => ctx.metrics.archive.record_archive_scanned(),
            ArchiveEnd::Skipped(r) => ctx
                .metrics
                .archive
                .record_archive_skipped(r, path_bytes, false),
            ArchiveEnd::Partial(r) => ctx
                .metrics
                .archive
                .record_archive_partial(r, path_bytes, false),
        }
        return;
    }

    // Extension-based pre-open skip: avoid opening files whose extension
    // marks them as definitely-binary or as a credential-safe lock file.
    // BinaryExtractable formats (.jar, .class, .pyc, .ipynb) are NOT in the
    // skip set — they will fall through to the content classifier below.
    //
    // Ordering: extension check first (cheap u64 binary search on the packed
    // table), then lock-file check (linear scan of short filename table).
    // Each path increments its own counter (`ext_skipped` / `lock_skipped`)
    // so callers can distinguish the skip reason.
    if skip_binary {
        if let Some(ext_os) = task.path.extension() {
            let ext = ext_os.as_encoded_bytes();
            if crate::git_scan::path_policy::ext_in_skip_set(ext) {
                ctx.metrics.ext_skipped = ctx.metrics.ext_skipped.saturating_add(1);
                return;
            }
        }
        if crate::git_scan::path_policy::is_lock_filename(path_bytes) {
            ctx.metrics.lock_skipped = ctx.metrics.lock_skipped.saturating_add(1);
            return;
        }
    }

    // Open file
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    let open_start = std::time::Instant::now();

    let mut file = match File::open(&task.path) {
        Ok(f) => f,
        Err(e) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            #[cfg(debug_assertions)]
            eprintln!("[local] Failed to open file {:?}: {}", task.path, e);
            let _ = e;

            return;
        }
    };

    // Use actual file size after open (snapshot semantics)
    // Discovery size is just a hint; file may have changed
    let file_size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            #[cfg(debug_assertions)]
            eprintln!("[local] Failed to get metadata {:?}: {}", task.path, e);
            let _ = e;

            return;
        }
    };

    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        ctx.metrics.open_stat_ns = ctx
            .metrics
            .open_stat_ns
            .saturating_add(open_start.elapsed().as_nanos() as u64);
    }

    // Empty file: record a clean sentinel and return.
    if file_size == 0 {
        scratch.pending.clear();
        emit_persistence_batch(
            scratch.store_producer.as_deref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
            &mut scratch.persist_batch,
            &mut ctx.metrics,
            task.discovery_sequence(),
        );
        return;
    }

    // Enforce size cap at open time for snapshot semantics.
    if file_size > scratch.max_file_size {
        return;
    }

    hint_sequential(&file, file_size);

    // Acquire pool buffer up-front so the first read doubles as
    // archive/binary probe — eliminates a separate probe + seek.
    let mut buf = scratch.pool.acquire();

    // Read the first chunk directly into the pool buffer.
    let first_read_max = chunk_size.min(buf.len()).min(file_size as usize);
    let first_n = match read_some(&mut file, &mut buf.as_mut_slice()[..first_read_max]) {
        Ok(n) => n,
        Err(e) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            #[cfg(debug_assertions)]
            eprintln!("[local] Failed to read {:?}: {}", task.path, e);
            let _ = e;
            return;
        }
    };

    if first_n == 0 {
        return;
    }

    // Archive sniff from the first bytes (replaces the old TAR_BLOCK_LEN probe).
    if scratch.archive.enabled {
        let sniff_len = first_n.min(TAR_BLOCK_LEN);
        if let Some(kind) = sniff_kind_from_header(&buf.as_slice()[..sniff_len]) {
            drop(buf); // release buffer before dispatch (re-opens file)
            ctx.metrics.archive.record_archive_seen();
            let outcome = dispatch_archive_scan(&task, ctx, kind);
            match outcome {
                ArchiveEnd::Scanned => ctx.metrics.archive.record_archive_scanned(),
                ArchiveEnd::Skipped(r) => ctx
                    .metrics
                    .archive
                    .record_archive_skipped(r, path_bytes, false),
                ArchiveEnd::Partial(r) => ctx
                    .metrics
                    .archive
                    .record_archive_partial(r, path_bytes, false),
            }
            return;
        }
    }

    // Binary classification from the first bytes.
    if skip_binary {
        let classify_len = first_n.min(crate::content_policy::CHECK_LEN);
        let verdict = crate::content_policy::classify_content(
            &buf.as_slice()[..classify_len],
            path_bytes,
            crate::content_policy::CHECK_LEN,
        );
        match verdict {
            crate::content_policy::ContentVerdict::Binary => {
                ctx.metrics.binary_skipped = ctx.metrics.binary_skipped.saturating_add(1);
                return;
            }
            crate::content_policy::ContentVerdict::BinaryExtractable(fmt) => {
                drop(buf); // release buffer before extraction
                extract_and_scan_file(&task, ctx, &mut file, file_size, path_bytes, fmt);
                return;
            }
            crate::content_policy::ContentVerdict::Text => {}
        }
    }

    // State for overlap carry pattern
    let mut offset: u64 = 0; // Logical offset of next "new" bytes
    let mut carry: usize = 0; // Bytes of overlap prefix for next scan
    let mut have: usize = 0; // Total bytes in buffer from last iteration
    let mut preloaded: usize = first_n; // First chunk already in buf[0..first_n]
    let mut file_had_findings = false;
    let mut scan_completed = false;

    loop {
        // Move tail overlap bytes to front as next prefix
        // This is a tiny copy (overlap bytes, typically 16-256)
        carry_overlap_prefix(buf.as_mut_slice(), have, carry);

        // First iteration reuses the bytes already in the buffer from
        // the probe read above; subsequent iterations read from disk.
        let n = if preloaded > 0 {
            let n = preloaded;
            preloaded = 0;
            n
        } else {
            // Read next payload bytes after the prefix.
            // Cap by remaining snapshot size to maintain point-in-time semantics:
            // if the file grows after open, we only scan up to the original size.
            let read_start = carry;
            let remaining_in_snapshot = file_size.saturating_sub(offset) as usize;
            if remaining_in_snapshot == 0 {
                // Reached snapshot boundary - done with this file
                scan_completed = true;
                break;
            }
            let read_max = chunk_size.min(buf.len() - carry).min(remaining_in_snapshot);
            let dst = &mut buf.as_mut_slice()[read_start..read_start + read_max];

            #[cfg(all(feature = "perf-stats", debug_assertions))]
            let read_start_t = std::time::Instant::now();

            let n = match read_some(&mut file, dst) {
                Ok(n) => n,
                Err(e) => {
                    ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
                    #[cfg(debug_assertions)]
                    eprintln!("[local] Read failed for {:?}: {}", task.path, e);
                    let _ = e;

                    break;
                }
            };

            #[cfg(all(feature = "perf-stats", debug_assertions))]
            {
                ctx.metrics.read_ns = ctx
                    .metrics
                    .read_ns
                    .saturating_add(read_start_t.elapsed().as_nanos() as u64);
            }

            n
        };

        // EOF: done with this file
        if n == 0 {
            scan_completed = true;
            break;
        }

        let read_len = carry + n; // Total bytes available for scanning
        let _prefix_len = carry; // (for debugging/tracing)

        // base_offset: absolute file offset of buf[0]
        // For first chunk: base_offset = 0, prefix_len = 0
        // For subsequent: base_offset = offset - carry
        let base_offset = offset.saturating_sub(carry as u64);

        let data = &buf.as_slice()[..read_len];
        scan_chunk_postprocess(
            engine.as_ref(),
            &mut scratch.scan_scratch,
            &mut scratch.pending,
            task.file_id,
            base_offset,
            carry,
            data,
            &mut ctx.metrics,
        );

        // Emit persistence batches only for chunks that produced findings.
        // Clean-file done-ledger entries are emitted once after the loop.
        if !scratch.pending.is_empty() {
            file_had_findings = true;
            emit_persistence_batch(
                scratch.store_producer.as_deref(),
                &*scratch.event_sink,
                path_bytes,
                &scratch.pending,
                &mut scratch.persist_batch,
                &mut ctx.metrics,
                task.discovery_sequence(),
            );
        }
        emit_findings(
            engine.as_ref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
        );

        // Advance offset by actual payload read
        offset = offset.saturating_add(n as u64);
        have = read_len;
        carry = overlap.min(read_len);

        // Stop at snapshot size (consistent point-in-time semantics)
        if offset >= file_size {
            scan_completed = true;
            break;
        }
    }

    // Clean files emit a single empty batch so the done-ledger records
    // "scanned, nothing found." Finding-bearing files already emitted
    // per-chunk batches inside the loop. Skip the sentinel when the loop
    // exited due to an IO error — a partially-scanned file must not be
    // recorded as clean.
    if scan_completed && !file_had_findings {
        // `scan_chunk_postprocess` clears `pending` before draining, so
        // it is already empty here when no chunk produced findings.
        debug_assert!(scratch.pending.is_empty());
        emit_persistence_batch(
            scratch.store_producer.as_deref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
            &mut scratch.persist_batch,
            &mut ctx.metrics,
            task.discovery_sequence(),
        );
    }

    // Buffer returned to pool on drop
    // Permit released when FileTask drops
}

/// Advise the kernel that this file will be read sequentially.
///
/// On Linux this doubles the default readahead window (from ~128 KiB to
/// ~256 KiB on typical configs) and tells the VM not to expect random
/// access, improving prefetch hit rates for the sequential chunk reads
/// that follow. Advisory and non-blocking; errors are ignored because
/// `posix_fadvise` never modifies file state.
#[cfg(target_os = "linux")]
fn hint_sequential(file: &File, len: u64) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: file descriptor is valid for the duration of this call.
    // posix_fadvise is advisory and non-blocking; errors are harmless.
    unsafe {
        let _ = libc::posix_fadvise(
            file.as_raw_fd(),
            0,
            len as libc::off_t,
            libc::POSIX_FADV_SEQUENTIAL,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn hint_sequential(_file: &File, _len: u64) {}

/// Read some bytes, handling EINTR.
///
/// Returns number of bytes read (0 at EOF).
///
/// # Why not `read_exact`?
///
/// We want partial reads at EOF (to handle final chunk), while `read_exact`
/// returns `UnexpectedEof` on short reads. This wrapper gives us EINTR-safe
/// partial-read semantics.
///
/// # Signal Handling
///
/// `EINTR` (interrupted system call) can occur when a signal is delivered
/// during the read. This wrapper retries automatically, which is the standard
/// Unix idiom for non-interruptible reads.
fn read_some(file: &mut File, dst: &mut [u8]) -> io::Result<usize> {
    loop {
        match file.read(dst) {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

// ============================================================================
// Entry Point
// ============================================================================

/// Scan local files with blocking reads.
///
/// This is the low-level entry point for local filesystem scanning. For most
/// use cases, prefer [`parallel_scan_dir`](super::parallel_scan::parallel_scan_dir)
/// which handles directory walking and gitignore.
///
/// # Arguments
///
/// - `engine`: Detection engine (determines overlap, provides scan logic)
/// - `source`: Iterator of files to scan (e.g., [`VecFileSource`])
/// - `cfg`: Configuration for workers, chunking, and memory budgets (includes `event_sink`)
///
/// # Returns
///
/// [`LocalReport`] containing:
/// - `stats`: Discovery statistics (files enqueued, bytes, I/O errors)
/// - `metrics`: Executor metrics (chunks scanned, bytes scanned, timing)
///
/// # Execution Model
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────┐
/// │                           scan_local()                              │
/// └─────────────────────────────────────────────────────────────────────┘
///                    │
///         ┌─────────┴─────────┐
///         ▼                   ▼
///   ┌───────────────┐   ┌───────────────────────────────────────────┐
///   │  main thread  │   │              Executor                     │
///   │  (discovery)  │   │  ┌─────────┐ ┌─────────┐ ┌─────────┐     │
///   │               │──►│  │Worker 0 │ │Worker 1 │ │Worker N │     │
///   │  next_file()  │   │  └─────────┘ └─────────┘ └─────────┘     │
///   │  in loop      │   │       │           │           │          │
///   └───────────────┘   │       ▼           ▼           ▼          │
///                       │  process_file() process_file() ...       │
///                       └───────────────────────────────────────────┘
/// ```
///
/// The main thread pulls files from `source` and enqueues them. Workers
/// process files in parallel using work-stealing. The `CountBudget` limits
/// how far ahead discovery can run.
///
/// # Example
///
/// ```ignore
/// // With MockEngine (for testing):
/// let engine = Arc::new(MockEngine::new(rules, 16));
/// let files = vec![LocalFile { path: "test.txt".into(), size: 1024 }];
/// let source = VecFileSource::new(files);
///
/// let report = scan_local(engine, source, LocalConfig::default());
///
/// // With real Engine (for production):
/// let engine = Arc::new(Engine::new(rules, transforms, tuning));
/// let report = scan_local(engine, source, LocalConfig::default());
/// ```
pub fn scan_local<E, S>(engine: Arc<E>, source: S, cfg: LocalConfig) -> LocalReport
where
    E: ScanEngine,
    S: FileSource,
{
    scan_local_with_progress(engine, source, cfg, Arc::new(NullLocalProgressSink))
}

/// Scan local files with blocking reads and an optional progress callback.
///
/// The callback is invoked from the discovery thread each time a file is
/// admitted to the executor.
pub fn scan_local_with_progress<E, S>(
    engine: Arc<E>,
    mut source: S,
    cfg: LocalConfig,
    progress_sink: Arc<dyn LocalProgressSink>,
) -> LocalReport
where
    E: ScanEngine,
    S: FileSource,
{
    cfg.validate(engine.as_ref());

    let overlap = engine.required_overlap();
    let buf_len = cfg.chunk_size.saturating_add(overlap);

    // Create buffer pool (workers acquire and release via local queues)
    let pool = TsBufferPool::new(TsBufferPoolConfig {
        buffer_len: buf_len,
        total_buffers: cfg.pool_buffers,
        workers: cfg.workers,
        local_queue_cap: cfg.local_queue_cap,
    });

    // Object budget for discovery backpressure
    let budget = CountBudget::new(cfg.max_in_flight_objects);

    let archive_cfg = cfg.archive.clone();
    let abort_run = Arc::new(AtomicBool::new(false));

    // Capture config values before moving into closure
    let chunk_size = cfg.chunk_size;
    let event_sink = cfg.event_sink.clone();
    let store_producer = cfg.store_producer.clone();

    // Keep a handle for post-join diagnostics (the original is moved into
    // the executor's init closure).
    let run_event_sink = Arc::clone(&event_sink);

    // Create executor
    let ex = Executor::<FileTask>::new(
        ExecutorConfig {
            workers: cfg.workers,
            seed: cfg.seed,
            pin_threads: cfg.pin_threads,
            ..ExecutorConfig::default()
        },
        {
            let engine = Arc::clone(&engine);
            let pool = pool.clone();
            let abort_run = Arc::clone(&abort_run);
            let store_producer = store_producer.clone();
            move |_wid| {
                let findings_cap = engine.max_findings_per_chunk();
                let scan_scratch = engine.new_scratch();
                let depth_cap = archive_cfg.max_archive_depth as usize + 2;
                let mut vpaths = Vec::with_capacity(depth_cap);
                for _ in 0..depth_cap {
                    vpaths.push(VirtualPathBuilder::with_capacity(
                        archive_cfg.max_virtual_path_len_per_entry,
                    ));
                }
                let path_budget_used = vec![0usize; depth_cap];
                let mut tar_cursors = Vec::with_capacity(depth_cap);
                for _ in 0..depth_cap {
                    tar_cursors.push(TarCursor::with_capacity(&archive_cfg));
                }
                let entry_display_cap = archive_cfg.max_virtual_path_len_per_entry;
                let gzip_name_cap = archive_cfg.max_virtual_path_len_per_entry;
                let gzip_header_cap = archive_cfg
                    .max_virtual_path_len_per_entry
                    .saturating_add(256)
                    .min(archive_cfg.max_archive_metadata_bytes as usize)
                    .clamp(64, 64 * 1024);

                LocalScratch {
                    engine: Arc::clone(&engine),
                    pool: pool.clone(),
                    scan_scratch,
                    pending: Vec::with_capacity(findings_cap),
                    persist_batch: Vec::with_capacity(findings_cap),
                    canon: EntryPathCanonicalizer::with_capacity(
                        DEFAULT_MAX_COMPONENTS,
                        archive_cfg.max_virtual_path_len_per_entry,
                    ),
                    vpaths,
                    path_budget_used,
                    budgets: ArchiveBudgets::new(&archive_cfg),
                    tar_cursors,
                    zip_cursor: ZipCursor::with_capacity(&archive_cfg),
                    entry_display_buf: Vec::with_capacity(entry_display_cap),
                    gzip_header_buf: vec![0u8; gzip_header_cap],
                    gzip_name_buf: Vec::with_capacity(gzip_name_cap),
                    next_virtual_file_id: 0x8000_0000,
                    abort_run: Arc::clone(&abort_run),
                    event_sink: Arc::clone(&event_sink),
                    store_producer: store_producer.clone(),
                    chunk_size,
                    max_file_size: cfg.max_file_size,
                    archive: archive_cfg.clone(),
                    skip_binary: cfg.skip_binary,
                    extract_buf: Vec::with_capacity(
                        crate::content_policy::extract::EXTRACT_INPUT_CAP,
                    ),
                    extract_out_buf: Vec::with_capacity(
                        crate::content_policy::extract::EXTRACT_OUTPUT_CAP,
                    ),
                    extract_scratch: Vec::with_capacity(
                        crate::content_policy::extract::JAR_ENTRY_CAP,
                    ),
                }
            }
        },
        process_file::<E>,
    );

    // Discovery loop
    let mut stats = LocalStats::default();
    let mut next_file_id: u32 = 0;
    // Batch discovery injections to amortize wakeups and injector contention.
    // Keep the batch small to avoid large bursts of in-flight work.
    let batch_cap = cfg.max_in_flight_objects.clamp(1, 64);
    let mut batch: Vec<FileTask> = Vec::with_capacity(batch_cap);

    let mut aborted = false;
    while let Some(file) = source.next_file() {
        if abort_run.load(Ordering::Relaxed) {
            aborted = true;
            break;
        }
        // Acquire in-flight permit (blocks if at capacity)
        let permit = budget.acquire(1);
        if abort_run.load(Ordering::Relaxed) {
            aborted = true;
            drop(permit);
            break;
        }

        let file_id = FileId(next_file_id);
        // Virtual archive-entry FileIds occupy 0x8000_0000.. so real
        // file IDs must stay below that boundary to avoid aliasing.
        const VIRTUAL_BASE: u32 = 0x8000_0000;
        next_file_id = match next_file_id.checked_add(1) {
            Some(id) if id < VIRTUAL_BASE => id,
            _ => {
                eprintln!(
                    "discovery file ID reached virtual-entry namespace \
                     boundary ({VIRTUAL_BASE:#x}); stopping file enumeration"
                );
                // Enqueue this last file, then stop accepting new files.
                stats.files_enqueued = stats.files_enqueued.saturating_add(1);
                stats.bytes_enqueued = stats.bytes_enqueued.saturating_add(file.size);
                progress_sink.on_progress(LocalProgress {
                    files_enqueued: stats.files_enqueued,
                    bytes_enqueued: stats.bytes_enqueued,
                });
                let task = FileTask {
                    file_id,
                    path: file.path,
                    _permit: permit,
                };
                batch.push(task);
                break;
            }
        };

        stats.files_enqueued = stats.files_enqueued.saturating_add(1);
        stats.bytes_enqueued = stats.bytes_enqueued.saturating_add(file.size);
        progress_sink.on_progress(LocalProgress {
            files_enqueued: stats.files_enqueued,
            bytes_enqueued: stats.bytes_enqueued,
        });

        // Enqueue task
        let task = FileTask {
            file_id,
            path: file.path,
            _permit: permit,
        };

        batch.push(task);
        if batch.len() >= batch_cap {
            // This should not fail since we haven't called join() yet.
            ex.spawn_external_batch(std::mem::take(&mut batch))
                .expect("executor rejected task batch before join");
        }
    }

    if !aborted && !batch.is_empty() {
        ex.spawn_external_batch(batch)
            .expect("executor rejected task batch before join");
    } else if aborted {
        batch.clear();
    }

    // Wait for all files to complete
    let metrics = ex.join();

    // Aggregate I/O errors from worker metrics into stats
    stats.io_errors = metrics.io_errors;
    stats.dropped_findings = metrics.findings_dropped;
    stats.persistence_emit_failures = metrics.persistence_emit_failures;
    stats.persistence_incomplete =
        stats.dropped_findings > 0 || stats.persistence_emit_failures > 0;

    if let Some(producer) = store_producer.as_deref() {
        let run_loss = FsRunLoss {
            dropped_findings: stats.dropped_findings,
            persistence_emit_failures: stats.persistence_emit_failures,
        };
        if let Err(err) = producer.record_fs_run_loss(run_loss) {
            stats.persistence_emit_failures = stats.persistence_emit_failures.saturating_add(1);
            stats.persistence_incomplete = true;
            let mut msg = StackMsg::<256>::new();
            let _ = std::fmt::Write::write_fmt(
                &mut msg,
                format_args!("fs persistence run-loss recording failed: {}", err.detail()),
            );
            run_event_sink.emit_core(crate::events::CoreEvent::Diagnostic(
                crate::events::DiagnosticEvent {
                    level: "error",
                    message: msg.as_str(),
                },
            ));
        }
    }

    LocalReport { stats, metrics }
}

#[cfg(test)]
#[path = "local_fs_owner_tests.rs"]
mod tests;
