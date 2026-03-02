//! Archive scanning core with a sink-driven entry interface.
//!
//! # Scope
//! - Streaming archive parsing (gzip/bzip2/tar/tar.gz/tar.bz2/zip) with deterministic budgets.
//! - Virtual path construction + path budget enforcement.
//! - Entry scanning is delegated to an [`ArchiveEntrySink`] to avoid coupling
//!   to the pipeline or simulation harness.
//!
//! # Entry points
//!
//! | Function | Format | Access pattern |
//! |---|---|---|
//! | [`scan_gzip_stream`] | `.gz` | Sequential (`Read`) |
//! | [`scan_bzip2_stream`] | `.bz2` | Sequential (`Read`) |
//! | [`scan_tar_stream`] | `.tar` (plain or wrapped) | Sequential (`TarRead`) |
//! | [`scan_targz_stream`] | `.tar.gz` / `.tgz` | Sequential (`Read`) |
//! | [`scan_tarbz2_stream`] | `.tar.bz2` / `.tbz2` | Sequential (`Read`) |
//! | [`scan_zip_source`] | `.zip` | Random access (`ZipSource`) |
//!
//! # Sliding-window read loop
//!
//! Every entry payload is read using the same pattern (shared across gzip,
//! bzip2, tar, and zip code paths):
//!
//! ```text
//! stream_buf layout on each iteration:
//!
//!   |<-- carry (overlap) -->|<--- new read (up to chunk_size) --->|
//!   ^                       ^
//!   buf[0]                  buf[carry]
//!
//! carry = overlap.min(bytes_emitted_so_far)
//! ```
//!
//! Before each read, the last `carry` bytes of the previous chunk are
//! copied to the front of `stream_buf` so that downstream pattern matchers
//! see a sliding window with `overlap` bytes of look-behind context.
//! Budget checks happen *after* the read returns: bytes beyond the budget
//! are truncated (`allowed < n`) and the loop exits.
//!
//! # Budget lifecycle
//!
//! Each scan function follows the same budget protocol (see [`ArchiveBudgets`]):
//!
//! ```text
//! reset() → enter_archive()
//!   ├─ begin_entry() / begin_entry_scan()
//!   │   ├─ charge_compressed_in()   (raw bytes consumed)
//!   │   ├─ charge_decompressed_out() (payload bytes delivered to sink)
//!   │   ├─ charge_discarded_out()    (payload bytes read but dropped)
//!   │   └─ end_entry(scanned)
//!   ├─ … (repeat per entry)
//!   └─ exit_archive()
//! ```
//!
//! Budget violations never panic: they return a [`BudgetHit`] that maps
//! deterministically to [`ArchiveEnd::Partial`] or [`ArchiveEnd::Skipped`].
//!
//! # Locator suffixes
//!
//! Each virtual path is suffixed with a fixed-length *locator* so that
//! downstream consumers can re-seek to the exact entry within the archive:
//!
//! ```text
//! @t<16-hex-digits>   tar entry (header block index)
//! @z<16-hex-digits>   zip entry (local file header offset, when valid)
//! @c<16-hex-digits>   zip entry (CDFH offset, when LFH offset is invalid)
//! ```
//!
//! # Nested archive handling
//!
//! Tar entries whose names match a known archive extension (`.gz`, `.bz2`,
//! `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`) are recursively descended up to
//! `max_archive_depth`. Zip
//! entries inside a tar stream cannot be recursed (no random access) and
//! are handled according to [`UnsupportedPolicy`](crate::archive::UnsupportedPolicy).
//! Recursion uses `split_first_mut` to peel per-depth scratch slices
//! without allocation.
//!
//! # Design notes
//! - No OS dependencies: callers provide `Read`/`Read+Seek` sources.
//! - All hot-path buffers live in [`ArchiveScratch`] and are reused.
//! - Chunk overlap is configured once at [`ArchiveScratch::new`] time and
//!   applied uniformly to every entry read loop.
//! - **bzip2 CPU exhaustion**: bzip2 block decompression can buffer up to
//!   900 KiB internally per `read()` call. The `is_deadline_expired()` check
//!   fires between read iterations, not during a single decompression call,
//!   so a single block decode can run uninterrupted for a noticeable wall-clock
//!   interval. Production deployments should set `max_wall_clock_secs_per_root`
//!   to bound total CPU time per source file.

use std::io::Read;

use crate::archive::detect_kind_from_name_bytes;
use crate::archive::formats::zip::LimitedRead;
use crate::archive::formats::{
    Bzip2Stream, CompressedStream, GzipStream, TarCursor, TarNext, TarRead, ZipCursor, ZipEntryMeta,
};
use crate::archive::formats::{ZipNext, ZipOpen, ZipSource};
use crate::archive::path::apply_hash_suffix_truncation;
use crate::archive::util;
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, ArchiveKind, ArchiveSkipReason, ArchiveStats, BudgetHit,
    ChargeResult, EntryPathCanonicalizer, EntrySkipReason, PartialReason, VirtualPathBuilder,
    DEFAULT_MAX_COMPONENTS,
};

/// Length of a locator suffix: `@` + kind byte + 16 hex digits.
const LOCATOR_LEN: usize = 18;

/// Upper bound on a single `read()` call into `stream_buf`.
///
/// Keeps per-iteration work bounded even when `chunk_size` is very large,
/// so that budget checks and sink delivery happen at a reasonable cadence.
const ARCHIVE_STREAM_READ_MAX: usize = 256 * 1024;

/// Outcome for a single archive scan.
///
/// Every archive scan returns exactly one of these variants:
///
/// - `Scanned` — the archive was fully processed; every entry was delivered
///   (or individually skipped) without hitting an archive-level or root-level
///   budget.
/// - `Skipped` — a policy decision prevented scanning before any entry
///   payload was delivered (unsupported format, encryption, depth limit, etc.).
/// - `Partial` — scanning stopped mid-archive due to a budget limit, I/O
///   error, or malformed content. Entries delivered before the stop are still
///   valid and may contain findings.
///
/// All three variants are terminal for the current archive. The caller
/// decides whether to continue scanning other archives in the same root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveEnd {
    Scanned,
    Skipped(ArchiveSkipReason),
    Partial(PartialReason),
}

/// Metadata for a single archive entry delivered to the sink.
///
/// Constructed once per entry and passed to
/// [`ArchiveEntrySink::on_entry_start`] before any payload chunks.
pub struct EntryMeta<'a> {
    /// Virtual path bytes including the locator suffix (`@t` / `@z` / `@c`)
    /// for tar and zip entries. Gzip entries omit the locator because gzip
    /// contains exactly one decompressed stream.
    pub display_path: &'a [u8],
    /// Uncompressed size from the archive header when known, or 0 when the
    /// format does not provide a reliable size (e.g., gzip streaming).
    pub size_hint: u64,
    /// Reserved for future per-entry metadata; currently always 0.
    pub flags: u32,
}

/// Chunk of entry data delivered to the sink via
/// [`ArchiveEntrySink::on_entry_chunk`].
///
/// Each chunk represents one iteration of the sliding-window read loop.
/// `data` is the full window: the overlap carry from the previous chunk
/// (look-behind context for pattern matchers) followed by the newly read
/// bytes. The first chunk has no carry, so `data.len() == new_bytes_len`.
///
/// ```text
///   data[0..carry]          = overlap from previous chunk
///   data[carry..carry+new]  = freshly read bytes (new_bytes_len = new)
///   base_offset             = entry-relative offset of data[0]
///   new_bytes_start         = entry-relative offset of data[carry]
/// ```
pub struct EntryChunk<'a> {
    /// Full window: overlap prefix + newly read bytes.
    /// Covers entry offsets `[base_offset, base_offset + data.len())`.
    pub data: &'a [u8],
    /// Entry-relative byte offset corresponding to `data[0]`.
    pub base_offset: u64,
    /// Entry-relative byte offset of the first freshly read byte.
    pub new_bytes_start: u64,
    /// Number of freshly read bytes at the tail of `data`.
    pub new_bytes_len: usize,
}

/// Sink interface that decouples archive parsing from downstream processing.
///
/// Implementors receive a structured stream of entry lifecycle events and
/// payload chunks. The archive core drives this trait; consumers (detection
/// pipeline, simulation harness, test stubs) implement it.
///
/// # Call sequence (per entry)
///
/// ```text
/// on_entry_start(&meta)        // exactly once
///   on_entry_chunk(chunk)      // zero or more (zero for empty/skipped entries)
///   on_entry_chunk(chunk)
///   ...
/// on_entry_end()               // exactly once, even on truncation or error
/// ```
///
/// The `start`/`end` pair is always balanced. `on_entry_end` is delivered
/// even when the entry was partially scanned due to a budget hit or I/O
/// error, so the sink can release per-entry state unconditionally.
///
/// # Error handling
///
/// Returning `Err` from any callback aborts the entire archive scan
/// immediately. The error propagates unchanged as the outer `Result::Err`
/// of the scan function.
pub trait ArchiveEntrySink {
    type Error;

    fn on_entry_start(&mut self, meta: &EntryMeta<'_>) -> Result<(), Self::Error>;
    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error>;
    fn on_entry_end(&mut self) -> Result<(), Self::Error>;
}

/// Reusable scratch state for archive scanning.
///
/// Buffers are preallocated to avoid per-entry allocations. This type is not
/// thread-safe and is intended to be reused across scans by a single worker.
/// `chunk_size` and `overlap` must match the engine/pipeline settings.
///
/// # Per-depth vectors
///
/// `vpaths`, `path_budget_used`, and `tar_cursors` are each sized to
/// `max_archive_depth + 2`. During recursive tar descent, each nesting
/// level peels its own element via `split_first_mut` so that the child
/// scan operates on the tail slice without any allocation.
///
/// # `stream_buf` layout
///
/// `stream_buf` is `chunk_size + overlap` bytes (with a minimum of
/// `overlap + 1` to guarantee at least one new byte per read). On each
/// read iteration the last `overlap` bytes from the previous chunk are
/// copied to the front, then up to `chunk_size` new bytes are read
/// after them.
pub struct ArchiveScratch<Z: ZipSource> {
    canon: EntryPathCanonicalizer,
    vpaths: Vec<VirtualPathBuilder>,
    path_budget_used: Vec<usize>,
    budgets: ArchiveBudgets,
    tar_cursors: Vec<TarCursor>,
    zip_cursor: ZipCursor<Z>,
    entry_display_buf: Vec<u8>,
    gzip_header_buf: Vec<u8>,
    gzip_name_buf: Vec<u8>,
    stream_buf: Vec<u8>,
    chunk_size: usize,
    overlap: usize,
    /// Flag set by policy to abort the whole run (not just the archive).
    abort_run: bool,
}

impl<Z: ZipSource> ArchiveScratch<Z> {
    /// Preallocate buffers sized from the archive config and chunk geometry.
    ///
    /// `chunk_size` is the non-overlap payload size; `overlap` is carried
    /// forward between chunks to preserve windowed scanning.
    pub fn new(archive: &ArchiveConfig, chunk_size: usize, overlap: usize) -> Self {
        debug_assert!(chunk_size > 0, "chunk_size must be positive");
        debug_assert!(
            overlap <= chunk_size,
            "overlap ({overlap}) must not exceed chunk_size ({chunk_size})"
        );
        // +2: one slot for the root level (not counted in `max_archive_depth`),
        // plus one for a gzip sub-entry within the root tar (gzip wraps the stream
        // but occupies a depth slot for its own vpath/cursor).
        let depth_cap = archive.max_archive_depth as usize + 2;
        let mut vpaths = Vec::with_capacity(depth_cap);
        for _ in 0..depth_cap {
            vpaths.push(VirtualPathBuilder::with_capacity(
                archive.max_virtual_path_len_per_entry,
            ));
        }
        let mut tar_cursors = Vec::with_capacity(depth_cap);
        for _ in 0..depth_cap {
            tar_cursors.push(TarCursor::with_capacity(archive));
        }
        let entry_display_cap = archive.max_virtual_path_len_per_entry;
        let path_budget_used = vec![0usize; depth_cap];
        let gzip_name_cap = archive.max_virtual_path_len_per_entry;
        // Gzip header buffer: must hold the 10-byte fixed header plus the
        // optional FNAME field (up to max_virtual_path_len_per_entry) plus
        // other optional fields (~256 bytes headroom). Clamped to a sane
        // range and the metadata budget.
        let gzip_header_cap = archive
            .max_virtual_path_len_per_entry
            .saturating_add(256)
            .min(archive.max_archive_metadata_bytes as usize)
            .clamp(64, 64 * 1024);
        // Guarantee at least overlap+1 bytes so every read iteration can
        // make forward progress (read at least 1 new byte after the carry).
        let buf_len = chunk_size
            .saturating_add(overlap)
            .max(overlap.saturating_add(1));

        Self {
            canon: EntryPathCanonicalizer::with_capacity(
                DEFAULT_MAX_COMPONENTS,
                archive.max_virtual_path_len_per_entry,
            ),
            vpaths,
            path_budget_used,
            budgets: ArchiveBudgets::new(archive),
            tar_cursors,
            zip_cursor: ZipCursor::with_capacity(archive),
            entry_display_buf: Vec::with_capacity(entry_display_cap),
            gzip_header_buf: vec![0u8; gzip_header_cap],
            gzip_name_buf: Vec::with_capacity(gzip_name_cap),
            stream_buf: vec![0u8; buf_len],
            chunk_size,
            overlap,
            abort_run: false,
        }
    }

    /// Returns `true` if a policy (e.g. `FailRun`) has requested that the
    /// entire scanning run be aborted, not just the current archive.
    #[inline]
    pub fn abort_run(&self) -> bool {
        self.abort_run
    }

    /// Resets the run-abort flag so the scratch can be reused for the next run.
    #[inline]
    pub fn clear_abort(&mut self) {
        self.abort_run = false;
    }

    /// Arm a deterministic countdown that overrides `is_deadline_expired()` in
    /// the underlying [`ArchiveBudgets`].
    ///
    /// See [`ArchiveBudgets::set_deadline_check_countdown`] for semantics.
    /// This forwarding method exists so that simulation tests can reach the
    /// budget countdown through the `ArchiveScratch` without exposing the
    /// `budgets` field.
    #[cfg(feature = "sim-harness")]
    pub(crate) fn set_deadline_check_countdown(&self, n: Option<u32>) {
        self.budgets.set_deadline_check_countdown(n);
    }
}

/// Borrow-split view over [`ArchiveScratch`] plus the caller's sink and stats.
///
/// Constructing this from `ArchiveScratch` via [`ArchiveScanCtx::new`]
/// decomposes the scratch into independent mutable borrows. This is the
/// key mechanism that enables recursive nesting: the parent peels the
/// first element from `vpaths`, `path_budget_used`, and `tar_cursors` for
/// its own depth, then hands the remaining tail slices to the child
/// `ArchiveScanCtx` — all without allocation or `unsafe`.
///
/// # Invariants
///
/// - The per-depth slices (`vpaths`, `path_budget_used`, `tar_cursors`)
///   always have length >= 1 when the context is in use. An empty slice
///   means the depth budget is exhausted and no further nesting is allowed.
/// - `stream_buf` is shared across all depths (only one read loop is
///   active at a time during depth-first traversal).
struct ArchiveScanCtx<'a, S, Z: ZipSource> {
    // ── Per-depth fields (peeled via `split_first_mut` during recursion) ──
    vpaths: &'a mut [VirtualPathBuilder],
    path_budget_used: &'a mut [usize],
    tar_cursors: &'a mut [TarCursor],

    // ── Shared mutable state ─────────────────────────────────────────────
    sink: &'a mut S,
    stats: &'a mut ArchiveStats,
    budgets: &'a mut ArchiveBudgets,
    canon: &'a mut EntryPathCanonicalizer,
    zip_cursor: &'a mut ZipCursor<Z>,
    entry_display_buf: &'a mut Vec<u8>,
    gzip_header_buf: &'a mut Vec<u8>,
    gzip_name_buf: &'a mut Vec<u8>,
    stream_buf: &'a mut Vec<u8>,
    abort_run: &'a mut bool,

    // ── Immutable config ─────────────────────────────────────────────────
    archive: &'a ArchiveConfig,
    chunk_size: usize,
    overlap: usize,
}

impl<'a, S, Z: ZipSource> ArchiveScanCtx<'a, S, Z> {
    /// Split `scratch` into independent borrows and combine with the caller's
    /// sink, stats, and config to form a scan context for the root depth.
    fn new(
        sink: &'a mut S,
        stats: &'a mut ArchiveStats,
        archive: &'a ArchiveConfig,
        scratch: &'a mut ArchiveScratch<Z>,
    ) -> Self {
        Self {
            sink,
            stats,
            budgets: &mut scratch.budgets,
            canon: &mut scratch.canon,
            vpaths: scratch.vpaths.as_mut_slice(),
            path_budget_used: scratch.path_budget_used.as_mut_slice(),
            tar_cursors: scratch.tar_cursors.as_mut_slice(),
            zip_cursor: &mut scratch.zip_cursor,
            entry_display_buf: &mut scratch.entry_display_buf,
            gzip_header_buf: &mut scratch.gzip_header_buf,
            gzip_name_buf: &mut scratch.gzip_name_buf,
            stream_buf: &mut scratch.stream_buf,
            archive,
            chunk_size: scratch.chunk_size,
            overlap: scratch.overlap,
            abort_run: &mut scratch.abort_run,
        }
    }
}

/// Map a [`BudgetHit`] to the top-level [`ArchiveEnd`] outcome for the
/// current archive.
///
/// `SkipEntry` is promoted to `Partial` (not `Skipped`) because the archive
/// scan is already in progress when a per-entry budget fires — some entries
/// may already have been delivered to the sink. The entry is cut short, but
/// the archive outcome must reflect that partial work occurred.
#[inline(always)]
fn budget_hit_to_archive_end(hit: BudgetHit) -> ArchiveEnd {
    match hit {
        BudgetHit::SkipArchive(r) => ArchiveEnd::Skipped(r),
        BudgetHit::PartialArchive(r) => ArchiveEnd::Partial(r),
        BudgetHit::StopRoot(r) => ArchiveEnd::Partial(r),
        BudgetHit::SkipEntry(r) => ArchiveEnd::Partial(r.to_partial()),
    }
}

/// Format a locator suffix into `out`: `@<kind><16-hex-digits>`.
///
/// `kind` is one of `b't'` (tar header block index), `b'z'` (zip LFH
/// offset), or `b'c'` (zip CDFH offset). Returns the full 18-byte slice.
#[inline]
fn build_locator(out: &mut [u8; LOCATOR_LEN], kind: u8, value: u64) -> &[u8] {
    out[0] = b'@';
    out[1] = kind;
    util::write_u64_hex_lower(value, &mut out[2..]);
    out
}

/// Charge discarded decompressed bytes (read but not delivered to the sink).
///
/// Mirrors [`ArchiveBudgets::charge_discarded_out`]: bypasses the per-entry
/// output-byte cap, but still enforces archive/root output caps and ratio caps
/// (including per-entry ratio while an entry scope is open).
#[inline(always)]
fn charge_discarded_bytes(budgets: &mut ArchiveBudgets, bytes: u64) -> Result<(), PartialReason> {
    if bytes == 0 {
        return Ok(());
    }
    match budgets.charge_discarded_out(bytes) {
        ChargeResult::Ok => Ok(()),
        ChargeResult::Clamp { hit, .. } => Err(util::budget_hit_to_partial(
            hit,
            PartialReason::MalformedTar,
        )),
    }
}

/// Drain `remaining` bytes from `input` without delivering them to the sink.
///
/// Used after a budget-capped or nested-archive entry to advance the tar
/// stream past the unconsumed payload. Each drained chunk is charged against
/// the budget as discarded output; a budget hit aborts the drain early with
/// the corresponding [`PartialReason`].
///
/// The wall-clock deadline is also checked at the top of each iteration so
/// that a timeout during the scan read loop does not silently drain a large
/// entry payload before returning.
fn discard_remaining_payload(
    input: &mut dyn TarRead,
    budgets: &mut ArchiveBudgets,
    buf: &mut [u8],
    mut remaining: u64,
) -> Result<(), PartialReason> {
    while remaining > 0 {
        if budgets.is_deadline_expired() {
            return Err(PartialReason::WallClockTimeout);
        }
        let step = buf.len().min(remaining as usize);
        let n = match input.read(&mut buf[..step]) {
            Ok(n) => n,
            Err(_) => return Err(PartialReason::MalformedTar),
        };
        if n == 0 {
            return Err(PartialReason::MalformedTar);
        }
        budgets.charge_compressed_in(input.take_compressed_delta());
        charge_discarded_bytes(budgets, n as u64)?;
        remaining = remaining.saturating_sub(n as u64);
    }
    Ok(())
}

/// Scan a gzip stream as a single virtual entry (root-level entry point).
///
/// The sink sees exactly one entry whose display name is the embedded gzip
/// filename, or `<gunzip>` when the gzip header has no `FNAME` field.
///
/// Budgets are reset at the start and balanced (`enter_archive` /
/// `exit_archive`) around the scan. The gzip header buffer is borrowed
/// from `scratch` for the duration and restored before returning.
///
/// # Errors
///
/// Sink errors (`S::Error`) are propagated immediately. I/O and budget
/// failures are represented as [`ArchiveEnd::Partial`] or
/// [`ArchiveEnd::Skipped`] in the `Ok` variant.
pub fn scan_gzip_stream<R: Read, S: ArchiveEntrySink, Z: ZipSource>(
    reader: R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let mut scan = ArchiveScanCtx::new(sink, stats, archive, scratch);
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);

    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(scan.vpaths.len() > 1);
    debug_assert!(scan.path_budget_used.len() > 1);
    scan.path_budget_used[1] = 0;

    let (mut gz, name_len) = match GzipStream::new_with_header(
        reader,
        scan.gzip_header_buf,
        scan.gzip_name_buf,
        max_len,
    ) {
        Ok(v) => v,
        Err(_) => return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError)),
    };

    let entry_name_bytes = if let Some(len) = name_len {
        let c =
            scan.canon
                .canonicalize(&scan.gzip_name_buf[..len], DEFAULT_MAX_COMPONENTS, max_len);
        if c.had_traversal {
            scan.stats.record_path_had_traversal();
        }
        if c.component_cap_exceeded {
            scan.stats.record_component_cap_exceeded();
        }
        if c.truncated {
            scan.stats.record_path_truncated();
        }
        c.bytes
    } else {
        b"<gunzip>"
    };

    let need;
    {
        let built = scan.vpaths[1].build(root_display, entry_name_bytes, max_len);
        need = built.bytes.len();
        scan.entry_display_buf.clear();
        scan.entry_display_buf.extend_from_slice(built.bytes);
    }
    if scan.path_budget_used[1].saturating_add(need) > archive.max_virtual_path_bytes_per_archive {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        *scan.gzip_header_buf = hdr_buf;
        return Ok(ArchiveEnd::Partial(PartialReason::PathBudgetExceeded));
    }
    scan.path_budget_used[1] = scan.path_budget_used[1].saturating_add(need);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        *scan.gzip_header_buf = hdr_buf;
        return Ok(budget_hit_to_archive_end(hit));
    }

    // Temporarily take ownership of entry_display_buf so we can borrow its
    // contents as `display` while still passing `&mut scan` into the inner
    // function. This avoids a double-borrow conflict. The buffer is restored
    // immediately after the call returns.
    let display_buf = std::mem::take(scan.entry_display_buf);
    let display = display_buf.as_slice();
    let outcome = scan_compressed_entry_stream(
        &mut scan,
        &mut gz,
        display,
        chunk_size,
        PartialReason::CompressedStreamCorrupt,
    );
    *scan.entry_display_buf = display_buf;
    let outcome = outcome?;
    scan.budgets.exit_archive();

    // Recover the header buffer from inside the GzipStream so it can be
    // reused for subsequent gzip scans without reallocation.
    let (_inner, hdr_buf) = gz.into_inner().into_parts();
    *scan.gzip_header_buf = hdr_buf;
    Ok(outcome)
}

/// Inner read loop for a single compressed-stream entry (gzip or bzip2).
///
/// Implements the sliding-window pattern described in the module docs:
/// reads up to `chunk_size` decompressed bytes per iteration, charges
/// budgets, and delivers each window (including the overlap prefix from
/// the prior chunk) to the sink.
///
/// # Guarantees
///
/// - `on_entry_end` is always delivered, even on truncation or I/O error.
/// - An entry that yields zero decompressed bytes is treated as corrupt
///   (`corruption_reason`) by policy, unless a budget limit was hit first
///   (in which case the budget-derived reason takes precedence).
///
/// # Read loop structure
///
/// Each iteration follows a fixed sequence:
/// 1. Copy the overlap carry from the previous chunk to the buffer front.
/// 2. Check the wall-clock deadline (early exit if expired).
/// 3. Probe remaining budget allowance (pre-clamp before issuing the read).
/// 4. Read up to `min(chunk_size, allowance, buf capacity)` bytes.
/// 5. Charge compressed-in and decompressed-out budgets post-read.
/// 6. Deliver the full window (`overlap prefix + allowed new bytes`) to the sink.
/// 7. If the budget truncated the read (`allowed < n`), exit.
fn scan_compressed_entry_stream<C: CompressedStream, S: ArchiveEntrySink, Z: ZipSource>(
    scan: &mut ArchiveScanCtx<'_, S, Z>,
    stream: &mut C,
    display: &[u8],
    chunk_size: usize,
    corruption_reason: PartialReason,
) -> Result<ArchiveEnd, S::Error> {
    let budgets = &mut *scan.budgets;
    let overlap = scan.overlap;

    if let Err(hit) = budgets.begin_entry() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let meta = EntryMeta {
        display_path: display,
        size_hint: 0,
        flags: 0,
    };
    scan.sink.on_entry_start(&meta)?;

    let buf = &mut scan.stream_buf;

    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;
    let mut entry_skip_reason: Option<EntrySkipReason> = None;

    loop {
        if budgets.is_deadline_expired() {
            outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
            entry_partial_reason = Some(PartialReason::WallClockTimeout);
            break;
        }

        // Slide the overlap window: copy the last `carry` bytes of the
        // previous chunk to the buffer front for pattern-matcher look-behind.
        if carry > 0 && have > 0 {
            buf.copy_within(have - carry..have, 0);
        }

        // Pre-clamp: probe remaining budget *before* issuing the read so we
        // never decompress bytes we know we cannot deliver. The 1-byte charge
        // on zero allowance materializes the specific BudgetHit for telemetry.
        let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = util::budget_hit_to_partial(hit, corruption_reason);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        // Defensive: if geometry or allowance leaves no room, treat the same
        // as a zero-allowance budget hit.
        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = util::budget_hit_to_partial(hit, corruption_reason);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf[carry..carry + read_max];
        let n = match stream.read(dst) {
            Ok(n) => n,
            Err(_) => {
                outcome = ArchiveEnd::Partial(corruption_reason);
                entry_partial_reason = Some(corruption_reason);
                break;
            }
        };

        if n == 0 {
            break;
        }

        budgets.charge_compressed_in(stream.take_compressed_delta());

        // Post-read charge: if the budget is now exhausted the charge returns
        // a clamped `allowed` count — we deliver only that many bytes and exit.
        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
            if let BudgetHit::SkipEntry(reason) = hit {
                entry_skip_reason = Some(reason);
            }
            let r = util::budget_hit_to_partial(hit, corruption_reason);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;

        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf[..read_len];
        let chunk = EntryChunk {
            data,
            base_offset,
            new_bytes_start: offset,
            new_bytes_len: allowed_usize,
        };
        scan.sink.on_entry_chunk(chunk)?;
        if !entry_scanned {
            scan.stats.record_entry_scanned();
            entry_scanned = true;
        }

        offset = offset.saturating_add(allowed);
        have = read_len;
        carry = overlap.min(read_len);

        // Budget truncation: we read `n` bytes but were only allowed to
        // deliver `allowed` of them. The entry is partially scanned.
        if allowed_usize < n {
            break;
        }
    }

    scan.sink.on_entry_end()?;
    budgets.end_entry(offset > 0);
    // A compressed entry that produced zero decompressed bytes (and was not
    // budget-limited) is treated as corrupt by scanner policy. This is
    // intentionally stricter than the format specs to avoid silently accepting
    // empty/truncated payloads in archive telemetry.
    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(corruption_reason);
        entry_partial_reason = Some(corruption_reason);
    }
    if let Some(reason) = entry_skip_reason {
        scan.stats.record_entry_skipped(reason, display, false);
    }
    if let Some(r) = entry_partial_reason {
        scan.stats.record_entry_partial(r, display, false);
    }

    Ok(outcome)
}

/// Scan a bzip2 stream as a single virtual entry (root-level entry point).
///
/// The sink sees exactly one entry named `<bunzip2>`.
pub fn scan_bzip2_stream<R: Read, S: ArchiveEntrySink, Z: ZipSource>(
    reader: R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let mut scan = ArchiveScanCtx::new(sink, stats, archive, scratch);
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let max_len = archive.max_virtual_path_len_per_entry;

    debug_assert!(scan.vpaths.len() > 1);
    debug_assert!(scan.path_budget_used.len() > 1);
    scan.path_budget_used[1] = 0;

    let entry_name_bytes = b"<bunzip2>";
    let need;
    {
        let built = scan.vpaths[1].build(root_display, entry_name_bytes, max_len);
        need = built.bytes.len();
        scan.entry_display_buf.clear();
        scan.entry_display_buf.extend_from_slice(built.bytes);
    }
    if scan.path_budget_used[1].saturating_add(need) > archive.max_virtual_path_bytes_per_archive {
        return Ok(ArchiveEnd::Partial(PartialReason::PathBudgetExceeded));
    }
    scan.path_budget_used[1] = scan.path_budget_used[1].saturating_add(need);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let mut bz2 = Bzip2Stream::new(reader);
    let display_buf = std::mem::take(scan.entry_display_buf);
    let display = display_buf.as_slice();
    let outcome = scan_compressed_entry_stream(
        &mut scan,
        &mut bz2,
        display,
        chunk_size,
        PartialReason::CompressedStreamCorrupt,
    )?;
    *scan.entry_display_buf = display_buf;
    scan.budgets.exit_archive();
    Ok(outcome)
}

/// Scan a tar stream (plain or gzip-wrapped) as sequential entries.
///
/// This is the top-level entry point for `.tar`, `.tar.gz`, and `.tar.bz2` archives.
/// It resets budgets, pushes an archive frame, delegates to the recursive
/// [`scan_tar_stream_nested`] for actual entry iteration, and pops the
/// frame on return.
///
/// # Parameters
///
/// - `ratio_active` — enables inflation-ratio pre-clamping before each
///   payload read. Set `true` when the tar stream is wrapped in a compressed
///   stream (gzip or bzip2) so that the ratio budget is enforced against
///   decompressed output. Ratio enforcement also runs inside
///   `charge_decompressed_out` regardless of this flag, but the pre-clamp
///   avoids decompressing bytes that would be immediately discarded.
///
/// # Errors
///
/// Sink errors propagate immediately. Budget and I/O failures map to
/// [`ArchiveEnd::Partial`] / [`ArchiveEnd::Skipped`].
#[allow(clippy::too_many_arguments)]
pub fn scan_tar_stream<R: TarRead, S: ArchiveEntrySink, Z: ZipSource>(
    input: &mut R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
    ratio_active: bool,
) -> Result<ArchiveEnd, S::Error> {
    let mut scan = ArchiveScanCtx::new(sink, stats, archive, scratch);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let outcome = scan_tar_stream_nested(&mut scan, input, root_display, 1, ratio_active)?;
    scan.budgets.exit_archive();
    Ok(outcome)
}

/// Recursive inner loop for tar entry iteration.
///
/// For each tar entry this function:
/// 1. Reads the header via [`TarCursor::next_entry`] and builds a
///    canonicalized virtual path with a `@t` locator suffix.
/// 2. Skips non-regular entries (directories, symlinks, etc.).
/// 3. Checks whether the entry name matches a known archive extension.
///    If so — and the depth limit has not been reached — the entry is
///    recursively descended as a nested archive (gzip/bzip2/tar/tar.gz/tar.bz2).
///    Zip entries inside tar cannot be descended (no random access) and
///    fall through to raw-byte scanning unless the policy aborts.
/// 4. Otherwise, runs the sliding-window read loop to deliver payload
///    chunks to the sink.
///
/// After each entry's payload (whether scanned or nested), any unconsumed
/// bytes are drained via [`discard_remaining_payload`] and tar padding is
/// consumed to keep the stream aligned for the next header.
///
/// # Scratch peeling
///
/// The function peels the first element from `scan.vpaths`,
/// `scan.path_budget_used`, and `scan.tar_cursors` for the current depth
/// and passes the remaining tail slices to child contexts. This avoids
/// allocation and ensures each nesting level has its own independent state.
fn scan_tar_stream_nested<S: ArchiveEntrySink, Z: ZipSource>(
    scan: &mut ArchiveScanCtx<'_, S, Z>,
    input: &mut dyn TarRead,
    container_display: &[u8],
    depth: u8,
    ratio_active: bool,
) -> Result<ArchiveEnd, S::Error> {
    let budgets = &mut *scan.budgets;
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let overlap = scan.overlap;
    let max_len = scan.archive.max_virtual_path_len_per_entry;
    let max_depth = scan.archive.max_archive_depth;

    debug_assert!(!scan.vpaths.is_empty(), "vpaths exhausted at depth {depth}");
    debug_assert!(
        !scan.path_budget_used.is_empty(),
        "path_budget_used exhausted at depth {depth}"
    );
    debug_assert!(
        !scan.tar_cursors.is_empty(),
        "tar_cursors exhausted at depth {depth}"
    );
    let (cur_vpath, rest_vpaths) = scan
        .vpaths
        .split_first_mut()
        .expect("vpath scratch exhausted");
    let (cur_path_used, rest_path_used) = scan
        .path_budget_used
        .split_first_mut()
        .expect("path budget scratch exhausted");
    let (cur_cursor, rest_cursors) = scan
        .tar_cursors
        .split_first_mut()
        .expect("tar cursor scratch exhausted");

    cur_cursor.reset();
    *cur_path_used = 0;

    let mut outcome = ArchiveEnd::Scanned;

    loop {
        if budgets.is_deadline_expired() {
            outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
            break;
        }

        let (entry_display, entry_size, entry_pad, entry_typeflag, nested_kind) = {
            let meta = match cur_cursor.next_entry(input, budgets, scan.archive) {
                Ok(TarNext::End) => break,
                Ok(TarNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(TarNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            };

            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, b't', meta.header_block_index);
            let entry_display = {
                let c = scan
                    .canon
                    .canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    scan.stats.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    scan.stats.record_component_cap_exceeded();
                }
                if c.truncated {
                    scan.stats.record_path_truncated();
                }
                cur_vpath
                    .build_with_suffix(container_display, c.bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if cur_path_used.saturating_add(need) > scan.archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            *cur_path_used = cur_path_used.saturating_add(need);

            let nested_kind = detect_kind_from_name_bytes(meta.name);

            (
                entry_display,
                meta.size,
                meta.pad,
                meta.typeflag,
                nested_kind,
            )
        };

        // Tar typeflag 0 (NUL) and '0' (ASCII 0x30) both denote regular files.
        // Everything else (directories, symlinks, device nodes, etc.) is skipped.
        let is_regular = entry_typeflag == 0 || entry_typeflag == b'0';
        if !is_regular {
            scan.stats
                .record_entry_skipped(EntrySkipReason::NonRegular, entry_display, false);
            match cur_cursor.skip_payload_and_pad(input, budgets, entry_size, entry_pad) {
                Ok(Ok(())) => continue,
                _ => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            }
        }

        budgets.begin_entry_scan();
        // `stop_archive` is set when a nested outcome or drain failure
        // requires us to break out of the outer entry loop entirely.
        let mut stop_archive = false;

        // -- Nested archive handling --
        // If the entry name matches a known archive extension, attempt
        // recursive descent. Zip-in-tar is not recursable (needs random
        // access), so it falls through to raw-byte scanning or aborts
        // depending on `unsupported_policy`.
        if let Some(kind) = nested_kind {
            match kind {
                ArchiveKind::Zip => {
                    scan.stats.record_archive_skipped(
                        ArchiveSkipReason::NeedsRandomAccessNoSpill,
                        entry_display,
                        false,
                    );
                    match scan.archive.unsupported_policy {
                        crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                            // Fall back to scanning raw bytes.
                        }
                        crate::archive::UnsupportedPolicy::FailArchive => {
                            scan.stats.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                        crate::archive::UnsupportedPolicy::FailRun => {
                            *scan.abort_run = true;
                            scan.stats.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                    }
                }
                ArchiveKind::Gzip
                | ArchiveKind::Bzip2
                | ArchiveKind::Tar
                | ArchiveKind::TarGz
                | ArchiveKind::TarBz2 => {
                    if depth >= max_depth {
                        scan.stats.record_archive_skipped(
                            ArchiveSkipReason::DepthExceeded,
                            entry_display,
                            false,
                        );
                    } else if let Err(hit) = budgets.enter_archive() {
                        let r = budget_hit_to_archive_end(hit);
                        match r {
                            ArchiveEnd::Skipped(reason) => {
                                scan.stats
                                    .record_archive_skipped(reason, entry_display, false)
                            }
                            ArchiveEnd::Partial(reason) => {
                                scan.stats
                                    .record_archive_partial(reason, entry_display, false)
                            }
                            _ => {}
                        }
                    } else {
                        scan.stats.record_archive_seen();
                        scan.stats.record_entry_scanned();

                        let nested_outcome = match kind {
                            ArchiveKind::Gzip => {
                                debug_assert!(
                                    !rest_vpaths.is_empty(),
                                    "vpaths exhausted for nested archive at depth {depth}"
                                );
                                debug_assert!(
                                    !rest_path_used.is_empty(),
                                    "path_budget_used exhausted for nested archive at depth {depth}"
                                );
                                let (gunzip_vpath, vpaths_tail) = rest_vpaths
                                    .split_first_mut()
                                    .expect("vpath scratch exhausted");
                                let (gunzip_path_used, path_used_tail) = rest_path_used
                                    .split_first_mut()
                                    .expect("path budget scratch exhausted");
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: vpaths_tail,
                                    path_budget_used: path_used_tail,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };

                                let (mut gz, name_len) = match GzipStream::new_with_header(
                                    LimitedRead::new(input, entry_size),
                                    child.gzip_header_buf,
                                    child.gzip_name_buf,
                                    max_len,
                                ) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                        budgets.exit_archive();
                                        budgets.end_entry(true);
                                        break;
                                    }
                                };
                                let entry_name_bytes = if let Some(len) = name_len {
                                    let c = child.canon.canonicalize(
                                        &child.gzip_name_buf[..len],
                                        DEFAULT_MAX_COMPONENTS,
                                        max_len,
                                    );
                                    if c.had_traversal {
                                        child.stats.record_path_had_traversal();
                                    }
                                    if c.component_cap_exceeded {
                                        child.stats.record_component_cap_exceeded();
                                    }
                                    if c.truncated {
                                        child.stats.record_path_truncated();
                                    }
                                    c.bytes
                                } else {
                                    b"<gunzip>"
                                };
                                let gunzip_display = gunzip_vpath
                                    .build(entry_display, entry_name_bytes, max_len)
                                    .bytes;
                                *gunzip_path_used = 0;
                                let need = gunzip_display.len();
                                if gunzip_path_used.saturating_add(need)
                                    > scan.archive.max_virtual_path_bytes_per_archive
                                {
                                    outcome =
                                        ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                                    budgets.exit_archive();
                                    budgets.end_entry(true);
                                    break;
                                }
                                *gunzip_path_used = gunzip_path_used.saturating_add(need);

                                let out = scan_compressed_entry_stream(
                                    &mut child,
                                    &mut gz,
                                    gunzip_display,
                                    chunk_size,
                                    PartialReason::CompressedStreamCorrupt,
                                )?;
                                let (entry_reader, hdr_buf) = gz.into_inner().into_parts();
                                *child.gzip_header_buf = hdr_buf;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Bzip2 => {
                                debug_assert!(
                                    !rest_vpaths.is_empty(),
                                    "vpaths exhausted for nested archive at depth {depth}"
                                );
                                debug_assert!(
                                    !rest_path_used.is_empty(),
                                    "path_budget_used exhausted for nested archive at depth {depth}"
                                );
                                let (bunzip_vpath, vpaths_tail) = rest_vpaths
                                    .split_first_mut()
                                    .expect("vpath scratch exhausted");
                                let (bunzip_path_used, path_used_tail) = rest_path_used
                                    .split_first_mut()
                                    .expect("path budget scratch exhausted");
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: vpaths_tail,
                                    path_budget_used: path_used_tail,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };

                                let entry_name_bytes = b"<bunzip2>";
                                let bunzip_display = bunzip_vpath
                                    .build(entry_display, entry_name_bytes, max_len)
                                    .bytes;
                                *bunzip_path_used = 0;
                                let need = bunzip_display.len();
                                if bunzip_path_used.saturating_add(need)
                                    > scan.archive.max_virtual_path_bytes_per_archive
                                {
                                    outcome =
                                        ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                                    budgets.exit_archive();
                                    budgets.end_entry(true);
                                    break;
                                }
                                *bunzip_path_used = bunzip_path_used.saturating_add(need);

                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut bz2 = Bzip2Stream::new(entry_reader);
                                let out = scan_compressed_entry_stream(
                                    &mut child,
                                    &mut bz2,
                                    bunzip_display,
                                    chunk_size,
                                    PartialReason::CompressedStreamCorrupt,
                                )?;
                                let entry_reader = bz2.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Tar => {
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };
                                let mut entry_reader = LimitedRead::new(input, entry_size);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut entry_reader,
                                    entry_display,
                                    depth + 1,
                                    ratio_active,
                                )?;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::TarGz => {
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };
                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut gz = GzipStream::new(entry_reader);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut gz,
                                    entry_display,
                                    depth + 1,
                                    true,
                                )?;
                                let entry_reader = gz.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::TarBz2 => {
                                let mut child = ArchiveScanCtx {
                                    sink: scan.sink,
                                    stats: scan.stats,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    zip_cursor: scan.zip_cursor,
                                    entry_display_buf: scan.entry_display_buf,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    overlap: scan.overlap,
                                    abort_run: scan.abort_run,
                                };
                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut bz2 = Bzip2Stream::new(entry_reader);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut bz2,
                                    entry_display,
                                    depth + 1,
                                    true,
                                )?;
                                let entry_reader = bz2.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Zip => unreachable!(),
                        };

                        budgets.exit_archive();

                        // Unpack the nested result: (.0 = ArchiveEnd, .1 = remaining bytes).
                        // A non-zero .1 means the nested scan did not consume all of the
                        // entry payload, so we must drain the remainder to realign the tar
                        // stream for the next header.
                        let mut entry_partial_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(util::budget_hit_to_partial(
                                BudgetHit::SkipArchive(r),
                                PartialReason::MalformedTar,
                            )),
                            ArchiveEnd::Scanned => None,
                        };

                        match nested_outcome.0 {
                            ArchiveEnd::Scanned => scan.stats.record_archive_scanned(),
                            ArchiveEnd::Skipped(r) => {
                                scan.stats.record_archive_skipped(r, entry_display, false)
                            }
                            ArchiveEnd::Partial(r) => {
                                scan.stats.record_archive_partial(r, entry_display, false);
                            }
                        }

                        // Root-level budget exhaustion propagates upward and stops the
                        // entire archive, because no further entries can make progress.
                        let stop_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(util::budget_hit_to_partial(
                                BudgetHit::SkipArchive(r),
                                PartialReason::MalformedTar,
                            )),
                            ArchiveEnd::Scanned => None,
                        };
                        if let Some(r) = stop_reason {
                            if matches!(
                                r,
                                PartialReason::RootOutputBudgetExceeded
                                    | PartialReason::WallClockTimeout
                            ) {
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        // Drain unconsumed payload bytes so the tar stream is aligned
                        // for the next 512-byte header boundary.
                        if !stop_archive && nested_outcome.1 > 0 {
                            if entry_partial_reason.is_none() {
                                entry_partial_reason = Some(PartialReason::MalformedTar);
                            }
                            if let Err(r) = discard_remaining_payload(
                                input,
                                budgets,
                                scan.stream_buf.as_mut_slice(),
                                nested_outcome.1,
                            ) {
                                if entry_partial_reason.is_none() {
                                    entry_partial_reason = Some(r);
                                }
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        budgets.end_entry(true);

                        if let Some(r) = entry_partial_reason {
                            scan.stats.record_entry_partial(r, entry_display, false);
                        }

                        if !stop_archive {
                            match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
                                Ok(Ok(())) => {}
                                _ => {
                                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                    stop_archive = true;
                                }
                            }
                        }

                        if stop_archive {
                            break;
                        }

                        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
                        continue;
                    }
                }
            }
        }

        let entry_meta = EntryMeta {
            display_path: entry_display,
            size_hint: entry_size,
            flags: 0,
        };
        scan.sink.on_entry_start(&entry_meta)?;

        // -- Sliding-window read loop for regular tar entries --
        // Same pattern as the gzip read loop: overlap carry, pre-clamp,
        // read, post-charge, deliver, advance. Additionally bounded by
        // `remaining` (the declared entry size from the tar header).
        let mut remaining = entry_size;
        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;
        let mut entry_skip_reason: Option<EntrySkipReason> = None;

        while remaining > 0 {
            if budgets.is_deadline_expired() {
                outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
                entry_partial_reason = Some(PartialReason::WallClockTimeout);
                break;
            }

            if carry > 0 && have > 0 {
                scan.stream_buf.copy_within(have - carry..have, 0);
            }

            let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allowance == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    if let BudgetHit::SkipEntry(reason) = hit {
                        entry_skip_reason = Some(reason);
                    }
                    let r = util::budget_hit_to_partial(hit, PartialReason::MalformedTar);
                    outcome = ArchiveEnd::Partial(r);
                    entry_partial_reason = Some(r);
                }
                break;
            }

            let read_max = chunk_size
                .min(scan.stream_buf.len().saturating_sub(carry))
                .min(allowance.min(u64::from(u32::MAX)) as usize)
                .min(remaining.min(u64::from(u32::MAX)) as usize);

            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    if let BudgetHit::SkipEntry(reason) = hit {
                        entry_skip_reason = Some(reason);
                    }
                    let r = util::budget_hit_to_partial(hit, PartialReason::MalformedTar);
                    outcome = ArchiveEnd::Partial(r);
                    entry_partial_reason = Some(r);
                }
                break;
            }

            let dst = &mut scan.stream_buf[carry..carry + read_max];
            let n = match input.read(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    entry_partial_reason = Some(PartialReason::MalformedTar);
                    break;
                }
            };

            if n == 0 {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                entry_partial_reason = Some(PartialReason::MalformedTar);
                break;
            }

            budgets.charge_compressed_in(input.take_compressed_delta());

            let mut allowed = n as u64;
            if let ChargeResult::Clamp { allowed: a, hit } =
                budgets.charge_decompressed_out(allowed)
            {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = util::budget_hit_to_partial(hit, PartialReason::MalformedTar);
                allowed = a;
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }

            if allowed == 0 {
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;

            let base_offset = offset.saturating_sub(carry as u64);
            let data = &scan.stream_buf[..read_len];
            let chunk = EntryChunk {
                data,
                base_offset,
                new_bytes_start: offset,
                new_bytes_len: allowed_usize,
            };
            scan.sink.on_entry_chunk(chunk)?;
            if !entry_scanned {
                scan.stats.record_entry_scanned();
                entry_scanned = true;
            }

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = overlap.min(read_len);

            remaining = remaining.saturating_sub(allowed);

            if allowed_usize < n {
                break;
            }
        }

        scan.sink.on_entry_end()?;

        // Drain unconsumed payload bytes to keep the tar stream aligned for
        // the next header.  The drain runs when:
        //   - The read loop consumed all bytes normally (no partial reason), OR
        //   - The budget hit was entry-scoped (SkipEntry), because the archive
        //     must continue scanning subsequent entries.
        // The drain is skipped for archive/root-level budget hits and
        // deadline/IO errors, where further I/O is either unsafe or pointless.
        let entry_scoped_hit = entry_skip_reason.is_some();
        if (entry_partial_reason.is_none() || entry_scoped_hit) && remaining > 0 {
            if let Err(r) =
                discard_remaining_payload(input, budgets, scan.stream_buf.as_mut_slice(), remaining)
            {
                if entry_partial_reason.is_none() {
                    entry_partial_reason = Some(r);
                }
                outcome = ArchiveEnd::Partial(r);
            }
        }

        budgets.end_entry(offset > 0);

        if let Some(reason) = entry_skip_reason {
            scan.stats
                .record_entry_skipped(reason, entry_display, false);
        }
        if let Some(r) = entry_partial_reason {
            scan.stats.record_entry_partial(r, entry_display, false);
        }

        // Tar entries are padded to 512-byte block boundaries. Consume the
        // padding so the cursor is aligned for the next header read.
        match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
            Ok(Ok(())) => {}
            _ => {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                break;
            }
        }

        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
    }

    Ok(outcome)
}

/// Scan a gzip-compressed tar stream (`.tar.gz` / `.tgz`).
///
/// Thin wrapper: wraps the reader in a [`GzipStream`] decoder and delegates
/// to [`scan_tar_stream`] with `ratio_active = true` so that inflation-ratio
/// enforcement applies to the decompressed tar payload.
pub fn scan_targz_stream<R: Read, S: ArchiveEntrySink, Z: ZipSource>(
    reader: R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let mut gz = GzipStream::new(reader);
    scan_tar_stream(&mut gz, root_display, archive, scratch, sink, stats, true)
}

/// Scan a bzip2-compressed tar stream (`.tar.bz2` / `.tbz2`).
///
/// Thin wrapper: wraps the reader in a [`Bzip2Stream`] decoder and delegates
/// to [`scan_tar_stream`] with `ratio_active = true` so that inflation-ratio
/// enforcement applies to the decompressed tar payload.
pub fn scan_tarbz2_stream<R: Read, S: ArchiveEntrySink, Z: ZipSource>(
    reader: R,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let mut bz2 = Bzip2Stream::new(reader);
    scan_tar_stream(&mut bz2, root_display, archive, scratch, sink, stats, true)
}

/// Scan a zip archive via random access.
///
/// Unlike the tar scanners which process a sequential byte stream, zip
/// scanning requires `Read + Seek` (via [`ZipSource`]) because the central
/// directory is at the end of the file and individual entries are seeked to
/// by their local file header offset.
///
/// # Entry processing
///
/// Entries are iterated from the central directory. For each entry:
/// 1. Name is canonicalized and combined with a locator suffix (`@z` for
///    valid LFH offsets, `@c` for CDFH-only fallback).
/// 2. Directories, encrypted entries, and entries with unsupported
///    compression methods are handled according to the configured
///    [`EncryptedPolicy`](crate::archive::EncryptedPolicy) /
///    [`UnsupportedPolicy`](crate::archive::UnsupportedPolicy).
/// 3. Regular entries are decompressed via the sliding-window read loop
///    and delivered to the sink.
///
/// # Differences from tar scanning
///
/// - No recursive nesting: each zip entry is scanned as raw bytes.
/// - Compressed-byte deltas are tracked manually (the zip entry reader
///   exposes cumulative compressed bytes, not per-read deltas).
/// - Inflation-ratio pre-clamping is active only for deflate entries
///   (method 8); stored entries (method 0) have a 1:1 ratio.
///
/// # Errors
///
/// Sink errors propagate immediately. Budget and I/O failures map to
/// [`ArchiveEnd`] variants in the `Ok` path.
pub fn scan_zip_source<S: ArchiveEntrySink, Z: ZipSource>(
    source: Z,
    root_display: &[u8],
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch<Z>,
    sink: &mut S,
    stats: &mut ArchiveStats,
) -> Result<ArchiveEnd, S::Error> {
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);

    scratch.budgets.reset();
    if let Err(hit) = scratch.budgets.enter_archive() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let cursor = &mut scratch.zip_cursor;
    let open = match cursor.open(source, &mut scratch.budgets, archive) {
        Ok(open) => open,
        Err(_) => {
            scratch.budgets.exit_archive();
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    // ZipOpen result: the cursor parsed the EOCD and central directory.
    // `Ready` means entries are available; `Skip`/`Stop` are early exits
    // caused by format issues or budget limits during CD parsing.
    match open {
        ZipOpen::Ready => {}
        ZipOpen::Skip(r) => {
            scratch.budgets.exit_archive();
            if r == ArchiveSkipReason::UnsupportedFeature {
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry
                    | crate::archive::UnsupportedPolicy::FailArchive => {
                        return Ok(ArchiveEnd::Skipped(r));
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        scratch.abort_run = true;
                        return Ok(ArchiveEnd::Skipped(r));
                    }
                }
            }
            return Ok(ArchiveEnd::Skipped(r));
        }
        ZipOpen::Stop(r) => {
            scratch.budgets.exit_archive();
            return Ok(ArchiveEnd::Partial(r));
        }
    }

    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(scratch.path_budget_used.len() > 1);
    scratch.path_budget_used[1] = 0;

    let buf = &mut scratch.stream_buf;
    let mut outcome = ArchiveEnd::Scanned;

    loop {
        if scratch.budgets.is_deadline_expired() {
            outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
            break;
        }

        // Parse the next CDFH entry, canonicalize its name, apply policy
        // checks (directory, encrypted, unsupported compression), and extract
        // the fields needed for payload reading. The inner block limits the
        // borrow on `scratch.canon` and `scratch.vpaths` so that
        // `scratch.budgets` can be borrowed independently below.
        let (
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
            entry_display,
        ) = {
            let meta = match cursor.next_entry(&mut scratch.budgets, archive) {
                Ok(ZipNext::End) => break,
                Ok(ZipNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(ZipNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    break;
                }
            };

            let (locator_kind, locator_value) = if meta.lfh_offset_valid {
                (b'z', meta.local_header_offset)
            } else {
                (b'c', meta.cdfh_offset)
            };
            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, locator_kind, locator_value);
            let entry_display = {
                let c = scratch
                    .canon
                    .canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    stats.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    stats.record_component_cap_exceeded();
                }
                let entry_bytes = if meta.name_truncated {
                    stats.record_path_truncated();
                    scratch.entry_display_buf.clear();
                    scratch.entry_display_buf.extend_from_slice(c.bytes);
                    apply_hash_suffix_truncation(
                        &mut scratch.entry_display_buf,
                        meta.name_hash64,
                        max_len,
                    );
                    scratch.entry_display_buf.as_slice()
                } else {
                    if c.truncated {
                        stats.record_path_truncated();
                    }
                    c.bytes
                };
                scratch.vpaths[1]
                    .build_with_suffix(root_display, entry_bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if scratch.path_budget_used[1].saturating_add(need)
                > archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            scratch.path_budget_used[1] = scratch.path_budget_used[1].saturating_add(need);

            if meta.is_dir {
                stats.record_entry_skipped(EntrySkipReason::NonRegular, entry_display, false);
                continue;
            }

            if meta.is_encrypted() {
                stats.record_entry_skipped(EntrySkipReason::EncryptedEntry, entry_display, false);
                match archive.encrypted_policy {
                    crate::archive::EncryptedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::EncryptedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                    crate::archive::EncryptedPolicy::FailRun => {
                        scratch.abort_run = true;
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                }
            }
            if !meta.compression_supported() {
                stats.record_entry_skipped(
                    EntrySkipReason::UnsupportedCompression,
                    entry_display,
                    false,
                );
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::UnsupportedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        scratch.abort_run = true;
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                }
            }

            (
                meta.flags,
                meta.method,
                meta.compressed_size,
                meta.uncompressed_size,
                meta.local_header_offset,
                meta.cdfh_offset,
                meta.lfh_offset_valid,
                meta.is_dir,
                meta.name_truncated,
                meta.name_hash64,
                entry_display,
            )
        };

        let meta = ZipEntryMeta {
            name: b"",
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
        };

        scratch.budgets.begin_entry_scan();

        let mut reader = match cursor.open_entry_reader(&meta, &mut scratch.budgets) {
            Ok(Ok(r)) => r,
            Ok(Err(r)) => {
                if r == PartialReason::MalformedZip {
                    stats.record_entry_skipped(EntrySkipReason::CorruptEntry, entry_display, false);
                    scratch.budgets.end_entry(false);
                    continue;
                }
                outcome = ArchiveEnd::Partial(r);
                scratch.budgets.end_entry(false);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
                scratch.budgets.end_entry(false);
                break;
            }
        };

        let entry_meta = EntryMeta {
            display_path: entry_display,
            size_hint: meta.uncompressed_size,
            flags: 0,
        };
        sink.on_entry_start(&entry_meta)?;

        // Manual compressed-byte delta tracking: unlike TarRead (which exposes
        // per-read deltas via `take_compressed_delta`), the zip entry reader
        // only reports cumulative compressed bytes. We diff successive reads.
        let mut last_comp = 0u64;
        // Deflate (method 8) can exhibit high inflation ratios; stored entries
        // (method 0) are 1:1 and do not need ratio pre-clamping.
        let ratio_active = meta.method == 8;

        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;
        let mut entry_skip_reason: Option<EntrySkipReason> = None;

        loop {
            if scratch.budgets.is_deadline_expired() {
                outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
                entry_partial_reason = Some(PartialReason::WallClockTimeout);
                break;
            }

            if carry > 0 && have > 0 {
                buf.copy_within(have - carry..have, 0);
            }

            let allowance = scratch
                .budgets
                .remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allowance == 0 {
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
                    if let BudgetHit::SkipEntry(reason) = hit {
                        entry_skip_reason = Some(reason);
                    }
                    let r = util::budget_hit_to_partial(hit, PartialReason::MalformedZip);
                    outcome = ArchiveEnd::Partial(r);
                    entry_partial_reason = Some(r);
                }
                break;
            }

            let read_max = chunk_size
                .min(buf.len().saturating_sub(carry))
                .min(allowance.min(u64::from(u32::MAX)) as usize);

            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
                    if let BudgetHit::SkipEntry(reason) = hit {
                        entry_skip_reason = Some(reason);
                    }
                    let r = util::budget_hit_to_partial(hit, PartialReason::MalformedZip);
                    outcome = ArchiveEnd::Partial(r);
                    entry_partial_reason = Some(r);
                }
                break;
            }

            let dst = &mut buf[carry..carry + read_max];

            let n = match reader.read_decompressed(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    entry_partial_reason = Some(PartialReason::MalformedZip);
                    break;
                }
            };

            let now = reader.total_compressed();
            let delta = now.saturating_sub(last_comp);
            last_comp = now;
            if delta > 0 {
                scratch.budgets.charge_compressed_in(delta);
            }

            if n == 0 {
                break;
            }

            let mut allowed = n as u64;
            if let ChargeResult::Clamp { allowed: a, hit } =
                scratch.budgets.charge_decompressed_out(allowed)
            {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = util::budget_hit_to_partial(hit, PartialReason::MalformedZip);
                allowed = a;
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            if allowed == 0 {
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;

            let base_offset = offset.saturating_sub(carry as u64);
            let data = &buf[..read_len];
            let chunk = EntryChunk {
                data,
                base_offset,
                new_bytes_start: offset,
                new_bytes_len: allowed_usize,
            };
            sink.on_entry_chunk(chunk)?;
            if !entry_scanned {
                stats.record_entry_scanned();
                entry_scanned = true;
            }

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = scratch.overlap.min(read_len);

            if allowed_usize < n {
                break;
            }
        }

        sink.on_entry_end()?;
        scratch.budgets.end_entry(offset > 0);
        if let Some(reason) = entry_skip_reason {
            stats.record_entry_skipped(reason, entry_display, false);
        }
        if let Some(r) = entry_partial_reason {
            stats.record_entry_partial(r, entry_display, false);
        }

        // A wall-clock timeout in the inner read loop must break the outer
        // entry-iteration loop too, otherwise we start a new entry after
        // the deadline has already fired.
        if matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::WallClockTimeout)
        ) {
            break;
        }
    }

    scratch.budgets.exit_archive();
    Ok(outcome)
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
