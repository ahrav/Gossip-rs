//! Shared archive scanning scaffolding for the blocking-I/O local scanner.
//!
//! # Purpose
//!
//! Provides types, budget-enforcement helpers, and the unified chunk-scan loop
//! used by all archive format modules (`local_fs_gzip`, `local_fs_bzip2`,
//! `local_fs_tar`, `local_fs_zip`). These format modules handle
//! format-specific parsing (headers, central directories, stream framing)
//! but delegate chunk scanning and budget enforcement back to this module.
//!
//! # Archive scanning model
//!
//! Archives are scanned as a tree of virtual entries. Each entry gets a
//! virtual [`FileId`] from the high-bit namespace, a display path built by
//! [`VirtualPathBuilder`], and a budget allocation tracked by
//! [`ArchiveBudgets`]. The scanning loop follows the same overlap-carry
//! pattern as top-level files, using [`ArchiveScanCtx::scan_and_emit_chunk`]
//! which internally calls [`scan_chunk_postprocess`](super::shared_core::scan_chunk_postprocess).
//!
//! # Nesting
//!
//! Archives can contain archives (e.g., a `.tar.gz` inside a `.zip`).
//! Nesting is handled by splitting [`LocalScratch`] buffers into disjoint
//! per-depth slices via `split_first_mut`. Each nesting level consumes
//! the head element of depth-indexed vectors (`vpaths`, `path_budget_used`,
//! `tar_cursors`), passing the tail to the child context. This avoids
//! aliasing while allowing recursion without heap allocation per level.
//!
//! # Budget enforcement
//!
//! Decompressed output is metered through `ArchiveBudgets`, which enforces:
//! - Per-entry output byte caps
//! - Per-archive output caps
//! - Root-level (cross-archive) output caps
//! - Inflation ratio limits (decompressed/compressed)
//! - Wall-clock deadlines
//!
//! Budget violations stop scanning deterministically and produce
//! [`ArchiveEnd::Partial`] or [`ArchiveEnd::Skipped`] outcomes so the
//! caller can record the reason in metrics.
//!
//! # Key types
//!
//! | Type | Role |
//! |------|------|
//! | [`ArchiveScanCtx`] | Borrowed per-depth scanning context (split from [`LocalScratch`]) |
//! | [`ArchiveEnd`] | Outcome enum: fully scanned, skipped, or partial |
//! | [`ChunkScanResult`] | Loop-iteration carry state from `scan_and_emit_chunk` |

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::api::FileId;
use crate::archive::formats::CompressedStream;
use crate::archive::formats::TarCursor;
use crate::archive::formats::TarRead;
use crate::archive::util::write_u64_hex_lower;
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, ArchiveKind, ArchiveSkipReason, BudgetHit, ChargeResult,
    EntryPathCanonicalizer, EntrySkipReason, PartialReason, VirtualPathBuilder,
};
use crate::store::{FsFindingRecord, StoreProducer};

use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::WorkerCtx;
use super::local_fs_bzip2::process_bzip2_file;
use super::local_fs_gzip::process_gzip_file;
use super::local_fs_owner::{FileTask, LocalScratch, emit_persistence_batch};
use super::local_fs_tar::{process_tar_file, process_tarbz2_file, process_targz_file};
use super::local_fs_zip::process_zip_file;
use super::metrics::WorkerMetricsLocal;
use super::scan_helpers::emit_findings;
use super::shared_core::scan_chunk_postprocess;
use super::ts_buffer_pool::TsBufferPool;

/// Allocate a virtual `FileId` for archive entries.
///
/// Virtual IDs live in the high-bit namespace (`0x8000_0000..=0xFFFF_FFFF`)
/// to avoid collision with real file IDs (which start at 0 and grow upward).
/// The counter wraps after ~2^31 entries, but collisions are tolerable:
/// `FileId` is only used by the engine for internal attribution, not for
/// deduplication or correctness in the scheduler.
#[inline]
pub(super) fn alloc_virtual_file_id(next_virtual_file_id: &mut u32) -> FileId {
    const VIRTUAL_FILE_ID_BASE: u32 = 0x8000_0000;
    const VIRTUAL_FILE_ID_MASK: u32 = 0x7FFF_FFFF;

    let id = *next_virtual_file_id;
    let next = (id.wrapping_add(1) & VIRTUAL_FILE_ID_MASK) | VIRTUAL_FILE_ID_BASE;
    *next_virtual_file_id = next;
    FileId(id)
}

/// Length of a locator suffix: `@` + kind byte + 16 hex digits = 18 bytes.
///
/// Locators are appended to virtual path segments to disambiguate entries
/// that share the same display name within an archive. The format is
/// `@<kind><hex64>` where `kind` identifies the offset type:
/// - `t` = tar header block index
/// - `z` = ZIP local file header offset (when valid)
/// - `c` = ZIP central directory file header offset (fallback)
pub(super) const LOCATOR_LEN: usize = 18;

/// Format a locator suffix into `out` and return the full slice.
///
/// See [`LOCATOR_LEN`] for format description.
#[inline]
pub(super) fn build_locator(out: &mut [u8; LOCATOR_LEN], kind: u8, value: u64) -> &[u8] {
    out[0] = b'@';
    out[1] = kind;
    write_u64_hex_lower(value, &mut out[2..]);
    out
}

/// Dispatch archive scanning by kind.
///
/// Routes to `process_gzip_file`, `process_bzip2_file`, `process_tar_file`,
/// `process_targz_file`, `process_tarbz2_file`, or `process_zip_file`
/// based on the detected [`ArchiveKind`].
///
/// The caller is responsible for recording archive-level stats
/// (`record_archive_scanned` / `record_archive_skipped` / `record_archive_partial`)
/// based on the returned [`ArchiveEnd`].
#[inline]
pub(super) fn dispatch_archive_scan<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    kind: ArchiveKind,
) -> ArchiveEnd {
    match kind {
        ArchiveKind::Gzip => process_gzip_file(task, ctx),
        ArchiveKind::Bzip2 => process_bzip2_file(task, ctx),
        ArchiveKind::Tar => process_tar_file(task, ctx),
        ArchiveKind::TarGz => process_targz_file(task, ctx),
        ArchiveKind::TarBz2 => process_tarbz2_file(task, ctx),
        ArchiveKind::Zip => process_zip_file(task, ctx),
    }
}

/// Hard cap on per-read output for archive streams (256 KiB).
///
/// Archive entry reads are clamped to this value even when the pool buffer
/// is larger. This bounds decompressor output per iteration, keeping
/// inflation-ratio checks responsive and limiting peak stack/heap pressure
/// from a single decompression call.
pub(super) const ARCHIVE_STREAM_READ_MAX: usize = 256 * 1024;

/// Outcome of scanning an archive container.
///
/// Used by `dispatch_archive_scan` and its callees to communicate
/// whether the archive was fully consumed, entirely skipped, or
/// partially scanned (budget exhaustion, corruption, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ArchiveEnd {
    /// All entries in the archive were scanned to completion.
    Scanned,
    /// The archive was not scanned at all (e.g., I/O error, encrypted,
    /// unsupported format). The reason is recorded for telemetry.
    Skipped(ArchiveSkipReason),
    /// Scanning stopped partway through the archive (budget exceeded,
    /// malformed entry, inflation ratio exceeded). Some entries may
    /// have been fully scanned before the stop.
    Partial(PartialReason),
}

/// Map an archive-level skip reason to the corresponding partial-scan reason.
///
/// Used when a nested archive is skipped mid-stream, promoting the skip into
/// a partial outcome for the parent entry/archive. Variants without a direct
/// `PartialReason` counterpart map to `MalformedZip` as a conservative fallback.
#[inline(always)]
pub(super) fn map_archive_skip_to_partial(reason: ArchiveSkipReason) -> PartialReason {
    match reason {
        ArchiveSkipReason::MetadataBudgetExceeded => PartialReason::MetadataBudgetExceeded,
        ArchiveSkipReason::PathBudgetExceeded => PartialReason::PathBudgetExceeded,
        ArchiveSkipReason::EntryCountExceeded => PartialReason::EntryCountExceeded,
        ArchiveSkipReason::ArchiveOutputBudgetExceeded => {
            PartialReason::ArchiveOutputBudgetExceeded
        }
        ArchiveSkipReason::RootOutputBudgetExceeded => PartialReason::RootOutputBudgetExceeded,
        ArchiveSkipReason::InflationRatioExceeded => PartialReason::InflationRatioExceeded,
        ArchiveSkipReason::UnsupportedFeature => PartialReason::UnsupportedFeature,
        ArchiveSkipReason::Disabled
        | ArchiveSkipReason::UnsupportedFormat
        | ArchiveSkipReason::EncryptedArchive
        | ArchiveSkipReason::DepthExceeded
        | ArchiveSkipReason::NeedsRandomAccessNoSpill
        | ArchiveSkipReason::IoError
        | ArchiveSkipReason::Corrupt => PartialReason::MalformedZip,
    }
}

/// Extract the [`PartialReason`] from a [`BudgetHit`].
///
/// Every budget violation carries a reason; this collapses the four `BudgetHit`
/// variants into a flat `PartialReason` for recording in metrics and diagnostics.
/// `SkipEntry` is promoted to an entry-level partial reason.
#[inline(always)]
pub(super) fn budget_hit_to_partial_reason(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => map_archive_skip_to_partial(r),
        BudgetHit::SkipEntry(r) => r.to_partial(),
    }
}

/// Convert a [`BudgetHit`] into the corresponding [`ArchiveEnd`] outcome.
///
/// `SkipArchive` maps to `Skipped`; all others map to `Partial`.
#[inline(always)]
pub(super) fn budget_hit_to_archive_end(hit: BudgetHit) -> ArchiveEnd {
    match hit {
        BudgetHit::SkipArchive(r) => ArchiveEnd::Skipped(r),
        BudgetHit::PartialArchive(r) => ArchiveEnd::Partial(r),
        BudgetHit::StopRoot(r) => ArchiveEnd::Partial(r),
        BudgetHit::SkipEntry(r) => ArchiveEnd::Partial(r.to_partial()),
    }
}

/// Borrowed view into [`LocalScratch`] for archive scanning.
///
/// Splits the per-worker scratch into disjoint borrows so nested archive
/// scans can recurse without aliasing. Each nesting level consumes the
/// head element of `vpaths`, `path_budget_used`, and `tar_cursors` via
/// `split_first_mut`, passing the tail to the child `ArchiveScanCtx`.
///
/// # Invariants
/// - All buffers are preallocated in `LocalScratch` and must not grow.
/// - Nested scans borrow disjoint slices of scratch buffers (no aliasing).
/// - `budgets` is shared across nested scans to enforce global caps.
/// - `path_budget_used` tracks per-depth virtual path byte usage.
/// - `abort_run` is set when `FailRun` policies trigger; callers must stop
///   dispatching new files once it becomes true.
pub(super) struct ArchiveScanCtx<'a, E: ScanEngine> {
    pub(super) engine: &'a Arc<E>,
    pub(super) pool: &'a TsBufferPool,
    pub(super) event_sink: &'a dyn crate::events::EventOutput,
    pub(super) store_producer: Option<&'a dyn StoreProducer>,
    pub(super) scan_scratch: &'a mut E::Scratch,
    /// Reusable findings drain buffer (cleared before each `drain_findings_into`).
    pub(super) pending: &'a mut Vec<<E::Scratch as EngineScratch>::Finding>,
    /// Reusable persistence batch buffer.
    pub(super) persist_batch: &'a mut Vec<FsFindingRecord>,
    /// Shared budget tracker — enforces output caps and inflation-ratio gates.
    pub(super) budgets: &'a mut ArchiveBudgets,
    pub(super) canon: &'a mut EntryPathCanonicalizer,
    /// Per-depth virtual path builders. Head is consumed at this depth.
    pub(super) vpaths: &'a mut [VirtualPathBuilder],
    /// Per-depth byte counters for virtual path budget enforcement.
    pub(super) path_budget_used: &'a mut [usize],
    /// Per-depth tar header cursors. Head is consumed at this depth.
    pub(super) tar_cursors: &'a mut [TarCursor],
    pub(super) gzip_header_buf: &'a mut Vec<u8>,
    pub(super) gzip_name_buf: &'a mut Vec<u8>,
    pub(super) next_virtual_file_id: &'a mut u32,
    pub(super) metrics: &'a mut WorkerMetricsLocal,
    pub(super) archive: &'a ArchiveConfig,
    pub(super) chunk_size: usize,
    /// Shared abort flag; set by `FailRun` policy handlers.
    pub(super) abort_run: &'a AtomicBool,
}

impl<'a, E: ScanEngine> ArchiveScanCtx<'a, E> {
    /// Create a top-level archive scan context from per-worker scratch.
    ///
    /// Borrows all depth-indexed slices at full length; nested calls peel off
    /// the head element via `split_first_mut` before constructing child contexts.
    pub(super) fn new(
        scratch: &'a mut LocalScratch<E>,
        metrics: &'a mut WorkerMetricsLocal,
    ) -> Self {
        Self {
            engine: &scratch.engine,
            pool: &scratch.pool,
            event_sink: &*scratch.event_sink,
            store_producer: scratch.store_producer.as_deref(),
            scan_scratch: &mut scratch.scan_scratch,
            pending: &mut scratch.pending,
            persist_batch: &mut scratch.persist_batch,
            budgets: &mut scratch.budgets,
            canon: &mut scratch.canon,
            vpaths: scratch.vpaths.as_mut_slice(),
            path_budget_used: scratch.path_budget_used.as_mut_slice(),
            tar_cursors: scratch.tar_cursors.as_mut_slice(),
            gzip_header_buf: &mut scratch.gzip_header_buf,
            gzip_name_buf: &mut scratch.gzip_name_buf,
            next_virtual_file_id: &mut scratch.next_virtual_file_id,
            metrics,
            archive: &scratch.archive,
            chunk_size: scratch.chunk_size,
            abort_run: scratch.abort_run.as_ref(),
        }
    }

    /// Scan a buffer chunk, drain/dedupe findings, emit events + persistence,
    /// and update chunk metrics.
    ///
    /// Shared core used by all compressed-stream archive entry scanning loops.
    /// The caller is responsible for reading bytes from the decompressor,
    /// charging budgets, and managing the outer loop condition — this method
    /// handles everything from `scan_chunk_into` through finding emission
    /// and carry/offset bookkeeping.
    ///
    /// # Arguments
    ///
    /// - `buf`: raw chunk buffer; `buf[..carry]` is overlap from the prior
    ///   iteration, `buf[carry..carry+allowed]` is fresh decompressed payload.
    /// - `carry`: overlap prefix byte count from the previous chunk.
    /// - `offset`: absolute decompressed-stream offset of the first *new* byte.
    /// - `allowed`: number of budget-approved payload bytes to scan.
    /// - `overlap`: engine's `required_overlap()`, used to compute next carry.
    /// - `file_id`: virtual file ID for this archive entry.
    /// - `display`: display path bytes for finding attribution.
    /// - `entry_scanned`: set to `true` on first successful scan; prevents
    ///   double-counting entries in metrics.
    ///
    /// # Returns
    ///
    /// [`ChunkScanResult`] containing the updated offset, valid-byte count,
    /// and overlap carry for the next loop iteration.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn scan_and_emit_chunk(
        &mut self,
        buf: &[u8],
        carry: usize,
        offset: u64,
        allowed: u64,
        overlap: usize,
        file_id: FileId,
        display: &[u8],
        entry_scanned: &mut bool,
    ) -> ChunkScanResult {
        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;
        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf[..read_len];

        scan_chunk_postprocess(
            self.engine.as_ref(),
            self.scan_scratch,
            self.pending,
            file_id,
            base_offset,
            carry,
            data,
            self.metrics,
        );

        if !*entry_scanned {
            self.metrics.archive.record_entry_scanned();
            *entry_scanned = true;
        }

        emit_persistence_batch(
            self.store_producer,
            self.event_sink,
            display,
            self.pending,
            self.persist_batch,
            self.metrics,
        );
        emit_findings(self.engine.as_ref(), self.event_sink, display, self.pending);

        ChunkScanResult {
            offset: offset.saturating_add(allowed),
            have: read_len,
            carry: overlap.min(read_len),
        }
    }
}

/// Loop-iteration state returned by [`ArchiveScanCtx::scan_and_emit_chunk`].
pub(super) struct ChunkScanResult {
    /// Byte offset for the next iteration.
    pub offset: u64,
    /// Number of valid bytes currently in the buffer.
    pub have: usize,
    /// Carry-forward overlap for the next read.
    pub carry: usize,
}

/// Charge decompressed bytes that were read but not scanned (entry truncation).
///
/// Discarded bytes still count against archive/root output budgets and, when
/// an entry is open, against the per-entry inflation ratio because the
/// decompressor already produced them. Per-entry output-byte caps are
/// intentionally bypassed for this discarded path.
///
/// Returns `Err` with the triggering [`PartialReason`] if charging the discard
/// pushes a budget over its limit.
#[inline(always)]
pub(super) fn charge_discarded_bytes(
    budgets: &mut ArchiveBudgets,
    bytes: u64,
) -> Result<(), PartialReason> {
    if bytes == 0 {
        return Ok(());
    }
    match budgets.charge_discarded_out(bytes) {
        ChargeResult::Ok => Ok(()),
        ChargeResult::Clamp { hit, .. } => Err(budget_hit_to_partial_reason(hit)),
    }
}

/// Apply decompressed-output budgeting for a read of `n` bytes.
///
/// Called after each decompressor read to enforce per-entry, per-archive, and
/// root-level output caps plus inflation-ratio limits. The function may reduce
/// the number of scannable bytes and signal that the caller must stop the loop.
///
/// # Returns
///
/// `(allowed, clamped)` where:
/// - `allowed` is the prefix length (in bytes) the caller may scan/emit.
///   May be less than `n` when a budget caps the output.
/// - `clamped` is `true` when the caller must break out of the scan loop
///   after processing this iteration (budget fully exhausted or entry skipped).
///
/// # Side effects
///
/// - Updates `entry_partial_reason` with the first budget-violation reason.
/// - Sets `*outcome` to `Partial` and `*stop_archive` to `true` when the
///   violation is archive-level (not just entry-level).
/// - Charges excess bytes (`n - allowed`) as discarded output to keep budget
///   counters consistent with the actual decompressor output.
#[inline(always)]
pub(super) fn apply_entry_budget_clamp(
    budgets: &mut ArchiveBudgets,
    n: usize,
    entry_partial_reason: &mut Option<PartialReason>,
    outcome: &mut ArchiveEnd,
    stop_archive: &mut bool,
) -> (u64, bool) {
    let mut allowed = n as u64;
    if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
        let r = budget_hit_to_partial_reason(hit);
        allowed = a;
        *entry_partial_reason = Some(r);
        if !matches!(hit, BudgetHit::SkipEntry(_)) {
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
    }

    if allowed == 0 {
        if let Err(r) = charge_discarded_bytes(budgets, n as u64) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (0, true);
    }

    if allowed < n as u64 {
        let extra = (n as u64).saturating_sub(allowed);
        if let Err(r) = charge_discarded_bytes(budgets, extra) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (allowed, true);
    }

    (allowed, false)
}

/// Drain remaining tar entry payload bytes to realign the stream.
///
/// After a nested archive scan or a budget clamp, the tar entry may have
/// unread payload bytes. These must be consumed so the tar cursor stays
/// aligned to the next entry header. Discarded bytes are charged against
/// the decompressed-output budgets via [`charge_discarded_bytes`].
///
/// Returns `Err(MalformedTar)` on EOF or I/O error mid-drain.
pub(super) fn discard_remaining_payload(
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

/// Scan a compressed stream (gzip or bzip2) as a single virtual entry.
///
/// Unified inner loop for nested compressed streams within tar archives.
/// Both gzip and bzip2 formats use the same sliding-window + budget protocol;
/// the only difference is the decompressor, abstracted via [`CompressedStream`].
///
/// The loop reads decompressed bytes, charges them against budgets, scans via
/// [`ArchiveScanCtx::scan_and_emit_chunk`], and carries overlap forward.
/// It terminates on any of: EOF, decode error, budget exhaustion, or deadline.
///
/// # Arguments
///
/// - `stream`: decompressor implementing [`CompressedStream`].
/// - `display`: display path bytes for finding attribution.
/// - `corruption_reason`: the `PartialReason` to report if the decompressor
///   returns an error (e.g., `MalformedGzip`, `MalformedBzip2`).
///
/// # Invariants
///
/// - All offsets are in the decompressed byte space.
/// - Budget clamps stop scanning deterministically; no silent data loss.
/// - Compressed input bytes are tracked via `take_compressed_delta` so
///   inflation-ratio enforcement uses real I/O counts, not estimates.
pub(super) fn scan_compressed_stream_nested<E: ScanEngine, C: CompressedStream>(
    scan: &mut ArchiveScanCtx<'_, E>,
    stream: &mut C,
    display: &[u8],
    corruption_reason: PartialReason,
) -> ArchiveEnd {
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let overlap = scan.engine.required_overlap();
    let file_id = alloc_virtual_file_id(scan.next_virtual_file_id);

    if let Err(hit) = scan.budgets.begin_entry() {
        return budget_hit_to_archive_end(hit);
    }

    let mut buf = scan.pool.acquire();

    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;
    let mut entry_skip_reason: Option<EntrySkipReason> = None;

    loop {
        if scan.budgets.is_deadline_expired() {
            outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
            entry_partial_reason = Some(PartialReason::WallClockTimeout);
            break;
        }

        if carry > 0 && have > 0 {
            buf.as_mut_slice().copy_within(have - carry..have, 0);
        }

        let allowance = scan
            .budgets
            .remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = scan.budgets.charge_decompressed_out(1) {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = scan.budgets.charge_decompressed_out(1) {
                if let BudgetHit::SkipEntry(reason) = hit {
                    entry_skip_reason = Some(reason);
                }
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

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

        scan.budgets
            .charge_compressed_in(stream.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } =
            scan.budgets.charge_decompressed_out(allowed)
        {
            if let BudgetHit::SkipEntry(reason) = hit {
                entry_skip_reason = Some(reason);
            }
            let r = budget_hit_to_partial_reason(hit);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let result = scan.scan_and_emit_chunk(
            buf.as_slice(),
            carry,
            offset,
            allowed,
            overlap,
            file_id,
            display,
            &mut entry_scanned,
        );
        offset = result.offset;
        have = result.have;
        carry = result.carry;

        if (allowed as usize) < n {
            break;
        }
    }

    scan.budgets.end_entry(offset > 0);
    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(corruption_reason);
        entry_partial_reason = Some(corruption_reason);
    }
    if let Some(reason) = entry_skip_reason {
        scan.metrics
            .archive
            .record_entry_skipped(reason, display, false);
    }
    if let Some(r) = entry_partial_reason {
        scan.metrics.archive.record_entry_partial(r, display, false);
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_virtual_file_id_sequential_and_wrapping() {
        let mut next = 0x8000_0000u32;

        let id0 = alloc_virtual_file_id(&mut next);
        assert_eq!(id0.0, 0x8000_0000);
        assert_eq!(next, 0x8000_0001);

        let id1 = alloc_virtual_file_id(&mut next);
        assert_eq!(id1.0, 0x8000_0001);
        assert_eq!(next, 0x8000_0002);
    }

    #[test]
    fn alloc_virtual_file_id_wraps_at_boundary() {
        // Just before the mask wraps.
        let mut next = 0xFFFF_FFFFu32;

        let id = alloc_virtual_file_id(&mut next);
        assert_eq!(id.0, 0xFFFF_FFFF);
        // After wrapping: (0xFFFF_FFFF + 1) & 0x7FFF_FFFF | 0x8000_0000
        assert_eq!(next, 0x8000_0000);
    }

    #[test]
    fn build_locator_format() {
        let mut buf = [0u8; LOCATOR_LEN];
        let loc = build_locator(&mut buf, b't', 0x0000_0000_0000_1234);

        assert_eq!(loc[0], b'@');
        assert_eq!(loc[1], b't');
        assert_eq!(&loc[2..], b"0000000000001234");
    }

    #[test]
    fn build_locator_zero_value() {
        let mut buf = [0u8; LOCATOR_LEN];
        let loc = build_locator(&mut buf, b'z', 0);
        assert_eq!(&loc[2..], b"0000000000000000");
    }
}
