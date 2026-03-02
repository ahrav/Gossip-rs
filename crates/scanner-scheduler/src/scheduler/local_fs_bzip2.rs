//! Bzip2 stream scanning in the local-filesystem scheduler.
//!
//! Handles `.bz2` files as single-entry virtual archives.

use std::fs::File;

use crate::archive::formats::Bzip2Stream;
use crate::archive::{ArchiveSkipReason, PartialReason};

use super::engine_trait::ScanEngine;
use super::executor::WorkerCtx;
use super::local_fs_archive_ctx::{
    budget_hit_to_archive_end, scan_compressed_stream_nested, ArchiveEnd, ArchiveScanCtx,
};
use super::local_fs_owner::{FileTask, LocalScratch};

/// Scan a `.bz2` file as a single virtual entry (`<bunzip2>`).
///
/// Delegates the inner read/scan loop to [`scan_compressed_stream_nested`]
/// after wiring up the archive lifecycle (`reset` → `enter_archive` →
/// `exit_archive`).
///
/// # Invariants
/// - Offsets are decompressed byte offsets.
/// - Decode failures map to `PartialReason::CompressedStreamCorrupt`.
pub(super) fn process_bzip2_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
) -> ArchiveEnd {
    let file = match File::open(&task.path) {
        Ok(f) => f,
        Err(_) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    let parent_bytes = task.path.as_os_str().as_encoded_bytes();
    let scratch = &mut ctx.scratch;
    let metrics = &mut ctx.metrics;
    let max_len = scratch.archive.max_virtual_path_len_per_entry;

    // Split depth-1 vpath + budget for path construction. The scan context
    // receives the tail; scan_compressed_stream_nested does not use vpaths.
    debug_assert!(scratch.vpaths.len() > 1);
    debug_assert!(scratch.path_budget_used.len() > 1);
    let (head_vp, rest_vp) = scratch.vpaths.as_mut_slice().split_at_mut(2);
    let (head_pb, rest_pb) = scratch.path_budget_used.as_mut_slice().split_at_mut(2);

    head_pb[1] = 0;
    let path_bytes = head_vp[1].build(parent_bytes, b"<bunzip2>", max_len).bytes;
    let need = path_bytes.len();
    if head_pb[1].saturating_add(need) > scratch.archive.max_virtual_path_bytes_per_archive {
        return ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
    }
    head_pb[1] = head_pb[1].saturating_add(need);

    let mut bz2 = Bzip2Stream::new(file);

    let mut scan = ArchiveScanCtx {
        engine: &scratch.engine,
        pool: &scratch.pool,
        event_sink: &*scratch.event_sink,
        store_producer: scratch.store_producer.as_deref(),
        scan_scratch: &mut scratch.scan_scratch,
        pending: &mut scratch.pending,
        persist_batch: &mut scratch.persist_batch,
        budgets: &mut scratch.budgets,
        canon: &mut scratch.canon,
        vpaths: rest_vp,
        path_budget_used: rest_pb,
        tar_cursors: scratch.tar_cursors.as_mut_slice(),
        gzip_header_buf: &mut scratch.gzip_header_buf,
        gzip_name_buf: &mut scratch.gzip_name_buf,
        next_virtual_file_id: &mut scratch.next_virtual_file_id,
        metrics,
        archive: &scratch.archive,
        chunk_size: scratch.chunk_size,
        abort_run: scratch.abort_run.as_ref(),
    };

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        return budget_hit_to_archive_end(hit);
    }

    let outcome = scan_compressed_stream_nested(
        &mut scan,
        &mut bz2,
        path_bytes,
        PartialReason::CompressedStreamCorrupt,
    );

    scan.budgets.exit_archive();
    outcome
}
