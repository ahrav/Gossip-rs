//! Gzip archive scanning.
//!
//! Handles `.gz` files as single-entry virtual archives.

use std::fs::File;

use crate::archive::formats::GzipStream;
use crate::archive::{ArchiveSkipReason, PartialReason, DEFAULT_MAX_COMPONENTS};

use super::engine_trait::ScanEngine;
use super::executor::WorkerCtx;
use super::local_fs_archive_ctx::{
    budget_hit_to_archive_end, scan_compressed_stream_nested, ArchiveEnd, ArchiveScanCtx,
};
use super::local_fs_owner::{FileTask, LocalScratch};

/// Scan a `.gz` file as a single virtual entry (`<gunzip>`).
///
/// Delegates the inner read/scan loop to [`scan_compressed_stream_nested`]
/// after parsing the gzip header and wiring up the archive lifecycle
/// (`reset` → `enter_archive` → `exit_archive`).
///
/// # Invariants
/// - Offsets are decompressed byte offsets.
/// - Concatenated gzip members are treated as one stream.
pub(super) fn process_gzip_file<E: ScanEngine>(
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

    // Parse gzip header to extract the optional original filename.
    let (mut gz, name_len) = match GzipStream::new_with_header(
        file,
        &mut scratch.gzip_header_buf,
        &mut scratch.gzip_name_buf,
        max_len,
    ) {
        Ok(v) => v,
        Err(_) => {
            metrics.io_errors = metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    // Canonicalize the entry name, recording path anomalies.
    let entry_name_bytes = if let Some(len) = name_len {
        let c = scratch.canon.canonicalize(
            &scratch.gzip_name_buf[..len],
            DEFAULT_MAX_COMPONENTS,
            max_len,
        );
        if c.had_traversal {
            metrics.archive.record_path_had_traversal();
        }
        if c.component_cap_exceeded {
            metrics.archive.record_component_cap_exceeded();
        }
        if c.truncated {
            metrics.archive.record_path_truncated();
        }
        c.bytes
    } else {
        b"<gunzip>"
    };

    // Split depth-1 vpath + budget for path construction. The scan context
    // receives the tail; scan_compressed_stream_nested does not use vpaths.
    debug_assert!(scratch.vpaths.len() > 1);
    debug_assert!(scratch.path_budget_used.len() > 1);
    let (head_vp, rest_vp) = scratch.vpaths.as_mut_slice().split_at_mut(2);
    let (head_pb, rest_pb) = scratch.path_budget_used.as_mut_slice().split_at_mut(2);

    head_pb[1] = 0;
    let path_bytes = head_vp[1]
        .build(parent_bytes, entry_name_bytes, max_len)
        .bytes;
    let need = path_bytes.len();
    if head_pb[1].saturating_add(need) > scratch.archive.max_virtual_path_bytes_per_archive {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
    }
    head_pb[1] = head_pb[1].saturating_add(need);

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
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        *scan.gzip_header_buf = hdr_buf;
        return budget_hit_to_archive_end(hit);
    }

    let outcome = scan_compressed_stream_nested(
        &mut scan,
        &mut gz,
        path_bytes,
        PartialReason::CompressedStreamCorrupt,
    );

    scan.budgets.exit_archive();

    // Recover the gzip header buffer for reuse.
    let (_inner, hdr_buf) = gz.into_inner().into_parts();
    *scan.gzip_header_buf = hdr_buf;

    outcome
}
