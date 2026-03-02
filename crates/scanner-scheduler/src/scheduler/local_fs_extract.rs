//! Binary file extraction and scanning.
//!
//! Handles files classified as extractable binary formats (e.g., `.class`,
//! `.jar`) by reading the full file, extracting text content, and scanning
//! the extracted output through the engine.

use std::fs::File;

use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::WorkerCtx;
use super::local_fs_owner::{emit_persistence_batch, FileTask, LocalScratch};
use super::scan_helpers::{
    account_effective_dropped_findings, apply_cross_rule_dedupe, emit_findings,
};

/// Read a file with an extractable binary format, extract text, and scan it.
///
/// Reads the entire file (up to 64 MiB) into `extract_buf`, runs the
/// format-specific extractor, then scans the extracted text through the
/// engine as a single chunk.
///
/// # Prerequisites
///
/// - The file must already be open. This function rewinds to position 0
///   before reading (the caller's probe/header read may have advanced it).
///
/// # Failure modes
///
/// - I/O errors (seek, read) increment `ctx.metrics.io_errors` and return
///   without scanning.
/// - Extraction failure (`ParseError` or `Empty`) returns without scanning.
///   No error is recorded because the file was already classified as
///   extractable by extension; a parse failure simply means the content
///   didn't match (e.g. a `.class` file with corrupt magic).
pub(super) fn extract_and_scan_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    file: &mut File,
    file_size: u64,
    path_bytes: &[u8],
    fmt: crate::content_policy::ExtractableFormat,
) {
    use crate::content_policy::extract::{extract_content, ExtractResult};
    use std::io::{Read, Seek, SeekFrom};

    // Seek back to start — the first read may have advanced the position.
    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
        #[cfg(debug_assertions)]
        eprintln!(
            "[local] Failed to rewind for extraction {:?}: {}",
            task.path, e
        );
        let _ = e;
        return;
    }

    // Read the entire file into a temporary buffer.
    let read_limit = file_size.min(64 * 1024 * 1024) as usize; // 64 MiB cap
    let scratch = &mut ctx.scratch;
    scratch.extract_buf.clear();
    scratch.extract_buf.reserve(read_limit);
    if file
        .take(read_limit as u64)
        .read_to_end(&mut scratch.extract_buf)
        .is_err()
    {
        ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
        return;
    }

    // Extract scannable text (extract_content clears out before dispatch).
    let result = extract_content(
        fmt,
        &scratch.extract_buf,
        &mut scratch.extract_out_buf,
        &mut scratch.extract_scratch,
    );

    if result != ExtractResult::Ok || scratch.extract_out_buf.is_empty() {
        return;
    }

    ctx.metrics.binary_extracted = ctx.metrics.binary_extracted.wrapping_add(1);

    // Scan the extracted text as a single chunk.
    let engine = &scratch.engine;
    engine.scan_chunk_into(
        &scratch.extract_out_buf,
        task.file_id,
        0,
        &mut scratch.scan_scratch,
    );
    let engine_dropped = scratch.scan_scratch.dropped_findings();
    let before_prefix = scratch.scan_scratch.pending_findings_len();
    let after_prefix = before_prefix;

    scratch.pending.clear();
    scratch
        .scan_scratch
        .drain_findings_into(&mut scratch.pending);

    let dedupe_removed = apply_cross_rule_dedupe(&mut scratch.pending, engine.as_ref());
    let scheduler_pruned = before_prefix
        .saturating_sub(after_prefix)
        .saturating_add(dedupe_removed);
    account_effective_dropped_findings(&mut ctx.metrics, engine_dropped, scheduler_pruned);
    if !scratch.pending.is_empty() {
        emit_persistence_batch(
            scratch.store_producer.as_deref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
            &mut scratch.persist_batch,
            &mut ctx.metrics,
        );
        emit_findings(
            engine.as_ref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
        );
        let count = scratch.pending.len() as u64;
        ctx.metrics.findings_emitted = ctx.metrics.findings_emitted.saturating_add(count);
    }
    ctx.metrics.bytes_scanned = ctx
        .metrics
        .bytes_scanned
        .saturating_add(scratch.extract_out_buf.len() as u64);
    ctx.metrics.chunks_scanned = ctx.metrics.chunks_scanned.saturating_add(1);
}
