//! TAR archive scanning (plain `.tar`, `.tar.gz`/`.tgz`, and `.tar.bz2`/`.tbz2`).
//!
//! Handles both top-level tar files and nested tar streams within other
//! archives. Supports recursive expansion into nested gzip, bzip2, and tar
//! archives up to the configured depth limit.

use std::fs::File;
use std::sync::atomic::Ordering;

use crate::archive::formats::zip::LimitedRead;
use crate::archive::formats::{Bzip2Stream, GzipStream, TarInput, TarNext, TarRead};
use crate::archive::{
    detect_kind_from_name_bytes, ArchiveKind, ArchiveSkipReason, BudgetHit, ChargeResult,
    EntrySkipReason, PartialReason, DEFAULT_MAX_COMPONENTS,
};

use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::WorkerCtx;
use super::local_fs_archive_ctx::{
    alloc_virtual_file_id, apply_entry_budget_clamp, budget_hit_to_archive_end,
    budget_hit_to_partial_reason, build_locator, discard_remaining_payload,
    map_archive_skip_to_partial, scan_compressed_stream_nested, ArchiveEnd, ArchiveScanCtx,
    ARCHIVE_STREAM_READ_MAX, LOCATOR_LEN,
};
use super::local_fs_owner::{emit_persistence_batch, FileTask, LocalScratch};
use super::scan_helpers::{
    account_effective_dropped_findings, apply_cross_rule_dedupe, emit_findings,
};

/// Build a child [`ArchiveScanCtx`] from the parent's individually-reborrowed
/// fields plus the caller's per-depth slices. This avoids repeating the
/// 16-field struct literal for every nesting branch.
///
/// A method on `ArchiveScanCtx` cannot be used because `budgets` is
/// reborrowed separately (`let budgets = &mut *scan.budgets;`) before
/// the match, so `&mut self` would conflict. A macro expands in-place
/// with disjoint field borrows, which the borrow checker accepts.
macro_rules! child_archive_ctx {
    ($scan:expr, $budgets:expr, $vpaths:expr, $path_budget_used:expr, $tar_cursors:expr) => {
        ArchiveScanCtx {
            engine: $scan.engine,
            pool: $scan.pool,
            event_sink: $scan.event_sink,
            store_producer: $scan.store_producer,
            scan_scratch: $scan.scan_scratch,
            pending: $scan.pending,
            persist_batch: $scan.persist_batch,
            budgets: $budgets,
            canon: $scan.canon,
            vpaths: $vpaths,
            path_budget_used: $path_budget_used,
            tar_cursors: $tar_cursors,
            gzip_header_buf: $scan.gzip_header_buf,
            gzip_name_buf: $scan.gzip_name_buf,
            next_virtual_file_id: $scan.next_virtual_file_id,
            metrics: $scan.metrics,
            archive: $scan.archive,
            chunk_size: $scan.chunk_size,
            abort_run: $scan.abort_run,
        }
    };
}

/// Scan a tar stream (plain, gzip-wrapped, or bzip2-wrapped), optionally
/// recursing into nested archives.
///
/// # Invariants
/// - Entry payloads are scanned with chunk+overlap semantics.
/// - Non-regular entries are skipped explicitly.
/// - Malformed headers or payload reads yield `PartialReason::MalformedTar`.
/// - Caller has already entered the archive budget for this container.
/// - `depth` is 1-based; nested expansion stops at `max_archive_depth`.
/// - `ratio_active` should be `true` only when the tar byte stream is itself
///   compressed (`tar.gz` / `tar.bz2`) so pre-read ratio probes reflect reality.
pub(super) fn scan_tar_stream_nested<E: ScanEngine>(
    scan: &mut ArchiveScanCtx<'_, E>,
    input: &mut dyn TarRead,
    container_display: &[u8],
    depth: u8,
    ratio_active: bool,
) -> ArchiveEnd {
    let budgets = &mut *scan.budgets;
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let overlap = scan.engine.required_overlap();
    let max_len = scan.archive.max_virtual_path_len_per_entry;
    let max_depth = scan.archive.max_archive_depth;

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

    let mut buf = scan.pool.acquire();
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
                    scan.metrics.archive.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    scan.metrics.archive.record_component_cap_exceeded();
                }
                if c.truncated {
                    scan.metrics.archive.record_path_truncated();
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

        let is_regular = entry_typeflag == 0 || entry_typeflag == b'0';
        if !is_regular {
            scan.metrics.archive.record_entry_skipped(
                EntrySkipReason::NonRegular,
                entry_display,
                false,
            );
            match cur_cursor.skip_payload_and_pad(input, budgets, entry_size, entry_pad) {
                Ok(Ok(())) => continue,
                _ => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            }
        }

        budgets.begin_entry_scan();
        let mut stop_archive = false;

        if let Some(kind) = nested_kind {
            match kind {
                ArchiveKind::Zip => {
                    scan.metrics.archive.record_archive_skipped(
                        ArchiveSkipReason::NeedsRandomAccessNoSpill,
                        entry_display,
                        false,
                    );
                    match scan.archive.unsupported_policy {
                        crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                            // Fall back to scanning raw bytes.
                        }
                        crate::archive::UnsupportedPolicy::FailArchive => {
                            scan.metrics.archive.record_entry_skipped(
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
                            scan.abort_run.store(true, Ordering::Relaxed);
                            scan.metrics.archive.record_entry_skipped(
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
                        scan.metrics.archive.record_archive_skipped(
                            ArchiveSkipReason::DepthExceeded,
                            entry_display,
                            false,
                        );
                    } else if let Err(hit) = budgets.enter_archive() {
                        let r = budget_hit_to_archive_end(hit);
                        match r {
                            ArchiveEnd::Skipped(reason) => scan
                                .metrics
                                .archive
                                .record_archive_skipped(reason, entry_display, false),
                            ArchiveEnd::Partial(reason) => scan
                                .metrics
                                .archive
                                .record_archive_partial(reason, entry_display, false),
                            _ => {}
                        }
                    } else {
                        scan.metrics.archive.record_archive_seen();
                        scan.metrics.archive.record_entry_scanned();

                        let nested_outcome = match kind {
                            ArchiveKind::Gzip => {
                                let (gunzip_vpath, vpaths_tail) = rest_vpaths
                                    .split_first_mut()
                                    .expect("vpath scratch exhausted");
                                let (gunzip_path_used, path_used_tail) = rest_path_used
                                    .split_first_mut()
                                    .expect("path budget scratch exhausted");
                                let mut child = child_archive_ctx!(
                                    scan,
                                    budgets,
                                    vpaths_tail,
                                    path_used_tail,
                                    rest_cursors
                                );

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
                                        child.metrics.archive.record_path_had_traversal();
                                    }
                                    if c.component_cap_exceeded {
                                        child.metrics.archive.record_component_cap_exceeded();
                                    }
                                    if c.truncated {
                                        child.metrics.archive.record_path_truncated();
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

                                let out = scan_compressed_stream_nested(
                                    &mut child,
                                    &mut gz,
                                    gunzip_display,
                                    PartialReason::CompressedStreamCorrupt,
                                );
                                let (entry_reader, hdr_buf) = gz.into_inner().into_parts();
                                *child.gzip_header_buf = hdr_buf;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Bzip2 => {
                                let (bunzip_vpath, vpaths_tail) = rest_vpaths
                                    .split_first_mut()
                                    .expect("vpath scratch exhausted");
                                let (bunzip_path_used, path_used_tail) = rest_path_used
                                    .split_first_mut()
                                    .expect("path budget scratch exhausted");
                                let mut child = child_archive_ctx!(
                                    scan,
                                    budgets,
                                    vpaths_tail,
                                    path_used_tail,
                                    rest_cursors
                                );

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
                                let out = scan_compressed_stream_nested(
                                    &mut child,
                                    &mut bz2,
                                    bunzip_display,
                                    PartialReason::CompressedStreamCorrupt,
                                );
                                let entry_reader = bz2.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Tar => {
                                let mut child = child_archive_ctx!(
                                    scan,
                                    budgets,
                                    rest_vpaths,
                                    rest_path_used,
                                    rest_cursors
                                );
                                let mut entry_reader = LimitedRead::new(input, entry_size);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut entry_reader,
                                    entry_display,
                                    depth + 1,
                                    ratio_active,
                                );
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::TarGz => {
                                let mut child = child_archive_ctx!(
                                    scan,
                                    budgets,
                                    rest_vpaths,
                                    rest_path_used,
                                    rest_cursors
                                );
                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut gz = GzipStream::new(entry_reader);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut gz,
                                    entry_display,
                                    depth + 1,
                                    true,
                                );
                                let entry_reader = gz.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::TarBz2 => {
                                let mut child = child_archive_ctx!(
                                    scan,
                                    budgets,
                                    rest_vpaths,
                                    rest_path_used,
                                    rest_cursors
                                );
                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut bz2 = Bzip2Stream::new(entry_reader);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut bz2,
                                    entry_display,
                                    depth + 1,
                                    true,
                                );
                                let entry_reader = bz2.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Zip => unreachable!(),
                        };

                        budgets.exit_archive();

                        let mut entry_partial_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
                            ArchiveEnd::Scanned => None,
                        };

                        match nested_outcome.0 {
                            ArchiveEnd::Scanned => scan.metrics.archive.record_archive_scanned(),
                            ArchiveEnd::Skipped(r) => {
                                scan.metrics
                                    .archive
                                    .record_archive_skipped(r, entry_display, false)
                            }
                            ArchiveEnd::Partial(r) => {
                                scan.metrics.archive.record_archive_partial(
                                    r,
                                    entry_display,
                                    false,
                                );
                            }
                        }

                        let stop_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
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

                        if !stop_archive && nested_outcome.1 > 0 {
                            if entry_partial_reason.is_none() {
                                entry_partial_reason = Some(PartialReason::MalformedTar);
                            }
                            if let Err(r) = discard_remaining_payload(
                                input,
                                budgets,
                                buf.as_mut_slice(),
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
                            scan.metrics
                                .archive
                                .record_entry_partial(r, entry_display, false);
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

        let entry_file_id = alloc_virtual_file_id(scan.next_virtual_file_id);
        let mut remaining = entry_size;
        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;
        let mut stop_archive = false;

        while remaining > 0 {
            if budgets.is_deadline_expired() {
                outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
                entry_partial_reason = Some(PartialReason::WallClockTimeout);
                stop_archive = true;
                break;
            }

            if carry > 0 && have > 0 {
                buf.as_mut_slice().copy_within(have - carry..have, 0);
            }

            let allow = budgets.remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allow == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let read_max = chunk_size
                .min(buf.as_mut_slice().len().saturating_sub(carry))
                .min(allow.min(remaining).min(u64::from(u32::MAX)) as usize);
            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let dst = &mut buf.as_mut_slice()[carry..carry + read_max];
            let n = match input.read(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    entry_partial_reason = Some(PartialReason::MalformedTar);
                    stop_archive = true;
                    break;
                }
            };
            budgets.charge_compressed_in(input.take_compressed_delta());
            if n == 0 {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                entry_partial_reason = Some(PartialReason::MalformedTar);
                stop_archive = true;
                break;
            }
            remaining = remaining.saturating_sub(n as u64);

            let (allowed, clamped) = apply_entry_budget_clamp(
                budgets,
                n,
                &mut entry_partial_reason,
                &mut outcome,
                &mut stop_archive,
            );
            if allowed == 0 {
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;
            let base_offset = offset.saturating_sub(carry as u64);
            let data = &buf.as_slice()[..read_len];

            scan.engine
                .scan_chunk_into(data, entry_file_id, base_offset, scan.scan_scratch);
            let engine_dropped = scan.scan_scratch.dropped_findings();
            let before_prefix = scan.scan_scratch.pending_findings_len();
            if !entry_scanned {
                scan.metrics.archive.record_entry_scanned();
                entry_scanned = true;
            }

            let new_bytes_start = offset;
            scan.scan_scratch.drop_prefix_findings(new_bytes_start);
            let after_prefix = scan.scan_scratch.pending_findings_len();

            scan.pending.clear();
            scan.scan_scratch.drain_findings_into(scan.pending);

            let dedupe_removed = apply_cross_rule_dedupe(scan.pending, scan.engine.as_ref());
            let scheduler_pruned = before_prefix
                .saturating_sub(after_prefix)
                .saturating_add(dedupe_removed);
            account_effective_dropped_findings(scan.metrics, engine_dropped, scheduler_pruned);

            scan.metrics.findings_emitted = scan
                .metrics
                .findings_emitted
                .wrapping_add(scan.pending.len() as u64);
            emit_persistence_batch(
                scan.store_producer,
                scan.event_sink,
                entry_display,
                scan.pending,
                scan.persist_batch,
                scan.metrics,
            );
            emit_findings(
                scan.engine.as_ref(),
                scan.event_sink,
                entry_display,
                scan.pending,
            );

            scan.metrics.chunks_scanned = scan.metrics.chunks_scanned.saturating_add(1);
            scan.metrics.bytes_scanned = scan.metrics.bytes_scanned.saturating_add(allowed);

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = overlap.min(read_len);

            if clamped {
                break;
            }
        }

        if !stop_archive && remaining > 0 {
            if let Err(r) = discard_remaining_payload(input, budgets, buf.as_mut_slice(), remaining)
            {
                if entry_partial_reason.is_none() {
                    entry_partial_reason = Some(r);
                }
                outcome = ArchiveEnd::Partial(r);
                stop_archive = true;
            }
        }

        budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            scan.metrics
                .archive
                .record_entry_partial(r, entry_display, false);
        }

        if stop_archive {
            break;
        }

        match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
            Ok(Ok(())) => {}
            Ok(Err(r)) => {
                outcome = ArchiveEnd::Partial(r);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                break;
            }
        }
        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
    }

    outcome
}

/// Shared entry point for `.tar`, `.tar.gz`, and `.tar.bz2` root files.
///
/// Wires up the [`ArchiveScanCtx`] from [`LocalScratch`], resets budgets,
/// enters the archive scope, then delegates to [`scan_tar_stream_nested`]
/// at depth 1. This avoids duplicating budget setup between compressed tar
/// variants.
///
/// The caller (`process_tar_file` / `process_targz_file` /
/// `process_tarbz2_file`) is responsible for opening the file and wrapping it
/// in the appropriate [`TarInput`] variant.
fn process_tar_like<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    mut input: TarInput,
) -> ArchiveEnd {
    let parent_bytes = task.path.as_os_str().as_encoded_bytes();

    let (scratch, metrics) = {
        let WorkerCtx {
            scratch, metrics, ..
        } = ctx;
        (scratch, metrics)
    };

    let mut scan = ArchiveScanCtx::new(scratch, metrics);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        return budget_hit_to_archive_end(hit);
    }

    let ratio_active = matches!(input, TarInput::Gzip(_) | TarInput::Bzip2(_));
    let outcome = scan_tar_stream_nested(&mut scan, &mut input, parent_bytes, 1, ratio_active);

    scan.budgets.exit_archive();
    outcome
}

/// Process a plain `.tar` file.
pub(super) fn process_tar_file<E: ScanEngine>(
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
    process_tar_like::<E>(task, ctx, TarInput::Plain(file))
}

/// Process a `.tar.gz` file via gzip+tar streaming.
pub(super) fn process_targz_file<E: ScanEngine>(
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
    process_tar_like::<E>(task, ctx, TarInput::Gzip(GzipStream::new(file)))
}

/// Process a `.tar.bz2` / `.tbz2` file via bzip2+tar streaming.
pub(super) fn process_tarbz2_file<E: ScanEngine>(
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
    let reader = std::io::BufReader::with_capacity(64 * 1024, file);
    process_tar_like::<E>(task, ctx, TarInput::Bzip2(Bzip2Stream::new(reader)))
}
