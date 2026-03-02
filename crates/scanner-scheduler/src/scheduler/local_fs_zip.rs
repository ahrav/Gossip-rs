//! ZIP archive scanning.
//!
//! Handles `.zip` files using file-backed random access via [`ZipCursor`].

use std::fs::File;
use std::sync::atomic::Ordering;

use crate::archive::formats::{ZipEntryMeta, ZipNext, ZipOpen};
use crate::archive::path::apply_hash_suffix_truncation;
use crate::archive::{ArchiveSkipReason, ChargeResult, PartialReason, DEFAULT_MAX_COMPONENTS};

use super::engine_trait::{EngineScratch, ScanEngine};
use super::executor::WorkerCtx;
use super::local_fs_archive_ctx::{
    alloc_virtual_file_id, budget_hit_to_archive_end, budget_hit_to_partial_reason, build_locator,
    charge_discarded_bytes, ArchiveEnd, ARCHIVE_STREAM_READ_MAX, LOCATOR_LEN,
};
use super::local_fs_owner::{emit_persistence_batch, FileTask, LocalScratch};
use super::scan_helpers::{
    account_effective_dropped_findings, apply_cross_rule_dedupe, emit_findings,
};

/// Scan a ZIP file using file-backed random access.
///
/// # Design Notes
/// - Central directory parsing is bounded by metadata budgets.
/// - Only stored/deflated entries are scanned; others are skipped explicitly.
pub(super) fn process_zip_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
) -> ArchiveEnd {
    let (scratch, metrics) = {
        let WorkerCtx {
            scratch, metrics, ..
        } = ctx;
        (scratch, metrics)
    };
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let LocalScratch {
        engine,
        pool,
        event_sink,
        store_producer,
        scan_scratch,
        pending,
        persist_batch,
        archive,
        canon,
        vpaths,
        path_budget_used,
        budgets,
        zip_cursor,
        entry_display_buf,
        next_virtual_file_id,
        abort_run,
        ..
    } = scratch;
    let overlap = engine.required_overlap();

    let file = match File::open(&task.path) {
        Ok(f) => f,
        Err(_) => {
            metrics.io_errors = metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    budgets.reset();
    if let Err(hit) = budgets.enter_archive() {
        return budget_hit_to_archive_end(hit);
    }

    let cursor = zip_cursor;
    let open = match cursor.open(file, budgets, archive) {
        Ok(open) => open,
        Err(_) => {
            budgets.exit_archive();
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    match open {
        ZipOpen::Ready => {}
        ZipOpen::Skip(r) => {
            budgets.exit_archive();
            if r == ArchiveSkipReason::UnsupportedFeature {
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry
                    | crate::archive::UnsupportedPolicy::FailArchive => {
                        return ArchiveEnd::Skipped(r);
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        abort_run.store(true, Ordering::Relaxed);
                        return ArchiveEnd::Skipped(r);
                    }
                }
            }
            return ArchiveEnd::Skipped(r);
        }
        ZipOpen::Stop(r) => {
            budgets.exit_archive();
            return ArchiveEnd::Partial(r);
        }
    }

    let parent_bytes = task.path.as_os_str().as_encoded_bytes();
    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(path_budget_used.len() > 1);
    path_budget_used[1] = 0;

    let mut buf = pool.acquire();
    let mut outcome = ArchiveEnd::Scanned;

    loop {
        if budgets.is_deadline_expired() {
            outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
            break;
        }

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
            let meta = match cursor.next_entry(budgets, archive) {
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
                let c = canon.canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    metrics.archive.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    metrics.archive.record_component_cap_exceeded();
                }
                let entry_bytes = if meta.name_truncated {
                    metrics.archive.record_path_truncated();
                    entry_display_buf.clear();
                    entry_display_buf.extend_from_slice(c.bytes);
                    apply_hash_suffix_truncation(entry_display_buf, meta.name_hash64, max_len);
                    entry_display_buf.as_slice()
                } else {
                    if c.truncated {
                        metrics.archive.record_path_truncated();
                    }
                    c.bytes
                };
                vpaths[1]
                    .build_with_suffix(parent_bytes, entry_bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if path_budget_used[1].saturating_add(need) > archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            path_budget_used[1] = path_budget_used[1].saturating_add(need);

            if meta.is_dir {
                metrics.archive.record_entry_skipped(
                    crate::archive::EntrySkipReason::NonRegular,
                    entry_display,
                    false,
                );
                continue;
            }

            if meta.is_encrypted() {
                metrics.archive.record_entry_skipped(
                    crate::archive::EntrySkipReason::EncryptedEntry,
                    entry_display,
                    false,
                );
                match archive.encrypted_policy {
                    crate::archive::EncryptedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::EncryptedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                    crate::archive::EncryptedPolicy::FailRun => {
                        abort_run.store(true, Ordering::Relaxed);
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                }
            }
            if !meta.compression_supported() {
                metrics.archive.record_entry_skipped(
                    crate::archive::EntrySkipReason::UnsupportedCompression,
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
                        abort_run.store(true, Ordering::Relaxed);
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

        budgets.begin_entry_scan();

        let mut reader = match cursor.open_entry_reader(&meta, budgets) {
            Ok(Ok(r)) => r,
            Ok(Err(r)) => {
                if r == PartialReason::MalformedZip {
                    metrics.archive.record_entry_skipped(
                        crate::archive::EntrySkipReason::CorruptEntry,
                        entry_display,
                        false,
                    );
                    budgets.end_entry(false);
                    continue;
                }
                outcome = ArchiveEnd::Partial(r);
                budgets.end_entry(false);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
                budgets.end_entry(false);
                break;
            }
        };

        let path_bytes = entry_display;
        let entry_file_id = alloc_virtual_file_id(next_virtual_file_id);

        let mut last_comp = 0u64;
        let ratio_active = meta.method == 8;

        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;
        let mut stop_archive = false;

        loop {
            if budgets.is_deadline_expired() {
                outcome = ArchiveEnd::Partial(PartialReason::WallClockTimeout);
                entry_partial_reason = Some(PartialReason::WallClockTimeout);
                stop_archive = true;
                break;
            }

            if carry > 0 && have > 0 {
                buf.as_mut_slice().copy_within(have - carry..have, 0);
            }

            let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allowance == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, crate::archive::BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let read_max = chunk_size
                .min(buf.len().saturating_sub(carry))
                .min(allowance.min(u64::from(u32::MAX)) as usize);

            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, crate::archive::BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

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
                budgets.charge_compressed_in(delta);
            }

            if n == 0 {
                break;
            }

            let mut allowed = n as u64;
            if let ChargeResult::Clamp { allowed: a, hit } =
                budgets.charge_decompressed_out(allowed)
            {
                let r = budget_hit_to_partial_reason(hit);
                allowed = a;
                entry_partial_reason = Some(r);
                if !matches!(hit, crate::archive::BudgetHit::SkipEntry(_)) {
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
            }
            if allowed == 0 {
                if let Err(r) = charge_discarded_bytes(budgets, n as u64) {
                    if entry_partial_reason.is_none() {
                        entry_partial_reason = Some(r);
                    }
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;

            let base_offset = offset.saturating_sub(carry as u64);
            let data = &buf.as_slice()[..read_len];

            engine.scan_chunk_into(data, entry_file_id, base_offset, scan_scratch);
            let engine_dropped = scan_scratch.dropped_findings();
            let before_prefix = scan_scratch.pending_findings_len();
            if !entry_scanned {
                metrics.archive.record_entry_scanned();
                entry_scanned = true;
            }

            let new_bytes_start = offset;
            scan_scratch.drop_prefix_findings(new_bytes_start);
            let after_prefix = scan_scratch.pending_findings_len();

            pending.clear();
            scan_scratch.drain_findings_into(pending);

            let dedupe_removed = apply_cross_rule_dedupe(pending, engine.as_ref());
            let scheduler_pruned = before_prefix
                .saturating_sub(after_prefix)
                .saturating_add(dedupe_removed);
            account_effective_dropped_findings(metrics, engine_dropped, scheduler_pruned);

            metrics.findings_emitted = metrics.findings_emitted.wrapping_add(pending.len() as u64);
            emit_persistence_batch(
                store_producer.as_deref(),
                &**event_sink,
                path_bytes,
                pending,
                persist_batch,
                metrics,
            );
            emit_findings(engine.as_ref(), &**event_sink, path_bytes, pending);

            metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(1);
            metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(allowed);

            offset = offset.saturating_add(allowed);

            have = read_len;
            carry = overlap.min(read_len);

            if allowed_usize < n {
                let extra = (n - allowed_usize) as u64;
                if let Err(r) = charge_discarded_bytes(budgets, extra) {
                    if entry_partial_reason.is_none() {
                        entry_partial_reason = Some(r);
                    }
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
                break;
            }
        }

        budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            metrics.archive.record_entry_partial(r, path_bytes, false);
        }
        if stop_archive {
            break;
        }
    }

    budgets.exit_archive();
    outcome
}
