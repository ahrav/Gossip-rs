//! Shared hot-path helpers for chunked scanning.
//!
//! This module is the behavior-preserving core used by every I/O backend:
//! blocking filesystem reads ([`local_fs_owner`](super::local_fs_owner)),
//! io_uring ([`local_fs_uring`](super::local_fs_uring)), archive entry
//! streams ([`local_fs_archive_ctx`](super::local_fs_archive_ctx)), and
//! the connector pipeline ([`connector_pipeline`](super::connector_pipeline)).
//!
//! Centralizing here guarantees that all paths execute the same post-scan
//! pipeline — any divergence in finding semantics would be a correctness bug.
//!
//! # Post-scan pipeline (in order)
//!
//! 1. **`scan_chunk_into`** — engine produces raw findings into scratch.
//! 2. **Overlap-prefix pruning** (`drop_prefix_findings`) — removes findings
//!    whose `root_hint_end` falls within the overlap prefix, since those bytes
//!    are "owned" by the previous chunk and findings were already emitted there.
//! 3. **Cross-rule dedupe** — collapses findings that matched the same secret
//!    location across different rules, keeping the highest-confidence winner.
//! 4. **Effective dropped-finding accounting** — adjusts the engine's reported
//!    cap-drops by subtracting findings the scheduler would have pruned anyway
//!    (overlap + dedupe), so persistence-loss signals remain accurate.
//! 5. **Chunk/byte/finding metrics updates** — records payload bytes only
//!    (excluding overlap prefix) for accurate throughput measurement.

use super::engine_trait::{EngineScratch, ScanEngine};
use super::metrics::WorkerMetricsLocal;
use super::scan_helpers::{account_effective_dropped_findings, apply_cross_rule_dedupe};

use crate::api::FileId;

/// Copy prior-chunk overlap bytes to the front of `buf`.
///
/// The overlap carry pattern avoids re-reading bytes from disk: instead of
/// seeking back, we `copy_within` the tail of the previous chunk to the
/// buffer head, then fill the remainder with new payload bytes.
///
/// Call this before filling payload bytes for the next chunk. On the first
/// iteration both `have` and `carry` are 0, so this is a no-op.
///
/// # Preconditions
///
/// - `have` is the number of valid bytes currently in `buf`.
/// - `carry <= have` (the overlap cannot exceed the data available).
#[inline(always)]
pub(super) fn carry_overlap_prefix(buf: &mut [u8], have: usize, carry: usize) {
    if carry == 0 || have == 0 {
        return;
    }
    debug_assert!(
        have >= carry,
        "overlap carry ({carry}) exceeds valid bytes ({have})"
    );
    buf.copy_within(have - carry..have, 0);
}

/// Scan one chunk and run the shared post-processing pipeline.
///
/// This is the single function that every I/O backend calls after assembling
/// a chunk buffer. It executes the full pipeline documented in the module-level
/// docs: scan → prefix prune → cross-rule dedupe → accounting → metrics.
///
/// After this function returns, `pending` contains the deduplicated findings
/// for this chunk, ready for emission and/or persistence. The caller is
/// responsible for emitting findings and clearing `pending` before the next call.
///
/// # Arguments
///
/// - `data`: the assembled chunk buffer. May contain an overlap prefix at the
///   front; `prefix_len` specifies how many leading bytes belong to the previous
///   chunk. Findings whose `root_hint_end` falls within the prefix are pruned.
/// - `base_offset`: absolute file offset of `data[0]`.
/// - `prefix_len`: bytes of overlap prefix in `data`. For the first chunk this
///   is 0; for subsequent chunks it equals `min(overlap, previous_chunk_len)`.
/// - `file_id`: logical file identifier for engine attribution.
///
/// # Metrics
///
/// Only payload bytes (`data.len() - prefix_len`) are counted toward
/// `bytes_scanned` and `chunks_scanned` to avoid double-counting overlap.
/// When `perf-stats` + `debug_assertions` are enabled, `scan_ns` is recorded
/// around the engine scan only (excluding post-processing).
#[inline(always)]
#[allow(clippy::too_many_arguments)] // Hot-path helper; split parameters avoid temporary structs.
pub(super) fn scan_chunk_postprocess<E: ScanEngine>(
    engine: &E,
    scratch: &mut E::Scratch,
    pending: &mut Vec<<E::Scratch as EngineScratch>::Finding>,
    file_id: FileId,
    base_offset: u64,
    prefix_len: usize,
    data: &[u8],
    metrics: &mut WorkerMetricsLocal,
) {
    // Time only the engine scan for `scan_ns` — post-processing (prefix prune,
    // dedupe, accounting) is scheduler work and must not inflate this counter.
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    let scan_start_t = std::time::Instant::now();

    engine.scan_chunk_into(data, file_id, base_offset, scratch);

    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        metrics.scan_ns = metrics
            .scan_ns
            .saturating_add(scan_start_t.elapsed().as_nanos() as u64);
    }

    let engine_dropped = scratch.dropped_findings();

    // Prefix bytes are owned by the previous chunk.
    let new_bytes_start = base_offset.saturating_add(prefix_len as u64);
    let before_prefix = scratch.pending_findings_len();
    scratch.drop_prefix_findings(new_bytes_start);
    let after_prefix = scratch.pending_findings_len();

    // drain_findings_into uses append semantics — clear first to avoid
    // accumulating findings across chunks.
    pending.clear();
    scratch.drain_findings_into(pending);

    let dedupe_removed = apply_cross_rule_dedupe(pending, engine);

    // Scheduler-side pruning (overlap prefix + cross-rule dedupe) removes
    // findings that would have been discarded anyway. Subtract from the
    // engine's reported drops so persistence-loss signals stay accurate.
    let scheduler_pruned = before_prefix
        .saturating_sub(after_prefix)
        .saturating_add(dedupe_removed);
    account_effective_dropped_findings(metrics, engine_dropped, scheduler_pruned);

    metrics.findings_emitted = metrics
        .findings_emitted
        .saturating_add(pending.len() as u64);

    let payload_bytes = data.len().saturating_sub(prefix_len);
    metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(1);
    metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(payload_bytes as u64);
}
