//! Streaming decode and scan logic.
//!
//! This module decodes transform output incrementally and scans it without
//! materializing the full decoded buffer whenever possible. The core path
//! keeps a decoded ring buffer, feeds Vectorscan stream DBs, and only
//! materializes candidate windows for rule evaluation.
//!
//! ## Data flow
//! - `stream_decode` yields decoded chunks.
//! - Chunks are appended to `decode_ring` (recent decoded bytes only).
//! - Vectorscan streams emit candidate windows into `pending_windows`.
//! - Windows are materialized from the ring (or re-decoded) and scanned.
//! - URL/Base64 span streams emit nested decode spans when bytes are still in
//!   the ring; otherwise we fall back to full decode.
//!
//! ## Invariants
//! - Decoded offsets are monotonically increasing during a stream decode.
//! - `pending_windows` is a timing wheel keyed by `hi` (G=1), so windows are
//!   only processed once the decoded offset has reached the window end.
//! - `scratch.slab` grows during decode, and may be truncated within the stream
//!   path when dropping bytes outside retained spans or when discarding output.
//!   On abort it is truncated back to its pre-decode length.
//! - Per-scan decode budgets (`max_total_decode_output_bytes`, per-transform
//!   `max_decoded_bytes`) are enforced on every chunk.
//! - `found_any` flips only for staged findings that survive emit-time policy
//!   and `min_confidence`; suppressed/low-confidence matches keep it `false`.
//!
//! ## Fallback triggers
//! Streaming will fall back to full decode when any of the following happen:
//! - the per-rule window cap is exceeded (risking unbounded work),
//! - a decoded window/span cannot be reconstructed from the ring,
//! - callback-side overflow/force-full signals are raised for pending windows,
//! - timing-wheel enqueue fails.
//!
//! Decoder errors/truncation (including decode-budget exhaustion) are handled as hard aborts for the stream path:
//! staged stream output is discarded and this call returns without fallback.
//!
//! ## Gate behavior
//! For `Gate::AnchorsInDecoded`, the preferred path is the decoded-space
//! Vectorscan gate. If it cannot be used, we fall back to prefilter hits and
//! may relax enforcement to avoid dropping UTF-16-only matches.
//!
//! ## Borrowing model
//! Timing-wheel drains use a collect-then-process pattern: windows are
//! batch-drained into a `Vec` first, then processed sequentially. This
//! avoids holding a mutable borrow on `pending_windows` during window
//! processing. The `process_window` closure uses a zero-copy ring path
//! when the window data is contiguous in the ring buffer.

use crate::api::{DecodeStep, FileId, StepId};
use crate::stdx::PushOutcome;
use memchr::memchr;
use std::ops::{ControlFlow, Range};
#[cfg(feature = "stats")]
use std::sync::atomic::Ordering;

use super::core::Engine;
use super::helpers::{
    coalesce_under_pressure_sorted, hash128, merge_ranges_with_gap_sorted, u64_to_usize,
};
use super::hit_pool::SpanU32;
use super::rule_repr::Variant;
use super::scratch::{RootSpanMapCtx, ScanScratch};
use super::transform::{
    Base64SpanStream, UrlSpanStream, base64_char_count, base64_skip_chars, map_decoded_offset,
    stream_decode,
};
use super::vectorscan_prefilter::{
    VsScratch, VsStream, VsStreamDb, VsStreamMatchCtx, VsStreamWindow, VsUtf16MatchTables,
    VsUtf16StreamMatchCtx, build_stream_match_ctx, build_utf16_stream_match_ctx,
    gate_match_callback, stream_match_callback, utf16_stream_match_callback,
};
use super::work_items::{
    EncRef, PendingDecodeSpan, PendingWindow, SpanStreamEntry, SpanStreamState, WorkItem,
};
use crate::api::{Gate, TransformConfig, TransformId, TransformMode};

/// RAII guard that clears `root_span_map_ctx` on drop.
///
/// Ensures the raw-pointer-based root-span mapping context does not outlive
/// the encoded buffer it references, even on early returns or panics.
///
/// # Safety
/// The caller must guarantee:
/// - `scratch` points to the `ScanScratch` passed to the enclosing
///   `decode_stream_and_scan` call.
/// - The `ScanScratch` outlives this guard (i.e., the guard is dropped
///   before the scratch reference goes out of scope).
struct RootSpanMapGuard {
    scratch: *mut ScanScratch,
}

/// Mix the root span into a decoded-content hash.
///
/// Identical decoded bytes at different root positions must be scanned
/// independently because findings carry root-buffer coordinates for dedup.
/// XOR with a second 128-bit hash is sufficient because both halves are
/// independently high-entropy (AEGIS-128L).
fn mix_root_hint_hash(h: u128, root_hint: &Option<Range<usize>>) -> u128 {
    let Some(hint) = root_hint.as_ref() else {
        return h;
    };
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&(hint.start as u64).to_le_bytes());
    buf[8..].copy_from_slice(&(hint.end as u64).to_le_bytes());
    h ^ hash128(&buf)
}

impl Drop for RootSpanMapGuard {
    fn drop(&mut self) {
        // SAFETY: Guard is scoped to the duration of decode_stream_and_scan.
        unsafe {
            (*self.scratch).root_span_map_ctx = None;
        }
    }
}

impl Engine {
    /// Decodes an encoded span in full, dedupes it, and enqueues it for scanning.
    ///
    /// This is the fallback path used when:
    /// - No Vectorscan stream DB exists for this transform, or
    /// - `decode_stream_and_scan` bailed out via `force_full`.
    ///
    /// The full decoded output is hashed (128-bit AEGIS-128L MAC via `hash128`) so
    /// identical decoded content from different encoded spans is scanned at
    /// most once per buffer.
    ///
    /// # Preconditions
    /// - `enc` slices into the root scan buffer or the decode slab (must remain
    ///   valid for the duration of this call).
    /// - `scratch.slab` is append-only at this point in the scan; the caller
    ///   must not have outstanding references into the slab.
    ///
    /// # Effects
    /// - Appends decoded bytes to `scratch.slab` and enqueues a `ScanBuf`
    ///   work item on success.
    /// - Enforces both per-transform (`tc.max_decoded_bytes`) and per-scan
    ///   (`max_total_decode_output_bytes`) decode budgets.
    /// - On dedupe hit or budget exhaustion, truncates the slab back and
    ///   returns without enqueueing.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decode_span_fallback(
        &self,
        tc: &TransformConfig,
        transform_idx: usize,
        enc_ref: &EncRef,
        enc: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        depth: usize,
        scratch: &mut ScanScratch,
    ) {
        if enc.len() < tc.min_len {
            return;
        }

        if tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded {
            if let Some(gate) = &self.b64_gate {
                if !gate.hits(enc) {
                    return;
                }
            }
        }

        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }
        let max_out = tc.max_decoded_bytes.min(remaining);

        let decoded_range = match scratch.slab.append_stream_decode(
            tc,
            enc,
            max_out,
            &mut scratch.total_decode_output_bytes,
            self.tuning.max_total_decode_output_bytes,
        ) {
            Ok(r) => r,
            Err(_) => return,
        };

        let decoded = scratch.slab.slice(decoded_range.clone());
        if decoded.is_empty() {
            scratch.slab.buf.truncate(decoded_range.start);
            return;
        }

        let h = mix_root_hint_hash(hash128(decoded), &root_hint);
        if !scratch.seen.insert(h) {
            scratch.slab.buf.truncate(decoded_range.start);
            return;
        }

        scratch.work_q.push(WorkItem::scan_slab(
            decoded_range.start as u32..decoded_range.end as u32,
            step_id,
            root_hint.as_ref().map(|r| r.start as u64..r.end as u64),
            Some(transform_idx as u16),
            Some(*enc_ref),
            depth as u8,
        ));
        scratch.work_items_enqueued = scratch.work_items_enqueued.saturating_add(1);
    }

    /// Re-decodes the decoded-byte window `[lo, hi)` from `encoded` into `out`.
    ///
    /// Called when the ring buffer has evicted the needed bytes. The function
    /// replays `stream_decode` from the beginning of `encoded`, skipping
    /// decoded bytes before `lo` and stopping as soon as `hi` is reached.
    ///
    /// # Returns
    /// - `true`  — exactly `hi - lo` bytes were reconstructed in `out`.
    /// - `false` — decoding failed, the transform truncated output, or
    ///   cumulative decoded bytes exceeded `max_out` before reaching `hi`.
    ///
    /// # Performance
    /// O(encoded.len()) — the entire encoded span is re-decoded even though
    /// only `[lo, hi)` is retained. This is the slow path; the ring-buffer
    /// extraction in `process_window` is preferred.
    pub(super) fn redecode_window_into(
        &self,
        tc: &TransformConfig,
        encoded: &[u8],
        lo: u64,
        hi: u64,
        max_out: usize,
        out: &mut Vec<u8>,
    ) -> bool {
        if hi <= lo {
            return true;
        }
        let needed = match usize::try_from(hi.saturating_sub(lo)) {
            Ok(n) => n,
            Err(_) => return false,
        };
        out.clear();
        if needed > 0 {
            out.reserve(needed);
        }

        let mut decoded_offset: u64 = 0;
        let mut local_out = 0usize;
        let mut truncated = false;

        let res = stream_decode(tc, encoded, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            local_out = local_out.saturating_add(chunk.len());

            let chunk_start = decoded_offset;
            let chunk_end = decoded_offset.saturating_add(chunk.len() as u64);
            if chunk_end > lo && chunk_start < hi {
                let copy_start = lo.saturating_sub(chunk_start) as usize;
                let copy_end = hi.min(chunk_end).saturating_sub(chunk_start) as usize;
                out.extend_from_slice(&chunk[copy_start..copy_end]);
            }
            decoded_offset = chunk_end;
            if decoded_offset >= hi {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        });

        if res.is_err() || truncated {
            return false;
        }
        out.len() == needed
    }

    /// Rolls back stream-local state and delegates to full-span fallback decode.
    ///
    /// This helper is used by both force-full checkpoints to keep rollback
    /// behavior identical across pre/post close-stream processing.
    ///
    /// # Effects
    /// - Restores slab length and decode-budget counters to their pre-stream
    ///   checkpoints.
    /// - Clears all stream-staged windows/spans/findings.
    /// - Invokes `decode_span_fallback` once with the original encoded input.
    #[allow(clippy::too_many_arguments)]
    fn rollback_stream_and_fallback(
        &self,
        tc: &TransformConfig,
        transform_idx: usize,
        enc_ref: &EncRef,
        encoded: &[u8],
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        depth: usize,
        scratch: &mut ScanScratch,
        slab_start: usize,
        total_decode_start: usize,
        count_force_full_stat: bool,
    ) {
        #[cfg(feature = "stats")]
        if count_force_full_stat {
            self.vs_stats
                .stream_force_full
                .fetch_add(1, Ordering::Relaxed);
        }
        #[cfg(not(feature = "stats"))]
        let _ = count_force_full_stat;

        scratch.slab.buf.truncate(slab_start);
        scratch.total_decode_output_bytes = total_decode_start;
        scratch.pending_windows.reset();
        scratch.vs_stream_matches.clear();
        scratch.pending_spans.clear();
        scratch.span_streams.clear();
        scratch.tmp_findings.clear();
        scratch.tmp_drop_hint_end.clear();
        scratch.tmp_norm_hash.clear();
        self.decode_span_fallback(
            tc,
            transform_idx,
            enc_ref,
            encoded,
            step_id,
            root_hint.clone(),
            depth,
            scratch,
        );
    }

    /// Stream-decodes `encoded` and scans windows without materializing the full buffer.
    ///
    /// # Strategy
    ///
    /// 1. Feed decoded chunks into a ring buffer (`decode_ring`) and a
    ///    Vectorscan stream DB (`vs_stream`).
    /// 2. Vectorscan callbacks emit `PendingWindow` entries into a timing wheel
    ///    (granularity G=1) keyed by `hi` — the window-end in decoded-byte space.
    /// 3. As `decoded_offset` advances, the timing wheel drains eligible windows.
    /// 4. Each window is materialized from the ring (zero-copy, preferred) or by
    ///    re-decoding from `encoded` (O(encoded.len()), fallback). If neither
    ///    succeeds, `force_full` is set to abort streaming.
    /// 5. Materialized windows are evaluated by
    ///    `run_rule_on_{raw,utf16}_window_into`.
    ///
    /// ## Coordinate spaces
    ///
    /// Three coordinate spaces are in play:
    /// - **Encoded-byte space** — offsets into `encoded`.
    /// - **Decoded-byte space** — monotonically increasing offsets produced by
    ///   `stream_decode`; used by the ring buffer, timing wheel, and Vectorscan
    ///   stream callbacks.
    /// - **Root-buffer space** — absolute offsets in the original scan input;
    ///   used for finding deduplication and output via `RootSpanMapCtx`.
    ///
    /// ## Deferred finding commit
    ///
    /// Findings are staged in `scratch.tmp_findings` (not `scratch.out`) until
    /// the entire stream succeeds and passes dedupe. On `force_full` or error
    /// the staged findings are discarded and `decode_span_fallback` re-scans
    /// from scratch. This all-or-nothing protocol prevents partial/duplicate
    /// results from leaking into output.
    ///
    /// ## UTF-16 scanning paths
    ///
    /// Two paths handle UTF-16 anchors in decoded streams:
    /// - **Stream path** (`use_utf16_stream`): a dedicated Vectorscan stream DB
    ///   scans decoded chunks incrementally. Lazily activated on the first NUL
    ///   byte (UTF-16 ASCII always contains NULs), replaying the ring buffer's
    ///   current contents to catch up the automaton.
    /// - **Block path** (fallback): decoded bytes are buffered in the slab and
    ///   scanned in a single block pass after streaming completes. Only activated
    ///   when a NUL byte is observed and the stream DB is unavailable.
    ///
    /// ## Gate behavior
    ///
    /// When `tc.gate == Gate::AnchorsInDecoded`:
    /// - **Preferred**: a dedicated Vectorscan gate stream (`vs_gate`) scans
    ///   decoded chunks for anchor literals.
    /// - **Fallback**: if the gate DB fails, enforcement is relaxed (false
    ///   rejection is worse than a redundant scan).
    /// - **UTF-16 caveat**: when UTF-16 anchors exist but the gate DB only
    ///   covers raw patterns, enforcement is also relaxed to avoid false
    ///   negatives on wide-encoded content.
    ///
    /// # Preconditions
    /// - `encoded` slices into the root buffer or decode slab and must remain
    ///   valid for this call.
    /// - `scratch` belongs to the current scan. The following fields are reset
    ///   at entry: `decode_ring`, `window_bytes`, `pending_windows`,
    ///   `vs_stream_matches`, `pending_spans`, `span_streams`, `tmp_findings`,
    ///   `tmp_drop_hint_end`, `tmp_norm_hash`.
    ///
    /// # Effects
    /// - Populates `scratch.tmp_findings` (committed at end) and `pending_spans`
    ///   (promoted to `work_q`). Updates decode budgets and dedupe state.
    /// - On `force_full`, rolls back all streaming state (slab, budgets, staging
    ///   buffers) and falls through to `decode_span_fallback`.
    /// - On decoder error/truncation, aborts this stream attempt, discards
    ///   staged output, and returns without forcing full fallback.
    /// - All Vectorscan scratch/stream resources are returned to `scratch` on
    ///   every exit path (normal, error, and force-full).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decode_stream_and_scan(
        &self,
        vs_stream: &VsStreamDb,
        tc: &TransformConfig,
        transform_idx: usize,
        enc_ref: &EncRef,
        encoded: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        root_hint_maps_encoded: bool,
        depth: usize,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        // Reset only the per-(rule,variant) hit counters that were incremented in the
        // previous stream call. This is O(touched) rather than O(rules×3).
        for idx in scratch.stream_hit_touched.drain() {
            let slot = idx as usize;
            if let Some(hit) = scratch.stream_hit_counts.get_mut(slot) {
                *hit = 0;
            }
        }

        scratch.root_span_map_ctx = if root_hint_maps_encoded {
            root_hint.as_ref().map(|hint| {
                RootSpanMapCtx::new(tc, encoded, hint.start, scratch.chunk_overlap_backscan)
            })
        } else {
            None
        };
        let _root_map_guard = RootSpanMapGuard {
            scratch: scratch as *mut ScanScratch,
        };

        if encoded.is_empty() {
            return;
        }

        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }
        let max_out = tc.max_decoded_bytes.min(remaining);
        if max_out == 0 {
            return;
        }

        let total_decode_start = scratch.total_decode_output_bytes;
        let mut force_full = false;
        let gate_enabled = tc.gate == Gate::AnchorsInDecoded;
        // `gate_hit` is written by the Vectorscan callback to indicate an anchor hit.
        let mut gate_hit: u8 = 0;
        let mut gate_db_active = false;
        let mut gate_db_failed = false;
        let mut gate_stream: Option<VsStream> = None;
        let mut gate_scratch: Option<VsScratch> = None;
        let gate_cb = gate_match_callback();

        #[cfg(feature = "b64-stats")]
        let is_b64_gate = tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded;

        scratch.decode_ring.reset();
        scratch.window_bytes.clear();
        scratch.pending_windows.reset();
        scratch.vs_stream_matches.clear();
        scratch.pending_spans.clear();
        scratch.span_streams.clear();
        scratch.tmp_findings.clear();
        scratch.tmp_drop_hint_end.clear();
        scratch.tmp_norm_hash.clear();

        let mut local_out = 0usize;
        let mut truncated = false;
        // Set to `true` when a Raw-variant match fires in the main prefilter
        // stream (Phase 7). Used as fallback gate evidence when the dedicated
        // gate DB is unavailable — the prefilter covers raw anchors but cannot
        // see wide-encoded (UTF-16) content.
        let mut prefilter_gate_hit = false;
        let mut found_any = false;

        if gate_enabled {
            if let Some(db) = self.vs_gate.as_ref() {
                let mut vs_gate_scratch = match scratch.vs_gate_scratch.take() {
                    Some(s) => Some(s),
                    None => db.alloc_scratch().ok(),
                };
                if let Some(vs_gate_scratch) = vs_gate_scratch.take() {
                    match db.open_stream() {
                        Ok(stream) => {
                            gate_db_active = true;
                            gate_stream = Some(stream);
                            gate_scratch = Some(vs_gate_scratch);
                        }
                        Err(_) => {
                            scratch.vs_gate_scratch = Some(vs_gate_scratch);
                        }
                    }
                }
            }
        }

        let slab_start = scratch.slab.buf.len();
        // `want_utf16_scan`: do we need to check for UTF-16 anchors at all?
        // `use_utf16_stream`: can we scan incrementally (preferred), or must we
        // buffer the full decode output for a single-shot block scan?
        // When `want_utf16_scan && !use_utf16_stream`, every decoded chunk is
        // appended to the slab so the block scanner can run after streaming ends.
        let want_utf16_scan = self.tuning.scan_utf16_variants && self.has_utf16_anchors;
        let use_utf16_stream = want_utf16_scan && self.vs_utf16_stream.is_some();
        // Slab range tracking for the UTF-16 block scan fallback. Only meaningful
        // when `want_utf16_scan && !use_utf16_stream`: Phase 2 appends every
        // decoded chunk to the slab so the single-pass block scanner can run
        // after streaming ends.
        let decoded_full_start = slab_start;
        let mut decoded_full_len = 0usize;
        let mut decoded_has_nul = false;
        let mut utf16_stream: Option<VsStream> = None;
        let mut utf16_stream_scratch: Option<VsScratch> = None;
        let mut utf16_stream_ctx: Option<VsUtf16StreamMatchCtx> = None;
        let utf16_stream_cb = utf16_stream_match_callback();

        // Materialize the decoded window [lo, hi) and run the matched rule.
        //
        // Resolution cascade (cheapest first):
        //   1. Zero-copy ring slice — O(1) when the window is contiguous in
        //      the ring buffer (the common case for small windows).
        //   2. Ring buffer copy — O(hi−lo), copies into `window_bytes`.
        //   3. Re-decode from `encoded` — O(encoded.len()), replays the
        //      transform to reconstruct evicted bytes.
        //   4. Abort — sets `force_full`, causing the caller to discard all
        //      streaming state and fall back to `decode_span_fallback`.
        let process_window = |win: PendingWindow,
                              hi: u64,
                              scratch: &mut ScanScratch,
                              found_any: &mut bool,
                              force_full: &mut bool| {
            if *force_full {
                return;
            }
            let lo = win.lo;
            if hi <= lo {
                return;
            }

            // Try zero-copy path first: if the window is contiguous in the ring
            // buffer we can scan the slice directly without copying.
            let bytes: &[u8] = if let Some(slice) = scratch.decode_ring.contiguous_range(lo, hi) {
                // SAFETY: `contiguous_range` borrows `decode_ring` immutably,
                // but we need to pass `scratch` mutably to `run_rule_on_*`.
                // This is sound because:
                //   1. `run_rule_on_{raw,utf16}_window_into` never read or
                //      write `decode_ring`.
                //   2. The slice is consumed (pattern-matched) within this
                //      `process_window` invocation and does not escape.
                //   3. `decode_ring.push()` (which invalidates ring slices)
                //      only runs in the main decode-loop body, which cannot
                //      execute while `process_window` is on the stack.
                unsafe { std::slice::from_raw_parts(slice.as_ptr(), slice.len()) }
            } else {
                // Fall back to copying from the ring (or re-decoding).
                scratch.window_bytes.clear();
                if !scratch
                    .decode_ring
                    .extend_range_to(lo, hi, &mut scratch.window_bytes)
                    && !self.redecode_window_into(
                        tc,
                        encoded,
                        lo,
                        hi,
                        max_out,
                        &mut scratch.window_bytes,
                    )
                {
                    *force_full = true;
                    return;
                }
                let (ptr, len) = (scratch.window_bytes.as_ptr(), scratch.window_bytes.len());
                // SAFETY: `window_bytes` is not mutated until the next
                // `process_window` call (which `clear()`s it at the top).
                // The slice does not escape this arm; it is consumed by
                // `run_rule_on_*` before this invocation returns.
                unsafe { std::slice::from_raw_parts(ptr, len) }
            };

            let rule = &self.rules_hot[win.rule_id as usize];
            let gates = self.resolve_gates(win.rule_id, rule);
            match win.variant {
                Variant::Raw => {
                    self.run_rule_on_raw_window_into(
                        win.rule_id,
                        rule,
                        bytes,
                        lo,
                        step_id,
                        &root_hint,
                        base_offset,
                        file_id,
                        scratch,
                        found_any,
                        win.anchor_hint,
                        &gates,
                    );
                }
                Variant::Utf16Le | Variant::Utf16Be => {
                    self.run_rule_on_utf16_window_into(
                        win.rule_id,
                        rule,
                        win.variant,
                        bytes,
                        lo,
                        step_id,
                        &root_hint,
                        base_offset,
                        file_id,
                        scratch,
                        found_any,
                        win.anchor_hint,
                        &gates,
                    );
                }
            }
        };

        let materialize_stream_matches = |matches: &mut Vec<VsStreamWindow>, pending_len: u32| {
            if pending_len == 0 {
                return;
            }
            // Defensive clamp: `push_stream_window_bounded` guarantees
            // `pending_len <= pending_cap <= matches.capacity()`, but we clamp
            // anyway so a stale or corrupted `pending_len` can never cause UB.
            let safe_len = (pending_len as usize).min(matches.capacity());
            debug_assert_eq!(
                safe_len,
                pending_len as usize,
                "vs_pending_len ({pending_len}) exceeds stream match capacity ({}); clamped",
                matches.capacity(),
            );
            // SAFETY: `push_stream_window_bounded` initialises elements
            // `0..pending_len` via `ptr::write` and caps `pending_len` at
            // `pending_cap`. The `min()` clamp above is a defence-in-depth
            // guard ensuring we never exceed the allocation even if the
            // invariant is violated.
            unsafe {
                matches.set_len(safe_len);
            }
        };

        // Shared ingestion path for callback-produced stream matches.
        //
        // Uses `mem::take` to move `vs_stream_matches` out of `scratch`,
        // drain windows into the timing wheel, then put the (now-empty) Vec
        // back. This is temporally safe because no Vectorscan scanning occurs
        // while the Vec is moved out — callbacks only fire during
        // `scan_stream` / `close_stream`, which are outside this closure.
        // `ctx.pending_ptr` is refreshed by the caller after each invocation
        // to stay in sync with the Vec's buffer address.
        let drain_vs_stream_matches =
            |scratch: &mut ScanScratch,
             decoded_offset: u64,
             prefilter_gate_hit: &mut bool,
             found_any: &mut bool,
             force_full: &mut bool,
             _count_window_cap_stats: bool| {
                if scratch.vs_stream_matches.is_empty() {
                    return;
                }
                let max_hits = self.tuning.max_windows_per_rule_variant as u32;
                let mut vs_matches = std::mem::take(&mut scratch.vs_stream_matches);
                for win in vs_matches.drain(..) {
                    if win.force_full {
                        *force_full = true;
                        break;
                    }
                    let variant = match Variant::from_idx(win.variant_idx) {
                        Some(v) => v,
                        None => {
                            debug_assert!(
                                false,
                                "Invalid variant_idx {} from Vectorscan callback",
                                win.variant_idx
                            );
                            continue;
                        }
                    };
                    if variant == Variant::Raw {
                        *prefilter_gate_hit = true;
                    }
                    let idx = win.rule_id as usize * 3 + variant.idx();
                    let hit = &mut scratch.stream_hit_counts[idx];
                    if *hit == 0 {
                        scratch.stream_hit_touched.push(idx as u32);
                    }
                    *hit = hit.saturating_add(1);
                    if *hit > max_hits {
                        #[cfg(feature = "stats")]
                        if _count_window_cap_stats {
                            self.vs_stats
                                .stream_window_cap_exceeded
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        *force_full = true;
                        break;
                    }
                    let pending = PendingWindow {
                        hi: win.hi,
                        lo: win.lo,
                        rule_id: win.rule_id,
                        variant,
                        anchor_hint: win.anchor_hint,
                    };
                    match scratch.pending_windows.push(pending.hi, pending) {
                        Ok(PushOutcome::Scheduled) => {}
                        Ok(PushOutcome::Ready(win)) => {
                            let hi = win.hi.min(decoded_offset);
                            process_window(win, hi, scratch, found_any, force_full);
                            if *force_full {
                                break;
                            }
                        }
                        Err(_e) => {
                            #[cfg(debug_assertions)]
                            eprintln!("TimingWheel push failed: {:?}", _e);
                            *force_full = true;
                            break;
                        }
                    }
                }
                vs_matches.clear();
                scratch.vs_stream_matches = vs_matches;
            };

        if depth < self.tuning.max_transform_depth {
            for (tidx, tcfg) in self.transforms.iter().enumerate() {
                if tcfg.mode == TransformMode::Disabled {
                    continue;
                }
                let state = match tcfg.id {
                    TransformId::UrlPercent => SpanStreamState::Url(UrlSpanStream::new(tcfg)),
                    TransformId::Base64 => SpanStreamState::Base64(Base64SpanStream::new(tcfg)),
                };
                scratch.span_streams.push(SpanStreamEntry {
                    transform_idx: tidx,
                    state,
                    spans_emitted: 0,
                    max_spans: tcfg.max_spans_per_buffer,
                });
            }
        }

        let mut vs_scratch = match scratch.vs_stream_scratch.take() {
            Some(s) => s,
            None => match vs_stream.alloc_scratch() {
                Ok(s) => s,
                Err(_) => return,
            },
        };

        let mut stream = match vs_stream.open_stream() {
            Ok(s) => s,
            Err(_) => {
                scratch.vs_stream_scratch = Some(vs_scratch);
                return;
            }
        };

        // Callback sink is fixed-capacity: callbacks append via raw ptr/len/cap
        // and set an overflow flag instead of triggering Vec growth in FFI.
        let stream_pending_cap =
            u32::try_from(scratch.vs_stream_matches.capacity()).unwrap_or(u32::MAX);
        let max_stream_pending = u32::try_from(scratch.pending_windows.capacity())
            .unwrap_or(u32::MAX)
            .min(stream_pending_cap);
        let mut vs_pending_len: u32 = 0;
        let mut vs_match_overflowed: u8 = 0;
        let mut ctx = build_stream_match_ctx(
            &mut scratch.vs_stream_matches,
            &mut vs_pending_len,
            vs_stream.meta(),
            max_stream_pending,
            &mut vs_match_overflowed,
        );

        let mut decoded_offset: u64 = 0;
        // Streamed 128-bit fingerprint via AEGIS-128L MAC.
        //
        // Avoids buffering the full decoded output just for deduplication:
        // each decoded chunk is fed to `mac.update()` and the final digest
        // is checked against `scratch.seen`. The full-buffer path uses
        // `hash128`, a convenience wrapper that takes a complete `&[u8]`.
        // AEGIS-128L's `Aegis128LMac` exposes an incremental `update()`
        // API natively, so we can hash each decoded chunk as it arrives
        // without collecting the entire output. A fixed zero key is
        // acceptable because we need collision resistance, not
        // authentication.
        let key = [0u8; 16];
        let mut mac = aegis::aegis128l::Aegis128LMac::<16>::new(&key);

        #[cfg(feature = "b64-stats")]
        if is_b64_gate {
            scratch.base64_stats.decode_attempts =
                scratch.base64_stats.decode_attempts.saturating_add(1);
            scratch.base64_stats.decode_attempt_bytes = scratch
                .base64_stats
                .decode_attempt_bytes
                .saturating_add(encoded.len() as u64);
        }

        // ── Main decode loop ──────────────────────────────────────────────
        //
        // Each decoded chunk passes through these phases in order:
        //
        //   1. Budget enforcement (per-transform + global decode limits)
        //   2. UTF-16 slab buffering (conditional; feeds block scanner later)
        //   3. Accounting (local_out, total_decode_output_bytes, MAC update,
        //      ring buffer push)
        //   4. Vectorscan stream scan (raw anchors)
        //   5. Gate DB scan (decoded-space anchor gating, if enabled)
        //   6. UTF-16 stream activation / feeding (lazy on first NUL byte)
        //   7. Vectorscan match → PendingWindow enqueue (timing wheel)
        //   8. Timing wheel drain → process_window for expired windows
        //   9. Span stream feeding (nested transform detection)
        let res = stream_decode(tc, encoded, |chunk| {
            // ── Phase 1: Budget enforcement ──────────────────────────────
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len())
                > self.tuning.max_total_decode_output_bytes
            {
                truncated = true;
                return ControlFlow::Break(());
            }

            // ── Phase 2: UTF-16 slab buffering (conditional) ────────────
            if want_utf16_scan && !use_utf16_stream {
                // We need the full decoded buffer to run the UTF-16 scanner later.
                if scratch.slab.buf.len().saturating_add(chunk.len()) > scratch.slab.limit {
                    truncated = true;
                    return ControlFlow::Break(());
                }
                scratch.slab.buf.extend_from_slice(chunk);
                decoded_full_len = decoded_full_len.saturating_add(chunk.len());
                if !decoded_has_nul && memchr(0, chunk).is_some() {
                    decoded_has_nul = true;
                }
            }

            // ── Phase 3: Accounting ──────────────────────────────────────
            local_out = local_out.saturating_add(chunk.len());
            scratch.total_decode_output_bytes = scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len());

            mac.update(chunk);
            scratch.decode_ring.push(chunk);

            // ── Phase 4: Vectorscan stream scan (raw anchors) ───────────
            if vs_stream
                .scan_stream(
                    &mut stream,
                    chunk,
                    &mut vs_scratch,
                    stream_match_callback(),
                    (&mut ctx as *mut VsStreamMatchCtx).cast(),
                )
                .is_err()
            {
                truncated = true;
                return ControlFlow::Break(());
            }
            if vs_match_overflowed != 0 {
                #[cfg(feature = "stats")]
                self.vs_stats
                    .stream_callback_overflow
                    .fetch_add(1, Ordering::Relaxed);
                force_full = true;
                return ControlFlow::Break(());
            }

            // ── Phase 5: Gate DB scan ─────────────────────────────────────
            if gate_db_active && gate_hit == 0 {
                if let (Some(db), Some(gstream), Some(gscratch)) = (
                    self.vs_gate.as_ref(),
                    gate_stream.as_mut(),
                    gate_scratch.as_mut(),
                ) {
                    if db
                        .scan_stream(
                            gstream,
                            chunk,
                            gscratch,
                            gate_cb,
                            (&mut gate_hit as *mut u8).cast(),
                        )
                        .is_err()
                    {
                        gate_db_active = false;
                        gate_db_failed = true;
                    }
                }
            }

            // ── Phase 6: UTF-16 stream activation / feeding ─────────────
            if use_utf16_stream {
                if let Some(db) = self.vs_utf16_stream.as_ref() {
                    let mut scanned_chunk = false;
                    if utf16_stream.is_none() && memchr(0, chunk).is_some() {
                        // Lazily start the UTF-16 stream on the first NUL byte.
                        //
                        // Why NUL ⇒ UTF-16: every UTF-16 code unit for ASCII is two bytes
                        // (e.g., 'A' = 0x41 0x00 LE or 0x00 0x41 BE), so a NUL-free
                        // decoded stream cannot contain UTF-16-encoded ASCII and scanning
                        // would be wasted work.
                        //
                        // Late start: replay the ring buffer's current contents (seg1/seg2)
                        // so the Vectorscan automaton sees all decoded bytes produced before
                        // this chunk.
                        let mut vs_utf16_scratch = match scratch.vs_utf16_stream_scratch.take() {
                            Some(s) => s,
                            None => match db.alloc_scratch() {
                                Ok(s) => s,
                                Err(_) => {
                                    truncated = true;
                                    return ControlFlow::Break(());
                                }
                            },
                        };
                        let mut ustream = match db.open_stream() {
                            Ok(s) => s,
                            Err(_) => {
                                scratch.vs_utf16_stream_scratch = Some(vs_utf16_scratch);
                                truncated = true;
                                return ControlFlow::Break(());
                            }
                        };
                        let base_offset = scratch.decode_ring.start_offset();
                        // Shared-sink invariant: `uctx` shares `pending_ptr`,
                        // `pending_len`, and `overflowed` with the main `ctx`.
                        // This is safe because the main stream and UTF-16
                        // stream never scan concurrently — they alternate
                        // within the same decode-loop iteration (Phase 4 then
                        // Phase 6), so at most one callback is active at a
                        // time. The single `vs_pending_len` / `vs_match_overflowed`
                        // accumulates matches from both streams for unified
                        // draining in Phase 7.
                        let mut uctx = build_utf16_stream_match_ctx(
                            &mut scratch.vs_stream_matches,
                            &mut vs_pending_len,
                            VsUtf16MatchTables {
                                targets: db.targets(),
                                pat_offsets: db.pat_offsets(),
                                pat_lens: db.pat_lens(),
                            },
                            base_offset,
                            max_stream_pending,
                            &mut vs_match_overflowed,
                        );
                        let (seg1, seg2) = scratch.decode_ring.segments();
                        if !seg1.is_empty()
                            && db
                                .scan_stream(
                                    &mut ustream,
                                    seg1,
                                    &mut vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                        {
                            truncated = true;
                            return ControlFlow::Break(());
                        }
                        if vs_match_overflowed != 0 {
                            force_full = true;
                            return ControlFlow::Break(());
                        }
                        if !seg2.is_empty()
                            && db
                                .scan_stream(
                                    &mut ustream,
                                    seg2,
                                    &mut vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                        {
                            truncated = true;
                            return ControlFlow::Break(());
                        }
                        if vs_match_overflowed != 0 {
                            force_full = true;
                            return ControlFlow::Break(());
                        }
                        utf16_stream = Some(ustream);
                        utf16_stream_scratch = Some(vs_utf16_scratch);
                        utf16_stream_ctx = Some(uctx);
                        scanned_chunk = true;
                    }

                    if !scanned_chunk {
                        if let (Some(ustream), Some(vs_utf16_scratch), Some(uctx)) = (
                            utf16_stream.as_mut(),
                            utf16_stream_scratch.as_mut(),
                            utf16_stream_ctx.as_mut(),
                        ) {
                            if db
                                .scan_stream(
                                    ustream,
                                    chunk,
                                    vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                            {
                                truncated = true;
                                return ControlFlow::Break(());
                            }
                            if vs_match_overflowed != 0 {
                                force_full = true;
                                return ControlFlow::Break(());
                            }
                        }
                    }
                }
            }

            // ── Phase 7: Vectorscan match → PendingWindow enqueue ────────
            materialize_stream_matches(&mut scratch.vs_stream_matches, vs_pending_len);
            drain_vs_stream_matches(
                scratch,
                decoded_offset,
                &mut prefilter_gate_hit,
                &mut found_any,
                &mut force_full,
                true,
            );
            vs_pending_len = 0;
            // Refresh `ctx.pending_ptr` after the take/put-back cycle in
            // `drain_vs_stream_matches`. In practice `Vec::clear()` never
            // reallocates so the pointer is stable, but re-reading it is
            // zero-cost and guards against future changes to the drain path.
            ctx.pending_ptr = scratch.vs_stream_matches.as_mut_ptr();
            if force_full {
                return ControlFlow::Break(());
            }

            decoded_offset = decoded_offset.saturating_add(chunk.len() as u64);

            // ── Phase 8: Timing wheel drain → window processing ─────────
            //
            // Batch-drain expired windows: collect first, process second.
            // This avoids raw-pointer aliasing across the timing-wheel callback.
            let mut batch = std::mem::take(&mut scratch.drain_batch);
            scratch
                .pending_windows
                .advance_and_drain_into(decoded_offset, &mut batch);
            for win in batch.drain(..) {
                if force_full {
                    break;
                }
                let hi = win.hi.min(decoded_offset);
                process_window(win, hi, scratch, &mut found_any, &mut force_full);
            }
            scratch.drain_batch = batch;

            if force_full {
                return ControlFlow::Break(());
            }

            // ── Phase 9: Span stream feeding (nested transforms) ────────
            let chunk_start = decoded_offset.saturating_sub(chunk.len() as u64);
            if depth < self.tuning.max_transform_depth {
                // Streaming span detectors emit child decode spans as we go.
                for entry in scratch.span_streams.iter_mut() {
                    if entry.spans_emitted >= entry.max_spans {
                        continue;
                    }
                    let tcfg = &self.transforms[entry.transform_idx];
                    let mut on_span = |lo: u64, hi: u64| -> bool {
                        if entry.spans_emitted >= entry.max_spans {
                            return false;
                        }
                        if scratch.work_items_enqueued + scratch.pending_spans.len()
                            >= self.tuning.max_work_items
                        {
                            return false;
                        }
                        if hi <= lo {
                            return true;
                        }
                        if !scratch.decode_ring.has_range(lo, hi) {
                            // Span bytes are no longer in the ring; force full decode.
                            force_full = true;
                            return false;
                        }

                        let span_start = scratch.slab.buf.len();
                        if !scratch
                            .decode_ring
                            .extend_range_to(lo, hi, &mut scratch.slab.buf)
                        {
                            scratch.slab.buf.truncate(span_start);
                            force_full = true;
                            return false;
                        }
                        let span_len = u64_to_usize(hi.saturating_sub(lo));
                        let span_end = span_start.saturating_add(span_len);
                        let range = span_start..span_end;

                        if tcfg.id == TransformId::Base64 && tcfg.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                if !gate.hits(&scratch.slab.buf[range.clone()]) {
                                    scratch.slab.buf.truncate(span_start);
                                    return true;
                                }
                            }
                        }

                        let mut span_starts = [0usize; 4];
                        let mut span_count = 0usize;

                        if tcfg.id == TransformId::Base64 {
                            let allow_space_ws = tcfg.base64_allow_space_ws;
                            let enc = &scratch.slab.buf[range.clone()];
                            for shift in 0..4usize {
                                let Some(rel) = base64_skip_chars(enc, shift, allow_space_ws)
                                else {
                                    break;
                                };
                                let start = span_start.saturating_add(rel);
                                if start >= span_end {
                                    continue;
                                }
                                if span_starts[..span_count].contains(&start) {
                                    continue;
                                }
                                let enc_aligned = &scratch.slab.buf[start..span_end];
                                let remaining_chars =
                                    base64_char_count(enc_aligned, allow_space_ws);
                                if remaining_chars < tcfg.min_len {
                                    continue;
                                }
                                span_starts[span_count] = start;
                                span_count += 1;
                                if span_count >= span_starts.len() {
                                    break;
                                }
                            }
                        } else {
                            span_starts[0] = span_start;
                            span_count = 1;
                        }

                        let mut enqueued_any = false;
                        for &aligned_start in span_starts.iter().take(span_count) {
                            if scratch.work_items_enqueued + scratch.pending_spans.len()
                                >= self.tuning.max_work_items
                            {
                                break;
                            }
                            let rel = aligned_start.saturating_sub(span_start);
                            let parent_span =
                                u64_to_usize(lo).saturating_add(rel)..u64_to_usize(hi);
                            let child_step_id = scratch.step_arena.push(
                                step_id,
                                DecodeStep::Transform {
                                    transform_idx: entry.transform_idx,
                                    parent_span: parent_span.clone(),
                                },
                            );
                            // Map the nested span back to root-buffer coordinates. For nested transforms,
                            // `parent_span` is in decoded-space offsets; we translate through the parent
                            // transform to get the corresponding encoded-space range, then offset by the
                            // root hint's start to get absolute root-buffer positions.
                            let child_root_hint = if let Some(hint) = root_hint.as_ref() {
                                let start = map_decoded_offset(tc, encoded, parent_span.start);
                                let end = map_decoded_offset(tc, encoded, parent_span.end);
                                Some(
                                    hint.start.saturating_add(start)
                                        ..hint.start.saturating_add(end),
                                )
                            } else {
                                Some(parent_span)
                            };

                            scratch.pending_spans.push(PendingDecodeSpan::new(
                                entry.transform_idx as u16,
                                aligned_start as u32..span_end as u32,
                                child_step_id,
                                child_root_hint.map(|r| r.start as u64..r.end as u64),
                                (depth + 1) as u8,
                            ));
                            enqueued_any = true;
                        }
                        if !enqueued_any {
                            scratch.slab.buf.truncate(span_start);
                        }
                        entry.spans_emitted = entry.spans_emitted.saturating_add(1);
                        true
                    };

                    match &mut entry.state {
                        SpanStreamState::Url(state) => state.feed(chunk, chunk_start, &mut on_span),
                        SpanStreamState::Base64(state) => {
                            state.feed(chunk, chunk_start, &mut on_span)
                        }
                    }
                    if force_full {
                        return ControlFlow::Break(());
                    }
                }
            }

            ControlFlow::Continue(())
        });

        // ── Post-stream: close Vectorscan streams, return scratch ──────
        //
        // All stream resources must be returned to `scratch` on every exit
        // path. The order below (main stream → gate → UTF-16) mirrors the
        // allocation order for symmetry, though correctness doesn't depend
        // on it.
        let _ = vs_stream.close_stream(
            stream,
            &mut vs_scratch,
            stream_match_callback(),
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        );
        scratch.vs_stream_scratch = Some(vs_scratch);

        if let Some(db) = self.vs_gate.as_ref() {
            if let (Some(gstream), Some(mut gscratch)) = (gate_stream.take(), gate_scratch.take()) {
                let _ = db.close_stream(
                    gstream,
                    &mut gscratch,
                    gate_cb,
                    (&mut gate_hit as *mut u8).cast(),
                );
                gate_scratch = Some(gscratch);
            }
        }
        if let Some(gscratch) = gate_scratch.take() {
            scratch.vs_gate_scratch = Some(gscratch);
        }

        if let Some(db) = self.vs_utf16_stream.as_ref() {
            if let (Some(ustream), Some(mut vs_utf16_scratch), Some(mut uctx)) = (
                utf16_stream.take(),
                utf16_stream_scratch.take(),
                utf16_stream_ctx.take(),
            ) {
                let _ = db.close_stream(
                    ustream,
                    &mut vs_utf16_scratch,
                    utf16_stream_cb,
                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                );
                utf16_stream_scratch = Some(vs_utf16_scratch);
            }
        }
        if let Some(vs_utf16_scratch) = utf16_stream_scratch.take() {
            scratch.vs_utf16_stream_scratch = Some(vs_utf16_scratch);
        }
        // `close_stream` flushes the Vectorscan automaton's internal state,
        // which may emit additional matches not seen during the streaming loop.
        // Propagate those matches into `vs_stream_matches` so the post-stream
        // processing below can handle them.
        materialize_stream_matches(&mut scratch.vs_stream_matches, vs_pending_len);
        if vs_match_overflowed != 0 {
            #[cfg(feature = "stats")]
            self.vs_stats
                .stream_callback_overflow
                .fetch_add(1, Ordering::Relaxed);
            force_full = true;
        }

        // ── Post-stream: force_full checkpoint 1 ─────────────────────────
        //
        // `force_full` can be set during the decode loop (phase 7/8/9) when
        // a window cap is exceeded, the ring cannot reconstruct a span, or
        // the timing wheel overflows. This is the first of two rollback
        // points — the second is at the "force_full checkpoint 2" banner
        // below. Both perform the identical rollback sequence:
        // truncate slab, reset budgets, clear staging buffers, then delegate
        // to `decode_span_fallback`. Two check points are needed because the
        // post-stream match processing (close_stream flush + end-of-stream
        // span finishers) can also set `force_full`.
        if force_full {
            self.rollback_stream_and_fallback(
                tc,
                transform_idx,
                enc_ref,
                encoded,
                step_id,
                &root_hint,
                depth,
                scratch,
                slab_start,
                total_decode_start,
                true,
            );
            return;
        }

        // ── Post-stream: process close_stream flush matches + finish spans ─
        if res.is_ok() {
            drain_vs_stream_matches(
                scratch,
                decoded_offset,
                &mut prefilter_gate_hit,
                &mut found_any,
                &mut force_full,
                false,
            );
            if !force_full {
                for entry in scratch.span_streams.iter_mut() {
                    let end_offset = decoded_offset;
                    let mut on_span = |lo: u64, hi: u64| -> bool {
                        if entry.spans_emitted >= entry.max_spans {
                            return false;
                        }
                        if scratch.work_items_enqueued + scratch.pending_spans.len()
                            >= self.tuning.max_work_items
                        {
                            return false;
                        }
                        if hi <= lo {
                            return true;
                        }
                        if !scratch.decode_ring.has_range(lo, hi) {
                            // End-of-stream spans must still be in the ring to materialize.
                            force_full = true;
                            return false;
                        }
                        let span_start = scratch.slab.buf.len();
                        if !scratch
                            .decode_ring
                            .extend_range_to(lo, hi, &mut scratch.slab.buf)
                        {
                            scratch.slab.buf.truncate(span_start);
                            force_full = true;
                            return false;
                        }
                        let span_len = u64_to_usize(hi.saturating_sub(lo));
                        let span_end = span_start.saturating_add(span_len);
                        let range = span_start..span_end;
                        let tcfg = &self.transforms[entry.transform_idx];
                        if tcfg.id == TransformId::Base64 && tcfg.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                if !gate.hits(&scratch.slab.buf[range.clone()]) {
                                    scratch.slab.buf.truncate(span_start);
                                    return true;
                                }
                            }
                        }

                        let mut span_starts = [0usize; 4];
                        let mut span_count = 0usize;

                        if tcfg.id == TransformId::Base64 {
                            let allow_space_ws = tcfg.base64_allow_space_ws;
                            let enc = &scratch.slab.buf[range.clone()];
                            for shift in 0..4usize {
                                let Some(rel) = base64_skip_chars(enc, shift, allow_space_ws)
                                else {
                                    break;
                                };
                                let start = span_start.saturating_add(rel);
                                if start >= span_end {
                                    continue;
                                }
                                if span_starts[..span_count].contains(&start) {
                                    continue;
                                }
                                let enc_aligned = &scratch.slab.buf[start..span_end];
                                let remaining_chars =
                                    base64_char_count(enc_aligned, allow_space_ws);
                                if remaining_chars < tcfg.min_len {
                                    continue;
                                }
                                span_starts[span_count] = start;
                                span_count += 1;
                                if span_count >= span_starts.len() {
                                    break;
                                }
                            }
                        } else {
                            span_starts[0] = span_start;
                            span_count = 1;
                        }

                        let mut enqueued_any = false;
                        for &aligned_start in span_starts.iter().take(span_count) {
                            if scratch.work_items_enqueued + scratch.pending_spans.len()
                                >= self.tuning.max_work_items
                            {
                                break;
                            }
                            let rel = aligned_start.saturating_sub(span_start);
                            let parent_span =
                                u64_to_usize(lo).saturating_add(rel)..u64_to_usize(hi);
                            let child_step_id = scratch.step_arena.push(
                                step_id,
                                DecodeStep::Transform {
                                    transform_idx: entry.transform_idx,
                                    parent_span: parent_span.clone(),
                                },
                            );
                            // Same mapping logic as the streaming loop above: translate decoded-space
                            // offsets back to root-buffer coordinates for accurate finding locations.
                            let child_root_hint = if let Some(hint) = root_hint.as_ref() {
                                let start = map_decoded_offset(tc, encoded, parent_span.start);
                                let end = map_decoded_offset(tc, encoded, parent_span.end);
                                Some(
                                    hint.start.saturating_add(start)
                                        ..hint.start.saturating_add(end),
                                )
                            } else {
                                Some(parent_span)
                            };
                            scratch.pending_spans.push(PendingDecodeSpan::new(
                                entry.transform_idx as u16,
                                aligned_start as u32..span_end as u32,
                                child_step_id,
                                child_root_hint.map(|r| r.start as u64..r.end as u64),
                                (depth + 1) as u8,
                            ));
                            enqueued_any = true;
                        }
                        if !enqueued_any {
                            scratch.slab.buf.truncate(span_start);
                        }
                        entry.spans_emitted = entry.spans_emitted.saturating_add(1);
                        true
                    };

                    match &mut entry.state {
                        SpanStreamState::Url(state) => state.finish(end_offset, &mut on_span),
                        SpanStreamState::Base64(state) => state.finish(end_offset, &mut on_span),
                    }
                    if force_full {
                        break;
                    }
                }
            }
        }

        // ── Post-stream: final timing wheel drain ─────────────────────────
        //
        // Flush all remaining pending windows (advance to u64::MAX). Windows
        // whose `hi` exceeds the actual decoded length are clamped to
        // `final_offset` so we don't read past the decoded data.
        if res.is_ok() && !force_full {
            let final_offset = decoded_offset;
            let mut batch = std::mem::take(&mut scratch.drain_batch);
            scratch
                .pending_windows
                .advance_and_drain_into(u64::MAX, &mut batch);
            for win in batch.drain(..) {
                if force_full {
                    break;
                }
                let hi = win.hi.min(final_offset);
                process_window(win, hi, scratch, &mut found_any, &mut force_full);
            }
            scratch.drain_batch = batch;
        }

        // ── Post-stream: force_full checkpoint 2 ─────────────────────────
        // Same rollback as checkpoint 1 above; triggered by post-stream match
        // processing or end-of-stream span finishers.
        if force_full {
            self.rollback_stream_and_fallback(
                tc,
                transform_idx,
                enc_ref,
                encoded,
                step_id,
                &root_hint,
                depth,
                scratch,
                slab_start,
                total_decode_start,
                false,
            );
            return;
        }

        // ── Post-stream: decode error / truncation early-return ─────────
        //
        // `local_out > max_out` is a defensive guard — Phase 1 should prevent
        // exceeding the budget, but we check here anyway to avoid propagating
        // corrupted accounting into downstream dedup or findings.
        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            #[cfg(feature = "b64-stats")]
            if is_b64_gate {
                scratch.base64_stats.decode_errors =
                    scratch.base64_stats.decode_errors.saturating_add(1);
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_error = scratch
                    .base64_stats
                    .decoded_bytes_wasted_error
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        // ── Post-stream: UTF-16 block scan (fallback path) ──────────────
        //
        // Activated when: (a) UTF-16 scanning is enabled, (b) the streaming
        // UTF-16 DB is unavailable (`!use_utf16_stream`), (c) a NUL byte was
        // observed (NUL ⇒ possible UTF-16 content), and (d) we have decoded
        // output. In this path the full decoded buffer was buffered in the
        // slab during the decode loop (Phase 2) for a single-pass block scan.
        if want_utf16_scan && !use_utf16_stream && decoded_has_nul && decoded_full_len > 0 {
            if let Some(vs_utf16) = self.vs_utf16.as_ref() {
                if let Some(mut vs_utf16_scratch) = scratch.vs_utf16_scratch.take() {
                    #[cfg(feature = "stats")]
                    self.vs_stats
                        .utf16_scans_attempted
                        .fetch_add(1, Ordering::Relaxed);

                    debug_assert!(scratch.touched_pairs.is_empty());
                    if !scratch.touched_pairs.is_empty() {
                        scratch
                            .hit_acc_pool
                            .reset_touched(scratch.touched_pairs.as_slice());
                        scratch.touched_pairs.clear();
                    }

                    let decoded_end = decoded_full_start.saturating_add(decoded_full_len);
                    let (decoded_ptr, decoded_len) = {
                        let decoded = &scratch.slab.buf[decoded_full_start..decoded_end];
                        (decoded.as_ptr(), decoded.len())
                    };
                    // SAFETY: `decoded_ptr` points to a slab range appended above. The slab does
                    // not reallocate during this scan, and we do not mutate the slab while
                    // `decoded` is in use.
                    let decoded = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_len) };
                    let result = vs_utf16.scan_utf16(decoded, scratch, &mut vs_utf16_scratch);
                    scratch.vs_utf16_scratch = Some(vs_utf16_scratch);

                    let used_vectorscan_utf16 = result.as_ref().map(|saw| *saw).unwrap_or(false);
                    match result {
                        Ok(_) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats.utf16_scans_ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats
                                .utf16_scans_err
                                .fetch_add(1, Ordering::Relaxed);

                            if !scratch.touched_pairs.is_empty() {
                                let touched_len = scratch.touched_pairs.len();
                                for i in 0..touched_len {
                                    let pair = scratch.touched_pairs[i] as usize;
                                    scratch.hit_acc_pool.reset_pair(pair);
                                }
                                scratch
                                    .hit_acc_pool
                                    .reset_touched(scratch.touched_pairs.as_slice());
                                scratch.touched_pairs.clear();
                            }
                            // Skip UTF-16 scan on error.
                        }
                    }

                    if !scratch.touched_pairs.is_empty() {
                        const VARIANTS: [Variant; 3] =
                            [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be];
                        let touched_len = scratch.touched_pairs.len();
                        let hay_len = decoded_len as u32;
                        let merge_gap = self.tuning.merge_gap as u32;
                        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

                        for i in 0..touched_len {
                            let pair = scratch.touched_pairs[i] as usize;
                            let rid = pair / 3;
                            let vidx = pair % 3;
                            let variant = VARIANTS[vidx];
                            if variant == Variant::Raw {
                                continue;
                            }
                            let rule = &self.rules_hot[rid];
                            let gates = self.resolve_gates(rid as u32, rule);

                            scratch.hit_acc_pool.take_into(pair, &mut scratch.windows);
                            if scratch.windows.is_empty() {
                                continue;
                            }

                            if used_vectorscan_utf16 && scratch.windows.len() > 1 {
                                scratch
                                    .windows
                                    .as_mut_slice()
                                    .sort_unstable_by_key(|s| s.start);
                            }

                            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
                            coalesce_under_pressure_sorted(
                                &mut scratch.windows,
                                hay_len,
                                pressure_gap_start,
                                self.tuning.max_windows_per_rule_variant,
                            );

                            if let Some(tp) = self.two_phase_gate(rule.two_phase) {
                                let seed_radius_bytes =
                                    tp.seed_radius.saturating_mul(variant.scale());
                                let full_radius_bytes =
                                    tp.full_radius.saturating_mul(variant.scale());
                                let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

                                scratch.expanded.clear();
                                let windows_len = scratch.windows.len();
                                for i in 0..windows_len {
                                    let seed = scratch.windows[i];
                                    let seed_range = seed.to_range();
                                    let win = &decoded[seed_range.clone()];
                                    if !super::helpers::contains_any_memmem(win, &tp.confirm[vidx])
                                    {
                                        continue;
                                    }

                                    let lo = seed_range.start.saturating_sub(extra);
                                    let hi = (seed_range.end + extra).min(decoded.len());
                                    // Preserve anchor_hint from the seed window.
                                    scratch.expanded.push(SpanU32::new(
                                        lo,
                                        hi,
                                        seed.anchor_hint as usize,
                                    ));
                                }

                                if scratch.expanded.is_empty() {
                                    continue;
                                }

                                merge_ranges_with_gap_sorted(&mut scratch.expanded, merge_gap);
                                coalesce_under_pressure_sorted(
                                    &mut scratch.expanded,
                                    hay_len,
                                    pressure_gap_start,
                                    self.tuning.max_windows_per_rule_variant,
                                );

                                let expanded_len = scratch.expanded.len();
                                for i in 0..expanded_len {
                                    let span = scratch.expanded[i];
                                    let w = span.to_range();
                                    let win = &decoded[w.clone()];
                                    self.run_rule_on_utf16_window_into(
                                        rid as u32,
                                        rule,
                                        variant,
                                        win,
                                        w.start as u64,
                                        step_id,
                                        &root_hint,
                                        base_offset,
                                        file_id,
                                        scratch,
                                        &mut found_any,
                                        span.anchor_hint as u64,
                                        &gates,
                                    );
                                }
                            } else {
                                let win_len = scratch.windows.len();
                                for i in 0..win_len {
                                    let span = scratch.windows[i];
                                    let w = span.to_range();
                                    let win = &decoded[w.clone()];
                                    self.run_rule_on_utf16_window_into(
                                        rid as u32,
                                        rule,
                                        variant,
                                        win,
                                        w.start as u64,
                                        step_id,
                                        &root_hint,
                                        base_offset,
                                        file_id,
                                        scratch,
                                        &mut found_any,
                                        span.anchor_hint as u64,
                                        &gates,
                                    );
                                }
                            }
                        }
                        scratch
                            .hit_acc_pool
                            .reset_touched(scratch.touched_pairs.as_slice());
                        scratch.touched_pairs.clear();
                    }
                }
            }
        }

        // Gate enforcement decision.
        //
        // The gate answers: "does the decoded content contain at least one
        // anchor pattern?"  Three evidence sources, in priority order:
        //
        // 1. `gate_hit != 0`        — dedicated Vectorscan gate stream matched.
        //                              Highest confidence; covers both raw and
        //                              UTF-16 anchors.
        // 2. `prefilter_gate_hit`    — a Raw-variant anchor from the main
        //                              prefilter stream. Moderate confidence:
        //                              covers raw anchors only.
        // 3. Neither fired           — safe to enforce only when no UTF-16
        //                              anchors exist (prefilter has no
        //                              wide-encoded patterns).
        //
        // Enforcement is relaxed (`enforce_gate = false`) when:
        // - Gate DB failed to open/scan (avoid false rejection), or
        // - UTF-16 anchors exist but only prefilter evidence is available
        //   (prefilter cannot see wide-encoded content → false negatives).
        let gate_satisfied = if gate_db_active || gate_hit != 0 {
            gate_hit != 0
        } else {
            prefilter_gate_hit
        };
        let enforce_gate = if gate_enabled {
            if gate_db_failed {
                false
            } else if gate_db_active || gate_hit != 0 {
                true
            } else {
                !self.tuning.scan_utf16_variants || !self.has_utf16_anchors
            }
        } else {
            false
        };
        if enforce_gate && !gate_satisfied {
            #[cfg(feature = "b64-stats")]
            if is_b64_gate {
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_no_anchor = scratch
                    .base64_stats
                    .decoded_bytes_wasted_no_anchor
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        #[cfg(feature = "b64-stats")]
        if is_b64_gate {
            scratch.base64_stats.decoded_bytes_total = scratch
                .base64_stats
                .decoded_bytes_total
                .saturating_add(local_out as u64);
            scratch.base64_stats.decoded_bytes_kept = scratch
                .base64_stats
                .decoded_bytes_kept
                .saturating_add(local_out as u64);
        }

        // ── Post-stream: content-hash dedupe ─────────────────────────────
        //
        // Finalize the streamed AEGIS-128L MAC over all decoded chunks to get
        // a 128-bit content fingerprint. If the same decoded content (at the
        // same root position) was already scanned, skip — no new findings.
        let h = mix_root_hint_hash(u128::from_le_bytes(mac.finalize()), &root_hint);
        if !scratch.seen.insert(h) {
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        // ── Post-stream: commit staged findings ─────────────────────────
        //
        // All-or-nothing: staged findings are only promoted to `scratch.out`
        // now that the stream completed, dedupe passed, and the gate was
        // satisfied. `run_rule_on_*_window_into` only stages findings that
        // already passed emit-time policy and `min_confidence`.
        // `mem::take` + put-back avoids double-borrowing `scratch`.
        let mut tmp_findings = std::mem::take(&mut scratch.tmp_findings);
        let mut tmp_drop_hint_end = std::mem::take(&mut scratch.tmp_drop_hint_end);
        let mut tmp_norm_hash = std::mem::take(&mut scratch.tmp_norm_hash);
        debug_assert_eq!(tmp_findings.len(), tmp_drop_hint_end.len());
        debug_assert_eq!(tmp_findings.len(), tmp_norm_hash.len());
        for ((rec, drop_end), norm_hash) in tmp_findings
            .drain(..)
            .zip(tmp_drop_hint_end.drain(..))
            .zip(tmp_norm_hash.drain(..))
        {
            scratch.push_finding_with_drop_hint(rec, norm_hash, drop_end, rec.dedupe_with_span);
        }
        scratch.tmp_findings = tmp_findings;
        scratch.tmp_drop_hint_end = tmp_drop_hint_end;
        scratch.tmp_norm_hash = tmp_norm_hash;

        // ── Post-stream: promote deferred child spans ───────────────────
        //
        // Deferred because `IfNoFindingsInThisBuffer` transforms must see the
        // final `found_any` state before deciding whether to enqueue.
        // `found_any` reflects emitted/staged findings only (post-policy and
        // post-threshold), not raw regex hits.
        let found_any_in_buf = found_any;
        let mut enqueued = 0usize;
        for pending in scratch.pending_spans.drain(..) {
            let mode = self.transforms[pending.transform_idx as usize].mode;
            if mode == TransformMode::IfNoFindingsInThisBuffer && found_any_in_buf {
                continue;
            }
            if scratch.work_items_enqueued >= self.tuning.max_work_items {
                break;
            }
            scratch.work_q.push(WorkItem::decode_span(
                pending.transform_idx,
                EncRef::slab(pending.range()),
                pending.step_id,
                pending.root_hint(),
                pending.depth,
            ));
            scratch.work_items_enqueued += 1;
            enqueued += 1;
        }

        let _ = enqueued;
        let _ = (transform_idx, base_offset, file_id);
    }
}
