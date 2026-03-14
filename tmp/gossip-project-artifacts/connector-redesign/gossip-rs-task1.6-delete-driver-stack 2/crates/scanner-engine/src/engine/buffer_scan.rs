//! Buffer-level scanning coordination.
//!
//! This module wires together the prefilter pipeline and final rule evaluation
//! for a single buffer (root or decoded). The pipeline is:
//!
//! 1. **Prefilter** — Run the Vectorscan prefilter on raw bytes to collect hit
//!    windows, populating `touched_pairs` and per-pair hit accumulators.
//! 2. **Normalize** — For each touched (rule, variant) pair, sort hit windows,
//!    merge adjacent/overlapping ones (gap-tolerant), and coalesce under
//!    pressure if the window count exceeds the per-(rule, variant) cap.
//! 3. **Two-phase confirm** (optional) — Re-check a narrow seed window with
//!    memmem confirmation before expanding to the full validation radius.
//!    This filters noisy prefilter hits cheaply.
//! 4. **Validate** — Run full regex matching on the resulting windows and emit
//!    findings via [`Engine::run_rule_on_window`] (in `window_validate`).
//!
//! ## Pair encoding
//!
//! Touched pairs are encoded as `pair = rule_id * 3 + variant_idx`, where
//! variant indices are `Raw = 0`, `Utf16Le = 1`, `Utf16Be = 2`. This flat
//! encoding avoids a two-level map and keeps the hot loop cache-friendly.
//!
//! ## One-shot prefilter skip
//!
//! When called from `scan_chunk_into` on the root buffer, the prefilter was
//! already run by the caller. The `scratch.root_prefilter_done` flag is a
//! one-shot signal consumed here: the first call (root buffer) skips the
//! prefilter; subsequent calls (transform buffers) see `false` and run it.
//!
//! All work is bounded by a `u32`-addressable buffer; windows and spans are
//! stored as [`SpanU32`] to keep hot-path memory compact.

use crate::api::{FileId, StepId};
use std::ops::Range;
#[cfg(feature = "stats")]
use std::sync::atomic::Ordering;

use super::core::Engine;
use super::helpers::{
    coalesce_under_pressure_sorted, contains_any_memmem, merge_ranges_with_gap_sorted,
};
use super::hit_pool::SpanU32;
use super::rule_repr::Variant;
use super::scratch::ScanScratch;

impl Engine {
    /// Applies the prefilter/gating pipeline to a single buffer.
    ///
    /// This is the inner scan loop called once per buffer (root or decoded).
    /// It processes only the `(rule, variant)` pairs that the Vectorscan
    /// prefilter touched, keeping work proportional to hits rather than to
    /// the total rule count.
    ///
    /// # Preconditions
    /// - `buf.len() <= u32::MAX` (spans are stored as [`SpanU32`]).
    /// - `scratch` belongs to the current scan and is not shared concurrently.
    /// - `root_hint` (if provided) is a byte range into `buf`'s coordinate
    ///   space, used to anchor findings back to the original input.
    ///
    /// # Effects
    /// - Populates per-(rule, variant) hit windows and emits findings into `scratch.out`.
    /// - Resets `touched_pairs` and hit accumulators at the end so the next
    ///   buffer starts clean.
    ///
    /// # Performance
    /// - Work scales with the number of touched (rule, variant) pairs rather
    ///   than all rules in the engine.
    /// - Sorting is conditional: raw windows always need sorting (Vectorscan
    ///   fires in match-end order), but UTF-16 windows from literal-anchor
    ///   matching arrive pre-sorted and skip the sort.
    pub(super) fn scan_rules_on_buffer(
        &self,
        buf: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        debug_assert!(buf.len() <= u32::MAX as usize);
        debug_assert!(self.tuning.merge_gap <= u32::MAX as usize);
        debug_assert!(self.tuning.pressure_gap_start <= u32::MAX as usize);
        let hay_len = buf.len() as u32;
        let merge_gap = self.tuning.merge_gap as u32;
        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

        // Check if scan_chunk_into already ran the prefilter for the root buffer.
        // This is a one-shot flag: consumed here so transform buffer calls see
        // `false` and run the full prefilter as normal.
        let (mut used_vectorscan_utf16, skip_prefilter) = if scratch.root_prefilter_done {
            scratch.root_prefilter_done = false;
            (scratch.root_prefilter_saw_utf16, true)
        } else {
            (false, false)
        };

        if !skip_prefilter {
            // Defensive: should already be empty from the prior buffer's reset.
            debug_assert!(scratch.touched_pairs.is_empty());
            if !scratch.touched_pairs.is_empty() {
                scratch
                    .hit_acc_pool
                    .reset_touched(scratch.touched_pairs.as_slice());
                scratch.touched_pairs.clear();
            }
            // Stage 1: Vectorscan prefilter on raw bytes (required).
            let vs = self
                .vs
                .as_ref()
                .expect("vectorscan prefilter database unavailable (fallback disabled)");
            let mut vs_scratch_owned = scratch
                .vs_scratch
                .take()
                .expect("vectorscan scratch missing");
            #[cfg(feature = "stats")]
            self.vs_stats
                .scans_attempted
                .fetch_add(1, Ordering::Relaxed);
            let (result, _vs_nanos) =
                crate::perf_counters::time(|| vs.scan_raw(buf, scratch, &mut vs_scratch_owned));
            crate::perf_counters::record_scan_vs_prefilter(_vs_nanos);
            scratch.vs_scratch = Some(vs_scratch_owned);
            let saw_utf16 = match result {
                Ok(saw) => {
                    #[cfg(feature = "stats")]
                    self.vs_stats.scans_ok.fetch_add(1, Ordering::Relaxed);
                    saw
                }
                Err(err) => {
                    #[cfg(feature = "stats")]
                    self.vs_stats.scans_err.fetch_add(1, Ordering::Relaxed);
                    panic!("vectorscan scan failed with fallback disabled: {err}");
                }
            };

            used_vectorscan_utf16 = saw_utf16;

            if !vs.raw_missing_rules().is_empty() {
                panic!(
                    "vectorscan raw db missing {} rule patterns (fallback disabled)",
                    vs.raw_missing_rules().len()
                );
            }

            #[cfg(feature = "stats")]
            {
                if saw_utf16 {
                    self.vs_stats
                        .anchor_after_vs
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.vs_stats.anchor_skipped.fetch_add(1, Ordering::Relaxed);
                }
            }

            if scratch.touched_pairs.is_empty() {
                crate::perf_counters::record_scan_zero_hit_chunk();
                return;
            }
        }

        // Only process (rule, variant) pairs that were actually touched by a
        // prefilter hit in this buffer. This avoids O(rules × variants) work
        // when nothing matched, which is critical once rule counts grow.
        //
        // Each `pair` encodes `rule_id * 3 + variant_idx` (see module docs).
        // We decode via integer division/modulus rather than a struct to keep
        // the touched_pairs vector as a flat u32 list.
        #[cfg(feature = "perf-counters")]
        let _validate_start = std::time::Instant::now();
        const VARIANTS: [Variant; 3] = [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be];
        let touched_len = scratch.touched_pairs.len();
        for i in 0..touched_len {
            let pair = scratch.touched_pairs[i] as usize;
            let rid = pair / 3;
            let vidx = pair % 3;
            let variant = VARIANTS[vidx];
            let rule = &self.rules_hot[rid];
            // Resolve gate pool references once per (rule, variant) pair rather
            // than inside the per-window loop. See ResolvedGates for rationale.
            let gates = self.resolve_gates(rid as u32, rule);

            scratch.hit_acc_pool.take_into(pair, &mut scratch.windows);
            if scratch.windows.is_empty() {
                continue;
            }

            // Vectorscan callbacks fire in match-end order (not start order),
            // and multiple patterns may interleave, so windows arrive unsorted.
            // Merge and coalesce below require sorted input.
            //
            // Raw variant: always needs sorting because Vectorscan always runs.
            // UTF-16 variants: only need sorting when the Vectorscan UTF-16 DB
            // was used (`used_vectorscan_utf16`). When the UTF-16 DB is absent,
            // UTF-16 hits can only come from literal-anchor matching, which
            // produces windows in start order — no sort needed.
            if (variant == Variant::Raw && scratch.windows.len() > 1)
                || (used_vectorscan_utf16
                    && matches!(variant, Variant::Utf16Le | Variant::Utf16Be)
                    && scratch.windows.len() > 1)
            {
                scratch
                    .windows
                    .as_mut_slice()
                    .sort_unstable_by_key(|s| s.start);
            }

            // Post-sort invariant: windows are now in non-decreasing order of start.
            // Merge adjacent/overlapping windows with the configured gap tolerance.
            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
            coalesce_under_pressure_sorted(
                &mut scratch.windows,
                hay_len,
                pressure_gap_start,
                self.tuning.max_windows_per_rule_variant,
            );

            // Two-phase confirmation: a cost-saving optimization for rules whose
            // prefilter fires frequently but whose regex is expensive.
            //
            // Seed pass: memmem-check each seed window for the confirm pattern.
            //   Windows without a match are dropped immediately.
            // Expand pass: surviving windows are widened from seed_radius to
            //   full_radius (the actual regex validation radius). The extra
            //   padding is `(full_radius - seed_radius) * variant.scale()`.
            //
            // Soundness argument: confirm patterns are mandatory literal
            // sub-expressions extracted from the regex AST (see
            // `compile_trigger_plan`). Because these literals *must* appear in
            // any valid regex match, their absence in the seed window proves
            // no match exists in any superset — widening after a miss would be
            // wasted work. This rejects ~80-95% of noisy prefilter hits before
            // paying the O(regex) cost.
            //
            // The confirm set is indexed by `vidx` (variant index) so the
            // memmem check uses the correct byte encoding (raw vs UTF-16).
            if let Some(tp) = self.two_phase_gate(rule.two_phase) {
                let seed_radius_bytes = tp.seed_radius.saturating_mul(variant.scale());
                let full_radius_bytes = tp.full_radius.saturating_mul(variant.scale());
                let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

                scratch.expanded.clear();
                let windows_len = scratch.windows.len();
                for i in 0..windows_len {
                    let seed = scratch.windows[i];
                    let seed_range = seed.to_range();
                    let win = &buf[seed_range.clone()];
                    if !contains_any_memmem(win, &tp.confirm[vidx]) {
                        continue;
                    }

                    let lo = seed_range.start.saturating_sub(extra);
                    let hi = (seed_range.end + extra).min(buf.len());
                    // Preserve the anchor_hint from the seed window.
                    scratch
                        .expanded
                        .push(SpanU32::new(lo, hi, seed.anchor_hint as usize));
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
                    let anchor_hint = span.anchor_hint as usize;
                    self.run_rule_on_window(
                        rid as u32,
                        rule,
                        variant,
                        buf,
                        w,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                        anchor_hint,
                        &gates,
                    );
                }
                continue;
            }

            let win_len = scratch.windows.len();
            for i in 0..win_len {
                let span = scratch.windows[i];
                let w = span.to_range();
                let anchor_hint = span.anchor_hint as usize;
                self.run_rule_on_window(
                    rid as u32,
                    rule,
                    variant,
                    buf,
                    w,
                    step_id,
                    root_hint.clone(),
                    base_offset,
                    file_id,
                    scratch,
                    anchor_hint,
                    &gates,
                );
            }
        }
        // Reset accumulators for all pairs touched in this buffer so the next
        // buffer starts with zeroed hit lists.
        //
        // Ordering constraint: this must happen *after* the validation loop
        // because `take_into` moves hits out of the accumulator into
        // `scratch.windows`. Resetting earlier would discard hits that haven't
        // been consumed yet.
        scratch
            .hit_acc_pool
            .reset_touched(scratch.touched_pairs.as_slice());
        scratch.touched_pairs.clear();

        #[cfg(feature = "perf-counters")]
        crate::perf_counters::record_scan_validate(_validate_start.elapsed().as_nanos() as u64);
    }
}
