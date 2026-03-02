//! Window merge and coalesce helpers.
//!
//! These routines reduce overlapping or nearby anchor windows into fewer,
//! wider spans to bound the number of regex validation passes.

use crate::engine::hit_pool::SpanU32;
use crate::scratch_memory::ScratchVec;

/// Merges sorted ranges in-place, allowing a soft merge gap.
///
/// # Preconditions
/// - `ranges` must be sorted by `start` ascending.
/// - Each span is normalized (`start <= end`).
///
/// # Effects
/// - Adjacent or overlapping ranges within `gap` bytes are merged into a single window.
/// - Output remains sorted and non-overlapping.
/// - When merging, preserves the **earliest** (smallest) anchor hint to maintain
///   conservative correctness.
///
/// # Design Notes
/// - The soft gap reduces the number of regex runs at the cost of slightly
///   wider windows.
/// - `gap == 0` behaves like a standard overlap/adjacency merge.
///
/// # Complexity
/// - O(n) time, O(1) extra space.
pub(crate) fn merge_ranges_with_gap_sorted(ranges: &mut ScratchVec<SpanU32>, gap: u32) {
    let len = ranges.len();
    if len <= 1 {
        return;
    }

    let s = ranges.as_mut_slice();
    let mut write = 0usize;
    let mut cur = s[0];

    for i in 1..len {
        // SAFETY: i < len and len == s.len().
        let r = unsafe { *s.get_unchecked(i) };
        debug_assert!(r.start >= cur.start);
        if r.start <= cur.end.saturating_add(gap) {
            cur.end = cur.end.max(r.end);
            // Preserve the earliest anchor hint when merging.
            cur.anchor_hint = cur.anchor_hint.min(r.anchor_hint);
        } else {
            // SAFETY: write < i < len, so write is in bounds.
            unsafe { *s.get_unchecked_mut(write) = cur };
            write += 1;
            cur = r;
        }
    }
    // SAFETY: write <= len - 1 < len, so write is in bounds.
    unsafe { *s.get_unchecked_mut(write) = cur };
    write += 1;
    ranges.truncate(write);
}

/// Coalesces windows until their count is below a cap.
///
/// # Preconditions
/// - `ranges` must be sorted by `start` ascending.
/// - Each span is normalized (`start <= end`) and bounded by `hay_len`.
/// - `ranges` should already be lightly merged with a small gap when possible.
///
/// # Effects
/// - Expands the merge gap exponentially to reduce the window count (capped at `hay_len`).
/// - If still over the cap, collapses to a single window spanning the first/last range
///   (clamped to `hay_len`).
/// - The final ranges are a superset of the original windows (given the preconditions).
/// - When collapsing, preserves the **earliest** (smallest) anchor hint.
///
/// # Complexity
/// - O(n * D) time where D = ceil(log2(hay_len / gap)) is the number of
///   gap-doubling passes; O(1) extra space.
pub(crate) fn coalesce_under_pressure_sorted(
    ranges: &mut ScratchVec<SpanU32>,
    hay_len: u32,
    mut gap: u32,
    max_windows: usize,
) {
    if ranges.len() <= max_windows {
        return;
    }

    // Increase the merge gap until we fit the cap or hit the buffer length.
    while ranges.len() > max_windows && gap < hay_len {
        merge_ranges_with_gap_sorted(ranges, gap);
        gap = gap.saturating_mul(2);
    }

    if ranges.len() > max_windows && !ranges.is_empty() {
        // Hard fallback: collapse to a single window to bound work deterministically.
        // Preserve the earliest anchor hint across all windows.
        let start = ranges[0].start;
        let end = ranges[ranges.len() - 1].end;
        let mut min_anchor = start;
        for i in 0..ranges.len() {
            min_anchor = min_anchor.min(ranges[i].anchor_hint);
        }
        ranges.clear();
        ranges.push(SpanU32 {
            start: start.min(hay_len),
            end: end.min(hay_len),
            anchor_hint: min_anchor.min(hay_len),
        });
    }
}
