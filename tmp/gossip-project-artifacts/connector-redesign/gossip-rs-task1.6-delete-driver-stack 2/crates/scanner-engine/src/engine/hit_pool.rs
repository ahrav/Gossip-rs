//! Hot-path data structures for hit accumulation.
//!
//! Contains compact span types and the hit accumulator pool used during
//! prefilter scanning to collect candidate windows.
//!
//! # Performance design
//! All arrays are fixed-size after construction (pair count and max_hits are
//! invariant for the lifetime of a `HitAccPool` instance). The struct stores
//! raw pointers instead of `Vec` to eliminate bounds-check loads on the hot
//! path.
//! Per-pair metadata (`len` + `coalesced` flag) is collocated into a 4-byte
//! `PairMeta` struct so that a single 32-bit load gives both fields and 16
//! consecutive pairs fit in one cache line.
//!
//! The overflow coalesce path is extracted as `#[cold] #[inline(never)]` to
//! keep the fast path compact and branch-predictor friendly.

use crate::scratch_memory::ScratchVec;
use std::ops::Range;

/// Compact span used in hot paths.
///
/// Uses `u32` offsets to reduce memory footprint and improve cache density.
/// Valid only for buffers whose length fits in `u32`. Spans are half-open
/// ranges (`start..end`).
///
/// # Fields
/// - `anchor_hint`: Vectorscan's `from` match offset, clamped to `[start, end]`.
///   Used to start regex searches near the anchor instead of at window start.
///   When windows are merged, the earliest (smallest) anchor_hint is preserved.
///
/// # Invariants
/// - `start <= end` and both fit in `u32`.
/// - `anchor_hint` is in `[start, end]` (clamped during construction).
/// - Only valid while the referenced buffer remains unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SpanU32 {
    pub(super) start: u32,
    pub(super) end: u32,
    /// Anchor hint from Vectorscan's `from` offset, clamped to window bounds.
    pub(super) anchor_hint: u32,
}

impl SpanU32 {
    /// Creates a span with an explicit anchor hint.
    ///
    /// The anchor hint is clamped to `[start, end]` to maintain invariants.
    pub(super) fn new(start: usize, end: usize, anchor_hint: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(start <= u32::MAX as usize);
        debug_assert!(end <= u32::MAX as usize);
        let clamped_hint = anchor_hint.clamp(start, end);
        Self {
            start: start as u32,
            end: end as u32,
            anchor_hint: clamped_hint as u32,
        }
    }

    /// Creates a span without an anchor hint (defaults to start).
    ///
    /// Used for backward compatibility and cases where anchor hints are unavailable.
    pub(super) fn new_no_hint(start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(start <= u32::MAX as usize);
        debug_assert!(end <= u32::MAX as usize);
        Self {
            start: start as u32,
            end: end as u32,
            anchor_hint: start as u32,
        }
    }

    pub(super) fn to_range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

// ---------------------------------------------------------------------------
// PairMeta: collocated per-pair hot metadata
// ---------------------------------------------------------------------------

/// Per-pair hot metadata, collocated for single-load access.
///
/// Packing `len` and `coalesced` into 4 bytes means a single 32-bit load
/// gives both fields. 16 consecutive pairs fit in one cache line.
///
/// # Invariants
/// - `len` is in `0..=max_hits` (constructor rejects max_hits > `u16::MAX`).
/// - `coalesced` is 0 or 1.
#[derive(Clone, Copy)]
#[repr(C)]
struct PairMeta {
    /// Number of windows accumulated for this pair.
    /// Max value is max_hits (constructor enforces max_hits ≤ `u16::MAX`).
    len: u16,
    /// 1 if this pair has been coalesced, 0 otherwise.
    coalesced: u8,
    _pad: u8,
}

const _: () = assert!(std::mem::size_of::<PairMeta>() == 4);

impl PairMeta {
    const ZERO: Self = Self {
        len: 0,
        coalesced: 0,
        _pad: 0,
    };
}

// ---------------------------------------------------------------------------
// HitAccPool: raw-pointer backed hit accumulator
// ---------------------------------------------------------------------------

/// Accumulates anchor hit windows across all (rule, variant) pairs.
///
/// Storage is fixed-stride: `windows` is laid out as `pair * max_hits + idx`.
/// Each pair starts as an append-only list. Once the hit count exceeds the cap,
/// it switches to a single "coalesced" window that covers the union of all hits
/// seen so far. The fallback is conservative (may over-expand) but guarantees
/// correctness while bounding memory growth.
///
/// Windows are pushed in non-decreasing order for anchor scans. When switching
/// to coalesced mode, ordering is no longer meaningful; downstream code must
/// not assume sorted windows unless it explicitly sorts them.
///
/// # Guarantees
/// - If `pair_meta[pair].coalesced != 0`, `coalesced[pair]` is a superset of
///   all hits seen so far for that pair.
///
/// # Performance
/// - Per-pair memory is capped at `max_hits`; append stays O(1) until coalesced.
/// - Single allocation for all pairs; no per-(rule, variant) allocations.
/// - All internal arrays are raw pointers — bounds are invariant after
///   construction so no runtime bounds checks are emitted on the fast path.
/// - Per-pair metadata (`len` + `coalesced`) is collocated into 4 bytes for
///   single-load access.
///
/// # Safety
/// - `new()` validates allocation sizes (`pair_count`, `max_hits`,
///   `pair_count * max_hits`) before any pointer arithmetic is used.
/// - Allocations use `Vec::into_boxed_slice()` → `Box::into_raw()` so the
///   stored pointer's layout exactly matches the length; `Drop` reconstructs
///   `Box<[T]>` via `Box::from_raw(slice_from_raw_parts_mut(..))`.
/// - Hot-path methods require `pair < pair_count`; debug assertions are
///   diagnostic only and are not a release-mode safety boundary.
/// - `reset_touched` requires that `touched_pairs` entries originate from
///   `mark_touched` for this pool instance.
/// - `unsafe impl Send`: raw pointers are exclusively owned (same pattern as
///   `ScratchVec`).
pub(super) struct HitAccPool {
    max_hits: u32,
    pair_count: u32,
    /// `ceil(pair_count / 64)` — number of `u64` words in the touched bitset.
    touched_word_count: u32,
    /// Explicit padding making the intended 16-byte header layout (three
    /// `u32` fields + pad) visible in the source. The struct uses default
    /// Rust repr, so field order is not guaranteed, but the pad documents
    /// the developer's alignment intent.
    _pad: u32,
    // Raw pointers to exclusively-owned heap allocations.
    // All arrays are fixed-size after construction.
    pair_meta: *mut PairMeta,
    windows: *mut SpanU32,
    coalesced: *mut SpanU32,
    touched_words: *mut u64,
}

// SAFETY: All raw pointers in `HitAccPool` are exclusively owned heap allocations,
// never aliased, and only accessed through `&self` / `&mut self`. This is
// the same ownership model as `ScratchVec` which also implements `Send`.
unsafe impl Send for HitAccPool {}

impl Drop for HitAccPool {
    fn drop(&mut self) {
        let pair_count = self.pair_count as usize;
        let max_hits = self.max_hits as usize;
        let word_count = self.touched_word_count as usize;

        // Reconstruct Box<[T]> from raw parts and let them drop.
        // SAFETY: Each pointer was obtained from Box::into_raw on a boxed
        // slice with the exact length stored in the struct. No other code
        // has taken ownership of these allocations.
        unsafe {
            // Cannot overflow: `new()` already validated via checked_mul.
            let total_windows = pair_count * max_hits;
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.pair_meta,
                pair_count,
            )));
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.windows,
                total_windows,
            )));
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.coalesced,
                pair_count,
            )));
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.touched_words,
                word_count,
            )));
        }
    }
}

impl HitAccPool {
    /// Allocate a pool for `pair_count` (rule, variant) pairs with a per-pair
    /// hit cap of `max_hits`.
    ///
    /// # Errors
    /// - Returns `Err` if `max_hits == 0` or if allocation sizes overflow.
    pub(super) fn new(pair_count: usize, max_hits: usize) -> Result<Self, String> {
        if max_hits == 0 {
            return Err("hit accumulator max_hits must be > 0".to_string());
        }
        let max_hits_u32 = u32::try_from(max_hits)
            .map_err(|_| "hit accumulator max_hits exceeds u32::MAX".to_string())?;
        if max_hits > u16::MAX as usize {
            return Err(
                "hit accumulator max_hits exceeds u16::MAX (PairMeta.len is u16)".to_string(),
            );
        }
        let pair_count_u32 = u32::try_from(pair_count)
            .map_err(|_| "hit accumulator pair_count exceeds u32::MAX".to_string())?;
        let total = pair_count
            .checked_mul(max_hits)
            .ok_or_else(|| "HitAccPool windows size overflow".to_string())?;

        let word_count = pair_count.div_ceil(64);

        // Allocate via Vec, shrink to exact capacity with into_boxed_slice(),
        // then take ownership of the raw pointer via Box::into_raw(). This
        // guarantees the pointer's allocation layout matches the length stored
        // in the struct, regardless of allocator over-provisioning.
        let pair_meta =
            Box::into_raw(vec![PairMeta::ZERO; pair_count].into_boxed_slice()) as *mut PairMeta;

        let windows = Box::into_raw(
            vec![
                SpanU32 {
                    start: 0,
                    end: 0,
                    anchor_hint: 0,
                };
                total
            ]
            .into_boxed_slice(),
        ) as *mut SpanU32;

        let coalesced = Box::into_raw(
            vec![
                SpanU32 {
                    start: 0,
                    end: 0,
                    anchor_hint: 0,
                };
                pair_count
            ]
            .into_boxed_slice(),
        ) as *mut SpanU32;

        let touched_words = Box::into_raw(vec![0u64; word_count].into_boxed_slice()) as *mut u64;

        Ok(Self {
            max_hits: max_hits_u32,
            pair_count: pair_count_u32,
            touched_word_count: word_count as u32,
            _pad: 0,
            pair_meta,
            windows,
            coalesced,
            touched_words,
        })
    }

    #[inline]
    pub(super) fn pair_count(&self) -> usize {
        self.pair_count as usize
    }

    #[inline]
    pub(super) fn max_hits(&self) -> u32 {
        self.max_hits
    }

    /// Clear the touched-bit for each pair in `touched_pairs`.
    ///
    /// O(#touched), not O(pair_count), so reset cost is proportional to work done.
    /// Duplicate indices are harmless (bit clear is idempotent) but callers
    /// should pass the deduplicated output from `mark_touched`.
    #[inline(always)]
    pub(super) fn reset_touched(&mut self, touched_pairs: &[u32]) {
        let words = self.touched_words;
        let pair_count = self.pair_count as usize;
        for &p in touched_pairs {
            let idx = p as usize;
            debug_assert!(idx < pair_count);
            // SAFETY: p < pair_count, so idx / 64 < touched_word_count.
            unsafe {
                let word = words.add(idx / 64);
                *word &= !(1u64 << (idx % 64));
            }
        }
    }

    /// Record `pair` as touched (idempotent). First touch appends to `touched_pairs`.
    ///
    /// The output list remains unique within a scan epoch, enabling `reset_touched`
    /// to clear bits in O(#unique_touched) time.
    ///
    /// # Safety
    ///
    /// - `pair < self.pair_count()` (equivalently, `pair / 64` is in-bounds for
    ///   `touched_words`).
    /// - `touched_pairs` must have spare capacity for at least one more element
    ///   (guaranteed when the caller pre-allocates for `pair_count` entries).
    #[inline(always)]
    unsafe fn mark_touched_unchecked(&mut self, pair: usize, touched_pairs: &mut ScratchVec<u32>) {
        // SAFETY: Caller guarantees `pair < pair_count`, so `pair / 64` is
        // within `touched_words` and all pointer arithmetic is in-bounds.
        let word = self.touched_words.add(pair / 64);
        let bit = 1u64 << (pair % 64);
        if (*word & bit) == 0 {
            *word |= bit;
            touched_pairs.push(pair as u32);
        }
    }

    /// Record a hit window for `pair`, preserving order until capped.
    ///
    /// Once the per-pair cap is exceeded, all hits are coalesced into a single
    /// span that conservatively covers every hit seen so far.
    #[cfg(any(test, feature = "bench", feature = "tiger-harness", kani))]
    #[inline(always)]
    pub(super) fn push_span(
        &mut self,
        pair: usize,
        span: SpanU32,
        touched_pairs: &mut ScratchVec<u32>,
    ) {
        debug_assert!(pair < self.pair_count as usize);
        // SAFETY: `pair < pair_count` is asserted above, and `touched_pairs`
        // is a valid scratch buffer pre-allocated for `pair_count` entries.
        unsafe { self.push_span_unchecked_hot(pair, span, touched_pairs) };
    }

    /// Hot unchecked insertion path used by scan callbacks.
    ///
    /// # Safety
    /// - `pair < self.pair_count()`.
    /// - `touched_pairs` must be valid mutable scratch state for this scan epoch.
    /// - Caller must guarantee single-threaded access to this pool instance.
    #[inline(always)]
    pub(super) unsafe fn push_span_unchecked_hot(
        &mut self,
        pair: usize,
        span: SpanU32,
        touched_pairs: &mut ScratchVec<u32>,
    ) {
        debug_assert!(pair < self.pair_count as usize);
        // SAFETY: Caller guarantees `pair < pair_count` and `touched_pairs`
        // has capacity for at least `pair_count` entries.
        unsafe {
            self.mark_touched_unchecked(pair, touched_pairs);
        }

        // Read len/coalesced as values so the mutable borrow of pair_meta
        // doesn't extend across coalesce_overflow.
        // SAFETY: `pair < pair_count` (caller invariant), so `pair_meta.add(pair)`
        // is within the allocation. The pointer is valid and properly aligned.
        let (len, coalesced) = unsafe {
            let m = &*self.pair_meta.add(pair);
            (m.len as usize, m.coalesced)
        };

        if coalesced != 0 {
            // Expand coalesced window, preserving the earliest anchor hint.
            // SAFETY: `pair < pair_count`, so `coalesced.add(pair)` is in-bounds.
            let c = unsafe { &mut *self.coalesced.add(pair) };
            c.start = c.start.min(span.start);
            c.end = c.end.max(span.end);
            c.anchor_hint = c.anchor_hint.min(span.anchor_hint);
            return;
        }

        let max_hits = self.max_hits as usize;
        if len < max_hits {
            let base = pair * max_hits;
            // SAFETY: `pair < pair_count` and `len < max_hits`, so
            // `base + len` is within the windows allocation. `pair_meta.add(pair)`
            // is in-bounds for the same reason.
            unsafe {
                *self.windows.add(base + len) = span;
                (*self.pair_meta.add(pair)).len = (len + 1) as u16;
            }
            return;
        }

        // Overflow: cold path extracted for branch predictor.
        self.coalesce_overflow(pair, span);
    }

    /// Coalesce all accumulated windows for `pair` into a single span.
    ///
    /// Called when the per-pair hit cap is exceeded. Extracted as a cold path
    /// to keep the fast path in `push_span` compact and branch-predictor
    /// friendly.
    #[cold]
    #[inline(never)]
    fn coalesce_overflow(&mut self, pair: usize, span: SpanU32) {
        let max_hits = self.max_hits as usize;
        // SAFETY: pair < pair_count (caller asserts).
        let meta = unsafe { &mut *self.pair_meta.add(pair) };
        let len = meta.len as usize;
        let base = pair * max_hits;

        let mut lo = span.start;
        let mut hi = span.end;
        let mut min_anchor = span.anchor_hint;

        // SAFETY: base..base+len is within the windows allocation.
        let windows = unsafe { std::slice::from_raw_parts(self.windows.add(base), len) };
        for s in windows {
            lo = lo.min(s.start);
            hi = hi.max(s.end);
            min_anchor = min_anchor.min(s.anchor_hint);
        }

        // SAFETY: pair < pair_count.
        unsafe {
            *self.coalesced.add(pair) = SpanU32 {
                start: lo,
                end: hi,
                anchor_hint: min_anchor,
            };
        }
        meta.coalesced = 1;
        meta.len = 0;
    }

    /// Drain accumulated windows for `pair` into `out`.
    ///
    /// If the pair is coalesced, this returns a single span; otherwise, it
    /// returns the per-hit list in insertion order and resets the count.
    /// The coalesced single-span case intentionally trades ordering/precision
    /// for bounded memory and guaranteed superset coverage.
    #[inline(always)]
    pub(super) fn take_into(&mut self, pair: usize, out: &mut ScratchVec<SpanU32>) {
        debug_assert!(pair < self.pair_count as usize);
        out.clear();

        // SAFETY: pair < pair_count.
        let meta = unsafe { &mut *self.pair_meta.add(pair) };

        if meta.coalesced != 0 {
            // SAFETY: pair < pair_count.
            out.push(unsafe { *self.coalesced.add(pair) });
            meta.coalesced = 0;
            return;
        }

        let len = meta.len as usize;
        if len == 0 {
            return;
        }
        let max_hits = self.max_hits as usize;
        let base = pair * max_hits;
        // SAFETY: base..base+len is within the windows allocation, and
        // SpanU32 is Copy so extend_from_slice is a single memcpy.
        let src = unsafe { std::slice::from_raw_parts(self.windows.add(base), len) };
        out.extend_from_slice(src);
        meta.len = 0;
    }

    /// Clears all accumulated state for `pair` without returning windows.
    #[inline(always)]
    pub(super) fn reset_pair(&mut self, pair: usize) {
        debug_assert!(pair < self.pair_count as usize);
        // SAFETY: pair < pair_count.
        let meta = unsafe { &mut *self.pair_meta.add(pair) };
        meta.len = 0;
        meta.coalesced = 0;
    }

    // Test-only accessors for internal state verification
    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn is_coalesced(&self, pair: usize) -> bool {
        debug_assert!(pair < self.pair_count as usize);
        // SAFETY: `pair < pair_count` is asserted above, so `pair_meta.add(pair)` is in-bounds.
        unsafe { (*self.pair_meta.add(pair)).coalesced != 0 }
    }

    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn pair_len(&self, pair: usize) -> u32 {
        debug_assert!(pair < self.pair_count as usize);
        // SAFETY: `pair < pair_count` is asserted above, so `pair_meta.add(pair)` is in-bounds.
        unsafe { (*self.pair_meta.add(pair)).len as u32 }
    }

    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn coalesced_span(&self, pair: usize) -> SpanU32 {
        debug_assert!(pair < self.pair_count as usize);
        // SAFETY: `pair < pair_count` is asserted above, so `coalesced.add(pair)` is in-bounds.
        unsafe { *self.coalesced.add(pair) }
    }

    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn window_at(&self, pair: usize, idx: usize) -> SpanU32 {
        let base = pair * self.max_hits as usize;
        debug_assert!(base + idx < (self.pair_count as usize) * (self.max_hits as usize));
        // SAFETY: `base + idx` is within the allocated window buffer as asserted above.
        unsafe { *self.windows.add(base + idx) }
    }
}

/// Benchmark harness wrapping [`HitAccPool`] with co-allocated scratch buffers.
///
/// Bundles the pool, touched-pair tracker, and output buffer so that Criterion
/// benchmarks can call `push` / `take` / `reset` without managing scratch state.
#[cfg(feature = "bench")]
pub struct BenchHitAccPool {
    pool: HitAccPool,
    touched: ScratchVec<u32>,
    output: ScratchVec<SpanU32>,
}

#[cfg(feature = "bench")]
impl BenchHitAccPool {
    /// Builds a benchmark-only accumulator wrapper.
    ///
    /// Panics if internal scratch allocations fail.
    pub fn new(pair_count: usize, max_hits: usize) -> Self {
        Self {
            pool: HitAccPool::new(pair_count, max_hits).expect("bench pool alloc"),
            touched: ScratchVec::with_capacity(pair_count).expect("bench touched alloc"),
            output: ScratchVec::with_capacity(max_hits).expect("bench output alloc"),
        }
    }

    /// Push one window for a `(rule, variant)` pair.
    ///
    /// Panics if `pair >= pair_count`.
    #[inline(always)]
    pub fn push(&mut self, pair: usize, start: u32, end: u32, hint: u32) {
        assert!(
            pair < self.pool.pair_count(),
            "pair index {} out of range (pair_count={})",
            pair,
            self.pool.pair_count()
        );
        self.pool.push_span(
            pair,
            SpanU32 {
                start,
                end,
                anchor_hint: hint,
            },
            &mut self.touched,
        );
    }

    /// Drains windows for `pair` and returns the number of drained spans.
    ///
    /// Panics if `pair >= pair_count`.
    #[inline(always)]
    pub fn take(&mut self, pair: usize) -> usize {
        assert!(
            pair < self.pool.pair_count(),
            "pair index {} out of range (pair_count={})",
            pair,
            self.pool.pair_count()
        );
        self.pool.take_into(pair, &mut self.output);
        self.output.len()
    }

    /// Resets all touched-pair state in the wrapped pool.
    pub fn reset(&mut self) {
        for &p in self.touched.as_slice() {
            self.pool.reset_pair(p as usize);
        }
        self.pool.reset_touched(self.touched.as_slice());
        self.touched.clear();
    }
}

/// Fuzz harness wrapping [`HitAccPool`] for use by fuzz targets.
///
/// Similar to [`BenchHitAccPool`] but with fuzz-friendly semantics: `new`
/// returns `Option` instead of panicking, `push`/`take` clamp the pair index
/// instead of asserting, and an extra `pair_count()` accessor is exposed.
#[cfg(feature = "tiger-harness")]
pub struct FuzzHitAccPool {
    pool: HitAccPool,
    touched: ScratchVec<u32>,
    output: ScratchVec<SpanU32>,
}

#[cfg(feature = "tiger-harness")]
impl FuzzHitAccPool {
    /// Builds a fuzz-only accumulator wrapper.
    ///
    /// Returns `None` if allocation fails (fuzz targets should bail on `None`).
    pub fn new(pair_count: usize, max_hits: usize) -> Option<Self> {
        let pool = HitAccPool::new(pair_count, max_hits).ok()?;
        let touched = ScratchVec::<u32>::with_capacity(pair_count).ok()?;
        let output = ScratchVec::<SpanU32>::with_capacity(max_hits).ok()?;
        Some(Self {
            pool,
            touched,
            output,
        })
    }

    /// Push one window. `pair` is clamped to `pair_count - 1`.
    pub fn push(&mut self, pair: usize, start: u32, end: u32, hint: u32) {
        let pair = pair % self.pool.pair_count().max(1);
        let (start, end) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        let hint = hint.clamp(start, end);
        self.pool.push_span(
            pair,
            SpanU32 {
                start,
                end,
                anchor_hint: hint,
            },
            &mut self.touched,
        );
    }

    /// Drain windows for `pair`.
    pub fn take(&mut self, pair: usize) -> usize {
        let pair = pair % self.pool.pair_count().max(1);
        self.pool.take_into(pair, &mut self.output);
        self.output.len()
    }

    /// Reset all touched-pair state.
    pub fn reset(&mut self) {
        for &p in self.touched.as_slice() {
            self.pool.reset_pair(p as usize);
        }
        self.pool.reset_touched(self.touched.as_slice());
        self.touched.clear();
    }

    /// Returns the pair count.
    pub fn pair_count(&self) -> usize {
        self.pool.pair_count()
    }
}

// ---------------------------------------------------------------------------
// Miri-compatible unit tests (no FFI, no feature gates)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_span(start: u32, end: u32) -> SpanU32 {
        SpanU32 {
            start,
            end,
            anchor_hint: start,
        }
    }

    /// Exercises construction, push, take, reset, and Drop for a single pair.
    /// Under Miri this validates the raw-pointer allocation / deallocation
    /// round-trip (issue 2) and basic memory safety.
    #[test]
    fn miri_single_pair_lifecycle() {
        let mut pool = HitAccPool::new(1, 4).unwrap();
        let mut touched = ScratchVec::<u32>::with_capacity(1).unwrap();
        let mut out = ScratchVec::<SpanU32>::with_capacity(4).unwrap();

        // Push 3 spans (below cap).
        for i in 0..3u32 {
            pool.push_span(0, make_span(i * 10, i * 10 + 5), &mut touched);
        }
        assert_eq!(touched.len(), 1);

        // Take and verify.
        pool.take_into(0, &mut out);
        assert_eq!(out.len(), 3);
        assert_eq!(out.as_slice()[0], make_span(0, 5));
        assert_eq!(out.as_slice()[2], make_span(20, 25));

        // Reset for next round.
        pool.reset_pair(0);
        pool.reset_touched(touched.as_slice());
        touched.clear();

        // Pool drops here — validates Drop impl.
    }

    /// Pushes past the per-pair cap to trigger `coalesce_overflow`, then
    /// drains via `take_into`. This exercises the `push_span` → cold
    /// `coalesce_overflow` transition (issue 3: Stacked Borrows concern).
    #[test]
    fn miri_coalesce_overflow_path() {
        let max_hits = 4;
        let mut pool = HitAccPool::new(1, max_hits).unwrap();
        let mut touched = ScratchVec::<u32>::with_capacity(1).unwrap();
        let mut out = ScratchVec::<SpanU32>::with_capacity(max_hits).unwrap();

        // Push exactly max_hits spans (fills without coalescing).
        for i in 0..max_hits as u32 {
            pool.push_span(0, make_span(i * 100, i * 100 + 50), &mut touched);
        }

        // Push one more — triggers coalesce_overflow.
        pool.push_span(0, make_span(500, 600), &mut touched);

        // Take: should return a single coalesced span.
        pool.take_into(0, &mut out);
        assert_eq!(out.len(), 1);
        let coalesced = out.as_slice()[0];
        assert_eq!(coalesced.start, 0);
        assert_eq!(coalesced.end, 600);
        assert_eq!(coalesced.anchor_hint, 0);

        pool.reset_pair(0);
        pool.reset_touched(touched.as_slice());
        touched.clear();
    }

    /// Multi-pair test: exercises stride arithmetic (`pair * max_hits`)
    /// and multi-word touched bitset operations (pair_count > 64).
    #[test]
    fn miri_multi_pair_stride_and_bitset() {
        let pair_count = 65; // Crosses the 64-bit word boundary.
        let max_hits = 4;
        let mut pool = HitAccPool::new(pair_count, max_hits).unwrap();
        let mut touched = ScratchVec::<u32>::with_capacity(pair_count).unwrap();
        let mut out = ScratchVec::<SpanU32>::with_capacity(max_hits).unwrap();

        // Push to pair 0 (first word, bit 0).
        pool.push_span(0, make_span(10, 20), &mut touched);
        // Push to pair 63 (first word, bit 63).
        pool.push_span(63, make_span(30, 40), &mut touched);
        // Push to pair 64 (second word, bit 0).
        pool.push_span(64, make_span(50, 60), &mut touched);

        assert_eq!(touched.len(), 3);

        // Verify each pair independently.
        pool.take_into(0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out.as_slice()[0], make_span(10, 20));

        pool.take_into(63, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out.as_slice()[0], make_span(30, 40));

        pool.take_into(64, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out.as_slice()[0], make_span(50, 60));

        // Reset all touched pairs.
        for &p in touched.as_slice() {
            pool.reset_pair(p as usize);
        }
        pool.reset_touched(touched.as_slice());
        touched.clear();
    }

    /// Edge case: pair_count = 0 should construct and drop without panicking.
    #[test]
    fn miri_zero_pair_count() {
        let pool = HitAccPool::new(0, 8).unwrap();
        drop(pool);
    }

    /// Constructor rejects max_hits = 0.
    #[test]
    fn rejects_zero_max_hits() {
        assert!(HitAccPool::new(10, 0).is_err());
    }

    /// Constructor rejects max_hits > u16::MAX (PairMeta.len overflow).
    #[test]
    fn rejects_max_hits_exceeding_u16() {
        assert!(HitAccPool::new(1, u16::MAX as usize + 1).is_err());
    }

    #[test]
    fn unsafe_hot_path_matches_safe_behavior() {
        let pair_count = 4usize;
        let max_hits = 3usize;
        let mut pool_safe = HitAccPool::new(pair_count, max_hits).unwrap();
        let mut pool_hot = HitAccPool::new(pair_count, max_hits).unwrap();
        let mut touched_safe = ScratchVec::<u32>::with_capacity(pair_count).unwrap();
        let mut touched_hot = ScratchVec::<u32>::with_capacity(pair_count).unwrap();
        let mut out_safe = ScratchVec::<SpanU32>::with_capacity(max_hits).unwrap();
        let mut out_hot = ScratchVec::<SpanU32>::with_capacity(max_hits).unwrap();

        let ops = [
            (0usize, make_span(10, 20)),
            (1usize, make_span(15, 25)),
            (0usize, make_span(30, 40)),
            (2usize, make_span(5, 9)),
            (0usize, make_span(50, 60)),
            (0usize, make_span(55, 80)), // overflow/coalesce for pair 0
            (1usize, make_span(2, 100)),
            (1usize, make_span(3, 110)),
            (1usize, make_span(1, 120)), // overflow/coalesce for pair 1
            (3usize, make_span(7, 8)),
        ];

        for (pair, span) in ops {
            pool_safe.push_span(pair, span, &mut touched_safe);
            // SAFETY: `pair` values are all < `pair_count` (4), `touched_hot` has
            // capacity for `pair_count` entries, and we have exclusive access.
            unsafe {
                pool_hot.push_span_unchecked_hot(pair, span, &mut touched_hot);
            }
        }

        assert_eq!(touched_safe.as_slice(), touched_hot.as_slice());

        for pair in 0..pair_count {
            pool_safe.take_into(pair, &mut out_safe);
            pool_hot.take_into(pair, &mut out_hot);
            assert_eq!(out_safe.as_slice(), out_hot.as_slice(), "pair={pair}");
        }
    }

    #[test]
    fn new_rejects_max_hits_u32_overflow() {
        match HitAccPool::new(1, (u32::MAX as usize) + 1) {
            Ok(_) => panic!("max_hits values above u32::MAX must be rejected"),
            Err(err) => assert!(
                err.contains("max_hits exceeds u32::MAX"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn new_rejects_windows_size_overflow() {
        match HitAccPool::new((usize::MAX / 2) + 1, 2) {
            Ok(_) => panic!("pair_count * max_hits overflow must be rejected"),
            Err(err) => assert!(
                err.contains("HitAccPool windows size overflow"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn new_rejects_pair_count_u32_overflow() {
        match HitAccPool::new((u32::MAX as usize) + 1, 2) {
            Ok(_) => panic!("pair_count values above u32::MAX must be rejected"),
            Err(err) => assert!(
                err.contains("pair_count exceeds u32::MAX"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn new_prefers_pair_count_overflow_guard_on_64bit() {
        match HitAccPool::new((usize::MAX / 2) + 1, 2) {
            Ok(_) => panic!("pair_count values above u32::MAX must be rejected"),
            Err(err) => assert!(
                err.contains("pair_count exceeds u32::MAX"),
                "unexpected error: {err}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Kani model-checking proofs
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod verification {
    use super::*;

    // Kani proofs use concrete allocation sizes to avoid symbolic Vec
    // allocation blowup (symbolic pair_count/max_hits cause CBMC to model
    // all possible allocation sizes simultaneously, consuming 60GB+ RAM).
    // The pair index and span values remain symbolic, which is what matters:
    // it proves the pointer arithmetic in push_span / take_into / reset
    // is safe for any valid `pair < pair_count` and any span values.

    const PAIR_COUNT: usize = 3;
    const MAX_HITS: usize = 2;

    /// Proves that `push_span` never causes OOB access for any valid
    /// `pair < pair_count` and any span values.
    #[kani::proof]
    #[kani::unwind(8)]
    fn verify_push_span_bounds() {
        let mut pool = HitAccPool::new(PAIR_COUNT, MAX_HITS).unwrap();
        let mut touched = ScratchVec::<u32>::with_capacity(PAIR_COUNT).unwrap();

        let pair: usize = kani::any();
        kani::assume(pair < PAIR_COUNT);

        let start: u32 = kani::any();
        let end: u32 = kani::any();
        kani::assume(start <= end);

        let span = SpanU32 {
            start,
            end,
            anchor_hint: start,
        };
        pool.push_span(pair, span, &mut touched);
        // Kani proves: no OOB, no UB for any pair and span.
    }

    /// Proves that pushing past the per-pair cap triggers the coalesce
    /// path without OOB access.
    #[kani::proof]
    #[kani::unwind(8)]
    fn verify_coalesce_overflow_bounds() {
        let mut pool = HitAccPool::new(PAIR_COUNT, MAX_HITS).unwrap();
        let mut touched = ScratchVec::<u32>::with_capacity(PAIR_COUNT).unwrap();

        let pair: usize = kani::any();
        kani::assume(pair < PAIR_COUNT);

        // Push MAX_HITS + 1 spans to trigger coalesce.
        for i in 0..MAX_HITS + 1 {
            pool.push_span(
                pair,
                SpanU32 {
                    start: i as u32,
                    end: (i + 10) as u32,
                    anchor_hint: i as u32,
                },
                &mut touched,
            );
        }
        // Kani proves: coalesce path has no OOB.
    }

    /// Proves that `take_into` never reads OOB for any valid pair,
    /// regardless of how many spans were pushed.
    #[kani::proof]
    #[kani::unwind(8)]
    fn verify_take_into_bounds() {
        let mut pool = HitAccPool::new(PAIR_COUNT, MAX_HITS).unwrap();
        let mut touched = ScratchVec::<u32>::with_capacity(PAIR_COUNT).unwrap();
        let mut out = ScratchVec::<SpanU32>::with_capacity(MAX_HITS).unwrap();

        let pair: usize = kani::any();
        kani::assume(pair < PAIR_COUNT);

        let push_count: usize = kani::any();
        kani::assume(push_count <= MAX_HITS);

        for i in 0..push_count {
            pool.push_span(
                pair,
                SpanU32 {
                    start: i as u32,
                    end: (i + 1) as u32,
                    anchor_hint: i as u32,
                },
                &mut touched,
            );
        }

        pool.take_into(pair, &mut out);
        // Kani proves: take_into reads only valid memory.
    }

    /// Proves that `reset_touched` never writes OOB in the touched_words
    /// bitset.
    #[kani::proof]
    #[kani::unwind(8)]
    fn verify_reset_touched_bounds() {
        let mut pool = HitAccPool::new(PAIR_COUNT, MAX_HITS).unwrap();
        let mut touched = ScratchVec::<u32>::with_capacity(PAIR_COUNT).unwrap();

        let pair: usize = kani::any();
        kani::assume(pair < PAIR_COUNT);

        pool.push_span(
            pair,
            SpanU32 {
                start: 0,
                end: 10,
                anchor_hint: 0,
            },
            &mut touched,
        );

        pool.reset_touched(touched.as_slice());
        // Kani proves: reset_touched never writes OOB.
    }
}
