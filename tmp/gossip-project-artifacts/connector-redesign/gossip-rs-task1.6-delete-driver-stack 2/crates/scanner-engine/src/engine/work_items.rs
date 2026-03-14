//! Work queue types for transform/scan traversal.
//!
//! Contains buffer references, pending decode spans, pending windows, and work
//! item types used for breadth-first traversal during scanning. Range values
//! are half-open `[lo, hi)` in their respective address spaces and are only
//! valid for the current scan (decode slab resets invalidate slab ranges).
//!
//! `PendingWindow` ordering is intentionally reversed so a max-heap behaves as
//! a min-heap keyed by earliest window end.
//!
//! # Lifetime model
//! - `Slab` ranges are only valid until the decode slab is reset/truncated.
//! - Root ranges are tied to the current input buffer.
//!
//! # WorkItem layout (40 bytes)
//!
//! WorkItem is packed into a flat 40-byte struct to maximize cache-line
//! utilization in the hot work-queue loop. Sentinel values replace `Option`
//! and enum discriminants:
//!
//! ```text
//! offset  field            sentinel meaning
//! ------  --------------   -----------------------
//!   0     flags: u8        bit 0 = is_decode_span
//!                          bit 1 = buf_is_slab
//!                          bit 2 = has_enc_ref
//!                          bit 3 = enc_is_slab
//!                          bit 4 = has_root_hint
//!                          bit 5 = has_transform_idx
//!   1     depth: u8        max 7 (MAX_DECODE_STEPS-1)
//!   2     transform_idx: u16
//!   4     step_id: u32
//!   8     buf_lo: u32      NONE_U32 for Root buf
//!  12     buf_hi: u32      NONE_U32 for Root buf
//!  16     enc_lo: u32      NONE_U32 when absent
//!  20     enc_hi: u32      NONE_U32 when absent
//!  24     root_hint_lo: u64   NONE_U64 when absent
//!  32     root_hint_hi: u64   NONE_U64 when absent
//! ```

use crate::api::{STEP_ROOT, StepId};
use std::ops::Range;

use super::rule_repr::Variant;
use super::transform::{Base64SpanStream, UrlSpanStream};

const NONE_U32: u32 = u32::MAX;
const NONE_U64: u64 = u64::MAX;

// -- Flag bit positions ---------------------------------------------------
const FLAG_IS_DECODE_SPAN: u8 = 1 << 0;
const FLAG_BUF_IS_SLAB: u8 = 1 << 1;
const FLAG_HAS_ENC_REF: u8 = 1 << 2;
const FLAG_ENC_IS_SLAB: u8 = 1 << 3;
const FLAG_HAS_ROOT_HINT: u8 = 1 << 4;
const FLAG_HAS_TRANSFORM_IDX: u8 = 1 << 5;

/// Work item in the transform/scan queue.
///
/// Flat, `Copy` representation replacing the former enum+nested-enum layout
/// (104B → 40B). All fields are plain integers (no heap pointers, no `Drop`),
/// so the work-queue loop dequeues via bitwise copy without writing a default
/// back to the slot. Sentinel values (`NONE_U32`/`NONE_U64`) mark absent
/// optional fields, and a flags byte encodes variant/presence bits.
///
/// Two logical variants exist, distinguished by `FLAG_IS_DECODE_SPAN`:
///
/// - **ScanBuf** (`!is_decode_span`): scan a buffer (root or slab).
///   `buf_lo`/`buf_hi` specify the slab range (or `NONE_U32` for root).
///   `enc_lo`/`enc_hi`/`transform_idx`/`root_hint` are optional.
///
/// - **DecodeSpan** (`is_decode_span`): decode an encoded span and scan.
///   `enc_lo`/`enc_hi` always set. `buf_lo`/`buf_hi` unused (`NONE_U32`).
///
/// # Invariants
/// - `depth <= 7` (enforced at engine build time via `max_transform_depth`).
/// - Buffer and enc ranges are half-open `[lo, hi)` in u32 space; callers
///   must chunk inputs so any single buffer fits in `u32::MAX` bytes.
/// - `root_hint_lo`/`root_hint_hi` are u64 file offsets (files can exceed 4GB).
/// - `step_id` is only valid while the originating scratch arena is alive.
#[derive(Clone, Copy)]
pub(super) struct WorkItem {
    flags: u8,
    depth: u8,
    transform_idx: u16,
    step_id: StepId, // u32 internally
    buf_lo: u32,
    buf_hi: u32,
    enc_lo: u32,
    enc_hi: u32,
    root_hint_lo: u64,
    root_hint_hi: u64,
}

const _: () = assert!(std::mem::size_of::<WorkItem>() <= 40);

impl WorkItem {
    // -- Constructors -----------------------------------------------------

    /// Root buffer scan (initial work item).
    #[inline(always)]
    pub(super) fn scan_root() -> Self {
        Self {
            flags: 0,
            depth: 0,
            transform_idx: 0,
            step_id: STEP_ROOT,
            buf_lo: NONE_U32,
            buf_hi: NONE_U32,
            enc_lo: NONE_U32,
            enc_hi: NONE_U32,
            root_hint_lo: NONE_U64,
            root_hint_hi: NONE_U64,
        }
    }

    /// Slab-backed buffer scan with full provenance.
    #[inline(always)]
    pub(super) fn scan_slab(
        slab_range: Range<u32>,
        step_id: StepId,
        root_hint: Option<Range<u64>>,
        transform_idx: Option<u16>,
        enc_ref: Option<EncRef>,
        depth: u8,
    ) -> Self {
        let mut flags = FLAG_BUF_IS_SLAB;
        if root_hint.is_some() {
            flags |= FLAG_HAS_ROOT_HINT;
        }
        if transform_idx.is_some() {
            flags |= FLAG_HAS_TRANSFORM_IDX;
        }
        let (enc_lo, enc_hi) = match enc_ref {
            Some(EncRef { lo, hi, is_slab }) => {
                flags |= FLAG_HAS_ENC_REF;
                if is_slab {
                    flags |= FLAG_ENC_IS_SLAB;
                }
                (lo, hi)
            }
            None => (NONE_U32, NONE_U32),
        };
        let (root_hint_lo, root_hint_hi) = match root_hint {
            Some(r) => (r.start, r.end),
            None => (NONE_U64, NONE_U64),
        };
        Self {
            flags,
            depth,
            transform_idx: transform_idx.unwrap_or(0),
            step_id,
            buf_lo: slab_range.start,
            buf_hi: slab_range.end,
            enc_lo,
            enc_hi,
            root_hint_lo,
            root_hint_hi,
        }
    }

    /// Decode-span work item.
    #[inline(always)]
    pub(super) fn decode_span(
        transform_idx: u16,
        enc_ref: EncRef,
        step_id: StepId,
        root_hint: Option<Range<u64>>,
        depth: u8,
    ) -> Self {
        let mut flags = FLAG_IS_DECODE_SPAN | FLAG_HAS_ENC_REF | FLAG_HAS_TRANSFORM_IDX;
        if enc_ref.is_slab {
            flags |= FLAG_ENC_IS_SLAB;
        }
        if root_hint.is_some() {
            flags |= FLAG_HAS_ROOT_HINT;
        }
        let (root_hint_lo, root_hint_hi) = match root_hint {
            Some(r) => (r.start, r.end),
            None => (NONE_U64, NONE_U64),
        };
        Self {
            flags,
            depth,
            transform_idx,
            step_id,
            buf_lo: NONE_U32,
            buf_hi: NONE_U32,
            enc_lo: enc_ref.lo,
            enc_hi: enc_ref.hi,
            root_hint_lo,
            root_hint_hi,
        }
    }

    // -- Queries ----------------------------------------------------------

    #[inline(always)]
    pub(super) fn is_decode_span(&self) -> bool {
        self.flags & FLAG_IS_DECODE_SPAN != 0
    }

    #[inline(always)]
    pub(super) fn depth(&self) -> u8 {
        self.depth
    }

    #[inline(always)]
    pub(super) fn step_id(&self) -> StepId {
        self.step_id
    }

    /// Returns the slab buffer range, or `None` for root buffer.
    #[inline(always)]
    pub(super) fn buf_slab_range(&self) -> Option<Range<u32>> {
        if self.flags & FLAG_BUF_IS_SLAB != 0 {
            Some(self.buf_lo..self.buf_hi)
        } else {
            None
        }
    }

    #[inline(always)]
    pub(super) fn transform_idx(&self) -> Option<u16> {
        if self.flags & FLAG_HAS_TRANSFORM_IDX != 0 {
            Some(self.transform_idx)
        } else {
            None
        }
    }

    #[inline(always)]
    pub(super) fn enc_ref(&self) -> Option<EncRef> {
        if self.flags & FLAG_HAS_ENC_REF != 0 {
            Some(EncRef {
                lo: self.enc_lo,
                hi: self.enc_hi,
                is_slab: self.flags & FLAG_ENC_IS_SLAB != 0,
            })
        } else {
            None
        }
    }

    #[inline(always)]
    pub(super) fn root_hint(&self) -> Option<Range<u64>> {
        if self.flags & FLAG_HAS_ROOT_HINT != 0 {
            Some(self.root_hint_lo..self.root_hint_hi)
        } else {
            None
        }
    }
}

impl Default for WorkItem {
    fn default() -> Self {
        Self::scan_root()
    }
}

/// Compact encoded-span reference (12 bytes).
///
/// Replaces the former `EncRef` enum (24 bytes). The `is_slab` flag
/// distinguishes root-buffer ranges from slab ranges.
///
/// # Invariants
/// - Ranges are half-open `[lo, hi)`.
/// - `is_slab == false` -> range indexes into the root input buffer.
/// - `is_slab == true`  -> range indexes into the decode slab.
#[derive(Clone, Copy)]
pub(super) struct EncRef {
    pub(super) lo: u32,
    pub(super) hi: u32,
    pub(super) is_slab: bool,
}

impl EncRef {
    #[inline(always)]
    pub(super) fn root(range: Range<u32>) -> Self {
        Self {
            lo: range.start,
            hi: range.end,
            is_slab: false,
        }
    }

    #[inline(always)]
    pub(super) fn slab(range: Range<u32>) -> Self {
        Self {
            lo: range.start,
            hi: range.end,
            is_slab: true,
        }
    }

    #[inline(always)]
    pub(super) fn range_usize(&self) -> Range<usize> {
        self.lo as usize..self.hi as usize
    }
}

/// Pending decode span captured during streaming decode.
///
/// These spans are produced incrementally from streaming transforms and later
/// enqueued as decode work. `root_hint` stores the originating root span to
/// preserve provenance when emitting findings.
///
/// # Invariants
/// - `range` indexes into the decode slab for the current scan (u32 space).
/// - `depth` is bounded by the transform depth limit.
#[derive(Clone, Copy)]
pub(super) struct PendingDecodeSpan {
    pub(super) transform_idx: u16,
    pub(super) depth: u8,
    pub(super) step_id: StepId,
    pub(super) range_lo: u32,
    pub(super) range_hi: u32,
    pub(super) root_hint_lo: u64,
    pub(super) root_hint_hi: u64,
}

impl PendingDecodeSpan {
    #[inline(always)]
    pub(super) fn new(
        transform_idx: u16,
        range: Range<u32>,
        step_id: StepId,
        root_hint: Option<Range<u64>>,
        depth: u8,
    ) -> Self {
        let (root_hint_lo, root_hint_hi) = match root_hint {
            Some(r) => (r.start, r.end),
            None => (NONE_U64, NONE_U64),
        };
        Self {
            transform_idx,
            depth,
            step_id,
            range_lo: range.start,
            range_hi: range.end,
            root_hint_lo,
            root_hint_hi,
        }
    }

    #[inline(always)]
    pub(super) fn range(&self) -> Range<u32> {
        self.range_lo..self.range_hi
    }

    #[inline(always)]
    pub(super) fn root_hint(&self) -> Option<Range<u64>> {
        if self.root_hint_lo == NONE_U64 {
            None
        } else {
            Some(self.root_hint_lo..self.root_hint_hi)
        }
    }
}

/// Pending decoded-space window produced by stream scanning.
///
/// Offsets are in decoded-byte space (relative to the stream) and are
/// half-open: `[lo, hi)`.
///
/// # Fields
/// - `anchor_hint`: Vectorscan's `from` match offset in decoded-byte space.
///   Used to start regex searches near the anchor instead of at window start.
///
/// # Ordering
/// - Ordered by earliest `hi`, then `lo`, then `(rule_id, variant)` so priority
///   queues drain windows as soon as their end offset is reached.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct PendingWindow {
    pub(super) hi: u64,
    pub(super) lo: u64,
    pub(super) rule_id: u32,
    pub(super) variant: Variant,
    /// Anchor hint from Vectorscan's `from` offset.
    pub(super) anchor_hint: u64,
}

impl Ord for PendingWindow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .hi
            .cmp(&self.hi)
            .then_with(|| other.lo.cmp(&self.lo))
            .then_with(|| other.rule_id.cmp(&self.rule_id))
            .then_with(|| (other.variant.idx()).cmp(&self.variant.idx()))
    }
}

impl PartialOrd for PendingWindow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Streaming span detector state for nested transforms.
///
/// Each variant tracks incremental parsing state so we can emit spans while
/// decoding without rescanning the full buffer.
pub(super) enum SpanStreamState {
    Url(UrlSpanStream),
    Base64(Base64SpanStream),
}

/// Per-transform span stream bookkeeping during decoded scanning.
///
/// Tracks per-buffer span caps and transform modes alongside the stream state.
///
/// # Invariants
/// - `spans_emitted <= max_spans` for the current buffer.
pub(super) struct SpanStreamEntry {
    pub(super) transform_idx: usize,
    pub(super) state: SpanStreamState,
    pub(super) spans_emitted: usize, // Spans emitted so far for this buffer.
    pub(super) max_spans: usize,     // Per-buffer cap for this transform.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_item_size() {
        assert!(
            std::mem::size_of::<WorkItem>() <= 40,
            "WorkItem grew beyond 40 bytes: {}",
            std::mem::size_of::<WorkItem>()
        );
    }

    #[test]
    fn pending_decode_span_size() {
        assert!(
            std::mem::size_of::<PendingDecodeSpan>() <= 32,
            "PendingDecodeSpan grew beyond 32 bytes: {}",
            std::mem::size_of::<PendingDecodeSpan>()
        );
    }

    #[test]
    fn work_item_round_trip_scan_root() {
        let item = WorkItem::scan_root();
        assert!(!item.is_decode_span());
        assert_eq!(item.depth(), 0);
        assert_eq!(item.step_id(), STEP_ROOT);
        assert!(item.buf_slab_range().is_none());
        assert!(item.transform_idx().is_none());
        assert!(item.enc_ref().is_none());
        assert!(item.root_hint().is_none());
    }

    #[test]
    fn work_item_round_trip_scan_slab() {
        let item = WorkItem::scan_slab(
            100..200,
            StepId(42),
            Some(1000..2000),
            Some(1),
            Some(EncRef::root(50..150)),
            3,
        );
        assert!(!item.is_decode_span());
        assert_eq!(item.depth(), 3);
        assert_eq!(item.step_id(), StepId(42));
        assert_eq!(item.buf_slab_range(), Some(100..200));
        assert_eq!(item.transform_idx(), Some(1));
        let enc = item.enc_ref().unwrap();
        assert!(!enc.is_slab);
        assert_eq!(enc.lo, 50);
        assert_eq!(enc.hi, 150);
        assert_eq!(item.root_hint(), Some(1000..2000));
    }

    #[test]
    fn work_item_round_trip_decode_span() {
        let item = WorkItem::decode_span(0, EncRef::slab(300..400), StepId(7), Some(5000..6000), 2);
        assert!(item.is_decode_span());
        assert_eq!(item.depth(), 2);
        assert_eq!(item.step_id(), StepId(7));
        assert_eq!(item.transform_idx(), Some(0));
        let enc = item.enc_ref().unwrap();
        assert!(enc.is_slab);
        assert_eq!(enc.lo, 300);
        assert_eq!(enc.hi, 400);
        assert_eq!(item.root_hint(), Some(5000..6000));
    }

    #[test]
    fn pending_decode_span_round_trip() {
        let pds = PendingDecodeSpan::new(1, 100..200, StepId(5), Some(1000..2000), 3);
        assert_eq!(pds.range(), 100..200);
        assert_eq!(pds.root_hint(), Some(1000..2000));

        let pds_no_hint = PendingDecodeSpan::new(0, 0..50, StepId(0), None, 0);
        assert!(pds_no_hint.root_hint().is_none());
    }
}
