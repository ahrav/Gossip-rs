//! Decode provenance and output storage.
//!
//! This module contains data structures for tracking the decode step chain
//! (provenance) and storing decoded output bytes during transform scanning.
//!
//! Both [`StepArena`] and [`DecodeSlab`] are owned by [`ScanScratch`] and
//! share its lifecycle: they are cleared between scans via `reset()` and
//! never reallocate during a scan. This invariant is critical for the raw-
//! pointer aliasing in `scan_chunk_into`'s work-queue loop.

use crate::api::{DecodeStep, STEP_ROOT, StepId, Utf16Endianness};
use crate::scratch_memory::ScratchVec;
use std::ops::{ControlFlow, Range};

use super::transform::stream_decode;
use crate::api::TransformConfig;

/// Arena-internal compact decode step (12 bytes vs 32 bytes for [`DecodeStep`]).
///
/// The public [`DecodeStep`] uses `usize` spans and an enum with `Range<usize>`
/// fields, which costs 32 bytes on 64-bit targets. This compact form uses `u32`
/// spans (safe because buffers are capped at `u32::MAX`) and packs the
/// discriminant + payload index into a single `u32`, yielding 12 bytes total.
///
/// Bit layout of `tag_and_idx`:
///   - Bit 31: 0 = Transform, 1 = Utf16Window
///   - Bits 30..0: transform_idx (Transform) or endianness ordinal (Utf16Window)
#[derive(Clone, Copy)]
struct CompactDecodeStep {
    tag_and_idx: u32,
    span_start: u32,
    span_end: u32,
}

const TAG_UTF16: u32 = 1 << 31;

impl CompactDecodeStep {
    fn from_decode_step(step: &DecodeStep) -> Self {
        match step {
            DecodeStep::Transform {
                transform_idx,
                parent_span,
            } => {
                assert!(
                    *transform_idx < (1 << 31),
                    "transform_idx {} overflows CompactDecodeStep (max {})",
                    transform_idx,
                    (1u32 << 31) - 1
                );
                debug_assert!(
                    parent_span.start <= u32::MAX as usize,
                    "span_start overflows u32"
                );
                debug_assert!(
                    parent_span.end <= u32::MAX as usize,
                    "span_end overflows u32"
                );
                Self {
                    tag_and_idx: *transform_idx as u32,
                    span_start: parent_span.start as u32,
                    span_end: parent_span.end as u32,
                }
            }
            DecodeStep::Utf16Window {
                endianness,
                parent_span,
            } => {
                debug_assert!(
                    parent_span.start <= u32::MAX as usize,
                    "span_start overflows u32"
                );
                debug_assert!(
                    parent_span.end <= u32::MAX as usize,
                    "span_end overflows u32"
                );
                let e = match endianness {
                    Utf16Endianness::Le => 0u32,
                    Utf16Endianness::Be => 1u32,
                };
                Self {
                    tag_and_idx: TAG_UTF16 | e,
                    span_start: parent_span.start as u32,
                    span_end: parent_span.end as u32,
                }
            }
        }
    }

    /// Returns a variant discriminant for dedup: 1=UTF-16 LE, 2=UTF-16 BE, 0=other.
    fn variant_discriminant(self) -> u8 {
        if self.tag_and_idx & TAG_UTF16 != 0 {
            match self.tag_and_idx & !TAG_UTF16 {
                0 => 1, // Le
                1 => 2, // Be
                _ => 0,
            }
        } else {
            0
        }
    }

    fn to_decode_step(self) -> DecodeStep {
        let span = (self.span_start as usize)..(self.span_end as usize);
        if self.tag_and_idx & TAG_UTF16 == 0 {
            DecodeStep::Transform {
                transform_idx: self.tag_and_idx as usize,
                parent_span: span,
            }
        } else {
            let e = match self.tag_and_idx & !TAG_UTF16 {
                0 => Utf16Endianness::Le,
                1 => Utf16Endianness::Be,
                _ => unreachable!("invalid endianness bits in CompactDecodeStep"),
            };
            DecodeStep::Utf16Window {
                endianness: e,
                parent_span: span,
            }
        }
    }
}

/// Node in the decode-step arena, linking to its parent step.
///
/// Each node records a single decode operation and a back-pointer to its
/// parent step. `StepId` values are indices into `StepArena::nodes`; the
/// chain terminates when `parent == STEP_ROOT` (a sentinel, not a valid index).
/// This sentinel approach avoids an `Option<StepId>` wrapper and keeps the
/// node at exactly 16 bytes (4-byte `StepId` + 12-byte `CompactDecodeStep`).
pub(super) struct StepNode {
    /// Parent step in the provenance chain, or [`STEP_ROOT`] for root-level steps.
    pub(super) parent: StepId,
    step: CompactDecodeStep,
}

impl StepNode {
    /// Variant discriminant for dedup: 1=UTF-16 LE, 2=UTF-16 BE, 0=other.
    pub(super) fn variant_discriminant(&self) -> u8 {
        self.step.variant_discriminant()
    }
}

// Compile-time size guards for compact arena types.
const _: () = assert!(std::mem::size_of::<CompactDecodeStep>() == 12);
const _: () = assert!(std::mem::size_of::<StepNode>() == 16);

/// Arena for decode steps so findings store compact `StepId` references.
///
/// Why an arena?
/// - Decoding is recursive; each derived buffer adds provenance.
/// - Storing full `Vec<DecodeStep>` per finding would allocate and clone heavily.
/// - A parent-linked arena lets us store provenance once and share it across
///   findings, with O(length) reconstruction only when materializing output.
///
/// This is append-only and reset between scans. `StepId` values are only valid
/// while this arena is alive and not reset.
///
/// # Performance
/// - `push` is O(1); `materialize` is O(depth) for a single finding.
pub(super) struct StepArena {
    /// Parent-linked decode step nodes.
    ///
    /// Each node records a single decode operation (transform ID, span) and
    /// points to its parent step. This compact representation enables sharing
    /// provenance across multiple findings from the same decoded buffer.
    pub(super) nodes: ScratchVec<StepNode>,
}

impl StepArena {
    pub(super) fn reset(&mut self) {
        self.nodes.clear();
    }

    /// Adds a decode step and returns its arena `StepId`.
    ///
    /// The step is compacted internally to reduce per-node memory.
    ///
    /// # Preconditions
    /// - `parent` is either `STEP_ROOT` or a `StepId` previously returned by
    ///   this arena and still alive (i.e. before `reset`).
    pub(super) fn push(&mut self, parent: StepId, step: DecodeStep) -> StepId {
        let id = StepId(self.nodes.len() as u32);
        self.nodes.push(StepNode {
            parent,
            step: CompactDecodeStep::from_decode_step(&step),
        });
        id
    }

    /// Reconstructs the step chain from root to leaf.
    ///
    /// The arena stores steps in leaf-to-root order via parent pointers.
    /// This function collects them and reverses in place to produce a
    /// root-to-leaf sequence suitable for reporting.
    pub(super) fn materialize(&self, mut id: StepId, out: &mut ScratchVec<DecodeStep>) {
        out.clear();
        while id != STEP_ROOT {
            let cur = id;
            let node = &self.nodes[cur.0 as usize];
            out.push(node.step.to_decode_step());
            id = node.parent;
        }
        // Reverse in place
        let len = out.len();
        for i in 0..len / 2 {
            out.as_mut_slice().swap(i, len - 1 - i);
        }
    }
}

/// Contiguous decoded-byte slab for derived buffers.
///
/// This is a monotonic append-only buffer:
/// - Decoders append into the slab and receive a `Range<usize>` back.
/// - Work items carry those ranges instead of owning new allocations.
/// - The slab never reallocates (capacity == global decode budget), so the
///   returned ranges remain valid for the lifetime of a scan.
///
/// The slab is cleared between scans, which invalidates all ranges at once.
///
/// # Invariants
/// - Append operations must not exceed `limit`; on overflow, callers roll back.
/// - Ranges returned from `append_stream_decode` are valid only until reset or
///   explicit truncation.
///
/// # Performance
/// - Avoids per-span allocations by reusing a single contiguous buffer.
pub(super) struct DecodeSlab {
    pub(super) buf: Vec<u8>,
    pub(super) limit: usize,
}

impl DecodeSlab {
    pub(super) fn with_limit(limit: usize) -> Self {
        let buf = Vec::with_capacity(limit);
        Self { buf, limit }
    }

    pub(super) fn reset(&mut self) {
        self.buf.clear();
    }

    pub(super) fn slice(&self, r: Range<usize>) -> &[u8] {
        &self.buf[r]
    }

    /// Append decoded bytes into the slab while enforcing per-transform and
    /// global decode budgets.
    ///
    /// # Rollback semantics
    ///
    /// On decode error, budget exhaustion, or zero output, the slab is
    /// truncated back to its pre-call length and `ctx_total_decode_output_bytes`
    /// is restored. This all-or-nothing approach ensures downstream code never
    /// sees a partially decoded buffer — either the full decode succeeds and
    /// the returned `Range` points at valid output, or `Err(())` is returned
    /// and the slab is unchanged.
    ///
    /// # Budgets (checked on every chunk emitted by the stream decoder)
    /// - `max_out` — per-transform output cap (from `TransformConfig::max_decoded_bytes`).
    /// - `global_limit` — scan-level output cap (`Tuning::max_total_decode_output_bytes`).
    /// - `self.limit` — slab capacity (pre-allocated, never grows).
    pub(super) fn append_stream_decode(
        &mut self,
        tc: &TransformConfig,
        input: &[u8],
        max_out: usize,
        ctx_total_decode_output_bytes: &mut usize,
        global_limit: usize,
    ) -> Result<Range<usize>, ()> {
        let start_len = self.buf.len();
        let start_ctx = *ctx_total_decode_output_bytes;
        let mut local_out = 0usize;
        let mut truncated = false;

        let res = stream_decode(tc, input, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if ctx_total_decode_output_bytes.saturating_add(chunk.len()) > global_limit {
                truncated = true;
                return ControlFlow::Break(());
            }
            if self.buf.len().saturating_add(chunk.len()) > self.limit {
                truncated = true;
                return ControlFlow::Break(());
            }

            self.buf.extend_from_slice(chunk);
            local_out = local_out.saturating_add(chunk.len());
            *ctx_total_decode_output_bytes =
                ctx_total_decode_output_bytes.saturating_add(chunk.len());

            ControlFlow::Continue(())
        });

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            self.buf.truncate(start_len);
            *ctx_total_decode_output_bytes = start_ctx;
            return Err(());
        }

        Ok(start_len..(start_len + local_out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_decode_step_transform_round_trip() {
        let step = DecodeStep::Transform {
            transform_idx: 42,
            parent_span: 100..500,
        };
        let compact = CompactDecodeStep::from_decode_step(&step);
        let back = compact.to_decode_step();
        match back {
            DecodeStep::Transform {
                transform_idx,
                parent_span,
            } => {
                assert_eq!(transform_idx, 42);
                assert_eq!(parent_span, 100..500);
            }
            _ => panic!("expected Transform variant"),
        }
    }

    #[test]
    fn compact_decode_step_utf16_le_round_trip() {
        let step = DecodeStep::Utf16Window {
            endianness: Utf16Endianness::Le,
            parent_span: 0..1024,
        };
        let compact = CompactDecodeStep::from_decode_step(&step);
        let back = compact.to_decode_step();
        match back {
            DecodeStep::Utf16Window {
                endianness,
                parent_span,
            } => {
                assert_eq!(endianness, Utf16Endianness::Le);
                assert_eq!(parent_span, 0..1024);
            }
            _ => panic!("expected Utf16Window variant"),
        }
    }

    #[test]
    fn compact_decode_step_utf16_be_round_trip() {
        let step = DecodeStep::Utf16Window {
            endianness: Utf16Endianness::Be,
            parent_span: 50..200,
        };
        let compact = CompactDecodeStep::from_decode_step(&step);
        let back = compact.to_decode_step();
        match back {
            DecodeStep::Utf16Window {
                endianness,
                parent_span,
            } => {
                assert_eq!(endianness, Utf16Endianness::Be);
                assert_eq!(parent_span, 50..200);
            }
            _ => panic!("expected Utf16Window variant"),
        }
    }

    #[test]
    fn compact_decode_step_max_transform_idx() {
        let step = DecodeStep::Transform {
            transform_idx: (1 << 31) - 1,
            parent_span: 0..u32::MAX as usize,
        };
        let compact = CompactDecodeStep::from_decode_step(&step);
        let back = compact.to_decode_step();
        match back {
            DecodeStep::Transform {
                transform_idx,
                parent_span,
            } => {
                assert_eq!(transform_idx, (1 << 31) - 1);
                assert_eq!(parent_span, 0..u32::MAX as usize);
            }
            _ => panic!("expected Transform variant"),
        }
    }
}
