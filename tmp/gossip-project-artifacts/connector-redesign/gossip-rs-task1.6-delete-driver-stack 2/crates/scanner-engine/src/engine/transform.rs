//! Transform span detection and streaming decode helpers.
//!
//! # Overview
//! This module implements the "transform" stage of the scanner for URL-percent
//! and Base64 payloads. Each transform has two pieces:
//! - a permissive span finder that favors recall over strict validation
//! - a streaming decoder that enforces correctness with bounded memory
//!
//! ## URL percent-encoding
//! - The span finder scans URL-ish runs (RFC3986 unreserved/reserved plus '%' and '+')
//!   and keeps runs that contain at least one escape (and optionally '+' when
//!   `plus_to_space` is enabled).
//! - The decoder converts `%HH` escapes and optional `+` to space; invalid or
//!   incomplete escapes pass through unchanged.
//!
//! ## Base64 (standard + URL-safe)
//! - The span finder scans runs of base64 alphabet plus allowed whitespace.
//!   `min_len` counts alphabet characters only; whitespace does not contribute.
//! - The decoder ignores whitespace, validates padding, and accepts an unpadded
//!   tail (2 or 3 characters in the final quantum).
//!
//! # Invariants and guarantees
//! - Span finders are single-pass and capped by `max_len` and `max_spans`.
//! - Spans are byte ranges into the original buffer, produced in ascending order.
//! - Long runs are split at `max_len` boundaries to bound worst-case work.
//! - Decoders are single-pass and O(1) memory; they emit bounded chunks via callbacks.
//!
//! # Span splitting (edge case)
//! Runs are split strictly on `max_len` byte boundaries, without aligning to
//! encoding quanta (`%HH` or 4-char base64). This is an explicit trade-off:
//! scanning stays bounded, but a valid encoding can be split across spans.
//! Downstream decode treats each span independently; percent-escape fragments
//! pass through unchanged, while base64 fragments can be rejected.
//!
//! # Trade-offs
//! These components intentionally trade precision for cheap scanning. Strict
//! validation happens in decode/gating, while span finders bias toward not
//! missing possible payloads.
//!
//! # Streaming usage
//! The `*SpanStream` scanners accept chunked input via `feed(chunk, base_offset, ...)`,
//! where `base_offset` is the absolute byte offset of `chunk[0]` in the original
//! buffer. Call `finish(end_offset, ...)` once at end-of-stream to flush a trailing
//! run; after `on_span` returns `false`, the stream becomes inert (construct a
//! new instance to scan again).
//! Chunks are expected to arrive in-order with monotonic `base_offset` (typically
//! contiguous). Gaps or overlaps split runs across chunk boundaries and may
//! suppress or fragment spans.

use super::hit_pool::SpanU32;
use crate::api::{TransformConfig, TransformId};
use crate::scratch_memory::ScratchVec;
use memchr::{memchr, memchr2};
use std::ops::{ControlFlow, Range};

/// Output buffer size used by streaming decoders.
pub(super) const STREAM_DECODE_CHUNK_BYTES: usize = 16 * 1024;

// --------------------------
// Transform: URL percent
// --------------------------

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Returns `true` if `b` is a URL-percent trigger byte (`%`, or `+` when
/// `plus_to_space` is enabled).
///
/// A trigger is the minimum evidence that a URL-ish run might contain encoded
/// content worth decoding. Runs without at least one trigger are discarded.
#[inline(always)]
pub(super) fn is_url_trigger(b: u8, plus_to_space: bool) -> bool {
    b == b'%' || (plus_to_space && b == b'+')
}

/// Convert an ASCII hex digit to its 4-bit numeric value.
///
/// Caller must verify `b.is_ascii_hexdigit()` first; non-hex bytes
/// silently map to 0.
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// Byte-class bitmask flags for the shared 256-byte lookup table (`BYTE_CLASS`).
// Each byte gets a bitwise-OR of these flags so both URL and base64 scanners
// can classify a byte with a single table lookup and mask test.
const URLISH: u8 = 1 << 0;
const B64_CHAR: u8 = 1 << 1;
const B64_WS: u8 = 1 << 2;
const B64_WS_SPACE: u8 = 1 << 3;

/// Builds the shared 256-byte classification table at compile time.
///
/// Each byte value is assigned a bitmask of flags so that both URL and base64
/// scanners can classify any byte with a single indexed load and mask test.
/// The flags are: `URLISH`, `B64_CHAR`, `B64_WS`, `B64_WS_SPACE`.
const fn build_byte_class() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        let mut flags = 0u8;

        // URL-ish: RFC3986 unreserved + reserved + '%' and '+' (scanner-specific).
        if (b >= b'A' && b <= b'Z')
            || (b >= b'a' && b <= b'z')
            || (b >= b'0' && b <= b'9')
            || matches!(
                b,
                b'%' | b'+'
                    | b'-'
                    | b'_'
                    | b'.'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'#'
                    | b'['
                    | b']'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b','
                    | b';'
                    | b'='
            )
        {
            flags |= URLISH;
        }

        // Base64 alphabet (standard + URL-safe) + padding.
        if (b >= b'A' && b <= b'Z')
            || (b >= b'a' && b <= b'z')
            || (b >= b'0' && b <= b'9')
            || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
        {
            flags |= B64_CHAR;
        }

        match b {
            b'\n' | b'\r' | b'\t' => flags |= B64_WS,
            b' ' => flags |= B64_WS_SPACE,
            _ => {}
        }

        table[i] = flags;
        i += 1;
    }
    table
}

/// Precomputed byte-class table mapping each byte value to its bitmask flags.
///
/// Indexed by `byte as usize`; the result is a bitwise-OR of `URLISH`,
/// `B64_CHAR`, `B64_WS`, and `B64_WS_SPACE` flags.
static BYTE_CLASS: [u8; 256] = build_byte_class();

/// Sentinel value indicating an invalid base64 byte in B64_DECODE table.
const B64_INVALID: u8 = 0xFF;
/// Sentinel value indicating padding ('=') in B64_DECODE table.
const B64_PAD: u8 = 64;
/// Sentinel for whitespace in the extended base64 decode table (`B64_DECODE_EX`).
/// Distinct from `B64_PAD` (64) and valid values (0-63), allowing a single
/// table lookup to classify whitespace, valid data, padding, and invalid bytes.
const B64_WS_SENTINEL: u8 = 0xFE;

/// Builds the base64 decode lookup table at compile time.
///
/// Maps each byte to its 6-bit decoded value (0–63), `B64_PAD` (64) for `=`,
/// or `B64_INVALID` (0xFF) for non-base64 bytes. Accepts both standard (`+/`)
/// and URL-safe (`-_`) alphabets simultaneously.
const fn build_b64_decode_table() -> [u8; 256] {
    let mut table = [B64_INVALID; 256];
    let mut i = 0u8;
    loop {
        table[i as usize] = match i {
            b'A'..=b'Z' => i - b'A',
            b'a'..=b'z' => i - b'a' + 26,
            b'0'..=b'9' => i - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => B64_PAD,
            _ => B64_INVALID,
        };
        if i == 255 {
            break;
        }
        i += 1;
    }
    table
}

/// Extended base64 decode table that also classifies whitespace.
///
/// Like the base table produced by [`build_b64_decode_table`], but maps
/// `' '`, `'\n'`, `'\r'`, `'\t'` to `B64_WS_SENTINEL` (0xFE) instead of
/// `B64_INVALID`. This lets the decoder's inner loop replace a 4-comparison
/// `matches!` whitespace check + separate table lookup with a single table
/// lookup and two comparisons.
const fn build_b64_decode_ex_table() -> [u8; 256] {
    let mut table = build_b64_decode_table();
    table[b' ' as usize] = B64_WS_SENTINEL;
    table[b'\n' as usize] = B64_WS_SENTINEL;
    table[b'\r' as usize] = B64_WS_SENTINEL;
    table[b'\t' as usize] = B64_WS_SENTINEL;
    table
}

static B64_DECODE_EX: [u8; 256] = build_b64_decode_ex_table();

/// Target for span collection, allowing reuse of `Vec` or `ScratchVec`.
///
/// Spans are half-open byte ranges (`start..end`) into the input buffer.
/// Implementations are expected to preserve insertion order and tolerate
/// being cleared and reused across scans.
/// Callers must ensure spans are valid for the sink (for example, `SpanU32`
/// requires all offsets fit in `u32`).
/// Callers are responsible for ensuring `start <= end` and that spans are
/// within the input buffer.
pub(super) trait SpanSink {
    fn clear(&mut self);
    fn len(&self) -> usize;
    fn push(&mut self, span: Range<usize>);
}

/// Stateful URL-ish span detector for chunked input.
///
/// The scan is permissive: any URL-ish run containing at least one escape (or
/// `+` when `plus_to_space` is enabled) can produce a span. Runs are split at
/// `max_len` boundaries to cap worst-case work; each split segment must still
/// satisfy the trigger and `min_len` requirements to be emitted.
///
/// Note: `max_len` splitting does not align to `%HH`; a split escape will be
/// treated as literal by the decoder, which is acceptable for this scan-first
/// design.
///
/// # Invariants
/// - Once `done` is set (via `on_span` returning `false`), no further spans
///   will be emitted; construct a new instance to scan again.
/// - `in_run` is `true` iff we are currently inside an eligible URL-ish run.
/// - Between chunks, run state (`start`, `run_len`, `triggers`) is preserved
///   so that runs can span chunk boundaries.
pub(super) struct UrlSpanStream {
    min_len: usize,
    max_len: usize,
    plus_to_space: bool,
    in_run: bool,
    start: u64,
    run_len: usize,
    triggers: usize,
    done: bool,
}

impl UrlSpanStream {
    pub(super) fn new(tc: &TransformConfig) -> Self {
        Self {
            min_len: tc.min_len,
            max_len: tc.max_encoded_len,
            plus_to_space: tc.plus_to_space,
            in_run: false,
            start: 0,
            run_len: 0,
            triggers: 0,
            done: false,
        }
    }

    /// Feed the next chunk of bytes into the scanner.
    ///
    /// `base_offset` must be the absolute offset of `chunk[0]` in the original
    /// buffer. Chunks should be provided in order with a monotonic
    /// `base_offset` (typically contiguous) so runs can span chunk boundaries.
    /// Spans are reported as half-open absolute ranges. Returning `false` from
    /// `on_span` stops the scan early; the stream becomes inert afterward.
    pub(super) fn feed<F>(&mut self, chunk: &[u8], base_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || chunk.is_empty() {
            return;
        }

        let mut i = 0usize;
        while i < chunk.len() {
            let b = chunk[i];
            let flags = BYTE_CLASS[b as usize];
            let urlish = (flags & URLISH) != 0;
            let abs = base_offset + i as u64;

            if !self.in_run {
                if !urlish {
                    i += 1;
                    continue;
                }
                self.in_run = true;
                self.start = abs;
                self.run_len = 0;
                self.triggers = 0;
            }

            if urlish {
                self.run_len += 1;
                if is_url_trigger(b, self.plus_to_space) {
                    self.triggers += 1;
                }
                i += 1;

                if self.run_len >= self.max_len {
                    if self.triggers > 0 && self.run_len >= self.min_len {
                        let end = self.start.saturating_add(self.run_len as u64);
                        if !on_span(self.start, end) {
                            self.done = true;
                            return;
                        }
                    }
                    self.in_run = false;
                }
            } else {
                if self.triggers > 0 && self.run_len >= self.min_len {
                    let end = abs;
                    if !on_span(self.start, end) {
                        self.done = true;
                        return;
                    }
                }
                self.in_run = false;
                i += 1;
            }
        }
    }

    /// Flush a trailing run at end-of-stream.
    ///
    /// `end_offset` should be the absolute offset immediately after the last
    /// input byte. No spans are emitted if the current run lacks a trigger or
    /// is shorter than `min_len`.
    pub(super) fn finish<F>(&mut self, end_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || !self.in_run {
            return;
        }
        if self.triggers > 0 && self.run_len >= self.min_len && !on_span(self.start, end_offset) {
            self.done = true;
        }
        self.in_run = false;
    }
}

/// Stateful base64-ish span detector for chunked input.
///
/// Runs may include allowed whitespace, but spans are trimmed to the last base64
/// alphabet byte. `min_chars` counts alphabet characters only; whitespace does
/// not contribute. Runs are split at `max_len` boundaries to keep scanning bounded.
///
/// Note: `max_len` splitting does not align to 4-char base64 quanta. A split
/// segment may fail strict decode if it ends with a 1-char tail.
///
/// # Invariants
/// - Once `done` is set (via `on_span` returning `false`), no further spans
///   will be emitted; construct a new instance to scan again.
/// - `in_run` is `true` iff we are currently inside an eligible base64 run.
/// - `have_b64` tracks whether at least one alphabet character (not whitespace)
///   has been seen in the current run; runs with only whitespace are discarded.
/// - Between chunks, run state is preserved so that runs can span boundaries.
/// - Padding ('=') terminates a span; a trailing `==` or `=` sequence can cross
///   chunk boundaries without merging into subsequent base64-looking bytes.
///
/// # Padding state machine
/// When `pad_seen` is true, the scanner is in "padding tail" mode:
/// - Additional `=` chars extend the span (for `==` padding split across chunks).
/// - Whitespace is tolerated but does not advance the span end.
/// - Any non-pad base64 char (A-Z, a-z, 0-9, +, /, -, _) finalizes the current
///   span and starts fresh—preventing `QUJD==QUJD` from merging into one span.
/// - Non-allowed bytes also finalize the span.
///
/// This ensures that `QUJDRA=` + `=` (split across chunks) correctly emits a
/// single span covering both `=` chars, while `QUJDRA==X` does not incorrectly
/// include `X` in the span.
pub(super) struct Base64SpanStream {
    min_chars: usize,
    max_len: usize,
    allow_space_ws: bool,
    /// True iff currently inside an eligible base64 run.
    in_run: bool,
    /// True iff we've seen at least one `=` in the current run; triggers
    /// padding-tail mode where only more `=` or whitespace is allowed before
    /// finalizing the span.
    pad_seen: bool,
    /// Absolute offset of the first byte in the current run.
    start: u64,
    /// Total bytes consumed in the current run (alphabet + whitespace).
    run_len: usize,
    /// Count of base64 alphabet chars (excludes `=` and whitespace).
    b64_chars: usize,
    /// True iff at least one non-pad alphabet char has been seen.
    have_b64: bool,
    /// Absolute offset of the last base64 byte (including `=`); span ends at
    /// `last_b64 + 1`.
    last_b64: u64,
    /// True iff `on_span` returned false; stream is inert afterward.
    done: bool,
}

impl Base64SpanStream {
    pub(super) fn new(tc: &TransformConfig) -> Self {
        Self {
            min_chars: tc.min_len,
            max_len: tc.max_encoded_len,
            allow_space_ws: tc.base64_allow_space_ws,
            in_run: false,
            pad_seen: false,
            start: 0,
            run_len: 0,
            b64_chars: 0,
            have_b64: false,
            last_b64: 0,
            done: false,
        }
    }

    /// Feed the next chunk of bytes into the scanner.
    ///
    /// `base_offset` must be the absolute offset of `chunk[0]` in the original
    /// buffer. Chunks should be provided in order with a monotonic
    /// `base_offset` (typically contiguous) so runs can span chunk boundaries.
    /// Spans are reported as half-open absolute ranges trimmed to the last
    /// base64 byte. Returning `false` from `on_span` stops the scan early; the
    /// stream becomes inert afterward.
    pub(super) fn feed<F>(&mut self, chunk: &[u8], base_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || chunk.is_empty() {
            return;
        }

        let allow_mask = if self.allow_space_ws {
            B64_CHAR | B64_WS | B64_WS_SPACE
        } else {
            B64_CHAR | B64_WS
        };

        let mut i = 0usize;
        while i < chunk.len() {
            let b = chunk[i];
            let flags = BYTE_CLASS[b as usize];
            let allowed = (flags & allow_mask) != 0;
            let abs = base_offset + i as u64;

            // ── Padding-tail mode ──
            // After seeing `=`, we only allow more `=` (to complete `==`) or
            // whitespace. Any data char finalizes the span so that adjacent
            // base64 blobs like `QUJD==QUJD` become two spans, not one.
            if self.in_run && self.pad_seen {
                if allowed {
                    if (flags & B64_CHAR) != 0 {
                        if b == b'=' {
                            // Extend padding: `=` followed by `=` across chunk.
                            self.run_len += 1;
                            self.last_b64 = abs;
                            i += 1;
                        } else {
                            // Non-pad base64 char after padding → finalize span,
                            // then let the outer loop start a fresh run at `i`.
                            if self.have_b64 && self.b64_chars >= self.min_chars {
                                let end = self.last_b64.saturating_add(1);
                                if !on_span(self.start, end) {
                                    self.done = true;
                                    return;
                                }
                            }
                            self.in_run = false;
                            self.pad_seen = false;
                            // Do NOT increment `i`; re-evaluate this byte as a
                            // potential run start on next iteration.
                        }
                    } else {
                        // Whitespace in padding tail: tolerate but don't advance
                        // `last_b64` so trailing ws is trimmed from span.
                        self.run_len += 1;
                        i += 1;
                    }
                } else {
                    // Disallowed byte terminates the padded span.
                    if self.have_b64 && self.b64_chars >= self.min_chars {
                        let end = self.last_b64.saturating_add(1);
                        if !on_span(self.start, end) {
                            self.done = true;
                            return;
                        }
                    }
                    self.in_run = false;
                    self.pad_seen = false;
                    i += 1;
                }

                if self.done {
                    return;
                }
                if !self.in_run {
                    continue;
                }
                // Check max_len even in padding tail to stay bounded.
                if self.run_len >= self.max_len {
                    if self.have_b64 && self.b64_chars >= self.min_chars {
                        let end = self.last_b64.saturating_add(1);
                        if !on_span(self.start, end) {
                            self.done = true;
                            return;
                        }
                    }
                    self.in_run = false;
                    self.pad_seen = false;
                }
                continue;
            }

            if !self.in_run {
                if !allowed {
                    i += 1;
                    continue;
                }
                self.in_run = true;
                self.start = abs;
                self.run_len = 0;
                self.b64_chars = 0;
                self.have_b64 = false;
            }

            if allowed {
                self.run_len += 1;
                if (flags & B64_CHAR) != 0 {
                    if b == b'=' {
                        // First `=` in this run: enter padding-tail mode if we
                        // have actual data; otherwise discard (leading `=` is
                        // not valid base64).
                        if self.have_b64 {
                            self.last_b64 = abs;
                            self.pad_seen = true;
                        } else {
                            // No data before `=`; abandon run.
                            self.in_run = false;
                        }
                        i += 1;
                        continue;
                    }
                    // Regular base64 alphabet char (not `=`).
                    self.b64_chars += 1;
                    self.last_b64 = abs;
                    self.have_b64 = true;
                }
                i += 1;

                if self.run_len >= self.max_len {
                    if self.have_b64 && self.b64_chars >= self.min_chars {
                        let end = self.last_b64.saturating_add(1);
                        if !on_span(self.start, end) {
                            self.done = true;
                            return;
                        }
                    }
                    self.in_run = false;
                }
            } else {
                if self.have_b64 && self.b64_chars >= self.min_chars {
                    let end = self.last_b64.saturating_add(1);
                    if !on_span(self.start, end) {
                        self.done = true;
                        return;
                    }
                }
                self.in_run = false;
                i += 1;
            }
        }
    }

    /// Flush a trailing run at end-of-stream, trimming trailing whitespace.
    ///
    /// The `_end_offset` parameter is accepted for API symmetry with `UrlSpanStream`
    /// but is unused here; base64 spans end at `last_b64 + 1`, so the span
    /// boundary is fully determined by the last alphabet/padding byte seen and
    /// does not depend on the caller-supplied end offset.
    pub(super) fn finish<F>(&mut self, _end_offset: u64, mut on_span: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        if self.done || !self.in_run {
            return;
        }
        if self.have_b64 && self.b64_chars >= self.min_chars {
            let end = self.last_b64.saturating_add(1);
            if !on_span(self.start, end) {
                self.done = true;
            }
        }
        self.in_run = false;
    }
}

impl SpanSink for Vec<Range<usize>> {
    fn clear(&mut self) {
        Vec::clear(self);
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        Vec::push(self, span);
    }
}

impl SpanSink for ScratchVec<Range<usize>> {
    fn clear(&mut self) {
        ScratchVec::clear(self);
    }

    fn len(&self) -> usize {
        ScratchVec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        ScratchVec::push(self, span);
    }
}

/// [`SpanSink`] for the compact `SpanU32` representation.
///
/// Callers must ensure all span offsets fit in `u32`; overflow is not checked
/// here (it is the engine's responsibility to reject buffers larger than 4 GiB).
impl SpanSink for ScratchVec<SpanU32> {
    fn clear(&mut self) {
        ScratchVec::clear(self);
    }

    fn len(&self) -> usize {
        ScratchVec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        ScratchVec::push(self, SpanU32::new_no_hint(span.start, span.end));
    }
}

/// Finds URL-encoded spans within `hay` and appends them to `spans`.
///
/// Spans are drawn from URL-ish runs that contain at least one escape (or `+`
/// when `plus_to_space` is enabled). The run is bounded by `max_len`, and runs
/// shorter than `min_len` are discarded. `min_len`/`max_len` are measured in
/// input bytes, not decoded output.
///
/// `spans` is cleared before results are appended.
///
/// Notes:
/// - "URL-ish" includes RFC3986 unreserved/reserved bytes plus '%' and '+'.
/// - Runs longer than `max_len` are split at the boundary to keep scans bounded.
///   Splits are byte-count based and may cut through a `%HH` escape.
/// - When `plus_to_space` is false, '+' is allowed in runs but does not trigger
///   a span by itself.
/// - Scanning stops after `max_spans` spans are appended.
pub(super) fn find_url_spans_into(
    hay: &[u8],
    min_len: usize,
    max_len: usize,
    max_spans: usize,
    plus_to_space: bool,
    spans: &mut impl SpanSink,
) {
    debug_assert!(max_len >= min_len);
    // Fast reject: URL spans require at least one '%' (or '+' when plus_to_space is enabled).
    // Note: the engine already applies this prefilter via transform_quick_trigger(),
    // but direct callers (e.g., microbench) can reach here without that guard.
    let has_trigger = if plus_to_space {
        memchr2(b'%', b'+', hay).is_some()
    } else {
        memchr(b'%', hay).is_some()
    };
    // Include unescaped prefixes by scanning URL-ish runs, not starting at the first '%'.
    // We still require at least one percent-escape (and optionally '+') to avoid
    // decoding every plain word.
    spans.clear();
    if !has_trigger {
        return;
    }
    let mut i = 0usize;

    while i < hay.len() && spans.len() < max_spans {
        let flags = BYTE_CLASS[hay[i] as usize];
        if (flags & URLISH) == 0 {
            i += 1;
            continue;
        }

        let start = i;
        let mut triggers = 0usize;

        while i < hay.len() && (i - start) < max_len {
            let b = hay[i];
            let flags = BYTE_CLASS[b as usize];
            if (flags & URLISH) == 0 {
                break;
            }
            if is_url_trigger(b, plus_to_space) {
                triggers += 1;
            }
            i += 1;
        }

        let end = i;
        if triggers > 0 && (end - start) >= min_len {
            spans.push(start..end);
        }
    }
}

/// Streaming URL-percent decoder.
///
/// Decodes `%HH` escapes and optionally converts `+` to space. Invalid or
/// incomplete escapes are passed through verbatim. Output is emitted in
/// bounded chunks (stream decode buffer), and the `on_bytes` callback may stop
/// decoding early by returning `ControlFlow::Break(())` (treated as success).
///
/// # Behavior
/// - Only `%` followed by two hex digits is decoded; all other bytes are
///   forwarded unchanged (including `%` itself).
/// - Output length is never larger than input length.
/// - `on_bytes` may be called multiple times; chunk boundaries are arbitrary.
///
/// # Errors
/// This function is infallible. The callback can stop decoding early by
/// returning `ControlFlow::Break(())`.
fn stream_decode_url_percent(
    input: &[u8],
    plus_to_space: bool,
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) {
    fn flush_buf(
        out: &mut [u8],
        n: &mut usize,
        on: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if *n == 0 {
            return ControlFlow::Continue(());
        }
        let cf = on(&out[..*n]);
        *n = 0;
        cf
    }

    let mut out = [0u8; STREAM_DECODE_CHUNK_BYTES];
    let mut n = 0usize;
    let headroom = out.len() - 4;
    let mut remaining = input;

    while !remaining.is_empty() {
        // SIMD-accelerated skip to next trigger byte.
        let trigger_pos = if plus_to_space {
            memchr2(b'%', b'+', remaining)
        } else {
            memchr(b'%', remaining)
        };

        // Bulk-copy the literal prefix (bytes before the trigger).
        let prefix_end = trigger_pos.unwrap_or(remaining.len());
        if prefix_end > 0 {
            let prefix = &remaining[..prefix_end];
            let mut copied = 0;
            while copied < prefix.len() {
                let avail = headroom - n;
                let take = (prefix.len() - copied).min(avail);
                out[n..n + take].copy_from_slice(&prefix[copied..copied + take]);
                n += take;
                copied += take;
                if n >= headroom {
                    match flush_buf(&mut out, &mut n, &mut on_bytes) {
                        ControlFlow::Continue(()) => {}
                        ControlFlow::Break(()) => return,
                    }
                }
            }
            remaining = &remaining[prefix_end..];
        }

        if remaining.is_empty() {
            break;
        }

        // Process consecutive trigger bytes without re-calling memchr.
        loop {
            let b = remaining[0];
            if b == b'%' && remaining.len() >= 3 && is_hex(remaining[1]) && is_hex(remaining[2]) {
                out[n] = (hex_val(remaining[1]) << 4) | hex_val(remaining[2]);
                n += 1;
                remaining = &remaining[3..];
            } else if plus_to_space && b == b'+' {
                out[n] = b' ';
                n += 1;
                remaining = &remaining[1..];
            } else {
                // Invalid escape or lone % at end — pass through verbatim.
                out[n] = b;
                n += 1;
                remaining = &remaining[1..];
            }

            if n >= headroom {
                match flush_buf(&mut out, &mut n, &mut on_bytes) {
                    ControlFlow::Continue(()) => {}
                    ControlFlow::Break(()) => return,
                }
            }

            // Continue if next byte is also a trigger.
            if remaining.is_empty() {
                break;
            }
            let next = remaining[0];
            if next != b'%' && !(plus_to_space && next == b'+') {
                break;
            }
        }
    }

    let _ = flush_buf(&mut out, &mut n, &mut on_bytes);
}

#[cfg(test)]
#[derive(Debug)]
enum UrlTestError {
    OutputTooLarge,
}

#[cfg(test)]
fn decode_url_percent_to_vec(
    input: &[u8],
    plus_to_space: bool,
    max_out: usize,
) -> Result<Vec<u8>, UrlTestError> {
    let mut out = Vec::with_capacity(input.len().min(max_out));
    let mut too_large = false;

    stream_decode_url_percent(input, plus_to_space, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    });

    if too_large {
        return Err(UrlTestError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform: Base64 (urlsafe + std alph, ignores whitespace)
// --------------------------

/// Decode errors returned by [`stream_decode_base64`].
#[derive(Debug)]
enum Base64DecodeError {
    /// A byte that is not in the base64 alphabet and not whitespace.
    InvalidByte,
    /// Padding (`=`) appeared in a position that violates the base64 spec
    /// (e.g., `=` as the first or second char of a quantum, or data after padding).
    InvalidPadding,
    /// The input ended with exactly one leftover base64 char, which cannot
    /// produce any output byte (a minimum of two chars per quantum is required).
    TruncatedQuantum,
}

/// Finds base64-ish spans within `hay` and appends them to `spans`.
///
/// Guarantees / invariants:
/// - Each byte is classified at most once (single-pass scan).
/// - Spans contain only base64 chars + allowed whitespace.
/// - Spans end at the last base64 byte; trailing whitespace is trimmed.
/// - Runs are split at `max_len` to bound worst-case work.
/// - Scanning stops after `max_spans` spans are appended.
///
/// Notes:
/// - `min_chars` counts base64 alphabet characters only; whitespace does not
///   contribute to the minimum.
/// - `max_len` counts all bytes in the run, including whitespace.
///   Splits are byte-count based and may cut through a 4-char base64 quantum.
/// - `allow_space_ws` adds ASCII space to the allowed whitespace set (in
///   addition to `\r`, `\n`, `\t`).
/// - The scan is intentionally permissive and relies on downstream decode gates
///   for strict validation.
pub(super) fn find_base64_spans_into(
    hay: &[u8],
    min_chars: usize,
    max_len: usize,
    max_spans: usize,
    allow_space_ws: bool,
    spans: &mut impl SpanSink,
) {
    debug_assert!(max_len >= min_chars);
    spans.clear();
    if max_spans == 0 {
        return;
    }

    let allow_mask = if allow_space_ws {
        B64_CHAR | B64_WS | B64_WS_SPACE
    } else {
        B64_CHAR | B64_WS
    };
    let mut span_count = 0usize;

    // Current run state.
    let mut in_run = false;
    let mut start = 0usize;
    let mut run_len = 0usize;
    let mut b64_chars = 0usize;
    let mut have_b64 = false;
    let mut last_b64 = 0usize;

    let mut i = 0usize;
    while i < hay.len() {
        let b = hay[i];
        let flags = BYTE_CLASS[b as usize];
        let allowed = (flags & allow_mask) != 0;

        if !in_run {
            if !allowed {
                i += 1;
                continue;
            }
            in_run = true;
            start = i;
            run_len = 0;
            b64_chars = 0;
            have_b64 = false;
        }

        if allowed {
            run_len += 1;
            if (flags & B64_CHAR) != 0 {
                if b == b'=' {
                    if have_b64 {
                        let mut pad_end = i;
                        if i + 1 < hay.len() && hay[i + 1] == b'=' {
                            pad_end = i + 1;
                            i += 1;
                        }
                        last_b64 = pad_end;
                        if b64_chars >= min_chars {
                            spans.push(start..(last_b64 + 1));
                            span_count += 1;
                            if span_count >= max_spans {
                                return;
                            }
                        }
                    }
                    in_run = false;
                    i += 1;
                    continue;
                }
                b64_chars += 1;
                last_b64 = i;
                have_b64 = true;
            }
            i += 1;

            if run_len >= max_len {
                // Split long runs eagerly; the next iteration starts fresh at `i`.
                if have_b64 && b64_chars >= min_chars {
                    spans.push(start..(last_b64 + 1));
                    span_count += 1;
                    if span_count >= max_spans {
                        return;
                    }
                }
                in_run = false;
            }
        } else {
            // Disallowed byte ends the run; consume it so we don't recheck it.
            if have_b64 && b64_chars >= min_chars {
                spans.push(start..(last_b64 + 1));
                span_count += 1;
                if span_count >= max_spans {
                    return;
                }
            }
            in_run = false;
            i += 1;
        }
    }

    if in_run && have_b64 && b64_chars >= min_chars && span_count < max_spans {
        spans.push(start..(last_b64 + 1));
    }
}

/// Returns the byte offset past the first `skip` base64-alphabet characters
/// in `encoded`, skipping over whitespace.
///
/// Returns `None` if `encoded` contains fewer than `skip` alphabet chars
/// or a non-base64 byte is encountered before the count is reached.
/// Padding (`=`) is counted as a base64 char by the `B64_CHAR` flag.
pub(super) fn base64_skip_chars(
    encoded: &[u8],
    skip: usize,
    allow_space_ws: bool,
) -> Option<usize> {
    if skip == 0 {
        return Some(0);
    }
    let mut seen = 0usize;
    let mut i = 0usize;

    // Fast path: advance 4 bytes at a time while all are B64_CHAR and we
    // haven't reached the target count yet.
    while i + 4 <= encoded.len() && seen + 4 <= skip {
        let f0 = BYTE_CLASS[encoded[i] as usize];
        let f1 = BYTE_CLASS[encoded[i + 1] as usize];
        let f2 = BYTE_CLASS[encoded[i + 2] as usize];
        let f3 = BYTE_CLASS[encoded[i + 3] as usize];

        if (f0 & f1 & f2 & f3 & B64_CHAR) == 0 {
            break;
        }
        seen += 4;
        i += 4;
    }
    if seen == skip {
        return Some(i);
    }

    // Slow path: handle whitespace, terminators, and approach target precisely.
    for (j, &b) in encoded[i..].iter().enumerate() {
        if matches!(b, b'\n' | b'\r' | b'\t') || (allow_space_ws && b == b' ') {
            continue;
        }
        if (BYTE_CLASS[b as usize] & B64_CHAR) == 0 {
            return None;
        }
        seen += 1;
        if seen == skip {
            return Some(i + j + 1);
        }
    }
    None
}

/// Counts the number of base64 data characters (A-Z, a-z, 0-9, +, /, -, _)
/// in `encoded`, ignoring whitespace and stopping at the first non-base64 byte.
///
/// Padding (`=`) is excluded from the count. This is used to check whether a
/// span meets the `min_chars` threshold before attempting decode.
pub(super) fn base64_char_count(encoded: &[u8], allow_space_ws: bool) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;

    // Fast path: process 4 bytes at a time when all are B64_CHAR (no whitespace
    // or invalid bytes). The AND of flags detects any non-B64 byte in a single
    // comparison since whitespace flags don't include B64_CHAR.
    while i + 4 <= encoded.len() {
        let f0 = BYTE_CLASS[encoded[i] as usize];
        let f1 = BYTE_CLASS[encoded[i + 1] as usize];
        let f2 = BYTE_CLASS[encoded[i + 2] as usize];
        let f3 = BYTE_CLASS[encoded[i + 3] as usize];

        if (f0 & f1 & f2 & f3 & B64_CHAR) == 0 {
            break;
        }

        count += 4
            - (encoded[i] == b'=') as usize
            - (encoded[i + 1] == b'=') as usize
            - (encoded[i + 2] == b'=') as usize
            - (encoded[i + 3] == b'=') as usize;
        i += 4;
    }

    // Slow path: handle whitespace, non-B64 terminators, and the tail.
    for &b in &encoded[i..] {
        if matches!(b, b'\n' | b'\r' | b'\t') || (allow_space_ws && b == b' ') {
            continue;
        }
        if (BYTE_CLASS[b as usize] & B64_CHAR) == 0 {
            break;
        }
        if b != b'=' {
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// SIMD base64 decode helpers (16 input bytes → 12 output bytes per chunk)
// ---------------------------------------------------------------------------
//
// Each arch module exposes:
//   unsafe fn decode_simd_chunks(src: &[u8], dst: &mut [u8]) -> (usize, usize)
//     Decodes as many aligned 16-byte chunks as possible.
//     Returns (bytes_consumed_from_src, bytes_written_to_dst).
//     Stops at the first chunk containing a non-base64 byte (whitespace,
//     padding, or invalid).
//
// Contract: these functions decode only "clean" runs of base64 alphabet
// chars (A-Z, a-z, 0-9, +, /, -, _). Whitespace, padding ('='), and
// invalid bytes cause the loop to break, returning how far it got.
// The scalar slow path in stream_decode_base64 handles the remainder.

#[cfg(target_arch = "aarch64")]
mod simd_b64 {
    use std::arch::aarch64::*;

    /// Classify 16 bytes: returns a vector of 6-bit decoded values and a bool
    /// indicating all bytes were valid base64 (standard + URL-safe alphabet).
    ///
    /// # Safety
    /// Requires aarch64 NEON intrinsics (architecturally guaranteed on this
    /// target). `input` must come from a valid 16-byte vector load.
    #[inline(always)]
    unsafe fn classify_and_decode(input: uint8x16_t) -> (uint8x16_t, bool) {
        // Range checks for each alphabet segment.
        let upper_lo = vdupq_n_u8(b'A');
        let upper_hi = vdupq_n_u8(b'Z');
        let lower_lo = vdupq_n_u8(b'a');
        let lower_hi = vdupq_n_u8(b'z');
        let digit_lo = vdupq_n_u8(b'0');
        let digit_hi = vdupq_n_u8(b'9');

        let is_upper = vandq_u8(vcgeq_u8(input, upper_lo), vcleq_u8(input, upper_hi));
        let is_lower = vandq_u8(vcgeq_u8(input, lower_lo), vcleq_u8(input, lower_hi));
        let is_digit = vandq_u8(vcgeq_u8(input, digit_lo), vcleq_u8(input, digit_hi));

        // Special characters: + (0x2B), - (0x2D) → 62; / (0x2F), _ (0x5F) → 63
        let is_plus = vceqq_u8(input, vdupq_n_u8(b'+'));
        let is_dash = vceqq_u8(input, vdupq_n_u8(b'-'));
        let is_slash = vceqq_u8(input, vdupq_n_u8(b'/'));
        let is_under = vceqq_u8(input, vdupq_n_u8(b'_'));

        let is_62 = vorrq_u8(is_plus, is_dash);
        let is_63 = vorrq_u8(is_slash, is_under);

        // Validate: every byte must belong to one of the groups.
        let valid = vorrq_u8(
            vorrq_u8(vorrq_u8(is_upper, is_lower), is_digit),
            vorrq_u8(is_62, is_63),
        );
        // Check all lanes are 0xFF (all valid).
        let all_valid = vminvq_u8(valid) == 0xFF;

        // Compute 6-bit values per range using wrapping arithmetic offsets:
        //   A-Z: value = byte - 65
        //   a-z: value = byte - 71  (= byte - 'a' + 26)
        //   0-9: value = byte + 4   (= byte - '0' + 52, wrapping u8)
        //   +/-: value = 62
        //   //_: value = 63
        let val_upper = vsubq_u8(input, vdupq_n_u8(65)); // A→0, Z→25
        let val_lower = vsubq_u8(input, vdupq_n_u8(71)); // a→26, z→51
        let val_digit = vaddq_u8(input, vdupq_n_u8(4)); // '0'→52, '9'→61
        let val_62 = vdupq_n_u8(62);
        let val_63 = vdupq_n_u8(63);

        // Select the correct value per byte using bitwise select (bsl).
        // Start with 0, overlay each range.
        let mut result = vandq_u8(is_upper, val_upper);
        result = vorrq_u8(result, vandq_u8(is_lower, val_lower));
        result = vorrq_u8(result, vandq_u8(is_digit, val_digit));
        result = vorrq_u8(result, vandq_u8(is_62, val_62));
        result = vorrq_u8(result, vandq_u8(is_63, val_63));

        (result, all_valid)
    }

    /// Pack 16 x 6-bit values into 12 output bytes (4 groups of 4→3).
    ///
    /// Input layout:  [a0,b0,c0,d0, a1,b1,c1,d1, a2,b2,c2,d2, a3,b3,c3,d3]
    /// Output layout: [o0,o1,o2,     o3,o4,o5,     o6,o7,o8,     o9,o10,o11]
    ///
    /// Where: o0 = (a<<2)|(b>>4), o1 = ((b&0xF)<<4)|(c>>2), o2 = ((c&3)<<6)|d
    ///
    /// # Safety
    /// Requires aarch64 NEON intrinsics. `vals` must contain 16 valid 6-bit
    /// base64 lane values produced by `classify_and_decode`.
    #[inline(always)]
    unsafe fn pack_16_to_12(vals: uint8x16_t) -> [u8; 12] {
        // Shuffle to create aligned inputs for the three output-byte formulas.
        // Type A positions (o0,o3,o6,o9): need a-values from indices 0,4,8,12
        //                                  and b-values from indices 1,5,9,13
        // Type B positions (o1,o4,o7,o10): need b-values and c-values
        // Type C positions (o2,o5,o8,o11): need c-values and d-values

        // Shuffle indices to create:
        // v_ab = [a0, b0, a1, b1, a2, b2, a3, b3, ?, ?, ?, ?, ?, ?, ?, ?]
        // v_cd = [c0, d0, c1, d1, c2, d2, c3, d3, ?, ?, ?, ?, ?, ?, ?, ?]
        let idx_ab = vcreate_u8(u64::from_le_bytes([0, 1, 4, 5, 8, 9, 12, 13]));
        let idx_cd = vcreate_u8(u64::from_le_bytes([2, 3, 6, 7, 10, 11, 14, 15]));

        let v_ab = vqtbl1_u8(vals, idx_ab); // 8 bytes: [a0,b0,a1,b1,a2,b2,a3,b3]
        let v_cd = vqtbl1_u8(vals, idx_cd); // 8 bytes: [c0,d0,c1,d1,c2,d2,c3,d3]

        // Widen pairs to u16 and merge: a*64+b and c*64+d
        // vmull with constant 64 on even positions, then add odd positions.
        // Even indices [a0,a1,a2,a3], odd indices [b0,b1,b2,b3]:
        let ab_even = vuzp1_u8(v_ab, v_ab); // [a0,a1,a2,a3,a0,a1,a2,a3]
        let ab_odd = vuzp2_u8(v_ab, v_ab); // [b0,b1,b2,b3,b0,b1,b2,b3]
        let cd_even = vuzp1_u8(v_cd, v_cd); // [c0,c1,c2,c3,...]
        let cd_odd = vuzp2_u8(v_cd, v_cd); // [d0,d1,d2,d3,...]

        // Widen to u16 and compute: even*64 + odd → 12-bit merged value
        let ab_merged: uint16x4_t = vget_low_u16(vmlal_u8(
            vmovl_u8(vget_low_u8(vcombine_u8(ab_odd, ab_odd))),
            vget_low_u8(vcombine_u8(ab_even, ab_even)),
            vdup_n_u8(64),
        ));
        let cd_merged: uint16x4_t = vget_low_u16(vmlal_u8(
            vmovl_u8(vget_low_u8(vcombine_u8(cd_odd, cd_odd))),
            vget_low_u8(vcombine_u8(cd_even, cd_even)),
            vdup_n_u8(64),
        ));

        // Now merge u16 pairs: ab*4096 + cd → 24-bit value in u32
        let ab32 = vmovl_u16(ab_merged); // u32x4
        let cd32 = vmovl_u16(cd_merged); // u32x4
        let packed = vmlaq_n_u32(cd32, ab32, 4096); // ab*4096 + cd → 24-bit in u32

        // Extract 3 bytes from each u32 lane (big-endian byte order within 24 bits).
        // packed[i] contains 24 bits of output: bits[23:16] = o0, [15:8] = o1, [7:0] = o2
        let mut out = [0u8; 12];
        let p = vreinterpretq_u8_u32(packed);
        // On little-endian: u32 bytes are [o2, o1, o0, 0] per lane.
        // Shuffle to extract [o0, o1, o2] per group, 12 bytes total.
        let extract_idx: uint8x16_t = vld1q_u8(
            [
                2u8, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 0xFF, 0xFF, 0xFF, 0xFF,
            ]
            .as_ptr(),
        );
        let shuffled = vqtbl1q_u8(p, extract_idx);
        // Bytes 12-15 of `shuffled` are 0 (vqtbl1q_u8 returns 0 for out-of-range
        // indices); `store_low12` writes only the low 12 bytes into `out`.
        store_low12(shuffled, &mut out);
        out
    }

    /// Stores the low 12 bytes of `v` into `out` without touching adjacent memory.
    ///
    /// # Safety
    /// Uses NEON load/store intrinsics; caller must ensure the target supports
    /// aarch64 NEON (guaranteed on this target).
    #[inline(always)]
    unsafe fn store_low12(v: uint8x16_t, out: &mut [u8; 12]) {
        // NEON only exposes 128-bit stores for this vector shape; write into a
        // 16-byte scratch first, then copy the 12 meaningful bytes.
        let mut tmp = [0u8; 16];
        vst1q_u8(tmp.as_mut_ptr(), v);
        out.copy_from_slice(&tmp[..12]);
    }

    /// Decode as many 16-byte base64 chunks as possible from `src` into `dst`.
    /// Returns (bytes_consumed, bytes_written).
    /// Stops on first chunk containing any non-base64 byte.
    ///
    /// # Safety
    /// Caller must ensure `dst` has room for `(src.len() / 16) * 12` bytes.
    #[inline]
    pub(super) unsafe fn decode_simd_chunks(src: &[u8], dst: &mut [u8]) -> (usize, usize) {
        let mut si = 0usize;
        let mut di = 0usize;
        let end = src.len() & !15; // round down to 16-byte boundary

        while si < end && di + 12 <= dst.len() {
            let input = vld1q_u8(src.as_ptr().add(si));
            let (vals, valid) = classify_and_decode(input);
            if !valid {
                break;
            }
            let packed = pack_16_to_12(vals);
            std::ptr::copy_nonoverlapping(packed.as_ptr(), dst.as_mut_ptr().add(di), 12);
            si += 16;
            di += 12;
        }

        (si, di)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn store_low12_does_not_clobber_adjacent_bytes() {
            #[repr(C)]
            struct Guarded {
                out: [u8; 12],
                guard: [u8; 4],
            }

            let mut guarded = Guarded {
                out: [0u8; 12],
                guard: [0xA5; 4],
            };
            // SAFETY: `vdupq_n_u8` is a NEON intrinsic available on all aarch64 targets.
            let v = unsafe { vdupq_n_u8(0x11) };
            // SAFETY: `store_low12` writes exactly 12 bytes; `guarded.out` is 12 bytes.
            unsafe { store_low12(v, &mut guarded.out) };
            assert_eq!(guarded.guard, [0xA5; 4]);
        }

        #[test]
        fn decode_simd_chunks_decodes_clean_input() {
            let src = b"QUJDREVGR0hJSktM";
            let mut dst = [0u8; 12];
            // SAFETY: `dst` has 12 bytes, `src` is 16 bytes; (16/16)*12 = 12 fits in `dst`.
            let (consumed, written) = unsafe { decode_simd_chunks(src, &mut dst) };
            assert_eq!((consumed, written), (16, 12));
            assert_eq!(&dst, b"ABCDEFGHIJKL");
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod simd_b64 {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    /// Classify 16 bytes and produce 6-bit decoded values.
    ///
    /// Returns `(decoded_values, all_valid)` where `all_valid` is true only
    /// when every lane belongs to the base64 alphabet (std + URL-safe).
    ///
    /// # Safety
    /// Caller must ensure SSSE3 is available (`#[target_feature(enable =
    /// "ssse3")]`) before invoking this function.
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn classify_and_decode(input: __m128i) -> (__m128i, bool) {
        // ASCII ranges are < 128, so signed compares are safe for these checks.
        let is_upper = _mm_and_si128(
            _mm_cmpgt_epi8(input, _mm_set1_epi8((b'A' - 1) as i8)),
            _mm_cmpgt_epi8(_mm_set1_epi8((b'Z' + 1) as i8), input),
        );
        let is_lower = _mm_and_si128(
            _mm_cmpgt_epi8(input, _mm_set1_epi8((b'a' - 1) as i8)),
            _mm_cmpgt_epi8(_mm_set1_epi8((b'z' + 1) as i8), input),
        );
        let is_digit = _mm_and_si128(
            _mm_cmpgt_epi8(input, _mm_set1_epi8((b'0' - 1) as i8)),
            _mm_cmpgt_epi8(_mm_set1_epi8((b'9' + 1) as i8), input),
        );
        let is_plus = _mm_cmpeq_epi8(input, _mm_set1_epi8(b'+' as i8));
        let is_dash = _mm_cmpeq_epi8(input, _mm_set1_epi8(b'-' as i8));
        let is_slash = _mm_cmpeq_epi8(input, _mm_set1_epi8(b'/' as i8));
        let is_under = _mm_cmpeq_epi8(input, _mm_set1_epi8(b'_' as i8));

        let is_62 = _mm_or_si128(is_plus, is_dash);
        let is_63 = _mm_or_si128(is_slash, is_under);

        let valid = _mm_or_si128(
            _mm_or_si128(_mm_or_si128(is_upper, is_lower), is_digit),
            _mm_or_si128(is_62, is_63),
        );
        let all_valid = _mm_movemask_epi8(valid) == 0xFFFF;

        let val_upper = _mm_sub_epi8(input, _mm_set1_epi8(65));
        let val_lower = _mm_sub_epi8(input, _mm_set1_epi8(71));
        let val_digit = _mm_add_epi8(input, _mm_set1_epi8(4));
        let val_62 = _mm_set1_epi8(62);
        let val_63 = _mm_set1_epi8(63);

        let mut decoded = _mm_and_si128(is_upper, val_upper);
        decoded = _mm_or_si128(decoded, _mm_and_si128(is_lower, val_lower));
        decoded = _mm_or_si128(decoded, _mm_and_si128(is_digit, val_digit));
        decoded = _mm_or_si128(decoded, _mm_and_si128(is_62, val_62));
        decoded = _mm_or_si128(decoded, _mm_and_si128(is_63, val_63));

        (decoded, all_valid)
    }

    /// Pack 16 x 6-bit values into 12 output bytes.
    ///
    /// # Safety
    /// Caller must ensure SSSE3 is available and `vals` contains 16 valid
    /// base64 lane values (0..=63) from `classify_and_decode`.
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn pack_16_to_12(vals: __m128i) -> [u8; 12] {
        // Merge pairs of 6-bit values into 12-bit values using u16 multiply.
        // Treat vals as u16 lanes (little-endian: low byte is even index, high is odd).
        // Even positions (a,c) need to be multiplied by 64 and added to odd (b,d).
        //
        // u16 lane = [lo, hi] = hi*256 + lo. We want lo*64 + hi.
        // So: lo*64 + hi = lo*64 + hi*1
        // Use _mm_maddubs_epi16 which does: pairs[i] = a[2i]*b[2i] + a[2i+1]*b[2i+1]
        // where a is treated as unsigned, b as signed, result is i16.
        // Set b = [64, 1, 64, 1, ...]: each pair → even*64 + odd*1 = 12-bit merged.
        let merge_const = _mm_set1_epi16(0x0140); // [64, 1] repeated as bytes
        let merged = _mm_maddubs_epi16(vals, merge_const);
        // merged is i16x8: [a0*64+b0, c0*64+d0, a1*64+b1, c1*64+d1, ...]

        // Now merge u16 pairs into u32: (a*64+b)*4096 + (c*64+d) = 24-bit packed.
        // Use _mm_madd_epi16: u32[i] = i16[2i]*i16_const[2i] + i16[2i+1]*i16_const[2i+1]
        let merge32_const = _mm_set1_epi32(0x0001_1000); // [4096, 1] as i16 pair
        let packed = _mm_madd_epi16(merged, merge32_const);
        // packed is i32x4: each contains 24 bits of decoded data.

        // Extract 3 bytes from each u32 (little-endian: bytes [o2, o1, o0, 0]).
        // Shuffle to [o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, ?, ?, ?, ?]
        #[rustfmt::skip]
        let shuffle = _mm_setr_epi8(
            2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12,
            -1, -1, -1, -1, // don't care
        );
        let result = _mm_shuffle_epi8(packed, shuffle);

        let mut out = [0u8; 12];
        store_low12(result, &mut out);
        out
    }

    /// Stores the low 12 bytes of `v` into `out` without touching adjacent memory.
    ///
    /// # Safety
    /// Uses SSE2 stores (`_mm_storeu_si128`); caller must ensure the required
    /// CPU features are available (the caller checks this before entering SIMD
    /// decode). The function is gated behind `ssse3` because it is only called
    /// from SSSE3 decode paths.
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn store_low12(v: __m128i, out: &mut [u8; 12]) {
        // SSSE3 uses a full 128-bit store; stage through 16-byte scratch to
        // avoid writing beyond the 12-byte output contract.
        let mut tmp = [0u8; 16];
        _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, v);
        out.copy_from_slice(&tmp[..12]);
    }

    /// Decode as many 16-byte base64 chunks as possible from `src` into `dst`.
    /// Returns (bytes_consumed, bytes_written).
    ///
    /// # Safety
    /// Caller must ensure `dst` has room for `(src.len() / 16) * 12` bytes.
    /// Requires SSSE3 support.
    #[inline]
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn decode_simd_chunks(src: &[u8], dst: &mut [u8]) -> (usize, usize) {
        let mut si = 0usize;
        let mut di = 0usize;
        let end = src.len() & !15;

        while si < end && di + 12 <= dst.len() {
            let input = _mm_loadu_si128(src.as_ptr().add(si) as *const __m128i);
            let (vals, valid) = classify_and_decode(input);
            if !valid {
                break;
            }
            let packed = pack_16_to_12(vals);
            std::ptr::copy_nonoverlapping(packed.as_ptr(), dst.as_mut_ptr().add(di), 12);
            si += 16;
            di += 12;
        }

        (si, di)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn store_low12_does_not_clobber_adjacent_bytes() {
            #[repr(C)]
            struct Guarded {
                out: [u8; 12],
                guard: [u8; 4],
            }

            let mut guarded = Guarded {
                out: [0u8; 12],
                guard: [0xA5; 4],
            };
            // SAFETY: SSE2 is available on all x86_64 targets. `_mm_set1_epi8` has
            // no memory-safety preconditions.
            let v = unsafe { _mm_set1_epi8(0x11) };
            // SAFETY: `guarded.out` is a 12-byte array, which satisfies store_low12's
            // requirement of a buffer with at least 12 writable bytes.
            unsafe { store_low12(v, &mut guarded.out) };
            assert_eq!(guarded.guard, [0xA5; 4]);
        }

        #[test]
        fn decode_simd_chunks_rejects_invalid_punctuation() {
            let src = b"AAAA:AAAAAAAAAAA";
            let mut dst = [0u8; 12];
            // SAFETY: `src` is a valid byte slice and `dst` has enough room (12 bytes)
            // for one decoded SIMD chunk. SSE2 is available on all x86_64 targets.
            let (consumed, written) = unsafe { decode_simd_chunks(src, &mut dst) };
            assert_eq!((consumed, written), (0, 0));
        }

        #[test]
        fn decode_simd_chunks_decodes_clean_input() {
            let src = b"QUJDREVGR0hJSktM";
            let mut dst = [0u8; 12];
            // SAFETY: `src` is a valid 16-byte slice and `dst` has 12 bytes of space,
            // satisfying decode_simd_chunks' buffer requirements. SSE2 is available.
            let (consumed, written) = unsafe { decode_simd_chunks(src, &mut dst) };
            assert_eq!((consumed, written), (16, 12));
            assert_eq!(&dst, b"ABCDEFGHIJKL");
        }
    }
}

// On architectures without SIMD support, decode_simd_chunks is not available;
// the fast-path in stream_decode_base64 uses the scalar 4-byte batch instead.

/// Returns true if SIMD base64 decode is available at runtime.
///
/// On aarch64, NEON is architecturally guaranteed. On x86_64, SSSE3 is
/// checked via `is_x86_feature_detected!`. On other architectures, returns
/// false and the decoder falls through to the scalar 4-byte batch path.
#[cfg(target_arch = "aarch64")]
fn has_simd_b64() -> bool {
    true // NEON is always available on aarch64
}

#[cfg(target_arch = "x86_64")]
fn has_simd_b64() -> bool {
    is_x86_feature_detected!("ssse3")
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn has_simd_b64() -> bool {
    false
}

/// Streaming base64 decoder that accepts std + URL-safe alphabets.
///
/// All ASCII whitespace (`' '`, `\n`, `\r`, `\t`) is unconditionally skipped
/// during decode, regardless of the `base64_allow_space_ws` setting. That
/// flag only controls whether spaces terminate *spans* during scanning; once
/// a span reaches the decoder, spaces are always tolerated.
///
/// Padding is validated, but an unpadded tail (2 or 3 bytes in the final
/// quantum) is accepted. Output is emitted in bounded chunks (stream decode
/// buffer). The `on_bytes` callback may stop decoding early by returning
/// `ControlFlow::Break(())` (treated as success).
///
/// # Behavior
/// - Once padding is seen, only trailing whitespace is allowed.
/// - Output may have been emitted before an error is returned.
///
/// # Errors
/// - `InvalidByte`: a non-base64, non-whitespace byte was encountered.
/// - `InvalidPadding`: padding appeared in an invalid position or after data.
/// - `TruncatedQuantum`: the input ends with a single leftover base64 char.
///
/// # Notes
/// Used both for full decode and decoded-gate streaming, so it is kept
/// branch-light and bounded in memory.
fn stream_decode_base64(
    input: &[u8],
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), Base64DecodeError> {
    fn flush_buf(
        out: &mut [u8],
        out_len: &mut usize,
        on: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if *out_len == 0 {
            return ControlFlow::Continue(());
        }
        let cf = on(&out[..*out_len]);
        *out_len = 0;
        cf
    }

    let mut quad: [u8; 4] = [0; 4];
    let mut qn = 0usize;
    let mut seen_pad = false;

    let mut out: [u8; STREAM_DECODE_CHUNK_BYTES] = [0; STREAM_DECODE_CHUNK_BYTES];
    let mut out_len = 0usize;
    let headroom = out.len() - 4;

    let mut pos = 0usize;
    while pos < input.len() {
        // Fast path: when no partial quad is pending, use SIMD to decode 16
        // input bytes → 12 output bytes per iteration, then fall back to the
        // 4-byte scalar batch for the tail.
        if qn == 0 && !seen_pad {
            // SIMD path: decode 16-byte chunks directly into the output buffer.
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            if has_simd_b64() {
                let remaining_input = input.len() - pos;
                let remaining_output = headroom.saturating_sub(out_len);
                if remaining_input >= 16 && remaining_output >= 12 {
                    // SAFETY: we checked has_simd_b64() and bounds above.
                    let (consumed, written) =
                        unsafe { simd_b64::decode_simd_chunks(&input[pos..], &mut out[out_len..]) };
                    pos += consumed;
                    out_len += written;
                }
            }

            // Scalar 4-byte batch: handle remaining aligned input after SIMD
            // and on architectures without SIMD support. Uses B64_DECODE_EX
            // where values 0-63 are valid data; anything >= B64_PAD means
            // padding, whitespace, or invalid and must exit to the slow path.
            while pos + 4 <= input.len() && out_len + 3 <= headroom {
                let v0 = B64_DECODE_EX[input[pos] as usize];
                let v1 = B64_DECODE_EX[input[pos + 1] as usize];
                let v2 = B64_DECODE_EX[input[pos + 2] as usize];
                let v3 = B64_DECODE_EX[input[pos + 3] as usize];

                if (v0 | v1 | v2 | v3) >= B64_PAD {
                    break;
                }

                out[out_len] = (v0 << 2) | (v1 >> 4);
                out[out_len + 1] = ((v1 & 0x0F) << 4) | (v2 >> 2);
                out[out_len + 2] = ((v2 & 0x03) << 6) | v3;
                out_len += 3;
                pos += 4;
            }

            // Flush if we filled up during the batch run.
            if out_len >= headroom {
                match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
                    ControlFlow::Continue(()) => {}
                    ControlFlow::Break(()) => return Ok(()),
                }
                continue;
            }
        }

        // ── Slow path: per-byte processing ──
        if pos >= input.len() {
            break;
        }
        let b = input[pos];
        pos += 1;

        let v = B64_DECODE_EX[b as usize];
        if v >= B64_WS_SENTINEL {
            if v == B64_WS_SENTINEL {
                continue;
            }
            return Err(Base64DecodeError::InvalidByte);
        }

        if seen_pad {
            return Err(Base64DecodeError::InvalidPadding);
        }

        quad[qn] = v;
        qn += 1;

        if qn < 4 {
            continue;
        }

        let a = quad[0];
        let b = quad[1];
        let c = quad[2];
        let d = quad[3];

        if a == B64_PAD || b == B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }

        let b0 = (a << 2) | (b >> 4);

        if c == B64_PAD && d != B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }

        if c == B64_PAD && d == B64_PAD {
            out[out_len] = b0;
            out_len += 1;
            seen_pad = true;
        } else {
            let b1 = ((b & 0x0F) << 4) | (c >> 2);

            if d == B64_PAD {
                out[out_len] = b0;
                out[out_len + 1] = b1;
                out_len += 2;
                seen_pad = true;
            } else {
                let b2 = ((c & 0x03) << 6) | d;

                out[out_len] = b0;
                out[out_len + 1] = b1;
                out[out_len + 2] = b2;
                out_len += 3;
            }
        }

        qn = 0;

        if out_len >= headroom {
            match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return Ok(()),
            }
        }
    }

    // Handle unpadded tail.
    if qn == 1 {
        return Err(Base64DecodeError::TruncatedQuantum);
    } else if qn == 2 {
        let a = quad[0];
        let b = quad[1];
        if a == B64_PAD || b == B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }
        let b0 = (a << 2) | (b >> 4);
        out[out_len] = b0;
        out_len += 1;
    } else if qn == 3 {
        let a = quad[0];
        let b = quad[1];
        let c = quad[2];
        if a == B64_PAD || b == B64_PAD || c == B64_PAD {
            return Err(Base64DecodeError::InvalidPadding);
        }
        let b0 = (a << 2) | (b >> 4);
        let b1 = ((b & 0x0F) << 4) | (c >> 2);
        out[out_len] = b0;
        out[out_len + 1] = b1;
        out_len += 2;
    }

    match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Ok(()),
    }
}

#[cfg(test)]
#[derive(Debug)]
enum Base64TestError {
    OutputTooLarge,
}

#[cfg(test)]
fn decode_base64_to_vec(input: &[u8], max_out: usize) -> Result<Vec<u8>, Base64TestError> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut too_large = false;

    stream_decode_base64(input, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    })
    .map_err(|_| Base64TestError::OutputTooLarge)?; // Map internal errors to generic failure for this helper

    if too_large {
        return Err(Base64TestError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform dispatch
// --------------------------

/// Quick prefilter: returns `false` when `buf` cannot possibly contain an
/// encoded payload, allowing the caller to skip the more expensive span scan.
///
/// For URL-percent, checks for `%` (and `+` when `plus_to_space` is set).
/// For base64, always returns `true` because the span finder itself is the
/// real filter (the alphabet is too common for a single-byte prefilter).
pub(super) fn transform_quick_trigger(tc: &TransformConfig, buf: &[u8]) -> bool {
    match tc.id {
        TransformId::UrlPercent => {
            if memchr(b'%', buf).is_some() {
                return true;
            }
            if tc.plus_to_space && memchr(b'+', buf).is_some() {
                return true;
            }
            false
        }
        TransformId::Base64 => true, // span finder is the real filter; engine applies anchor gate when enabled
    }
}

/// Dispatch to the appropriate span finder for the configured transform.
pub(super) fn find_spans_into(tc: &TransformConfig, buf: &[u8], out: &mut impl SpanSink) {
    match tc.id {
        TransformId::UrlPercent => find_url_spans_into(
            buf,
            tc.min_len,
            tc.max_encoded_len,
            tc.max_spans_per_buffer,
            tc.plus_to_space,
            out,
        ),
        TransformId::Base64 => find_base64_spans_into(
            buf,
            tc.min_len,
            tc.max_encoded_len,
            tc.max_spans_per_buffer,
            tc.base64_allow_space_ws,
            out,
        ),
    }
}

/// Dispatch to the appropriate streaming decoder, erasing the error type.
///
/// URL-percent decode is infallible (invalid escapes pass through); base64
/// decode may fail on invalid bytes, bad padding, or a truncated final
/// quantum. In either case, `on_bytes` may have been called with partial
/// output before an error is returned.
pub(super) fn stream_decode(
    tc: &TransformConfig,
    input: &[u8],
    on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), ()> {
    match tc.id {
        TransformId::UrlPercent => {
            stream_decode_url_percent(input, tc.plus_to_space, on_bytes);
            Ok(())
        }
        TransformId::Base64 => stream_decode_base64(input, on_bytes).map_err(|_| ()),
    }
}

/// Map a decoded output offset back to the number of encoded bytes consumed.
///
/// Returns the encoded offset (half-open) such that decoding `encoded[0..offset]`
/// would produce at least `decoded_offset` bytes. If `decoded_offset` exceeds
/// decoded output length, returns `encoded.len()`.
pub(super) fn map_decoded_offset(
    tc: &TransformConfig,
    encoded: &[u8],
    decoded_offset: usize,
) -> usize {
    match tc.id {
        TransformId::UrlPercent => map_decoded_offset_url(encoded, decoded_offset),
        TransformId::Base64 => {
            map_decoded_offset_base64(encoded, decoded_offset, tc.base64_allow_space_ws)
        }
    }
}

/// Walk `encoded` byte-by-byte, counting decoded output chars, and return the
/// encoded byte position at which the `decoded_offset`-th output byte has been
/// produced. A `%HH` escape consumes 3 encoded bytes for 1 decoded byte;
/// all other bytes are 1:1.
fn map_decoded_offset_url(encoded: &[u8], decoded_offset: usize) -> usize {
    if decoded_offset == 0 {
        return 0;
    }
    let mut decoded = 0usize;
    let mut i = 0usize;
    while i < encoded.len() {
        if decoded >= decoded_offset {
            break;
        }
        let b = encoded[i];
        if b == b'%' && i + 2 < encoded.len() && is_hex(encoded[i + 1]) && is_hex(encoded[i + 2]) {
            i += 3;
        } else {
            i += 1;
        }
        decoded += 1;
    }
    i.min(encoded.len())
}

/// Walk `encoded` quantum-by-quantum, tracking cumulative decoded byte count,
/// and return the encoded byte position at which `decoded_offset` output bytes
/// have been produced.
///
/// Base64 output bytes arrive at quantum positions 2, 3, and 4 (when not
/// padding). The function returns as soon as the running total reaches
/// `decoded_offset`, so it never decodes more than necessary.
fn map_decoded_offset_base64(encoded: &[u8], decoded_offset: usize, allow_space_ws: bool) -> usize {
    if decoded_offset == 0 {
        return 0;
    }
    let total_decoded = base64_decoded_len(encoded, allow_space_ws);
    if decoded_offset >= total_decoded {
        return encoded.len();
    }
    let mut decoded = 0usize;
    let mut quad: [u8; 4] = [0; 4];
    let mut qn = 0usize;
    let mut i = 0usize;

    while i < encoded.len() {
        let b = encoded[i];
        i += 1;
        let v = B64_DECODE_EX[b as usize];
        if v == B64_WS_SENTINEL {
            if b == b' ' && !allow_space_ws {
                break;
            }
            continue;
        }
        if v == B64_INVALID {
            break;
        }
        quad[qn] = v;
        qn += 1;

        if qn == 2 {
            decoded += 1;
            if decoded >= decoded_offset {
                return i;
            }
        } else if qn == 3 {
            if quad[2] == B64_PAD {
                break;
            }
            decoded += 1;
            if decoded >= decoded_offset {
                return i;
            }
        } else if qn == 4 {
            if quad[2] == B64_PAD {
                break;
            }
            if quad[3] != B64_PAD {
                decoded += 1;
                if decoded >= decoded_offset {
                    return i;
                }
            }
            qn = 0;
        }
    }

    i.min(encoded.len())
}

/// Compute the total decoded byte count for `encoded` without materializing
/// the output. Used by [`map_decoded_offset_base64`] to detect whether the
/// requested offset exceeds the payload, allowing an early `encoded.len()`
/// return.
fn base64_decoded_len(encoded: &[u8], allow_space_ws: bool) -> usize {
    let mut decoded = 0usize;
    let mut quad: [u8; 4] = [0; 4];
    let mut qn = 0usize;

    for &b in encoded {
        let v = B64_DECODE_EX[b as usize];
        if v == B64_WS_SENTINEL {
            // Space is only whitespace when allow_space_ws is set; otherwise
            // it terminates the scan (same as B64_INVALID).
            if b == b' ' && !allow_space_ws {
                break;
            }
            continue;
        }
        if v == B64_INVALID {
            break;
        }
        quad[qn] = v;
        qn += 1;

        if qn == 2 {
            decoded += 1;
        } else if qn == 3 {
            if quad[2] == B64_PAD {
                break;
            }
            decoded += 1;
        } else if qn == 4 {
            if quad[2] == B64_PAD {
                break;
            }
            if quad[3] != B64_PAD {
                decoded += 1;
            }
            qn = 0;
        }
    }

    decoded
}

/// Decode into a `Vec` with output-size protection (tests only).
#[cfg(test)]
pub(super) fn decode_to_vec(
    tc: &TransformConfig,
    input: &[u8],
    max_out: usize,
) -> Result<Vec<u8>, ()> {
    match tc.id {
        TransformId::UrlPercent => {
            decode_url_percent_to_vec(input, tc.plus_to_space, max_out).map_err(|_| ())
        }
        TransformId::Base64 => decode_base64_to_vec(input, max_out).map_err(|_| ()),
    }
}

// --------------------------
// Benchmark helpers (bench feature only)
// --------------------------

/// Benchmark helper: stream decode URL percent-encoding, discarding output.
/// Returns bytes successfully decoded.
#[cfg(feature = "bench")]
pub fn bench_stream_decode_url(input: &[u8], plus_to_space: bool) -> usize {
    let mut decoded_bytes = 0usize;
    stream_decode_url_percent(input, plus_to_space, |chunk| {
        decoded_bytes += chunk.len();
        ControlFlow::Continue(())
    });
    decoded_bytes
}

/// Benchmark helper: stream decode Base64, discarding output.
/// Returns bytes successfully decoded.
#[cfg(feature = "bench")]
pub fn bench_stream_decode_base64(input: &[u8]) -> usize {
    let mut decoded_bytes = 0usize;
    let _ = stream_decode_base64(input, |chunk| {
        decoded_bytes += chunk.len();
        ControlFlow::Continue(())
    });
    decoded_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Gate, TransformConfig, TransformId, TransformMode};

    /// Verifies that `==` padding split across chunk boundaries produces a
    /// single span covering both `=` chars.
    ///
    /// Input: chunk1 = `QUJDRA=` (offset 0), chunk2 = `=X` (offset 7).
    /// Expected span: `0..8` covering `QUJDRA==`; `X` must NOT be included.
    ///
    /// This guards against a regression where padding-tail mode was missing
    /// and the scanner would either:
    /// - emit `0..7` (missing the second `=`), or
    /// - merge `X` into the span if it looked base64-ish.
    #[test]
    fn base64_span_stream_splits_on_padding_across_chunks() {
        let tc = TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 1024,
            max_decoded_bytes: 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        };

        let mut stream = Base64SpanStream::new(&tc);
        let mut spans = Vec::new();
        let mut on_span = |lo: u64, hi: u64| -> bool {
            spans.push((lo, hi));
            true
        };

        stream.feed(b"QUJDRA=", 0, &mut on_span);
        stream.feed(b"=X", 7, &mut on_span);
        stream.finish(9, &mut on_span);

        assert!(
            spans.iter().any(|&(lo, hi)| lo == 0 && hi == 8),
            "expected span 0..8, got {spans:?}"
        );
    }

    #[test]
    fn base64_skip_chars_fast_path_exact_hit_returns_offset() {
        assert_eq!(base64_skip_chars(b"QUJD", 4, false), Some(4));
        assert_eq!(base64_skip_chars(b"QUJDREVG", 8, false), Some(8));
    }
}
