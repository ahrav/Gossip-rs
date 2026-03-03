//! Byte-offset to line-number mapping for eval corpus files.
//!
//! [`LineIndex`] bridges scanner output (byte offsets) and ground-truth
//! annotations (line numbers). The matching layer ([`crate::matching`])
//! builds one index per file, validates finding byte offsets against
//! [`LineIndex::data_len`], and calls [`LineIndex::line_range`] to convert
//! finding byte spans into inclusive line ranges for overlap comparison
//! with [`crate::types::TruthItem`] annotations.
//!
//! # Complexity
//!
//! Build once per file in O(b) time where b = file size in bytes, using
//! [`memchr`]-based newline scanning. Query in O(log L) via binary search
//! where L = number of lines.
//!
//! # Line-ending conventions
//!
//! Line endings are identified by `\n` (LF). Bare `\r` (CR) without a
//! following `\n` is treated as line content, not a line separator. CRLF
//! (`\r\n`) is handled correctly — the `\r` becomes trailing content on the
//! preceding line; the `\n` triggers the line break.
//!
//! A trailing newline does **not** create an entry for the empty region
//! after it. For `b"foo\nbar\n"`, `line_starts` is `[0, 4]` (two lines),
//! not `[0, 4, 8]`. This matches the POSIX convention where `\n` is a line
//! terminator, not a separator.

/// Maps byte offsets to 1-indexed line numbers within a single file.
///
/// Internally stores the byte offset of the first byte of each line in a
/// sorted, immutable array. Line N corresponds to `line_starts[N-1]`, so
/// `line_starts[0]` is always 0 (line 1 starts at byte 0).
///
/// # Example
///
/// ```rust,ignore
/// let data = b"hello\nworld\n";
/// let idx = LineIndex::new(data);
/// assert_eq!(idx.data_len(), 12);           // 12 bytes total
/// assert_eq!(idx.line_count(), 2);          // two lines (trailing \n is a terminator)
/// assert_eq!(idx.line_of(0), 1);            // 'h' is on line 1
/// assert_eq!(idx.line_of(6), 2);            // 'w' is on line 2
/// assert_eq!(idx.line_range(0, 7), (1, 2)); // [0,7) spans lines 1–2
/// ```
///
/// # Invariants
///
/// - `line_starts` is non-empty (always contains at least `[0]`).
/// - `line_starts` is strictly monotonically increasing.
/// - `line_starts[0] == 0`.
/// - Every `line_starts[i]` for `i > 0` immediately follows a `\n` byte
///   in the original data.
///
/// # Limits
///
/// Supports files up to [`u32::MAX`] bytes (~4 GiB). The constructor panics
/// on larger inputs. Query methods accept `u64` offsets because the scanner
/// emits 64-bit streaming byte offsets; the assert in [`Self::line_of`]
/// catches any mismatch at the call site rather than silently truncating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineIndex {
    /// Byte offset of the first byte of each line. Immutable after
    /// construction — `Box<[u32]>` prevents accidental push/resize.
    line_starts: Box<[u32]>,
    /// Length of the original data, retained for bounds checking in
    /// [`Self::line_of`] without needing a reference to the source bytes.
    data_len: u32,
}

impl LineIndex {
    /// Build a line index from raw file content.
    ///
    /// Scans for `\n` bytes using [`memchr`] (SIMD-accelerated on supported
    /// platforms). Each `\n` that is *not* the final byte registers the
    /// following byte as a new line start. A trailing `\n` does not create
    /// an entry for the empty region after it (POSIX terminator semantics).
    ///
    /// Pre-allocates assuming ~32 bytes per line to avoid repeated
    /// reallocation. Typical source files have longer lines, so this
    /// slightly over-provisions capacity.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` exceeds [`u32::MAX`]. Byte offsets are stored as
    /// `u32` internally, so larger files would silently corrupt the index.
    pub fn new(data: &[u8]) -> Self {
        assert!(
            data.len() <= u32::MAX as usize,
            "LineIndex supports files up to {} bytes, got {}",
            u32::MAX,
            data.len()
        );
        let data_len = data.len() as u32;

        // Pre-allocate assuming ~32 bytes per line. Typical source lines are
        // longer, so this over-provisions capacity slightly, avoiding most
        // reallocations.
        let mut line_starts = Vec::with_capacity(data.len() / 32 + 1);
        line_starts.push(0u32);

        for pos in memchr::memchr_iter(b'\n', data) {
            let next = (pos as u32) + 1;
            // Trailing newline: don't create an entry for the empty region
            // after the last `\n`.
            if next < data_len {
                line_starts.push(next);
            }
        }

        assert!(!line_starts.is_empty());
        assert!(line_starts[0] == 0);
        // O(n) monotonicity check — debug-only due to cost on large files.
        debug_assert!(line_starts.windows(2).all(|w| w[0] < w[1]));

        Self {
            line_starts: line_starts.into_boxed_slice(),
            data_len,
        }
    }

    /// Returns the 1-indexed line number containing `byte_offset`.
    ///
    /// Uses [`partition_point`] (binary search) over the line-start offsets.
    /// No heap allocation.
    ///
    /// Accepts `byte_offset == data_len` (one-past-the-end) to support
    /// two edge cases: a zero-width range at EOF where `byte_start == data_len`,
    /// and a range ending one past the file where `byte_end == data_len + 1`
    /// (so `line_of(byte_end - 1)` receives `data_len`). Callers passing raw
    /// scanner offsets should validate against [`data_len`] first, as
    /// [`crate::matching`] does.
    ///
    /// The parameter is `u64` rather than `u32` because the scanner emits
    /// 64-bit streaming byte offsets. The assert catches overflow at the
    /// call site rather than silently truncating to `u32`.
    ///
    /// [`partition_point`]: slice::partition_point
    /// [`line_range`]: Self::line_range
    /// [`data_len`]: Self::data_len
    ///
    /// # Panics
    ///
    /// Panics if `byte_offset` exceeds the indexed data length.
    #[inline]
    pub fn line_of(&self, byte_offset: u64) -> u32 {
        assert!(
            byte_offset <= self.data_len as u64,
            "byte offset {} out of range for {}-byte file",
            byte_offset,
            self.data_len
        );
        // partition_point returns the count of entries where `start <= offset`.
        // Because line_starts is 0-indexed but lines are 1-indexed, this count
        // directly gives the 1-indexed line number (no +1/-1 adjustment needed).
        // The widening cast to u64 avoids truncating the caller's offset.
        let result = self
            .line_starts
            .partition_point(|&s| (s as u64) <= byte_offset) as u32;
        debug_assert!(result >= 1 && result <= self.line_count());
        result
    }

    /// Convert a half-open byte range `[byte_start, byte_end)` to an inclusive
    /// 1-indexed line range `(start_line, end_line)`.
    ///
    /// This is the primary bridge between scanner output (which uses half-open
    /// byte ranges via [`crate::types::NormalizedFinding`]) and ground-truth
    /// annotations (which use inclusive line ranges per
    /// [`crate::types::TruthItem`]). The matching layer calls this once per
    /// finding to project byte spans into line-number space for overlap tests.
    ///
    /// A finding on a single line returns `(n, n)`. A zero-width range
    /// (`byte_start == byte_end`) returns the line containing `byte_start`
    /// for both bounds — this handles metadata-only findings gracefully
    /// rather than underflowing on `byte_end - 1`.
    ///
    /// # Panics
    ///
    /// Panics if `byte_end < byte_start` (inverted range), if
    /// `byte_start > data_len`, or if `byte_end > data_len + 1` (for
    /// non-zero-width ranges, the last checked offset is `byte_end - 1`).
    #[inline]
    pub fn line_range(&self, byte_start: u64, byte_end: u64) -> (u32, u32) {
        assert!(
            byte_end >= byte_start,
            "inverted byte range: [{byte_start}, {byte_end})"
        );
        let start_line = self.line_of(byte_start);
        // Half-open to inclusive: the last byte *inside* the range is at
        // `byte_end - 1`, so we look up the line containing that byte.
        // For zero-width ranges this would underflow, so we short-circuit.
        let end_line = if byte_end > byte_start {
            self.line_of(byte_end - 1)
        } else {
            start_line
        };
        debug_assert!(start_line <= end_line);
        (start_line, end_line)
    }

    /// Length of the original data in bytes.
    ///
    /// The matching layer checks `finding.byte_end <= data_len()` before
    /// calling [`line_of`] or [`line_range`], which panic on out-of-bounds
    /// offsets. This gate turns stale scanner output or truncated file reads
    /// into a diagnostic counter rather than a panic.
    ///
    /// [`line_of`]: Self::line_of
    /// [`line_range`]: Self::line_range
    #[inline]
    pub fn data_len(&self) -> u32 {
        self.data_len
    }

    /// Total number of lines in the indexed data.
    ///
    /// Always >= 1: even an empty file is treated as having one empty line,
    /// matching the convention used by most text editors (vim, VS Code). Equal to
    /// `line_starts.len()` — the length of the internal offset array.
    #[inline]
    pub fn line_count(&self) -> u32 {
        // Safe: line_starts.len() <= data_len + 1, and data_len <= u32::MAX.
        self.line_starts.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Spot-check tests ──────────────────────────────────────────
    //
    // These anchor concrete examples for readability and debugging.
    // The property tests below (P1–P7) cover the full input space.

    #[test]
    #[allow(clippy::type_complexity)]
    fn single_line_inputs() {
        // (label, input, expected_line_count, [(byte_offset, expected_line)])
        let cases: &[(&str, &[u8], u32, &[(u64, u32)])] = &[
            ("empty", b"", 1, &[(0, 1)]),
            ("no newline", b"abc", 1, &[(0, 1), (2, 1)]),
            ("bare newline", b"\n", 1, &[(0, 1)]),
            (
                "trailing newline (POSIX terminator)",
                b"abc\n",
                1,
                &[(0, 1), (3, 1)],
            ),
        ];
        for &(label, input, expected_count, offsets) in cases {
            let idx = LineIndex::new(input);
            assert_eq!(idx.line_count(), expected_count, "{label}: line_count");
            for &(offset, expected_line) in offsets {
                assert_eq!(
                    idx.line_of(offset),
                    expected_line,
                    "{label}: line_of({offset})"
                );
            }
        }
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn multi_line_inputs() {
        // (label, input, expected_line_count, [(byte_offset, expected_line)],
        //  optional [(byte_start, byte_end, expected_start_line, expected_end_line)])
        let cases: &[(&str, &[u8], u32, &[(u64, u32)], &[(u64, u64, u32, u32)])] = &[
            (
                "two lines, trailing newline",
                b"aaa\nbbb\n",
                2,
                &[(0, 1), (3, 1), (4, 2)], // \n byte belongs to line 1
                &[(0, 5, 1, 2)],
            ),
            (
                "three consecutive newlines",
                b"\n\n\n",
                3,
                &[(0, 1), (1, 2), (2, 3)],
                &[],
            ),
            (
                "empty line in middle",
                b"a\n\nb",
                3,
                &[(0, 1), (2, 2), (3, 3)],
                &[],
            ),
            (
                "no trailing newline",
                b"a\nb\nc",
                3,
                &[(0, 1), (2, 2), (4, 3)],
                &[],
            ),
        ];
        for &(label, input, expected_count, offsets, ranges) in cases {
            let idx = LineIndex::new(input);
            assert_eq!(idx.line_count(), expected_count, "{label}: line_count");
            for &(offset, expected_line) in offsets {
                assert_eq!(
                    idx.line_of(offset),
                    expected_line,
                    "{label}: line_of({offset})"
                );
            }
            for &(start, end, expected_start, expected_end) in ranges {
                assert_eq!(
                    idx.line_range(start, end),
                    (expected_start, expected_end),
                    "{label}: line_range({start}, {end})"
                );
            }
        }
    }

    #[test]
    fn line_range_zero_width() {
        // Zero-width span at a line boundary should return the starting line.
        let idx = LineIndex::new(b"abc\ndef");
        assert_eq!(idx.line_range(4, 4), (2, 2));
        assert_eq!(idx.line_range(0, 0), (1, 1));
    }

    #[test]
    fn line_range_spanning_lines() {
        // b"abc\ndef\nghi": bytes 0-2=abc, 3=\n, 4-6=def, 7=\n, 8-10=ghi
        let idx = LineIndex::new(b"abc\ndef\nghi");
        // [0, 8) — last included byte is 7 (\n at end of line 2).
        assert_eq!(idx.line_range(0, 8), (1, 2));
        // [0, 9) — last included byte is 8 ('g' on line 3).
        assert_eq!(idx.line_range(0, 9), (1, 3));
        // [4, 7) — bytes 4-6 = "def", entirely line 2.
        assert_eq!(idx.line_range(4, 7), (2, 2));
    }

    #[test]
    fn crlf_handling() {
        // b"abc\r\ndef\r\n": \r at positions 3 and 8, \n at positions 4 and 9.
        // \r is treated as line content, not a line separator.
        let idx = LineIndex::new(b"abc\r\ndef\r\n");
        assert_eq!(idx.line_count(), 2);
        assert_eq!(idx.line_of(3), 1); // \r belongs to line 1
        assert_eq!(idx.line_of(4), 1); // \n belongs to line 1
        assert_eq!(idx.line_of(5), 2); // 'd' starts line 2
        assert_eq!(idx.line_of(8), 2); // \r belongs to line 2
    }

    #[test]
    fn line_of_at_eof() {
        // Offset == data_len is one-past-the-end, allowed for half-open ranges.
        let idx = LineIndex::new(b"abc\ndef\n");
        assert_eq!(idx.line_of(8), 2); // data_len = 8, maps to last line

        let idx = LineIndex::new(b"abc\ndef");
        assert_eq!(idx.line_of(7), 2); // data_len = 7, no trailing newline
    }

    // ── Property tests ────────────────────────────────────────────
    //
    // Seven properties that together guarantee correctness of the
    // byte-to-line mapping:
    //
    // P1  Monotonicity — line numbers never decrease as offsets increase.
    // P2  Line-count formula — line_count == newlines + 1 - trailing.
    // P3  Valid range — every line_of() result is in [1, line_count].
    // P4  Range ordering — line_range() start <= end, bounded by line_count.
    // P5  Newline anchoring — every line_starts[i>0] follows a \n byte.
    // P6  Cross-method — line_range() agrees with line_of() pointwise.
    // P7  Boundary precision — line number increments exactly at \n boundaries.

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// Construct a byte vector with precisely controlled newline placement.
        ///
        /// Each entry in `lens` specifies the number of non-newline bytes for
        /// that line. Lines are joined by `\n`, and a trailing `\n` is appended
        /// iff `trailing_newline` is true. This gives the property tests full
        /// control over line structure, unlike random byte generation where `\n`
        /// appears only ~1/256 of the time.
        fn build_from_line_lengths(lens: &[usize], trailing_newline: bool) -> Vec<u8> {
            let mut data = Vec::new();
            for (i, &len) in lens.iter().enumerate() {
                data.extend(std::iter::repeat_n(b'x', len));
                if i + 1 < lens.len() || trailing_newline {
                    data.push(b'\n');
                }
            }
            data
        }

        /// Composite strategy producing byte vectors with high newline density.
        ///
        /// Four variants target different edge-case profiles:
        ///
        /// - **Structured**: explicit line lengths joined by `\n`, with or
        ///   without a trailing newline. Exercises the POSIX terminator
        ///   convention and multi-line files of varying shape.
        /// - **Dense**: 50/50 mix of `\n` and filler. Stresses consecutive
        ///   newlines (empty lines) and rapid line-boundary transitions.
        /// - **Long single line**: up to 2000 bytes with no newlines. Ensures
        ///   the index degrades gracefully to `line_starts == [0]`.
        /// - **All newlines**: maximizes line count per byte, exercising the
        ///   trailing-newline exclusion at every position.
        fn line_data() -> impl Strategy<Value = Vec<u8>> {
            prop_oneof![
                // Structured: generate line lengths, join with \n.
                (proptest::collection::vec(0usize..100, 0..50), any::<bool>())
                    .prop_map(|(lens, trailing)| build_from_line_lengths(&lens, trailing)),
                // Dense: only \n and filler.
                proptest::collection::vec(prop_oneof![Just(b'\n'), Just(b'x')], 0..200),
                // Single long line (no newlines).
                proptest::collection::vec(Just(b'x'), 0..2000),
                // All newlines.
                proptest::collection::vec(Just(b'\n'), 0..100),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            // ── P1: Monotonicity ──────────────────────────────────
            // For all adjacent byte offsets a < b, line_of(a) <= line_of(b).

            #[test]
            fn monotonicity(data in line_data()) {
                let idx = LineIndex::new(&data);
                for a in 0..data.len().saturating_sub(1) {
                    let b = a + 1;
                    let la = idx.line_of(a as u64);
                    let lb = idx.line_of(b as u64);
                    prop_assert!(
                        la <= lb,
                        "monotonicity violated: line_of({}) = {} > line_of({}) = {}",
                        a, la, b, lb
                    );
                }
            }

            // ── P2: Line count formula ────────────────────────────
            // line_count == (number of \n bytes) + 1 - (1 if trailing \n else 0).
            // This is the algebraic identity that defines "POSIX terminator" semantics.

            #[test]
            fn line_count_formula(data in line_data()) {
                let idx = LineIndex::new(&data);
                let newline_count = memchr::memchr_iter(b'\n', &data).count() as u32;
                let trailing = if data.last() == Some(&b'\n') { 1u32 } else { 0 };
                let expected = newline_count + 1 - trailing;
                prop_assert_eq!(
                    idx.line_count(),
                    expected,
                    "newlines={}, trailing={}",
                    newline_count, trailing
                );
            }

            // ── P3: Valid range ───────────────────────────────────
            // Every line_of() result falls in [1, line_count].

            #[test]
            fn valid_range(data in line_data(), offset_frac in 0.0f64..1.0) {
                prop_assume!(!data.is_empty());
                let idx = LineIndex::new(&data);
                let offset = ((data.len() - 1) as f64 * offset_frac) as u64;
                let line = idx.line_of(offset);
                prop_assert!(
                    line >= 1,
                    "line_of({}) = {} < 1", offset, line
                );
                prop_assert!(
                    line <= idx.line_count(),
                    "line_of({}) = {} > line_count = {}",
                    offset, line, idx.line_count()
                );
            }

            // ── P4: Range ordered + bounded ───────────────────────
            // line_range() returns (s, e) with 1 <= s <= e <= line_count,
            // and zero-width byte ranges always produce s == e.

            #[test]
            fn range_ordered(
                data in line_data(),
                s_frac in 0.0f64..1.0,
                e_frac in 0.0f64..1.0,
            ) {
                prop_assume!(!data.is_empty());
                let idx = LineIndex::new(&data);
                let max_offset = data.len() as u64;
                let raw_s = (max_offset as f64 * s_frac) as u64;
                let raw_e = (max_offset as f64 * e_frac) as u64;
                let (s, e) = if raw_s <= raw_e { (raw_s, raw_e) } else { (raw_e, raw_s) };

                let (start_line, end_line) = idx.line_range(s, e);
                prop_assert!(start_line >= 1);
                prop_assert!(end_line <= idx.line_count());
                prop_assert!(
                    start_line <= end_line,
                    "line_range({}, {}) = ({}, {})",
                    s, e, start_line, end_line
                );

                // Zero-width ranges always produce start == end.
                if s == e {
                    prop_assert_eq!(
                        start_line, end_line,
                        "zero-width range should give equal lines"
                    );
                }
            }

            // ── P5: Boundaries follow newlines ────────────────────
            // line_starts[0] == 0, and every line_starts[i>0] is preceded by \n.
            // This is the structural invariant the constructor must maintain.

            #[test]
            fn boundaries_follow_newlines(data in line_data()) {
                let idx = LineIndex::new(&data);
                for (i, &start) in idx.line_starts.iter().enumerate() {
                    if i == 0 {
                        prop_assert_eq!(start, 0, "line_starts[0] must be 0");
                    } else {
                        let prev_byte = data[(start - 1) as usize];
                        prop_assert_eq!(
                            prev_byte, b'\n',
                            "line_starts[{}] = {}, but byte at {} is not \\n",
                            i, start, start - 1
                        );
                    }
                }
            }

            // ── P6: Cross-method consistency ──────────────────────
            // For any half-open byte range [s, e_excl) with s < e_excl:
            //   line_range(s, e_excl) == (line_of(s), line_of(e_excl - 1))
            // Ensures the convenience method and the primitive agree.

            #[test]
            fn cross_method_consistency(
                data in line_data(),
                s_frac in 0.0f64..1.0,
                e_frac in 0.0f64..1.0,
            ) {
                prop_assume!(!data.is_empty());
                let idx = LineIndex::new(&data);
                let max_offset = (data.len() - 1) as u64;
                let raw_s = (max_offset as f64 * s_frac) as u64;
                let raw_e = (max_offset as f64 * e_frac) as u64;
                let (s, e) = if raw_s <= raw_e { (raw_s, raw_e) } else { (raw_e, raw_s) };
                // Convert to half-open: end is exclusive, so add 1 (capped at data.len()).
                let e_exclusive = (e + 1).min(data.len() as u64);

                let (range_start, range_end) = idx.line_range(s, e_exclusive);
                let direct_start = idx.line_of(s);
                let direct_end = idx.line_of(e);
                prop_assert_eq!(
                    range_start, direct_start,
                    "line_range start disagrees: range({}, {})=({}, {}), line_of({})={}",
                    s, e_exclusive, range_start, range_end, s, direct_start
                );
                prop_assert_eq!(
                    range_end, direct_end,
                    "line_range end disagrees: range({}, {})=({}, {}), line_of({})={}",
                    s, e_exclusive, range_start, range_end, e, direct_end
                );
            }

            // ── P7: Newline boundary precision ────────────────────
            // Line numbers change exactly at \n boundaries: stepping past a \n
            // that starts a new line increments the line number by 1; all other
            // byte transitions leave it unchanged.

            #[test]
            fn newline_boundary_precision(data in line_data()) {
                prop_assume!(data.len() >= 2);
                let idx = LineIndex::new(&data);
                for (p, &byte) in data.iter().enumerate().take(data.len() - 1) {
                    let curr = idx.line_of(p as u64);
                    let next = idx.line_of((p + 1) as u64);
                    if byte == b'\n' {
                        // If the next byte starts a new line (is in
                        // line_starts), the line number must increase by 1.
                        // If the \n is trailing (next byte is NOT in
                        // line_starts), the line number stays the same
                        // because both bytes belong to the last line.
                        let next_byte_starts_line =
                            idx.line_starts.binary_search(&((p + 1) as u32)).is_ok();
                        if next_byte_starts_line {
                            prop_assert_eq!(
                                next, curr + 1,
                                "at \\n position {}: expected line {} -> {}",
                                p, curr, curr + 1
                            );
                        } else {
                            prop_assert_eq!(
                                next, curr,
                                "trailing \\n at {}: line should not advance",
                                p
                            );
                        }
                    } else {
                        prop_assert_eq!(
                            next, curr,
                            "non-\\n at {}: line should not change ({} -> {})",
                            p, curr, next
                        );
                    }
                }
            }
        }
    }
}
