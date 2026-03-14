//! Dotenv (`.env`, `.env.*`) text extractor.
//!
//! Extracts normalized `KEY=VALUE` lines from dotenv content so scan rules keep
//! key context (for example `password=...`, `api_key=...`) while stripping
//! comments, quoting, and escape sequences.
//!
//! # Why extract rather than scan raw text?
//!
//! Raw dotenv files mix scannable secrets with noise (comments, `export`
//! prefixes, quoting punctuation, escape sequences). Feeding them through
//! this extractor first produces a clean `KEY=value\n` stream where every
//! line is a complete assignment, making downstream rule matching both
//! simpler and more accurate.
//!
//! # Supported syntax
//!
//! | Form | Behaviour |
//! |------|-----------|
//! | `KEY=VALUE` | Bare assignment |
//! | `export KEY=VALUE` | Lowercase `export` prefix stripped |
//! | Empty lines, `# ...` | Skipped entirely |
//! | Unquoted value | Leading and trailing whitespace trimmed; `#` starts inline comment at the start of the value or after whitespace |
//! | `'...'` | Single-quoted: literal bytes, no escape processing |
//! | `"..."` | Double-quoted: `\n`, `\r`, `\t`, `\\`, `\"` unescaped; unknown `\x` keeps `x` |
//! | Quoted multiline | Spans physical lines until closing quote |
//!
//! # Algorithm
//!
//! The extractor performs a single forward pass over the input bytes:
//!
//! 1. Advance through lines, skipping blanks and comments.
//! 2. Strip an optional `export` prefix, then locate the `=` separator.
//! 3. Dispatch the value portion to a quoting-specific parser (unquoted,
//!    single-quoted, or double-quoted). Quoted parsers may consume
//!    additional lines from the raw input via the shared `pos` cursor.
//! 4. Each `KEY=value\n` entry is written atomically to `out` using a
//!    checkpoint/rollback pattern: if the value is malformed or the output
//!    budget ([`EXTRACT_OUTPUT_CAP`]) is exhausted, `out` is truncated back
//!    to its pre-entry length so callers never observe a partial assignment.
//!
//! # Performance
//!
//! The parser is byte-oriented and allocation-free beyond the caller-provided
//! output buffer. Line scanning, delimiter searches (`=`, `'`, `"`, `#`), and
//! plain-text spans inside double-quoted values all use `memchr`/`memchr2` for
//! SIMD-accelerated matching. Malformed lines are skipped without panicking.
//!
//! [`EXTRACT_OUTPUT_CAP`]: super::extract::EXTRACT_OUTPUT_CAP

use memchr::{memchr, memchr2};

use super::extract::{EXTRACT_OUTPUT_CAP, ExtractResult, Extractor};

/// Maximum number of continuation lines a multiline quoted value may span.
///
/// Prevents unbounded scanning when malformed input opens a quote but never
/// closes it. Beyond this limit the value is treated as malformed
/// ([`ValueResult::Skip`]) and the parser moves on.
const MAX_MULTILINE_LINES: usize = 1024;

/// Extracts normalized `KEY=VALUE\n` lines from dotenv files.
///
/// Implements [`Extractor`] by appending one newline-terminated assignment per
/// recognized line. The `scratch` buffer is unused; all work is done directly
/// in `out`. See the [module docs](self) for the full grammar and algorithm.
pub struct DotEnvExtractor;

/// Outcome of attempting to write one `KEY=value\n` entry to `out`.
///
/// The main loop uses this three-way result to decide whether to continue
/// scanning (`Appended`, `Skipped`) or stop early (`CapReached`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineResult {
    /// Entry was fully written to `out`.
    Appended,
    /// The output budget was exhausted; `out` was rolled back and the caller
    /// should stop processing further lines.
    CapReached,
}

/// Result of parsing the value portion of an assignment (`...` in `KEY=...`).
///
/// The caller (`append_entry`) maps these into [`LineResult`] variants and
/// handles the checkpoint rollback on `Skip` and `CapReached`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueResult {
    /// Value was fully parsed and appended to `out` (without trailing newline).
    Ok,
    /// Value was malformed (e.g. EOF inside a quoted string). Caller must
    /// roll back any bytes this parser appended.
    Skip,
    /// Output budget exhausted mid-value. Caller must roll back.
    CapReached,
}

impl Extractor for DotEnvExtractor {
    fn extract(&self, data: &[u8], out: &mut Vec<u8>, _scratch: &mut Vec<u8>) -> ExtractResult {
        let start_len = out.len();
        let mut pos = 0usize;

        while pos < data.len() {
            let line = next_line(data, &mut pos);
            let mut line = line.trim_ascii_start();
            if line.is_empty() || line[0] == b'#' {
                continue;
            }

            line = strip_export_prefix(line);
            let Some(eq) = memchr(b'=', line) else {
                continue;
            };

            let key = line[..eq].trim_ascii();
            if key.is_empty() {
                continue;
            }

            let value = &line[eq + 1..];
            match append_entry(key, value, data, &mut pos, out) {
                LineResult::Appended => {}
                LineResult::CapReached => break,
            }
        }

        if out.len() == start_len {
            ExtractResult::Empty
        } else {
            ExtractResult::Ok
        }
    }
}

/// Append one normalized `KEY=VALUE\n` entry atomically to `out`.
///
/// Uses two rollback mechanisms to maintain invariants:
///
/// - **Output rollback**: `out` is checkpointed before writing and truncated
///   back on any failure, so callers never observe a partial `KEY=value` entry.
/// - **Position rollback**: on `ValueResult::Skip` (malformed quote), the input
///   cursor `pos` is rewound to where it was before the value parser ran. This
///   prevents a runaway multiline quote from swallowing subsequent assignments;
///   instead, each continuation line is re-evaluated as a potential new entry.
fn append_entry(
    key: &[u8],
    value: &[u8],
    data: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> LineResult {
    let checkpoint = out.len();
    if !push_bytes(out, key) || !push_byte(out, b'=') {
        out.truncate(checkpoint);
        return LineResult::CapReached;
    }

    let value_start = out.len();
    let resume_pos = *pos;
    let value = value.trim_ascii_start();
    let value_result = match value.first().copied() {
        Some(b'"') => parse_double_quoted(&value[1..], data, pos, out),
        Some(b'\'') => parse_single_quoted(&value[1..], data, pos, out),
        _ => parse_unquoted(value, out),
    };

    match value_result {
        ValueResult::Ok => {
            // Normalize the value to match what an unquoted re-parse would
            // produce, making the output a true fixed point. Unquoted values
            // are already trimmed by `parse_unquoted` and `trim_ascii_start`
            // in the caller; this catches quoted values whose content has
            // leading or trailing whitespace (e.g. `A=" x "` normalizes to
            // `A=x\n`, matching what a bare `A= x ` would produce).
            let leading_ws = out[value_start..]
                .iter()
                .take_while(|b| b.is_ascii_whitespace())
                .count();
            if leading_ws > 0 {
                out.copy_within(value_start + leading_ws.., value_start);
                out.truncate(out.len() - leading_ws);
            }
            let trim_end = out[value_start..]
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(value_start, |p| value_start + p + 1);
            out.truncate(trim_end);
            if push_byte(out, b'\n') {
                LineResult::Appended
            } else {
                out.truncate(checkpoint);
                LineResult::CapReached
            }
        }
        ValueResult::Skip => {
            // Roll back position so continuation lines consumed by the
            // multiline parser are re-evaluated as independent entries.
            *pos = resume_pos;
            out.truncate(checkpoint);

            // Fallback: emit the first physical line's raw value as unquoted.
            // For a security scanner, silently dropping `DB_URL="postgres://...`
            // would lose credentials. Strip the opening quote char and parse
            // the remainder as unquoted (trim + inline-comment strip).
            let raw = match value.first().copied() {
                Some(b'"' | b'\'') => value[1..].trim_ascii_start(),
                _ => value,
            };
            if !push_bytes(out, key) || !push_byte(out, b'=') {
                out.truncate(checkpoint);
                return LineResult::CapReached;
            }
            match parse_unquoted(raw, out) {
                ValueResult::Ok => {
                    if push_byte(out, b'\n') {
                        LineResult::Appended
                    } else {
                        out.truncate(checkpoint);
                        LineResult::CapReached
                    }
                }
                ValueResult::CapReached => {
                    out.truncate(checkpoint);
                    LineResult::CapReached
                }
                ValueResult::Skip => unreachable!("parse_unquoted never returns Skip"),
            }
        }
        ValueResult::CapReached => {
            out.truncate(checkpoint);
            LineResult::CapReached
        }
    }
}

/// Parse an unquoted value: strip any trailing inline comment (preceded by
/// whitespace), trim trailing whitespace, then append the result.
///
/// Unquoted values are always single-line, so this never advances `pos`.
fn parse_unquoted(value: &[u8], out: &mut Vec<u8>) -> ValueResult {
    let end = unquoted_comment_start(value).unwrap_or(value.len());
    let value = value[..end].trim_ascii_end();
    if push_bytes(out, value) {
        ValueResult::Ok
    } else {
        ValueResult::CapReached
    }
}

/// Parse a single-quoted value: copy bytes literally until the closing `'`.
///
/// Backslashes have no special meaning and are copied verbatim. If the closing
/// quote is not found on the current line, the parser fetches continuation
/// lines from `data` via `pos`, emitting `\n` between segments. Returns
/// [`ValueResult::Skip`] if EOF is reached without a closing quote.
fn parse_single_quoted<'a>(
    mut segment: &'a [u8],
    data: &'a [u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> ValueResult {
    let mut is_continuation = false;
    let mut continuation_lines = 0usize;
    loop {
        if let Some(end_quote) = memchr(b'\'', segment) {
            if is_continuation && !trailing_is_ignorable(&segment[end_quote + 1..]) {
                return ValueResult::Skip;
            }
            if push_bytes(out, &segment[..end_quote]) {
                return ValueResult::Ok;
            }
            return ValueResult::CapReached;
        }

        if !push_bytes(out, segment) {
            return ValueResult::CapReached;
        }
        if *pos >= data.len() {
            return ValueResult::Skip;
        }
        continuation_lines += 1;
        if continuation_lines > MAX_MULTILINE_LINES {
            return ValueResult::Skip;
        }
        if !push_byte(out, b'\n') {
            return ValueResult::CapReached;
        }
        segment = next_line(data, pos);
        is_continuation = true;
    }
}

/// Parse a double-quoted value with escape processing until the closing `"`.
///
/// Recognized escapes: `\n`, `\r`, `\t`, `\\`, `\"`. Any other `\x` drops
/// the backslash and keeps `x`, matching the permissive behavior of most
/// dotenv libraries.
///
/// Like [`parse_single_quoted`], this fetches continuation lines from `data`
/// for multiline values. A backslash at a segment boundary (i.e. `\` is the
/// last byte before a line break) is emitted as a literal `\` because its
/// intended escape target is ambiguous.
fn parse_double_quoted<'a>(
    mut segment: &'a [u8],
    data: &'a [u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
) -> ValueResult {
    let mut is_continuation = false;
    let mut continuation_lines = 0usize;
    loop {
        let mut idx = 0usize;
        while idx < segment.len() {
            let rest = &segment[idx..];
            match memchr2(b'\\', b'"', rest) {
                Some(offset) => {
                    // Bulk-copy plain text before the special byte.
                    if offset > 0 && !push_bytes(out, &rest[..offset]) {
                        return ValueResult::CapReached;
                    }
                    idx += offset;
                    if segment[idx] == b'"' {
                        // On continuation lines, only accept the close-quote
                        // when the remainder of the physical line is
                        // syntactically ignorable (whitespace / comment).
                        // Otherwise this `"` likely belongs to a separate
                        // assignment on the next line; treat the value as
                        // malformed so rollback can re-parse it.
                        if is_continuation && !trailing_is_ignorable(&segment[idx + 1..]) {
                            return ValueResult::Skip;
                        }
                        return ValueResult::Ok;
                    }
                    // Backslash: consume escape pair.
                    idx += 1;
                    if idx < segment.len() {
                        let unescaped = match segment[idx] {
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            b'\\' => b'\\',
                            b'"' => b'"',
                            other => other,
                        };
                        if !push_byte(out, unescaped) {
                            return ValueResult::CapReached;
                        }
                        idx += 1;
                    } else {
                        // Trailing `\` at segment end — emit as literal.
                        if !push_byte(out, b'\\') {
                            return ValueResult::CapReached;
                        }
                    }
                }
                None => {
                    // No special bytes remain — bulk-copy the rest.
                    if !push_bytes(out, rest) {
                        return ValueResult::CapReached;
                    }
                    idx = segment.len();
                }
            }
        }

        if *pos >= data.len() {
            return ValueResult::Skip;
        }
        continuation_lines += 1;
        if continuation_lines > MAX_MULTILINE_LINES {
            return ValueResult::Skip;
        }
        if !push_byte(out, b'\n') {
            return ValueResult::CapReached;
        }
        segment = next_line(data, pos);
        is_continuation = true;
    }
}

/// Check whether the bytes following a closing quote on a continuation line
/// are syntactically ignorable — either empty, whitespace-only, or whitespace
/// followed by a `#` comment. Any other content means the `"` was likely an
/// opening quote for a different assignment, not a valid close for the current
/// multiline value.
fn trailing_is_ignorable(tail: &[u8]) -> bool {
    let trimmed = tail.trim_ascii_start();
    trimmed.is_empty() || trimmed[0] == b'#'
}

/// Find the byte offset of the first `#` that starts an inline comment.
///
/// A `#` qualifies as a comment start only at position 0 or immediately after
/// ASCII whitespace. Mid-token hashes (e.g. `abc#def`, color codes) are kept
/// as part of the value, matching the behavior common among dotenv
/// implementations.
fn unquoted_comment_start(value: &[u8]) -> Option<usize> {
    let mut start = 0;
    while let Some(offset) = memchr(b'#', &value[start..]) {
        let idx = start + offset;
        if idx == 0 || value[idx - 1].is_ascii_whitespace() {
            return Some(idx);
        }
        start = idx + 1;
    }
    None
}

/// Strip a lowercase `export` prefix followed by at least one ASCII
/// whitespace character, returning the remainder.
///
/// Only the exact lowercase spelling is recognized; `EXPORT` and `Export`
/// are left as-is so that `EXPORT_PATH=...` is not misinterpreted.
fn strip_export_prefix(line: &[u8]) -> &[u8] {
    if line.len() <= 6 || &line[..6] != b"export" || !line[6].is_ascii_whitespace() {
        return line;
    }
    line[7..].trim_ascii_start()
}

/// Return the next logical line from `data[*pos..]` and advance `pos` past
/// the LF terminator (if any).
///
/// The returned slice excludes line terminators (both `\n` and `\r\n`).
/// At EOF the final (possibly empty) line is returned and `pos` is left at
/// `data.len()`, so the caller's `while pos < data.len()` naturally exits.
fn next_line<'a>(data: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let start = *pos;
    let remaining = &data[start..];
    let rel = memchr(b'\n', remaining).unwrap_or(remaining.len());
    *pos = start + rel;
    let mut end = *pos;
    if *pos < data.len() {
        *pos += 1;
    }
    if end > start && data[end - 1] == b'\r' {
        end -= 1;
    }
    &data[start..end]
}

/// Append one byte to `out` if the extraction budget has not been reached.
///
/// Returns `false` (without writing) when `out.len() >= EXTRACT_OUTPUT_CAP`,
/// signalling the caller to stop or roll back.
#[inline]
fn push_byte(out: &mut Vec<u8>, b: u8) -> bool {
    if out.len() >= EXTRACT_OUTPUT_CAP {
        return false;
    }
    out.push(b);
    true
}

/// Append `bytes` to `out` if the entire slice fits within the extraction
/// budget.
///
/// This is all-or-nothing: if the combined length would exceed
/// [`EXTRACT_OUTPUT_CAP`], nothing is written and `false` is returned. The
/// atomicity avoids partial value fragments in the output.
#[inline]
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> bool {
    if out.len().saturating_add(bytes.len()) > EXTRACT_OUTPUT_CAP {
        return false;
    }
    out.extend_from_slice(bytes);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Parameterized extraction cases covering every supported syntax variant.
    ///
    /// Each case feeds `input` through `DotEnvExtractor::extract` and asserts
    /// both the returned status and the exact output bytes.
    #[rstest]
    #[case::basic_assignments(
        b"API_KEY=SECRET\nDB_PASSWORD=hunter2\n" as &[u8],
        ExtractResult::Ok,
        b"API_KEY=SECRET\nDB_PASSWORD=hunter2\n" as &[u8],
    )]
    #[case::skips_comments_and_empty_lines(
        b"# comment\n \n\t# another\nTOKEN=abc\n",
        ExtractResult::Ok,
        b"TOKEN=abc\n"
    )]
    #[case::export_prefix(
        b"export API_KEY=abc\n export\tDB_URL=postgres://localhost\n",
        ExtractResult::Ok,
        b"API_KEY=abc\nDB_URL=postgres://localhost\n"
    )]
    #[case::double_quoted_escapes(
        b"KEY=\"line\\nnext\\t\\\"q\\\"\\\\\"\n",
        ExtractResult::Ok,
        b"KEY=line\nnext\t\"q\"\\\n"
    )]
    #[case::single_quoted_keeps_backslashes(
        b"KEY='line\\nnext\\t\\\"q\\\"'\n",
        ExtractResult::Ok,
        b"KEY=line\\nnext\\t\\\"q\\\"\n"
    )]
    #[case::unquoted_trim_and_inline_comment(
        b"A=foo # comment\nB=bar#not_comment\nC=   value   \n",
        ExtractResult::Ok,
        b"A=foo\nB=bar#not_comment\nC=value\n"
    )]
    #[case::multiline_double_quoted(
        b"CERT=\"line1\nline2\"\n",
        ExtractResult::Ok,
        b"CERT=line1\nline2\n"
    )]
    #[case::multiline_single_quoted(
        b"CERT='line1\nline2'\n",
        ExtractResult::Ok,
        b"CERT=line1\nline2\n"
    )]
    #[case::malformed_lines_skipped(
        b"NO_EQUALS\nBROKEN=\"unterminated\nNEXT=ok\n",
        ExtractResult::Ok,
        b"BROKEN=unterminated\nNEXT=ok\n"
    )]
    #[case::empty_when_no_assignments(
        b"# just comments\n   \n",
        ExtractResult::Empty,
        b"" as &[u8],
    )]
    #[case::double_quoted_trailing_whitespace_trimmed(b"A=\" \"\n", ExtractResult::Ok, b"A=\n")]
    #[case::single_quoted_trailing_whitespace_trimmed(
        b"A='value  '\n",
        ExtractResult::Ok,
        b"A=value\n"
    )]
    #[case::quoted_leading_whitespace_trimmed(b"A=' hello'\n", ExtractResult::Ok, b"A=hello\n")]
    #[case::quoted_both_sides_whitespace_trimmed(
        b"A=\" hello \"\n",
        ExtractResult::Ok,
        b"A=hello\n"
    )]
    #[case::multiple_equals_in_value(b"KEY=val=ue\n", ExtractResult::Ok, b"KEY=val=ue\n")]
    #[case::mixed_quote_in_double_quoted(
        b"KEY=\"it's quoted\"\n",
        ExtractResult::Ok,
        b"KEY=it's quoted\n"
    )]
    #[case::hyphen_in_key(b"KEY-NAME=value\n", ExtractResult::Ok, b"KEY-NAME=value\n")]
    #[case::unicode_in_value(
        "KEY=caf\u{00e9}\n".as_bytes(),
        ExtractResult::Ok,
        "KEY=caf\u{00e9}\n".as_bytes()
    )]
    #[case::backslash_at_line_boundary_in_dquote(
        b"KEY=\"hello\\\nworld\"\n",
        ExtractResult::Ok,
        b"KEY=hello\\\nworld\n"
    )]
    #[case::empty_key_skipped(b"=value\nKEY=ok\n", ExtractResult::Ok, b"KEY=ok\n")]
    #[case::windows_crlf(b"K1=v1\r\nK2=v2\r\n", ExtractResult::Ok, b"K1=v1\nK2=v2\n")]
    #[case::windows_crlf_multiline_quoted(
        b"K=\"line1\r\nline2\"\r\n",
        ExtractResult::Ok,
        b"K=line1\nline2\n"
    )]
    #[case::incomplete_double_quote_eof(
        b"A=\"unterminated\n",
        ExtractResult::Ok,
        b"A=unterminated\n"
    )]
    #[case::incomplete_single_quote_eof(
        b"A='unterminated\n",
        ExtractResult::Ok,
        b"A=unterminated\n"
    )]
    #[case::unterminated_double_quote_fallback(
        b"DB_URL=\"postgres://user:pass@host/db\n",
        ExtractResult::Ok,
        b"DB_URL=postgres://user:pass@host/db\n"
    )]
    #[case::unterminated_single_quote_fallback(
        b"SECRET='partial_value\n",
        ExtractResult::Ok,
        b"SECRET=partial_value\n"
    )]
    #[case::crlf_with_export(b"export API_KEY=value\r\n", ExtractResult::Ok, b"API_KEY=value\n")]
    #[case::no_trailing_newline(b"A=1\nB=2", ExtractResult::Ok, b"A=1\nB=2\n")]
    #[case::single_entry_no_trailing_newline(b"SECRET=abc", ExtractResult::Ok, b"SECRET=abc\n")]
    #[case::key_with_spaces_trimmed(b" MY KEY =value\n", ExtractResult::Ok, b"MY KEY=value\n")]
    #[case::null_bytes_in_value(b"KEY=ab\x00cd\n", ExtractResult::Ok, b"KEY=ab\x00cd\n")]
    #[case::export_uppercase_not_stripped(
        b"EXPORT_PATH=foo\n",
        ExtractResult::Ok,
        b"EXPORT_PATH=foo\n"
    )]
    fn extract_cases(
        #[case] input: &[u8],
        #[case] expected_result: ExtractResult,
        #[case] expected_output: &[u8],
    ) {
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, expected_result);
        assert_eq!(out, expected_output);
    }

    /// An unterminated double-quoted value followed by a line whose value
    /// contains a `"` must not swallow the subsequent assignment. The parser
    /// should emit a raw fallback for the malformed entry and still emit the
    /// valid one.
    #[test]
    fn unterminated_dquote_does_not_consume_next_quoted_assignment() {
        let input = b"BROKEN=\"unterminated\nNEXT=\"ok\"\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "BROKEN=unterminated\nNEXT=ok\n",
            "malformed BROKEN should emit raw fallback; NEXT should be independently parsed"
        );
    }

    /// Same as the double-quote variant: an unterminated single-quoted value
    /// must not swallow the next quoted assignment.
    #[test]
    fn unterminated_squote_does_not_consume_next_quoted_assignment() {
        let input = b"BROKEN='unterminated\nNEXT='ok'\n";
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "BROKEN=unterminated\nNEXT=ok\n",
            "malformed BROKEN should emit raw fallback; NEXT should be independently parsed"
        );
    }

    /// Budget enforcement: when `out` is already near capacity the extractor
    /// must not append partial data and must return `Empty`.
    #[test]
    fn respects_extract_output_cap() {
        let mut out = vec![b'x'; EXTRACT_OUTPUT_CAP - 2];
        let original = out.clone();
        let result = DotEnvExtractor.extract(b"A=1\n", &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Empty);
        assert_eq!(out, original);
    }

    /// A value that, combined with its key and newline, exactly fills the
    /// output cap should be emitted. One byte over should be rolled back.
    #[test]
    fn near_cap_boundary() {
        // KEY= takes 4 bytes, trailing \n takes 1 byte → value can be cap-5 bytes.
        let key = b"K";
        let overhead = key.len() + 1 + 1; // key + '=' + '\n'
        let max_val_len = EXTRACT_OUTPUT_CAP - overhead;

        // Exactly at cap: should succeed.
        let val_exact: Vec<u8> = vec![b'x'; max_val_len];
        let mut input = Vec::new();
        input.extend_from_slice(key);
        input.push(b'=');
        input.extend_from_slice(&val_exact);
        input.push(b'\n');
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(&input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert_eq!(out.len(), EXTRACT_OUTPUT_CAP);

        // One byte over: the entry should be rolled back, yielding Empty.
        let val_over: Vec<u8> = vec![b'x'; max_val_len + 1];
        let mut input = Vec::new();
        input.extend_from_slice(key);
        input.push(b'=');
        input.extend_from_slice(&val_over);
        input.push(b'\n');
        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(&input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Empty);
        assert!(out.is_empty());
    }

    /// A multiline quoted value exceeding `MAX_MULTILINE_LINES` continuation
    /// lines is treated as malformed. The parser skips it and continues with
    /// subsequent assignments.
    #[test]
    fn multiline_limit_exceeded_skips_entry() {
        // Build input: A="line\nline\n...line (>1024 continuations, never closed)
        // followed by a valid assignment.
        let mut input = b"A=\"start".to_vec();
        for _ in 0..MAX_MULTILINE_LINES + 10 {
            input.extend_from_slice(b"\ncontinuation");
        }
        input.extend_from_slice(b"\nOK=yes\n");

        let mut out = Vec::new();
        let result = DotEnvExtractor.extract(&input, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(
            out.windows(b"OK=yes\n".len()).any(|w| w == b"OK=yes\n"),
            "valid assignment after the runaway quote should still be emitted"
        );
        assert!(
            out.starts_with(b"A=start\n"),
            "the runaway multiline value should emit the first line as raw fallback"
        );
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Generate a single-line dotenv entry (no embedded newlines in values).
    ///
    /// Suitable for tests that require idempotent output (re-extracting the
    /// output yields the same bytes). Multiline quoted values are excluded
    /// because the output format uses bare `\n` as both line separator and
    /// embedded literal, so multiline values inherently lose structure on
    /// re-parse.
    fn dotenv_line_single() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // KEY=VALUE (unquoted)
            "[A-Z_]{1,20}=[a-zA-Z0-9_]{0,40}\n".prop_map(|s| s.into_bytes()),
            // comment
            "# [a-zA-Z ]{0,40}\n".prop_map(|s| s.into_bytes()),
            // blank
            Just(b"\n".to_vec()),
            // export KEY=VALUE
            "export [A-Z_]{1,20}=[a-zA-Z0-9_]{0,40}\n".prop_map(|s| s.into_bytes()),
            // double-quoted (simple)
            "[A-Z_]{1,20}=\"[a-zA-Z0-9_ ]{0,40}\"\n".prop_map(|s| s.into_bytes()),
            // single-quoted (simple)
            "[A-Z_]{1,20}='[a-zA-Z0-9_ ]{0,40}'\n".prop_map(|s| s.into_bytes()),
            // double-quoted with idempotency-safe escapes (\\t, \\\\)
            //
            // Excluded: \\n and \\r produce literal newlines that split on
            // re-parse; \\" produces a `"` that triggers quoting on re-parse.
            // All excluded escapes are covered by `dotenv_line()`.
            (
                "[A-Z_]{1,20}",
                prop::collection::vec(
                    prop_oneof![
                        "[a-zA-Z0-9_ ]{1,10}".prop_map(|s| s.into_bytes()),
                        Just(b"\\t".to_vec()),
                        Just(b"\\\\".to_vec()),
                    ],
                    1..6,
                )
            )
                .prop_map(|(key, parts)| {
                    let mut line = key.into_bytes();
                    line.extend_from_slice(b"=\"");
                    for p in parts {
                        line.extend_from_slice(&p);
                    }
                    line.extend_from_slice(b"\"\n");
                    line
                }),
            // single-quoted with literal backslash sequences
            (
                "[A-Z_]{1,20}",
                "[a-zA-Z0-9_]{0,10}\\\\[t\"\\\\][a-zA-Z0-9_]{0,10}"
            )
                .prop_map(|(key, val)| {
                    let mut line = key.into_bytes();
                    line.push(b'\'');
                    line.extend_from_slice(val.as_bytes());
                    line.extend_from_slice(b"'\n");
                    line
                }),
        ]
    }

    /// Generate a dotenv line including multiline quoted variants.
    ///
    /// Includes all single-line variants plus multiline double- and
    /// single-quoted values with embedded newlines. Not suitable for
    /// idempotency or well-formedness tests (multiline values produce
    /// output lines without `=` separators).
    fn dotenv_line() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // All single-line variants (8 arms weighted 8×).
            8 => dotenv_line_single(),
            // double-quoted with newline-producing escapes (\\n, \\r)
            1 => (
                "[A-Z_]{1,20}",
                prop::collection::vec(
                    prop_oneof![
                        "[a-zA-Z0-9_ ]{1,10}".prop_map(|s| s.into_bytes()),
                        Just(b"\\n".to_vec()),
                        Just(b"\\r".to_vec()),
                        Just(b"\\t".to_vec()),
                        Just(b"\\\\".to_vec()),
                        Just(b"\\\"".to_vec()),
                    ],
                    1..6,
                )
            )
                .prop_map(|(key, parts)| {
                    let mut line = key.into_bytes();
                    line.extend_from_slice(b"=\"");
                    for p in parts {
                        line.extend_from_slice(&p);
                    }
                    line.extend_from_slice(b"\"\n");
                    line
                }),
            // double-quoted with escape sequences producing non-newline output
            1 => "[A-Z_]{1,20}=\"[a-zA-Z0-9_ ]{0,15}\\\\n[a-zA-Z0-9_ ]{0,15}\"\n"
                .prop_map(|s| s.into_bytes()),
            // unquoted with inline comment
            1 => "[A-Z_]{1,20}=[a-zA-Z0-9_]{1,20} #[a-zA-Z ]{0,20}\n"
                .prop_map(|s| s.into_bytes()),
            // CRLF line ending
            1 => "[A-Z_]{1,20}=[a-zA-Z0-9_]{0,40}\r\n".prop_map(|s| s.into_bytes()),
            // unterminated double quote (triggers fallback)
            1 => "[A-Z_]{1,20}=\"[a-zA-Z0-9_]{0,40}\n".prop_map(|s| s.into_bytes()),
            // unterminated single quote (triggers fallback)
            1 => "[A-Z_]{1,20}='[a-zA-Z0-9_]{0,40}\n".prop_map(|s| s.into_bytes()),
            // multiline double-quoted (embedded newline before closing quote)
            1 => ("[A-Z_]{1,20}", "[a-zA-Z0-9_]{1,20}", "[a-zA-Z0-9_]{1,20}").prop_map(
                |(key, line1, line2)| {
                    let mut line = key.into_bytes();
                    line.extend_from_slice(b"=\"");
                    line.extend_from_slice(line1.as_bytes());
                    line.push(b'\n');
                    line.extend_from_slice(line2.as_bytes());
                    line.extend_from_slice(b"\"\n");
                    line
                }
            ),
            // multiline single-quoted (embedded newline before closing quote)
            1 => ("[A-Z_]{1,20}", "[a-zA-Z0-9_]{1,20}", "[a-zA-Z0-9_]{1,20}").prop_map(
                |(key, line1, line2)| {
                    let mut line = key.into_bytes();
                    line.extend_from_slice(b"='");
                    line.extend_from_slice(line1.as_bytes());
                    line.push(b'\n');
                    line.extend_from_slice(line2.as_bytes());
                    line.extend_from_slice(b"'\n");
                    line
                }
            ),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(crate::test_utils::proptest_cases(512)))]

        /// Output length must never exceed the extraction budget.
        #[test]
        fn output_never_exceeds_cap(lines in prop::collection::vec(dotenv_line(), 0..50)) {
            let input: Vec<u8> = lines.into_iter().flatten().collect();
            let mut out = Vec::new();
            let _ = DotEnvExtractor.extract(&input, &mut out, &mut Vec::new());
            prop_assert!(out.len() <= EXTRACT_OUTPUT_CAP);
        }

        /// Every non-empty line in the output must contain at least one `=`
        /// with a non-empty key before it.
        ///
        /// Uses single-line generators only: multiline quoted values produce
        /// output lines that are value continuations (no `=`), which is correct
        /// behavior but violates this per-line structural check.
        #[test]
        fn output_lines_are_well_formed(lines in prop::collection::vec(dotenv_line_single(), 1..30)) {
            let input: Vec<u8> = lines.into_iter().flatten().collect();
            let mut out = Vec::new();
            let _ = DotEnvExtractor.extract(&input, &mut out, &mut Vec::new());
            for line in out.split(|&b| b == b'\n') {
                if line.is_empty() { continue; }
                let eq_count = line.iter().filter(|&&b| b == b'=').count();
                prop_assert!(eq_count >= 1, "line missing '=': {:?}",
                    String::from_utf8_lossy(line));
                let eq_pos = line.iter().position(|&b| b == b'=').unwrap();
                prop_assert!(eq_pos > 0, "empty key in line: {:?}",
                    String::from_utf8_lossy(line));
            }
        }

        /// The output is a fixed point: re-extracting produces identical bytes.
        ///
        /// This is the defining property of normalization. If it breaks, the
        /// output format has a quoting/trimming asymmetry (e.g. quoted
        /// whitespace surviving the first pass but being trimmed on re-parse
        /// as an unquoted value).
        ///
        /// Uses single-line generators only: multiline quoted values embed
        /// literal `\n` in the output, which on re-parse splits into separate
        /// lines (the continuation part has no `=` and is discarded). This is
        /// inherent to the unquoted output format, not a normalization bug.
        #[test]
        fn extraction_is_idempotent(lines in prop::collection::vec(dotenv_line_single(), 1..20)) {
            let input: Vec<u8> = lines.into_iter().flatten().collect();
            let mut out1 = Vec::new();
            let _ = DotEnvExtractor.extract(&input, &mut out1, &mut Vec::new());
            if out1.is_empty() { return Ok(()); }
            let mut out2 = Vec::new();
            let _ = DotEnvExtractor.extract(&out1, &mut out2, &mut Vec::new());
            prop_assert_eq!(&out1, &out2, "extraction is not idempotent");
        }

        /// The extractor must never panic on arbitrary byte sequences.
        #[test]
        fn never_panics_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let mut out = Vec::new();
            let _ = DotEnvExtractor.extract(&data, &mut out, &mut Vec::new());
        }
    }
}
