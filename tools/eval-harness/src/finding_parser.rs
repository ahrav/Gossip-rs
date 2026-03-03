//! JSONL finding parser for scanner output.
//!
//! Reads JSONL produced by the scanner's [`JsonlEncoder`] and extracts
//! [`NormalizedFinding`] records for accuracy evaluation. Non-finding
//! event types (progress, summary, diagnostic, etc.) are silently skipped;
//! malformed lines are counted but do not halt parsing.
//!
//! The two entry points differ only in I/O:
//!
//! - [`parse_findings_jsonl`] — in-memory, infallible (errors become counters)
//! - [`parse_findings_file`] — reads from disk, returns `Result` for I/O errors
//!
//! After parsing, call [`dedup_findings_with_mode`] to apply the selected
//! dedup semantics before matching.
//!
//! # Wire format
//!
//! Each JSONL line is a JSON object with a `"type"` discriminator. This
//! module only extracts `"finding"` events; all other types are counted
//! and skipped. A typical finding line:
//!
//! ```json
//! {"type":"finding","source":"fs","path":"src/main.rs","start":42,"end":80,"rule_id":7,"rule":"aws-access-key","confidence_score":5}
//! ```
//!
//! (Actual wire lines may include additional fields such as `commit_id`
//! and `change_kind` — both intentionally discarded here because the
//! eval corpora are file-level, not commit-level.)
//!
//! [`JsonlEncoder`]: scanner_git::events::VecEventSink

use std::borrow::Cow;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::pipeline::DedupMode;
use crate::types::{FileReadError, NormalizedFinding, normalize_path};

// ── Wire format ──────────────────────────────────────────────────────────

/// Zero-copy borrowing view of one JSONL line for deserialization.
///
/// All fields except `event_type` are optional so that lines with
/// unrecognized or missing fields parse successfully instead of
/// producing a serde error. This makes the parser robust to new
/// event types and future wire-format additions.
///
/// Uses `Cow<'a, str>` fields: borrows when possible (no JSON escape
/// sequences), allocates only when serde must decode escapes like `\\`,
/// `\"`, or `\uXXXX`.
#[derive(Deserialize)]
struct WireLine<'a> {
    /// The `"type"` discriminator from the wire format. Renamed because
    /// `type` is a Rust keyword.
    #[serde(rename = "type")]
    event_type: Cow<'a, str>,
    /// Optional on the wire so non-finding event shapes remain parseable.
    /// Required only when `event_type == "finding"`.
    path: Option<Cow<'a, str>>,
    start: Option<u64>,
    end: Option<u64>,
    rule: Option<Cow<'a, str>>,
    /// Optional confidence score. Missing values default to 0 during parse.
    confidence_score: Option<i8>,
}

// ── Public types ─────────────────────────────────────────────────────────

/// Outcome of parsing a JSONL stream.
///
/// Separates successfully extracted findings from diagnostic counters so
/// callers can both consume results and report parse quality (e.g., warn
/// when `malformed_lines` is unexpectedly high, indicating a corrupt or
/// truncated file).
///
/// # Counting invariant
///
/// Every input line is classified into exactly one bucket:
///
/// ```text
/// total_lines == findings.len() + non_finding_lines + malformed_lines + skipped_findings
/// ```
///
/// This invariant is enforced by a property test (`line_count_invariant_always_holds`)
/// over arbitrary inputs.
///
/// **Note:** This invariant holds immediately after parsing. Calling
/// [`dedup_findings`] on `findings` reduces its length without adjusting
/// the counters — the counters describe parse-time classification, not
/// post-dedup state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonlParseResult {
    /// Successfully parsed and validated findings.
    pub findings: Vec<NormalizedFinding>,
    /// Total lines processed (including empty, non-finding, malformed, and
    /// skipped).
    pub total_lines: u64,
    /// Lines that parsed as valid JSON but were not finding events (e.g.,
    /// progress, summary, diagnostic), plus empty lines (after `\r`
    /// trimming).
    pub non_finding_lines: u64,
    /// Lines that failed JSON deserialization entirely.
    pub malformed_lines: u64,
    /// Lines that deserialized as findings but were rejected during
    /// validation (inverted span, empty normalized path, missing required
    /// fields on a finding-typed line).
    pub skipped_findings: u64,
    /// First serde error message encountered, if any. Aids debugging when
    /// `malformed_lines` is unexpectedly high.
    pub first_malformed_error: Option<String>,
    /// Reason the first finding was skipped, if any. Aids debugging when
    /// `skipped_findings` is unexpectedly high.
    pub first_skip_reason: Option<String>,
}

// ── Public API ───────────────────────────────────────────────────────────

/// Parse JSONL text in memory.
///
/// Every line is processed independently — malformed lines increment
/// counters but never halt parsing. The returned [`JsonlParseResult::findings`]
/// may contain duplicates; call [`dedup_findings`] afterward if needed.
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from finding paths. Must be pre-canonicalized
/// (forward slashes, no `.`/`..` components); use `""` for no stripping.
pub fn parse_findings_jsonl(jsonl: &str, canonical_root: &str) -> JsonlParseResult {
    parse_findings_jsonl_inner(jsonl, canonical_root, 0)
}

/// Core JSONL parsing loop with an optional capacity hint for the findings Vec.
///
/// `capacity_hint` of 0 falls back to the default (no pre-allocation).
/// [`parse_findings_file`] estimates capacity from the file size to avoid
/// repeated Vec reallocations for large files.
fn parse_findings_jsonl_inner(
    jsonl: &str,
    canonical_root: &str,
    capacity_hint: usize,
) -> JsonlParseResult {
    let findings = if capacity_hint > 0 {
        Vec::with_capacity(capacity_hint)
    } else {
        Vec::new()
    };

    let mut result = JsonlParseResult {
        findings,
        total_lines: 0,
        non_finding_lines: 0,
        malformed_lines: 0,
        skipped_findings: 0,
        first_malformed_error: None,
        first_skip_reason: None,
    };

    // split('\n') rather than lines(): str::lines() strips trailing
    // newlines and yields zero items for "", which would make total_lines
    // undershoot and violate the counting invariant. split('\n') always
    // yields at least one element, so even "" counts as one (empty) line.
    for line in jsonl.split('\n') {
        parse_line(line, canonical_root, &mut result);
    }

    result
}

/// Parse JSONL from a file on disk.
///
/// Reads the entire file into memory, then delegates to the same core
/// parsing loop used by [`parse_findings_jsonl`], with a capacity hint
/// estimated from the file size. Only I/O failures produce errors; parse
/// failures are captured as counters in the returned [`JsonlParseResult`].
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from finding paths. Must be pre-canonicalized
/// (forward slashes, no `.`/`..` components); use `""` for no stripping.
pub fn parse_findings_file(
    path: &Path,
    canonical_root: &str,
) -> Result<JsonlParseResult, FileReadError> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| FileReadError::new(path.to_path_buf(), e))?;
    // JSONL finding lines average ~140 bytes; pre-allocate to avoid repeated
    // Vec reallocations for large files. Mirrors the CSV parser's approach.
    let capacity_hint = contents.len() / 140;
    Ok(parse_findings_jsonl_inner(
        &contents,
        canonical_root,
        capacity_hint,
    ))
}

/// Sort and deduplicate findings in place, retaining the highest
/// confidence per identity.
///
/// Identity is `(path, byte_start, byte_end, rule)` — confidence is
/// excluded from comparison (see [`NormalizedFinding`]'s `Eq` impl).
/// After dedup, findings are sorted by identity and each surviving
/// element carries the maximum confidence seen across all duplicates.
/// Idempotent: calling twice produces the same result as calling once.
pub fn dedup_findings(findings: &mut Vec<NormalizedFinding>) {
    findings.sort();
    findings.dedup_by(|a, b| {
        // dedup_by: `a` = candidate for removal, `b` = retained element.
        if a == b {
            b.confidence = b.confidence.max(a.confidence);
            true
        } else {
            false
        }
    });
}

/// Apply deduplication according to the selected pipeline mode.
///
/// - [`DedupMode::ByRule`]: keep one finding per
///   `(path, byte_start, byte_end, rule)` with max confidence.
/// - [`DedupMode::AcrossRules`]: keep one finding per
///   `(path, byte_start, byte_end)` across all rules.
pub fn dedup_findings_with_mode(findings: &mut Vec<NormalizedFinding>, mode: DedupMode) {
    match mode {
        DedupMode::ByRule => dedup_findings(findings),
        DedupMode::AcrossRules => cross_rule_dedup_findings(findings),
    }
}

/// Sort and deduplicate findings in place across rules, retaining the highest
/// confidence per `(path, byte_start, byte_end)` span.
///
/// This pass is self-contained: callers do not need to run [`dedup_findings`]
/// first. Identity duplicates and cross-rule collisions are both resolved by
/// the same ordering + dedup scan.
///
/// Tie-breaking is deterministic:
/// - higher confidence wins
/// - equal confidence resolves to lexicographically smaller rule name
///
/// This function mutates ordering: output is sorted by
/// `(path, byte_start, byte_end)` with deterministic tie-breaks.
/// Running it discards per-rule alternatives at identical spans, which is
/// useful for rule-agnostic location scoring but loses "which rule fired"
/// detail for those collapsed spans.
///
/// Idempotent and `O(n log n)` due to sorting.
pub fn cross_rule_dedup_findings(findings: &mut Vec<NormalizedFinding>) {
    findings.sort_unstable_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.byte_start.cmp(&b.byte_start))
            .then(a.byte_end.cmp(&b.byte_end))
            // Descending confidence: winner leads each span group.
            .then(b.confidence.cmp(&a.confidence))
            // Ascending rule name for deterministic tie-breaks.
            .then(a.rule.cmp(&b.rule))
    });
    findings.dedup_by(|a, b| {
        a.path == b.path && a.byte_start == b.byte_start && a.byte_end == b.byte_end
    });
}

// ── Internal ─────────────────────────────────────────────────────────────

/// Record a skipped finding with a reason, updating counters.
///
/// `first_skip_reason` is sticky: once set, later reasons are ignored so
/// diagnostics stay compact while preserving a representative failure cause.
fn record_skip(result: &mut JsonlParseResult, reason: &str) {
    if result.first_skip_reason.is_none() {
        result.first_skip_reason = Some(reason.to_owned());
    }
    result.skipped_findings += 1;
}

/// Process a single JSONL line into `result`.
///
/// Categorizes the line into exactly one of four buckets, maintaining
/// the [`JsonlParseResult`] counting invariant:
///
/// | Condition | Bucket | Action |
/// |---|---|---|
/// | Valid finding with all identity fields | `findings` | Push `NormalizedFinding` |
/// | Non-finding event type, or empty line (after `\r` trimming) | `non_finding_lines` | Count only |
/// | Unparseable JSON | `malformed_lines` | Count only |
/// | Finding-typed but invalid (missing fields, empty rule, inverted span, empty path) | `skipped_findings` | [`record_skip`] |
///
/// A missing `"type"` discriminator cannot deserialize into [`WireLine`] and
/// therefore falls into `malformed_lines` (not `skipped_findings`).
///
/// Handles Windows-style CRLF line endings by stripping trailing `\r`
/// before attempting JSON parse, so the caller can split on `\n` alone.
fn parse_line(line: &str, canonical_root: &str, result: &mut JsonlParseResult) {
    result.total_lines += 1;

    // Trim trailing \r for Windows-style line endings.
    let line = line.trim_end_matches('\r');

    if line.is_empty() {
        result.non_finding_lines += 1;
        return;
    }

    let wire: WireLine<'_> = match serde_json::from_str(line) {
        Ok(w) => w,
        Err(e) => {
            if result.first_malformed_error.is_none() {
                result.first_malformed_error = Some(e.to_string());
            }
            result.malformed_lines += 1;
            return;
        }
    };

    if wire.event_type != "finding" {
        result.non_finding_lines += 1;
        return;
    }

    // All four identity fields must be present for a finding.
    let (Some(path), Some(start), Some(end), Some(rule)) =
        (wire.path, wire.start, wire.end, wire.rule)
    else {
        record_skip(result, "missing required field(s)");
        return;
    };

    if rule.is_empty() {
        record_skip(result, "empty rule");
        return;
    }

    // Reject inverted spans here for an actionable error message
    // (with skip counting) rather than letting NormalizedFinding::new's
    // assert! panic with a generic message.
    if end < start {
        record_skip(result, "inverted span");
        return;
    }

    // normalize_path can return "" for degenerate inputs (e.g., "..", ".")
    // where all path components are consumed by lexical resolution.
    let normalized = normalize_path(&path, canonical_root);
    if normalized.is_empty() {
        record_skip(result, "empty normalized path");
        return;
    }

    // Missing confidence defaults to 0 (neutral). This is a safe default
    // for PRC-AUC — a finding with confidence 0 will only survive at the
    // lowest threshold.
    let confidence = wire.confidence_score.unwrap_or(0);

    result.findings.push(NormalizedFinding::new(
        normalized,
        start,
        end,
        rule.into_owned(),
        confidence,
    ));
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit tests ──────────────────────────────────────────────

    #[test]
    fn parse_mixed_events() {
        let jsonl = [
            r#"{"type":"finding","path":"src/a.rs","start":0,"end":10,"rule":"key","confidence_score":5}"#,
            r#"{"type":"progress","stage":"scan","objects":100}"#,
            r#"{"type":"finding","path":"src/b.rs","start":20,"end":30,"rule":"token","confidence_score":3}"#,
        ]
        .join("\n");

        let result = parse_findings_jsonl(&jsonl, "");

        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.non_finding_lines, 1);
        assert_eq!(result.malformed_lines, 0);
        assert_eq!(result.skipped_findings, 0);
        assert_eq!(result.total_lines, 3);
    }

    #[test]
    fn malformed_json_counted() {
        let jsonl = "not json at all\n\
                     {\"type\":\"finding\",\"path\":\"a\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}";

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.malformed_lines, 1);
    }

    #[test]
    fn dedup_retains_max_confidence() {
        let jsonl = [
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":3}"#,
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":7}"#,
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":1}"#,
        ]
        .join("\n");

        let mut result = parse_findings_jsonl(&jsonl, "");
        assert_eq!(result.findings.len(), 3);

        dedup_findings(&mut result.findings);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].confidence, 7);
    }

    #[test]
    fn empty_input() {
        let result = parse_findings_jsonl("", "");

        assert!(result.findings.is_empty());
        assert_eq!(result.total_lines, 1);
        assert_eq!(result.non_finding_lines, 1);
    }

    #[rstest::rstest]
    #[case::inverted_span(
        r#"{"type":"finding","path":"a.rs","start":50,"end":10,"rule":"r","confidence_score":0}"#
    )]
    #[case::missing_rule_field(r#"{"type":"finding","path":"a.rs","start":0,"end":10}"#)]
    #[case::empty_rule_string(
        r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"","confidence_score":0}"#
    )]
    #[case::empty_path(
        r#"{"type":"finding","path":"","start":0,"end":10,"rule":"r","confidence_score":0}"#
    )]
    #[case::degenerate_path_dot(
        r#"{"type":"finding","path":".","start":0,"end":10,"rule":"r","confidence_score":0}"#
    )]
    #[case::degenerate_path_dotdot(
        r#"{"type":"finding","path":"..","start":0,"end":10,"rule":"r","confidence_score":0}"#
    )]
    fn invalid_finding_skipped(#[case] jsonl: &str) {
        let result = parse_findings_jsonl(jsonl, "");
        assert!(result.findings.is_empty(), "should skip: {jsonl}");
        assert_eq!(
            result.skipped_findings, 1,
            "should count as skipped: {jsonl}"
        );
    }

    #[test]
    fn path_normalization_with_root() {
        let jsonl = r#"{"type":"finding","path":"corpus/data/src/a.rs","start":0,"end":10,"rule":"r","confidence_score":0}"#;

        let result = parse_findings_jsonl(jsonl, "corpus/data");

        assert_eq!(result.findings[0].path, "src/a.rs");
    }

    #[test]
    fn blank_lines_counted_as_non_finding() {
        let jsonl = "\n\n{\"type\":\"finding\",\"path\":\"a\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}\n\n";

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.non_finding_lines, 4);
    }

    #[test]
    fn unknown_event_type_is_non_finding() {
        let jsonl = r#"{"type":"new_future_event","data":"stuff"}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert!(result.findings.is_empty());
        assert_eq!(result.non_finding_lines, 1);
        assert_eq!(result.malformed_lines, 0);
    }

    #[test]
    fn zero_length_finding_is_valid() {
        let jsonl =
            r#"{"type":"finding","path":"a.rs","start":5,"end":5,"rule":"r","confidence_score":0}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].byte_start, 5);
        assert_eq!(result.findings[0].byte_end, 5);
    }

    #[test]
    fn line_count_invariant() {
        let jsonl = [
            r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":0}"#,
            "bad json",
            r#"{"type":"progress"}"#,
            // Inverted span.
            r#"{"type":"finding","path":"a.rs","start":50,"end":10,"rule":"r","confidence_score":0}"#,
            "",
        ]
        .join("\n");

        let result = parse_findings_jsonl(&jsonl, "");

        assert_eq!(
            result.total_lines,
            result.findings.len() as u64
                + result.non_finding_lines
                + result.malformed_lines
                + result.skipped_findings,
        );
    }

    #[test]
    fn extra_fields_ignored() {
        let jsonl = r#"{"type":"finding","path":"a.rs","start":0,"end":10,"rule":"r","confidence_score":0,"source":"git","commit_id":7,"change_kind":"add","rule_id":42}"#;

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].path, "a.rs");
    }

    #[test]
    fn windows_line_endings() {
        let jsonl = "{\"type\":\"finding\",\"path\":\"a.rs\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}\r\n\
                     {\"type\":\"finding\",\"path\":\"b.rs\",\"start\":0,\"end\":1,\"rule\":\"r\",\"confidence_score\":0}\r\n";

        let result = parse_findings_jsonl(jsonl, "");

        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn escaped_path_parsed_correctly() {
        let jsonl = r#"{"type":"finding","path":"src\/a.rs","start":0,"end":10,"rule":"r","confidence_score":0}"#;
        let result = parse_findings_jsonl(jsonl, "");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].path, "src/a.rs");
    }

    #[test]
    fn file_not_found_error() {
        let err = parse_findings_file(Path::new("/nonexistent/path.jsonl"), "").unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/path.jsonl"),
            "error should contain path: {msg}"
        );
    }

    #[test]
    fn dedup_distinct_findings_untouched() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 0, 10, "r1".into(), 5),
            NormalizedFinding::new("a.rs".into(), 20, 30, "r1".into(), 3),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r1".into(), 7),
        ];

        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn dedup_empty_vec() {
        let mut findings: Vec<NormalizedFinding> = Vec::new();
        dedup_findings(&mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn first_malformed_error_captured() {
        let jsonl =
            "not json\n{\"type\":\"finding\",\"path\":\"a\",\"start\":0,\"end\":1,\"rule\":\"r\"}";
        let result = parse_findings_jsonl(jsonl, "");
        assert_eq!(result.malformed_lines, 1);
        assert!(result.first_malformed_error.is_some());
    }

    #[test]
    fn first_skip_reason_captured() {
        let jsonl = r#"{"type":"finding","path":"a.rs","start":50,"end":10,"rule":"r"}"#;
        let result = parse_findings_jsonl(jsonl, "");
        assert_eq!(result.skipped_findings, 1);
        assert!(
            result
                .first_skip_reason
                .as_deref()
                .unwrap()
                .contains("inverted"),
        );
    }

    // NOTE: encoder_parser_roundtrip test removed during gossip-rs port.
    // The original test depended on `scanner_rs::unified::harness_api::encode_finding`
    // which has not been ported to gossip-rs. Re-add once `encode_finding` is
    // available in scanner-git or scanner-engine.
    //
    // The test verified that encoding a FindingEvent via encode_finding and
    // re-parsing the JSONL output through parse_findings_jsonl produces the
    // same finding fields (path, byte_start, byte_end, rule, confidence).

    #[test]
    fn dedup_mixed_distinct_and_duplicate() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 0, 10, "r1".into(), 3),
            NormalizedFinding::new("a.rs".into(), 0, 10, "r1".into(), 7),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r1".into(), 5),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r1".into(), 2),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].confidence, 7);
        assert_eq!(findings[1].confidence, 5);
    }

    #[test]
    fn cross_rule_dedup_keeps_highest_confidence() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 10, 20, "aws".into(), 12),
            NormalizedFinding::new("a.rs".into(), 10, 20, "entropy".into(), 30),
            NormalizedFinding::new("a.rs".into(), 10, 20, "generic".into(), 18),
        ];
        cross_rule_dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "entropy");
        assert_eq!(findings[0].confidence, 30);
    }

    #[test]
    fn cross_rule_dedup_tie_breaks_by_rule_name() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 10, 20, "zz-rule".into(), 42),
            NormalizedFinding::new("a.rs".into(), 10, 20, "aa-rule".into(), 42),
            NormalizedFinding::new("a.rs".into(), 10, 20, "mm-rule".into(), 42),
        ];
        cross_rule_dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "aa-rule");
        assert_eq!(findings[0].confidence, 42);
    }

    #[test]
    fn cross_rule_dedup_mixed_paths_independent() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 0, 10, "r1".into(), 10),
            NormalizedFinding::new("a.rs".into(), 0, 10, "r2".into(), 20),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r1".into(), 5),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r2".into(), 7),
        ];
        cross_rule_dedup_findings(&mut findings);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].path, "a.rs");
        assert_eq!(findings[0].rule, "r2");
        assert_eq!(findings[1].path, "b.rs");
        assert_eq!(findings[1].rule, "r2");
    }

    #[test]
    fn cross_rule_dedup_preserves_overlapping_non_identical_spans() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 0, 10, "r1".into(), 20),
            NormalizedFinding::new("a.rs".into(), 5, 15, "r2".into(), 30),
        ];
        cross_rule_dedup_findings(&mut findings);
        assert_eq!(
            findings.len(),
            2,
            "overlapping spans with different boundaries must both survive"
        );
    }

    #[test]
    fn cross_rule_dedup_empty_vec() {
        let mut findings: Vec<NormalizedFinding> = Vec::new();
        cross_rule_dedup_findings(&mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn cross_rule_dedup_single_finding_unchanged() {
        let mut findings = vec![NormalizedFinding::new(
            "a.rs".into(),
            0,
            10,
            "rule".into(),
            5,
        )];
        cross_rule_dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "rule");
        assert_eq!(findings[0].confidence, 5);
    }

    #[test]
    fn cross_rule_dedup_all_distinct_spans_is_noop() {
        let mut findings = vec![
            NormalizedFinding::new("a.rs".into(), 0, 10, "r1".into(), 5),
            NormalizedFinding::new("a.rs".into(), 20, 30, "r2".into(), 3),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r3".into(), 7),
        ];
        cross_rule_dedup_findings(&mut findings);
        assert_eq!(
            findings.len(),
            3,
            "all-distinct spans must survive cross-rule dedup"
        );
    }

    #[test]
    fn cross_rule_dedup_output_is_sorted() {
        let mut findings = vec![
            NormalizedFinding::new("c.rs".into(), 50, 60, "r1".into(), 1),
            NormalizedFinding::new("a.rs".into(), 0, 10, "r2".into(), 2),
            NormalizedFinding::new("a.rs".into(), 20, 30, "r3".into(), 3),
            NormalizedFinding::new("b.rs".into(), 0, 10, "r1".into(), 4),
        ];
        cross_rule_dedup_findings(&mut findings);
        assert!(
            findings.windows(2).all(|w| {
                (w[0].path.as_str(), w[0].byte_start, w[0].byte_end)
                    <= (w[1].path.as_str(), w[1].byte_start, w[1].byte_end)
            }),
            "output must be sorted by (path, byte_start, byte_end)"
        );
    }

    // ── Property tests ──────────────────────────────────────────

    mod prop {
        use super::*;
        use std::collections::{BTreeMap, BTreeSet};

        use proptest::prelude::*;

        /// Generate findings with guaranteed cross-rule collisions by creating
        /// 2-3 span templates and emitting three rule variants per span.
        fn cross_rule_scenario() -> impl Strategy<Value = Vec<NormalizedFinding>> {
            proptest::collection::vec(
                (
                    prop_oneof![
                        Just("a.txt".to_string()),
                        Just("b.txt".to_string()),
                        Just("c.txt".to_string())
                    ],
                    0u64..50,
                    1u64..50,
                    -128i8..=127i8,
                    -128i8..=127i8,
                    -128i8..=127i8,
                ),
                2..=3,
            )
            .prop_map(|templates| {
                let mut findings = Vec::with_capacity(templates.len() * 3);
                for (path, start, span_len, c1, c2, c3) in templates {
                    let end = start + span_len;
                    findings.push(NormalizedFinding::new(
                        path.clone(),
                        start,
                        end,
                        "r1".into(),
                        c1,
                    ));
                    findings.push(NormalizedFinding::new(
                        path.clone(),
                        start,
                        end,
                        "r2".into(),
                        c2,
                    ));
                    findings.push(NormalizedFinding::new(path, start, end, "r3".into(), c3));
                }
                dedup_findings(&mut findings);
                findings
            })
        }

        fn expected_cross_rule_winners(
            input: &[NormalizedFinding],
        ) -> BTreeMap<(String, u64, u64), (i8, String)> {
            let mut expected = BTreeMap::<(String, u64, u64), (i8, String)>::new();
            for finding in input {
                let key = (finding.path.clone(), finding.byte_start, finding.byte_end);
                expected
                    .entry(key)
                    .and_modify(|(best_conf, best_rule)| {
                        if finding.confidence > *best_conf
                            || (finding.confidence == *best_conf
                                && finding.rule.as_str() < best_rule.as_str())
                        {
                            *best_conf = finding.confidence;
                            *best_rule = finding.rule.clone();
                        }
                    })
                    .or_insert_with(|| (finding.confidence, finding.rule.clone()));
            }
            expected
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Arbitrary input never panics.
            #[test]
            fn parse_never_panics(input in "\\PC*") {
                let _ = parse_findings_jsonl(&input, "");
            }

            /// The line-count invariant holds for all inputs.
            #[test]
            fn line_count_invariant_always_holds(input in "\\PC*") {
                let r = parse_findings_jsonl(&input, "");
                prop_assert_eq!(
                    r.total_lines,
                    r.findings.len() as u64
                        + r.non_finding_lines
                        + r.malformed_lines
                        + r.skipped_findings,
                );
            }

            /// Dedup is idempotent — running it twice yields the same result.
            #[test]
            fn dedup_idempotent(
                paths in proptest::collection::vec("[a-z]{1,5}", 1..10),
                starts in proptest::collection::vec(0u64..100, 1..10),
                ends in proptest::collection::vec(0u64..200, 1..10),
                rules in proptest::collection::vec("[a-z]{1,3}", 1..10),
                confs in proptest::collection::vec(-128i8..=127i8, 1..10),
            ) {
                let len = paths.len().min(starts.len()).min(ends.len()).min(rules.len()).min(confs.len());
                let mut findings: Vec<NormalizedFinding> = (0..len)
                    .map(|i| NormalizedFinding {
                        path: paths[i].clone(),
                        byte_start: starts[i],
                        byte_end: ends[i],
                        rule: rules[i].clone(),
                        confidence: confs[i],
                    })
                    .collect();

                dedup_findings(&mut findings);
                let snapshot = findings.clone();
                dedup_findings(&mut findings);
                prop_assert_eq!(findings, snapshot);
            }

            /// Dedup never increases the number of findings.
            #[test]
            fn dedup_never_grows(
                paths in proptest::collection::vec("[a-z]{1,3}", 1..20),
                confs in proptest::collection::vec(-128i8..=127i8, 1..20),
            ) {
                let len = paths.len().min(confs.len());
                let mut findings: Vec<NormalizedFinding> = (0..len)
                    .map(|i| NormalizedFinding {
                        path: paths[i].clone(),
                        byte_start: 0,
                        byte_end: 10,
                        rule: "r".into(),
                        confidence: confs[i],
                    })
                    .collect();
                let original_len = findings.len();

                dedup_findings(&mut findings);
                prop_assert!(findings.len() <= original_len);
            }

            /// Cross-rule dedup is idempotent and preserves max confidence per span.
            #[test]
            fn cross_rule_dedup_idempotent_and_preserves_max_confidence(
                input in cross_rule_scenario(),
            ) {
                let expected = expected_cross_rule_winners(&input);

                let mut findings = input.clone();
                cross_rule_dedup_findings(&mut findings);
                prop_assert_eq!(findings.len(), expected.len());

                let mut seen = BTreeSet::new();
                for finding in &findings {
                    let key = (finding.path.clone(), finding.byte_start, finding.byte_end);
                    prop_assert!(seen.insert(key.clone()));
                    let (best_conf, _) = expected.get(&key).unwrap();
                    prop_assert_eq!(finding.confidence, *best_conf);
                }

                let snapshot = findings.clone();
                cross_rule_dedup_findings(&mut findings);
                prop_assert_eq!(findings, snapshot);
            }

            /// Equal-confidence cross-rule ties resolve to lexicographically smallest rule.
            #[test]
            fn cross_rule_dedup_tie_breaks_deterministically(
                input in cross_rule_scenario(),
            ) {
                let expected = expected_cross_rule_winners(&input);

                let mut findings = input;
                cross_rule_dedup_findings(&mut findings);
                prop_assert_eq!(findings.len(), expected.len());

                for finding in &findings {
                    let key = (finding.path.clone(), finding.byte_start, finding.byte_end);
                    let (best_conf, best_rule) = expected.get(&key).unwrap();
                    prop_assert_eq!(finding.confidence, *best_conf);
                    prop_assert_eq!(finding.rule.as_str(), best_rule.as_str());
                }
            }

            /// Valid JSONL finding lines always parse into a finding with matching fields.
            #[test]
            fn valid_finding_roundtrips(
                path in "[a-z]{1,5}(/[a-z]{1,5}){0,3}\\.[a-z]{1,3}",
                start in 0u64..1000,
                span in 0u64..500,
                rule in "[a-z][a-z0-9_-]{0,9}",
                confidence in -128i8..=127i8,
            ) {
                let end = start + span;
                let line = format!(
                    r#"{{"type":"finding","path":"{path}","start":{start},"end":{end},"rule":"{rule}","confidence_score":{confidence}}}"#,
                );

                let result = parse_findings_jsonl(&line, "");

                prop_assert_eq!(result.findings.len(), 1, "should parse exactly one finding");
                prop_assert_eq!(result.malformed_lines, 0);
                prop_assert_eq!(result.skipped_findings, 0);

                let f = &result.findings[0];
                prop_assert_eq!(&f.path, &path);
                prop_assert_eq!(f.byte_start, start);
                prop_assert_eq!(f.byte_end, end);
                prop_assert_eq!(&f.rule, &rule);
                prop_assert_eq!(f.confidence, confidence);
            }

            /// Finding lines without confidence_score default to 0.
            #[test]
            fn missing_confidence_defaults_zero(
                path in "[a-z]{1,5}\\.[a-z]{1,3}",
                start in 0u64..1000,
                span in 0u64..500,
                rule in "[a-z][a-z0-9_-]{0,9}",
            ) {
                let end = start + span;
                let line = format!(
                    r#"{{"type":"finding","path":"{path}","start":{start},"end":{end},"rule":"{rule}"}}"#,
                );

                let result = parse_findings_jsonl(&line, "");

                prop_assert_eq!(result.findings.len(), 1);
                prop_assert_eq!(result.findings[0].confidence, 0);
            }
        }
    }
}
