//! LeakyRepo CSV parser and count-based comparison adapter.
//!
//! LeakyRepo is a benchmark that uses **count-based** ground truth: each CSV
//! row specifies how many secrets a file should contain (`num_risk` +
//! `num_informative`), not where they are. This is coarser than position-based
//! benchmarks (CredData) but sufficient for regression testing.
//!
//! The CSV lives at `.leaky-meta/secrets.csv` inside the corpus and looks like:
//!
//! ```text
//! # name,num_risk,num_informative
//! .bash_profile,6,5
//! .bashrc,3,3
//! .docker/.dockercfg,2,2
//! ```
//!
//! Count-based TP/FP/FN uses the standard bag-comparison formula:
//!
//! - `tp  = min(expected, actual)`
//! - `fp  = actual.saturating_sub(expected)`
//! - `fn  = expected.saturating_sub(actual)`
//!
//! Count-based precision and recall are provable upper bounds on their
//! position-based counterparts: the formula assumes maximum overlap
//! between expected and actual findings, so TP is maximized (and FP/FN
//! minimized) relative to any position-based matching.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::finding_parser::dedup_findings;
use crate::types::{NormalizedFinding, normalize_path};

// ── Types ─────────────────────────────────────────────────────────────────

/// Per-file expected secret count from a single LeakyRepo CSV data row.
///
/// Each row in the ground-truth CSV maps to one `FileExpectation`. The parser
/// ([`parse_leaky_repo`]) guarantees uniqueness by path, so downstream code
/// can safely index by `path` without worrying about collisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileExpectation {
    /// Forward-slash normalized path relative to the corpus root, produced
    /// by [`normalize_path`](crate::types::normalize_path) with an empty root.
    pub path: String,
    /// Total expected secrets (`num_risk + num_informative` from the CSV).
    pub expected_count: u32,
}

/// Per-file comparison of expected vs actual secret counts.
///
/// Produced by [`compare_counts`] for each file that appears in either the
/// ground truth or the scanner output (or both). The three classification
/// fields (`tp`, `fp`, `false_neg`) satisfy two algebraic invariants that
/// hold for every instance:
///
/// - **`tp + fp == actual`** — every deduplicated scanner finding is either
///   a true positive or a false positive.
/// - **`tp + false_neg == expected`** — every expected secret is either
///   detected (TP) or missed (FN).
///
/// These invariants follow directly from the `min`/`saturating_sub` formulas
/// and are verified by property tests in this module.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FileCountComparison {
    /// Forward-slash normalized path.
    pub path: String,
    /// Expected secret count from ground truth.
    pub expected: u32,
    /// Actual unique findings from the scanner (after deduplication).
    pub actual: u32,
    /// True positives: `min(expected, actual)`.
    pub tp: u32,
    /// False positives: `actual.saturating_sub(expected)`.
    pub fp: u32,
    /// False negatives: `expected.saturating_sub(actual)`.
    pub false_neg: u32,
}

// ── Error ─────────────────────────────────────────────────────────────────

/// Errors from parsing a LeakyRepo CSV.
///
/// Parsing is fail-fast: the first malformed row or duplicate path aborts
/// the entire parse. This is intentional — partial ground truth would
/// silently corrupt TP/FP/FN counts, so it is better to reject early.
#[derive(Debug)]
pub enum LeakyRepoError {
    /// Underlying I/O failure.
    ///
    /// `path` is `Some` when the error originates from a known file
    /// (e.g., [`parse_leaky_repo_csv`]) and `None` when the source is a
    /// generic [`BufRead`] reader.
    Io {
        path: Option<PathBuf>,
        source: std::io::Error,
    },
    /// A data row could not be parsed (missing fields, non-numeric counts).
    InvalidRow {
        /// 1-indexed line number.
        line: usize,
        reason: String,
    },
    /// The same normalized path appeared more than once. Duplicates are
    /// rejected because the count-based comparison is keyed by path — two
    /// rows for the same file would produce an ambiguous expected count.
    DuplicatePath {
        /// 1-indexed line number of the second occurrence.
        line: usize,
        path: String,
    },
}

impl fmt::Display for LeakyRepoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                path: Some(p),
                source,
            } => write!(f, "failed to read {}: {source}", p.display()),
            Self::Io { path: None, source } => write!(f, "I/O error: {source}"),
            Self::InvalidRow { line, reason } => {
                write!(f, "line {line}: {reason}")
            }
            Self::DuplicatePath { line, path } => {
                write!(f, "line {line}: duplicate path {path:?}")
            }
        }
    }
}

impl std::error::Error for LeakyRepoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LeakyRepoError {
    fn from(e: std::io::Error) -> Self {
        Self::Io {
            path: None,
            source: e,
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────

/// Parse a LeakyRepo ground-truth CSV from any [`BufRead`] source.
///
/// Lines starting with `#` are comments. Empty/whitespace-only lines are
/// skipped. Each data row is split from the right via `rsplitn(3, ',')` so
/// that commas embedded in file paths are preserved — the last two fields
/// are always numeric, so splitting from the right unambiguously separates
/// path from counts without CSV quoting.
///
/// Paths are normalized through [`normalize_path`](crate::types::normalize_path)
/// with an empty root (no prefix stripping), since the CSV paths are already
/// relative to the corpus root. A UTF-8 BOM on the first line is stripped
/// to handle files saved by Windows editors.
///
/// # Errors
///
/// - [`LeakyRepoError::Io`] — on any I/O failure from the reader.
/// - [`LeakyRepoError::InvalidRow`] — if a data row has fewer than 3 fields
///   or contains non-numeric count values.
/// - [`LeakyRepoError::DuplicatePath`] — if two data rows resolve to the
///   same normalized path.
pub fn parse_leaky_repo(reader: impl BufRead) -> Result<Vec<FileExpectation>, LeakyRepoError> {
    let mut expectations = Vec::with_capacity(256);
    let mut seen = HashSet::with_capacity(256);

    for (idx, raw_line) in reader.lines().enumerate() {
        let line_num = idx + 1; // 1-indexed for error messages
        let raw = raw_line?;

        // Strip UTF-8 BOM on the very first line (common in Windows-edited CSVs).
        let line = if line_num == 1 {
            raw.strip_prefix('\u{feff}').unwrap_or(&raw)
        } else {
            &raw
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Split from the right: the last two fields are always numeric, so
        // rsplitn(3, ',') yields [num_informative, num_risk, path].
        // This handles commas inside path names without requiring quoting.
        let mut parts = trimmed.rsplitn(3, ',');

        let num_informative_str = parts.next().ok_or_else(|| LeakyRepoError::InvalidRow {
            line: line_num,
            reason: "missing num_informative field".into(),
        })?;
        let num_risk_str = parts.next().ok_or_else(|| LeakyRepoError::InvalidRow {
            line: line_num,
            reason: "missing num_risk field".into(),
        })?;
        let path_raw = parts.next().ok_or_else(|| LeakyRepoError::InvalidRow {
            line: line_num,
            reason: "missing path field (need at least 3 comma-separated fields)".into(),
        })?;

        let num_risk: u32 = num_risk_str
            .trim()
            .parse()
            .map_err(|e: std::num::ParseIntError| LeakyRepoError::InvalidRow {
                line: line_num,
                reason: format!("invalid num_risk: {e}"),
            })?;

        let num_informative: u32 =
            num_informative_str
                .trim()
                .parse()
                .map_err(|e: std::num::ParseIntError| LeakyRepoError::InvalidRow {
                    line: line_num,
                    reason: format!("invalid num_informative: {e}"),
                })?;

        let path = normalize_path(path_raw.trim(), "");

        if !seen.insert(path.clone()) {
            return Err(LeakyRepoError::DuplicatePath {
                line: line_num,
                path,
            });
        }

        let expected_count =
            num_risk
                .checked_add(num_informative)
                .ok_or_else(|| LeakyRepoError::InvalidRow {
                    line: line_num,
                    reason: format!(
                        "num_risk ({num_risk}) + num_informative ({num_informative}) overflows u32"
                    ),
                })?;

        expectations.push(FileExpectation {
            path,
            expected_count,
        });
    }

    Ok(expectations)
}

/// Convenience wrapper: open a file at `path` and parse it as a LeakyRepo CSV.
///
/// Equivalent to opening the file as a [`BufReader`] and calling
/// [`parse_leaky_repo`]. I/O errors from [`File::open`] are wrapped in
/// [`LeakyRepoError::Io`].
pub fn parse_leaky_repo_csv(path: &Path) -> Result<Vec<FileExpectation>, LeakyRepoError> {
    let file = File::open(path).map_err(|source| LeakyRepoError::Io {
        path: Some(path.to_path_buf()),
        source,
    })?;
    parse_leaky_repo(BufReader::new(file))
}

// ── Comparison ────────────────────────────────────────────────────────────

/// Compare scanner findings against LeakyRepo file-level expectations.
///
/// Findings are deduplicated internally (sort + dedup retaining max
/// confidence) then grouped by path. Comparison proceeds in two passes:
///
/// 1. **Expected files** — for each entry in `expectations`, count how many
///    deduplicated findings share that path and apply the `min`/`saturating_sub`
///    formula. Files with no findings get `actual = 0` (all expected secrets
///    become FN).
///
/// 2. **Unlisted files** — scanner findings whose path does not appear in
///    `expectations` are emitted with `expected = 0`, marking every finding
///    as FP. This captures false alarms on files the ground truth does not
///    mention (implicitly clean).
///
/// Output is sorted by path for deterministic, diff-friendly ordering.
pub fn compare_counts(
    mut findings: Vec<NormalizedFinding>,
    expectations: &[FileExpectation],
) -> Vec<FileCountComparison> {
    dedup_findings(&mut findings);

    // Group deduplicated findings by path.
    let mut actual_counts: HashMap<&str, u32> = HashMap::with_capacity(findings.len().min(4096));
    for f in &findings {
        *actual_counts.entry(f.path.as_str()).or_default() += 1;
    }

    let mut results = Vec::with_capacity(expectations.len() + 64);

    // Expected files — consume matching entries from actual_counts.
    for exp in expectations {
        let actual = actual_counts.remove(exp.path.as_str()).unwrap_or(0);
        let expected = exp.expected_count;
        results.push(FileCountComparison {
            path: exp.path.clone(),
            expected,
            actual,
            tp: expected.min(actual),
            fp: actual.saturating_sub(expected),
            false_neg: expected.saturating_sub(actual),
        });
    }

    // Remaining entries: unlisted files (scanner found secrets not in ground truth).
    for (path, actual) in actual_counts {
        results.push(FileCountComparison {
            path: path.to_string(),
            expected: 0,
            actual,
            tp: 0,
            fp: actual,
            false_neg: 0,
        });
    }

    results.sort_by(|a, b| a.path.cmp(&b.path));
    results
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse an in-memory CSV string.
    fn parse(csv: &str) -> Result<Vec<FileExpectation>, LeakyRepoError> {
        parse_leaky_repo(csv.as_bytes())
    }

    /// Helper: build a NormalizedFinding with minimal boilerplate.
    fn finding(path: &str, start: u64, end: u64) -> NormalizedFinding {
        NormalizedFinding::new(path.into(), start, end, "test_rule".into(), 50)
    }

    // ── parse: happy path ─────────────────────────────────────

    #[test]
    fn parse_basic() {
        let csv = "# name,num_risk,num_informative\n\
                    .bash_profile,6,5\n\
                    .bashrc,3,3\n\
                    .docker/.dockercfg,2,2\n";
        let result = parse(csv).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].path, ".bash_profile");
        assert_eq!(result[0].expected_count, 11);
        assert_eq!(result[2].path, ".docker/.dockercfg");
        assert_eq!(result[2].expected_count, 4);
    }

    #[test]
    fn parse_empty() {
        let csv = "# name,num_risk,num_informative\n";
        let result = parse(csv).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_comment_variations() {
        let csv = "# header\n\
                    # another comment\n\
                    \n\
                    file.txt,1,2\n\
                    \n\
                    # trailing comment\n";
        let result = parse(csv).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, "file.txt");
    }

    #[test]
    fn parse_trailing_comment_no_newline() {
        // CSV ends with a comment line and no trailing newline.
        let csv = "file.txt,1,2\n# end";
        let result = parse(csv).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn parse_bom() {
        let csv = "\u{feff}# header\nfile.txt,1,0\n";
        let result = parse(csv).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, "file.txt");
    }

    #[test]
    fn parse_crlf() {
        let csv = "# header\r\nfile.txt,3,2\r\n";
        let result = parse(csv).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].expected_count, 5);
    }

    #[test]
    fn parse_comma_in_path() {
        // rsplitn(3, ',') splits from right: "5", "3", "path/with,comma.txt"
        let csv = "path/with,comma.txt,3,5\n";
        let result = parse(csv).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, "path/with,comma.txt");
        assert_eq!(result[0].expected_count, 8);
    }

    #[test]
    fn parse_whitespace_around_numbers() {
        let csv = "file.txt, 3 , 5 \n";
        let result = parse(csv).unwrap();
        assert_eq!(result[0].expected_count, 8);
    }

    #[test]
    fn parse_zero_counts() {
        let csv = "empty.txt,0,0\n";
        let result = parse(csv).unwrap();
        assert_eq!(result[0].expected_count, 0);
    }

    // ── parse: error cases ────────────────────────────────────

    #[test]
    fn parse_duplicate_error() {
        let csv = "file.txt,1,2\nfile.txt,3,4\n";
        let err = parse(csv).unwrap_err();
        assert!(matches!(err, LeakyRepoError::DuplicatePath { line: 2, .. }));
    }

    #[rstest::rstest]
    #[case::non_numeric_field("file.txt,abc,2\n", 1)]
    #[case::missing_fields("file.txt,1\n", 1)]
    #[case::negative_number("file.txt,-1,2\n", 1)]
    #[case::overflow("file.txt,4294967295,1\n", 1)]
    fn parse_invalid_row_cases(#[case] csv: &str, #[case] expected_line: usize) {
        let err = parse(csv).unwrap_err();
        assert!(
            matches!(err, LeakyRepoError::InvalidRow { line, .. } if line == expected_line),
            "expected InvalidRow at line {expected_line}, got {err:?}"
        );
    }

    // ── compare_counts: core logic ───────────────────────────

    #[rstest::rstest]
    #[case::overcounting(3, 5, 3, 2, 0)]
    #[case::undercounting(3, 1, 1, 0, 2)]
    #[case::zero_expected(0, 3, 0, 3, 0)]
    #[case::no_findings(3, 0, 0, 0, 3)]
    fn compare_formula_cases(
        #[case] expected_count: u32,
        #[case] num_findings: u32,
        #[case] exp_tp: u32,
        #[case] exp_fp: u32,
        #[case] exp_fn: u32,
    ) {
        let expectations = vec![FileExpectation {
            path: "a.txt".into(),
            expected_count,
        }];
        let findings: Vec<NormalizedFinding> = (0..num_findings)
            .map(|i| finding("a.txt", u64::from(i) * 10, u64::from(i) * 10 + 5))
            .collect();
        let result = compare_counts(findings, &expectations);
        assert_eq!(result.len(), 1, "result count");
        assert_eq!(result[0].tp, exp_tp, "tp");
        assert_eq!(result[0].fp, exp_fp, "fp");
        assert_eq!(result[0].false_neg, exp_fn, "false_neg");
    }

    #[test]
    fn compare_empty() {
        let result = compare_counts(vec![], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn compare_unlisted_file() {
        // Scanner found secrets in a file not in expectations.
        let findings = vec![finding("unknown.txt", 0, 5), finding("unknown.txt", 10, 15)];
        let result = compare_counts(findings, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, "unknown.txt");
        assert_eq!(result[0].expected, 0);
        assert_eq!(result[0].actual, 2);
        assert_eq!(result[0].tp, 0);
        assert_eq!(result[0].fp, 2);
        assert_eq!(result[0].false_neg, 0);
    }

    #[test]
    fn compare_dedup() {
        // Duplicate findings (same identity, different confidence) counted once.
        let expectations = vec![FileExpectation {
            path: "a.txt".into(),
            expected_count: 2,
        }];
        let findings = vec![
            NormalizedFinding::new("a.txt".into(), 0, 5, "r1".into(), 30),
            NormalizedFinding::new("a.txt".into(), 0, 5, "r1".into(), 80), // dup
            NormalizedFinding::new("a.txt".into(), 10, 15, "r1".into(), 50),
        ];
        let result = compare_counts(findings, &expectations);
        assert_eq!(result[0].actual, 2); // deduped from 3 to 2
        assert_eq!(result[0].tp, 2);
        assert_eq!(result[0].fp, 0);
        assert_eq!(result[0].false_neg, 0);
    }

    #[test]
    fn compare_multi_file_with_unlisted() {
        let expectations = vec![
            FileExpectation {
                path: "a.txt".into(),
                expected_count: 3,
            },
            FileExpectation {
                path: "b.txt".into(),
                expected_count: 1,
            },
        ];
        let findings = vec![
            finding("a.txt", 0, 5),
            finding("a.txt", 10, 15),
            finding("b.txt", 0, 5),
            finding("b.txt", 10, 15), // extra finding beyond expected
            finding("c.txt", 0, 5),   // unlisted file
        ];
        let result = compare_counts(findings, &expectations);
        assert_eq!(result.len(), 3);
        // a.txt: expected=3, actual=2 => tp=2, fp=0, fn=1
        let a = result.iter().find(|r| r.path == "a.txt").unwrap();
        assert_eq!((a.tp, a.fp, a.false_neg), (2, 0, 1));
        // b.txt: expected=1, actual=2 => tp=1, fp=1, fn=0
        let b = result.iter().find(|r| r.path == "b.txt").unwrap();
        assert_eq!((b.tp, b.fp, b.false_neg), (1, 1, 0));
        // c.txt: expected=0, actual=1 => tp=0, fp=1, fn=0
        let c = result.iter().find(|r| r.path == "c.txt").unwrap();
        assert_eq!((c.tp, c.fp, c.false_neg), (0, 1, 0));
    }

    // ── Error display ─────────────────────────────────────────

    #[test]
    fn error_display() {
        let e = LeakyRepoError::InvalidRow {
            line: 42,
            reason: "bad number".into(),
        };
        assert_eq!(e.to_string(), "line 42: bad number");

        let e = LeakyRepoError::DuplicatePath {
            line: 7,
            path: "foo.txt".into(),
        };
        assert_eq!(e.to_string(), "line 7: duplicate path \"foo.txt\"");

        // Io with path context.
        let e = LeakyRepoError::Io {
            path: Some(PathBuf::from("/data/secrets.csv")),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };
        assert_eq!(
            e.to_string(),
            "failed to read /data/secrets.csv: file not found"
        );

        // Io without path (generic reader).
        let e = LeakyRepoError::Io {
            path: None,
            source: std::io::Error::other("broken pipe"),
        };
        assert_eq!(e.to_string(), "I/O error: broken pipe");
    }

    // ── Property-based tests ──────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Parsed paths never contain backslashes.
            #[test]
            fn parsed_paths_no_backslash(
                path in "[a-z._/]{1,30}",
                risk in 0u32..50,
                info in 0u32..50,
            ) {
                let csv = format!("{path},{risk},{info}\n");
                let result = parse_leaky_repo(csv.as_bytes()).unwrap();
                prop_assert_eq!(result.len(), 1);
                prop_assert!(!result[0].path.contains('\\'));
            }

            /// Parse roundtrip: generated CSV re-parses to matching fields.
            #[test]
            fn parse_roundtrip(
                // Avoid commas in path for the roundtrip test since the
                // serialized CSV is unquoted.
                path in "[a-z._/]{1,20}",
                risk in 0u32..100,
                info in 0u32..100,
            ) {
                let csv = format!("# header\n{path},{risk},{info}\n");
                let result = parse_leaky_repo(csv.as_bytes()).unwrap();
                prop_assert_eq!(result.len(), 1);
                prop_assert_eq!(result[0].expected_count, risk + info);
            }

            /// The algebraic invariants tp+fp==actual and tp+fn==expected hold
            /// for every entry produced by compare_counts (integration-level).
            #[test]
            fn compare_invariants_through_function(
                expected in 0u32..20,
                actual in 0u32..20,
            ) {
                let expectations = vec![FileExpectation {
                    path: "f.txt".into(),
                    expected_count: expected,
                }];
                let findings: Vec<NormalizedFinding> = (0..actual)
                    .map(|i| finding("f.txt", u64::from(i) * 10, u64::from(i) * 10 + 5))
                    .collect();
                let result = compare_counts(findings, &expectations);
                for entry in &result {
                    prop_assert_eq!(
                        entry.tp + entry.fp, entry.actual,
                        "tp+fp != actual for {}", entry.path
                    );
                    prop_assert_eq!(
                        entry.tp + entry.false_neg, entry.expected,
                        "tp+fn != expected for {}", entry.path
                    );
                }
            }

            /// Adding duplicate findings does not change compare_counts results.
            #[test]
            fn compare_dedup_idempotent(
                expected in 1u32..10,
                actual in 1u32..10,
                extra_dupes in 1u32..5,
            ) {
                let expectations = vec![FileExpectation {
                    path: "f.txt".into(),
                    expected_count: expected,
                }];
                let base_findings: Vec<NormalizedFinding> = (0..actual)
                    .map(|i| finding("f.txt", u64::from(i) * 10, u64::from(i) * 10 + 5))
                    .collect();
                let mut with_dupes = base_findings.clone();
                for _ in 0..extra_dupes {
                    with_dupes.push(base_findings[0].clone());
                }
                let result_base = compare_counts(base_findings, &expectations);
                let result_dupes = compare_counts(with_dupes, &expectations);
                prop_assert_eq!(result_base, result_dupes, "duplicates changed result");
            }

            /// Output of compare_counts is always sorted by path.
            #[test]
            fn compare_output_always_sorted(
                expected_paths in proptest::collection::hash_set("[a-z]{1,8}", 1..10usize),
                unlisted_paths in proptest::collection::hash_set("[A-Z]{1,8}", 0..5usize),
            ) {
                let expectations: Vec<FileExpectation> = expected_paths.iter().map(|p| {
                    FileExpectation {
                        path: p.clone(),
                        expected_count: 1,
                    }
                }).collect();
                let findings: Vec<NormalizedFinding> = unlisted_paths.iter().map(|p| {
                    NormalizedFinding::new(p.clone(), 0, 5, "r".into(), 50)
                }).collect();
                let result = compare_counts(findings, &expectations);
                for w in result.windows(2) {
                    prop_assert!(
                        w[0].path <= w[1].path,
                        "output not sorted: {:?} > {:?}", w[0].path, w[1].path
                    );
                }
            }
        }
    }
}
