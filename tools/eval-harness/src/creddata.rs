//! CredData CSV parser for Samsung CredData ground-truth meta files.
//!
//! [Samsung CredData](https://github.com/Samsung/CredData) ships labeled
//! credential corpora as 13-column PascalCase CSV files. This module
//! parses them into [`TruthItem`] records using only the 5 columns needed
//! for evaluation: `FilePath`, `LineStart`, `LineEnd`, `GroundTruth`, and
//! `Category`. The remaining 8 columns are silently ignored by the csv
//! crate's header-based serde matching, avoiding per-row allocations for
//! unused data.
//!
//! # Entry points
//!
//! | Function | Input | Errors |
//! |---|---|---|
//! | [`parse_csv_reader`] | in-memory `Read` | Infallible — all errors become counters |
//! | [`parse_csv`] | disk path | File-open errors; row errors become counters |
//! | [`load_meta_dir`] | directory path | Directory-read errors; per-file errors collected |
//!
//! The split between [`parse_csv_reader`] (pure, testable) and [`parse_csv`]
//! (handles I/O, BOM stripping) follows a ports-and-adapters pattern so the
//! core parsing logic can be fuzzed without touching the filesystem.
//!
//! # Row validation pipeline
//!
//! Each CSV data row passes through these checks in order. The first
//! failure stops processing for that row and increments the appropriate
//! counter in [`CsvParseResult`]:
//!
//! 1. **Deserialize** — serde maps the CSV columns to [`MetaRow`] fields.
//!    Failures (missing columns, non-numeric line numbers) count as
//!    `malformed_rows`.
//! 2. **Label** — `GroundTruth` must be `"T"`, `"F"`, or `"X"`.
//! 3. **Non-empty fields** — `FilePath` and `Category` must be non-empty.
//! 4. **Positive line numbers** — CredData uses `-1` as a sentinel for
//!    unknown location; zero is also rejected since [`TruthItem`] requires
//!    1-indexed lines.
//! 5. **Non-inverted range** — `LineEnd >= LineStart`.
//! 6. **Path normalization** — [`normalize_path`] must produce a non-empty
//!    result (degenerate inputs like `".."` normalize to `""`).
//!
//! Steps 2-6 increment `skipped_rows`. Rows passing all checks become
//! [`TruthItem`] entries in `items`.
//!
//! # CredData CSV format
//!
//! ```text
//! Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,GroundTruth,ValueStart,ValueEnd,CryptographyKey,PredefinedPattern,Category
//! ```
//!
//! The `Category` column (e.g., `"Password"`, `"Token"`, `"AWS"`) maps to
//! [`TruthItem::rule`], serving as the rule-name axis for per-rule
//! precision/recall breakdowns.

use std::io;
use std::path::{Path, PathBuf};

use crate::types::{FileReadError, TruthItem, TruthLabel, normalize_path};

// ── Wire format ──────────────────────────────────────────────────────────

/// Partial deserialization of a CredData CSV row.
///
/// Only the 5 columns needed for [`TruthItem`] construction are declared.
/// The csv crate's header-based serde matching silently skips the remaining
/// 8 columns (Id, FileID, Domain, RepoName, ValueStart, ValueEnd,
/// CryptographyKey, PredefinedPattern), avoiding per-row deserialization
/// and allocation overhead for 8 unused columns.
///
/// Fields use `i64` for line numbers (not `u32`) because CredData encodes
/// "unknown location" as `-1`. Accepting the sentinel at the serde layer
/// and rejecting it during validation keeps deserialization infallible for
/// otherwise well-formed rows.
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MetaRow {
    /// Relative path within the CredData corpus (e.g., `"data/repo/src/a.py"`).
    file_path: String,
    /// 1-indexed start line, or `-1` for unknown location.
    line_start: i64,
    /// 1-indexed end line (inclusive), or `-1` for unknown location.
    line_end: i64,
    /// One of `"T"` (positive), `"F"` (negative), or `"X"` (placeholder).
    ground_truth: String,
    /// Credential category (e.g., `"Password"`, `"Token"`). Maps to
    /// [`TruthItem::rule`] for per-rule accuracy breakdowns.
    category: String,
}

// ── Result types ─────────────────────────────────────────────────────────

/// Outcome of parsing one or more CredData CSV files.
///
/// # Counting invariant
///
/// Every CSV data row (excluding the header) is classified into exactly
/// one bucket:
///
/// ```text
/// total_rows == items.len() + skipped_rows + malformed_rows
/// ```
///
/// This invariant is enforced by a property test
/// (`counting_invariant_always_holds`) over arbitrary inputs.
#[derive(Clone, Debug)]
pub struct CsvParseResult {
    /// Successfully parsed and validated truth items.
    pub items: Vec<TruthItem>,
    /// Total CSV data rows processed (excludes header row).
    pub total_rows: u64,
    /// Rows that parsed successfully but failed validation (unknown label,
    /// empty path/category, sentinel line numbers, inverted range).
    pub skipped_rows: u64,
    /// Rows that failed serde deserialization (non-numeric fields, missing
    /// columns, UTF-8 errors).
    pub malformed_rows: u64,
    /// First serde error message encountered, if any. Aids debugging when
    /// `malformed_rows` is unexpectedly high.
    pub first_malformed_error: Option<String>,
    /// Reason the first row was skipped, if any. Aids debugging when
    /// `skipped_rows` is unexpectedly high.
    pub first_skip_reason: Option<String>,
}

impl CsvParseResult {
    /// A zero-valued result with no items and no rows processed.
    fn empty() -> Self {
        Self {
            items: Vec::new(),
            total_rows: 0,
            skipped_rows: 0,
            malformed_rows: 0,
            first_malformed_error: None,
            first_skip_reason: None,
        }
    }

    /// A zero-valued result pre-allocated for approximately `capacity` items.
    fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            total_rows: 0,
            skipped_rows: 0,
            malformed_rows: 0,
            first_malformed_error: None,
            first_skip_reason: None,
        }
    }

    /// Absorb `other` into `self`, summing all counters and appending items.
    ///
    /// Preserves the counting invariant: if both `self` and `other` satisfy
    /// `total == items + skipped + malformed`, the merged result does too.
    fn merge(&mut self, other: Self) {
        self.total_rows += other.total_rows;
        self.skipped_rows += other.skipped_rows;
        self.malformed_rows += other.malformed_rows;
        if self.first_malformed_error.is_none() {
            self.first_malformed_error = other.first_malformed_error;
        }
        if self.first_skip_reason.is_none() {
            self.first_skip_reason = other.first_skip_reason;
        }
        self.items.extend(other.items);
    }
}

/// Outcome of loading all CSV files from a directory.
///
/// Per-file failures are collected rather than aborting the entire load.
/// Only directory-level I/O errors (unreadable directory) produce `Err`
/// from [`load_meta_dir`].
///
/// # File counting invariant
///
/// ```text
/// files_found == files_parsed + file_errors.len() as u32
/// ```
#[derive(Debug)]
pub struct DirLoadResult {
    /// Merged parse results from all successfully parsed files.
    pub parsed: CsvParseResult,
    /// Per-file errors for files that could not be opened or read.
    pub file_errors: Vec<FileReadError>,
    /// Number of `.csv` files discovered in the directory.
    pub files_found: u32,
    /// Number of `.csv` files successfully parsed (opened and fully read).
    pub files_parsed: u32,
}

// ── Public API ───────────────────────────────────────────────────────────

/// Parse a CredData CSV from an in-memory reader.
///
/// Infallible: all errors (I/O, deserialization, validation) become
/// counters in the returned [`CsvParseResult`]. Designed for testability
/// and fuzzing — the disk wrapper [`parse_csv`] handles file-open errors
/// and BOM stripping separately.
///
/// The reader must start after any UTF-8 BOM (callers using [`parse_csv`]
/// get this for free). The csv reader is configured with `flexible(true)`
/// so rows with extra trailing columns (common in hand-edited CSVs) are
/// tolerated rather than rejected.
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from file paths. Use `""` for no stripping.
///
/// See the module-level [row validation pipeline](self#row-validation-pipeline)
/// for the exact sequence of checks applied to each row.
pub fn parse_csv_reader<R: io::Read>(reader: R, canonical_root: &str) -> CsvParseResult {
    parse_csv_reader_inner(reader, canonical_root, 0)
}

/// Record a skipped row with a reason, updating counters.
fn record_skip(result: &mut CsvParseResult, reason: &str) {
    if result.first_skip_reason.is_none() {
        result.first_skip_reason = Some(reason.to_owned());
    }
    result.skipped_rows += 1;
}

/// Core CSV parsing loop with an optional capacity hint for the items Vec.
///
/// `capacity_hint` of 0 falls back to the default (no pre-allocation).
/// [`parse_csv`] estimates capacity from the file size to avoid repeated
/// Vec reallocations for large files.
fn parse_csv_reader_inner<R: io::Read>(
    reader: R,
    canonical_root: &str,
    capacity_hint: usize,
) -> CsvParseResult {
    let mut csv_reader = csv::ReaderBuilder::new().flexible(true).from_reader(reader);

    let mut result = if capacity_hint > 0 {
        CsvParseResult::with_capacity(capacity_hint)
    } else {
        CsvParseResult::empty()
    };

    for row_result in csv_reader.deserialize::<MetaRow>() {
        result.total_rows += 1;

        let row = match row_result {
            Ok(row) => row,
            Err(e) => {
                if result.first_malformed_error.is_none() {
                    result.first_malformed_error = Some(e.to_string());
                }
                result.malformed_rows += 1;
                continue;
            }
        };

        let label = match row.ground_truth.as_str() {
            "T" => TruthLabel::Positive,
            "F" => TruthLabel::Negative,
            "X" => TruthLabel::Placeholder,
            _ => {
                record_skip(&mut result, "unknown GroundTruth label");
                continue;
            }
        };

        if row.file_path.is_empty() || row.category.is_empty() {
            record_skip(&mut result, "empty FilePath or Category");
            continue;
        }

        // Sentinel line numbers: CredData uses -1 for "unknown location".
        // Clamping to 1 would fabricate concrete annotations at line 1,
        // corrupting precision/recall. Skip instead.
        if row.line_start <= 0 || row.line_end <= 0 {
            record_skip(&mut result, "non-positive line number");
            continue;
        }

        // Inverted range — check on original i64 values before narrowing,
        // so clamping cannot mask the inversion.
        if row.line_end < row.line_start {
            record_skip(&mut result, "inverted line range");
            continue;
        }

        // Line numbers exceeding u32::MAX indicate corrupt data (no real
        // source file has 4+ billion lines). Skip rather than clamp, which
        // would fabricate incorrect line numbers.
        if row.line_start > u32::MAX as i64 || row.line_end > u32::MAX as i64 {
            record_skip(&mut result, "line number exceeds u32::MAX");
            continue;
        }

        // Safe narrowing cast: all values are in [1, u32::MAX] at this point.
        let line_start = row.line_start as u32;
        let line_end = row.line_end as u32;

        // normalize_path can return "" for degenerate inputs (e.g., "..")
        let norm_path = normalize_path(&row.file_path, canonical_root);
        if norm_path.is_empty() {
            record_skip(&mut result, "empty normalized path");
            continue;
        }

        result.items.push(TruthItem::new(
            norm_path,
            line_start,
            line_end,
            label,
            row.category,
        ));
    }

    result
}

/// Strip a UTF-8 BOM (`EF BB BF`) from the start of a byte slice.
///
/// CredData CSVs exported from Excel or other Windows tools frequently
/// carry a BOM. Left in place, it becomes part of the first header field
/// name (`\u{FEFF}Id`), which would break header matching for any struct
/// that declares that field. Stripping it defensively avoids subtle
/// deserialization failures if the set of used columns ever changes.
fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data)
}

/// Parse a CredData CSV file from disk.
///
/// Reads the entire file into memory, strips any UTF-8 BOM, then
/// delegates to the same core parsing loop used by [`parse_csv_reader`],
/// with a capacity hint estimated from the file size. The eager read (rather than
/// streaming) is intentional: BOM detection requires inspecting the
/// first bytes, and CredData meta CSVs are small (typically < 1 MB).
///
/// Files larger than 256 MB are rejected as a sanity check — real
/// CredData meta CSVs are well under 1 MB.
///
/// Only file-open/read failures produce errors; row-level issues are
/// counted in [`CsvParseResult`].
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from file paths. Use `""` for no stripping.
pub fn parse_csv(path: &Path, canonical_root: &str) -> Result<CsvParseResult, FileReadError> {
    // Sanity-check file size before reading into memory. Real CredData
    // meta CSVs are well under 1 MB; anything above 256 MB is almost
    // certainly the wrong file.
    const MAX_CSV_SIZE: u64 = 256 * 1024 * 1024;
    let meta = std::fs::metadata(path).map_err(|e| FileReadError::new(path.to_path_buf(), e))?;
    if meta.len() > MAX_CSV_SIZE {
        return Err(FileReadError::new(
            path.to_path_buf(),
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "file size {} bytes exceeds {} byte limit for CredData CSV",
                    meta.len(),
                    MAX_CSV_SIZE,
                ),
            ),
        ));
    }
    let data = std::fs::read(path).map_err(|e| FileReadError::new(path.to_path_buf(), e))?;
    let data = strip_bom(&data);
    // CredData CSV rows average ~100 bytes; pre-allocate to avoid repeated
    // Vec reallocations for large files.
    let estimated_rows = data.len() / 100;
    Ok(parse_csv_reader_inner(
        io::Cursor::new(data),
        canonical_root,
        estimated_rows,
    ))
}

/// Load all `.csv` files from a directory with partial-success semantics.
///
/// Discovers files by extension (case-insensitive `.csv` match), sorts
/// them lexicographically for deterministic item ordering, then parses
/// each via [`parse_csv`]. Per-file failures are collected in
/// [`DirLoadResult::file_errors`] rather than aborting, so a single
/// corrupt file does not block evaluation of the rest of the corpus.
///
/// Only directory-level I/O errors (e.g., permission denied on `read_dir`)
/// produce `Err`. Non-`.csv` files in the directory are silently ignored.
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from file paths. Use `""` for no stripping.
pub fn load_meta_dir(dir: &Path, canonical_root: &str) -> Result<DirLoadResult, FileReadError> {
    let mut csv_paths: Vec<PathBuf> = Vec::new();
    let mut file_errors: Vec<FileReadError> = Vec::new();

    for entry_result in
        std::fs::read_dir(dir).map_err(|e| FileReadError::new(dir.to_path_buf(), e))?
    {
        let entry = match entry_result {
            Ok(e) => e,
            Err(source) => {
                file_errors.push(FileReadError::new(dir.to_path_buf(), source));
                continue;
            }
        };
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
        {
            csv_paths.push(path);
        }
    }
    csv_paths.sort();

    let files_found = csv_paths.len() as u32;
    let mut merged = CsvParseResult::empty();
    let mut files_parsed = 0u32;

    for csv_path in &csv_paths {
        match parse_csv(csv_path, canonical_root) {
            Ok(result) => {
                merged.merge(result);
                files_parsed += 1;
            }
            Err(e) => file_errors.push(e),
        }
    }

    Ok(DirLoadResult {
        parsed: merged,
        file_errors,
        files_found,
        files_parsed,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const HEADER: &str = "Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,\
                           GroundTruth,ValueStart,ValueEnd,CryptographyKey,\
                           PredefinedPattern,Category";

    /// Build a full 13-column CSV row from the 5 fields we care about.
    fn make_row(
        file_path: &str,
        line_start: i64,
        line_end: i64,
        ground_truth: &str,
        category: &str,
    ) -> String {
        format!(
            "1,f1,domain,repo,{file_path},{line_start},{line_end},\
             {ground_truth},-1,-1,N,N,{category}"
        )
    }

    fn parse_str(csv: &str, canonical_root: &str) -> CsvParseResult {
        parse_csv_reader(Cursor::new(csv.as_bytes()), canonical_root)
    }

    // ── Unit tests ──────────────────────────────────────────────

    #[test]
    fn parse_valid_rows() {
        let csv = format!(
            "{HEADER}\n{}\n{}\n{}",
            make_row("data/a.py", 1, 5, "T", "Password"),
            make_row("data/b.py", 10, 10, "F", "Token"),
            make_row("data/c.py", 3, 7, "X", "Key"),
        );
        let result = parse_str(&csv, "");

        assert_eq!(result.items.len(), 3);
        assert_eq!(result.total_rows, 3);
        assert_eq!(result.skipped_rows, 0);
        assert_eq!(result.malformed_rows, 0);

        assert_eq!(result.items[0].path, "data/a.py");
        assert_eq!(result.items[0].line_start, 1);
        assert_eq!(result.items[0].line_end, 5);
        assert_eq!(result.items[0].label, TruthLabel::Positive);
        assert_eq!(result.items[0].rule, "Password");

        assert_eq!(result.items[1].label, TruthLabel::Negative);
        assert_eq!(result.items[2].label, TruthLabel::Placeholder);
    }

    #[rstest::rstest]
    #[case::unknown_label("a.py", 1, 1, "Q", "Password")]
    #[case::inverted_range("a.py", 10, 5, "T", "Key")]
    #[case::empty_category("a.py", 1, 1, "T", "")]
    #[case::empty_filepath("", 1, 1, "T", "Password")]
    fn parse_skips_invalid_rows(
        #[case] path: &str,
        #[case] start: i64,
        #[case] end: i64,
        #[case] label: &str,
        #[case] cat: &str,
    ) {
        let csv = format!("{HEADER}\n{}", make_row(path, start, end, label, cat));
        let result = parse_str(&csv, "");
        assert!(result.items.is_empty(), "expected no items");
        assert_eq!(result.skipped_rows, 1, "expected 1 skipped row");
    }

    #[test]
    fn parse_skips_degenerate_paths() {
        for degenerate in ["..", ".", "../.."] {
            let csv = format!("{HEADER}\n{}", make_row(degenerate, 1, 1, "T", "Key"));
            let result = parse_str(&csv, "");
            assert!(
                result.items.is_empty(),
                "degenerate path {degenerate:?} should produce no items"
            );
            assert_eq!(
                result.skipped_rows, 1,
                "degenerate path {degenerate:?} should count as skipped"
            );
            assert!(
                result
                    .first_skip_reason
                    .as_deref()
                    .unwrap()
                    .contains("empty normalized path"),
                "degenerate path {degenerate:?} skip reason should mention empty normalized path"
            );
        }
    }

    #[test]
    fn parse_line_number_clamping() {
        // Sentinel -1/-1 → skip.
        let csv = format!("{HEADER}\n{}", make_row("a.py", -1, -1, "T", "Key"));
        let r = parse_str(&csv, "");
        assert!(r.items.is_empty(), "-1/-1 should be skipped");
        assert_eq!(r.skipped_rows, 1);

        // Mixed: positive start, negative end → skip.
        let csv = format!("{HEADER}\n{}", make_row("a.py", 5, -1, "T", "Key"));
        let r = parse_str(&csv, "");
        assert!(r.items.is_empty(), "5/-1 should be skipped");
        assert_eq!(r.skipped_rows, 1);

        // Zero → skip (TruthItem requires 1-indexed).
        let csv = format!("{HEADER}\n{}", make_row("a.py", 0, 0, "T", "Key"));
        let r = parse_str(&csv, "");
        assert!(r.items.is_empty(), "0/0 should be skipped");
        assert_eq!(r.skipped_rows, 1);

        // Valid positive values → kept.
        let csv = format!("{HEADER}\n{}", make_row("a.py", 5, 10, "T", "Key"));
        let r = parse_str(&csv, "");
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].line_start, 5);
        assert_eq!(r.items[0].line_end, 10);

        // Overflow → skipped (no real file has 4+ billion lines).
        let csv = format!(
            "{HEADER}\n{}",
            make_row("a.py", 5_000_000_000, 5_000_000_000, "T", "Key")
        );
        let r = parse_str(&csv, "");
        assert!(r.items.is_empty(), "overflow values should be skipped");
        assert_eq!(r.skipped_rows, 1);

        // Inverted range with both values > u32::MAX → skipped.
        // Clamping must not mask the inversion.
        let csv = format!(
            "{HEADER}\n{}",
            make_row("a.py", 5_000_000_001, 5_000_000_000, "T", "Key")
        );
        let r = parse_str(&csv, "");
        assert!(
            r.items.is_empty(),
            "inverted overflow range should be skipped"
        );
        assert_eq!(r.skipped_rows, 1);
    }

    #[test]
    fn parse_header_only() {
        let result = parse_str(HEADER, "");

        assert!(result.items.is_empty());
        assert_eq!(result.total_rows, 0);
        assert_eq!(result.skipped_rows, 0);
        assert_eq!(result.malformed_rows, 0);
    }

    #[test]
    fn parse_quoted_fields() {
        // FilePath contains a comma — must be quoted in CSV.
        let csv =
            format!("{HEADER}\n1,f1,d,r,\"path/with,comma/file.py\",1,1,T,-1,-1,N,N,Password");
        let result = parse_str(&csv, "");

        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].path, "path/with,comma/file.py");
    }

    #[test]
    fn corpus_root_stripped_from_paths() {
        let csv = format!(
            "{HEADER}\n{}",
            make_row("data/repo/src/a.py", 1, 1, "T", "Key")
        );
        let result = parse_str(&csv, "data/repo");

        assert_eq!(result.items[0].path, "src/a.py");
    }

    #[test]
    fn parse_handles_utf8_bom() {
        let csv = format!("\u{FEFF}{HEADER}\n{}", make_row("a.py", 1, 1, "T", "Key"));

        // Write to temp file so parse_csv strips BOM.
        let dir = std::env::temp_dir().join("creddata_bom_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("bom.csv");
        std::fs::write(&file, csv.as_bytes()).unwrap();

        let result = parse_csv(&file, "").unwrap();
        assert_eq!(result.items.len(), 1, "BOM should not break header parsing");
        assert_eq!(result.items[0].path, "a.py");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_not_found_error() {
        let err = parse_csv(Path::new("/nonexistent/creddata.csv"), "").unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("/nonexistent/creddata.csv"),
            "error should contain path: {msg}"
        );
    }

    #[test]
    fn parse_malformed_row_continues() {
        // Row with non-numeric LineStart increments malformed, doesn't abort.
        let csv = format!(
            "{HEADER}\n1,f1,d,r,a.py,abc,1,T,-1,-1,N,N,Key\n{}",
            make_row("b.py", 1, 1, "T", "Password"),
        );
        let result = parse_str(&csv, "");

        assert_eq!(
            result.items.len(),
            1,
            "valid row after malformed should be parsed"
        );
        assert_eq!(result.malformed_rows, 1);
        assert_eq!(result.items[0].path, "b.py");
    }

    #[test]
    fn first_malformed_error_captured() {
        let csv = format!(
            "{HEADER}\n1,f1,d,r,a.py,abc,1,T,-1,-1,N,N,Key\n{}",
            make_row("b.py", 1, 1, "T", "Password"),
        );
        let result = parse_str(&csv, "");
        assert_eq!(result.malformed_rows, 1);
        assert!(
            result.first_malformed_error.is_some(),
            "first_malformed_error should be captured"
        );
    }

    #[test]
    fn first_skip_reason_captured() {
        let csv = format!("{HEADER}\n{}", make_row("a.py", 1, 1, "Q", "Password"));
        let result = parse_str(&csv, "");
        assert_eq!(result.skipped_rows, 1);
        assert!(
            result
                .first_skip_reason
                .as_deref()
                .unwrap()
                .contains("unknown"),
        );
    }

    // ── Directory loading test ──────────────────────────────────

    #[test]
    fn load_meta_dir_merges_sorted() {
        let dir = std::env::temp_dir().join("creddata_dir_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let csv_a = format!("{HEADER}\n{}", make_row("a.py", 1, 1, "T", "Key"));
        let csv_b = format!(
            "{HEADER}\n{}\n{}",
            make_row("b.py", 2, 3, "F", "Token"),
            make_row("b2.py", 4, 5, "T", "Password"),
        );
        let csv_c = format!("{HEADER}\n{}", make_row("c.py", 10, 10, "X", "AWS"));

        // Write in reverse order to verify sorting.
        std::fs::write(dir.join("c.csv"), &csv_c).unwrap();
        std::fs::write(dir.join("a.csv"), &csv_a).unwrap();
        std::fs::write(dir.join("b.csv"), &csv_b).unwrap();
        // Non-csv file should be ignored.
        std::fs::write(dir.join("readme.txt"), "not a csv").unwrap();

        let result = load_meta_dir(&dir, "").unwrap();

        assert_eq!(result.files_found, 3);
        assert_eq!(result.files_parsed, 3);
        assert!(result.file_errors.is_empty());
        assert_eq!(result.parsed.items.len(), 4);

        // Sorted order: a.csv first, then b.csv, then c.csv.
        assert_eq!(result.parsed.items[0].path, "a.py");
        assert_eq!(result.parsed.items[1].path, "b.py");
        assert_eq!(result.parsed.items[2].path, "b2.py");
        assert_eq!(result.parsed.items[3].path, "c.py");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_meta_dir_partial_failure() {
        let dir = std::env::temp_dir().join("creddata_partial_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // One valid CSV file.
        let csv_good = format!("{HEADER}\n{}", make_row("a.py", 1, 1, "T", "Key"));
        std::fs::write(dir.join("good.csv"), &csv_good).unwrap();

        // A directory masquerading as a .csv file — parse_csv will fail to
        // read it because std::fs::read on a directory returns an error.
        std::fs::create_dir_all(dir.join("bad.csv")).unwrap();

        let result = load_meta_dir(&dir, "").unwrap();

        assert_eq!(result.files_found, 2);
        assert_eq!(result.files_parsed, 1);
        assert_eq!(result.file_errors.len(), 1);
        assert!(
            result.file_errors[0]
                .path()
                .to_str()
                .unwrap()
                .contains("bad.csv"),
            "error should reference the bad file"
        );
        // Valid file's items were still merged.
        assert_eq!(result.parsed.items.len(), 1);
        assert_eq!(result.parsed.items[0].path, "a.py");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_meta_dir_not_found() {
        let err = load_meta_dir(Path::new("/nonexistent/creddata/dir"), "").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/creddata/dir"),
            "error should contain path: {msg}"
        );
    }

    // ── Property tests ──────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Arbitrary input never panics.
            #[test]
            fn parse_never_panics(input in "\\PC*") {
                let _ = parse_csv_reader(Cursor::new(input.as_bytes()), "");
            }

            /// The counting invariant holds for all inputs.
            #[test]
            fn counting_invariant_always_holds(input in "\\PC*") {
                let r = parse_csv_reader(Cursor::new(input.as_bytes()), "");
                prop_assert_eq!(
                    r.total_rows,
                    r.items.len() as u64 + r.skipped_rows + r.malformed_rows,
                    "invariant: total = items + skipped + malformed"
                );
            }

            /// All output items satisfy TruthItem structural invariants.
            #[test]
            fn output_invariants(input in "\\PC*") {
                let r = parse_csv_reader(Cursor::new(input.as_bytes()), "");
                for item in &r.items {
                    prop_assert!(item.line_start >= 1, "line_start must be >= 1");
                    prop_assert!(
                        item.line_end >= item.line_start,
                        "line_end must be >= line_start"
                    );
                    prop_assert!(!item.path.is_empty(), "path must not be empty");
                    prop_assert!(!item.rule.is_empty(), "rule must not be empty");
                }
            }

            /// Valid MetaRow values roundtrip: generate → CSV → parse → verify.
            #[test]
            fn roundtrip_valid_rows(
                file_path in "[a-z]{1,5}(/[a-z]{1,5}){0,2}\\.[a-z]{2,3}",
                line_start in 1i64..10000,
                line_span in 0i64..100,
                label_char in prop_oneof![Just("T"), Just("F"), Just("X")],
                category in "[A-Z][a-z]{2,10}",
            ) {
                let line_end = line_start + line_span;
                let csv = format!(
                    "{HEADER}\n1,f1,d,r,{file_path},{line_start},{line_end},\
                     {label_char},-1,-1,N,N,{category}"
                );
                let r = parse_csv_reader(Cursor::new(csv.as_bytes()), "");

                prop_assert_eq!(r.items.len(), 1, "should parse exactly one item");
                prop_assert_eq!(r.malformed_rows, 0);
                prop_assert_eq!(r.skipped_rows, 0);

                let item = &r.items[0];
                prop_assert_eq!(&item.path, &file_path);
                prop_assert_eq!(item.line_start, line_start as u32);
                prop_assert_eq!(item.line_end, line_end as u32);
                prop_assert_eq!(&item.rule, &category);
            }

            /// Parsing is deterministic: same input always yields same output.
            #[test]
            fn parse_is_deterministic(input in "\\PC{0,200}") {
                let a = parse_csv_reader(Cursor::new(input.as_bytes()), "");
                let b = parse_csv_reader(Cursor::new(input.as_bytes()), "");
                prop_assert_eq!(a.total_rows, b.total_rows);
                prop_assert_eq!(a.skipped_rows, b.skipped_rows);
                prop_assert_eq!(a.malformed_rows, b.malformed_rows);
                prop_assert_eq!(a.items.len(), b.items.len());
                for (ia, ib) in a.items.iter().zip(b.items.iter()) {
                    prop_assert_eq!(ia, ib);
                }
            }
        }
    }
}
