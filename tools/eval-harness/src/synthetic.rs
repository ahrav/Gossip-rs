//! Synthetic corpus manifest loader.
//!
//! Loads a JSON manifest file containing ground-truth annotations into
//! [`Vec<TruthItem>`]. The manifest is a bare JSON array of objects with
//! fields matching [`TruthItem`]'s serde shape.
//!
//! # Expected JSON format
//!
//! ```json
//! [
//!   {"path": "src/a.py", "line_start": 1, "line_end": 1, "label": "positive", "rule": "aws-key"},
//!   {"path": "src/b.py", "line_start": 5, "line_end": 6, "label": "negative", "category": "generic-api-key"}
//! ]
//! ```
//!
//! The `rule` field also accepts `"category"` as an alias for
//! interoperability with manifest generators that use that name. If both
//! fields are present in the same object, `rule` takes precedence.
//!
//! # Fail-fast vs partial-failure
//!
//! Unlike the CredData CSV loader ([`crate::creddata`]), which uses
//! counter-based partial-failure semantics to tolerate individual bad rows
//! in large multi-file corpora, this module fails on the first error.
//! Synthetic manifests are small, hand-authored files where any defect
//! signals a generation bug — silently skipping a corrupt item would
//! produce misleading precision/recall numbers.
//!
//! # Pipeline position
//!
//! This is Phase 2 (ground-truth loading) for synthetic corpora — a
//! complement to the CredData CSV loader in [`crate::creddata`] and the
//! JSONL finding parser in [`crate::finding_parser`].

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::types::{TruthItem, TruthLabel, normalize_path};

// ── Deserialization helper ────────────────────────────────────────────────

/// Intermediate representation that accepts both `rule` and `category` fields.
///
/// Serde's `#[serde(alias)]` rejects JSON objects containing both the primary
/// and alias key ("duplicate field"). Manifests from migration-era generators
/// may include both for backwards compatibility, so we deserialize into this
/// permissive shape first, then merge into [`TruthItem`].
#[derive(Deserialize)]
struct RawManifestItem {
    path: String,
    line_start: u32,
    line_end: u32,
    label: TruthLabel,
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

// ── Error type ───────────────────────────────────────────────────────────

/// Error from loading or validating a synthetic manifest file.
///
/// Structured as a three-variant enum so callers can distinguish
/// infrastructure failures (I/O, JSON syntax) from semantic problems
/// (domain-constraint violations in an otherwise well-formed record).
/// All three variants carry the file path for context. The
/// [`Validation`](SyntheticError::Validation) variant additionally
/// carries the item index so error messages can pinpoint the exact
/// offending record without re-parsing.
///
/// This type is separate from [`crate::types::FileReadError`] because
/// synthetic manifests require richer error reporting: JSON parse errors,
/// per-item validation, and the file path for context. `FileReadError`
/// only covers raw I/O failures.
#[derive(Debug)]
pub enum SyntheticError {
    /// File could not be read from disk.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// File contents are not valid JSON or do not match the expected schema.
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// An individual item violates a domain constraint that serde cannot
    /// express (e.g., zero-indexed line number, inverted range). Carries
    /// the file path so error messages identify which manifest failed.
    Validation {
        path: PathBuf,
        index: usize,
        reason: String,
    },
}

impl fmt::Display for SyntheticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {}", path.display(), source)
            }
            Self::Json { path, source } => {
                write!(f, "failed to parse {}: {}", path.display(), source)
            }
            Self::Validation {
                path,
                index,
                reason,
            } => {
                write!(f, "{}[{index}]: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for SyntheticError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Validation { .. } => None,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Construct a [`SyntheticError::Validation`] for the item at `index` in
/// the manifest at `path`.
fn validation_err(path: &Path, index: usize, reason: impl Into<String>) -> SyntheticError {
    SyntheticError::Validation {
        path: path.to_path_buf(),
        index,
        reason: reason.into(),
    }
}

// ── Public API ───────────────────────────────────────────────────────────

/// Load a synthetic corpus manifest from disk.
///
/// The file must contain a bare JSON array of objects whose shape matches
/// [`TruthItem`] (fields: `path`, `line_start`, `line_end`, `label`,
/// `rule`). The `rule` field also accepts `"category"` as an alias; if
/// both are present, `rule` takes precedence.
///
/// An empty array (`[]`) is valid and returns an empty `Vec`.
///
/// `canonical_root` is passed through to [`normalize_path`] for stripping
/// the corpus-root prefix from item paths. Must be pre-canonicalized
/// (forward slashes, no `.`/`..` components); use `""` for no stripping.
///
/// # Validation
///
/// After successful deserialization, every item is checked in order
/// against these domain constraints (serde cannot express them):
///
/// 1. `path` must be non-empty (before normalization).
/// 2. `line_start` must be >= 1 (1-indexed convention shared with
///    [`TruthItem`] and the CredData corpus).
/// 3. `line_end` must be >= 1 (same 1-indexed convention).
/// 4. `rule` must be non-empty.
/// 5. `line_end` must be >= `line_start` (no inverted ranges).
/// 6. Normalized `path` must be non-empty (degenerate inputs like `".."`
///    normalize to `""`; the error includes the raw path for debugging).
///
/// Validation halts on the first violation. The ordering is chosen so
/// the most informative error (missing path) surfaces before less
/// obvious ones (inverted range).
///
/// # Errors
///
/// - [`SyntheticError::Io`] — the file could not be read (missing,
///   permissions, etc.) or exceeds the 16 MB size guard.
/// - [`SyntheticError::Json`] — file contents are not valid JSON or do
///   not match the expected `Vec<TruthItem>` schema (includes unknown
///   label values, which serde rejects at parse time).
/// - [`SyntheticError::Validation`] — an individual item passes serde
///   parsing but violates a domain constraint listed above.
///
/// The entire manifest must be valid because ground-truth corruption
/// would silently invalidate the full evaluation.
pub fn load_synthetic_manifest(
    path: &Path,
    canonical_root: &str,
) -> Result<Vec<TruthItem>, SyntheticError> {
    // Sanity-check file size before reading into memory. Synthetic
    // manifests are small, hand-authored files; anything above 16 MB is
    // almost certainly the wrong file.
    const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;
    let meta = std::fs::metadata(path).map_err(|e| SyntheticError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if meta.len() > MAX_MANIFEST_SIZE {
        return Err(SyntheticError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "file size {} bytes exceeds {} byte limit for synthetic manifest",
                    meta.len(),
                    MAX_MANIFEST_SIZE,
                ),
            ),
        });
    }

    let contents = std::fs::read_to_string(path).map_err(|e| SyntheticError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let raw_items: Vec<RawManifestItem> =
        serde_json::from_str(&contents).map_err(|e| SyntheticError::Json {
            path: path.to_path_buf(),
            source: e,
        })?;

    // Convert raw items to TruthItem, merging rule/category and validating.
    // Checked in a deterministic order (path, line_start, line_end, rule,
    // range, normalized path) so the first error reported is always the
    // most structurally fundamental.
    let mut items = Vec::with_capacity(raw_items.len());
    for (i, raw) in raw_items.into_iter().enumerate() {
        if raw.path.is_empty() {
            return Err(validation_err(path, i, "path must not be empty"));
        }
        if raw.line_start == 0 {
            return Err(validation_err(
                path,
                i,
                format!("line_start is {}, must be >= 1 (1-indexed)", raw.line_start),
            ));
        }
        if raw.line_end == 0 {
            return Err(validation_err(
                path,
                i,
                format!("line_end is {}, must be >= 1 (1-indexed)", raw.line_end),
            ));
        }

        // Accept `rule` or `category` (or both — prefer `rule`).
        let rule = raw.rule.or(raw.category).unwrap_or_default();
        if rule.is_empty() {
            return Err(validation_err(path, i, "rule must not be empty"));
        }

        if raw.line_end < raw.line_start {
            return Err(validation_err(
                path,
                i,
                format!(
                    "line_end ({}) < line_start ({})",
                    raw.line_end, raw.line_start
                ),
            ));
        }

        // Normalize the path for cross-platform comparison, matching what
        // creddata and finding_parser do for their respective loaders.
        let normalized = normalize_path(&raw.path, canonical_root);
        if normalized.is_empty() {
            return Err(validation_err(
                path,
                i,
                format!("path {:?} normalizes to empty string", raw.path),
            ));
        }

        items.push(TruthItem {
            path: normalized,
            line_start: raw.line_start,
            line_end: raw.line_end,
            label: raw.label,
            rule,
        });
    }

    Ok(items)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TruthLabel;
    use std::io::Write as _;

    /// Helper: write `content` to a temp file and return its path.
    fn temp_json(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    // ── Unit tests ───────────────────────────────────────────────

    #[test]
    fn valid_manifest_loads() {
        let json = r#"[
            {"path":"src/a.py","line_start":1,"line_end":1,"label":"positive","rule":"aws-key"},
            {"path":"src/b.py","line_start":5,"line_end":6,"label":"negative","rule":"generic-api-key"},
            {"path":"src/c.py","line_start":10,"line_end":10,"label":"placeholder","rule":"password"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();

        assert_eq!(items.len(), 3);

        assert_eq!(items[0].path, "src/a.py");
        assert_eq!(items[0].line_start, 1);
        assert_eq!(items[0].line_end, 1);
        assert_eq!(items[0].label, TruthLabel::Positive);
        assert_eq!(items[0].rule, "aws-key");

        assert_eq!(items[1].label, TruthLabel::Negative);
        assert_eq!(items[2].label, TruthLabel::Placeholder);
    }

    #[test]
    fn category_alias_works() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive","category":"aws-key"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items[0].rule, "aws-key");
    }

    #[test]
    fn invalid_label_rejected() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"unknown","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        assert!(matches!(err, SyntheticError::Json { .. }));
    }

    #[test]
    fn missing_file_io_error() {
        let err = load_synthetic_manifest(Path::new("/nonexistent/truth.json"), "").unwrap_err();
        assert!(matches!(err, SyntheticError::Io { .. }));
    }

    #[test]
    fn empty_array_ok() {
        let f = temp_json("[]");
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert!(items.is_empty());
    }

    #[rstest::rstest]
    #[case::empty_path(
        r#"[{"path":"","line_start":1,"line_end":1,"label":"positive","rule":"r"}]"#,
        "path"
    )]
    #[case::zero_line_start(
        r#"[{"path":"x.py","line_start":0,"line_end":1,"label":"positive","rule":"r"}]"#,
        "line_start"
    )]
    #[case::zero_line_end(
        r#"[{"path":"x.py","line_start":1,"line_end":0,"label":"positive","rule":"r"}]"#,
        "line_end"
    )]
    #[case::empty_rule(
        r#"[{"path":"x.py","line_start":1,"line_end":1,"label":"positive","rule":""}]"#,
        "rule"
    )]
    #[case::inverted_range(
        r#"[{"path":"x.py","line_start":10,"line_end":5,"label":"positive","rule":"r"}]"#,
        "line_end"
    )]
    fn validation_rejects_bad_items(#[case] json: &str, #[case] keyword: &str) {
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        match err {
            SyntheticError::Validation { index, reason, .. } => {
                assert_eq!(index, 0, "json={json}");
                assert!(
                    reason.contains(keyword),
                    "expected '{keyword}' in: {reason}"
                );
            }
            other => panic!("expected Validation for '{keyword}', got {other}"),
        }
    }

    #[test]
    fn duplicate_items_preserved() {
        let item = r#"{"path":"a.py","line_start":1,"line_end":1,"label":"positive","rule":"r"}"#;
        let json = format!("[{item},{item},{item}]");
        let f = temp_json(&json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items.len(), 3, "duplicates must not be silently removed");
    }

    #[test]
    fn both_rule_and_category_present_prefers_rule() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive","rule":"aws-key","category":"generic-api-key"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(
            items[0].rule, "aws-key",
            "rule takes precedence over category"
        );
    }

    #[test]
    fn neither_rule_nor_category_rejected() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive"}
        ]"#;
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        match err {
            SyntheticError::Validation { index, reason, .. } => {
                assert_eq!(index, 0);
                assert!(reason.contains("rule"), "{reason}");
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn extra_fields_ignored() {
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive","rule":"r","extra":"ignored"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn paths_are_normalized() {
        let json = r#"[
            {"path":"src/a.py","line_start":1,"line_end":1,"label":"positive","rule":"r"},
            {"path":"src\\b.py","line_start":1,"line_end":1,"label":"positive","rule":"r"},
            {"path":"./src/c.py","line_start":1,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items[0].path, "src/a.py");
        assert_eq!(items[1].path, "src/b.py", "backslash should be normalized");
        assert_eq!(items[2].path, "src/c.py", "leading ./ should be stripped");
    }

    #[test]
    fn corpus_root_stripped_from_paths() {
        let json = r#"[
            {"path":"corpus/data/a.py","line_start":1,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "corpus/data").unwrap();
        assert_eq!(items[0].path, "a.py");
    }

    #[test]
    fn degenerate_path_rejected() {
        let json = r#"[
            {"path":"..","line_start":1,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        match err {
            SyntheticError::Validation { index, reason, .. } => {
                assert_eq!(index, 0);
                assert!(reason.contains("normalizes to empty"), "{reason}");
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn file_size_guard_rejects_oversized() {
        // Create a temp file larger than MAX_MANIFEST_SIZE (16 MB).
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let chunk = vec![b' '; 1024 * 1024]; // 1 MB
        for _ in 0..17 {
            f.write_all(&chunk).unwrap();
        }
        f.flush().unwrap();

        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        match &err {
            SyntheticError::Io { source, .. } => {
                assert!(
                    source.to_string().contains("exceeds"),
                    "expected size-guard message, got: {source}"
                );
            }
            other => panic!("expected Io with size guard, got {other}"),
        }
    }

    // ── Edge-case validation tests ─────────────────────────────

    #[test]
    fn validation_error_reports_correct_index() {
        // Valid item at index 0, invalid (empty path) at index 1.
        let json = r#"[
            {"path":"ok.py","line_start":1,"line_end":1,"label":"positive","rule":"r"},
            {"path":"","line_start":1,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        match err {
            SyntheticError::Validation { index, .. } => {
                assert_eq!(index, 1, "error should point to the second item");
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn validation_ordering_path_before_line_start() {
        // Item has both empty path AND line_start == 0. Path check should
        // fire first because it is structurally more fundamental.
        let json = r#"[
            {"path":"","line_start":0,"line_end":1,"label":"positive","rule":"r"}
        ]"#;
        let f = temp_json(json);
        let err = load_synthetic_manifest(f.path(), "").unwrap_err();
        match err {
            SyntheticError::Validation { reason, .. } => {
                assert!(
                    reason.contains("path"),
                    "expected path error first, got: {reason}"
                );
            }
            other => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn both_rule_and_category_last_key_wins_in_serde() {
        // When both `"rule"` and `"category"` are present, our code
        // prefers `rule` via `raw.rule.or(raw.category)`. If only
        // `"category"` is present, it becomes the rule. This test
        // documents that serde deserializes both independently (no
        // "duplicate field" rejection) and our merge logic is explicit.
        let json = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive","category":"cat-val","rule":"rule-val"}
        ]"#;
        let f = temp_json(json);
        let items = load_synthetic_manifest(f.path(), "").unwrap();
        assert_eq!(items[0].rule, "rule-val", "rule takes precedence");

        // Reversed key order — still rule wins because our code checks
        // `raw.rule` first, not JSON key ordering.
        let json2 = r#"[
            {"path":"x.py","line_start":1,"line_end":1,"label":"positive","rule":"rule-val","category":"cat-val"}
        ]"#;
        let f2 = temp_json(json2);
        let items2 = load_synthetic_manifest(f2.path(), "").unwrap();
        assert_eq!(
            items2[0].rule, "rule-val",
            "rule wins regardless of key order"
        );
    }

    // ── Property tests ───────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        fn truth_label_strategy() -> impl Strategy<Value = &'static str> {
            prop_oneof![Just("positive"), Just("negative"), Just("placeholder"),]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn roundtrip(
                path in "[a-z]{1,20}/[a-z]{1,20}\\.[a-z]{1,4}",
                line_start in 1u32..10_000,
                span in 0u32..100,
                label in truth_label_strategy(),
                rule in "[a-z_]{1,20}",
            ) {
                let line_end = line_start + span;
                let json = format!(
                    r#"[{{"path":"{path}","line_start":{line_start},"line_end":{line_end},"label":"{label}","rule":"{rule}"}}]"#,
                );
                let f = temp_json(&json);
                let items = load_synthetic_manifest(f.path(), "").unwrap();
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].path, path);
                assert_eq!(items[0].line_start, line_start);
                assert_eq!(items[0].line_end, line_end);
                assert_eq!(items[0].rule, rule);
                let expected_label: TruthLabel =
                    serde_json::from_str(&format!("\"{label}\"")).unwrap();
                assert_eq!(items[0].label, expected_label);
            }

            #[test]
            fn never_panic(data: Vec<u8>, root in "\\PC{0,20}") {
                let mut f = tempfile::NamedTempFile::new().unwrap();
                f.write_all(&data).unwrap();
                f.flush().unwrap();
                // Must return Ok or Err — never panic.
                let _ = load_synthetic_manifest(f.path(), &root);
            }
        }
    }
}
