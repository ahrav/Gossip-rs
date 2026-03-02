//! JSONL parity helpers for scanner runtime validation.
//!
//! This module ports the canonical finding comparison model from scanner-rs
//! and adapts it to gossip-rs runtime event output. It intentionally focuses on
//! stable comparison dimensions (path/rule/span/git metadata) and ignores
//! unstable fields.
//!
//! Canonicalization invariants:
//! - Both scanner-rs finding shapes (`type="finding"` + `rule`) and
//!   gossip-rs finding shapes (no `type`, `rule_name`) are accepted.
//! - Git findings with `commit_id` must have a matching `commit_meta` event.
//! - A summary event with `throughput_mib_s` is required.
//! - Output findings are sorted to keep parity assertions deterministic.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// Canonical finding identity used for deterministic parity comparison.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanonicalFinding {
    /// Source-displayed path (normalized when a root prefix is provided).
    pub path: String,
    /// Rule identity (`rule_name` in gossip-rs, `rule` in scanner-rs).
    pub rule: String,
    /// Inclusive start offset.
    pub start: u64,
    /// Exclusive end offset.
    pub end: u64,
    /// Source kind (`fs`, `git`, ...).
    pub source: String,
    /// Git-only change kind (`add` / `modify`), omitted for FS findings.
    pub change_kind: Option<String>,
    /// Git commit OID resolved from `commit_meta`, omitted for FS findings.
    pub commit_oid: Option<String>,
    /// Git commit timestamp resolved from `commit_meta`, omitted for FS findings.
    pub commit_timestamp: Option<u64>,
}

/// Canonicalized run payload used by parity tests.
#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalRun {
    /// Sorted canonical finding identities.
    pub findings: Vec<CanonicalFinding>,
    /// Throughput from the summary event field `throughput_mib_s`.
    pub throughput_mib_s: f64,
}

#[derive(Debug)]
struct PendingFinding {
    path: String,
    rule: String,
    start: u64,
    end: u64,
    source: String,
    change_kind: Option<String>,
    commit_id: Option<u32>,
}

/// Errors emitted while canonicalizing JSONL output into parity tuples.
#[derive(Debug)]
pub enum CanonicalizeError {
    /// One JSONL record could not be parsed.
    Json {
        line: usize,
        source: serde_json::Error,
    },
    /// A required field is not present on a record.
    MissingField { line: usize, field: &'static str },
    /// A field exists but does not match the expected JSON type.
    InvalidFieldType {
        line: usize,
        field: &'static str,
        expected: &'static str,
    },
    /// A git finding referenced `commit_id` without a matching `commit_meta`.
    MissingCommitMeta { commit_id: u32 },
    /// No summary record exposed `throughput_mib_s`.
    MissingSummaryThroughput,
}

impl fmt::Display for CanonicalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json { line, source } => {
                write!(f, "failed to parse JSONL line {}: {}", line, source)
            }
            Self::MissingField { line, field } => {
                write!(f, "line {} is missing required field '{}'", line, field)
            }
            Self::InvalidFieldType {
                line,
                field,
                expected,
            } => write!(
                f,
                "line {} has invalid type for '{}'; expected {}",
                line, field, expected
            ),
            Self::MissingCommitMeta { commit_id } => {
                write!(
                    f,
                    "finding references commit_id {} but no commit_meta event was emitted",
                    commit_id
                )
            }
            Self::MissingSummaryThroughput => {
                write!(f, "scan output did not include a summary throughput value")
            }
        }
    }
}

impl std::error::Error for CanonicalizeError {}

fn required_str(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<String, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Err(CanonicalizeError::MissingField { line, field });
    };
    let Some(s) = raw.as_str() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "string",
        });
    };
    Ok(s.to_owned())
}

fn required_u64(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<u64, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Err(CanonicalizeError::MissingField { line, field });
    };
    let Some(n) = raw.as_u64() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "u64",
        });
    };
    Ok(n)
}

fn optional_u32(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<Option<u32>, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    let Some(n) = raw.as_u64() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "u32",
        });
    };
    let parsed = u32::try_from(n).map_err(|_| CanonicalizeError::InvalidFieldType {
        line,
        field,
        expected: "u32",
    })?;
    Ok(Some(parsed))
}

fn optional_string(
    value: &serde_json::Value,
    line: usize,
    field: &'static str,
) -> Result<Option<String>, CanonicalizeError> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    let Some(s) = raw.as_str() else {
        return Err(CanonicalizeError::InvalidFieldType {
            line,
            field,
            expected: "string",
        });
    };
    Ok(Some(s.to_owned()))
}

fn rule_field(value: &serde_json::Value, line: usize) -> Result<String, CanonicalizeError> {
    if value.get("rule_name").is_some() {
        return required_str(value, line, "rule_name");
    }
    required_str(value, line, "rule")
}

fn is_finding_event(value: &serde_json::Value) -> bool {
    let type_field = value.get("type").and_then(serde_json::Value::as_str);
    if matches!(type_field, Some("finding")) {
        return true;
    }
    type_field.is_none()
        && value.get("path").is_some()
        && (value.get("rule_name").is_some() || value.get("rule").is_some())
        && value.get("start").is_some()
        && value.get("end").is_some()
}

fn normalize_path(path: String, roots: &[&Path]) -> String {
    let candidate = Path::new(&path);
    for root in roots {
        if let Ok(stripped) = candidate.strip_prefix(root) {
            if stripped.as_os_str().is_empty() {
                // Exact match (path == root): preserve the filename so that
                // single-file scans retain file identity instead of collapsing
                // to an empty string.
                if let Some(name) = candidate.file_name() {
                    return name.to_string_lossy().replace('\\', "/");
                }
            }
            return stripped.to_string_lossy().replace('\\', "/");
        }
    }
    path.replace('\\', "/")
}

/// Parse JSONL scan output into canonical finding identities and throughput.
///
/// Expected input is scanner event output containing finding events,
/// optional `commit_meta` events, and a summary event with
/// `throughput_mib_s`.
///
/// Findings are returned in sorted order so parity checks are stable even if
/// event emission order varies.
pub fn canonicalize_jsonl_events(bytes: &[u8]) -> Result<CanonicalRun, CanonicalizeError> {
    canonicalize_jsonl_events_with_roots(bytes, &[])
}

/// Canonicalize JSONL events and normalize paths by stripping known roots.
///
/// This enables stable golden comparison across machines where absolute
/// checkout paths differ.
///
/// `roots` are checked in order; the first matching prefix is stripped.
pub fn canonicalize_jsonl_events_with_roots(
    bytes: &[u8],
    roots: &[&Path],
) -> Result<CanonicalRun, CanonicalizeError> {
    let mut commit_meta: HashMap<u32, (String, u64)> = HashMap::new();
    let mut pending_findings = Vec::new();
    let mut throughput_mib_s = None;

    for (line_idx, line) in bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let line_no = line_idx + 1;
        let value: serde_json::Value =
            serde_json::from_slice(line).map_err(|source| CanonicalizeError::Json {
                line: line_no,
                source,
            })?;

        if is_finding_event(&value) {
            let path = normalize_path(required_str(&value, line_no, "path")?, roots);
            let rule = rule_field(&value, line_no)?;
            let start = required_u64(&value, line_no, "start")?;
            let end = required_u64(&value, line_no, "end")?;
            let source = required_str(&value, line_no, "source")?;
            let change_kind = optional_string(&value, line_no, "change_kind")?;
            let commit_id = optional_u32(&value, line_no, "commit_id")?;
            pending_findings.push(PendingFinding {
                path,
                rule,
                start,
                end,
                source,
                change_kind,
                commit_id,
            });
            // Defer commit metadata join so finding and commit_meta ordering in
            // the stream does not affect parity output.
            continue;
        }

        let Some(event_type) = value.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };

        match event_type {
            "commit_meta" => {
                let commit_id_u64 = required_u64(&value, line_no, "commit_id")?;
                let commit_id = u32::try_from(commit_id_u64).map_err(|_| {
                    CanonicalizeError::InvalidFieldType {
                        line: line_no,
                        field: "commit_id",
                        expected: "u32",
                    }
                })?;
                let oid = required_str(&value, line_no, "oid")?;
                let timestamp = required_u64(&value, line_no, "timestamp")?;
                commit_meta.insert(commit_id, (oid, timestamp));
            }
            "summary" => {
                let Some(raw) = value.get("throughput_mib_s") else {
                    return Err(CanonicalizeError::MissingField {
                        line: line_no,
                        field: "throughput_mib_s",
                    });
                };
                let Some(tp) = raw.as_f64() else {
                    return Err(CanonicalizeError::InvalidFieldType {
                        line: line_no,
                        field: "throughput_mib_s",
                        expected: "f64",
                    });
                };
                throughput_mib_s = Some(tp);
            }
            _ => {}
        }
    }

    let mut findings = Vec::with_capacity(pending_findings.len());
    for finding in pending_findings {
        let (commit_oid, commit_timestamp) = if let Some(commit_id) = finding.commit_id {
            let Some((oid, ts)) = commit_meta.get(&commit_id) else {
                return Err(CanonicalizeError::MissingCommitMeta { commit_id });
            };
            (Some(oid.clone()), Some(*ts))
        } else {
            (None, None)
        };

        findings.push(CanonicalFinding {
            path: finding.path,
            rule: finding.rule,
            start: finding.start,
            end: finding.end,
            source: finding.source,
            change_kind: finding.change_kind,
            commit_oid,
            commit_timestamp,
        });
    }
    findings.sort();

    let Some(throughput_mib_s) = throughput_mib_s else {
        return Err(CanonicalizeError::MissingSummaryThroughput);
    };

    Ok(CanonicalRun {
        findings,
        throughput_mib_s,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_accepts_scanner_rs_finding_shape() {
        let jsonl = br#"{"type":"finding","source":"fs","path":"secret.txt","start":0,"end":41,"rule":"generic-api-key","confidence_score":5}
{"type":"summary","source":"fs","status":"complete","elapsed_ms":1,"bytes":41,"findings":1,"errors":0,"throughput_mib_s":0.00}
"#;

        let run = canonicalize_jsonl_events(jsonl).expect("canonicalize");
        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].rule, "generic-api-key");
    }

    #[test]
    fn canonicalize_accepts_gossip_rs_finding_shape() {
        let jsonl = br#"{"path":"secret.txt","rule_name":"aws-access-token","start":20,"end":40,"source":"fs","confidence_score":8}
{"type":"summary","source":"fs","status":"complete","elapsed_ms":1,"bytes_scanned":41,"findings_emitted":1,"errors":0,"throughput_mib_s":0.00}
"#;

        let run = canonicalize_jsonl_events(jsonl).expect("canonicalize");
        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].rule, "aws-access-token");
    }

    #[test]
    fn canonicalize_joins_commit_meta() {
        let jsonl = br#"{"type":"finding","source":"git","path":"a.txt","start":1,"end":3,"rule":"tok","rule_id":0,"commit_id":7,"change_kind":"add","confidence_score":0}
{"type":"commit_meta","commit_id":7,"oid":"0123","timestamp":100}
{"type":"summary","source":"git","status":"complete","elapsed_ms":1,"bytes":1,"findings":1,"errors":0,"throughput_mib_s":2.50}
"#;

        let run = canonicalize_jsonl_events(jsonl).expect("canonicalize");
        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].commit_oid.as_deref(), Some("0123"));
        assert_eq!(run.findings[0].commit_timestamp, Some(100));
    }

    #[test]
    fn canonicalize_normalizes_path_prefix() {
        let jsonl = br#"{"path":"/tmp/corpus/dir/secret.txt","rule_name":"generic-api-key","start":0,"end":41,"source":"fs","confidence_score":5}
{"type":"summary","source":"fs","status":"complete","elapsed_ms":1,"bytes_scanned":41,"findings_emitted":1,"errors":0,"throughput_mib_s":0.00}
"#;
        let root = Path::new("/tmp/corpus/dir");
        let run = canonicalize_jsonl_events_with_roots(jsonl, &[root]).expect("canonicalize");
        assert_eq!(run.findings[0].path, "secret.txt");
    }

    #[test]
    fn normalize_path_preserves_filename_when_path_equals_root() {
        let jsonl = br#"{"path":"/tmp/secret.txt","rule_name":"generic-api-key","start":0,"end":41,"source":"fs","confidence_score":5}
{"type":"summary","source":"fs","status":"complete","elapsed_ms":1,"bytes_scanned":41,"findings_emitted":1,"errors":0,"throughput_mib_s":0.00}
"#;
        let root = Path::new("/tmp/secret.txt");
        let run = canonicalize_jsonl_events_with_roots(jsonl, &[root]).expect("canonicalize");
        assert_eq!(
            run.findings[0].path, "secret.txt",
            "exact root match should fall back to basename, not empty string"
        );
    }

    #[test]
    fn canonicalize_requires_commit_meta_for_git_findings() {
        let jsonl = br#"{"path":"a.txt","rule_name":"tok","start":1,"end":3,"source":"git","commit_id":9,"change_kind":"add","confidence_score":0}
{"type":"summary","source":"git","status":"complete","elapsed_ms":1,"bytes_scanned":1,"findings_emitted":1,"errors":0,"throughput_mib_s":2.50}
"#;
        let err = canonicalize_jsonl_events(jsonl).expect_err("missing commit_meta must error");
        match err {
            CanonicalizeError::MissingCommitMeta { commit_id } => assert_eq!(commit_id, 9),
            _ => panic!("unexpected error: {err}"),
        }
    }
}
