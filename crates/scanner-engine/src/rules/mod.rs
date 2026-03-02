//! Rule loading for the scanner.
//!
//! Rules can be loaded from an external YAML file at runtime, or from the
//! built-in set embedded via `include_str!`. The YAML schema mirrors `RuleSpec`
//! fields and uses the same `build_regex()` + `assert_valid()` validation.
//!
//! # Invariants
//!
//! - Runtime file loading always returns structured `RulesError` values for
//!   parse/validation failures.
//! - Built-in rules are parsed/validated lazily on first use via `OnceLock`,
//!   then cloned from cache; invalid embedded YAML is treated as a programming
//!   error and panics.
//! - Regex compilation uses progressive size tiers so one complex rule does not
//!   require raising memory limits globally.

pub(crate) mod yaml;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::api::RuleSpec;
use regex::bytes::Regex;

/// Progressive regex size limits (bytes) to tolerate large DFAs on complex rules.
///
/// We retry compilation on `CompiledTooBig` so a single oversized rule does not
/// require globally lifting size limits for all patterns.
const REGEX_SIZE_LIMITS: &[usize] = &[32 * 1024 * 1024, 128 * 1024 * 1024, 512 * 1024 * 1024];

/// Build a bytes regex with increasing size limits.
///
/// This retries only `CompiledTooBig` failures at higher limits; all other
/// regex errors return immediately.
///
/// Returns an error if the pattern is invalid or still exceeds the largest
/// configured limit.
pub(crate) fn build_regex(pattern: &str) -> Result<Regex, String> {
    for &limit in REGEX_SIZE_LIMITS {
        let mut builder = regex::bytes::RegexBuilder::new(pattern);
        builder.unicode(false);
        builder.size_limit(limit);
        builder.dfa_size_limit(limit);
        match builder.build() {
            Ok(re) => return Ok(re),
            Err(regex::Error::CompiledTooBig(_)) => {
                eprintln!("note: regex exceeded {limit} byte compile limit, retrying at next tier");
                continue;
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    Err(format!(
        "regex compiled too big even at {} bytes",
        REGEX_SIZE_LIMITS[REGEX_SIZE_LIMITS.len() - 1]
    ))
}

/// Errors that can occur when loading rules from an external file.
#[derive(Debug)]
pub(crate) enum RulesError {
    /// I/O error reading the rules file.
    Io(std::io::Error),
    /// YAML parsing error.
    Yaml(serde_norway::Error),
    /// Regex compilation failure for a specific rule.
    Regex {
        rule_name: String,
        pattern: String,
        error: String,
    },
    /// Rule validation failure (e.g., invalid invariants).
    Validation { rule_name: String, message: String },
    /// Offline validation configuration error (unknown type, missing params).
    OfflineValidation { rule_name: String, message: String },
    /// The rules file contained no rules.
    NoRules,
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulesError::Io(e) => write!(f, "I/O error: {e}"),
            RulesError::Yaml(e) => write!(f, "YAML parse error: {e}"),
            RulesError::Regex {
                rule_name,
                pattern,
                error,
            } => write!(
                f,
                "regex error in rule '{rule_name}': {error} (pattern: {pattern})"
            ),
            RulesError::Validation { rule_name, message } => {
                write!(f, "validation error in rule '{rule_name}': {message}")
            }
            RulesError::OfflineValidation { rule_name, message } => {
                write!(
                    f,
                    "offline_validation error in rule '{rule_name}': {message}"
                )
            }
            RulesError::NoRules => write!(f, "rules file contains no rules"),
        }
    }
}

impl std::error::Error for RulesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RulesError::Io(e) => Some(e),
            RulesError::Yaml(e) => Some(e),
            _ => None,
        }
    }
}

/// Read rule YAML text from `path`.
///
/// This is separated from parsing so callers can compute provenance metadata
/// (for example, content hashes) and then parse exactly the same bytes.
pub(crate) fn read_rules_text(path: &Path) -> Result<String, RulesError> {
    let content = std::fs::read_to_string(path).map_err(RulesError::Io)?;
    Ok(content)
}

/// Load and validate rules from a YAML file.
///
/// Test-only convenience wrapper around [`read_rules_text`] plus
/// [`load_rules_from_content`].
#[cfg(test)]
pub(crate) fn load_rules(path: &Path) -> Result<Vec<RuleSpec>, RulesError> {
    let content = read_rules_text(path)?;
    load_rules_from_content(&content)
}

/// Parse and validate rules from YAML content already in memory.
///
/// This is used by callers that need to hash/log the exact bytes first, then
/// parse and validate those same bytes without re-reading from disk.
pub(crate) fn load_rules_from_content(content: &str) -> Result<Vec<RuleSpec>, RulesError> {
    let rules = yaml::parse_yaml_rules(content)?;
    if rules.is_empty() {
        return Err(RulesError::NoRules);
    }

    // Validate each rule, catching assertion panics from assert_valid().
    // Only string-typed panics (from assert!/panic! macros) are treated as
    // validation errors. Other panic types (OOM, stack overflow, etc.) are
    // re-raised because they are not validation failures.
    for rule in &rules {
        let name = rule.name.to_string();
        // SAFETY: AssertUnwindSafe is sound here — assert_valid() performs
        // read-only invariant checks on rule fields and does not mutate state.
        // We catch panics to convert validation failures into structured
        // RulesError values instead of crashing on user-supplied rule files.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rule.assert_valid();
        }));
        if let Err(payload) = result {
            let message = if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                // Not an assertion failure — re-raise the original panic.
                std::panic::resume_unwind(payload);
            };
            return Err(RulesError::Validation {
                rule_name: name,
                message,
            });
        }
    }

    Ok(rules)
}

/// Returns the default rules file path next to the current executable.
///
/// Returns `None` if the executable path cannot be determined (e.g., `/proc`
/// not mounted in containers, or the binary has no parent directory).
/// The returned path is a candidate location and may not exist.
///
/// Only the executable-adjacent location is checked. The current working
/// directory is intentionally excluded because this tool scans untrusted
/// repositories — loading a `default_rules.yaml` planted inside a repo
/// would let an attacker suppress detections or crash the scanner.
pub(crate) fn default_rules_path() -> Option<PathBuf> {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warning: cannot determine executable path: {e}");
            return None;
        }
    };
    Some(exe.parent()?.join("default_rules.yaml"))
}

/// The built-in rule set, embedded from `default_rules.yaml` at compile time.
const BUILTIN_RULES_YAML: &str = include_str!("../../default_rules.yaml");

/// Deterministic hasher for rule-content provenance fingerprints.
///
/// Seeds are fixed to preserve existing startup hash behavior.
const RULE_CONTENT_HASHER: ahash::RandomState = ahash::RandomState::with_seeds(
    0x524C_5348_3031,
    0xA341_6F5D_19B2_CC93,
    0x9E37_79B9_7F4A_7C15,
    0xD1B5_4A32_D192_ED03,
);

/// Hash arbitrary rule content bytes into a deterministic 64-bit fingerprint.
///
/// This is a non-cryptographic hash intended for provenance logs.
#[inline]
pub(crate) fn rules_content_hash64(bytes: &[u8]) -> u64 {
    RULE_CONTENT_HASHER.hash_one(bytes)
}

/// Hash the built-in rule YAML into a deterministic 64-bit fingerprint.
///
/// Suitable for startup provenance logs when using the compile-time fallback.
#[inline]
pub(crate) fn builtin_rules_hash64() -> u64 {
    rules_content_hash64(BUILTIN_RULES_YAML.as_bytes())
}

/// Parse and return the built-in rule set.
///
/// This replaces the old `gitleaks_rules()` function. Rules are parsed and
/// compiled once (via `OnceLock`) then cloned on subsequent calls, so the
/// `Box::leak` allocations in the YAML parser happen at most once.
///
/// Panics if embedded YAML is invalid or empty, because that indicates a
/// build-time packaging/programming error, not runtime user input.
pub(crate) fn builtin_rules() -> Vec<RuleSpec> {
    static BUILTIN: OnceLock<Vec<RuleSpec>> = OnceLock::new();
    BUILTIN
        .get_or_init(|| {
            let rules = yaml::parse_yaml_rules(BUILTIN_RULES_YAML)
                .expect("built-in rules YAML must be valid");
            assert!(
                !rules.is_empty(),
                "built-in rules YAML must contain at least one rule"
            );
            rules
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_rules_valid_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"rules:
  - name: "test-rule"
    regex: 'tok_[a-z0-9]{{8}}'
    anchors: ["tok_"]
    radius: 64
"#
        )
        .unwrap();
        let rules = load_rules(f.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test-rule");
    }

    #[test]
    fn load_rules_empty_file_returns_no_rules() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "rules: []").unwrap();
        match load_rules(f.path()) {
            Err(RulesError::NoRules) => {}
            other => panic!("expected NoRules, got: {other:?}"),
        }
    }

    #[test]
    fn load_rules_nonexistent_path_returns_io_error() {
        match load_rules(Path::new("/nonexistent/rules.yaml")) {
            Err(RulesError::Io(_)) => {}
            other => panic!("expected Io error, got: {other:?}"),
        }
    }

    #[test]
    fn load_rules_validation_failure_returns_validation_error() {
        // entropy with min_len > max_len triggers assert_valid() panic.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"rules:
  - name: "bad-entropy"
    regex: 'tok_[a-z0-9]{{8}}'
    anchors: ["tok_"]
    radius: 64
    entropy:
      min_bits_per_byte: 3.5
      min_len: 100
      max_len: 10
"#
        )
        .unwrap();
        match load_rules(f.path()) {
            Err(RulesError::Validation { rule_name, .. }) => {
                assert_eq!(rule_name, "bad-entropy");
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn rules_error_display_formats() {
        let io_err = RulesError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(io_err.to_string().contains("I/O error"));

        let no_rules = RulesError::NoRules;
        assert!(no_rules.to_string().contains("no rules"));

        let regex_err = RulesError::Regex {
            rule_name: "r1".into(),
            pattern: "[bad".into(),
            error: "unclosed".into(),
        };
        let msg = regex_err.to_string();
        assert!(msg.contains("r1") && msg.contains("unclosed"));

        let val_err = RulesError::Validation {
            rule_name: "r2".into(),
            message: "min > max".into(),
        };
        assert!(val_err.to_string().contains("r2"));
    }

    #[test]
    fn rules_error_source_chains() {
        use std::error::Error;

        let io_err = RulesError::Io(std::io::Error::other("test"));
        assert!(io_err.source().is_some());

        let no_rules = RulesError::NoRules;
        assert!(no_rules.source().is_none());

        let regex_err = RulesError::Regex {
            rule_name: String::new(),
            pattern: String::new(),
            error: String::new(),
        };
        assert!(regex_err.source().is_none());
    }

    #[test]
    fn build_regex_valid_pattern() {
        assert!(build_regex(r"[a-z]+").is_ok());
    }

    #[test]
    fn build_regex_invalid_pattern() {
        assert!(build_regex(r"[unclosed").is_err());
    }

    #[test]
    fn rules_content_hash64_is_stable_and_formats_as_u64_hex() {
        let h1 = rules_content_hash64(b"rules: []\n");
        let h2 = rules_content_hash64(b"rules: []\n");
        let h3 = rules_content_hash64(b"rules:\n- name: x\n");
        assert_eq!(h1, h2, "same bytes should hash identically");
        assert_ne!(h1, h3, "different bytes should generally hash differently");
        assert_eq!(
            format!("{h1:016x}").len(),
            16,
            "u64 fingerprint should format as 16 hex chars"
        );
    }

    #[test]
    fn builtin_rules_hash64_matches_builtin_yaml_hash() {
        assert_eq!(
            builtin_rules_hash64(),
            rules_content_hash64(BUILTIN_RULES_YAML.as_bytes())
        );
    }
}
