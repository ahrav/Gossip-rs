//! Helpers for reading JSONL finding output emitted by integration test sinks.

/// Path attribution and start offset extracted from one finding event.
#[derive(Debug)]
pub(crate) struct FindingLine {
    pub(crate) path: String,
    pub(crate) start: u64,
}

/// Extract a JSON string value for a given key from a single JSON line.
///
/// This is a minimal parser that handles backslash-escaped quotes.
pub(crate) fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let bytes = rest.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        if bytes[end] == b'\\' {
            end += if end + 1 < bytes.len() { 2 } else { 1 };
        } else if bytes[end] == b'"' {
            return Some(rest[..end].to_string());
        } else {
            end += 1;
        }
    }
    None
}

/// Extract a JSON numeric value for a given key from a single JSON line.
pub(crate) fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Collect the `path` field from each finding event in a JSONL stream.
pub(crate) fn finding_paths(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| line.contains("\"type\":\"finding\""))
        .filter_map(|line| extract_json_string(line, "path"))
        .collect()
}

/// Parse JSONL finding lines into `(path, start)` pairs.
///
/// This is intentionally lossy: end offsets and rule names are ignored because
/// the tests only assert path attribution and the start position.
pub(crate) fn parse_findings(output: &str) -> Vec<FindingLine> {
    let mut out = Vec::new();
    for line in output.lines() {
        if !line.contains("\"type\":\"finding\"") {
            continue;
        }
        let path = extract_json_string(line, "path").unwrap_or_default();
        let start = extract_json_u64(line, "start").unwrap_or(0);
        out.push(FindingLine { path, start });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{extract_json_string, extract_json_u64};

    #[test]
    fn extract_json_string_accepts_whitespace_after_colon() {
        let json = r#"{"path": "src/main.rs"}"#;

        assert_eq!(
            extract_json_string(json, "path"),
            Some("src/main.rs".to_string())
        );
    }

    #[test]
    fn extract_json_string_never_panics_on_trailing_escape() {
        let json = "{\"path\":\"unterminated\\";

        let result = std::panic::catch_unwind(|| extract_json_string(json, "path"));

        assert!(result.is_ok());
    }

    #[test]
    fn extract_json_u64_accepts_whitespace_after_colon() {
        let json = r#"{"start": 42}"#;

        assert_eq!(extract_json_u64(json, "start"), Some(42));
    }

    #[test]
    fn extract_json_string_returns_none_for_unterminated_value() {
        let json = "{\"path\":\"unterminated";

        assert_eq!(extract_json_string(json, "path"), None);
    }
}
