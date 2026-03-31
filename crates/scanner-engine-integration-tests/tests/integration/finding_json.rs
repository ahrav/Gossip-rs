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
    let needle = format!("\"{}\":\"", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let bytes = rest.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        if bytes[end] == b'\\' {
            end += 2;
        } else if bytes[end] == b'"' {
            break;
        } else {
            end += 1;
        }
    }
    Some(rest[..end].to_string())
}

/// Extract a JSON numeric value for a given key from a single JSON line.
pub(crate) fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
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
