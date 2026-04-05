//! JSONL event sink for scanner runtime output.
//!
//! The CLI uses this sink to stream findings and diagnostics as newline-delimited
//! JSON records. The sink implements both scheduler core events and git-specific
//! events so the runtime can pass one sink type through all scan modes.
//!
//! Encoding invariants:
//! - Exactly one JSON object is emitted per line.
//! - Finding records intentionally omit a `type` field for scanner-rs parity.
//! - `BrokenPipe` is treated as success to support piped CLI output.

use std::io::{self, BufWriter, ErrorKind, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use scanner_git::{GitEvent, GitEventOutput};
use scanner_scheduler::events::{CoreEvent, EventOutput};

/// JSONL event sink backed by a buffered writer.
pub struct JsonlEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
}

impl<W: Write + Send> JsonlEventSink<W> {
    /// Create a JSONL sink over `writer`.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(BufWriter::new(writer)),
        }
    }

    fn write_line(&self, encode: impl FnOnce(&mut Vec<u8>)) {
        let mut line = Vec::with_capacity(256);
        encode(&mut line);
        line.push(b'\n');

        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        let _ = handle_io(guard.write_all(&line));
    }
}

impl<W: Write + Send> EventOutput for JsonlEventSink<W> {
    fn emit_core(&self, event: CoreEvent<'_>) {
        self.write_line(|line| encode_core_event(event, line));
    }

    fn flush(&self) {
        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        let _ = handle_io(guard.flush());
    }
}

impl<W: Write + Send> GitEventOutput for JsonlEventSink<W> {
    fn emit_git(&self, event: GitEvent<'_>) {
        self.write_line(|line| encode_git_event(event, line));
    }
}

/// Human-readable text event sink.
pub struct TextEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    verbose: bool,
}

impl<W: Write + Send> TextEventSink<W> {
    /// Create a text sink over `writer`.
    #[must_use]
    pub fn new(writer: W, verbose: bool) -> Self {
        Self {
            writer: Mutex::new(BufWriter::new(writer)),
            verbose,
        }
    }
}

impl<W: Write + Send> EventOutput for TextEventSink<W> {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let mut line = Vec::with_capacity(256);
        match event {
            CoreEvent::Finding(finding) => {
                if self.verbose {
                    line.extend_from_slice(b"--- finding ---\n");
                    line.extend_from_slice(b"  rule:   ");
                    line.extend_from_slice(finding.rule_name.as_bytes());
                    line.push(b'\n');
                    line.extend_from_slice(b"  path:   ");
                    line.extend_from_slice(sanitize_path(finding.object_path).as_bytes());
                    line.push(b'\n');
                    line.extend_from_slice(b"  range:  ");
                    write_u64(&mut line, finding.start);
                    line.push(b'-');
                    write_u64(&mut line, finding.end);
                    line.push(b'\n');
                    line.extend_from_slice(b"  source: ");
                    line.extend_from_slice(finding.source.as_str().as_bytes());
                    line.push(b'\n');
                } else {
                    line.extend_from_slice(sanitize_path(finding.object_path).as_bytes());
                    line.push(b':');
                    write_u64(&mut line, finding.start);
                    line.push(b'-');
                    write_u64(&mut line, finding.end);
                    line.extend_from_slice(b"  ");
                    line.extend_from_slice(finding.rule_name.as_bytes());
                    line.extend_from_slice(b"  (");
                    line.extend_from_slice(finding.source.as_str().as_bytes());
                    line.extend_from_slice(b")\n");
                }
            }
            CoreEvent::Progress(progress) => {
                if self.verbose {
                    line.extend_from_slice(b"[progress] ");
                    line.extend_from_slice(progress.source.as_str().as_bytes());
                    line.extend_from_slice(b" | ");
                    line.extend_from_slice(progress.stage.as_bytes());
                    line.extend_from_slice(b" | objects=");
                    write_u64(&mut line, progress.objects_scanned);
                    line.extend_from_slice(b" bytes=");
                    write_u64(&mut line, progress.bytes_scanned);
                    line.extend_from_slice(b" findings=");
                    write_u64(&mut line, progress.findings_emitted);
                    line.push(b'\n');
                }
            }
            CoreEvent::Summary(summary) => {
                line.extend_from_slice(b"[summary] ");
                line.extend_from_slice(summary.source.as_str().as_bytes());
                line.extend_from_slice(b" | ");
                line.extend_from_slice(summary.status.as_bytes());
                line.extend_from_slice(b" | elapsed=");
                write_u64(&mut line, summary.elapsed_ms);
                line.extend_from_slice(b"ms bytes=");
                write_u64(&mut line, summary.bytes_scanned);
                line.extend_from_slice(b" findings=");
                write_u64(&mut line, summary.findings_emitted);
                line.extend_from_slice(b" errors=");
                write_u64(&mut line, summary.errors);
                line.extend_from_slice(b" throughput=");
                write_f64(&mut line, summary.throughput_mib_s);
                line.extend_from_slice(b" MiB/s\n");
            }
            CoreEvent::Diagnostic(diagnostic) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "[{}] {}",
                    diagnostic.level,
                    diagnostic.message
                );
            }
        }
        if line.is_empty() {
            return;
        }
        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        let _ = handle_io(guard.write_all(&line));
    }

    fn flush(&self) {
        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        let _ = handle_io(guard.flush());
    }
}

impl<W: Write + Send> GitEventOutput for TextEventSink<W> {
    fn emit_git(&self, _event: GitEvent<'_>) {}
}

/// Streaming JSON array sink.
pub struct JsonEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    first: AtomicBool,
    closed: AtomicBool,
}

impl<W: Write + Send> JsonEventSink<W> {
    /// Create a JSON sink over `writer`.
    #[must_use]
    pub fn new(mut writer: W) -> Self {
        let _ = writer.write_all(b"[");
        Self {
            writer: Mutex::new(BufWriter::new(writer)),
            first: AtomicBool::new(true),
            closed: AtomicBool::new(false),
        }
    }

    fn write_element(&self, encode: impl FnOnce(&mut Vec<u8>)) {
        let mut element = Vec::with_capacity(256);
        encode(&mut element);

        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        let sep: &[u8] = if self.first.swap(false, Ordering::Relaxed) {
            b"\n"
        } else {
            b",\n"
        };
        if handle_io(guard.write_all(sep)).is_err() {
            return;
        }
        let _ = handle_io(guard.write_all(&element));
    }
}

impl<W: Write + Send> EventOutput for JsonEventSink<W> {
    fn emit_core(&self, event: CoreEvent<'_>) {
        self.write_element(|line| encode_core_event(event, line));
    }

    fn flush(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        if handle_io(guard.write_all(b"\n]\n")).is_err() {
            return;
        }
        let _ = handle_io(guard.flush());
    }
}

impl<W: Write + Send> GitEventOutput for JsonEventSink<W> {
    fn emit_git(&self, event: GitEvent<'_>) {
        self.write_element(|line| encode_git_event(event, line));
    }
}

/// SARIF 2.1.0 sink.
pub struct SarifEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    first: AtomicBool,
    closed: AtomicBool,
}

impl<W: Write + Send> SarifEventSink<W> {
    /// Create a SARIF sink over `writer`.
    #[must_use]
    pub fn new(mut writer: W) -> Self {
        let version = env!("CARGO_PKG_VERSION");
        let _ = write!(
            writer,
            "{{\"version\":\"2.1.0\",\"$schema\":\"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json\",\
             \"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"scanner-rs\",\
             \"version\":\"{version}\"}}}},\"results\":["
        );
        Self {
            writer: Mutex::new(BufWriter::new(writer)),
            first: AtomicBool::new(true),
            closed: AtomicBool::new(false),
        }
    }
}

impl<W: Write + Send> EventOutput for SarifEventSink<W> {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let finding = match event {
            CoreEvent::Finding(finding) => finding,
            _ => return,
        };

        let mut result = Vec::with_capacity(256);
        encode_sarif_result(&finding, &mut result);

        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        if !self.first.swap(false, Ordering::Relaxed) && handle_io(guard.write_all(b",")).is_err() {
            return;
        }
        let _ = handle_io(guard.write_all(&result));
    }

    fn flush(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        let Ok(mut guard) = self.writer.lock() else {
            return;
        };
        if handle_io(guard.write_all(b"]}]}\n")).is_err() {
            return;
        }
        let _ = handle_io(guard.flush());
    }
}

impl<W: Write + Send> GitEventOutput for SarifEventSink<W> {
    fn emit_git(&self, _event: GitEvent<'_>) {}
}

fn handle_io(result: io::Result<()>) -> io::Result<()> {
    // CLI parity: downstream pipe closures are non-fatal.
    if let Err(error) = result {
        if error.kind() == ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn encode_core_event(event: CoreEvent<'_>, line: &mut Vec<u8>) {
    match event {
        CoreEvent::Finding(finding) => {
            // Keep the record shape aligned with scanner-rs golden fixtures.
            line.push(b'{');
            push_key(line, b"path");
            write_json_bytes(line, finding.object_path);

            line.push(b',');
            push_key(line, b"rule_name");
            write_json_str(line, finding.rule_name);

            line.push(b',');
            push_key(line, b"start");
            write_u64(line, finding.start);

            line.push(b',');
            push_key(line, b"end");
            write_u64(line, finding.end);

            line.push(b',');
            push_key(line, b"source");
            write_json_str(line, finding.source.as_str());

            line.push(b',');
            push_key(line, b"confidence_score");
            write_i8(line, finding.confidence_score);

            // norm_hash intentionally omitted — secret-derived digest must not appear in event logs.
            if let Some(commit_id) = finding.commit_id {
                line.push(b',');
                push_key(line, b"commit_id");
                write_u64(line, u64::from(commit_id));
            }

            if let Some(change_kind) = finding.change_kind {
                line.push(b',');
                push_key(line, b"change_kind");
                write_json_str(line, change_kind);
            }

            line.push(b'}');
        }
        CoreEvent::Progress(progress) => {
            line.extend_from_slice(b"{\"type\":\"progress\"");
            line.push(b',');
            push_key(line, b"source");
            write_json_str(line, progress.source.as_str());
            line.push(b',');
            push_key(line, b"stage");
            write_json_str(line, progress.stage);
            line.push(b',');
            push_key(line, b"objects_scanned");
            write_u64(line, progress.objects_scanned);
            line.push(b',');
            push_key(line, b"bytes_scanned");
            write_u64(line, progress.bytes_scanned);
            line.push(b',');
            push_key(line, b"findings_emitted");
            write_u64(line, progress.findings_emitted);
            line.push(b'}');
        }
        CoreEvent::Summary(summary) => {
            line.extend_from_slice(b"{\"type\":\"summary\"");
            line.push(b',');
            push_key(line, b"source");
            write_json_str(line, summary.source.as_str());
            line.push(b',');
            push_key(line, b"status");
            write_json_str(line, summary.status);
            line.push(b',');
            push_key(line, b"elapsed_ms");
            write_u64(line, summary.elapsed_ms);
            line.push(b',');
            push_key(line, b"bytes_scanned");
            write_u64(line, summary.bytes_scanned);
            line.push(b',');
            push_key(line, b"findings_emitted");
            write_u64(line, summary.findings_emitted);
            line.push(b',');
            push_key(line, b"errors");
            write_u64(line, summary.errors);
            line.push(b',');
            push_key(line, b"throughput_mib_s");
            write_f64(line, summary.throughput_mib_s);
            line.push(b'}');
        }
        CoreEvent::Diagnostic(diagnostic) => {
            line.extend_from_slice(b"{\"type\":\"diagnostic\"");
            line.push(b',');
            push_key(line, b"level");
            write_json_str(line, diagnostic.level);
            line.push(b',');
            push_key(line, b"message");
            write_json_str(line, diagnostic.message);
            line.push(b'}');
        }
    }
}

fn encode_git_event(event: GitEvent<'_>, line: &mut Vec<u8>) {
    match event {
        GitEvent::CommitMeta(meta) => {
            line.extend_from_slice(b"{\"type\":\"commit_meta\"");

            line.push(b',');
            push_key(line, b"commit_id");
            write_u64(line, u64::from(meta.commit_id));

            line.push(b',');
            push_key(line, b"oid");
            write_oid_hex(line, &meta.commit_oid);

            line.push(b',');
            push_key(line, b"timestamp");
            write_u64(line, meta.timestamp);

            if let Some(identity) = meta.identity {
                if identity.author_name != scanner_git::SENTINEL_ID {
                    line.push(b',');
                    push_key(line, b"author_name_id");
                    write_u64(line, u64::from(identity.author_name));
                }
                if identity.author_email != scanner_git::SENTINEL_ID {
                    line.push(b',');
                    push_key(line, b"author_email_id");
                    write_u64(line, u64::from(identity.author_email));
                }
                if identity.committer_name != scanner_git::SENTINEL_ID {
                    line.push(b',');
                    push_key(line, b"committer_name_id");
                    write_u64(line, u64::from(identity.committer_name));
                }
                if identity.committer_email != scanner_git::SENTINEL_ID {
                    line.push(b',');
                    push_key(line, b"committer_email_id");
                    write_u64(line, u64::from(identity.committer_email));
                }
            }

            line.push(b'}');
        }
        GitEvent::IdentityDictionary(identity) => {
            line.extend_from_slice(b"{\"type\":\"identity_dictionary\"");
            line.push(b',');
            push_key(line, b"id");
            write_u64(line, u64::from(identity.id));
            line.push(b',');
            push_key(line, b"value");
            write_json_bytes(line, identity.value);
            line.push(b'}');
        }
    }
}

fn encode_sarif_result(finding: &scanner_scheduler::events::FindingEvent<'_>, line: &mut Vec<u8>) {
    line.extend_from_slice(b"{\"ruleId\":");
    write_json_str(line, finding.rule_name);
    line.extend_from_slice(b",\"message\":{\"text\":");
    let message = format!("Secret matched rule {}", finding.rule_name);
    write_json_str(line, &message);
    line.extend_from_slice(
        b"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":",
    );
    write_json_bytes(line, finding.object_path);
    line.extend_from_slice(b"},\"region\":{\"byteOffset\":");
    write_u64(line, finding.start);
    line.extend_from_slice(b",\"byteLength\":");
    write_u64(line, finding.end.saturating_sub(finding.start));
    line.extend_from_slice(b"}}}],\"rank\":");
    let rank = ((finding.confidence_score.max(0) as f64) / 10.0) * 100.0;
    write_f64(line, rank.min(100.0));
    line.push(b'}');
}

fn sanitize_path(path: &[u8]) -> String {
    let text = String::from_utf8_lossy(path);
    if !text.chars().any(char::is_control) {
        return text.into_owned();
    }
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            escaped.push_str(&format!("\\u{{{:04x}}}", ch as u32));
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

fn push_key(line: &mut Vec<u8>, key: &[u8]) {
    line.push(b'"');
    line.extend_from_slice(key);
    line.extend_from_slice(b"\":");
}

fn write_i8(line: &mut Vec<u8>, value: i8) {
    line.extend_from_slice(value.to_string().as_bytes());
}

fn write_u64(line: &mut Vec<u8>, value: u64) {
    line.extend_from_slice(value.to_string().as_bytes());
}

fn write_f64(line: &mut Vec<u8>, value: f64) {
    // Summary throughput is rendered with fixed precision for stable fixtures.
    let rendered = if value.is_finite() {
        format!("{value:.2}")
    } else {
        "0.00".to_owned()
    };
    line.extend_from_slice(rendered.as_bytes());
}

fn write_oid_hex(line: &mut Vec<u8>, oid: &scanner_git::OidBytes) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    line.push(b'"');
    for byte in oid.as_slice() {
        line.push(HEX[(byte >> 4) as usize]);
        line.push(HEX[(byte & 0x0f) as usize]);
    }
    line.push(b'"');
}

fn write_json_str(line: &mut Vec<u8>, value: &str) {
    write_json_bytes(line, value.as_bytes());
}

fn write_json_bytes(line: &mut Vec<u8>, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    line.push(b'"');
    for &byte in value {
        match byte {
            b'"' => line.extend_from_slice(b"\\\""),
            b'\\' => line.extend_from_slice(b"\\\\"),
            b'\n' => line.extend_from_slice(b"\\n"),
            b'\r' => line.extend_from_slice(b"\\r"),
            b'\t' => line.extend_from_slice(b"\\t"),
            0x08 => line.extend_from_slice(b"\\b"),
            0x0c => line.extend_from_slice(b"\\f"),
            0x20..=0x7e => line.push(byte),
            _ => {
                line.extend_from_slice(b"\\u00");
                line.push(HEX[(byte >> 4) as usize]);
                line.push(HEX[(byte & 0x0f) as usize]);
            }
        }
    }
    line.push(b'"');
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use scanner_scheduler::events::{CoreEvent, FindingEvent};
    use scanner_scheduler::source_kind::SourceKind;

    fn load_event_golden(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("parity")
            .join("golden")
            .join("events")
            .join(name);
        String::from_utf8(fs::read(path).expect("event golden fixture"))
            .expect("event golden fixture must be utf8")
    }

    #[test]
    fn finding_record_is_encoded_without_norm_hash_or_rule_id() {
        let sink = JsonlEventSink::new(Vec::<u8>::new());
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 10,
            end: 40,
            rule_id: 7,
            rule_name: "aws-access-key",
            norm_hash: Some([0xAB; 32]),
            commit_id: None,
            change_kind: None,
            confidence_score: 8,
        }));
        sink.flush();

        let output = sink
            .writer
            .into_inner()
            .expect("lock not poisoned")
            .into_inner()
            .expect("vec writer");
        let line = String::from_utf8(output).expect("valid utf8 output");
        assert_eq!(line, load_event_golden("finding_fs.jsonl"));
        assert!(
            !line.contains("norm_hash"),
            "encoded event must omit norm_hash, got: {line}"
        );
        assert!(
            !line.contains("rule_id"),
            "encoded event must omit rule_id, got: {line}"
        );
    }

    #[test]
    fn finding_record_includes_git_fields_when_present() {
        let sink = JsonlEventSink::new(Vec::<u8>::new());
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: b"config/.env",
            start: 0,
            end: 32,
            rule_id: 9,
            rule_name: "generic-secret",
            norm_hash: Some([0xCD; 32]),
            commit_id: Some(3),
            change_kind: Some("add"),
            confidence_score: -4,
        }));
        sink.flush();

        let output = sink
            .writer
            .into_inner()
            .expect("lock not poisoned")
            .into_inner()
            .expect("vec writer");
        let line = String::from_utf8(output).expect("valid utf8 output");
        assert_eq!(line, load_event_golden("finding_git.jsonl"));
        assert!(
            !line.contains("norm_hash"),
            "encoded git event must omit norm_hash, got: {line}"
        );
        assert!(
            !line.contains("rule_id"),
            "encoded git event must omit rule_id, got: {line}"
        );
    }

    #[test]
    fn text_sink_writes_compact_finding_lines() {
        let sink = TextEventSink::new(Vec::<u8>::new(), false);
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 5,
            end: 12,
            rule_id: 1,
            rule_name: "rule",
            norm_hash: Some([0x11; 32]),
            commit_id: None,
            change_kind: None,
            confidence_score: 0,
        }));
        sink.flush();

        let output = sink
            .writer
            .into_inner()
            .expect("lock not poisoned")
            .into_inner()
            .expect("vec writer");
        let text = String::from_utf8(output).expect("valid utf8 output");
        assert_eq!(text, "src/main.rs:5-12  rule  (fs)\n");
    }

    #[test]
    fn json_sink_emits_valid_json_array() {
        let sink = JsonEventSink::new(Vec::<u8>::new());
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 1,
            end: 2,
            rule_id: 1,
            rule_name: "rule",
            norm_hash: None,
            commit_id: None,
            change_kind: None,
            confidence_score: 3,
        }));
        sink.flush();

        let output = sink
            .writer
            .into_inner()
            .expect("lock not poisoned")
            .into_inner()
            .expect("vec writer");
        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("valid JSON array payload");
        assert!(value.as_array().is_some());
    }

    #[test]
    fn json_sink_double_flush_produces_valid_json() {
        let sink = JsonEventSink::new(Vec::<u8>::new());
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 1,
            end: 2,
            rule_id: 1,
            rule_name: "rule",
            norm_hash: None,
            commit_id: None,
            change_kind: None,
            confidence_score: 3,
        }));
        // Simulate the double-flush that occurs in production:
        // forward_events() flushes when the channel closes, then cli::run()
        // calls sink.flush() again.
        sink.flush();
        sink.flush();

        let output = sink
            .writer
            .into_inner()
            .expect("lock not poisoned")
            .into_inner()
            .expect("vec writer");
        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("double flush must still produce valid JSON");
        assert!(value.as_array().is_some());
    }

    #[test]
    fn sarif_sink_emits_valid_document() {
        let sink = SarifEventSink::new(Vec::<u8>::new());
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 10,
            end: 20,
            rule_id: 2,
            rule_name: "aws-access-key",
            norm_hash: None,
            commit_id: None,
            change_kind: None,
            confidence_score: 7,
        }));
        sink.flush();

        let output = sink
            .writer
            .into_inner()
            .expect("lock not poisoned")
            .into_inner()
            .expect("vec writer");
        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("valid SARIF JSON payload");
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(
            value["runs"][0]["results"][0]["ruleId"],
            serde_json::Value::String("aws-access-key".to_owned())
        );
    }

    #[test]
    fn sarif_sink_double_flush_produces_valid_document() {
        let sink = SarifEventSink::new(Vec::<u8>::new());
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 10,
            end: 20,
            rule_id: 2,
            rule_name: "aws-access-key",
            norm_hash: None,
            commit_id: None,
            change_kind: None,
            confidence_score: 7,
        }));
        // Simulate double-flush from forward_events + cli::run.
        sink.flush();
        sink.flush();

        let output = sink
            .writer
            .into_inner()
            .expect("lock not poisoned")
            .into_inner()
            .expect("vec writer");
        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("double flush must still produce valid SARIF");
        assert_eq!(value["version"], "2.1.0");
    }
}
