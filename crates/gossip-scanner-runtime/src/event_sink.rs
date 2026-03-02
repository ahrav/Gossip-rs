//! JSONL event sink for scanner runtime output.
//!
//! The CLI uses this sink to stream findings and diagnostics as newline-delimited
//! JSON records. The sink implements both scheduler core events and git-specific
//! events so the runtime can pass one sink type through all scan modes.

use std::io::{self, BufWriter, ErrorKind, Write};
use std::sync::Mutex;

use scanner_git::{GitEvent, GitEventOutput};
use scanner_scheduler::events::{CoreEvent, EventOutput};

/// JSONL event sink backed by a buffered writer.
pub struct JsonlEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
}

impl<W: Write + Send> JsonlEventSink<W> {
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

fn handle_io(result: io::Result<()>) -> io::Result<()> {
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
    use super::*;
    use scanner_scheduler::events::{CoreEvent, FindingEvent};
    use scanner_scheduler::source_kind::SourceKind;

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
        assert_eq!(
            line,
            "{\"path\":\"src/main.rs\",\"rule_name\":\"aws-access-key\",\"start\":10,\"end\":40,\"source\":\"fs\",\"confidence_score\":8}\n"
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
        assert_eq!(
            line,
            "{\"path\":\"config/.env\",\"rule_name\":\"generic-secret\",\"start\":0,\"end\":32,\"source\":\"git\",\"confidence_score\":-4,\"commit_id\":3,\"change_kind\":\"add\"}\n"
        );
    }
}
