//! Structured event surface for scanner-git.

use crate::identity_intern::{CommitIdentityIds, SENTINEL_ID};
use crate::json_write::{
    write_f64, write_i8, write_json_bytes, write_json_str, write_oid_hex, write_u64,
};
use crate::object_id::OidBytes;
pub use scanner_scheduler::events::{
    CoreEvent, DiagnosticEvent, EventOutput, FindingEvent, ProgressEvent, SummaryEvent,
};
use std::sync::Mutex;

/// Git commit metadata payload.
pub struct CommitMetaEvent {
    /// Commit-graph position (same value as `FindingEvent::commit_id`).
    pub commit_id: u32,
    /// Raw commit object ID (SHA-1 or SHA-256).
    pub commit_oid: OidBytes,
    /// Committer timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Optional interned identity IDs.
    pub identity: Option<CommitIdentityIds>,
}

/// Identity dictionary entry used by git identity interning.
pub struct IdentityDictionaryEvent<'a> {
    /// Interned numeric ID.
    pub id: u32,
    /// Raw interned bytes (not guaranteed UTF-8).
    pub value: &'a [u8],
}

/// Git-specific structured events.
pub enum GitEvent<'a> {
    /// Per-commit metadata emitted at most once for commits with findings.
    CommitMeta(CommitMetaEvent),
    /// Dictionary rows for interned identity strings.
    IdentityDictionary(IdentityDictionaryEvent<'a>),
}

/// Git extension sink layered over scheduler core events.
pub trait GitEventOutput: EventOutput {
    /// Emit a git-specific event.
    fn emit_git(&self, event: GitEvent<'_>);
}

/// Compatibility event enum preserved for git-scan internals/tests.
pub enum ScanEvent<'a> {
    /// Finding emitted from a scanned object.
    Finding(FindingEvent<'a>),
    /// Periodic progress signal for long-running scans.
    Progress(ProgressEvent),
    /// End-of-scan summary.
    Summary(SummaryEvent),
    /// Diagnostic message from scan/runtime plumbing.
    Diagnostic(DiagnosticEvent<'a>),
    /// Git commit metadata.
    CommitMeta(CommitMetaEvent),
    /// Git identity dictionary entry.
    IdentityDictionary(IdentityDictionaryEvent<'a>),
}

/// Compatibility sink trait preserved for git-scan internals/tests.
pub trait EventSink: Send + Sync {
    /// Emit one event.
    fn emit(&self, event: ScanEvent<'_>);
    /// Flush buffered output.
    fn flush(&self);
}

impl<T> EventSink for T
where
    T: GitEventOutput + ?Sized,
{
    fn emit(&self, event: ScanEvent<'_>) {
        match event {
            ScanEvent::Finding(f) => self.emit_core(CoreEvent::Finding(f)),
            ScanEvent::Progress(p) => self.emit_core(CoreEvent::Progress(p)),
            ScanEvent::Summary(s) => self.emit_core(CoreEvent::Summary(s)),
            ScanEvent::Diagnostic(d) => self.emit_core(CoreEvent::Diagnostic(d)),
            ScanEvent::CommitMeta(m) => self.emit_git(GitEvent::CommitMeta(m)),
            ScanEvent::IdentityDictionary(d) => self.emit_git(GitEvent::IdentityDictionary(d)),
        }
    }

    fn flush(&self) {
        EventOutput::flush(self);
    }
}

#[derive(Default)]
pub struct NullEventSink;

impl EventOutput for NullEventSink {
    #[inline]
    fn emit_core(&self, _event: CoreEvent<'_>) {}

    #[inline]
    fn flush(&self) {}
}

impl GitEventOutput for NullEventSink {
    #[inline]
    fn emit_git(&self, _event: GitEvent<'_>) {}
}

#[derive(Default)]
pub struct VecEventSink {
    encoded: Mutex<Vec<u8>>,
}

impl VecEventSink {
    #[inline]
    pub fn new() -> Self {
        Self {
            encoded: Mutex::new(Vec::new()),
        }
    }

    /// Drain all encoded lines accumulated so far.
    #[inline]
    pub fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.encoded.lock().expect("vec event sink mutex poisoned"))
    }
}

impl EventOutput for VecEventSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let mut line = Vec::with_capacity(256);
        match event {
            CoreEvent::Finding(f) => {
                line.extend_from_slice(b"{\"type\":\"finding\"");

                line.extend_from_slice(b",\"source\":");
                write_json_str(&mut line, f.source.as_str());

                line.extend_from_slice(b",\"path\":");
                write_json_bytes(&mut line, f.object_path);

                line.extend_from_slice(b",\"start\":");
                write_u64(&mut line, f.start);

                line.extend_from_slice(b",\"end\":");
                write_u64(&mut line, f.end);

                line.extend_from_slice(b",\"rule_id\":");
                write_u64(&mut line, u64::from(f.rule_id));

                line.extend_from_slice(b",\"rule\":");
                write_json_str(&mut line, f.rule_name);

                line.extend_from_slice(b",\"confidence_score\":");
                write_i8(&mut line, f.confidence_score);

                // norm_hash intentionally omitted — secret-derived digest must not appear in event logs.
                if let Some(commit_id) = f.commit_id {
                    line.extend_from_slice(b",\"commit_id\":");
                    write_u64(&mut line, u64::from(commit_id));
                }

                if let Some(change_kind) = f.change_kind {
                    line.extend_from_slice(b",\"change_kind\":");
                    write_json_str(&mut line, change_kind);
                }

                line.push(b'}');
            }
            CoreEvent::Diagnostic(d) => {
                line.extend_from_slice(b"{\"type\":\"diagnostic\"");

                line.extend_from_slice(b",\"level\":");
                write_json_str(&mut line, d.level);

                line.extend_from_slice(b",\"message\":");
                write_json_str(&mut line, d.message);

                line.push(b'}');
            }
            CoreEvent::Progress(p) => {
                line.extend_from_slice(b"{\"type\":\"progress\"");

                line.extend_from_slice(b",\"source\":");
                write_json_str(&mut line, p.source.as_str());

                line.extend_from_slice(b",\"stage\":");
                write_json_str(&mut line, p.stage);

                line.extend_from_slice(b",\"objects_scanned\":");
                write_u64(&mut line, p.objects_scanned);

                line.extend_from_slice(b",\"bytes_scanned\":");
                write_u64(&mut line, p.bytes_scanned);

                line.extend_from_slice(b",\"findings_emitted\":");
                write_u64(&mut line, p.findings_emitted);

                line.push(b'}');
            }
            CoreEvent::Summary(s) => {
                line.extend_from_slice(b"{\"type\":\"summary\"");

                line.extend_from_slice(b",\"source\":");
                write_json_str(&mut line, s.source.as_str());

                line.extend_from_slice(b",\"status\":");
                write_json_str(&mut line, s.status);

                line.extend_from_slice(b",\"elapsed_ms\":");
                write_u64(&mut line, s.elapsed_ms);

                line.extend_from_slice(b",\"bytes_scanned\":");
                write_u64(&mut line, s.bytes_scanned);

                line.extend_from_slice(b",\"findings_emitted\":");
                write_u64(&mut line, s.findings_emitted);

                line.extend_from_slice(b",\"errors\":");
                write_u64(&mut line, s.errors);

                line.extend_from_slice(b",\"throughput_mib_s\":");
                write_f64(&mut line, s.throughput_mib_s);

                line.push(b'}');
            }
        }

        line.push(b'\n');
        self.encoded
            .lock()
            .expect("vec event sink mutex poisoned")
            .extend_from_slice(&line);
    }

    #[inline]
    fn flush(&self) {}
}

impl GitEventOutput for VecEventSink {
    fn emit_git(&self, event: GitEvent<'_>) {
        let mut line = Vec::with_capacity(256);
        match event {
            GitEvent::CommitMeta(meta) => {
                line.extend_from_slice(b"{\"type\":\"commit_meta\"");

                line.extend_from_slice(b",\"commit_id\":");
                write_u64(&mut line, u64::from(meta.commit_id));

                line.extend_from_slice(b",\"oid\":");
                write_oid_hex(&mut line, &meta.commit_oid);

                line.extend_from_slice(b",\"timestamp\":");
                write_u64(&mut line, meta.timestamp);

                if let Some(ids) = meta.identity {
                    write_identity_field(&mut line, b"author_name_id", ids.author_name);
                    write_identity_field(&mut line, b"author_email_id", ids.author_email);
                    write_identity_field(&mut line, b"committer_name_id", ids.committer_name);
                    write_identity_field(&mut line, b"committer_email_id", ids.committer_email);
                }

                line.push(b'}');
            }
            GitEvent::IdentityDictionary(entry) => {
                line.extend_from_slice(b"{\"type\":\"identity_dictionary\"");

                line.extend_from_slice(b",\"id\":");
                write_u64(&mut line, u64::from(entry.id));

                line.extend_from_slice(b",\"value\":");
                write_json_bytes(&mut line, entry.value);

                line.push(b'}');
            }
        }

        line.push(b'\n');
        self.encoded
            .lock()
            .expect("vec event sink mutex poisoned")
            .extend_from_slice(&line);
    }
}

#[inline]
fn write_identity_field(line: &mut Vec<u8>, name: &[u8], id: u32) {
    if id != SENTINEL_ID {
        line.push(b',');
        line.push(b'"');
        line.extend_from_slice(name);
        line.extend_from_slice(b"\":");
        write_u64(line, u64::from(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_scheduler::source_kind::SourceKind;

    #[test]
    fn vec_event_sink_omits_norm_hash_in_json() {
        let sink = VecEventSink::new();
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: b"secret.txt",
            start: 10,
            end: 20,
            rule_id: 7,
            rule_name: "rule",
            norm_hash: [0xAB; 32],
            commit_id: Some(3),
            change_kind: Some("modify"),
            confidence_score: 2,
        }));

        let output = String::from_utf8(sink.take()).expect("valid utf-8 output");
        assert!(
            !output.contains("norm_hash"),
            "event JSON must omit norm_hash, got: {output}"
        );
    }
}
