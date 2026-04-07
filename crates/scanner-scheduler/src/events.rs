//! Structured event types and sinks for scanner scheduler output.
//!
//! `CoreEvent` covers git-free scheduler events emitted by all scan paths.
//! `GitEvent` carries git-specific payloads and is only emitted by git-aware
//! call sites. Sinks that need full fidelity can implement both traits.

use crate::json_write::{write_f64, write_i8, write_json_bytes, write_json_str, write_u64};
use crate::source_kind::SourceKind;
use std::fmt;
use std::sync::Mutex;

/// Wire-encoded length of a blob OID: 1 byte length prefix + 32 bytes
/// zero-padded payload. Must match `OidBytes::WIRE_LEN` in `scanner-git`.
pub const BLOB_OID_WIRE_LEN: usize = 33;

/// Scheduler event emitted during a scan run.
///
/// Covers finding reports, progress ticks, end-of-scan summaries, and
/// diagnostic messages. Git-specific payloads live in [`GitEvent`].
pub enum CoreEvent<'a> {
    /// Finding emitted from a scanned object.
    Finding(FindingEvent<'a>),
    /// Periodic progress signal for long-running scans.
    Progress(ProgressEvent),
    /// End-of-scan summary.
    Summary(SummaryEvent),
    /// Diagnostic message from scan/runtime plumbing.
    Diagnostic(DiagnosticEvent<'a>),
}

/// Structured finding payload written by scheduler event sinks.
///
/// `start` and `end` carry blob-absolute root-hint coordinates in
/// root-file coordinates. For raw (non-transform) findings these typically
/// coincide with the exact match bounds. On derived paths they remain the
/// engine's best available root hint and may be broader than the
/// transformed match span.
///
/// Both scan paths populate them from the engine's
/// `FindingRec::root_hint_start` and `root_hint_end`. Event sinks surface
/// these offsets directly, and persistence identity derivation consumes
/// the same coordinates.
pub struct FindingEvent<'a> {
    /// Source family that emitted this finding.
    pub source: SourceKind,
    /// Source-relative object path for the scanned payload.
    pub object_path: &'a [u8],
    /// Inclusive blob-absolute byte offset marking the start of the finding.
    pub start: u64,
    /// Exclusive blob-absolute byte offset marking the end of the finding.
    pub end: u64,
    /// Numeric identifier of the matching detection rule.
    pub rule_id: u32,
    /// Human-readable rule name resolved from `rule_id`.
    pub rule_name: &'a str,
    /// Normalized content hash for deduplication and persistence identity.
    ///
    /// The digest is always present on the scheduler event surface so runtime
    /// sinks can derive durable finding identity without a parallel side
    /// channel.
    pub norm_hash: [u8; 32],
    /// Encoded Git blob object ID for the scanned payload.
    ///
    /// `None` means the finding did not come from the Git scan path. When
    /// present, byte 0 stores the raw OID length (20 for SHA-1, 32 for
    /// SHA-256) and bytes 1..=32 store the zero-padded raw OID bytes.
    pub blob_oid: Option<[u8; BLOB_OID_WIRE_LEN]>,
    /// Commit-graph position for Git findings.
    pub commit_id: Option<u32>,
    /// Git diff classification associated with the finding.
    pub change_kind: Option<&'a str>,
    /// Additive confidence score from gate signals.
    pub confidence_score: i8,
}

/// Debug-format wrapper that prints `[redacted]` for secret-derived digests.
pub struct RedactedNormHash;

impl fmt::Debug for RedactedNormHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Debug for FindingEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FindingEvent")
            .field("source", &self.source)
            .field("object_path", &self.object_path)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("rule_id", &self.rule_id)
            .field("rule_name", &self.rule_name)
            // Secret-derived digests are redacted to keep debug output safe.
            .field("norm_hash", &RedactedNormHash)
            .field("blob_oid", &self.blob_oid)
            .field("commit_id", &self.commit_id)
            .field("change_kind", &self.change_kind)
            .field("confidence_score", &self.confidence_score)
            .finish()
    }
}

/// Scheduler progress counters.
pub struct ProgressEvent {
    pub source: SourceKind,
    pub stage: &'static str,
    pub objects_scanned: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
}

/// End-of-run summary counters.
pub struct SummaryEvent {
    pub source: SourceKind,
    pub status: &'static str,
    pub elapsed_ms: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
    pub errors: u64,
    pub throughput_mib_s: f64,
}

/// Non-fatal diagnostic event payload.
pub struct DiagnosticEvent<'a> {
    pub level: &'static str,
    pub message: &'a str,
}

/// Git-specific event emitted alongside [`CoreEvent`] by git-aware scan paths.
pub enum GitEvent<'a> {
    /// Per-commit metadata for git scans.
    CommitMeta(CommitMetaEvent<'a>),
    /// Dictionary entries used by git identity interning.
    IdentityDictionary(IdentityDictionaryEvent<'a>),
}

/// Git commit metadata payload.
pub struct CommitMetaEvent<'a> {
    pub commit_id: &'a [u8],
    pub author: &'a str,
    pub committer: &'a str,
}

/// One interned identity dictionary entry.
pub struct IdentityEntry<'a> {
    pub id: u32,
    pub name: &'a str,
    pub email: &'a str,
}

/// Batch of identity dictionary entries.
pub struct IdentityDictionaryEvent<'a> {
    pub entries: &'a [IdentityEntry<'a>],
}

/// Git-free event sink surface used by scheduler scan paths.
///
/// `emit_core` must preserve event ordering as observed by callers.
pub trait EventOutput: Send + Sync {
    fn emit_core(&self, event: CoreEvent<'_>);
    fn flush(&self);
}

/// Git-specific extension surface layered on top of [`EventOutput`].
pub trait GitEventOutput: EventOutput {
    fn emit_git(&self, event: GitEvent<'_>);
}

/// No-op event sink that silently discards all events.
///
/// Useful as a default or in tests where event output is irrelevant.
#[derive(Default)]
pub struct NullEventOutput;

impl EventOutput for NullEventOutput {
    #[inline]
    fn emit_core(&self, _event: CoreEvent<'_>) {}

    #[inline]
    fn flush(&self) {}
}

impl GitEventOutput for NullEventOutput {
    #[inline]
    fn emit_git(&self, _event: GitEvent<'_>) {}
}

/// Event sink that JSON-encodes events into an in-memory byte buffer.
///
/// Each event is serialized as a single newline-delimited JSON line.
/// Accumulated output can be drained via [`VecEventOutput::take`].
#[derive(Default)]
pub struct VecEventOutput {
    encoded: Mutex<Vec<u8>>,
}

impl VecEventOutput {
    /// Create an empty `VecEventOutput`.
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

impl EventOutput for VecEventOutput {
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

impl GitEventOutput for VecEventOutput {
    fn emit_git(&self, event: GitEvent<'_>) {
        let mut line = Vec::with_capacity(256);
        match event {
            GitEvent::CommitMeta(meta) => {
                line.extend_from_slice(b"{\"type\":\"commit_meta\"");

                line.extend_from_slice(b",\"commit_id\":");
                write_hex_bytes(&mut line, meta.commit_id);

                line.extend_from_slice(b",\"author\":");
                write_json_str(&mut line, meta.author);

                line.extend_from_slice(b",\"committer\":");
                write_json_str(&mut line, meta.committer);

                line.push(b'}');
            }
            GitEvent::IdentityDictionary(dict) => {
                line.extend_from_slice(b"{\"type\":\"identity_dictionary\",\"entries\":[");

                for (idx, entry) in dict.entries.iter().enumerate() {
                    if idx > 0 {
                        line.push(b',');
                    }
                    line.extend_from_slice(b"{\"id\":");
                    write_u64(&mut line, u64::from(entry.id));
                    line.extend_from_slice(b",\"name\":");
                    write_json_str(&mut line, entry.name);
                    line.extend_from_slice(b",\"email\":");
                    write_json_str(&mut line, entry.email);
                    line.push(b'}');
                }

                line.extend_from_slice(b"]}");
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
fn write_hex_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.push(b'"');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        buf.push(HEX[(byte >> 4) as usize]);
        buf.push(HEX[(byte & 0x0f) as usize]);
    }
    buf.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_event_output_is_noop() {
        let sink = NullEventOutput;
        sink.emit_core(CoreEvent::Diagnostic(DiagnosticEvent {
            level: "info",
            message: "hello",
        }));
        sink.emit_git(GitEvent::CommitMeta(CommitMetaEvent {
            commit_id: &[0xde, 0xad, 0xbe, 0xef],
            author: "a",
            committer: "b",
        }));
        sink.flush();
    }

    #[test]
    fn vec_event_output_encodes_core_events() {
        let sink = VecEventOutput::new();
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"dir/file.txt",
            start: 10,
            end: 20,
            rule_id: 7,
            rule_name: "rule",
            norm_hash: [0xAB; 32],
            blob_oid: None,
            commit_id: Some(3),
            change_kind: Some("modify"),
            confidence_score: 85,
        }));

        let output = String::from_utf8(sink.take()).expect("valid utf-8 output");
        assert_eq!(
            output,
            "{\"type\":\"finding\",\"source\":\"fs\",\"path\":\"dir/file.txt\",\"start\":10,\"end\":20,\"rule_id\":7,\"rule\":\"rule\",\"confidence_score\":85,\"commit_id\":3,\"change_kind\":\"modify\"}\n"
        );
    }

    #[test]
    fn finding_event_debug_redacts_norm_hash() {
        // Valid SHA-1 wire encoding: byte 0 = length (20), bytes 1..=20 = OID
        // content, bytes 21..=32 = zero-padding.
        let mut wire_oid = [0u8; 33];
        wire_oid[0] = 20;
        wire_oid[1..=20].fill(0xAA);

        let finding = FindingEvent {
            source: SourceKind::Git,
            object_path: b"dir/file.txt",
            start: 10,
            end: 20,
            rule_id: 7,
            rule_name: "rule",
            norm_hash: [0xDE; 32],
            blob_oid: Some(wire_oid),
            commit_id: Some(3),
            change_kind: Some("modify"),
            confidence_score: 85,
        };

        let debug = format!("{finding:?}");
        assert!(
            debug.contains("norm_hash: [redacted]"),
            "Debug output must redact norm_hash, got: {debug}"
        );
        assert!(
            !debug.contains("222, 222, 222"),
            "Debug output must not leak norm_hash bytes, got: {debug}"
        );
    }

    #[test]
    fn vec_event_output_encodes_git_events() {
        let sink = VecEventOutput::new();
        let entries = [IdentityEntry {
            id: 1,
            name: "alice",
            email: "alice@example.com",
        }];

        sink.emit_git(GitEvent::CommitMeta(CommitMetaEvent {
            commit_id: &[0xab, 0xcd],
            author: "alice",
            committer: "bob",
        }));
        sink.emit_git(GitEvent::IdentityDictionary(IdentityDictionaryEvent {
            entries: &entries,
        }));

        let output = String::from_utf8(sink.take()).expect("valid utf-8 output");
        assert!(output.contains("{\"type\":\"commit_meta\",\"commit_id\":\"abcd\""));
        assert!(output.contains("{\"type\":\"identity_dictionary\",\"entries\":[{\"id\":1,\"name\":\"alice\",\"email\":\"alice@example.com\"}]"));
    }
}
