//! Minimal structured event sink used by extracted scheduler paths.
//!
//! This is intentionally lightweight: it preserves the scheduler-facing
//! `emit`/`flush` contract and test sink behavior without carrying over the
//! full monolith JSON encoder stack. The richer split-event surface lands in
//! Step 2b.
use super::SourceKind;
use std::sync::Mutex;

pub enum ScanEvent<'a> {
    Finding(FindingEvent<'a>),
    Progress(ProgressEvent),
    Summary(SummaryEvent),
    Diagnostic(DiagnosticEvent<'a>),
}

pub struct FindingEvent<'a> {
    pub source: SourceKind,
    pub object_path: &'a [u8],
    pub start: u64,
    pub end: u64,
    pub rule_id: u32,
    pub rule_name: &'a str,
    pub commit_id: Option<u32>,
    pub change_kind: Option<&'a str>,
    pub confidence_score: i8,
}

pub struct ProgressEvent {
    pub source: SourceKind,
    pub stage: &'static str,
    pub objects_scanned: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
}

pub struct SummaryEvent {
    pub source: SourceKind,
    pub status: &'static str,
    pub elapsed_ms: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
    pub errors: u64,
    pub throughput_mib_s: f64,
}

pub struct DiagnosticEvent<'a> {
    pub level: &'static str,
    pub message: &'a str,
}

pub trait EventOutput: Send + Sync {
    fn emit(&self, event: ScanEvent<'_>);
    fn flush(&self);
}

/// Backward-compatible alias trait so extracted files using `EventSink`
/// continue to compile while new call sites can adopt `EventOutput`.
pub trait EventSink: EventOutput {}

impl<T: EventOutput + ?Sized> EventSink for T {}

#[derive(Default)]
pub struct NullEventSink;

impl EventOutput for NullEventSink {
    #[inline]
    fn emit(&self, _event: ScanEvent<'_>) {}

    #[inline]
    fn flush(&self) {}
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

    #[inline]
    pub fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.encoded.lock().expect("vec event sink mutex poisoned"))
    }
}

impl EventOutput for VecEventSink {
    fn emit(&self, event: ScanEvent<'_>) {
        let mut line = String::new();
        match event {
            ScanEvent::Finding(f) => {
                let source = match f.source {
                    SourceKind::Fs => "fs",
                    SourceKind::Git => "git",
                };
                let path = escape_json(&String::from_utf8_lossy(f.object_path));
                let rule = escape_json(f.rule_name);
                line.push_str("{\"type\":\"finding\"");
                line.push_str(",\"source\":\"");
                line.push_str(source);
                line.push_str("\"");
                line.push_str(",\"path\":\"");
                line.push_str(&path);
                line.push_str("\"");
                line.push_str(",\"start\":");
                line.push_str(&f.start.to_string());
                line.push_str(",\"end\":");
                line.push_str(&f.end.to_string());
                line.push_str(",\"rule_id\":");
                line.push_str(&f.rule_id.to_string());
                line.push_str(",\"rule\":\"");
                line.push_str(&rule);
                line.push_str("\"");
                line.push_str(",\"confidence_score\":");
                line.push_str(&f.confidence_score.to_string());
                if let Some(commit_id) = f.commit_id {
                    line.push_str(",\"commit_id\":");
                    line.push_str(&commit_id.to_string());
                }
                if let Some(change_kind) = f.change_kind {
                    line.push_str(",\"change_kind\":\"");
                    line.push_str(&escape_json(change_kind));
                    line.push_str("\"");
                }
                line.push('}');
            }
            ScanEvent::Diagnostic(d) => {
                line.push_str("{\"type\":\"diagnostic\"");
                line.push_str(",\"level\":\"");
                line.push_str(d.level);
                line.push_str("\"");
                line.push_str(",\"message\":\"");
                line.push_str(&escape_json(d.message));
                line.push_str("\"}");
            }
            ScanEvent::Progress(p) => {
                let source = match p.source {
                    SourceKind::Fs => "fs",
                    SourceKind::Git => "git",
                };
                line.push_str("{\"type\":\"progress\"");
                line.push_str(",\"source\":\"");
                line.push_str(source);
                line.push_str("\"");
                line.push_str(",\"stage\":\"");
                line.push_str(p.stage);
                line.push_str("\"");
                line.push_str(",\"objects_scanned\":");
                line.push_str(&p.objects_scanned.to_string());
                line.push_str(",\"bytes_scanned\":");
                line.push_str(&p.bytes_scanned.to_string());
                line.push_str(",\"findings_emitted\":");
                line.push_str(&p.findings_emitted.to_string());
                line.push('}');
            }
            ScanEvent::Summary(s) => {
                let source = match s.source {
                    SourceKind::Fs => "fs",
                    SourceKind::Git => "git",
                };
                line.push_str("{\"type\":\"summary\"");
                line.push_str(",\"source\":\"");
                line.push_str(source);
                line.push_str("\"");
                line.push_str(",\"status\":\"");
                line.push_str(s.status);
                line.push_str("\"");
                line.push_str(",\"elapsed_ms\":");
                line.push_str(&s.elapsed_ms.to_string());
                line.push_str(",\"bytes_scanned\":");
                line.push_str(&s.bytes_scanned.to_string());
                line.push_str(",\"findings_emitted\":");
                line.push_str(&s.findings_emitted.to_string());
                line.push_str(",\"errors\":");
                line.push_str(&s.errors.to_string());
                line.push_str(",\"throughput_mib_s\":");
                line.push_str(&s.throughput_mib_s.to_string());
                line.push('}');
            }
        }
        line.push('\n');
        self.encoded
            .lock()
            .expect("vec event sink mutex poisoned")
            .extend_from_slice(line.as_bytes());
    }

    #[inline]
    fn flush(&self) {}
}

#[inline]
fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}
