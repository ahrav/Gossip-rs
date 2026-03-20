//! Production-safe coordination telemetry recorder.
//!
//! The distributed runtime requires a [`CoordinationEventRecorder`], but event
//! recording is explicitly best-effort and separate from durability. For the
//! MVP-A cutover this module provides a real production recorder that emits
//! structured `tracing` events while enforcing a strict safe-field policy:
//!
//! - raw item keys, paths, git identity bytes, and diagnostic text are never
//!   emitted directly;
//! - toxic fields are reduced to `len + short hash` digests;
//! - recorder sink failures are non-fatal and logged once per category.
//!
//! The sink boundary stays private to this crate so Epic 1 can land with a
//! thin, low-blast-radius adapter. A future OTLP sink can implement the same
//! private sink trait without changing the runtime-facing recorder contract.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use gossip_contracts::identity::{domain_hasher, finalize_64};
use gossip_scanner_runtime::OwnedCoreEvent;
use gossip_scanner_runtime::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, StoredGitEvent,
};

const TELEMETRY_TARGET: &str = "gossip_worker::coordination";
const DIGEST_DOMAIN: &str = "gossip/worker/coordination-telemetry/v1";

/// Production recorder for distributed coordination telemetry.
///
/// All recorder output is best-effort. Sink failures are absorbed here so the
/// distributed runtime can continue making progress through the durable commit
/// pipeline without coupling liveness to telemetry availability.
pub struct ProductionCoordinationEventRecorder {
    sink: Arc<dyn CoordinationTelemetrySink>,
    core_error_logged: AtomicBool,
    git_error_logged: AtomicBool,
    progress_error_logged: AtomicBool,
}

impl Default for ProductionCoordinationEventRecorder {
    fn default() -> Self {
        Self::with_sink(Arc::new(TracingCoordinationTelemetrySink))
    }
}

impl ProductionCoordinationEventRecorder {
    /// Build the default production recorder backed by structured `tracing`
    /// events.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with_sink(sink: Arc<dyn CoordinationTelemetrySink>) -> Self {
        Self {
            sink,
            core_error_logged: AtomicBool::new(false),
            git_error_logged: AtomicBool::new(false),
            progress_error_logged: AtomicBool::new(false),
        }
    }

    fn emit_best_effort(&self, category: RecorderCategory, record: SanitizedCoordinationRecord) {
        let shard_id = record.shard_id();
        if self.sink.emit(record).is_err() && !category.error_flag(self).swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                target: TELEMETRY_TARGET,
                event_name = "coordination_recorder_sink_failure",
                category = category.as_str(),
                shard_id = %shard_id,
                "coordination telemetry sink failed; subsequent failures suppressed",
            );
        }
    }
}

impl CoordinationEventRecorder for ProductionCoordinationEventRecorder {
    fn record_core_event(&self, shard_id: &str, event: OwnedCoreEvent) -> Result<()> {
        self.emit_best_effort(
            RecorderCategory::Core,
            SanitizedCoordinationRecord::from_core_event(shard_id, event),
        );
        Ok(())
    }

    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()> {
        self.emit_best_effort(
            RecorderCategory::Git,
            SanitizedCoordinationRecord::from_git_event(shard_id, event),
        );
        Ok(())
    }

    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()> {
        self.emit_best_effort(
            RecorderCategory::Progress,
            SanitizedCoordinationRecord::from_commit_progress(shard_id, event),
        );
        Ok(())
    }
}

/// Private sink boundary for sanitized telemetry records.
trait CoordinationTelemetrySink: Send + Sync {
    fn emit(&self, record: SanitizedCoordinationRecord) -> Result<()>;
}

/// Structured `tracing` sink used by the production recorder.
#[derive(Clone, Copy, Debug, Default)]
struct TracingCoordinationTelemetrySink;

impl CoordinationTelemetrySink for TracingCoordinationTelemetrySink {
    fn emit(&self, record: SanitizedCoordinationRecord) -> Result<()> {
        match record {
            SanitizedCoordinationRecord::CoreFinding {
                shard_id,
                source,
                object_path,
                start,
                end,
                rule_id,
                rule_name,
                commit_id,
                change_kind,
                confidence_score,
            } => {
                tracing::debug!(
                    target: TELEMETRY_TARGET,
                    event_name = "coordination_core_finding",
                    category = "core",
                    shard_id = %shard_id,
                    source,
                    object_path = %object_path,
                    start,
                    end,
                    rule_id,
                    rule_name = %rule_name,
                    commit_id = %OptionalField::new(commit_id),
                    change_kind = %OptionalField::new(change_kind),
                    confidence_score,
                    "coordination core finding",
                );
            }
            SanitizedCoordinationRecord::CoreProgress {
                shard_id,
                source,
                stage,
                objects_scanned,
                bytes_scanned,
                findings_emitted,
            } => {
                tracing::debug!(
                    target: TELEMETRY_TARGET,
                    event_name = "coordination_core_progress",
                    category = "core",
                    shard_id = %shard_id,
                    source,
                    stage,
                    objects_scanned,
                    bytes_scanned,
                    findings_emitted,
                    "coordination core progress",
                );
            }
            SanitizedCoordinationRecord::CoreSummary {
                shard_id,
                source,
                status,
                elapsed_ms,
                bytes_scanned,
                findings_emitted,
                errors,
                throughput_mib_s,
            } => {
                tracing::info!(
                    target: TELEMETRY_TARGET,
                    event_name = "coordination_core_summary",
                    category = "core",
                    shard_id = %shard_id,
                    source,
                    status,
                    elapsed_ms,
                    bytes_scanned,
                    findings_emitted,
                    errors,
                    throughput_mib_s,
                    "coordination core summary",
                );
            }
            SanitizedCoordinationRecord::CoreDiagnostic {
                shard_id,
                diagnostic_level,
                diagnostic_message,
            } => emit_diagnostic(shard_id, diagnostic_level, diagnostic_message),
            SanitizedCoordinationRecord::GitCommitMeta {
                shard_id,
                commit_id,
                oid,
                timestamp,
                author_name_id,
                author_email_id,
                committer_name_id,
                committer_email_id,
            } => {
                tracing::trace!(
                    target: TELEMETRY_TARGET,
                    event_name = "coordination_git_commit_meta",
                    category = "git",
                    shard_id = %shard_id,
                    commit_id,
                    oid = %oid,
                    timestamp,
                    author_name_id = %OptionalField::new(author_name_id),
                    author_email_id = %OptionalField::new(author_email_id),
                    committer_name_id = %OptionalField::new(committer_name_id),
                    committer_email_id = %OptionalField::new(committer_email_id),
                    "coordination git commit metadata",
                );
            }
            SanitizedCoordinationRecord::GitIdentityDictionary {
                shard_id,
                identity_id,
                value,
            } => {
                tracing::trace!(
                    target: TELEMETRY_TARGET,
                    event_name = "coordination_git_identity_dictionary",
                    category = "git",
                    shard_id = %shard_id,
                    identity_id,
                    value = %value,
                    "coordination git identity dictionary entry",
                );
            }
            SanitizedCoordinationRecord::CommitBegin {
                shard_id,
                tenant_id,
                policy_hash,
                run_id,
                lease_shard_id,
                fence_epoch,
                item_key,
                size_hint,
            } => {
                tracing::trace!(
                    target: TELEMETRY_TARGET,
                    event_name = "coordination_commit_begin",
                    category = "progress",
                    shard_id = %shard_id,
                    tenant_id = %tenant_id,
                    policy_hash = %policy_hash,
                    run_id,
                    lease_shard_id,
                    fence_epoch,
                    item_key = %item_key,
                    size_hint = %OptionalField::new(size_hint),
                    "coordination commit begin",
                );
            }
            SanitizedCoordinationRecord::CommitFinish {
                shard_id,
                tenant_id,
                policy_hash,
                run_id,
                lease_shard_id,
                fence_epoch,
                item_key,
            } => {
                tracing::trace!(
                    target: TELEMETRY_TARGET,
                    event_name = "coordination_commit_finish",
                    category = "progress",
                    shard_id = %shard_id,
                    tenant_id = %tenant_id,
                    policy_hash = %policy_hash,
                    run_id,
                    lease_shard_id,
                    fence_epoch,
                    item_key = %item_key,
                    "coordination commit finish",
                );
            }
        }

        Ok(())
    }
}

fn emit_diagnostic(
    shard_id: RedactedDigest,
    diagnostic_level: &'static str,
    diagnostic_message: RedactedDigest,
) {
    match diagnostic_level {
        "error" | "fatal" => {
            tracing::error!(
                target: TELEMETRY_TARGET,
                event_name = "coordination_core_diagnostic",
                category = "core",
                shard_id = %shard_id,
                diagnostic_level,
                diagnostic_message = %diagnostic_message,
                "coordination core diagnostic",
            );
        }
        "warn" | "warning" => {
            tracing::warn!(
                target: TELEMETRY_TARGET,
                event_name = "coordination_core_diagnostic",
                category = "core",
                shard_id = %shard_id,
                diagnostic_level,
                diagnostic_message = %diagnostic_message,
                "coordination core diagnostic",
            );
        }
        "debug" => {
            tracing::debug!(
                target: TELEMETRY_TARGET,
                event_name = "coordination_core_diagnostic",
                category = "core",
                shard_id = %shard_id,
                diagnostic_level,
                diagnostic_message = %diagnostic_message,
                "coordination core diagnostic",
            );
        }
        "trace" => {
            tracing::trace!(
                target: TELEMETRY_TARGET,
                event_name = "coordination_core_diagnostic",
                category = "core",
                shard_id = %shard_id,
                diagnostic_level,
                diagnostic_message = %diagnostic_message,
                "coordination core diagnostic",
            );
        }
        _ => {
            tracing::info!(
                target: TELEMETRY_TARGET,
                event_name = "coordination_core_diagnostic",
                category = "core",
                shard_id = %shard_id,
                diagnostic_level,
                diagnostic_message = %diagnostic_message,
                "coordination core diagnostic",
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecorderCategory {
    Core,
    Git,
    Progress,
}

impl RecorderCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Git => "git",
            Self::Progress => "progress",
        }
    }

    fn error_flag<'a>(self, recorder: &'a ProductionCoordinationEventRecorder) -> &'a AtomicBool {
        match self {
            Self::Core => &recorder.core_error_logged,
            Self::Git => &recorder.git_error_logged,
            Self::Progress => &recorder.progress_error_logged,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RedactedDigest {
    len: usize,
    hash64: u64,
}

impl RedactedDigest {
    #[inline]
    fn bytes(label: &'static str, bytes: &[u8]) -> Self {
        let mut hasher = domain_hasher(DIGEST_DOMAIN);
        hasher.update(label.as_bytes());
        hasher.update(&[0]);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        Self {
            len: bytes.len(),
            hash64: finalize_64(&hasher),
        }
    }

    #[inline]
    fn text(label: &'static str, text: &str) -> Self {
        Self::bytes(label, text.as_bytes())
    }
}

impl fmt::Display for RedactedDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "len={},hash={:016x}", self.len, self.hash64)
    }
}

impl fmt::Debug for RedactedDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedDigest({self})")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OptionalField<T>(Option<T>);

impl<T> OptionalField<T> {
    const fn new(value: Option<T>) -> Self {
        Self(value)
    }
}

impl<T: fmt::Display> fmt::Display for OptionalField<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(value) => fmt::Display::fmt(value, f),
            None => f.write_str("none"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum SanitizedCoordinationRecord {
    CoreFinding {
        shard_id: RedactedDigest,
        source: &'static str,
        object_path: RedactedDigest,
        start: u64,
        end: u64,
        rule_id: u32,
        rule_name: RedactedDigest,
        commit_id: Option<u32>,
        change_kind: Option<RedactedDigest>,
        confidence_score: i8,
    },
    CoreProgress {
        shard_id: RedactedDigest,
        source: &'static str,
        stage: &'static str,
        objects_scanned: u64,
        bytes_scanned: u64,
        findings_emitted: u64,
    },
    CoreSummary {
        shard_id: RedactedDigest,
        source: &'static str,
        status: &'static str,
        elapsed_ms: u64,
        bytes_scanned: u64,
        findings_emitted: u64,
        errors: u64,
        throughput_mib_s: f64,
    },
    CoreDiagnostic {
        shard_id: RedactedDigest,
        diagnostic_level: &'static str,
        diagnostic_message: RedactedDigest,
    },
    GitCommitMeta {
        shard_id: RedactedDigest,
        commit_id: u32,
        oid: RedactedDigest,
        timestamp: u64,
        author_name_id: Option<u32>,
        author_email_id: Option<u32>,
        committer_name_id: Option<u32>,
        committer_email_id: Option<u32>,
    },
    GitIdentityDictionary {
        shard_id: RedactedDigest,
        identity_id: u32,
        value: RedactedDigest,
    },
    CommitBegin {
        shard_id: RedactedDigest,
        tenant_id: RedactedDigest,
        policy_hash: RedactedDigest,
        run_id: u64,
        lease_shard_id: u64,
        fence_epoch: u64,
        item_key: RedactedDigest,
        size_hint: Option<u64>,
    },
    CommitFinish {
        shard_id: RedactedDigest,
        tenant_id: RedactedDigest,
        policy_hash: RedactedDigest,
        run_id: u64,
        lease_shard_id: u64,
        fence_epoch: u64,
        item_key: RedactedDigest,
    },
}

impl SanitizedCoordinationRecord {
    fn from_core_event(shard_id: &str, event: OwnedCoreEvent) -> Self {
        let shard_id = redact_text("shard_id", shard_id);
        match event {
            OwnedCoreEvent::Finding {
                source,
                object_path,
                start,
                end,
                rule_id,
                rule_name,
                commit_id,
                change_kind,
                confidence_score,
            } => Self::CoreFinding {
                shard_id,
                source: source.as_str(),
                object_path: redact_bytes("object_path", &object_path),
                start,
                end,
                rule_id,
                rule_name: redact_text("rule_name", &rule_name),
                commit_id,
                change_kind: change_kind
                    .as_deref()
                    .map(|value| redact_text("change_kind", value)),
                confidence_score,
            },
            OwnedCoreEvent::Progress {
                source,
                stage,
                objects_scanned,
                bytes_scanned,
                findings_emitted,
            } => Self::CoreProgress {
                shard_id,
                source: source.as_str(),
                stage,
                objects_scanned,
                bytes_scanned,
                findings_emitted,
            },
            OwnedCoreEvent::Summary {
                source,
                status,
                elapsed_ms,
                bytes_scanned,
                findings_emitted,
                errors,
                throughput_mib_s,
            } => Self::CoreSummary {
                shard_id,
                source: source.as_str(),
                status,
                elapsed_ms,
                bytes_scanned,
                findings_emitted,
                errors,
                throughput_mib_s,
            },
            OwnedCoreEvent::Diagnostic { level, message } => Self::CoreDiagnostic {
                shard_id,
                diagnostic_level: level,
                diagnostic_message: redact_text("diagnostic_message", &message),
            },
        }
    }

    fn from_git_event(shard_id: &str, event: StoredGitEvent) -> Self {
        let shard_id = redact_text("shard_id", shard_id);
        match event {
            StoredGitEvent::CommitMeta {
                commit_id,
                oid_hex,
                timestamp,
                author_name_id,
                author_email_id,
                committer_name_id,
                committer_email_id,
            } => Self::GitCommitMeta {
                shard_id,
                commit_id,
                oid: redact_text("git_commit_oid", &oid_hex),
                timestamp,
                author_name_id,
                author_email_id,
                committer_name_id,
                committer_email_id,
            },
            StoredGitEvent::IdentityDictionary { id, value } => Self::GitIdentityDictionary {
                shard_id,
                identity_id: id,
                value: redact_bytes("git_identity_value", &value),
            },
        }
    }

    fn from_commit_progress(shard_id: &str, event: CommitProgressRecord) -> Self {
        let shard_id = redact_text("shard_id", shard_id);
        match event {
            CommitProgressRecord::Begin {
                write_context,
                item_key,
                size_hint,
            } => Self::CommitBegin {
                shard_id,
                tenant_id: redact_bytes("tenant_id", write_context.tenant_id().as_bytes()),
                policy_hash: redact_bytes("policy_hash", write_context.policy_hash().as_bytes()),
                run_id: write_context.run_id().as_raw(),
                lease_shard_id: write_context.shard_id().as_raw(),
                fence_epoch: write_context.fence_epoch().as_raw(),
                item_key: redact_bytes("item_key", item_key.as_bytes()),
                size_hint,
            },
            CommitProgressRecord::Finish {
                write_context,
                item_key,
            } => Self::CommitFinish {
                shard_id,
                tenant_id: redact_bytes("tenant_id", write_context.tenant_id().as_bytes()),
                policy_hash: redact_bytes("policy_hash", write_context.policy_hash().as_bytes()),
                run_id: write_context.run_id().as_raw(),
                lease_shard_id: write_context.shard_id().as_raw(),
                fence_epoch: write_context.fence_epoch().as_raw(),
                item_key: redact_bytes("item_key", item_key.as_bytes()),
            },
        }
    }

    fn shard_id(&self) -> RedactedDigest {
        match self {
            Self::CoreFinding { shard_id, .. }
            | Self::CoreProgress { shard_id, .. }
            | Self::CoreSummary { shard_id, .. }
            | Self::CoreDiagnostic { shard_id, .. }
            | Self::GitCommitMeta { shard_id, .. }
            | Self::GitIdentityDictionary { shard_id, .. }
            | Self::CommitBegin { shard_id, .. }
            | Self::CommitFinish { shard_id, .. } => *shard_id,
        }
    }
}

#[inline]
fn redact_bytes(label: &'static str, bytes: &[u8]) -> RedactedDigest {
    RedactedDigest::bytes(label, bytes)
}

#[inline]
fn redact_text(label: &'static str, text: &str) -> RedactedDigest {
    RedactedDigest::text(label, text)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use tracing::Level;
    use tracing_subscriber::fmt::writer::MakeWriter;

    #[derive(Clone, Default)]
    struct SharedLogBuffer(Arc<Mutex<Vec<u8>>>);

    struct SharedLogWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> MakeWriter<'a> for SharedLogBuffer {
        type Writer = SharedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter {
                buffer: Arc::clone(&self.0),
            }
        }
    }

    impl Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut guard = self.buffer.lock().expect("shared log buffer lock");
            guard.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn capture_logs(level: Level, body: impl FnOnce()) -> String {
        let buffer = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .compact()
            .with_writer(buffer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, body);

        let bytes = buffer.0.lock().expect("shared log buffer lock").clone();
        String::from_utf8(bytes).expect("captured tracing output should be UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gossip_contracts::connector::ItemKey;
    use gossip_contracts::identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId};
    use gossip_contracts::persistence::WriteContext;
    use tracing::Level;

    use crate::recorder::test_support::capture_logs;

    fn secret_canary() -> String {
        ["TEST_", "COORD_", "RECORDER_", "CANARY_", "7f9b2c4d"].concat()
    }

    fn write_context() -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(42),
            ShardId::from_raw(9),
            FenceEpoch::from_raw(3),
        )
    }

    #[test]
    fn sanitized_records_hash_toxic_fields() {
        let canary = secret_canary();

        let diagnostic = SanitizedCoordinationRecord::from_core_event(
            &format!("shard-{canary}"),
            OwnedCoreEvent::Diagnostic {
                level: "warn",
                message: canary.clone(),
            },
        );
        let git = SanitizedCoordinationRecord::from_git_event(
            "git-shard",
            StoredGitEvent::IdentityDictionary {
                id: 7,
                value: canary.as_bytes().to_vec(),
            },
        );
        let progress = SanitizedCoordinationRecord::from_commit_progress(
            "progress-shard",
            CommitProgressRecord::Begin {
                write_context: write_context(),
                item_key: ItemKey::try_from_slice(canary.as_bytes())
                    .expect("canary item key should be valid"),
                size_hint: Some(128),
            },
        );

        let diagnostic_debug = format!("{diagnostic:?}");
        let git_debug = format!("{git:?}");
        let progress_debug = format!("{progress:?}");

        assert!(!diagnostic_debug.contains(&canary));
        assert!(!git_debug.contains(&canary));
        assert!(!progress_debug.contains(&canary));

        match diagnostic {
            SanitizedCoordinationRecord::CoreDiagnostic {
                shard_id,
                diagnostic_message,
                ..
            } => {
                let shard = shard_id.to_string();
                let message = diagnostic_message.to_string();
                assert!(shard.contains("hash="));
                assert!(message.contains("hash="));
                assert!(!shard.contains(&canary));
                assert!(!message.contains(&canary));
            }
            _ => panic!("expected core diagnostic record"),
        }

        match git {
            SanitizedCoordinationRecord::GitIdentityDictionary { value, .. } => {
                let value = value.to_string();
                assert!(value.contains("len="));
                assert!(value.contains("hash="));
                assert!(!value.contains(&canary));
            }
            _ => panic!("expected git identity dictionary record"),
        }

        match progress {
            SanitizedCoordinationRecord::CommitBegin {
                tenant_id,
                policy_hash,
                item_key,
                ..
            } => {
                let tenant_id = tenant_id.to_string();
                let policy_hash = policy_hash.to_string();
                let item_key = item_key.to_string();
                assert!(tenant_id.contains("hash="));
                assert!(policy_hash.contains("hash="));
                assert!(item_key.contains("hash="));
                assert!(!item_key.contains(&canary));
            }
            _ => panic!("expected commit-begin record"),
        }
    }

    #[test]
    fn tracing_sink_never_logs_raw_canary_bytes() {
        let recorder = ProductionCoordinationEventRecorder::default();
        let canary = secret_canary();
        let logs = capture_logs(Level::TRACE, || {
            recorder
                .record_core_event(
                    &format!("shard-{canary}"),
                    OwnedCoreEvent::Diagnostic {
                        level: "warn",
                        message: canary.clone(),
                    },
                )
                .expect("diagnostic telemetry should be best-effort");
            recorder
                .record_git_event(
                    &format!("git-shard-{canary}"),
                    StoredGitEvent::CommitMeta {
                        commit_id: 17,
                        oid_hex: canary.clone(),
                        timestamp: 1234,
                        author_name_id: Some(1),
                        author_email_id: Some(2),
                        committer_name_id: Some(3),
                        committer_email_id: Some(4),
                    },
                )
                .expect("git telemetry should be best-effort");
            recorder
                .record_git_event(
                    "git-shard",
                    StoredGitEvent::IdentityDictionary {
                        id: 11,
                        value: canary.as_bytes().to_vec(),
                    },
                )
                .expect("git identity telemetry should be best-effort");
            recorder
                .record_commit_progress(
                    "progress-shard",
                    CommitProgressRecord::Begin {
                        write_context: write_context(),
                        item_key: ItemKey::try_from_slice(canary.as_bytes())
                            .expect("canary item key should be valid"),
                        size_hint: Some(64),
                    },
                )
                .expect("commit telemetry should be best-effort");
        });

        assert!(logs.contains("coordination_core_diagnostic"));
        assert!(logs.contains("coordination_git_commit_meta"));
        assert!(logs.contains("coordination_git_identity_dictionary"));
        assert!(logs.contains("coordination_commit_begin"));
        assert!(logs.contains("hash="));
        assert!(!logs.contains(&canary));
    }

    #[test]
    fn recorder_suppresses_repeated_sink_failures_per_category() {
        #[derive(Debug)]
        struct FailingSink {
            canary: String,
        }

        impl CoordinationTelemetrySink for FailingSink {
            fn emit(&self, _record: SanitizedCoordinationRecord) -> Result<()> {
                anyhow::bail!("telemetry sink exploded: {}", self.canary)
            }
        }

        let canary = secret_canary();
        let recorder = ProductionCoordinationEventRecorder::with_sink(Arc::new(FailingSink {
            canary: canary.clone(),
        }));

        let logs = capture_logs(Level::WARN, || {
            for _ in 0..3 {
                recorder
                    .record_core_event(
                        "core-shard",
                        OwnedCoreEvent::Diagnostic {
                            level: "warn",
                            message: canary.clone(),
                        },
                    )
                    .expect("core telemetry failures must be non-fatal");
            }
            for _ in 0..2 {
                recorder
                    .record_git_event(
                        "git-shard",
                        StoredGitEvent::IdentityDictionary {
                            id: 1,
                            value: canary.as_bytes().to_vec(),
                        },
                    )
                    .expect("git telemetry failures must be non-fatal");
            }
            for _ in 0..2 {
                recorder
                    .record_commit_progress(
                        "progress-shard",
                        CommitProgressRecord::Finish {
                            write_context: write_context(),
                            item_key: ItemKey::try_from_slice(canary.as_bytes())
                                .expect("canary item key should be valid"),
                        },
                    )
                    .expect("progress telemetry failures must be non-fatal");
            }
        });

        assert_eq!(logs.matches("coordination_recorder_sink_failure").count(), 3);
        assert!(!logs.contains(&canary));
    }
}
