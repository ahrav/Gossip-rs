//! Production-safe coordination telemetry recorder.
//!
//! The distributed runtime requires a [`CoordinationEventRecorder`], but event
//! recording is explicitly best-effort and separate from durability. This
//! module provides a production recorder that emits structured `tracing`
//! events while enforcing a strict safe-field policy:
//!
//! - raw item keys, paths, git identity bytes, and diagnostic text are never
//!   emitted directly;
//! - toxic fields are reduced to `len + short hash` digests;
//! - recorder sink failures are non-fatal and logged once per category.
//!
//! The sink boundary stays private to this crate so future sink backends can be
//! added without changing the runtime-facing recorder contract.

use std::cell::RefCell;
use std::fmt;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use gossip_contracts::identity::domain::COORDINATION_TELEMETRY_V1;
use gossip_contracts::identity::{domain_hasher, finalize_64};
use gossip_scanner_runtime::OwnedCoreEvent;
use gossip_scanner_runtime::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, StoredGitEvent,
};

/// Tracing target for all coordination telemetry events. Subscribers can filter
/// on this target to isolate coordination output from other worker logs.
const TELEMETRY_TARGET: &str = "gossip_worker::coordination";

/// Cached BLAKE3 derive-key hasher for [`RedactedDigest`]. Seeds the
/// per-thread [`LOCAL_HASHER`] so the expensive key-schedule compression
/// runs only once per process.
static TELEMETRY_HASHER: LazyLock<gossip_contracts::blake3::Hasher> =
    LazyLock::new(|| domain_hasher(COORDINATION_TELEMETRY_V1));

thread_local! {
    /// Per-thread hasher seeded from [`TELEMETRY_HASHER`]. Using `reset()` between
    /// calls avoids the memcpy of cloning the full hasher state.
    static LOCAL_HASHER: RefCell<gossip_contracts::blake3::Hasher> =
        RefCell::new(TELEMETRY_HASHER.clone());
}

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

impl fmt::Debug for ProductionCoordinationEventRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionCoordinationEventRecorder")
            .field("sink", &*self.sink)
            .field(
                "core_error_logged",
                &self.core_error_logged.load(Ordering::Relaxed),
            )
            .field(
                "git_error_logged",
                &self.git_error_logged.load(Ordering::Relaxed),
            )
            .field(
                "progress_error_logged",
                &self.progress_error_logged.load(Ordering::Relaxed),
            )
            .finish()
    }
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

    pub(crate) fn with_sink(sink: Arc<dyn CoordinationTelemetrySink>) -> Self {
        Self {
            sink,
            core_error_logged: AtomicBool::new(false),
            git_error_logged: AtomicBool::new(false),
            progress_error_logged: AtomicBool::new(false),
        }
    }

    /// Forwards a sanitized record to the sink, absorbing failures. The first
    /// failure per [`RecorderCategory`] emits a warning; subsequent failures
    /// for the same category are silently suppressed to avoid log flooding
    /// during sustained sink outages.
    fn emit_best_effort(&self, category: RecorderCategory, record: SanitizedCoordinationRecord) {
        let shard_id = record.shard_id();
        // The `swap(true)` returns the *previous* value: `false` on the first
        // failure, `true` on every subsequent one. The warning fires exactly
        // once per category.
        if let Err(error) = self.sink.emit(record)
            && !category.error_flag(self).swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                target: TELEMETRY_TARGET,
                event_name = "coordination_recorder_sink_failure",
                category = category.as_str(),
                shard_id = %shard_id,
                %error,
                "coordination telemetry sink failed; subsequent failures suppressed",
            );
        }
    }
}

/// Best-effort recorder: all methods return `Ok(())` regardless of sink
/// outcome. Sink failures are absorbed internally and logged once per
/// category. Upstream callers must not couple durable commit progress to
/// telemetry availability.
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

/// Crate-local sink boundary for sanitized telemetry records.
///
/// Kept `pub(crate)` so the recorder owns the sanitization contract: callers
/// outside this crate interact only with [`CoordinationEventRecorder`] (which
/// accepts raw events), and this trait accepts only pre-sanitized records.
/// Alternative sink backends (metrics, file, etc.) can be added by
/// implementing this trait without changing the runtime-facing API.
pub(crate) trait CoordinationTelemetrySink: Send + Sync + fmt::Debug {
    /// Emit a single sanitized record. Returning `Err` signals a transient
    /// sink failure; the caller (`emit_best_effort`) handles suppression.
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

/// Emits a coordination diagnostic event at a compile-time tracing level.
/// Factored into a macro because `tracing::event!` requires a const level.
macro_rules! emit_diagnostic_at_level {
    ($level_macro:ident, $shard_id:expr, $diagnostic_level:expr, $diagnostic_message:expr) => {
        tracing::$level_macro!(
            target: TELEMETRY_TARGET,
            event_name = "coordination_core_diagnostic",
            category = "core",
            shard_id = %$shard_id,
            diagnostic_level = $diagnostic_level,
            diagnostic_message = %$diagnostic_message,
            "coordination core diagnostic",
        )
    };
}

/// Routes a diagnostic record to the tracing level matching `diagnostic_level`.
///
/// The `"info"` level is handled by the wildcard arm along with any
/// unrecognized level strings, both of which emit at `info!`.
fn emit_diagnostic(
    shard_id: RedactedDigest,
    diagnostic_level: &'static str,
    diagnostic_message: RedactedDigest,
) {
    match diagnostic_level {
        "error" | "fatal" => {
            emit_diagnostic_at_level!(error, shard_id, diagnostic_level, diagnostic_message)
        }
        "warn" | "warning" => {
            emit_diagnostic_at_level!(warn, shard_id, diagnostic_level, diagnostic_message)
        }
        "debug" => emit_diagnostic_at_level!(debug, shard_id, diagnostic_level, diagnostic_message),
        "trace" => emit_diagnostic_at_level!(trace, shard_id, diagnostic_level, diagnostic_message),
        _ => emit_diagnostic_at_level!(info, shard_id, diagnostic_level, diagnostic_message),
    }
}

/// Discriminant for the three independent error-suppression channels.
///
/// Each category tracks its own "first failure logged" flag so that a broken
/// git sink does not suppress the first-failure warning for core events (or
/// vice versa).
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

    /// Returns the per-category atomic flag on `recorder` that tracks whether
    /// the first sink failure has already been logged.
    fn error_flag(self, recorder: &ProductionCoordinationEventRecorder) -> &AtomicBool {
        match self {
            Self::Core => &recorder.core_error_logged,
            Self::Git => &recorder.git_error_logged,
            Self::Progress => &recorder.progress_error_logged,
        }
    }
}

/// One-way digest that replaces sensitive field values in telemetry output.
///
/// Stores `(original_length, 64-bit BLAKE3 hash)` so operators can correlate
/// records ("same hash ⇒ same input") and gauge payload size without exposing
/// raw bytes. The hash is domain-separated by
/// [`COORDINATION_TELEMETRY_V1`] and further keyed by a field-level `label`
/// (e.g. `"shard_id"`, `"item_key"`), so identical byte sequences in different
/// field positions produce distinct digests.
///
/// Display format: `len=<n>,hash=<016x>`.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) struct RedactedDigest {
    len: usize,
    hash64: u64,
}

impl RedactedDigest {
    /// Builds a digest from raw bytes. Uses BLAKE3 derive-key mode with
    /// [`COORDINATION_TELEMETRY_V1`] as the context (key derivation, not part
    /// of the update stream). The update stream is
    /// `label || 0x00 || le64(len) || bytes`, where the null separator and
    /// length prefix prevent label/payload ambiguity.
    #[inline]
    fn bytes(label: &'static str, bytes: &[u8]) -> Self {
        LOCAL_HASHER.with_borrow_mut(|hasher| {
            hasher.reset();
            hasher.update(label.as_bytes());
            hasher.update(&[0]);
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
            Self {
                len: bytes.len(),
                hash64: finalize_64(hasher),
            }
        })
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

/// Wrapper that formats `None` as `"none"` instead of being omitted.
///
/// `tracing` field values must implement `Display`. Bare `Option<T>` cannot be
/// used directly as a field value, and omitting the field entirely would make
/// log schemas inconsistent across records. This wrapper ensures every
/// optional field always appears in the structured output.
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

/// Pre-sanitized coordination telemetry record ready for sink emission.
///
/// Every field that could contain tenant data, file paths, git identity bytes,
/// or diagnostic text is stored as a [`RedactedDigest`]. Scalar metrics
/// (`u64` counters, `f64` throughput), `&'static str` labels, and integer IDs
/// pass through unchanged because they carry no customer-attributable content.
///
/// Variants mirror the three event families of [`CoordinationEventRecorder`]:
/// core scanner events, git metadata, and commit lifecycle progress.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SanitizedCoordinationRecord {
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
    /// Converts a raw core event into a sanitized record, redacting `shard_id`,
    /// `object_path`, `rule_name`, `change_kind`, and diagnostic messages.
    ///
    /// Secret-derived `norm_hash` values are dropped instead of logged.
    fn from_core_event(shard_id: &str, event: OwnedCoreEvent) -> Self {
        let shard_id = RedactedDigest::text("shard_id", shard_id);
        match event {
            OwnedCoreEvent::Finding {
                source,
                object_path,
                start,
                end,
                rule_id,
                rule_name,
                norm_hash: _,
                commit_id,
                change_kind,
                confidence_score,
            } => Self::CoreFinding {
                shard_id,
                source: source.as_str(),
                object_path: RedactedDigest::bytes("object_path", &object_path),
                start,
                end,
                rule_id,
                rule_name: RedactedDigest::text("rule_name", &rule_name),
                commit_id,
                change_kind: change_kind
                    .as_deref()
                    .map(|value| RedactedDigest::text("change_kind", value)),
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
                diagnostic_message: RedactedDigest::text("diagnostic_message", &message),
            },
        }
    }

    /// Converts a git event into a sanitized record, redacting `shard_id`,
    /// commit OIDs, and identity dictionary values (raw name/email bytes).
    fn from_git_event(shard_id: &str, event: StoredGitEvent) -> Self {
        let shard_id = RedactedDigest::text("shard_id", shard_id);
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
                oid: RedactedDigest::text("git_commit_oid", &oid_hex),
                timestamp,
                author_name_id,
                author_email_id,
                committer_name_id,
                committer_email_id,
            },
            StoredGitEvent::IdentityDictionary { id, value } => Self::GitIdentityDictionary {
                shard_id,
                identity_id: id,
                value: RedactedDigest::bytes("git_identity_value", &value),
            },
        }
    }

    /// Converts a commit lifecycle marker into a sanitized record, redacting
    /// `shard_id`, `tenant_id`, `policy_hash`, and `item_key`.
    fn from_commit_progress(shard_id: &str, event: CommitProgressRecord) -> Self {
        let shard_id = RedactedDigest::text("shard_id", shard_id);
        let (write_context, item_key, size_hint) = match event {
            CommitProgressRecord::Begin {
                write_context,
                item_key,
                size_hint,
            } => (write_context, item_key, Some(size_hint)),
            CommitProgressRecord::Finish {
                write_context,
                item_key,
            } => (write_context, item_key, None),
        };
        let tenant_id = RedactedDigest::bytes("tenant_id", write_context.tenant_id().as_bytes());
        let policy_hash =
            RedactedDigest::bytes("policy_hash", write_context.policy_hash().as_bytes());
        let run_id = write_context.run_id().as_raw();
        let lease_shard_id = write_context.shard_id().as_raw();
        let fence_epoch = write_context.fence_epoch().as_raw();
        let item_key = RedactedDigest::bytes("item_key", item_key.as_bytes());

        match size_hint {
            Some(size_hint) => Self::CommitBegin {
                shard_id,
                tenant_id,
                policy_hash,
                run_id,
                lease_shard_id,
                fence_epoch,
                item_key,
                size_hint,
            },
            None => Self::CommitFinish {
                shard_id,
                tenant_id,
                policy_hash,
                run_id,
                lease_shard_id,
                fence_epoch,
                item_key,
            },
        }
    }

    /// Extracts the (already redacted) shard ID for error-suppression log context.
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
    use scanner_scheduler::source_kind::SourceKind;
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

    /// Builds the raw event tuples for full-coverage testing. Each tuple is
    /// `(shard_id, event)`. Grouped by recorder category so callers can route
    /// them through either the sanitization layer or the public trait methods.
    #[allow(clippy::type_complexity)]
    fn canary_raw_events(
        canary: &str,
    ) -> (
        Vec<(String, OwnedCoreEvent)>,
        Vec<(String, StoredGitEvent)>,
        Vec<(String, CommitProgressRecord)>,
    ) {
        let canary_item_key =
            ItemKey::try_from_slice(canary.as_bytes()).expect("canary item key should be valid");

        let core = vec![
            (
                format!("finding-shard-{canary}"),
                OwnedCoreEvent::Finding {
                    source: SourceKind::Fs,
                    object_path: canary.as_bytes().to_vec(),
                    start: 10,
                    end: 20,
                    rule_id: 17,
                    rule_name: canary.to_owned(),
                    norm_hash: [0xAB; 32],
                    commit_id: Some(99),
                    change_kind: Some(canary.to_owned()),
                    confidence_score: 7,
                },
            ),
            (
                format!("progress-shard-{canary}"),
                OwnedCoreEvent::Progress {
                    source: SourceKind::Git,
                    stage: "scan",
                    objects_scanned: 100,
                    bytes_scanned: 200,
                    findings_emitted: 3,
                },
            ),
            (
                format!("summary-shard-{canary}"),
                OwnedCoreEvent::Summary {
                    source: SourceKind::Fs,
                    status: "ok",
                    elapsed_ms: 55,
                    bytes_scanned: 1024,
                    findings_emitted: 4,
                    errors: 0,
                    throughput_mib_s: 12.5,
                },
            ),
            (
                format!("diagnostic-shard-{canary}"),
                OwnedCoreEvent::Diagnostic {
                    level: "warn",
                    message: canary.to_owned(),
                },
            ),
        ];
        let git = vec![
            (
                format!("git-commit-shard-{canary}"),
                StoredGitEvent::CommitMeta {
                    commit_id: 17,
                    // Use a distinctive 20-byte pattern (SHA-1 length) whose hex
                    // representation contains the canary's first 8 hex chars.
                    oid_hex: gossip_stdx::HexOid::from_oid_bytes(&[
                        0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
                        0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
                    ]),
                    timestamp: 1234,
                    author_name_id: Some(1),
                    author_email_id: Some(2),
                    committer_name_id: Some(3),
                    committer_email_id: Some(4),
                },
            ),
            (
                format!("git-identity-shard-{canary}"),
                StoredGitEvent::IdentityDictionary {
                    id: 11,
                    value: canary.as_bytes().to_vec(),
                },
            ),
        ];
        let progress = vec![
            (
                format!("commit-begin-shard-{canary}"),
                CommitProgressRecord::Begin {
                    write_context: write_context(),
                    item_key: canary_item_key.clone(),
                    size_hint: Some(64),
                },
            ),
            (
                format!("commit-finish-shard-{canary}"),
                CommitProgressRecord::Finish {
                    write_context: write_context(),
                    item_key: canary_item_key,
                },
            ),
        ];
        (core, git, progress)
    }

    fn full_coverage_records(canary: &str) -> Vec<SanitizedCoordinationRecord> {
        let (core, git, progress) = canary_raw_events(canary);
        let mut records: Vec<SanitizedCoordinationRecord> = Vec::new();
        for (shard_id, event) in core {
            records.push(SanitizedCoordinationRecord::from_core_event(
                &shard_id, event,
            ));
        }
        for (shard_id, event) in git {
            records.push(SanitizedCoordinationRecord::from_git_event(
                &shard_id, event,
            ));
        }
        for (shard_id, event) in progress {
            records.push(SanitizedCoordinationRecord::from_commit_progress(
                &shard_id, event,
            ));
        }
        records
    }

    fn assert_digest_string_is_redacted(display: &str, canary: &str) {
        assert!(display.contains("len="));
        assert!(display.contains("hash="));
        assert!(!display.contains(canary));
    }

    #[test]
    fn redacted_digest_distinguishes_same_length_inputs_and_field_labels() {
        let left = RedactedDigest::text("rule_name", "abcd");
        let right = RedactedDigest::text("rule_name", "wxyz");
        let relabeled = RedactedDigest::text("object_path", "abcd");

        assert_ne!(left, right);
        assert_ne!(left, relabeled);
        assert_eq!(left.len, right.len);
        assert_eq!(left.len, relabeled.len);
    }

    #[test]
    fn redacted_digest_is_deterministic_and_text_bytes_equivalent() {
        let a = RedactedDigest::text("shard_id", "abc");
        let b = RedactedDigest::text("shard_id", "abc");
        assert_eq!(a, b);

        let text = RedactedDigest::text("field", "hello");
        let bytes = RedactedDigest::bytes("field", b"hello");
        assert_eq!(text, bytes);
    }

    #[test]
    fn redacted_digest_handles_empty_input() {
        let empty = RedactedDigest::bytes("field", &[]);
        assert_eq!(empty.len, 0);
        let nonempty = RedactedDigest::bytes("field", &[1]);
        assert_ne!(empty, nonempty);
    }

    #[test]
    fn redacted_digest_display_format_is_stable() {
        let d = RedactedDigest::text("shard_id", "test");
        let s = d.to_string();
        assert!(s.starts_with("len=4,hash="));
        // 16 hex chars for the 64-bit hash
        assert_eq!(s.len(), "len=4,hash=".len() + 16);
    }

    #[test]
    fn redacted_digest_reset_clears_state_between_calls() {
        let first = RedactedDigest::bytes("field", b"alpha");
        let second = RedactedDigest::bytes("field", b"beta");
        let reference = RedactedDigest::bytes("field", b"beta");

        assert_ne!(
            first, second,
            "different inputs should produce different digests"
        );
        assert_eq!(
            second, reference,
            "reset() must fully clear state from the previous call"
        );
    }

    #[test]
    fn sanitized_records_hash_toxic_fields() {
        let canary = secret_canary();

        for record in full_coverage_records(&canary) {
            let debug = format!("{record:?}");
            assert!(!debug.contains(&canary));

            match record {
                SanitizedCoordinationRecord::CoreFinding {
                    shard_id,
                    object_path,
                    rule_name,
                    change_kind,
                    ..
                } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&object_path.to_string(), &canary);
                    assert_digest_string_is_redacted(&rule_name.to_string(), &canary);
                    assert_digest_string_is_redacted(
                        &change_kind.expect("finding change kind").to_string(),
                        &canary,
                    );
                }
                SanitizedCoordinationRecord::CoreProgress { shard_id, .. } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                }
                SanitizedCoordinationRecord::CoreSummary { shard_id, .. } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                }
                SanitizedCoordinationRecord::CoreDiagnostic {
                    shard_id,
                    diagnostic_message,
                    ..
                } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&diagnostic_message.to_string(), &canary);
                }
                SanitizedCoordinationRecord::GitCommitMeta { shard_id, oid, .. } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&oid.to_string(), &canary);
                }
                SanitizedCoordinationRecord::GitIdentityDictionary {
                    shard_id, value, ..
                } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&value.to_string(), &canary);
                }
                SanitizedCoordinationRecord::CommitBegin {
                    shard_id,
                    tenant_id,
                    policy_hash,
                    item_key,
                    ..
                } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&tenant_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&policy_hash.to_string(), &canary);
                    assert_digest_string_is_redacted(&item_key.to_string(), &canary);
                }
                SanitizedCoordinationRecord::CommitFinish {
                    shard_id,
                    tenant_id,
                    policy_hash,
                    item_key,
                    ..
                } => {
                    assert_digest_string_is_redacted(&shard_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&tenant_id.to_string(), &canary);
                    assert_digest_string_is_redacted(&policy_hash.to_string(), &canary);
                    assert_digest_string_is_redacted(&item_key.to_string(), &canary);
                }
            }
        }
    }

    #[test]
    fn sanitized_core_finding_drops_norm_hash() {
        let record = SanitizedCoordinationRecord::from_core_event(
            "shard",
            OwnedCoreEvent::Finding {
                source: SourceKind::Fs,
                object_path: b"path".to_vec(),
                start: 0,
                end: 10,
                rule_id: 1,
                rule_name: "rule".to_owned(),
                norm_hash: [0xDE; 32],
                commit_id: None,
                change_kind: None,
                confidence_score: 5,
            },
        );

        let debug = format!("{record:?}");
        assert!(
            !debug.contains("norm_hash"),
            "sanitized telemetry must drop norm_hash, got: {debug}"
        );
        assert!(
            !debug.contains("222, 222, 222"),
            "sanitized telemetry must not leak norm_hash bytes, got: {debug}"
        );
    }

    #[test]
    fn tracing_sink_never_logs_raw_canary_bytes() {
        let recorder = ProductionCoordinationEventRecorder::default();
        let canary = secret_canary();
        let (core, git, progress) = canary_raw_events(&canary);
        let logs = capture_logs(Level::TRACE, || {
            for (shard_id, event) in core {
                recorder
                    .record_core_event(&shard_id, event)
                    .expect("core telemetry should be best-effort");
            }
            for (shard_id, event) in git {
                recorder
                    .record_git_event(&shard_id, event)
                    .expect("git telemetry should be best-effort");
            }
            for (shard_id, event) in progress {
                recorder
                    .record_commit_progress(&shard_id, event)
                    .expect("progress telemetry should be best-effort");
            }
        });

        for event_name in [
            "coordination_core_finding",
            "coordination_core_progress",
            "coordination_core_summary",
            "coordination_core_diagnostic",
            "coordination_git_commit_meta",
            "coordination_git_identity_dictionary",
            "coordination_commit_begin",
            "coordination_commit_finish",
        ] {
            assert!(logs.contains(event_name), "missing {event_name} from logs");
        }
        assert!(logs.contains("hash="));
        assert!(logs.contains("len="));
        assert!(!logs.contains(&canary));
    }

    #[test]
    fn recorder_suppresses_repeated_sink_failures_per_category() {
        #[derive(Debug)]
        struct FailingSink;

        impl CoordinationTelemetrySink for FailingSink {
            fn emit(&self, _record: SanitizedCoordinationRecord) -> Result<()> {
                anyhow::bail!("simulated sink failure")
            }
        }

        let canary = secret_canary();
        let recorder = ProductionCoordinationEventRecorder::with_sink(Arc::new(FailingSink));
        let core_shard = RedactedDigest::text("shard_id", "core-shard").to_string();
        let git_shard = RedactedDigest::text("shard_id", "git-shard").to_string();
        let progress_shard = RedactedDigest::text("shard_id", "progress-shard").to_string();

        let logs = capture_logs(Level::WARN, || {
            for _ in 0..4 {
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
            for _ in 0..4 {
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
            for _ in 0..4 {
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

        assert_eq!(
            logs.matches("coordination_recorder_sink_failure").count(),
            3
        );
        assert_eq!(logs.matches(&core_shard).count(), 1);
        assert_eq!(logs.matches(&git_shard).count(), 1);
        assert_eq!(logs.matches(&progress_shard).count(), 1);
        assert!(logs.contains("hash="));
        assert!(!logs.contains(&canary));
    }

    #[test]
    fn tracing_sink_renders_none_optional_fields() {
        let recorder = ProductionCoordinationEventRecorder::default();
        let canary = secret_canary();
        let logs = capture_logs(Level::TRACE, || {
            // CoreFinding with commit_id: None, change_kind: None
            recorder
                .record_core_event(
                    "none-finding-shard",
                    OwnedCoreEvent::Finding {
                        source: SourceKind::Fs,
                        object_path: b"path".to_vec(),
                        start: 0,
                        end: 10,
                        rule_id: 1,
                        rule_name: "rule".to_owned(),
                        norm_hash: [0xBC; 32],
                        commit_id: None,
                        change_kind: None,
                        confidence_score: 5,
                    },
                )
                .expect("finding with None fields should succeed");

            // GitCommitMeta with all four identity IDs as None
            recorder
                .record_git_event(
                    "none-git-shard",
                    StoredGitEvent::CommitMeta {
                        commit_id: 1,
                        oid_hex: gossip_stdx::HexOid::from_oid_bytes(&[0xAB, 0xC1, 0x23]),
                        timestamp: 100,
                        author_name_id: None,
                        author_email_id: None,
                        committer_name_id: None,
                        committer_email_id: None,
                    },
                )
                .expect("git commit meta with None identity IDs should succeed");

            // CommitBegin with size_hint: None
            recorder
                .record_commit_progress(
                    "none-progress-shard",
                    CommitProgressRecord::Begin {
                        write_context: write_context(),
                        item_key: ItemKey::try_from_slice(b"item-key")
                            .expect("item key should be valid"),
                        size_hint: None,
                    },
                )
                .expect("commit begin with None size_hint should succeed");
        });

        // Verify specific structured fields render as "none" — tying the
        // assertion to the exact OptionalField usage rather than a bare
        // substring that could match unrelated log output.
        for field in ["commit_id=none", "change_kind=none", "size_hint=none"] {
            assert!(
                logs.contains(field),
                "OptionalField::None should render as \"{field}\" in tracing output, \
                 but captured logs were: {logs}",
            );
        }
        assert!(
            !logs.contains(&canary),
            "canary must not leak into tracing output",
        );
    }

    #[test]
    fn emit_diagnostic_routes_each_level_to_correct_tracing_level() {
        let cases: &[(&str, &str)] = &[
            ("error", "ERROR"),
            ("fatal", "ERROR"),
            ("warn", "WARN"),
            ("warning", "WARN"),
            ("debug", "DEBUG"),
            ("trace", "TRACE"),
            ("info", "INFO"),
            ("unknown_level", "INFO"),
        ];

        for &(input_level, expected_output) in cases {
            let recorder = ProductionCoordinationEventRecorder::default();
            let logs = capture_logs(Level::TRACE, || {
                recorder
                    .record_core_event(
                        "diag-level-shard",
                        OwnedCoreEvent::Diagnostic {
                            level: input_level,
                            message: format!("msg-for-{input_level}"),
                        },
                    )
                    .expect("diagnostic telemetry should be best-effort");
            });

            assert!(
                logs.contains(expected_output),
                "input level {input_level:?} should route to tracing level {expected_output}, \
                 but captured logs were: {logs}",
            );
            assert!(
                logs.contains("coordination_core_diagnostic"),
                "diagnostic event name missing for input level {input_level:?}",
            );
        }
    }
}
