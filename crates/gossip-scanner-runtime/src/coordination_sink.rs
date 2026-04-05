//! Coordination-backed event sink for distributed scans.
//!
//! This sink captures both scheduler core events and git-specific events and
//! forwards owned copies to a coordinator-facing recorder. Recorder failures are
//! intentionally non-fatal for event emission: authoritative durability is
//! enforced by the receipt-driven commit pipeline (`ReceiptCommitSink` ->
//! `ResultCommitter`), while event recording remains best-effort telemetry.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use gossip_contracts::connector::ItemKey;
use gossip_contracts::identity::NormHash;
use gossip_contracts::persistence::{PersistenceFinding, WriteContext};
use gossip_stdx::HexOid;
use scanner_git::{GitEvent, GitEventOutput};
use scanner_scheduler::events::{CoreEvent, EventOutput};

use crate::OwnedCoreEvent;

/// Owned git event representation persisted by distributed sinks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredGitEvent {
    /// Metadata for a single commit (OID, timestamp, identity dictionary IDs).
    CommitMeta {
        commit_id: u32,
        oid_hex: HexOid,
        timestamp: u64,
        author_name_id: Option<u32>,
        author_email_id: Option<u32>,
        committer_name_id: Option<u32>,
        committer_email_id: Option<u32>,
    },
    /// An entry in the identity dictionary mapping IDs to raw name/email bytes.
    IdentityDictionary { id: u32, value: Vec<u8> },
}

/// Commit lifecycle progress markers emitted by commit sinks.
///
/// These are best-effort telemetry events for observability; authoritative
/// durability is enforced by the receipt-driven commit pipeline
/// (`ReceiptCommitSink` -> `ResultCommitter`), not by these markers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitProgressRecord {
    /// Item processing has started; `size_hint` is the expected byte length.
    Begin {
        write_context: WriteContext,
        item_key: ItemKey,
        size_hint: Option<u64>,
    },
    /// Item processing completed successfully.
    Finish {
        write_context: WriteContext,
        item_key: ItemKey,
    },
}

/// Coordinator-facing recorder for distributed scan output.
pub trait CoordinationEventRecorder: Send + Sync + fmt::Debug {
    /// Persists a scanner core event (finding, progress, summary, diagnostic).
    fn record_core_event(&self, shard_id: &str, event: OwnedCoreEvent) -> Result<()>;
    /// Persists a git-specific event (commit metadata or identity dictionary entry).
    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()>;
    /// Persists a commit lifecycle progress marker (begin/finish).
    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()>;
}

/// Map a sentinel identity ID to `None`, real IDs to `Some`.
fn sentinel_to_option(id: u32) -> Option<u32> {
    (id != scanner_git::SENTINEL_ID).then_some(id)
}

/// Persistence-ready representation of one Git finding observed during scan
/// execution.
///
/// `span_start` and `span_end` are blob-level byte offsets captured from
/// `FindingEvent::start/end`. For Git findings these correspond to
/// `FindingKey::start/end` (root-hint coordinates within the blob). The FS
/// path uses decoded-buffer match spans for the same trait methods, so
/// cross-source identity convergence is guaranteed only for non-transformed
/// findings (the common case).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GitFindingForPersistence {
    pub(crate) span_start: u64,
    pub(crate) span_end: u64,
    pub(crate) norm_hash: NormHash,
    pub(crate) rule_id: u32,
}

const _: () = assert!(std::mem::size_of::<GitFindingForPersistence>() <= 56);

impl fmt::Debug for GitFindingForPersistence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitFindingForPersistence")
            .field("span_start", &self.span_start)
            .field("span_end", &self.span_end)
            .field("norm_hash", &"[redacted]")
            .field("rule_id", &self.rule_id)
            .finish()
    }
}

impl PersistenceFinding for GitFindingForPersistence {
    #[inline]
    fn rule_id(&self) -> u32 {
        self.rule_id
    }

    #[inline]
    fn norm_hash(&self) -> NormHash {
        self.norm_hash
    }

    #[inline]
    fn span_start(&self) -> u64 {
        self.span_start
    }

    #[inline]
    fn span_end(&self) -> u64 {
        self.span_end
    }
}

/// Distributed event sink that forwards events to a coordinator recorder.
///
/// Recorder errors are non-fatal. The first failure for each event kind
/// (core / git) is logged; subsequent failures are suppressed to avoid
/// flooding logs during sustained recorder outages.
pub struct CoordinationEventSink {
    shard_id: Arc<str>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    core_error_logged: AtomicBool,
    git_error_logged: AtomicBool,
}

impl CoordinationEventSink {
    /// Creates a sink that forwards events to `recorder` tagged with `shard_id`.
    #[must_use]
    pub fn new(recorder: Arc<dyn CoordinationEventRecorder>, shard_id: Arc<str>) -> Self {
        Self {
            shard_id,
            recorder,
            core_error_logged: AtomicBool::new(false),
            git_error_logged: AtomicBool::new(false),
        }
    }

    fn warn_recorder_failure(
        &self,
        error_flag: &AtomicBool,
        error: anyhow::Error,
        message: &'static str,
    ) {
        if !error_flag.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                shard_id = %self.shard_id,
                %error,
                "{message}",
            );
        }
    }
}

impl EventOutput for CoordinationEventSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let owned = OwnedCoreEvent::from_core(event);
        if let Err(error) = self.recorder.record_core_event(&self.shard_id, owned) {
            self.warn_recorder_failure(
                &self.core_error_logged,
                error,
                "recorder failed to persist core event; subsequent failures suppressed",
            );
        }
    }

    fn flush(&self) {}
}

impl GitEventOutput for CoordinationEventSink {
    fn emit_git(&self, event: GitEvent<'_>) {
        let owned = match event {
            GitEvent::CommitMeta(meta) => StoredGitEvent::CommitMeta {
                commit_id: meta.commit_id,
                oid_hex: HexOid::from_oid_bytes(meta.commit_oid.as_slice()),
                timestamp: meta.timestamp,
                author_name_id: meta
                    .identity
                    .and_then(|ids| sentinel_to_option(ids.author_name)),
                author_email_id: meta
                    .identity
                    .and_then(|ids| sentinel_to_option(ids.author_email)),
                committer_name_id: meta
                    .identity
                    .and_then(|ids| sentinel_to_option(ids.committer_name)),
                committer_email_id: meta
                    .identity
                    .and_then(|ids| sentinel_to_option(ids.committer_email)),
            },
            GitEvent::IdentityDictionary(entry) => StoredGitEvent::IdentityDictionary {
                id: entry.id,
                value: entry.value.to_vec(),
            },
        };

        if let Err(error) = self.recorder.record_git_event(&self.shard_id, owned) {
            self.warn_recorder_failure(
                &self.git_error_logged,
                error,
                "recorder failed to persist git event; subsequent failures suppressed",
            );
        }
    }
}

/// Wrapper around [`CoordinationEventSink`] that counts and captures `Finding`
/// events while forwarding all events to the inner sink unchanged.
///
/// The count and captured finding payloads are retrieved after the scan
/// completes. The Git repo-frontier worker uses the captured findings to route
/// git detections through the same persistence translation path used by
/// filesystem scans.
///
/// The counter uses `Relaxed` ordering because it is only read after the scan
/// thread joins (establishing a happens-before via `std::thread::scope`), so
/// the final value is always visible to the reader. Captured findings are
/// stored behind a `Mutex<Vec<_>>` because pack workers emit findings from
/// multiple threads during git scans.
/// The lock is held only for a single `Vec::push` per finding (~nanoseconds),
/// so contention is negligible for typical sparse-findings repositories. For
/// finding-dense repos under high pack-worker parallelism, per-worker local
/// collection merged post-join would eliminate contention entirely.
pub(crate) struct FindingsCaptureSink {
    inner: Arc<CoordinationEventSink>,
    finding_count: AtomicU64,
    /// Captured finding data for persistence. Guarded by Mutex because
    /// pack workers emit findings from multiple threads. Per-finding lock
    /// acquisition is acceptable: most repos have zero or few findings.
    /// For high-finding-density repos, consider per-adapter local collection
    /// merged post-join.
    captured_findings: Mutex<Vec<GitFindingForPersistence>>,
}

impl FindingsCaptureSink {
    /// Wrap an existing coordination event sink with a findings counter.
    pub(crate) fn new(inner: Arc<CoordinationEventSink>) -> Self {
        Self {
            inner,
            finding_count: AtomicU64::new(0),
            // Small initial capacity avoids the first three reallocation cycles
            // (0 -> 1 -> 2 -> 4 -> 8) under the lock. Most repos produce zero
            // findings, but when findings do occur they tend to cluster.
            captured_findings: Mutex::new(Vec::with_capacity(8)),
        }
    }

    /// Return the number of `Finding` events observed during the scan.
    ///
    /// Intended to be called after the scan thread has joined, so the count
    /// reflects the full scan. The `Relaxed` load is safe because the thread
    /// join provides the necessary happens-before synchronization.
    pub(crate) fn detected_finding_count(&self) -> u64 {
        self.finding_count.load(Ordering::Relaxed)
    }

    /// Drain the captured findings accumulated during scan execution.
    pub(crate) fn take_captured_findings(&self) -> Vec<GitFindingForPersistence> {
        let mut guard = self
            .captured_findings
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        std::mem::take(&mut *guard)
    }
}

impl EventOutput for FindingsCaptureSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        if let CoreEvent::Finding(finding) = &event {
            self.finding_count.fetch_add(1, Ordering::Relaxed);
            // Build the persistence struct outside the lock. `from_digest`
            // is a byte copy, but keeping construction out of the critical
            // section means any future work (validation, hashing) added to
            // the constructor won't widen the lock window.
            let record = GitFindingForPersistence {
                span_start: finding.start,
                span_end: finding.end,
                norm_hash: NormHash::from_digest(finding.norm_hash),
                rule_id: finding.rule_id,
            };
            self.captured_findings
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(record);
        }
        // Forward the borrowed event directly to the inner sink, which
        // performs its own `OwnedCoreEvent::from_core` conversion exactly
        // once. This avoids the double-conversion that would result from
        // calling `from_core` here and then `emit_into`.
        self.inner.emit_core(event);
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

impl GitEventOutput for FindingsCaptureSink {
    fn emit_git(&self, event: GitEvent<'_>) {
        self.inner.emit_git(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use scanner_scheduler::events::{DiagnosticEvent, FindingEvent, ProgressEvent};
    use scanner_scheduler::source_kind::SourceKind;

    /// Test recorder that captures all event kinds for assertion.
    #[derive(Debug, Default)]
    struct TestRecorder {
        core_events: Mutex<Vec<OwnedCoreEvent>>,
        git_events: Mutex<Vec<StoredGitEvent>>,
    }

    impl CoordinationEventRecorder for TestRecorder {
        fn record_core_event(&self, _shard_id: &str, event: OwnedCoreEvent) -> Result<()> {
            self.core_events.lock().unwrap().push(event);
            Ok(())
        }

        fn record_git_event(&self, _shard_id: &str, event: StoredGitEvent) -> Result<()> {
            self.git_events.lock().unwrap().push(event);
            Ok(())
        }

        fn record_commit_progress(
            &self,
            _shard_id: &str,
            _event: CommitProgressRecord,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn make_sink_and_recorder() -> (FindingsCaptureSink, Arc<TestRecorder>) {
        let recorder = Arc::new(TestRecorder::default());
        let inner = Arc::new(CoordinationEventSink::new(
            Arc::clone(&recorder) as Arc<dyn CoordinationEventRecorder>,
            Arc::from("test-shard"),
        ));
        let sink = FindingsCaptureSink::new(inner);
        (sink, recorder)
    }

    fn finding_event() -> CoreEvent<'static> {
        CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"/tmp/secret.txt",
            start: 10,
            end: 42,
            rule_id: 7,
            rule_name: "test-rule",
            norm_hash: [0xAA; 32],
            commit_id: None,
            change_kind: None,
            confidence_score: 85,
        })
    }

    fn progress_event() -> CoreEvent<'static> {
        CoreEvent::Progress(ProgressEvent {
            source: SourceKind::Fs,
            stage: "scanning",
            objects_scanned: 100,
            bytes_scanned: 2048,
            findings_emitted: 1,
        })
    }

    fn diagnostic_event() -> CoreEvent<'static> {
        CoreEvent::Diagnostic(DiagnosticEvent {
            level: "warn",
            message: "something happened",
        })
    }

    #[test]
    fn findings_capture_sink_counts_finding_events() {
        let (sink, recorder) = make_sink_and_recorder();

        sink.emit_core(finding_event());

        assert_eq!(
            sink.detected_finding_count(),
            1,
            "should count exactly one finding"
        );

        let forwarded = recorder.core_events.lock().unwrap();
        assert_eq!(
            forwarded.len(),
            1,
            "inner sink should also receive the finding"
        );
        match &forwarded[0] {
            OwnedCoreEvent::Finding { norm_hash, .. } => {
                assert_eq!(*norm_hash, [0xAA; 32]);
            }
            other => panic!("expected finding event, got: {other:?}"),
        }
    }

    #[test]
    fn findings_capture_sink_skips_non_finding_events() {
        let (sink, recorder) = make_sink_and_recorder();

        sink.emit_core(progress_event());
        sink.emit_core(diagnostic_event());

        assert_eq!(
            sink.detected_finding_count(),
            0,
            "non-finding events must not be counted"
        );

        let forwarded = recorder.core_events.lock().unwrap();
        assert_eq!(
            forwarded.len(),
            2,
            "inner sink should still receive all events"
        );
        assert!(matches!(forwarded[0], OwnedCoreEvent::Progress { .. }));
        assert!(matches!(forwarded[1], OwnedCoreEvent::Diagnostic { .. }));
    }

    #[test]
    fn findings_capture_sink_counts_multiple_findings() {
        let (sink, _recorder) = make_sink_and_recorder();

        sink.emit_core(finding_event());
        sink.emit_core(finding_event());

        assert_eq!(
            sink.detected_finding_count(),
            2,
            "should count both findings"
        );
    }

    #[test]
    fn findings_capture_sink_captures_finding_data() {
        let (sink, _recorder) = make_sink_and_recorder();

        sink.emit_core(finding_event());

        let captured = sink.take_captured_findings();
        assert_eq!(captured.len(), 1, "finding payload should be captured");
        assert_eq!(captured[0].rule_id(), 7);
        assert_eq!(captured[0].span_start(), 10);
        assert_eq!(captured[0].span_end(), 42);
        assert_eq!(captured[0].norm_hash(), NormHash::from_digest([0xAA; 32]));
    }

    #[test]
    fn git_finding_for_persistence_debug_redacts_norm_hash() {
        let finding = GitFindingForPersistence {
            span_start: 1,
            span_end: 9,
            norm_hash: NormHash::from_digest([0xFF; 32]),
            rule_id: 2,
        };

        let debug = format!("{finding:?}");
        assert!(
            debug.contains("[redacted]"),
            "Debug output must redact norm_hash, got: {debug}"
        );
        assert!(
            debug.contains(r#"norm_hash: "[redacted]""#),
            "Debug output must show redacted norm_hash field, got: {debug}"
        );
    }

    #[test]
    fn findings_capture_sink_forwards_git_events() {
        let (sink, recorder) = make_sink_and_recorder();

        let oid = scanner_git::OidBytes::sha1([0xab; 20]);
        sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
            commit_id: 1,
            commit_oid: oid,
            timestamp: 1_700_000_000,
            identity: None,
        }));

        let forwarded = recorder.git_events.lock().unwrap();
        assert_eq!(
            forwarded.len(),
            1,
            "inner sink should receive the git event"
        );
        assert!(matches!(forwarded[0], StoredGitEvent::CommitMeta { .. }));
    }

    #[test]
    fn findings_capture_sink_flush_delegates() {
        let (sink, _recorder) = make_sink_and_recorder();

        // CoordinationEventSink::flush is a no-op, so this verifies the
        // delegation path completes without error or panic.
        sink.flush();
    }
}
