//! Coordination-backed event sink for distributed scans.
//!
//! This sink captures both scheduler core events and git-specific events and
//! forwards owned copies to a coordinator-facing recorder. Recorder failures are
//! intentionally non-fatal for event emission: authoritative durability is
//! enforced by the receipt-driven commit pipeline (`ReceiptCommitSink` ->
//! `ResultCommitter`), while event recording remains best-effort telemetry.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::Result;
use gossip_contracts::connector::ItemKey;
use gossip_contracts::persistence::WriteContext;
use scanner_git::{GitEvent, GitEventOutput};
use scanner_scheduler::events::{CoreEvent, EventOutput};

use crate::OwnedCoreEvent;

/// Owned git event representation persisted by distributed sinks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredGitEvent {
    /// Metadata for a single commit (OID, timestamp, identity dictionary IDs).
    CommitMeta {
        commit_id: u32,
        oid_hex: String,
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

/// Closed set of low-cardinality Git execution stage signals.
///
/// These signals let operators distinguish the claim, mirror, execution,
/// durable-receipt, checkpoint, and lease-loss boundaries for one repo-frontier
/// shard without emitting raw repository-identifying data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageSignal {
    /// The worker claimed a shard lease.
    ///
    /// `latency_ms` is the elapsed wall time spent waiting on claim.
    ShardClaimed { latency_ms: u64 },
    /// Mirror acquisition or refresh finished for the claimed repo.
    ///
    /// `latency_ms` is the wall-clock duration of the mirror step.
    /// `error_class` is a closed-set retry posture when mirror sync failed;
    /// `None` means the mirror step succeeded.
    MirrorSyncCompleted {
        latency_ms: u64,
        error_class: Option<&'static str>,
    },
    /// Repo-native scan execution finished.
    ///
    /// `latency_ms` is the wall-clock duration of the execution step.
    /// `items_scanned` and `bytes_scanned` are passthrough aggregate counters.
    ScanCompleted {
        latency_ms: u64,
        items_scanned: u64,
        bytes_scanned: u64,
    },
    /// Durable findings + done-ledger receipt submission finished.
    ///
    /// `latency_ms` is the wall-clock duration of the receipt step.
    /// `receipts` is the number of authoritative receipt families confirmed.
    DurableReceiptCompleted { latency_ms: u64, receipts: u64 },
    /// The outer coordinator checkpoint/complete call finished.
    ///
    /// `latency_ms` is the wall-clock duration of the shard-advance step.
    CheckpointAdvanced { latency_ms: u64 },
    /// The worker can no longer trust the claimed lease.
    ///
    /// `reason` is a closed, low-cardinality discriminant.
    LeaseUncertaintyObserved { reason: &'static str },
}

/// Coordinator-facing recorder for distributed scan output.
pub trait CoordinationEventRecorder: Send + Sync + fmt::Debug {
    /// Persists a scanner core event (finding, progress, summary, diagnostic).
    fn record_core_event(&self, shard_id: &str, event: OwnedCoreEvent) -> Result<()>;
    /// Persists a git-specific event (commit metadata or identity dictionary entry).
    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()>;
    /// Persists a commit lifecycle progress marker (begin/finish).
    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()>;
    /// Persists a low-cardinality Git stage signal.
    ///
    /// Recorder failures remain non-fatal for callers; stage telemetry follows
    /// the same best-effort contract as core, git, and progress events.
    fn record_stage_signal(&self, shard_id: &str, signal: StageSignal) -> Result<()>;
}

/// Map a sentinel identity ID to `None`, real IDs to `Some`.
fn sentinel_to_option(id: u32) -> Option<u32> {
    (id != scanner_git::SENTINEL_ID).then_some(id)
}

/// Distributed event sink that forwards events to a coordinator recorder.
///
/// Recorder errors are non-fatal. The first failure for each event kind
/// (core / git / stage) is logged; subsequent failures are suppressed to avoid
/// flooding logs during sustained recorder outages.
pub struct CoordinationEventSink {
    shard_id: Arc<str>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    core_error_logged: AtomicBool,
    git_error_logged: AtomicBool,
    stage_error_logged: AtomicBool,
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
            stage_error_logged: AtomicBool::new(false),
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

    /// Emit one best-effort stage signal for the current shard.
    pub(crate) fn emit_stage_signal(&self, signal: StageSignal) {
        if let Err(error) = self.recorder.record_stage_signal(&self.shard_id, signal) {
            self.warn_recorder_failure(
                &self.stage_error_logged,
                error,
                "recorder failed to persist stage signal; subsequent failures suppressed",
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
                oid_hex: gossip_stdx::hex_encode(meta.commit_oid.as_slice()),
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

/// Wrapper around [`CoordinationEventSink`] that counts `Finding` events
/// while forwarding all events to the inner sink unchanged.
///
/// The count is retrieved via [`detected_finding_count`](Self::detected_finding_count)
/// after the scan completes. The caller uses this count to decide whether
/// the shard checkpoint can safely advance (zero findings) or must be
/// rejected (nonzero findings without durable persistence).
///
/// The counter uses `Relaxed` ordering because it is only read after the scan
/// thread joins (establishing a happens-before via `std::thread::scope`), so
/// the final value is always visible to the reader.
pub(crate) struct FindingsCaptureSink {
    inner: Arc<CoordinationEventSink>,
    finding_count: AtomicU64,
}

impl FindingsCaptureSink {
    /// Wrap an existing coordination event sink with a findings counter.
    pub(crate) fn new(inner: Arc<CoordinationEventSink>) -> Self {
        Self {
            inner,
            finding_count: AtomicU64::new(0),
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
}

impl EventOutput for FindingsCaptureSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        if matches!(event, CoreEvent::Finding(_)) {
            self.finding_count.fetch_add(1, Ordering::Relaxed);
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
        stage_signals: Mutex<Vec<(String, StageSignal)>>,
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

        fn record_stage_signal(&self, shard_id: &str, signal: StageSignal) -> Result<()> {
            self.stage_signals
                .lock()
                .unwrap()
                .push((shard_id.to_owned(), signal));
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
            norm_hash: Some([0xAA; 32]),
            commit_id: None,
            change_kind: None,
            confidence_score: 85,
        })
    }

    #[test]
    fn sink_forwards_stage_signals_to_recorder() {
        let recorder = Arc::new(TestRecorder::default());
        let sink = CoordinationEventSink::new(
            Arc::clone(&recorder) as Arc<dyn CoordinationEventRecorder>,
            Arc::from("stage-shard"),
        );

        sink.emit_stage_signal(StageSignal::MirrorSyncCompleted {
            latency_ms: 17,
            error_class: Some("retryable"),
        });

        let forwarded = recorder.stage_signals.lock().unwrap();
        assert_eq!(forwarded.len(), 1, "stage signal should be forwarded");
        assert_eq!(forwarded[0].0, "stage-shard");
        assert_eq!(
            forwarded[0].1,
            StageSignal::MirrorSyncCompleted {
                latency_ms: 17,
                error_class: Some("retryable"),
            }
        );
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
                assert_eq!(*norm_hash, Some([0xAA; 32]));
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
