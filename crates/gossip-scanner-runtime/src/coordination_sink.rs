//! Coordination-backed event sink for distributed scans.
//!
//! This sink captures both scheduler core events and git-specific events and
//! forwards owned copies to a coordinator-facing recorder. The findings wrapper
//! layered on top also accumulates the sparse commit-ordinal lookup required by
//! Git findings translation. Recorder failures are intentionally non-fatal for
//! event emission: authoritative durability is enforced by the receipt-driven
//! commit pipeline (`ReceiptCommitSink` -> `ResultCommitter`), while event
//! recording remains best-effort telemetry.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use gossip_contracts::connector::{ItemKey, ToxicDigest};
use gossip_contracts::persistence::WriteContext;
use scanner_git::{GitEvent, GitEventOutput, OidBytes};
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

/// Closed-set mirror-sync error posture for stage telemetry.
///
/// Maps from the connector-level [`ErrorClass`](gossip_contracts::connector::ErrorClass)
/// (which is `#[non_exhaustive]`) to a fixed set of telemetry labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorErrorClass {
    Retryable,
    Permanent,
    /// Forward-compatibility bucket for unknown `ErrorClass` variants.
    Other,
}

impl MirrorErrorClass {
    /// Returns the static label used in tracing fields and dashboards.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Permanent => "permanent",
            Self::Other => "other",
        }
    }
}

/// Closed-set lease-uncertainty reason for stage telemetry.
///
/// Maps from the runtime-level [`LeaseUncertainty`](super::distributed::LeaseUncertainty)
/// variants to fixed telemetry labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseUncertaintyReason {
    DeadlineElapsed,
    StaleFence,
    LeaseExpired,
}

impl LeaseUncertaintyReason {
    /// Returns the static label used in tracing fields and dashboards.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeadlineElapsed => "deadline_elapsed",
            Self::StaleFence => "stale_fence",
            Self::LeaseExpired => "lease_expired",
        }
    }
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
    /// `None` means the mirror step succeeded.
    MirrorSyncCompleted {
        latency_ms: u64,
        error_class: Option<MirrorErrorClass>,
    },
    /// Repo-native scan execution finished.
    ///
    /// `latency_ms` is the wall-clock duration of the execution step.
    /// `items_scanned` and `bytes_scanned` are passthrough aggregate counters.
    /// `None` means the scan failed before counters were available (partial
    /// progress unknown); `Some(0)` means the scan completed with zero items.
    ScanCompleted {
        latency_ms: u64,
        items_scanned: Option<u64>,
        bytes_scanned: Option<u64>,
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
    LeaseUncertaintyObserved { reason: LeaseUncertaintyReason },
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
    /// Pre-computed digest of `shard_id` for log-safe error messages.
    /// Raw shard identifiers may contain repository-identifying data and must
    /// not appear in log output.
    redacted_shard_id: ToxicDigest,
    recorder: Arc<dyn CoordinationEventRecorder>,
    core_error_logged: AtomicBool,
    git_error_logged: AtomicBool,
    stage_error_logged: AtomicBool,
}

impl CoordinationEventSink {
    /// Creates a sink that forwards events to `recorder` tagged with `shard_id`.
    #[must_use]
    pub fn new(recorder: Arc<dyn CoordinationEventRecorder>, shard_id: Arc<str>) -> Self {
        let redacted_shard_id = ToxicDigest::of_bytes(shard_id.as_bytes());
        Self {
            shard_id,
            redacted_shard_id,
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
                shard_id = %self.redacted_shard_id,
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

    /// Returns the pre-computed digest of the shard identifier for log-safe
    /// error messages. Raw shard identifiers may contain repository-identifying
    /// data and must not appear in log output.
    pub(crate) fn redacted_shard_id(&self) -> &ToxicDigest {
        &self.redacted_shard_id
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

/// Wrapper around [`CoordinationEventSink`] that counts `Finding` events,
/// captures Git commit OIDs, and forwards all events to the inner sink
/// unchanged.
///
/// The caller drains both capture paths after the scan thread joins:
/// [`detected_finding_count`](Self::detected_finding_count) reports how many
/// findings were emitted, and [`drain_commit_oid_map`](Self::drain_commit_oid_map)
/// returns the sparse `commit_id -> OidBytes` lookup populated from
/// `GitEvent::CommitMeta`. Git findings translation uses that lookup to
/// resolve per-scan ordinals into stable commit identities.
///
/// Both capture paths are additive: every event is still forwarded exactly once
/// to the inner sink. The counter uses `Relaxed` ordering because it is only
/// read after the scan thread joins (establishing a happens-before via
/// `std::thread::scope`), so the final value is always visible to the reader.
pub(crate) struct FindingsCaptureSink {
    inner: Arc<CoordinationEventSink>,
    finding_count: AtomicU64,
    /// Sparse mapping from finding `commit_id` ordinals to stable commit OIDs.
    ///
    /// Populated from `GitEvent::CommitMeta` and drained after the scan joins.
    /// A `Mutex` keeps the capture path aligned with the crate's poisoning
    /// recovery conventions; contention stays low because scanner-git guarantees
    /// at most one `CommitMeta` event per `commit_id` (gated by `AtomicBitSet`
    /// in `CommitMetaContext`).
    commit_oid_map: Mutex<HashMap<u32, OidBytes>>,
}

impl FindingsCaptureSink {
    /// Defense-in-depth ceiling for the sparse commit-OID lookup.
    ///
    /// At roughly 50 bytes per entry (u32 key + 33-byte OidBytes + hashbrown
    /// control and alignment overhead), 500K entries consume ~25 MB — well
    /// above any realistic scan but prevents a pathological repository from
    /// exhausting worker memory.
    #[cfg(not(test))]
    const MAX_COMMIT_OID_MAP_ENTRIES: usize = 500_000;

    /// Test-only ceiling small enough to exercise the capacity guard without
    /// inserting hundreds of thousands of entries.
    #[cfg(test)]
    const MAX_COMMIT_OID_MAP_ENTRIES: usize = 8;

    /// Sensible default when no caller-supplied hint is available.
    ///
    /// `CommitMeta` events fire only for finding-bearing commits (gated by a
    /// non-empty `findings_buf` in `EngineAdapter::stream_findings`), so the
    /// map typically holds a few dozen entries. 64 avoids early reallocations
    /// without over-reserving for the common case.
    pub(crate) const DEFAULT_COMMIT_OID_CAPACITY: usize = 64;

    /// Wrap an existing coordination event sink with findings capture state.
    ///
    /// `commit_oid_capacity_hint` sizes the internal `commit_id → OidBytes`
    /// lookup. Pass [`DEFAULT_COMMIT_OID_CAPACITY`](Self::DEFAULT_COMMIT_OID_CAPACITY)
    /// when no better estimate is available. The hint is clamped to
    /// [`MAX_COMMIT_OID_MAP_ENTRIES`](Self::MAX_COMMIT_OID_MAP_ENTRIES) so
    /// callers need not bounds-check.
    pub(crate) fn new(inner: Arc<CoordinationEventSink>, commit_oid_capacity_hint: usize) -> Self {
        let capped = commit_oid_capacity_hint.min(Self::MAX_COMMIT_OID_MAP_ENTRIES);
        Self {
            inner,
            finding_count: AtomicU64::new(0),
            commit_oid_map: Mutex::new(HashMap::with_capacity(capped)),
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

    /// Drain the captured sparse mapping from commit ordinals to stable OIDs.
    ///
    /// Intended to be called after the scan thread has joined, when no more
    /// git events can append entries. Returns the owned map and leaves the
    /// internal map empty via `std::mem::take`. Poisoned locks are recovered
    /// so the caller can still translate Git findings deterministically.
    pub(crate) fn drain_commit_oid_map(&self) -> HashMap<u32, OidBytes> {
        std::mem::take(
            &mut *self
                .commit_oid_map
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
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
        // Only commit metadata contributes to Git finding identity. Capture the
        // ordinal-to-OID pair under the mutex, then drop the guard before
        // forwarding so the recorder path never runs while holding the lock.
        if let GitEvent::CommitMeta(ref meta) = event {
            let mut map = self
                .commit_oid_map
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let below_cap = map.len() < Self::MAX_COMMIT_OID_MAP_ENTRIES;
            if below_cap || map.contains_key(&meta.commit_id) {
                map.insert(meta.commit_id, meta.commit_oid);
                // Warn exactly once when a new key pushes us to the ceiling.
                if below_cap && map.len() == Self::MAX_COMMIT_OID_MAP_ENTRIES {
                    tracing::warn!(
                        max = Self::MAX_COMMIT_OID_MAP_ENTRIES,
                        "commit OID map reached capacity; new keys will be dropped"
                    );
                }
            }
        }
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
        let sink =
            FindingsCaptureSink::new(inner, FindingsCaptureSink::DEFAULT_COMMIT_OID_CAPACITY);
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
            error_class: Some(MirrorErrorClass::Retryable),
        });

        let forwarded = recorder.stage_signals.lock().unwrap();
        assert_eq!(forwarded.len(), 1, "stage signal should be forwarded");
        assert_eq!(forwarded[0].0, "stage-shard");
        assert_eq!(
            forwarded[0].1,
            StageSignal::MirrorSyncCompleted {
                latency_ms: 17,
                error_class: Some(MirrorErrorClass::Retryable),
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

        let commit_oid_map = sink.drain_commit_oid_map();
        assert_eq!(
            commit_oid_map.get(&1),
            Some(&oid),
            "commit metadata should populate the sparse commit OID map"
        );
    }

    #[test]
    fn findings_capture_sink_commit_oid_map_skips_non_commit_meta_events() {
        let (sink, _recorder) = make_sink_and_recorder();

        sink.emit_git(GitEvent::IdentityDictionary(
            scanner_git::IdentityDictionaryEvent {
                id: 7,
                value: b"alice@example.com",
            },
        ));
        sink.emit_core(finding_event());

        assert!(
            sink.drain_commit_oid_map().is_empty(),
            "only commit metadata events should populate the commit OID map"
        );
    }

    #[test]
    fn findings_capture_sink_drain_commit_oid_map_clears_entries() {
        let (sink, _recorder) = make_sink_and_recorder();

        sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
            commit_id: 42,
            commit_oid: scanner_git::OidBytes::sha1([0xcd; 20]),
            timestamp: 1_700_000_001,
            identity: None,
        }));

        let first = sink.drain_commit_oid_map();
        let second = sink.drain_commit_oid_map();

        assert_eq!(first.len(), 1, "first drain should return captured entries");
        assert!(
            second.is_empty(),
            "second drain should observe an empty map"
        );
    }

    #[test]
    fn findings_capture_sink_commit_oid_map_last_write_wins() {
        let (sink, _recorder) = make_sink_and_recorder();

        let first = scanner_git::OidBytes::sha1([0x11; 20]);
        let second = scanner_git::OidBytes::sha256([0x22; 32]);
        sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
            commit_id: 9,
            commit_oid: first,
            timestamp: 1_700_000_002,
            identity: None,
        }));
        sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
            commit_id: 9,
            commit_oid: second,
            timestamp: 1_700_000_003,
            identity: None,
        }));

        let commit_oid_map = sink.drain_commit_oid_map();
        assert_eq!(
            commit_oid_map.get(&9),
            Some(&second),
            "later commit metadata should overwrite the earlier OID for the same ordinal"
        );
    }

    #[test]
    fn findings_capture_sink_tracks_findings_and_commit_oid_map_independently() {
        let (sink, _recorder) = make_sink_and_recorder();

        let oid = scanner_git::OidBytes::sha256([0xef; 32]);
        sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
            commit_id: 3,
            commit_oid: oid,
            timestamp: 1_700_000_004,
            identity: None,
        }));
        sink.emit_core(finding_event());
        sink.emit_core(finding_event());

        assert_eq!(
            sink.detected_finding_count(),
            2,
            "finding counting should remain independent from git metadata capture"
        );

        let commit_oid_map = sink.drain_commit_oid_map();
        assert_eq!(
            commit_oid_map.get(&3),
            Some(&oid),
            "git metadata capture should remain independent from finding counting"
        );
    }

    #[test]
    fn findings_capture_sink_flush_delegates() {
        let (sink, _recorder) = make_sink_and_recorder();

        // CoordinationEventSink::flush is a no-op, so this verifies the
        // delegation path completes without error or panic.
        sink.flush();
    }

    #[test]
    fn findings_capture_sink_emit_git_concurrent_contention() {
        // Verify the commit_oid_map mutex is safe under concurrent writes.
        // Four threads each insert a distinct commit_id; the merged map must
        // contain all four entries with no lost updates.
        let (sink, _recorder) = make_sink_and_recorder();

        std::thread::scope(|s| {
            for i in 0u8..4 {
                let sink = &sink;
                s.spawn(move || {
                    let oid = scanner_git::OidBytes::sha1([i + 1; 20]);
                    sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
                        commit_id: u32::from(i),
                        commit_oid: oid,
                        timestamp: 1_700_000_000 + u64::from(i),
                        identity: None,
                    }));
                });
            }
        });

        let map = sink.drain_commit_oid_map();
        assert_eq!(map.len(), 4, "all four concurrent inserts must be visible");
        for i in 0u8..4 {
            let expected = scanner_git::OidBytes::sha1([i + 1; 20]);
            assert_eq!(
                map.get(&u32::from(i)),
                Some(&expected),
                "commit_id {i} must map to its expected OID"
            );
        }
    }

    #[test]
    fn findings_capture_sink_commit_oid_map_enforces_capacity_ceiling() {
        // MAX_COMMIT_OID_MAP_ENTRIES is 8 under #[cfg(test)]. Insert exactly 8
        // entries to fill the map, then 2 more that must be silently dropped.
        let (sink, recorder) = make_sink_and_recorder();

        let max = FindingsCaptureSink::MAX_COMMIT_OID_MAP_ENTRIES;
        for i in 0..max as u32 {
            sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
                commit_id: i,
                commit_oid: scanner_git::OidBytes::sha1([i as u8 + 1; 20]),
                timestamp: 1_700_000_000 + u64::from(i),
                identity: None,
            }));
        }

        let map = sink.drain_commit_oid_map();
        assert_eq!(
            map.len(),
            max,
            "map should accept exactly MAX_COMMIT_OID_MAP_ENTRIES entries"
        );

        // Re-populate to capacity (drain cleared it), then add 2 beyond the ceiling.
        for i in 0..max as u32 {
            sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
                commit_id: i,
                commit_oid: scanner_git::OidBytes::sha1([i as u8 + 1; 20]),
                timestamp: 1_700_000_000 + u64::from(i),
                identity: None,
            }));
        }
        for i in max as u32..max as u32 + 2 {
            sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
                commit_id: i,
                commit_oid: scanner_git::OidBytes::sha1([i as u8 + 1; 20]),
                timestamp: 1_700_000_000 + u64::from(i),
                identity: None,
            }));
        }

        let map = sink.drain_commit_oid_map();
        assert_eq!(map.len(), max, "entries beyond the ceiling must be dropped");
        assert!(
            !map.contains_key(&(max as u32)),
            "commit_id beyond the ceiling must not appear in the map"
        );
        assert!(
            !map.contains_key(&(max as u32 + 1)),
            "second commit_id beyond the ceiling must not appear in the map"
        );

        // All events — including those beyond the ceiling — must still be
        // forwarded to the inner sink.
        let forwarded = recorder.git_events.lock().unwrap();
        let total_events = max + max + 2;
        assert_eq!(
            forwarded.len(),
            total_events,
            "all events must be forwarded regardless of ceiling"
        );
    }

    #[test]
    fn commit_oid_map_allows_existing_key_update_at_capacity() {
        // Fill the map to capacity, then update an existing key. The update
        // does not grow the map, so it should succeed even at the ceiling.
        let (sink, _recorder) = make_sink_and_recorder();
        let max = FindingsCaptureSink::MAX_COMMIT_OID_MAP_ENTRIES;

        for i in 0..max as u32 {
            sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
                commit_id: i,
                commit_oid: scanner_git::OidBytes::sha1([i as u8 + 1; 20]),
                timestamp: 1_700_000_000 + u64::from(i),
                identity: None,
            }));
        }

        // Map is now at capacity. Update commit_id 0 with a different OID.
        let updated_oid = scanner_git::OidBytes::sha256([0xFF; 32]);
        sink.emit_git(GitEvent::CommitMeta(scanner_git::CommitMetaEvent {
            commit_id: 0,
            commit_oid: updated_oid,
            timestamp: 1_700_000_999,
            identity: None,
        }));

        let map = sink.drain_commit_oid_map();
        assert_eq!(map.len(), max, "map size must remain at capacity");
        assert_eq!(
            map.get(&0),
            Some(&updated_oid),
            "existing key must be updatable even at capacity"
        );
    }
}
