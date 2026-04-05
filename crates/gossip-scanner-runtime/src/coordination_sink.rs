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
use gossip_contracts::connector::ItemKey;
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
    /// recovery conventions; contention stays low because commit metadata is
    /// emitted at most once per commit.
    commit_oid_map: Mutex<HashMap<u32, OidBytes>>,
}

impl FindingsCaptureSink {
    /// Defense-in-depth ceiling for the sparse commit-OID lookup.
    ///
    /// At ~80 bytes per entry (u32 key + 33-byte OidBytes + HashMap overhead),
    /// 500K entries consume ~40 MB — well above any realistic scan but prevents
    /// a pathological repository from exhausting worker memory.
    const MAX_COMMIT_OID_MAP_ENTRIES: usize = 500_000;

    /// Wrap an existing coordination event sink with findings capture state.
    pub(crate) fn new(inner: Arc<CoordinationEventSink>) -> Self {
        Self {
            inner,
            finding_count: AtomicU64::new(0),
            // Most scan passes encounter at most a few dozen commits with
            // findings, so 64 avoids early reallocations without over-reserving.
            commit_oid_map: Mutex::new(HashMap::with_capacity(64)),
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
            if map.len() < Self::MAX_COMMIT_OID_MAP_ENTRIES {
                map.insert(meta.commit_id, meta.commit_oid);
            } else if map.len() == Self::MAX_COMMIT_OID_MAP_ENTRIES {
                tracing::warn!(
                    max = Self::MAX_COMMIT_OID_MAP_ENTRIES,
                    "commit OID map reached capacity; subsequent entries will be dropped"
                );
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
            norm_hash: Some([0xAA; 32]),
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
}
