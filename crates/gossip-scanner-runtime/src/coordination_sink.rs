//! Coordination-backed event sink for distributed scans.
//!
//! This sink captures both scheduler core events and git-specific events and
//! forwards owned copies to a coordinator-facing recorder. The findings wrapper
//! layered on top also accumulates persistence-ready Git finding payloads and
//! validates the embedded blob OIDs required by Git findings translation.
//! Recorder failures are intentionally non-fatal for event emission:
//! authoritative durability is enforced by the receipt-driven commit pipeline
//! (`ReceiptCommitSink` -> `ResultCommitter`), while event recording remains
//! best-effort telemetry.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use gossip_contracts::connector::{ItemKey, ToxicDigest};
use gossip_contracts::identity::NormHash;
use gossip_contracts::persistence::{PersistenceFinding, WriteContext};
use gossip_stdx::HexOid;
use scanner_git::{GitEvent, GitEventOutput, OidBytes};
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

fn decode_blob_oid(raw: [u8; 33]) -> Option<OidBytes> {
    let len = raw[0] as usize;
    if len != OidBytes::SHA1_LEN as usize && len != OidBytes::SHA256_LEN as usize {
        return None;
    }
    if raw[(len + 1)..].iter().any(|&byte| byte != 0) {
        return None;
    }
    OidBytes::try_from_slice(&raw[1..=len])
}

/// Persistence-ready representation of one Git finding observed during scan
/// execution.
///
/// `blob_offset_start` and `blob_offset_end` are blob-absolute offsets
/// captured from `FindingEvent::start/end`. For root (non-transform) findings
/// these correspond to the regex match span (group 0) in root-file coordinates
/// via `base_offset + match_span.start`. For transform findings these are
/// best-available root-hint coordinates derived via
/// `base_offset + RootSpanMapCtx::map_span(decoded_span).start`, which maps
/// decoded-byte positions back to approximate encoded-byte positions.
///
/// Both root and transform offsets participate in `OccurrenceId` derivation,
/// so Git and FS scans of the same content converge on the same occurrence
/// identity through these root-hint coordinates. Exact-match propagation for
/// transforms is approximate (encoded-byte-mapped), not byte-exact.
///
/// Cross-source convergence is only guaranteed for blobs whose offsets fit in
/// u32 space (< 4 GiB). The Git path narrows `root_hint_start` to a u32
/// `FindingKey.start`; offsets that overflow are rejected by
/// `EngineAdapterError::FindingOffsetOverflow` before reaching this struct.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GitFindingForPersistence {
    /// Repository-relative object path used as the stable per-object identity input.
    pub(crate) object_path: Box<[u8]>,
    /// Blob object ID that defines the strong version identity for this object.
    pub(crate) blob_oid: OidBytes,
    /// Half-open blob-absolute start offset within the object content.
    pub(crate) blob_offset_start: u64,
    /// Half-open blob-absolute end offset within the object content.
    pub(crate) blob_offset_end: u64,
    /// Content-derived normalization hash for finding identity.
    pub(crate) norm_hash: NormHash,
    /// Rule identifier emitted by the scanner.
    pub(crate) rule_id: u32,
}

// Layout budget (64-bit): Box<[u8]>=16, OidBytes≈40 with alignment, 2×u64=16,
// NormHash=32, u32+pad=8 -> typically 112 bytes.
const _: () = assert!(std::mem::size_of::<GitFindingForPersistence>() <= 128);

impl fmt::Debug for GitFindingForPersistence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitFindingForPersistence")
            .field("object_path_len", &self.object_path.len())
            .field("blob_oid", &self.blob_oid)
            .field("blob_offset_start", &self.blob_offset_start)
            .field("blob_offset_end", &self.blob_offset_end)
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
    fn blob_offset_start(&self) -> u64 {
        self.blob_offset_start
    }

    #[inline]
    fn blob_offset_end(&self) -> u64 {
        self.blob_offset_end
    }
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
/// events for later Git persistence translation, then forwards all events to
/// the inner sink unchanged.
///
/// The count and captured finding payloads are retrieved after the scan
/// completes. The Git repo-frontier worker uses the captured findings to route
/// git detections through the same persistence translation path used by
/// filesystem scans.
///
/// The counter uses `Relaxed` ordering because it is only
/// read after the scan thread joins (establishing a happens-before via
/// `std::thread::scope`), so the final value is always visible to the reader.
/// Captured findings are stored behind a `Mutex<Vec<_>>` because pack workers
/// emit findings from multiple threads during git scans.
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
    /// Wrap an existing coordination event sink with findings capture state.
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
        let mut guard = match self.captured_findings.lock() {
            Ok(guard) => guard,
            Err(poison) => {
                tracing::error!(
                    "captured_findings mutex poisoned; a scan worker panicked \
                     while holding the lock — recovered findings may be incomplete"
                );
                poison.into_inner()
            }
        };
        std::mem::take(&mut *guard)
    }
}

impl EventOutput for FindingsCaptureSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        if let CoreEvent::Finding(finding) = &event {
            self.finding_count.fetch_add(1, Ordering::Relaxed);
            match finding.blob_oid.and_then(decode_blob_oid) {
                Some(blob_oid) => {
                    let record = GitFindingForPersistence {
                        object_path: finding.object_path.into(),
                        blob_oid,
                        blob_offset_start: finding.start,
                        blob_offset_end: finding.end,
                        norm_hash: NormHash::from_digest(finding.norm_hash),
                        rule_id: finding.rule_id,
                    };
                    match self.captured_findings.lock() {
                        Ok(mut guard) => guard.push(record),
                        Err(poison) => {
                            tracing::error!(
                                "captured_findings mutex poisoned; recovered guard and \
                                 committed finding — subsequent lock attempts will also \
                                 require poison recovery"
                            );
                            poison.into_inner().push(record);
                        }
                    }
                }
                None => {
                    tracing::error!(
                        source = %finding.source.as_str(),
                        object_path_len = finding.object_path.len(),
                        commit_id = ?finding.commit_id,
                        "finding missing or invalid blob_oid; persistence capture skipped"
                    );
                }
            }
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

    fn encoded_blob_oid(oid: OidBytes) -> [u8; 33] {
        let mut raw = [0u8; 33];
        let len = oid.len() as usize;
        raw[0] = oid.len();
        raw[1..=len].copy_from_slice(oid.as_slice());
        raw
    }

    fn finding_event() -> CoreEvent<'static> {
        CoreEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: b"/tmp/secret.txt",
            start: 100,
            end: 142,
            rule_id: 7,
            rule_name: "test-rule",
            norm_hash: [0xAA; 32],
            blob_oid: Some(encoded_blob_oid(OidBytes::sha1([0x11; 20]))),
            commit_id: Some(11),
            change_kind: Some("modify"),
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
        assert_eq!(captured[0].object_path.as_ref(), b"/tmp/secret.txt");
        assert_eq!(captured[0].blob_oid, OidBytes::sha1([0x11; 20]));
        assert_eq!(captured[0].rule_id(), 7);
        // `GitFindingForPersistence.blob_offset_start/blob_offset_end` carry the blob-absolute
        // root-hint offsets from `FindingEvent.start/end` — these feed
        // persistence identity derivation.
        assert_eq!(captured[0].blob_offset_start(), 100);
        assert_eq!(captured[0].blob_offset_end(), 142);
        assert_eq!(captured[0].norm_hash(), NormHash::from_digest([0xAA; 32]));
    }

    #[test]
    fn git_finding_for_persistence_debug_redacts_norm_hash() {
        let finding = GitFindingForPersistence {
            object_path: b"src/lib.rs".to_vec().into_boxed_slice(),
            blob_oid: OidBytes::sha1([0x22; 20]),
            blob_offset_start: 1,
            blob_offset_end: 9,
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
    fn findings_capture_sink_skips_invalid_blob_oid_payloads() {
        let (sink, _recorder) = make_sink_and_recorder();

        let mut raw = [0u8; 33];
        raw[0] = 21;
        sink.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: b"/tmp/bad.txt",
            start: 5,
            end: 15,
            rule_id: 9,
            rule_name: "bad",
            norm_hash: [0xBB; 32],
            blob_oid: Some(raw),
            commit_id: Some(3),
            change_kind: Some("add"),
            confidence_score: 10,
        }));

        assert_eq!(sink.detected_finding_count(), 1);
        assert!(
            sink.take_captured_findings().is_empty(),
            "invalid blob OIDs must be skipped during persistence capture"
        );
    }

    #[test]
    fn findings_capture_sink_flush_delegates() {
        let (sink, _recorder) = make_sink_and_recorder();

        // CoordinationEventSink::flush is a no-op, so this verifies the
        // delegation path completes without error or panic.
        sink.flush();
    }
}
