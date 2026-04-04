//! Coordination-backed event sink for distributed scans.
//!
//! This sink captures both scheduler core events and git-specific events and
//! forwards owned copies to a coordinator-facing recorder. Recorder failures are
//! intentionally non-fatal for event emission: authoritative durability is
//! enforced by the receipt-driven commit pipeline (`ReceiptCommitSink` ->
//! `ResultCommitter`), while event recording remains best-effort telemetry.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

/// Wrapper around [`CoordinationEventSink`] that intercepts `Finding` events
/// and clones them into an internal buffer while forwarding all events to the
/// inner sink unchanged.
///
/// After the scan completes, callers retrieve the buffered findings via
/// [`drain_findings`](Self::drain_findings) to write them into the durable
/// [`FindingsSink`](gossip_contracts::persistence::FindingsSink) before
/// advancing the shard checkpoint.
pub(crate) struct FindingsCaptureSink {
    inner: Arc<CoordinationEventSink>,
    captured: Mutex<Vec<OwnedCoreEvent>>,
}

impl FindingsCaptureSink {
    /// Wrap an existing coordination event sink with a findings capture layer.
    pub(crate) fn new(inner: Arc<CoordinationEventSink>) -> Self {
        Self {
            inner,
            captured: Mutex::new(Vec::new()),
        }
    }

    /// Drain all captured `Finding` events, leaving the buffer empty.
    ///
    /// Intended to be called exactly once after the scan completes and before
    /// the findings are written to the durable persistence layer.
    pub(crate) fn drain_findings(&self) -> Vec<OwnedCoreEvent> {
        self.captured
            .lock()
            .expect("findings capture lock poisoned")
            .drain(..)
            .collect()
    }
}

impl EventOutput for FindingsCaptureSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        // Convert to owned first — `CoreEvent` is not `Copy`, so we must
        // capture before forwarding. All events are replayed into the inner
        // sink via `emit_into` so telemetry sees the full stream.
        let owned = OwnedCoreEvent::from_core(event);
        if matches!(owned, OwnedCoreEvent::Finding { .. }) {
            self.captured
                .lock()
                .expect("findings capture lock poisoned")
                .push(owned.clone());
        }
        owned.emit_into(self.inner.as_ref());
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
