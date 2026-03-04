//! Coordination-backed event sink for distributed scans.
//!
//! This sink captures both scheduler core events and git-specific events and
//! forwards owned copies to a coordinator-facing recorder. Recorder failures are
//! intentionally non-fatal for event emission: commit durability is enforced by
//! `DurableCommitSink`, while event recording remains best-effort telemetry.

use std::sync::Arc;

use anyhow::Result;
use scanner_git::{GitEvent, GitEventOutput};
use scanner_scheduler::events::{CoreEvent, EventOutput};

/// Owned core event representation persisted by distributed sinks.
#[derive(Clone, Debug, PartialEq)]
pub enum StoredCoreEvent {
    /// A secret finding detected by the engine.
    Finding {
        source: scanner_scheduler::source_kind::SourceKind,
        object_path: Vec<u8>,
        start: u64,
        end: u64,
        rule_id: u32,
        rule_name: String,
        commit_id: Option<u32>,
        change_kind: Option<String>,
        confidence_score: i8,
    },
    /// Periodic scan progress checkpoint.
    Progress {
        source: scanner_scheduler::source_kind::SourceKind,
        stage: &'static str,
        objects_scanned: u64,
        bytes_scanned: u64,
        findings_emitted: u64,
    },
    /// Final scan summary emitted when a source completes.
    Summary {
        source: scanner_scheduler::source_kind::SourceKind,
        status: &'static str,
        elapsed_ms: u64,
        bytes_scanned: u64,
        findings_emitted: u64,
        errors: u64,
        throughput_mib_s: f64,
    },
    /// Runtime diagnostic (warning or error) from the scan engine.
    Diagnostic {
        level: &'static str,
        message: String,
    },
}

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

/// Commit lifecycle checkpoints emitted by durable commit sinks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitProgressRecord {
    /// Item processing has started; `size_hint` is the expected byte length.
    Begin {
        item_key: Vec<u8>,
        size_hint: Option<u64>,
    },
    /// Item processing completed successfully.
    Finish { item_key: Vec<u8> },
}

/// Identity chain derived for distributed finding persistence.
///
/// Contains all intermediate hashes from norm through occurrence so
/// downstream systems can verify the derivation chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityChainRecord {
    /// Connector-provided item key (e.g. file path bytes).
    pub item_key: Vec<u8>,
    /// Numeric rule identifier that matched.
    pub rule_id: u32,
    /// Byte offset of the finding start within the item.
    pub start: u64,
    /// Byte offset of the finding end within the item.
    pub end: u64,
    /// Engine-assigned confidence score for this finding.
    pub confidence_score: i8,
    /// Normalised hash of the secret value.
    pub norm_hash: [u8; 32],
    /// Tenant-scoped secret hash derived from `norm_hash`.
    pub secret_hash: [u8; 32],
    /// Stable finding identifier derived from tenant, item, rule, and secret.
    pub finding_id: [u8; 32],
    /// Version-specific occurrence identifier.
    pub occurrence_id: [u8; 32],
}

/// Coordinator-facing recorder for distributed scan output.
pub trait CoordinationEventRecorder: Send + Sync {
    /// Persists a scanner core event (finding, progress, summary, diagnostic).
    fn record_core_event(&self, shard_id: &str, event: StoredCoreEvent) -> Result<()>;
    /// Persists a git-specific event (commit metadata or identity dictionary entry).
    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()>;
    /// Persists a commit lifecycle checkpoint (begin/finish).
    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()>;
    /// Persists a derived identity chain record for a finding.
    fn record_identity_chain(&self, shard_id: &str, record: IdentityChainRecord) -> Result<()>;
}

/// Distributed event sink that forwards events to a coordinator recorder.
pub struct CoordinationEventSink {
    shard_id: String,
    recorder: Arc<dyn CoordinationEventRecorder>,
}

impl CoordinationEventSink {
    /// Creates a sink that forwards events to `recorder` tagged with `shard_id`.
    #[must_use]
    pub fn new(recorder: Arc<dyn CoordinationEventRecorder>, shard_id: impl Into<String>) -> Self {
        Self {
            shard_id: shard_id.into(),
            recorder,
        }
    }
}

impl EventOutput for CoordinationEventSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let owned = match event {
            CoreEvent::Finding(finding) => StoredCoreEvent::Finding {
                source: finding.source,
                object_path: finding.object_path.to_vec(),
                start: finding.start,
                end: finding.end,
                rule_id: finding.rule_id,
                rule_name: finding.rule_name.to_owned(),
                commit_id: finding.commit_id,
                change_kind: finding.change_kind.map(ToOwned::to_owned),
                confidence_score: finding.confidence_score,
            },
            CoreEvent::Progress(progress) => StoredCoreEvent::Progress {
                source: progress.source,
                stage: progress.stage,
                objects_scanned: progress.objects_scanned,
                bytes_scanned: progress.bytes_scanned,
                findings_emitted: progress.findings_emitted,
            },
            CoreEvent::Summary(summary) => StoredCoreEvent::Summary {
                source: summary.source,
                status: summary.status,
                elapsed_ms: summary.elapsed_ms,
                bytes_scanned: summary.bytes_scanned,
                findings_emitted: summary.findings_emitted,
                errors: summary.errors,
                throughput_mib_s: summary.throughput_mib_s,
            },
            CoreEvent::Diagnostic(diagnostic) => StoredCoreEvent::Diagnostic {
                level: diagnostic.level,
                message: diagnostic.message.to_owned(),
            },
        };

        let _ = self.recorder.record_core_event(&self.shard_id, owned);
    }

    fn flush(&self) {}
}

impl GitEventOutput for CoordinationEventSink {
    fn emit_git(&self, event: GitEvent<'_>) {
        let owned = match event {
            GitEvent::CommitMeta(meta) => StoredGitEvent::CommitMeta {
                commit_id: meta.commit_id,
                oid_hex: oid_to_hex(&meta.commit_oid),
                timestamp: meta.timestamp,
                author_name_id: meta.identity.and_then(|ids| {
                    (ids.author_name != scanner_git::SENTINEL_ID).then_some(ids.author_name)
                }),
                author_email_id: meta.identity.and_then(|ids| {
                    (ids.author_email != scanner_git::SENTINEL_ID).then_some(ids.author_email)
                }),
                committer_name_id: meta.identity.and_then(|ids| {
                    (ids.committer_name != scanner_git::SENTINEL_ID).then_some(ids.committer_name)
                }),
                committer_email_id: meta.identity.and_then(|ids| {
                    (ids.committer_email != scanner_git::SENTINEL_ID).then_some(ids.committer_email)
                }),
            },
            GitEvent::IdentityDictionary(entry) => StoredGitEvent::IdentityDictionary {
                id: entry.id,
                value: entry.value.to_vec(),
            },
        };

        let _ = self.recorder.record_git_event(&self.shard_id, owned);
    }
}

fn oid_to_hex(oid: &scanner_git::OidBytes) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(oid.as_slice().len() * 2);
    for byte in oid.as_slice() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
