//! Coordination-backed event sink for distributed scans.
//!
//! This sink captures both scheduler core events and git-specific events and
//! forwards owned copies to a coordinator-facing recorder. Recorder failures are
//! intentionally non-fatal for event emission: commit durability is enforced by
//! `DurableCommitSink`, while event recording remains best-effort telemetry.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
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

/// Commit lifecycle checkpoints emitted by durable commit sinks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitProgressRecord {
    /// Item processing has started; `size_hint` is the expected byte length.
    Begin {
        write_context: WriteContext,
        item_key: Vec<u8>,
        size_hint: Option<u64>,
    },
    /// Item processing completed successfully.
    Finish {
        write_context: WriteContext,
        item_key: Vec<u8>,
    },
}

/// Identity chain derived for distributed finding persistence.
///
/// Contains all intermediate hashes from norm through occurrence so
/// downstream systems can verify the derivation chain.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityChainRecord {
    write_context: WriteContext,
    item_key: Vec<u8>,
    rule_id: u32,
    start: u64,
    end: u64,
    confidence_score: i8,
    norm_hash: [u8; 32],
    secret_hash: [u8; 32],
    finding_id: [u8; 32],
    occurrence_id: [u8; 32],
}

impl fmt::Debug for IdentityChainRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityChainRecord")
            .field("write_context", &self.write_context)
            .field("item_key", &self.item_key)
            .field("rule_id", &self.rule_id)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("confidence_score", &self.confidence_score)
            .field("norm_hash", &"[redacted]")
            .field("secret_hash", &"[redacted]")
            .field("finding_id", &self.finding_id)
            .field("occurrence_id", &self.occurrence_id)
            .finish()
    }
}

impl IdentityChainRecord {
    /// Fallible constructor that validates span boundaries.
    ///
    /// Returns `Err` when `end <= start` (empty or inverted span).
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        write_context: WriteContext,
        item_key: Vec<u8>,
        rule_id: u32,
        start: u64,
        end: u64,
        confidence_score: i8,
        norm_hash: [u8; 32],
        secret_hash: [u8; 32],
        finding_id: [u8; 32],
        occurrence_id: [u8; 32],
    ) -> Result<Self> {
        if end <= start {
            return Err(anyhow::anyhow!(
                "identity chain record requires a non-empty span: start={start}, end={end}",
            ));
        }
        Ok(Self {
            write_context,
            item_key,
            rule_id,
            start,
            end,
            confidence_score,
            norm_hash,
            secret_hash,
            finding_id,
            occurrence_id,
        })
    }

    /// Construct an identity chain record from all component fields.
    ///
    /// Panics when `end <= start`. Prefer [`Self::try_new`] when the caller
    /// can handle the error.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        write_context: WriteContext,
        item_key: Vec<u8>,
        rule_id: u32,
        start: u64,
        end: u64,
        confidence_score: i8,
        norm_hash: [u8; 32],
        secret_hash: [u8; 32],
        finding_id: [u8; 32],
        occurrence_id: [u8; 32],
    ) -> Self {
        Self::try_new(
            write_context,
            item_key,
            rule_id,
            start,
            end,
            confidence_score,
            norm_hash,
            secret_hash,
            finding_id,
            occurrence_id,
        )
        .expect("identity chain record requires a non-empty span")
    }

    /// Shared routing and fencing metadata for the emitted write.
    #[inline]
    #[must_use]
    pub fn write_context(&self) -> WriteContext {
        self.write_context
    }

    /// Connector-provided item key (e.g. file path bytes).
    #[inline]
    #[must_use]
    pub fn item_key(&self) -> &[u8] {
        &self.item_key
    }

    /// Numeric rule identifier that matched.
    #[inline]
    #[must_use]
    pub fn rule_id(&self) -> u32 {
        self.rule_id
    }

    /// Byte offset of the finding start within the item.
    #[inline]
    #[must_use]
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Byte offset one past the finding end within the item.
    #[inline]
    #[must_use]
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Engine-assigned confidence score for this finding.
    #[inline]
    #[must_use]
    pub fn confidence_score(&self) -> i8 {
        self.confidence_score
    }

    /// Normalised hash of the secret value.
    #[inline]
    #[must_use]
    pub fn norm_hash(&self) -> &[u8; 32] {
        &self.norm_hash
    }

    /// Tenant-scoped secret hash derived from `norm_hash`.
    #[inline]
    #[must_use]
    pub fn secret_hash(&self) -> &[u8; 32] {
        &self.secret_hash
    }

    /// Stable finding identifier derived from tenant, item, rule, and secret.
    #[inline]
    #[must_use]
    pub fn finding_id(&self) -> &[u8; 32] {
        &self.finding_id
    }

    /// Version-specific occurrence identifier.
    #[inline]
    #[must_use]
    pub fn occurrence_id(&self) -> &[u8; 32] {
        &self.occurrence_id
    }
}

/// Coordinator-facing recorder for distributed scan output.
pub trait CoordinationEventRecorder: Send + Sync {
    /// Persists a scanner core event (finding, progress, summary, diagnostic).
    fn record_core_event(&self, shard_id: &str, event: OwnedCoreEvent) -> Result<()>;
    /// Persists a git-specific event (commit metadata or identity dictionary entry).
    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()>;
    /// Persists a commit lifecycle checkpoint (begin/finish).
    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()>;
    /// Persists a derived identity chain record for a finding.
    fn record_identity_chain(&self, shard_id: &str, record: IdentityChainRecord) -> Result<()>;
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
}

impl EventOutput for CoordinationEventSink {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let owned = OwnedCoreEvent::from_core(event);
        if let Err(error) = self.recorder.record_core_event(&self.shard_id, owned)
            && !self.core_error_logged.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                shard_id = %self.shard_id,
                %error,
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

        if let Err(error) = self.recorder.record_git_event(&self.shard_id, owned)
            && !self.git_error_logged.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                shard_id = %self.shard_id,
                %error,
                "recorder failed to persist git event; subsequent failures suppressed",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use gossip_contracts::{
        identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId},
        persistence::WriteContext,
    };

    use super::IdentityChainRecord;

    fn write_context() -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(33),
            ShardId::from_raw(44),
            FenceEpoch::from_raw(55),
        )
    }

    #[test]
    fn identity_chain_record_round_trips_all_fields() {
        let wc = write_context();
        let item_key = b"test-item-key".to_vec();
        let record = IdentityChainRecord::new(
            wc,
            item_key.clone(),
            42,
            100,
            200,
            -3,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
        );

        assert_eq!(record.write_context(), wc);
        assert_eq!(record.item_key(), item_key.as_slice());
        assert_eq!(record.rule_id(), 42);
        assert_eq!(record.start(), 100);
        assert_eq!(record.end(), 200);
        assert_eq!(record.confidence_score(), -3);
        assert_eq!(record.norm_hash(), &[0x11; 32]);
        assert_eq!(record.secret_hash(), &[0x22; 32]);
        assert_eq!(record.finding_id(), &[0x33; 32]);
        assert_eq!(record.occurrence_id(), &[0x44; 32]);
    }

    #[test]
    fn identity_chain_record_debug_redacts_hashes() {
        let record = IdentityChainRecord::new(
            write_context(),
            b"item-key".to_vec(),
            1,
            10,
            20,
            5,
            [0xDE; 32],
            [0xDE; 32],
            [0xAA; 32],
            [0xBB; 32],
        );
        let debug = format!("{record:?}");
        assert!(
            debug.contains("[redacted]"),
            "Debug output must redact sensitive hashes, got: {debug}"
        );
        assert!(
            !debug.contains("dede"),
            "Debug output must not leak hash bytes, got: {debug}"
        );
    }
}
