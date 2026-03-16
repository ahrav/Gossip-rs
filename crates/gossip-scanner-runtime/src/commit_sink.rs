//! Commit sink types and adapters for runtime entry points.
//!
//! Durable sinks derive finding identity chains while scan loops remain focused
//! on enumeration and detection.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use gossip_contracts::{
    connector::{ItemKey, VersionId},
    identity::{
        FindingIdInputs, NormHash, ObjectVersionId, OccurrenceIdInputs, StableItemId,
        TenantSecretKey, derive_finding_id, derive_occurrence_id, key_secret_hash,
    },
    persistence::WriteContext,
};

use crate::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, IdentityChainRecord,
};
use crate::result_translation::rule_fingerprint_from_rule_id;

/// Per-item metadata passed to [`CommitSink::begin_item`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemMeta {
    /// Connector-assigned stable identity for the scanned item.
    pub stable_item_id: StableItemId,
    /// Connector-assigned version for the scanned snapshot.
    pub version: Option<VersionId>,
    /// Approximate byte length of the item payload, if known before scanning.
    pub size_hint: Option<u64>,
}

/// Compact finding record forwarded through the [`CommitSink`] bridge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FindingRecord {
    /// Numeric identifier of the detection rule that matched.
    pub rule_id: u32,
    /// Byte offset of the match start within the item payload.
    pub start: u64,
    /// Byte offset one past the match end.
    pub end: u64,
    /// Digest of the normalized secret bytes.
    pub norm_hash: [u8; 32],
    /// Additive confidence score from gate signals.
    pub confidence_score: i8,
}

impl fmt::Debug for FindingRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FindingRecord")
            .field("rule_id", &self.rule_id)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("norm_hash", &"[redacted]")
            .field("confidence_score", &self.confidence_score)
            .finish()
    }
}

/// All findings for a single item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FindingsBatch {
    /// Findings emitted for one item.
    pub findings: Vec<FindingRecord>,
}

/// Per-item lifecycle sink for persisting scan results.
pub trait CommitSink: Send + Sync {
    /// Register a new item and its metadata.
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()>;

    /// Record one batch of findings for an in-progress item.
    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()>;

    /// Mark the item as fully scanned.
    fn finish_item(&self, item_key: &ItemKey) -> Result<()>;
}

/// No-op sink used by CLI and direct-mode scans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CliNoOpCommitSink;

impl CommitSink for CliNoOpCommitSink {
    fn begin_item(&self, _item_key: &ItemKey, _meta: &ItemMeta) -> Result<()> {
        Ok(())
    }

    fn upsert_findings(&self, _item_key: &ItemKey, _batch: &FindingsBatch) -> Result<()> {
        Ok(())
    }

    fn finish_item(&self, _item_key: &ItemKey) -> Result<()> {
        Ok(())
    }
}

/// Durable commit sink used by distributed-mode coordination sinks.
///
/// The `in_flight_meta` Mutex is effectively uncontended: the commit forwarder
/// is a single-threaded drain loop, so only one thread calls `begin_item`,
/// `upsert_findings`, and `finish_item`. The Mutex satisfies the `Send + Sync`
/// bound required by `CommitSink` without introducing real contention.
pub struct DurableCommitSink {
    recorder_shard_label: Arc<str>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
    in_flight_meta: Mutex<BTreeMap<Vec<u8>, ItemMeta>>,
}

impl DurableCommitSink {
    /// Creates a durable commit sink bound to one recorder shard label and one
    /// shared write context.
    #[must_use]
    pub fn new(
        recorder: Arc<dyn CoordinationEventRecorder>,
        recorder_shard_label: Arc<str>,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
    ) -> Self {
        Self {
            recorder_shard_label,
            recorder,
            write_context,
            tenant_secret_key,
            in_flight_meta: Mutex::new(BTreeMap::new()),
        }
    }

    fn metadata_for_item(&self, item_key: &ItemKey) -> Result<ItemMeta> {
        let guard = self
            .in_flight_meta
            .lock()
            .map_err(|_| anyhow!("durable commit sink metadata lock poisoned"))?;
        guard
            .get(item_key.as_bytes())
            .cloned()
            .ok_or_else(|| anyhow!("upsert_findings called before begin_item for item"))
    }

    fn derive_identity_record(
        &self,
        item_key: &ItemKey,
        meta: &ItemMeta,
        finding: &FindingRecord,
    ) -> Result<IdentityChainRecord> {
        let norm_hash = NormHash::from_digest(finding.norm_hash);
        let secret_hash = key_secret_hash(&self.tenant_secret_key, &norm_hash);

        let finding_id = derive_finding_id(&FindingIdInputs {
            tenant: self.write_context.tenant_id(),
            item: meta.stable_item_id,
            rule: rule_fingerprint_from_rule_id(finding.rule_id),
            secret: secret_hash,
        });

        // When the source exposes version metadata it defines occurrence
        // identity directly. Otherwise the item-key bytes provide a stable
        // deterministic surrogate version for the same logical key.
        let object_version = meta
            .version
            .map(|version| version.object_version_id())
            .unwrap_or_else(|| {
                tracing::debug!(
                    item_key = ?item_key.as_bytes(),
                    "deriving ObjectVersionId from item-key bytes"
                );
                ObjectVersionId::from_version_bytes(item_key.as_bytes())
            });
        if finding.end <= finding.start {
            return Err(anyhow!(
                "finding has invalid span [{}, {}): end must exceed start",
                finding.start,
                finding.end
            ));
        }
        let occurrence_id = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_id,
            version: object_version,
            byte_offset: finding.start,
            byte_length: finding.end - finding.start,
        });

        Ok(IdentityChainRecord::new(
            self.write_context,
            item_key.as_bytes().to_vec(),
            finding.rule_id,
            finding.start,
            finding.end,
            finding.confidence_score,
            *norm_hash.as_bytes(),
            *secret_hash.as_bytes(),
            *finding_id.as_bytes(),
            *occurrence_id.as_bytes(),
        ))
    }
}

impl CommitSink for DurableCommitSink {
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
        let key_bytes = item_key.as_bytes().to_vec();
        self.in_flight_meta
            .lock()
            .map_err(|_| anyhow!("durable commit sink metadata lock poisoned"))?
            .insert(key_bytes.clone(), meta.clone());

        self.recorder.record_commit_progress(
            &self.recorder_shard_label,
            CommitProgressRecord::Begin {
                write_context: self.write_context,
                item_key: key_bytes,
                size_hint: meta.size_hint,
            },
        )
    }

    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()> {
        let meta = self.metadata_for_item(item_key)?;
        for finding in &batch.findings {
            let record = self.derive_identity_record(item_key, &meta, finding)?;
            self.recorder
                .record_identity_chain(&self.recorder_shard_label, record)?;
        }
        Ok(())
    }

    fn finish_item(&self, item_key: &ItemKey) -> Result<()> {
        self.in_flight_meta
            .lock()
            .map_err(|_| anyhow!("durable commit sink metadata lock poisoned"))?
            .remove(item_key.as_bytes());

        self.recorder.record_commit_progress(
            &self.recorder_shard_label,
            CommitProgressRecord::Finish {
                write_context: self.write_context,
                item_key: item_key.as_bytes().to_vec(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use gossip_contracts::{
        identity::{
            FenceEpoch, ObjectVersionId, PolicyHash, RunId, ShardId, TenantId, TenantSecretKey,
        },
        persistence::WriteContext,
    };

    use super::*;
    use crate::OwnedCoreEvent;
    use crate::coordination_sink::StoredGitEvent;

    #[derive(Default)]
    struct Recorder {
        identity: Mutex<Vec<IdentityChainRecord>>,
        progress: Mutex<Vec<CommitProgressRecord>>,
    }

    impl CoordinationEventRecorder for Recorder {
        fn record_core_event(&self, _shard_id: &str, _event: OwnedCoreEvent) -> Result<()> {
            Ok(())
        }

        fn record_git_event(&self, _shard_id: &str, _event: StoredGitEvent) -> Result<()> {
            Ok(())
        }

        fn record_commit_progress(
            &self,
            _shard_id: &str,
            event: CommitProgressRecord,
        ) -> Result<()> {
            self.progress.lock().expect("progress lock").push(event);
            Ok(())
        }

        fn record_identity_chain(
            &self,
            _shard_id: &str,
            record: IdentityChainRecord,
        ) -> Result<()> {
            self.identity.lock().expect("identity lock").push(record);
            Ok(())
        }
    }

    #[test]
    fn durable_commit_sink_derives_identity_chain() {
        let recorder = Arc::new(Recorder::default());
        let write_context = WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x12; 32]),
            RunId::from_raw(13),
            ShardId::from_raw(14),
            FenceEpoch::from_raw(15),
        );
        let sink = DurableCommitSink::new(
            recorder.clone(),
            Arc::from("shard-a"),
            write_context,
            TenantSecretKey::from_bytes([0x22; 32]),
        );

        let item_key = ItemKey::try_from_slice(b"path/to/file.txt").expect("item key");
        sink.begin_item(
            &item_key,
            &ItemMeta {
                stable_item_id: StableItemId::from_bytes([0x33; 32]),
                version: None,
                size_hint: None,
            },
        )
        .expect("begin item");

        sink.upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 9,
                    start: 2,
                    end: 12,
                    norm_hash: [0x33; 32],
                    confidence_score: 7,
                }],
            },
        )
        .expect("upsert findings");
        sink.finish_item(&item_key).expect("finish item");

        let identity = recorder.identity.lock().expect("identity lock");
        assert_eq!(identity.len(), 1);
        assert_eq!(identity[0].rule_id(), 9);
        assert_eq!(identity[0].start(), 2);
        assert_eq!(identity[0].end(), 12);
        assert_eq!(identity[0].write_context(), write_context);

        let progress = recorder.progress.lock().expect("progress lock");
        assert_eq!(progress.len(), 2);
        match &progress[0] {
            CommitProgressRecord::Begin {
                write_context: got, ..
            } => {
                assert_eq!(*got, write_context);
            }
            other => panic!("expected begin progress record, got {other:?}"),
        }
    }

    #[test]
    fn upsert_without_begin_item_is_rejected() {
        let recorder = Arc::new(Recorder::default());
        let write_context = WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x12; 32]),
            RunId::from_raw(13),
            ShardId::from_raw(14),
            FenceEpoch::from_raw(15),
        );
        let sink = DurableCommitSink::new(
            recorder.clone(),
            Arc::from("shard-b"),
            write_context,
            TenantSecretKey::from_bytes([0x22; 32]),
        );

        let item_key = ItemKey::try_from_slice(b"path/to/other.txt").expect("item key");
        let result = sink.upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 5,
                    start: 0,
                    end: 10,
                    norm_hash: [0x44; 32],
                    confidence_score: 3,
                }],
            },
        );

        assert!(
            result.is_err(),
            "upsert_findings without begin_item must fail"
        );

        let identity = recorder.identity.lock().expect("identity lock");
        assert!(identity.is_empty(), "identity record must not be produced");
    }

    #[test]
    fn invalid_span_is_rejected_not_silently_zeroed() {
        let recorder = Arc::new(Recorder::default());
        let write_context = WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x12; 32]),
            RunId::from_raw(13),
            ShardId::from_raw(14),
            FenceEpoch::from_raw(15),
        );
        let sink = DurableCommitSink::new(
            recorder.clone(),
            Arc::from("shard-c"),
            write_context,
            TenantSecretKey::from_bytes([0x22; 32]),
        );

        let item_key = ItemKey::try_from_slice(b"path/to/bad.txt").expect("item key");
        sink.begin_item(
            &item_key,
            &ItemMeta {
                stable_item_id: StableItemId::from_bytes([0x33; 32]),
                version: None,
                size_hint: None,
            },
        )
        .expect("begin item");

        // end == start (empty span)
        let result = sink.upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 1,
                    start: 10,
                    end: 10,
                    norm_hash: [0xAA; 32],
                    confidence_score: 5,
                }],
            },
        );
        assert!(
            result.is_err(),
            "empty span (end == start) must be rejected"
        );

        // end < start (inverted span)
        let result = sink.upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 2,
                    start: 20,
                    end: 15,
                    norm_hash: [0xBB; 32],
                    confidence_score: 3,
                }],
            },
        );
        assert!(
            result.is_err(),
            "inverted span (end < start) must be rejected"
        );

        let identity = recorder.identity.lock().expect("identity lock");
        assert!(
            identity.is_empty(),
            "no identity records should be produced for invalid spans"
        );
    }

    #[test]
    fn durable_commit_sink_uses_explicit_version_for_identity() {
        let recorder = Arc::new(Recorder::default());
        let write_context = WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x12; 32]),
            RunId::from_raw(13),
            ShardId::from_raw(14),
            FenceEpoch::from_raw(15),
        );
        let sink = DurableCommitSink::new(
            recorder.clone(),
            Arc::from("shard-v"),
            write_context,
            TenantSecretKey::from_bytes([0x22; 32]),
        );

        let item_key = ItemKey::try_from_slice(b"path/to/versioned.txt").expect("item key");
        let versioned_meta = ItemMeta {
            stable_item_id: StableItemId::from_bytes([0x33; 32]),
            version: Some(VersionId::Strong(ObjectVersionId::from_bytes([0x55; 32]))),
            size_hint: Some(1024),
        };
        sink.begin_item(&item_key, &versioned_meta)
            .expect("begin item");
        sink.upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 9,
                    start: 2,
                    end: 12,
                    norm_hash: [0x33; 32],
                    confidence_score: 7,
                }],
            },
        )
        .expect("upsert findings");

        let versioned_identity = recorder.identity.lock().expect("identity lock");
        assert_eq!(versioned_identity.len(), 1);
        assert_eq!(versioned_identity[0].rule_id(), 9);

        // The version-present path should produce a different occurrence_id
        // than the None-version path for the same item key.
        drop(versioned_identity);

        let recorder2 = Arc::new(Recorder::default());
        let sink2 = DurableCommitSink::new(
            recorder2.clone(),
            Arc::from("shard-v2"),
            write_context,
            TenantSecretKey::from_bytes([0x22; 32]),
        );
        sink2
            .begin_item(
                &item_key,
                &ItemMeta {
                    stable_item_id: StableItemId::from_bytes([0x33; 32]),
                    version: None,
                    size_hint: None,
                },
            )
            .expect("begin item");
        sink2
            .upsert_findings(
                &item_key,
                &FindingsBatch {
                    findings: vec![FindingRecord {
                        rule_id: 9,
                        start: 2,
                        end: 12,
                        norm_hash: [0x33; 32],
                        confidence_score: 7,
                    }],
                },
            )
            .expect("upsert findings");

        let none_identity = recorder2.identity.lock().expect("identity lock");
        assert_eq!(none_identity.len(), 1);
        let versioned_identity = recorder.identity.lock().expect("identity lock");

        assert_ne!(
            versioned_identity[0].occurrence_id(),
            none_identity[0].occurrence_id(),
            "explicit version must produce a different occurrence_id than None-version"
        );
        // Finding IDs should be identical (version doesn't affect finding identity).
        assert_eq!(
            versioned_identity[0].finding_id(),
            none_identity[0].finding_id(),
            "finding_id is version-independent"
        );
    }
}
