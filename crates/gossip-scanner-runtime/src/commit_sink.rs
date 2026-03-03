//! Commit sink adapters for runtime entry points.
//!
//! The distributed sink derives identities at commit time from engine finding
//! records so the scan loop remains focused on detection and scheduling.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use gossip_contracts::{
    connector::ItemKey,
    identity::{
        derive_finding_id, derive_occurrence_id, key_secret_hash, ConnectorTag, FindingIdInputs,
        IdentityInputError, ItemIdentityKey, NormHash, ObjectVersionId, OccurrenceIdInputs,
        RuleFingerprint, TenantId, TenantSecretKey,
    },
};
use gossip_scan_driver::{CommitSink, FindingRecord, FindingsBatch, ItemMeta};

use crate::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, IdentityChainRecord,
};

pub use gossip_scan_driver::NoOpCommitSink as CliNoOpCommitSink;

/// Durable commit sink used by distributed mode.
///
/// This sink derives the full finding identity chain from engine-level finding
/// batches and persists records through the coordinator recorder.
///
/// Derivation flow:
/// `norm_hash -> secret_hash -> finding_id -> occurrence_id`.
///
/// The sink stores per-item metadata from `begin_item` so `upsert_findings`
/// can use connector-provided version IDs when present.
pub struct DurableCommitSink {
    shard_id: String,
    recorder: std::sync::Arc<dyn CoordinationEventRecorder>,
    tenant_id: TenantId,
    tenant_secret_key: TenantSecretKey,
    connector_tag: ConnectorTag,
    in_flight_meta: Mutex<BTreeMap<Vec<u8>, ItemMeta>>,
}

impl DurableCommitSink {
    #[must_use]
    pub fn new(
        recorder: std::sync::Arc<dyn CoordinationEventRecorder>,
        shard_id: impl Into<String>,
        tenant_id: TenantId,
        tenant_secret_key: TenantSecretKey,
        connector_tag: ConnectorTag,
    ) -> Self {
        Self {
            shard_id: shard_id.into(),
            recorder,
            tenant_id,
            tenant_secret_key,
            connector_tag,
            in_flight_meta: Mutex::new(BTreeMap::new()),
        }
    }

    fn metadata_for_item(&self, item_key: &ItemKey) -> Result<ItemMeta> {
        let guard = self
            .in_flight_meta
            .lock()
            .map_err(|_| anyhow!("durable commit sink metadata lock poisoned"))?;
        Ok(guard.get(item_key.as_bytes()).cloned().unwrap_or_default())
    }

    fn item_identity_key(&self, item_key: &ItemKey) -> Result<ItemIdentityKey> {
        ItemIdentityKey::try_new(self.connector_tag, item_key.as_bytes()).map_err(
            |error: IdentityInputError| {
                anyhow!("invalid item key for identity derivation: {error}")
            },
        )
    }

    fn derive_identity_record(
        &self,
        item_key: &ItemKey,
        meta: &ItemMeta,
        finding: &FindingRecord,
    ) -> Result<IdentityChainRecord> {
        let stable_item = self.item_identity_key(item_key)?.stable_id();

        let norm_hash = NormHash::from_digest(finding.norm_hash);
        let secret_hash = key_secret_hash(&self.tenant_secret_key, &norm_hash);

        let finding_id = derive_finding_id(&FindingIdInputs {
            tenant: self.tenant_id,
            item: stable_item,
            rule: rule_fingerprint_from_rule_id(finding.rule_id),
            secret: secret_hash,
        });

        let object_version = meta
            .version
            .map(|version| version.object_version_id())
            .unwrap_or_else(|| ObjectVersionId::from_version_bytes(item_key.as_bytes()));
        let occurrence_id = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_id,
            version: object_version,
            byte_offset: finding.start,
            byte_length: finding.end.saturating_sub(finding.start),
        });

        Ok(IdentityChainRecord {
            item_key: item_key.as_bytes().to_vec(),
            rule_id: finding.rule_id,
            start: finding.start,
            end: finding.end,
            confidence_score: finding.confidence_score,
            norm_hash: *norm_hash.as_bytes(),
            secret_hash: *secret_hash.as_bytes(),
            finding_id: *finding_id.as_bytes(),
            occurrence_id: *occurrence_id.as_bytes(),
        })
    }
}

impl CommitSink for DurableCommitSink {
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
        self.in_flight_meta
            .lock()
            .map_err(|_| anyhow!("durable commit sink metadata lock poisoned"))?
            .insert(item_key.as_bytes().to_vec(), meta.clone());

        self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Begin {
                item_key: item_key.as_bytes().to_vec(),
                size_hint: meta.size_hint,
            },
        )
    }

    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()> {
        let meta = self.metadata_for_item(item_key)?;
        for finding in &batch.findings {
            let record = self.derive_identity_record(item_key, &meta, finding)?;
            self.recorder
                .record_identity_chain(&self.shard_id, record)?;
        }
        Ok(())
    }

    fn finish_item(&self, item_key: &ItemKey) -> Result<()> {
        self.in_flight_meta
            .lock()
            .map_err(|_| anyhow!("durable commit sink metadata lock poisoned"))?
            .remove(item_key.as_bytes());

        self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Finish {
                item_key: item_key.as_bytes().to_vec(),
            },
        )
    }
}

fn rule_fingerprint_from_rule_id(rule_id: u32) -> RuleFingerprint {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&rule_id.to_le_bytes());
    RuleFingerprint::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use gossip_scan_driver::{FindingsBatch, ItemMeta};

    use super::*;
    use crate::coordination_sink::{StoredCoreEvent, StoredGitEvent};

    #[derive(Default)]
    struct Recorder {
        identity: Mutex<Vec<IdentityChainRecord>>,
        progress: Mutex<Vec<CommitProgressRecord>>,
    }

    impl CoordinationEventRecorder for Recorder {
        fn record_core_event(&self, _shard_id: &str, _event: StoredCoreEvent) -> Result<()> {
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
        let sink = DurableCommitSink::new(
            recorder.clone(),
            "shard-a",
            TenantId::from_bytes([0x11; 32]),
            TenantSecretKey::from_bytes([0x22; 32]),
            ConnectorTag::from_ascii(b"fs"),
        );

        let item_key = ItemKey::try_from_slice(b"path/to/file.txt").expect("item key");
        sink.begin_item(&item_key, &ItemMeta::default())
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
        assert_eq!(identity[0].rule_id, 9);
        assert_eq!(identity[0].start, 2);
        assert_eq!(identity[0].end, 12);

        let progress = recorder.progress.lock().expect("progress lock");
        assert_eq!(progress.len(), 2);
    }

    /// Calling `upsert_findings` without a prior `begin_item` is a protocol
    /// violation. The current code silently falls back to `ItemMeta::default()`
    /// via `unwrap_or_default()`, which means identity derivation uses an
    /// item-key-based version ID instead of the connector-provided one. This
    /// test documents that the violation is silently tolerated.
    #[test]
    fn upsert_without_begin_item_uses_default_metadata() {
        let recorder = Arc::new(Recorder::default());
        let sink = DurableCommitSink::new(
            recorder.clone(),
            "shard-b",
            TenantId::from_bytes([0x11; 32]),
            TenantSecretKey::from_bytes([0x22; 32]),
            ConnectorTag::from_ascii(b"fs"),
        );

        let item_key = ItemKey::try_from_slice(b"path/to/other.txt").expect("item key");

        // Deliberately skip begin_item — this is a protocol violation.
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

        // Current behaviour: succeeds silently with default metadata.
        // If we tighten the contract, this should return Err.
        assert!(
            result.is_ok(),
            "upsert_findings without begin_item currently succeeds (uses default metadata)"
        );

        let identity = recorder.identity.lock().expect("identity lock");
        assert_eq!(
            identity.len(),
            1,
            "identity record should still be produced"
        );
    }
}
