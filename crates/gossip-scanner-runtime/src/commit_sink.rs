//! Commit sink adapters for runtime entry points.
//!
//! The distributed sink derives identities at commit time from engine finding
//! records so the scan loop remains focused on detection and scheduling.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{Result, anyhow};
use gossip_contracts::{
    connector::ItemKey,
    identity::{
        FindingIdInputs, NormHash, ObjectVersionId, OccurrenceIdInputs, RuleFingerprint, TenantId,
        TenantSecretKey, derive_finding_id, derive_occurrence_id, key_secret_hash,
    },
};
use gossip_scan_driver::{CommitSink, FindingRecord, FindingsBatch, ItemMeta};

use crate::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, IdentityChainRecord,
};

/// Re-export of the no-op commit sink for CLI use where findings are not persisted.
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
    in_flight_meta: Mutex<BTreeMap<Vec<u8>, ItemMeta>>,
}

impl DurableCommitSink {
    /// Creates a durable commit sink bound to `shard_id`.
    ///
    /// All identity derivation uses the provided `tenant_id` and
    /// `tenant_secret_key`, while stable item identity is trusted from
    /// connector-provided [`ItemMeta`]. Derived records are persisted through
    /// `recorder`.
    #[must_use]
    pub fn new(
        recorder: std::sync::Arc<dyn CoordinationEventRecorder>,
        shard_id: impl Into<String>,
        tenant_id: TenantId,
        tenant_secret_key: TenantSecretKey,
    ) -> Self {
        Self {
            shard_id: shard_id.into(),
            recorder,
            tenant_id,
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
            tenant: self.tenant_id,
            item: meta.stable_item_id,
            rule: rule_fingerprint_from_rule_id(finding.rule_id),
            secret: secret_hash,
        });

        let object_version = meta
            .version
            .map(|version| version.object_version_id())
            .unwrap_or_else(|| {
                tracing::warn!(
                    item_key = ?item_key.as_bytes(),
                    "missing connector version metadata; temporarily deriving ObjectVersionId \
                     from item_key bytes until filesystem version propagation is plumbed"
                );
                ObjectVersionId::from_version_bytes(item_key.as_bytes())
            });
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
        );

        let item_key = ItemKey::try_from_slice(b"path/to/file.txt").expect("item key");
        sink.begin_item(
            &item_key,
            &ItemMeta {
                stable_item_id: gossip_contracts::identity::StableItemId::from_bytes([0x33; 32]),
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
        assert_eq!(identity[0].rule_id, 9);
        assert_eq!(identity[0].start, 2);
        assert_eq!(identity[0].end, 12);

        let progress = recorder.progress.lock().expect("progress lock");
        assert_eq!(progress.len(), 2);
    }

    /// Calling `upsert_findings` without a prior `begin_item` is a protocol
    /// violation and must be rejected so the runtime never fabricates stable
    /// identity or version metadata.
    #[test]
    fn upsert_without_begin_item_is_rejected() {
        let recorder = Arc::new(Recorder::default());
        let sink = DurableCommitSink::new(
            recorder.clone(),
            "shard-b",
            TenantId::from_bytes([0x11; 32]),
            TenantSecretKey::from_bytes([0x22; 32]),
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

        assert!(
            result.is_err(),
            "upsert_findings without begin_item must fail"
        );

        let identity = recorder.identity.lock().expect("identity lock");
        assert!(identity.is_empty(), "identity record must not be produced");
    }
}
