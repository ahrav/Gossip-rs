//! Shared commit-sink traits and lightweight record types for runtime entry points.
//!
//! Distributed receipt-driven execution provides its adapter in
//! `distributed.rs`, while CLI and direct-mode scans use [`CliNoOpCommitSink`].

use std::fmt;

use anyhow::Result;
use gossip_contracts::{
    connector::{ItemKey, VersionId},
    identity::StableItemId,
};

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
///
/// This bridge carries only the identity-relevant finding fields available at
/// the scan-loop seam. Runtime-local metadata such as root-hint offsets is
/// reconstructed or defaulted by the concrete sink implementation when it
/// translates into persistence rows.
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

/// One append-only batch of findings for a single item.
///
/// Callers may submit multiple batches between [`CommitSink::begin_item`] and
/// [`CommitSink::finish_item`]; implementations accumulate them in item order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FindingsBatch {
    /// Findings emitted for one item.
    pub findings: Vec<FindingRecord>,
}

/// Per-item lifecycle sink for scan-result durability.
///
/// The sink models a strict item lifecycle:
///
/// 1. `begin_item` registers one in-flight item key and its metadata,
/// 2. `upsert_findings` appends zero or more finding batches for that item, and
/// 3. `finish_item` seals the item and hands the accumulated result to the
///    implementation-specific durability path.
///
/// Distributed execution routes this lifecycle into the receipt-driven commit
/// pipeline, while direct CLI scans use a no-op implementation.
pub trait CommitSink: Send + Sync {
    /// Register a new item and its metadata.
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()>;

    /// Record one batch of findings for an in-progress item.
    ///
    /// Implementations must reject findings with empty or inverted spans
    /// (`end <= start`).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_record_debug_redacts_norm_hash() {
        let record = FindingRecord {
            rule_id: 1,
            start: 0,
            end: 10,
            norm_hash: [0xDE; 32],
            confidence_score: 5,
        };
        let debug = format!("{record:?}");
        assert!(
            debug.contains("[redacted]"),
            "Debug output must redact norm_hash, got: {debug}"
        );
        assert!(
            !debug.contains("dede"),
            "Debug output must not leak norm_hash bytes, got: {debug}"
        );
    }
}
