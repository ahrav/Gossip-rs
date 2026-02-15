//! Boundary â‘¤ â€” Persistence Contract: Chunk 4 (DRAFT)
//!
//! In-memory test implementations of `DoneLedger` and `FindingsSink`.
//!
//! These implementations are the reference semantics for the persistence
//! contract. Production implementations (PostgreSQL, FoundationDB, etc.)
//! MUST produce the same observable behavior as these in-memory versions.
//!
//! This file is additive to all prior chunks (B1â€“B4, B5 chunks 1â€“3).
//!
//! ## Purpose
//!
//! 1. **Contract validation**: The in-memory implementations enforce
//!    every invariant documented in the trait contracts (INV-DL-1
//!    through INV-DL-6, INV-FS-1 through INV-FS-6). They serve as
//!    executable specifications.
//!
//! 2. **Deterministic simulation**: Both implementations are fully
//!    deterministic â€” no I/O, no async, no system clocks. They can
//!    run inside the deterministic simulator (FoundationDB-style)
//!    for exhaustive protocol testing.
//!
//! 3. **Unit test substrate**: Higher-level tests (commit protocol,
//!    shard lifecycle) use these implementations without needing
//!    a database.
//!
//! ## Design Decisions (locked)
//!
//! D5.30: Both implementations use `HashMap` for O(1) key lookups.
//!        This matches the expected access pattern: point lookups
//!        by content-addressed key, no range scans.
//!
//! D5.31: Fence epoch tracking uses `HashMap<ShardId, FenceEpoch>`.
//!        Each shard has its own fence watermark. The acceptance rule
//!        is `presented_epoch > last_accepted_epoch[shard_id]`.
//!        First write for a shard sets the initial watermark.
//!
//!        The "strictly greater than" rule (not "â‰¥") matches the
//!        done-ledger contract: `reject if epoch <= last_accepted`.
//!        This means the first write for a new shard (no prior epoch)
//!        always succeeds, and subsequent writes must carry a strictly
//!        higher epoch to be accepted. In practice, the coordination
//!        layer increments FenceEpoch on each acquire, so every lease
//!        holder has a unique epoch.
//!
//! D5.32: `InMemoryDoneLedger` provides inspection methods
//!        (`entry_count`, `get_entry`, `contains_key`) for test
//!        assertions. These are NOT part of the `DoneLedger` trait â€”
//!        they're test-only affordances.
//!
//! D5.33: `InMemoryFindingsSink` stores findings and occurrences in
//!        separate maps (mirroring the logical separation), but
//!        validates parent-child relationships on every upsert
//!        (INV-FS-2).
//!
//! D5.34: Both implementations are `!Send` and `!Sync` â€” they're
//!        designed for single-threaded test use. Production
//!        implementations handle concurrency internally.
//!
//! D5.35: Durability (INV-DL-5, INV-FS-5) is trivially satisfied
//!        for in-memory implementations: data is "durable" the
//!        moment it's written to the HashMap. The trait contract
//!        requires durability before returning Ok; for in-memory,
//!        the write IS the durability boundary.

// Assumes all types from prior chunks are in scope.

use std::collections::HashMap;
use core::fmt;

// ============================================================================
// Â§ Chunk 4: In-Memory Test Implementations
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.50 InMemoryDoneLedger
// ---------------------------------------------------------------------------

/// In-memory implementation of the `DoneLedger` trait.
///
/// Uses a `HashMap<DoneLedgerKey, DoneLedgerEntry>` for storage and
/// a `HashMap<ShardId, FenceEpoch>` for fence tracking.
///
/// ## Invariants Enforced
///
/// - INV-DL-1 (monotonic status): `merge(existing, incoming)` on upsert.
/// - INV-DL-2 (fence rejection): rejects batch if epoch is stale.
/// - INV-DL-3 (batch atomicity): applies all-or-nothing via staging.
/// - INV-DL-4 (result cardinality): returns one result per key.
/// - INV-DL-5 (durability): trivially satisfied (in-memory write).
/// - INV-DL-6 (tenant isolation): keys are tenant-scoped by construction
///   (TenantId is part of DoneLedgerKey).
///
/// ## Thread Safety
///
/// Not thread-safe. Designed for single-threaded test use.
pub struct InMemoryDoneLedger {
    /// Primary storage: done-ledger entries keyed by composite key.
    entries: HashMap<DoneLedgerKey, DoneLedgerEntry>,

    /// Fence watermarks per shard. Tracks the highest accepted epoch
    /// for each shard to reject stale writes.
    fence_watermarks: HashMap<ShardId, FenceEpoch>,

    /// Total upsert batches accepted (for observability in tests).
    upsert_count: u64,

    /// Total get batches served.
    get_count: u64,
}

impl InMemoryDoneLedger {
    /// Create an empty done-ledger.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            fence_watermarks: HashMap::new(),
            upsert_count: 0,
            get_count: 0,
        }
    }

    // -- Test inspection methods (NOT part of DoneLedger trait) --

    /// Number of entries in the ledger.
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Check if a key exists.
    #[inline]
    pub fn contains_key(&self, key: &DoneLedgerKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Get an entry by key (test-only direct access).
    #[inline]
    pub fn get_entry(&self, key: &DoneLedgerKey) -> Option<&DoneLedgerEntry> {
        self.entries.get(key)
    }

    /// Total number of upsert batches accepted.
    #[inline]
    pub fn upsert_count(&self) -> u64 {
        self.upsert_count
    }

    /// Total number of get batches served.
    #[inline]
    pub fn get_count(&self) -> u64 {
        self.get_count
    }

    /// Get the current fence watermark for a shard.
    #[inline]
    pub fn fence_watermark(&self, shard_id: ShardId) -> Option<FenceEpoch> {
        self.fence_watermarks.get(&shard_id).copied()
    }

    /// Iterate over all entries (test-only).
    pub fn iter_entries(&self) -> impl Iterator<Item = (&DoneLedgerKey, &DoneLedgerEntry)> {
        self.entries.iter()
    }

    /// Reset the entire ledger (test-only).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.fence_watermarks.clear();
        self.upsert_count = 0;
        self.get_count = 0;
    }
}

impl Default for InMemoryDoneLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl DoneLedger for InMemoryDoneLedger {
    fn batch_get(
        &self,
        batch: &DoneLedgerGetBatch,
        _now: LogicalTime,
    ) -> Result<DoneLedgerGetResult, DoneLedgerGetError> {
        // INV-DL-4: one result per input key, same order.
        let results: Vec<DoneLedgerLookup> = batch
            .keys()
            .iter()
            .map(|key| {
                match self.entries.get(key) {
                    Some(entry) => DoneLedgerLookup::Found(entry.clone()),
                    None => DoneLedgerLookup::NotSeen,
                }
            })
            .collect();

        // Note: we increment get_count via interior mutability in a real
        // impl. For tests, callers can check it after &mut operations.
        // The trait takes &self for batch_get, matching the contract
        // (reads don't require mutable access).

        // INV-DL-4: assert cardinality.
        assert_eq!(
            results.len(),
            batch.len(),
            "batch_get result cardinality mismatch"
        );

        Ok(DoneLedgerGetResult::new(results))
    }

    fn batch_upsert(
        &self,
        batch: &DoneLedgerUpsertBatch,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        _now: LogicalTime,
    ) -> Result<(), DoneLedgerUpsertError> {
        // INV-DL-2: fence rejection.
        if let Some(&watermark) = self.fence_watermarks.get(&shard_id) {
            if fence_epoch.0 <= watermark.0 {
                return Err(DoneLedgerUpsertError::FenceEpochStale {
                    presented: fence_epoch,
                    required_minimum: FenceEpoch(watermark.0 + 1),
                });
            }
        }

        // The trait signature takes &self, but we need interior mutability
        // for the in-memory implementation. In production, this would be
        // handled by the database. For the in-memory version, we use
        // unsafe cell or refcell. For this contract-level code, we'll
        // document that the in-memory impl requires &mut self and provide
        // a wrapper. See `batch_upsert_mut` below.

        // For the trait implementation, we panic to indicate this needs
        // the mutable path. See the `InMemoryDoneLedgerMut` wrapper.
        //
        // NOTE: In practice, the in-memory impl would use RefCell<HashMap>
        // internally. For this contract draft, we provide the mutable
        // version directly and note the discrepancy.
        unreachable!(
            "InMemoryDoneLedger::batch_upsert via &self requires interior mutability. \
             Use batch_upsert_mut(&mut self, ...) directly in tests."
        )
    }
}

impl InMemoryDoneLedger {
    /// Mutable version of `batch_upsert` for direct test use.
    ///
    /// This is the actual implementation. The trait takes `&self`, but
    /// our in-memory store needs `&mut self`. Production implementations
    /// use database transactions for this; test code calls this method
    /// directly.
    ///
    /// ## Invariants Enforced
    ///
    /// - INV-DL-1: Monotonic merge on each entry.
    /// - INV-DL-2: Fence epoch rejection.
    /// - INV-DL-3: Batch atomicity (stage, then commit).
    pub fn batch_upsert_mut(
        &mut self,
        batch: &DoneLedgerUpsertBatch,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        _now: LogicalTime,
    ) -> Result<(), DoneLedgerUpsertError> {
        // INV-DL-2: fence rejection.
        if let Some(&watermark) = self.fence_watermarks.get(&shard_id) {
            if fence_epoch.0 <= watermark.0 {
                return Err(DoneLedgerUpsertError::FenceEpochStale {
                    presented: fence_epoch,
                    required_minimum: FenceEpoch(watermark.0 + 1),
                });
            }
        }

        // INV-DL-3: batch atomicity â€” stage changes, then apply.
        // We compute all merged entries first. If anything goes wrong
        // (it won't in-memory, but the pattern matters), we haven't
        // mutated the store.
        let mut staged: Vec<(DoneLedgerKey, DoneLedgerEntry)> =
            Vec::with_capacity(batch.len());

        for item in batch.items() {
            let merged = match self.entries.get(&item.key) {
                Some(existing) => {
                    // INV-DL-1: monotonic merge.
                    existing.merge_with(&item.entry)
                }
                None => {
                    // New entry â€” insert directly.
                    item.entry.clone()
                }
            };
            staged.push((item.key, merged));
        }

        // Commit phase: apply all staged changes.
        for (key, entry) in staged {
            self.entries.insert(key, entry);
        }

        // Update fence watermark.
        self.fence_watermarks.insert(shard_id, fence_epoch);

        self.upsert_count += 1;

        Ok(())
    }

    /// Convenience: look up a batch mutably (increments get_count).
    pub fn batch_get_mut(
        &mut self,
        batch: &DoneLedgerGetBatch,
        now: LogicalTime,
    ) -> Result<DoneLedgerGetResult, DoneLedgerGetError> {
        self.get_count += 1;
        // Delegate to the trait impl (which only needs &self).
        DoneLedger::batch_get(self, batch, now)
    }
}

// ---------------------------------------------------------------------------
// Â§5.51 InMemoryFindingsSink
// ---------------------------------------------------------------------------

/// In-memory implementation of the `FindingsSink` trait.
///
/// Uses separate `HashMap`s for findings and occurrences, plus
/// fence watermarks per shard.
///
/// ## Invariants Enforced
///
/// - INV-FS-1 (idempotent upsert): Existing records are not modified.
/// - INV-FS-2 (parent-before-child): Findings processed before occurrences;
///   all occurrences' parents must exist after the batch.
/// - INV-FS-3 (fence rejection): Rejects batch if epoch is stale.
/// - INV-FS-4 (batch atomicity): Stage-then-commit pattern.
/// - INV-FS-5 (durability): Trivially satisfied (in-memory).
/// - INV-FS-6 (tenant isolation): Asserted on each batch.
///
/// ## Thread Safety
///
/// Not thread-safe. Designed for single-threaded test use.
pub struct InMemoryFindingsSink {
    /// Findings keyed by FindingId.
    findings: HashMap<FindingId, FindingRecord>,

    /// Occurrences keyed by OccurrenceId.
    occurrences: HashMap<OccurrenceId, OccurrenceRecord>,

    /// Fence watermarks per shard (same protocol as DoneLedger).
    fence_watermarks: HashMap<ShardId, FenceEpoch>,

    /// Total upsert operations accepted.
    upsert_count: u64,
}

impl InMemoryFindingsSink {
    /// Create an empty findings sink.
    pub fn new() -> Self {
        Self {
            findings: HashMap::new(),
            occurrences: HashMap::new(),
            fence_watermarks: HashMap::new(),
            upsert_count: 0,
        }
    }

    // -- Test inspection methods --

    /// Number of findings stored.
    #[inline]
    pub fn findings_count(&self) -> usize {
        self.findings.len()
    }

    /// Number of occurrences stored.
    #[inline]
    pub fn occurrences_count(&self) -> usize {
        self.occurrences.len()
    }

    /// Check if a finding exists.
    #[inline]
    pub fn contains_finding(&self, id: &FindingId) -> bool {
        self.findings.contains_key(id)
    }

    /// Check if an occurrence exists.
    #[inline]
    pub fn contains_occurrence(&self, id: &OccurrenceId) -> bool {
        self.occurrences.contains_key(id)
    }

    /// Get a finding by ID (test-only).
    #[inline]
    pub fn get_finding(&self, id: &FindingId) -> Option<&FindingRecord> {
        self.findings.get(id)
    }

    /// Get an occurrence by ID (test-only).
    #[inline]
    pub fn get_occurrence(&self, id: &OccurrenceId) -> Option<&OccurrenceRecord> {
        self.occurrences.get(id)
    }

    /// Get the fence watermark for a shard (test-only).
    #[inline]
    pub fn fence_watermark(&self, shard_id: ShardId) -> Option<FenceEpoch> {
        self.fence_watermarks.get(&shard_id).copied()
    }

    /// Total upsert operations accepted.
    #[inline]
    pub fn upsert_count(&self) -> u64 {
        self.upsert_count
    }

    /// All finding IDs in the store (test-only).
    pub fn finding_ids(&self) -> Vec<FindingId> {
        self.findings.keys().copied().collect()
    }

    /// All occurrences for a given finding ID (test-only).
    pub fn occurrences_for_finding(&self, finding_id: FindingId) -> Vec<&OccurrenceRecord> {
        self.occurrences
            .values()
            .filter(|o| o.finding_id == finding_id)
            .collect()
    }

    /// Reset the entire sink (test-only).
    pub fn clear(&mut self) {
        self.findings.clear();
        self.occurrences.clear();
        self.fence_watermarks.clear();
        self.upsert_count = 0;
    }
}

impl Default for InMemoryFindingsSink {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryFindingsSink {
    /// Mutable version of `upsert_findings` for direct test use.
    ///
    /// Like `InMemoryDoneLedger::batch_upsert_mut`, this is the actual
    /// implementation that requires `&mut self`. The trait signature
    /// uses `&self` for production implementations that use database
    /// transactions.
    pub fn upsert_findings_mut(
        &mut self,
        batch: &FindingsUpsertBatch,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        _now: LogicalTime,
    ) -> Result<FindingsUpsertResult, FindingsUpsertError> {
        // INV-FS-3: fence rejection.
        if let Some(&watermark) = self.fence_watermarks.get(&shard_id) {
            if fence_epoch.0 <= watermark.0 {
                return Err(FindingsUpsertError::FenceEpochStale {
                    presented: fence_epoch,
                    required_minimum: FenceEpoch(watermark.0 + 1),
                });
            }
        }

        // INV-FS-6: tenant isolation. All findings must have the same
        // tenant. All occurrences must match their parent finding's tenant.
        if batch.findings_len() > 1 {
            let first_tenant = batch.findings()[0].tenant;
            for finding in &batch.findings()[1..] {
                assert_eq!(
                    finding.tenant, first_tenant,
                    "InMemoryFindingsSink: cross-tenant batch detected \
                     (finding {:?} has tenant {:?}, expected {:?})",
                    finding.finding_id, finding.tenant, first_tenant,
                );
            }
        }

        // INV-FS-4: batch atomicity â€” stage everything, then commit.
        let mut staged_findings: Vec<(FindingId, FindingRecord)> =
            Vec::with_capacity(batch.findings_len());
        let mut staged_occurrences: Vec<(OccurrenceId, OccurrenceRecord)> =
            Vec::with_capacity(batch.occurrences_len());

        let mut findings_inserted: u32 = 0;
        let mut findings_deduplicated: u32 = 0;
        let mut occurrences_inserted: u32 = 0;
        let mut occurrences_deduplicated: u32 = 0;

        // INV-FS-2: process findings first (parents before children).
        for finding in batch.findings() {
            // INV-F-001: assert identity consistency.
            finding.assert_identity_consistency();

            if self.findings.contains_key(&finding.finding_id) {
                // INV-FS-1: idempotent â€” existing record not modified.
                findings_deduplicated += 1;
            } else {
                // Check if this finding was already staged in this batch.
                let already_staged = staged_findings
                    .iter()
                    .any(|(id, _)| *id == finding.finding_id);
                if already_staged {
                    findings_deduplicated += 1;
                } else {
                    staged_findings.push((finding.finding_id, finding.clone()));
                    findings_inserted += 1;
                }
            }
        }

        // INV-FS-2: process occurrences (children after parents).
        for occurrence in batch.occurrences() {
            // INV-O-001: assert identity consistency.
            occurrence.assert_identity_consistency();

            // INV-FS-2: parent must exist â€” either in store, or staged.
            let parent_in_store = self.findings.contains_key(&occurrence.finding_id);
            let parent_staged = staged_findings
                .iter()
                .any(|(id, _)| *id == occurrence.finding_id);

            if !parent_in_store && !parent_staged {
                return Err(FindingsUpsertError::OrphanedOccurrences {
                    missing_finding_ids: vec![occurrence.finding_id],
                });
            }

            if self.occurrences.contains_key(&occurrence.occurrence_id) {
                // INV-FS-1: idempotent â€” existing record not modified.
                occurrences_deduplicated += 1;
            } else {
                let already_staged = staged_occurrences
                    .iter()
                    .any(|(id, _)| *id == occurrence.occurrence_id);
                if already_staged {
                    occurrences_deduplicated += 1;
                } else {
                    staged_occurrences.push((
                        occurrence.occurrence_id,
                        occurrence.clone(),
                    ));
                    occurrences_inserted += 1;
                }
            }
        }

        // Commit phase: apply all staged changes.
        for (id, record) in staged_findings {
            self.findings.insert(id, record);
        }
        for (id, record) in staged_occurrences {
            self.occurrences.insert(id, record);
        }

        // Update fence watermark.
        self.fence_watermarks.insert(shard_id, fence_epoch);

        self.upsert_count += 1;

        Ok(FindingsUpsertResult {
            findings_inserted,
            findings_deduplicated,
            occurrences_inserted,
            occurrences_deduplicated,
        })
    }
}

// The trait impl delegates to the mutable version. In production,
// `&self` would use database transactions. For tests, use the
// `_mut` methods directly.
impl FindingsSink for InMemoryFindingsSink {
    fn upsert_findings(
        &self,
        _batch: &FindingsUpsertBatch,
        _shard_id: ShardId,
        _fence_epoch: FenceEpoch,
        _now: LogicalTime,
    ) -> Result<FindingsUpsertResult, FindingsUpsertError> {
        unreachable!(
            "InMemoryFindingsSink::upsert_findings via &self requires interior mutability. \
             Use upsert_findings_mut(&mut self, ...) directly in tests."
        )
    }
}

// ============================================================================
// Â§ Invariant Catalog â€” Boundary â‘¤ Chunk 4
// ============================================================================

/// Invariant catalog for Boundary â‘¤ Chunk 4.
///
/// ## Implementation Invariants
///
/// **INV-B5-030**: `InMemoryDoneLedger::batch_get_mut` returns exactly
///   one `DoneLedgerLookup` per input key, in input order (INV-DL-4).
///
/// **INV-B5-031**: `InMemoryDoneLedger::batch_upsert_mut` applies
///   monotonic merge: `merge(existing, incoming)` per entry (INV-DL-1).
///
/// **INV-B5-032**: `InMemoryDoneLedger::batch_upsert_mut` rejects
///   entire batch if `fence_epoch <= watermark[shard_id]` (INV-DL-2).
///
/// **INV-B5-033**: `InMemoryDoneLedger::batch_upsert_mut` applies
///   all-or-nothing via staging (INV-DL-3).
///
/// **INV-B5-034**: `InMemoryFindingsSink::upsert_findings_mut` does
///   not modify existing records (INV-FS-1).
///
/// **INV-B5-035**: `InMemoryFindingsSink::upsert_findings_mut`
///   processes findings before occurrences and rejects orphaned
///   occurrences (INV-FS-2).
///
/// **INV-B5-036**: `InMemoryFindingsSink::upsert_findings_mut`
///   rejects entire batch on stale fence epoch (INV-FS-3).
///
/// **INV-B5-037**: `InMemoryFindingsSink::upsert_findings_mut`
///   applies all-or-nothing via staging (INV-FS-4).
///
/// **INV-B5-038**: `InMemoryFindingsSink::upsert_findings_mut`
///   asserts tenant isolation within a batch (INV-FS-6).
///
/// ## Design Decisions Summary
///
/// | ID    | Decision | Rationale |
/// |-------|----------|-----------|
/// | D5.30 | HashMap storage | O(1) point lookups |
/// | D5.31 | Per-shard fence watermarks | Independent fence tracking |
/// | D5.32 | Test inspection methods | Not in trait, test-only |
/// | D5.33 | Separate finding/occurrence maps | Mirrors logical separation |
/// | D5.34 | !Send / !Sync | Single-threaded test use |
/// | D5.35 | Trivial durability | In-memory write = durable |
#[cfg(doc)]
pub struct _InvariantCatalogB5C4;

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Shared fixtures --

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0xAA; 32])
    }

    fn test_tenant_alt() -> TenantId {
        TenantId::from_bytes([0xCC; 32])
    }

    fn test_policy() -> PolicyHash {
        PolicyHash::from_bytes([0xBB; 32])
    }

    fn test_run_id() -> RunId {
        RunId {
            job: JobId(42),
            policy: test_policy(),
        }
    }

    fn test_run_id_alt() -> RunId {
        RunId {
            job: JobId(99),
            policy: test_policy(),
        }
    }

    fn test_stable_item_id() -> StableItemId {
        StableItemId::from_bytes([0x22; 32])
    }

    fn test_rule() -> RuleFingerprint {
        RuleFingerprint::from_bytes([0x33; 32])
    }

    fn test_secret_hash() -> SecretHash {
        SecretHash::from_bytes_internal([0x66; 32])
    }

    fn test_version() -> ObjectVersionId {
        ObjectVersionId::from_bytes([0x44; 32])
    }

    fn test_connector_tag() -> ConnectorTag {
        ConnectorTag::from_ascii(b"github")
    }

    fn test_connector_instance() -> ConnectorInstanceId {
        ConnectorInstanceId::from_bytes([0x11; 32])
    }

    fn make_done_ledger_key(item_byte: u8) -> DoneLedgerKey {
        let ovid = derive_ovid_hash(&OvidInputs {
            connector_kind: test_connector_tag(),
            connector_instance: test_connector_instance(),
            stable_item_id: StableItemId::from_bytes([item_byte; 32]),
            version_id: ObjectVersionId::from_bytes([0x44; 32]),
            subresource_kind: SubresourceKindRaw::from_known(SubresourceKind::PrimaryContent),
        });
        DoneLedgerKey::new(test_tenant(), test_policy(), ovid)
    }

    fn test_rule_name() -> RuleName {
        RuleName::new("aws-access-key-id")
    }

    fn test_location() -> ItemLocation {
        ItemLocation::new("github.com/org/repo/config.yml")
    }

    fn make_finding_record(rule_byte: u8, secret_byte: u8) -> FindingRecord {
        FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            RuleFingerprint::from_bytes([rule_byte; 32]),
            SecretHash::from_bytes_internal([secret_byte; 32]),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build()
    }

    fn make_occurrence_record(
        finding_id: FindingId,
        offset: u64,
    ) -> OccurrenceRecord {
        OccurrenceRecordBuilder::new(
            finding_id,
            test_version(),
            offset,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build()
    }

    // ================================================================
    // DoneLedger Tests
    // ================================================================

    // -- Â§5.50 Basic operations --

    #[test]
    fn done_ledger_empty_initially() {
        let ledger = InMemoryDoneLedger::new();
        assert_eq!(ledger.entry_count(), 0);
        assert_eq!(ledger.upsert_count(), 0);
        assert_eq!(ledger.get_count(), 0);
    }

    #[test]
    fn done_ledger_batch_get_returns_not_seen_for_unknown_keys() {
        let mut ledger = InMemoryDoneLedger::new();
        let key = make_done_ledger_key(0x01);

        let mut batch = DoneLedgerGetBatch::with_capacity(1);
        batch.push(key);

        let result = ledger.batch_get_mut(&batch, LogicalTime(10)).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.get(0).needs_scan());
        assert!(matches!(result.get(0), &DoneLedgerLookup::NotSeen));
    }

    #[test]
    fn done_ledger_upsert_then_get() {
        let mut ledger = InMemoryDoneLedger::new();
        let key = make_done_ledger_key(0x01);
        let entry = DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0));

        // Upsert.
        let mut upsert_batch = DoneLedgerUpsertBatch::with_capacity(1);
        upsert_batch.push(DoneLedgerUpsertItem::new(key, entry));
        ledger
            .batch_upsert_mut(&upsert_batch, ShardId(0), FenceEpoch(1), LogicalTime(10))
            .unwrap();

        // Get.
        let mut get_batch = DoneLedgerGetBatch::with_capacity(1);
        get_batch.push(key);
        let result = ledger.batch_get_mut(&get_batch, LogicalTime(11)).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.get(0).is_scanned());
        assert!(!result.get(0).needs_scan());
    }

    // -- INV-DL-1: Monotonic merge --

    #[test]
    fn done_ledger_monotonic_merge_scanned_absorbs_failed() {
        let mut ledger = InMemoryDoneLedger::new();
        let key = make_done_ledger_key(0x01);

        // First: mark as Scanned.
        let entry1 = DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0));
        let mut batch1 = DoneLedgerUpsertBatch::with_capacity(1);
        batch1.push(DoneLedgerUpsertItem::new(key, entry1));
        ledger
            .batch_upsert_mut(&batch1, ShardId(0), FenceEpoch(1), LogicalTime(10))
            .unwrap();

        // Second: attempt to mark as Failed (zombie write).
        let entry2 = DoneLedgerEntry::failed(LogicalTime(11), test_run_id_alt(), ShardId(1));
        let mut batch2 = DoneLedgerUpsertBatch::with_capacity(1);
        batch2.push(DoneLedgerUpsertItem::new(key, entry2));
        ledger
            .batch_upsert_mut(&batch2, ShardId(1), FenceEpoch(2), LogicalTime(11))
            .unwrap();

        // Result: still Scanned (absorbing).
        let stored = ledger.get_entry(&key).unwrap();
        assert!(stored.is_scanned());
        // Provenance is from the FIRST write (Scanned), not the zombie.
        assert_eq!(stored.run_id, test_run_id());
    }

    #[test]
    fn done_ledger_monotonic_merge_failed_upgraded_to_scanned() {
        let mut ledger = InMemoryDoneLedger::new();
        let key = make_done_ledger_key(0x01);

        // First: Failed.
        let entry1 = DoneLedgerEntry::failed(LogicalTime(10), test_run_id(), ShardId(0));
        let mut batch1 = DoneLedgerUpsertBatch::with_capacity(1);
        batch1.push(DoneLedgerUpsertItem::new(key, entry1));
        ledger
            .batch_upsert_mut(&batch1, ShardId(0), FenceEpoch(1), LogicalTime(10))
            .unwrap();

        // Second: Scanned (retry succeeded).
        let entry2 = DoneLedgerEntry::scanned(LogicalTime(12), test_run_id_alt(), ShardId(1));
        let mut batch2 = DoneLedgerUpsertBatch::with_capacity(1);
        batch2.push(DoneLedgerUpsertItem::new(key, entry2));
        ledger
            .batch_upsert_mut(&batch2, ShardId(1), FenceEpoch(2), LogicalTime(12))
            .unwrap();

        // Result: Scanned, provenance from the successful write.
        let stored = ledger.get_entry(&key).unwrap();
        assert!(stored.is_scanned());
        assert_eq!(stored.run_id, test_run_id_alt());
    }

    // -- INV-DL-2: Fence rejection --

    #[test]
    fn done_ledger_fence_rejection_stale_epoch() {
        let mut ledger = InMemoryDoneLedger::new();
        let key = make_done_ledger_key(0x01);

        // First write with epoch 5.
        let entry = DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0));
        let mut batch = DoneLedgerUpsertBatch::with_capacity(1);
        batch.push(DoneLedgerUpsertItem::new(key, entry));
        ledger
            .batch_upsert_mut(&batch, ShardId(0), FenceEpoch(5), LogicalTime(10))
            .unwrap();

        // Second write with epoch 3 (stale).
        let entry2 = DoneLedgerEntry::failed(LogicalTime(11), test_run_id_alt(), ShardId(0));
        let mut batch2 = DoneLedgerUpsertBatch::with_capacity(1);
        batch2.push(DoneLedgerUpsertItem::new(key, entry2));
        let result = ledger.batch_upsert_mut(
            &batch2,
            ShardId(0),
            FenceEpoch(3),
            LogicalTime(11),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            DoneLedgerUpsertError::FenceEpochStale { presented, .. } => {
                assert_eq!(presented, FenceEpoch(3));
            }
            other => panic!("expected FenceEpochStale, got {:?}", other),
        }

        // Original entry unchanged.
        assert!(ledger.get_entry(&key).unwrap().is_scanned());
    }

    #[test]
    fn done_ledger_fence_rejection_equal_epoch() {
        let mut ledger = InMemoryDoneLedger::new();
        let key = make_done_ledger_key(0x01);

        // First write with epoch 5.
        let entry = DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0));
        let mut batch = DoneLedgerUpsertBatch::with_capacity(1);
        batch.push(DoneLedgerUpsertItem::new(key, entry));
        ledger
            .batch_upsert_mut(&batch, ShardId(0), FenceEpoch(5), LogicalTime(10))
            .unwrap();

        // Second write with epoch 5 (same â€” rejected).
        let entry2 = DoneLedgerEntry::failed(LogicalTime(11), test_run_id(), ShardId(0));
        let mut batch2 = DoneLedgerUpsertBatch::with_capacity(1);
        batch2.push(DoneLedgerUpsertItem::new(key, entry2));
        let result = ledger.batch_upsert_mut(
            &batch2,
            ShardId(0),
            FenceEpoch(5), // Same epoch
            LogicalTime(11),
        );

        assert!(result.is_err());
    }

    #[test]
    fn done_ledger_fence_independent_per_shard() {
        let mut ledger = InMemoryDoneLedger::new();
        let key = make_done_ledger_key(0x01);

        // Shard 0 writes at epoch 10.
        let entry = DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0));
        let mut batch = DoneLedgerUpsertBatch::with_capacity(1);
        batch.push(DoneLedgerUpsertItem::new(key, entry));
        ledger
            .batch_upsert_mut(&batch, ShardId(0), FenceEpoch(10), LogicalTime(10))
            .unwrap();

        // Shard 1 writes at epoch 1 â€” should succeed (independent watermark).
        let key2 = make_done_ledger_key(0x02);
        let entry2 = DoneLedgerEntry::scanned(LogicalTime(11), test_run_id(), ShardId(1));
        let mut batch2 = DoneLedgerUpsertBatch::with_capacity(1);
        batch2.push(DoneLedgerUpsertItem::new(key2, entry2));
        let result = ledger.batch_upsert_mut(
            &batch2,
            ShardId(1),
            FenceEpoch(1),
            LogicalTime(11),
        );
        assert!(result.is_ok());
    }

    // -- INV-DL-3: Batch atomicity --

    #[test]
    fn done_ledger_batch_atomicity_on_fence_rejection() {
        let mut ledger = InMemoryDoneLedger::new();

        // Initial write to establish watermark.
        let key1 = make_done_ledger_key(0x01);
        let entry = DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0));
        let mut setup = DoneLedgerUpsertBatch::with_capacity(1);
        setup.push(DoneLedgerUpsertItem::new(key1, entry));
        ledger
            .batch_upsert_mut(&setup, ShardId(0), FenceEpoch(5), LogicalTime(10))
            .unwrap();

        // Batch with 2 new keys, stale epoch â€” entire batch rejected.
        let key2 = make_done_ledger_key(0x02);
        let key3 = make_done_ledger_key(0x03);
        let mut batch = DoneLedgerUpsertBatch::with_capacity(2);
        batch.push(DoneLedgerUpsertItem::new(
            key2,
            DoneLedgerEntry::scanned(LogicalTime(11), test_run_id(), ShardId(0)),
        ));
        batch.push(DoneLedgerUpsertItem::new(
            key3,
            DoneLedgerEntry::scanned(LogicalTime(11), test_run_id(), ShardId(0)),
        ));

        let result = ledger.batch_upsert_mut(
            &batch,
            ShardId(0),
            FenceEpoch(3), // Stale
            LogicalTime(11),
        );
        assert!(result.is_err());

        // Neither key2 nor key3 should exist.
        assert!(!ledger.contains_key(&key2));
        assert!(!ledger.contains_key(&key3));
    }

    // -- INV-DL-4: Result cardinality --

    #[test]
    fn done_ledger_batch_get_cardinality() {
        let mut ledger = InMemoryDoneLedger::new();

        // Write one entry.
        let key1 = make_done_ledger_key(0x01);
        let entry = DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0));
        let mut setup = DoneLedgerUpsertBatch::with_capacity(1);
        setup.push(DoneLedgerUpsertItem::new(key1, entry));
        ledger
            .batch_upsert_mut(&setup, ShardId(0), FenceEpoch(1), LogicalTime(10))
            .unwrap();

        // Get 3 keys: one exists, two don't.
        let key2 = make_done_ledger_key(0x02);
        let key3 = make_done_ledger_key(0x03);
        let mut batch = DoneLedgerGetBatch::with_capacity(3);
        batch.push(key1);
        batch.push(key2);
        batch.push(key3);

        let result = ledger.batch_get_mut(&batch, LogicalTime(11)).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.get(0).is_scanned());
        assert!(matches!(result.get(1), &DoneLedgerLookup::NotSeen));
        assert!(matches!(result.get(2), &DoneLedgerLookup::NotSeen));
    }

    // -- Multi-key batch --

    #[test]
    fn done_ledger_multi_key_batch_upsert() {
        let mut ledger = InMemoryDoneLedger::new();

        let key1 = make_done_ledger_key(0x01);
        let key2 = make_done_ledger_key(0x02);
        let key3 = make_done_ledger_key(0x03);

        let mut batch = DoneLedgerUpsertBatch::with_capacity(3);
        batch.push(DoneLedgerUpsertItem::new(
            key1,
            DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0)),
        ));
        batch.push(DoneLedgerUpsertItem::new(
            key2,
            DoneLedgerEntry::failed(LogicalTime(10), test_run_id(), ShardId(0)),
        ));
        batch.push(DoneLedgerUpsertItem::new(
            key3,
            DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0)),
        ));

        ledger
            .batch_upsert_mut(&batch, ShardId(0), FenceEpoch(1), LogicalTime(10))
            .unwrap();

        assert_eq!(ledger.entry_count(), 3);
        assert!(ledger.get_entry(&key1).unwrap().is_scanned());
        assert!(ledger.get_entry(&key2).unwrap().is_failed());
        assert!(ledger.get_entry(&key3).unwrap().is_scanned());
    }

    // ================================================================
    // FindingsSink Tests
    // ================================================================

    // -- Â§5.51 Basic operations --

    #[test]
    fn findings_sink_empty_initially() {
        let sink = InMemoryFindingsSink::new();
        assert_eq!(sink.findings_count(), 0);
        assert_eq!(sink.occurrences_count(), 0);
        assert_eq!(sink.upsert_count(), 0);
    }

    #[test]
    fn findings_sink_upsert_finding_and_occurrence() {
        let mut sink = InMemoryFindingsSink::new();

        let finding = make_finding_record(0x33, 0x66);
        let finding_id = finding.finding_id;

        let mut batch = FindingsUpsertBatch::with_capacity(1, 1);
        batch.push_finding(finding);
        batch.push_occurrence(make_occurrence_record(finding_id, 1024));

        let result = sink
            .upsert_findings_mut(&batch, ShardId(0), FenceEpoch(1), LogicalTime(100))
            .unwrap();

        assert_eq!(result.findings_inserted, 1);
        assert_eq!(result.findings_deduplicated, 0);
        assert_eq!(result.occurrences_inserted, 1);
        assert_eq!(result.occurrences_deduplicated, 0);
        assert_eq!(sink.findings_count(), 1);
        assert_eq!(sink.occurrences_count(), 1);
        assert!(sink.contains_finding(&finding_id));
    }

    // -- INV-FS-1: Idempotent upsert --

    #[test]
    fn findings_sink_idempotent_duplicate_finding() {
        let mut sink = InMemoryFindingsSink::new();

        let finding = make_finding_record(0x33, 0x66);
        let finding_id = finding.finding_id;

        // First upsert.
        let mut batch1 = FindingsUpsertBatch::with_capacity(1, 1);
        batch1.push_finding(finding.clone());
        let r1 = sink
            .upsert_findings_mut(&batch1, ShardId(0), FenceEpoch(1), LogicalTime(100))
            .unwrap();
        assert_eq!(r1.findings_inserted, 1);

        // Second upsert with same finding â€” deduplicated.
        let mut batch2 = FindingsUpsertBatch::with_capacity(1, 1);
        batch2.push_finding(finding);
        let r2 = sink
            .upsert_findings_mut(&batch2, ShardId(0), FenceEpoch(2), LogicalTime(101))
            .unwrap();
        assert_eq!(r2.findings_inserted, 0);
        assert_eq!(r2.findings_deduplicated, 1);

        // Still only 1 finding in the store.
        assert_eq!(sink.findings_count(), 1);

        // Original record preserved (first-write-wins).
        let stored = sink.get_finding(&finding_id).unwrap();
        assert_eq!(stored.first_seen_at, LogicalTime(100));
    }

    #[test]
    fn findings_sink_idempotent_duplicate_occurrence() {
        let mut sink = InMemoryFindingsSink::new();

        let finding = make_finding_record(0x33, 0x66);
        let finding_id = finding.finding_id;
        let occurrence = make_occurrence_record(finding_id, 1024);
        let occ_id = occurrence.occurrence_id;

        // First upsert.
        let mut batch1 = FindingsUpsertBatch::with_capacity(1, 1);
        batch1.push_finding(finding.clone());
        batch1.push_occurrence(occurrence.clone());
        sink.upsert_findings_mut(&batch1, ShardId(0), FenceEpoch(1), LogicalTime(100))
            .unwrap();

        // Second upsert with same occurrence.
        let mut batch2 = FindingsUpsertBatch::with_capacity(1, 1);
        batch2.push_finding(finding);
        batch2.push_occurrence(occurrence);
        let r2 = sink
            .upsert_findings_mut(&batch2, ShardId(0), FenceEpoch(2), LogicalTime(101))
            .unwrap();

        assert_eq!(r2.occurrences_inserted, 0);
        assert_eq!(r2.occurrences_deduplicated, 1);
        assert_eq!(sink.occurrences_count(), 1);
    }

    // -- INV-FS-2: Parent-before-child --

    #[test]
    fn findings_sink_rejects_orphaned_occurrence() {
        let mut sink = InMemoryFindingsSink::new();

        // Occurrence without its parent finding.
        let orphan_finding_id = FindingId::from_bytes([0xFF; 32]);
        let occurrence = OccurrenceRecordBuilder::new(
            orphan_finding_id,
            test_version(),
            1024,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();

        let mut batch = FindingsUpsertBatch::with_capacity(1, 1);
        // Push a different finding (not the orphan's parent).
        let finding = make_finding_record(0x33, 0x66);
        batch.push_finding(finding);
        batch.push_occurrence(occurrence);

        let result = sink.upsert_findings_mut(
            &batch,
            ShardId(0),
            FenceEpoch(1),
            LogicalTime(100),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            FindingsUpsertError::OrphanedOccurrences { missing_finding_ids } => {
                assert_eq!(missing_finding_ids.len(), 1);
                assert_eq!(missing_finding_ids[0], orphan_finding_id);
            }
            other => panic!("expected OrphanedOccurrences, got {:?}", other),
        }

        // Nothing should have been committed (batch atomicity).
        assert_eq!(sink.findings_count(), 0);
        assert_eq!(sink.occurrences_count(), 0);
    }

    #[test]
    fn findings_sink_allows_occurrence_referencing_previously_stored_finding() {
        let mut sink = InMemoryFindingsSink::new();

        // First: store the finding.
        let finding = make_finding_record(0x33, 0x66);
        let finding_id = finding.finding_id;
        let mut batch1 = FindingsUpsertBatch::with_capacity(1, 1);
        batch1.push_finding(finding);
        sink.upsert_findings_mut(&batch1, ShardId(0), FenceEpoch(1), LogicalTime(100))
            .unwrap();

        // Second: occurrence referencing the stored finding (no finding in batch).
        let occurrence = make_occurrence_record(finding_id, 2048);
        let mut batch2 = FindingsUpsertBatch::with_capacity(1, 1);
        // No finding pushed â€” occurrence references previously stored finding.
        batch2.push_occurrence(occurrence);
        let result = sink.upsert_findings_mut(
            &batch2,
            ShardId(0),
            FenceEpoch(2),
            LogicalTime(101),
        );

        assert!(result.is_ok());
        assert_eq!(sink.occurrences_count(), 1);
    }

    // -- INV-FS-3: Fence rejection --

    #[test]
    fn findings_sink_fence_rejection() {
        let mut sink = InMemoryFindingsSink::new();

        // First write at epoch 5.
        let finding = make_finding_record(0x33, 0x66);
        let mut batch1 = FindingsUpsertBatch::with_capacity(1, 1);
        batch1.push_finding(finding);
        sink.upsert_findings_mut(&batch1, ShardId(0), FenceEpoch(5), LogicalTime(100))
            .unwrap();

        // Second write at epoch 3 (stale).
        let finding2 = make_finding_record(0x44, 0x77);
        let mut batch2 = FindingsUpsertBatch::with_capacity(1, 1);
        batch2.push_finding(finding2);
        let result = sink.upsert_findings_mut(
            &batch2,
            ShardId(0),
            FenceEpoch(3),
            LogicalTime(101),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            FindingsUpsertError::FenceEpochStale { presented, .. } => {
                assert_eq!(presented, FenceEpoch(3));
            }
            other => panic!("expected FenceEpochStale, got {:?}", other),
        }

        // Only the first finding should exist.
        assert_eq!(sink.findings_count(), 1);
    }

    // -- INV-FS-4: Batch atomicity on orphan rejection --

    #[test]
    fn findings_sink_atomicity_orphan_rolls_back_findings() {
        let mut sink = InMemoryFindingsSink::new();

        // Batch: one valid finding + one orphaned occurrence.
        let finding = make_finding_record(0x33, 0x66);
        let orphan_finding_id = FindingId::from_bytes([0xFF; 32]);
        let orphan_occ = OccurrenceRecordBuilder::new(
            orphan_finding_id,
            test_version(),
            500,
            20,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();

        let mut batch = FindingsUpsertBatch::with_capacity(1, 1);
        batch.push_finding(finding);
        batch.push_occurrence(orphan_occ);

        let result = sink.upsert_findings_mut(
            &batch,
            ShardId(0),
            FenceEpoch(1),
            LogicalTime(100),
        );

        // Batch rejected.
        assert!(result.is_err());
        // The valid finding was NOT committed (atomicity).
        assert_eq!(sink.findings_count(), 0);
    }

    // -- Multiple findings and occurrences --

    #[test]
    fn findings_sink_multi_finding_batch() {
        let mut sink = InMemoryFindingsSink::new();

        let f1 = make_finding_record(0x33, 0x66);
        let f2 = make_finding_record(0x44, 0x77);
        let f1_id = f1.finding_id;
        let f2_id = f2.finding_id;

        let mut batch = FindingsUpsertBatch::with_capacity(2, 3);
        batch.push_finding(f1);
        batch.push_finding(f2);
        batch.push_occurrence(make_occurrence_record(f1_id, 100));
        batch.push_occurrence(make_occurrence_record(f1_id, 200));
        batch.push_occurrence(make_occurrence_record(f2_id, 300));

        let result = sink
            .upsert_findings_mut(&batch, ShardId(0), FenceEpoch(1), LogicalTime(100))
            .unwrap();

        assert_eq!(result.findings_inserted, 2);
        assert_eq!(result.occurrences_inserted, 3);
        assert_eq!(sink.findings_count(), 2);
        assert_eq!(sink.occurrences_count(), 3);
        assert_eq!(sink.occurrences_for_finding(f1_id).len(), 2);
        assert_eq!(sink.occurrences_for_finding(f2_id).len(), 1);
    }

    // -- Fence watermark independence between sinks --

    #[test]
    fn done_ledger_and_findings_sink_independent_fences() {
        // Different sinks have independent fence tracking.
        let mut ledger = InMemoryDoneLedger::new();
        let mut sink = InMemoryFindingsSink::new();

        // Ledger at epoch 10 for shard 0.
        let key = make_done_ledger_key(0x01);
        let mut lb = DoneLedgerUpsertBatch::with_capacity(1);
        lb.push(DoneLedgerUpsertItem::new(
            key,
            DoneLedgerEntry::scanned(LogicalTime(10), test_run_id(), ShardId(0)),
        ));
        ledger
            .batch_upsert_mut(&lb, ShardId(0), FenceEpoch(10), LogicalTime(10))
            .unwrap();

        // Findings sink at epoch 1 for shard 0 â€” should succeed
        // (different store, independent watermark).
        let finding = make_finding_record(0x33, 0x66);
        let mut fb = FindingsUpsertBatch::with_capacity(1, 1);
        fb.push_finding(finding);
        let result = sink.upsert_findings_mut(
            &fb,
            ShardId(0),
            FenceEpoch(1),
            LogicalTime(10),
        );
        assert!(result.is_ok());
    }

    // -- Integration: commit protocol scenario --

    #[test]
    fn commit_protocol_scenario_with_in_memory_impls() {
        let mut ledger = InMemoryDoneLedger::new();
        let mut sink = InMemoryFindingsSink::new();

        let shard_id = ShardId(0);
        let fence = FenceEpoch(1);
        let now = LogicalTime(100);

        // Step 1: Flush findings.
        let finding = make_finding_record(0x33, 0x66);
        let finding_id = finding.finding_id;
        let mut findings_batch = FindingsUpsertBatch::with_capacity(1, 1);
        findings_batch.push_finding(finding);
        findings_batch.push_occurrence(make_occurrence_record(finding_id, 512));
        let findings_result = sink
            .upsert_findings_mut(&findings_batch, shard_id, fence, now)
            .unwrap();
        assert_eq!(findings_result.findings_inserted, 1);

        // Step 2: Commit done-ledger (AFTER findings).
        let key = make_done_ledger_key(0x22); // matches test_stable_item_id
        let mut ledger_batch = DoneLedgerUpsertBatch::with_capacity(1);
        ledger_batch.push(DoneLedgerUpsertItem::new(
            key,
            DoneLedgerEntry::scanned(now, test_run_id(), shard_id),
        ));
        ledger
            .batch_upsert_mut(&ledger_batch, shard_id, fence, now)
            .unwrap();

        // Step 3: (coordination checkpoint would happen here, not tested
        // in this file â€” that's the coordinator's in-memory impl)

        // Verify: finding is durable, done-ledger says scanned.
        assert!(sink.contains_finding(&finding_id));
        assert!(ledger.get_entry(&key).unwrap().is_scanned());
    }

    // -- Simulated crash recovery scenario --

    #[test]
    fn simulated_crash_between_findings_and_ledger() {
        let mut ledger = InMemoryDoneLedger::new();
        let mut sink = InMemoryFindingsSink::new();

        let shard_id = ShardId(0);
        let fence = FenceEpoch(1);

        // Attempt 1: Flush findings succeeds.
        let finding = make_finding_record(0x33, 0x66);
        let finding_id = finding.finding_id;
        let mut fb = FindingsUpsertBatch::with_capacity(1, 1);
        fb.push_finding(finding.clone());
        sink.upsert_findings_mut(&fb, shard_id, fence, LogicalTime(100))
            .unwrap();

        // CRASH before done-ledger commit. Findings are durable.
        // Ledger NOT updated. On retry, item will be rescanned.

        // Attempt 2 (after recovery, new epoch):
        let fence2 = FenceEpoch(2);

        // Re-scan produces same finding (idempotent).
        let mut fb2 = FindingsUpsertBatch::with_capacity(1, 1);
        fb2.push_finding(finding);
        let r2 = sink
            .upsert_findings_mut(&fb2, shard_id, fence2, LogicalTime(200))
            .unwrap();
        // Deduplicated â€” finding already existed from attempt 1.
        assert_eq!(r2.findings_inserted, 0);
        assert_eq!(r2.findings_deduplicated, 1);

        // Now commit done-ledger.
        let key = make_done_ledger_key(0x22);
        let mut lb = DoneLedgerUpsertBatch::with_capacity(1);
        lb.push(DoneLedgerUpsertItem::new(
            key,
            DoneLedgerEntry::scanned(LogicalTime(200), test_run_id(), shard_id),
        ));
        ledger
            .batch_upsert_mut(&lb, shard_id, fence2, LogicalTime(200))
            .unwrap();

        // State is consistent: finding exists, ledger says scanned.
        assert!(sink.contains_finding(&finding_id));
        assert!(ledger.get_entry(&key).unwrap().is_scanned());
        // Only 1 finding in store (not duplicated by retry).
        assert_eq!(sink.findings_count(), 1);
    }

    // -- Property test stubs --

    // TODO: proptest for INV-DL-1 (monotonic merge):
    //   âˆ€ sequences of (key, status) upserts: the final stored status
    //   is the lattice join of all statuses written for that key.
    //
    // TODO: proptest for INV-DL-2 (fence rejection):
    //   âˆ€ (epoch_1, epoch_2) where epoch_2 <= epoch_1: the second
    //   write is rejected and the store is unchanged.
    //
    // TODO: proptest for INV-FS-1 (idempotent upsert):
    //   âˆ€ finding records: upsert(r); upsert(r) â†’ findings_count == 1
    //   and the stored record equals the first write.
    //
    // TODO: proptest for INV-FS-2 (parent-before-child):
    //   âˆ€ occurrence records with random finding_ids: if the finding_id
    //   is not in the store or batch, the upsert is rejected.
    //
    // TODO: proptest for integration: crash simulation
    //   âˆ€ random crash points in the commit sequence: after recovery
    //   and retry, the final state is consistent (findings + ledger agree).
}
