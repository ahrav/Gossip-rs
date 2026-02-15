//! Boundary â‘¤ â€” Persistence Contract: Chunk 2 (DRAFT)
//!
//! Findings Sink: the contract for durably persisting detected secrets
//! and their version-specific occurrence locations.
//!
//! This file is additive to Boundaries â‘ â€“â‘£ (all chunks) and B5 chunk 1
//! (done-ledger types and trait).
//!
//! ## Problem Statement
//!
//! When the scanner engine detects a secret in an item, the detection
//! must be durably persisted before the done-ledger is updated (B5C1
//! ordering requirement). The findings sink is the persistence target
//! for these detections.
//!
//! The findings sink must handle:
//!
//! 1. **Idempotent upsert**: The same finding (identified by `FindingId`)
//!    may be produced multiple times due to at-least-once delivery. The
//!    sink must produce the same result regardless of how many times
//!    the same finding is written.
//!
//! 2. **Two-level records**: A finding (stable across versions) may have
//!    multiple occurrences (version-specific locations). Both must be
//!    persisted, but they have different identity and lifecycle semantics.
//!
//! 3. **Triage identity**: End users triage findings (dismiss, acknowledge,
//!    remediate). Triage state should survive policy changes where
//!    possible. This creates a tension between detection identity
//!    (FindingId, which is policy-scoped) and triage identity (which
//!    should be policy-independent).
//!
//! 4. **Fence-gating**: Like the done-ledger, findings writes must be
//!    fence-gated to prevent zombie workers from writing stale data.
//!
//! ## Design Decisions (locked)
//!
//! D5.10: Finding records are **upserted by FindingId**. If a record
//!        with the same FindingId already exists, the upsert is a no-op
//!        (finding metadata is immutable â€” it's derived from the same
//!        deterministic inputs that produced the FindingId).
//!
//!        **Why immutable**: FindingId is a deterministic hash of
//!        `(tenant, item, rule, secret_hash)`. If any of these change,
//!        the FindingId changes. Therefore, the same FindingId always
//!        corresponds to the same metadata. There's nothing to "update."
//!
//!        Reference: Git's content-addressed object model â€” objects are
//!        immutable because their identity IS their content hash.
//!        IPFS CID specification follows the same principle.
//!
//! D5.11: Occurrence records are **upserted by OccurrenceId**. Like
//!        findings, occurrences are content-addressed and immutable.
//!        The same OccurrenceId always corresponds to the same
//!        `(finding, version, offset, length)` tuple.
//!
//!        Occurrences are child records of findings: each occurrence
//!        references its parent `FindingId`. The sink MUST ensure the
//!        parent finding exists before inserting an occurrence. In
//!        practice, findings and their occurrences are always written
//!        in the same batch, so the sink processes findings first,
//!        then occurrences.
//!
//! D5.12: `FindingRecord` carries **display-safe contextual metadata**
//!        beyond the identity fields: `ItemLocation` for human-readable
//!        context, `rule_name` for dashboard display, `first_seen_at`
//!        for temporal ordering.
//!
//!        **Why**: The triage UI needs to display findings with useful
//!        context. Storing this metadata at write time avoids expensive
//!        joins at read time (the scan item and rule objects may not
//!        be readily available when querying historical findings).
//!
//!        These fields are informational â€” they don't participate in
//!        identity derivation and may be updated if a more recent scan
//!        provides better metadata (e.g., a more accurate `ItemLocation`).
//!
//! D5.13: `FindingRecord` includes a `triage_group_key` field for
//!        **policy-resilient triage correlation**.
//!
//!        **The Problem**: `FindingId` includes `RuleFingerprint` and
//!        `SecretHash`, both of which change when policy changes:
//!        - Rule update â†’ new `RuleFingerprint` â†’ new `FindingId`
//!        - Hash mode change â†’ new `SecretHash` â†’ new `FindingId`
//!
//!        When FindingId changes, existing triage state (dismissed,
//!        acknowledged) is "orphaned" â€” the new FindingId has no triage
//!        state, so the finding appears as new to the triaging user.
//!
//!        **The Solution**: `triage_group_key` is a secondary identity
//!        derived from `(tenant_id, stable_item_id)` â€” the dimensions
//!        that survive policy changes. When a policy change produces a
//!        new FindingId for the same logical secret in the same item,
//!        the triage system can use `triage_group_key` to carry forward
//!        triage state from the old FindingId.
//!
//!        **Why not just use (tenant, item) directly?** Because the
//!        triage system needs a fixed-width, pre-computed key for
//!        efficient lookups. Also, separating it as a named concept
//!        makes the design intent explicit.
//!
//!        **Limitations**: This only works for triage correlation within
//!        the same item. If a secret moves to a different file, the
//!        `StableItemId` changes, and triage correlation requires a
//!        higher-level "secret-level" identity (the `SecretHash` itself,
//!        but that also changes on hash mode changes). Full cross-item
//!        secret tracking is a UI/analytics concern, not a contract
//!        concern.
//!
//!        Reference: The `evidence_hash_version` field in `PolicyHash`
//!        (B1 chunk 5) separates normalization changes from rule changes,
//!        enabling finer-grained rescan decisions. `triage_group_key`
//!        is the persistence-side complement of that separation.
//!
//! D5.14: The findings sink uses **batch operations** exclusively,
//!        matching the done-ledger (D5.5) and TigerBeetle's design.
//!
//!        A `FindingsUpsertBatch` contains both finding records AND
//!        their occurrence records in a single batch. The sink processes
//!        findings first (parent records), then occurrences (child
//!        records). This avoids foreign-key violations and enables
//!        single-round-trip persistence.
//!
//! D5.15: The findings sink is fence-gated by `(ShardId, FenceEpoch)`,
//!        matching the done-ledger (D5.6). Both sinks participate in
//!        the same fencing protocol â€” a zombie worker's writes are
//!        rejected by BOTH sinks, not just one.
//!
//!        Reference: Kleppmann, "How to do distributed locking" (2016)
//!        â€” all external services must participate in the fencing
//!        protocol for it to be effective.

// Assumes all types from Boundaries â‘ â€“â‘£ and B5 chunk 1 are in scope:
// use crate::{
//     CanonicalBytes, Hasher, define_id_32,
//     domain_hasher, finalize_32,
//     TenantId, PolicyHash, ConnectorTag, StableItemId,
//     ObjectVersionId, VersionId, FenceEpoch, ShardId,
//     RunId, LogicalTime, RuleFingerprint, SecretHash,
//     FindingId, FindingIdInputs, derive_finding_id,
//     OccurrenceId, OccurrenceIdInputs, derive_occurrence_id,
//     ItemLocation,
//     // From B5 chunk 1:
//     ConnectorInstanceId, SubresourceKindRaw, OvidHash, OvidInputs,
//     DoneLedgerKey,
// };

use core::fmt;
use blake3::Hasher;

// ============================================================================
// Â§ Chunk 2: Findings Sink Contract
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.20 Domain constants for triage correlation
// ---------------------------------------------------------------------------

/// Domain tags for findings-sink hash derivations.
pub mod domain_findings {
    /// Triage group key derivation.
    pub const TRIAGE_GROUP_KEY_V1: &[u8] = b"gossip/persistence/v1/triage-group";
}

// ---------------------------------------------------------------------------
// Â§5.21 TriageGroupKey â€” policy-resilient triage correlation
// ---------------------------------------------------------------------------

define_id_32! {
    /// Secondary identity for correlating triage state across policy changes.
    ///
    /// When detection policy changes (new rules, new hash mode), `FindingId`
    /// changes even though the "same" secret is still present in the "same"
    /// item. `TriageGroupKey` captures the policy-independent dimensions
    /// of the finding, enabling the triage system to carry forward triage
    /// state (dismissed, acknowledged, remediated) to the new FindingId.
    ///
    /// ## Derivation
    ///
    /// ```text
    /// TriageGroupKey = blake3("gossip/persistence/v1/triage-group",
    ///     tenant_id || stable_item_id)
    /// ```
    ///
    /// ## What is included
    ///
    /// - `tenant_id`: Tenant isolation (same item, different tenants = different
    ///   triage groups).
    /// - `stable_item_id`: Item identity. Findings in the same item belong
    ///   to the same triage group.
    ///
    /// ## What is NOT included
    ///
    /// - `RuleFingerprint`: Excluded so triage survives rule updates.
    /// - `SecretHash`: Excluded so triage survives hash mode changes.
    /// - `ObjectVersionId`: Excluded because triage is version-independent.
    ///
    /// ## Usage Pattern
    ///
    /// The triage system (not defined in this crate) uses `TriageGroupKey`
    /// as a secondary index:
    ///
    /// ```text
    /// 1. Old policy scan produces FindingId_A, TriageGroupKey_X
    /// 2. User dismisses FindingId_A â†’ triage state linked to both
    ///    FindingId_A and TriageGroupKey_X
    /// 3. New policy scan produces FindingId_B (different!), TriageGroupKey_X (same!)
    /// 4. Triage system looks up TriageGroupKey_X â†’ finds prior dismissal
    /// 5. User sees FindingId_B as "previously dismissed" (carry-forward)
    /// ```
    ///
    /// ## Granularity Trade-off
    ///
    /// This groups ALL findings in the same item under one key, regardless
    /// of which rule or secret produced them. This is intentionally coarse:
    /// - Finer granularity (per-secret) would require including
    ///   `SecretHash`, which changes on hash mode updates.
    /// - Coarser granularity (per-tenant) would be useless.
    /// - Item-level is the sweet spot: users typically triage at the
    ///   item level ("this file is a false positive" or "this repo is
    ///   excluded"), and a small number of findings per item makes
    ///   carry-forward manageable.
    ///
    /// ## Invariants
    ///
    /// **Safety (determinism)**: Pure function of (tenant, item).
    ///
    /// **Safety (policy-independence)**: Same (tenant, item) â†’ same key,
    /// regardless of policy changes.
    TriageGroupKey
}

/// Inputs for `TriageGroupKey` derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TriageGroupKeyInputs {
    pub tenant: TenantId,
    pub item: StableItemId,
}

impl CanonicalBytes for TriageGroupKeyInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.tenant.write_canonical(h);
        self.item.write_canonical(h);
    }
}

/// Derive a `TriageGroupKey` from its inputs.
///
/// Pure function: same inputs â†’ same output.
pub fn derive_triage_group_key(inputs: &TriageGroupKeyInputs) -> TriageGroupKey {
    let mut h = domain_hasher(domain_findings::TRIAGE_GROUP_KEY_V1);
    inputs.write_canonical(&mut h);
    TriageGroupKey::from_bytes(finalize_32(&h))
}

// ---------------------------------------------------------------------------
// Â§5.22 RuleName â€” display-safe rule identifier
// ---------------------------------------------------------------------------

/// Human-readable rule name for display in triage UIs.
///
/// This is NOT the `RuleFingerprint` (which is a content-addressed hash
/// of the full rule definition). `RuleName` is a stable, user-facing
/// label like `"aws-access-key-id"` or `"generic-private-key"`.
///
/// ## Why a Separate Type
///
/// `RuleFingerprint` is a 32-byte hash â€” not useful for display.
/// `RuleName` is what the user sees in dashboards and triage workflows.
/// Separating them allows rules to evolve (new patterns, new configs)
/// without changing the user-visible name.
///
/// ## Invariants
///
/// **Safety (non-empty)**: A rule name MUST NOT be empty.
///
/// **Safety (display-safe)**: A rule name MUST NOT contain credentials,
/// PII, or other sensitive data. It appears in logs, dashboards, and
/// alert notifications.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuleName(Box<str>);

impl RuleName {
    /// Construct from a string.
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty.
    pub fn new(name: &str) -> Self {
        assert!(!name.is_empty(), "RuleName must not be empty");
        Self(name.into())
    }

    /// The name as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Â§5.23 FindingRecord â€” the durable finding representation
// ---------------------------------------------------------------------------

/// A complete finding record ready for persistence.
///
/// A finding represents: "Rule R detected secret S in item I for tenant T."
/// This is the **version-stable** detection record â€” it doesn't change
/// when the item's version changes (unless the secret disappears).
///
/// ## Identity vs. Metadata
///
/// The record has two categories of fields:
///
/// **Identity fields** (deterministic, participate in `FindingId`):
/// - `finding_id`: The content-addressed identity.
/// - `tenant`: Which tenant owns this finding.
/// - `stable_item_id`: Which item contains the secret.
/// - `rule_fingerprint`: Which detection rule found it.
/// - `secret_hash`: Keyed identity of the secret material.
///
/// **Metadata fields** (informational, NOT in `FindingId`):
/// - `rule_name`: Human-readable rule label for triage UI.
/// - `location`: Human-readable item location for triage UI.
/// - `triage_group_key`: Policy-resilient triage correlation key.
/// - `first_seen_at`: Logical time when first detected.
/// - `first_seen_run`: The run that first detected this finding.
///
/// ## Upsert Semantics
///
/// On upsert:
/// - If no record with this `FindingId` exists â†’ insert.
/// - If a record with this `FindingId` already exists â†’ no-op
///   (the identity fields are guaranteed identical by content-addressing;
///   metadata fields are preserved from the first write).
///
/// **Why first-write-wins for metadata**: The `first_seen_at` timestamp
/// and `first_seen_run` are meaningful only if they reflect the actual
/// first detection. Overwriting them on re-scan would lose the temporal
/// provenance. For `location` and `rule_name`, the first detection's
/// values are stable enough â€” they only change if the item moves or
/// the rule is renamed, which are rare events handled by the triage
/// system, not the sink.
///
/// ## Invariants
///
/// **INV-F-001 (identity consistency)**: `finding_id` MUST equal
///   `derive_finding_id(&FindingIdInputs { tenant, stable_item_id,
///   rule_fingerprint, secret_hash })`. Implementations SHOULD assert
///   this at construction time.
///
/// **INV-F-002 (triage group consistency)**: `triage_group_key` MUST
///   equal `derive_triage_group_key(&TriageGroupKeyInputs { tenant,
///   item: stable_item_id })`.
///
/// **INV-F-003 (tenant scope)**: All records in a single upsert batch
///   MUST belong to the same tenant. Cross-tenant batches are a
///   correctness violation.
#[derive(Clone, Debug)]
pub struct FindingRecord {
    // -- Identity fields --

    /// Deterministic finding identity. Primary key for upsert.
    pub finding_id: FindingId,

    /// Tenant that owns this finding.
    pub tenant: TenantId,

    /// Item containing the secret.
    pub stable_item_id: StableItemId,

    /// Detection rule identity.
    pub rule_fingerprint: RuleFingerprint,

    /// Keyed secret identity. Redacted in Debug (via SecretHash's impl).
    pub secret_hash: SecretHash,

    // -- Metadata fields --

    /// Human-readable rule name for triage display.
    pub rule_name: RuleName,

    /// Human-readable item location for triage display.
    pub location: ItemLocation,

    /// Policy-resilient triage correlation key.
    pub triage_group_key: TriageGroupKey,

    /// Logical time when this finding was first detected.
    /// Meaningful only on first write; preserved on idempotent re-upsert.
    pub first_seen_at: LogicalTime,

    /// The run that first detected this finding.
    pub first_seen_run: RunId,
}

impl FindingRecord {
    /// Validate identity consistency invariants (INV-F-001, INV-F-002).
    ///
    /// Returns `true` if `finding_id` and `triage_group_key` match
    /// their derivation from the record's fields.
    pub fn check_identity_consistency(&self) -> bool {
        let expected_finding = derive_finding_id(&FindingIdInputs {
            tenant: self.tenant,
            item: self.stable_item_id,
            rule: self.rule_fingerprint,
            secret: self.secret_hash,
        });
        let expected_triage = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: self.tenant,
            item: self.stable_item_id,
        });

        self.finding_id == expected_finding
            && self.triage_group_key == expected_triage
    }

    /// Assert identity consistency. Panics on mismatch.
    ///
    /// Call at construction and at persistence boundary for
    /// defense-in-depth.
    ///
    /// Reference: Tiger Style â€” "assert at every boundary."
    pub fn assert_identity_consistency(&self) {
        let expected_finding = derive_finding_id(&FindingIdInputs {
            tenant: self.tenant,
            item: self.stable_item_id,
            rule: self.rule_fingerprint,
            secret: self.secret_hash,
        });
        assert!(
            self.finding_id == expected_finding,
            "FindingRecord identity mismatch: finding_id {:?} != expected {:?}",
            self.finding_id,
            expected_finding,
        );

        let expected_triage = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: self.tenant,
            item: self.stable_item_id,
        });
        assert!(
            self.triage_group_key == expected_triage,
            "FindingRecord triage group mismatch: {:?} != expected {:?}",
            self.triage_group_key,
            expected_triage,
        );
    }
}

// ---------------------------------------------------------------------------
// Â§5.24 FindingRecordBuilder â€” validated construction
// ---------------------------------------------------------------------------

/// Builder for `FindingRecord` with automatic identity derivation
/// and validation.
///
/// The builder computes `finding_id` and `triage_group_key` from
/// the provided fields, ensuring INV-F-001 and INV-F-002 by
/// construction.
pub struct FindingRecordBuilder {
    tenant: TenantId,
    stable_item_id: StableItemId,
    rule_fingerprint: RuleFingerprint,
    secret_hash: SecretHash,
    rule_name: RuleName,
    location: ItemLocation,
    first_seen_at: LogicalTime,
    first_seen_run: RunId,
}

impl FindingRecordBuilder {
    /// Start building a finding record.
    pub fn new(
        tenant: TenantId,
        stable_item_id: StableItemId,
        rule_fingerprint: RuleFingerprint,
        secret_hash: SecretHash,
        rule_name: RuleName,
        location: ItemLocation,
        first_seen_at: LogicalTime,
        first_seen_run: RunId,
    ) -> Self {
        Self {
            tenant,
            stable_item_id,
            rule_fingerprint,
            secret_hash,
            rule_name,
            location,
            first_seen_at,
            first_seen_run,
        }
    }

    /// Build the `FindingRecord`, computing identities and asserting
    /// consistency.
    pub fn build(self) -> FindingRecord {
        let finding_id = derive_finding_id(&FindingIdInputs {
            tenant: self.tenant,
            item: self.stable_item_id,
            rule: self.rule_fingerprint,
            secret: self.secret_hash,
        });

        let triage_group_key = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: self.tenant,
            item: self.stable_item_id,
        });

        let record = FindingRecord {
            finding_id,
            tenant: self.tenant,
            stable_item_id: self.stable_item_id,
            rule_fingerprint: self.rule_fingerprint,
            secret_hash: self.secret_hash,
            rule_name: self.rule_name,
            location: self.location,
            triage_group_key,
            first_seen_at: self.first_seen_at,
            first_seen_run: self.first_seen_run,
        };

        // Tiger Style: assert at construction boundary.
        record.assert_identity_consistency();
        record
    }
}

// ---------------------------------------------------------------------------
// Â§5.25 OccurrenceRecord â€” version-specific location
// ---------------------------------------------------------------------------

/// A version-specific occurrence of a finding.
///
/// An occurrence represents: "Finding F was observed at byte offset O
/// with length L in version V of the item."
///
/// ## Relationship to FindingRecord
///
/// `OccurrenceRecord` is a child of `FindingRecord`. Every occurrence
/// references a parent `FindingId`. The sink MUST ensure the parent
/// finding exists when inserting an occurrence (enforced by batching
/// findings and occurrences together, with findings processed first).
///
/// ## Upsert Semantics
///
/// Like findings, occurrences are upserted by `OccurrenceId`:
/// - If no record with this `OccurrenceId` exists â†’ insert.
/// - If a record already exists â†’ no-op (content-addressed, immutable).
///
/// ## Why Occurrences Are Separate Records
///
/// A single finding may have many occurrences:
/// - Same secret at multiple offsets in the same version
/// - Same secret at different offsets across different versions
///
/// Embedding occurrences in the finding record would:
/// - Make the finding record unbounded (violates Tiger Style)
/// - Require updating the finding on each new version scan
/// - Break the "immutable by content-address" property
///
/// ## Invariants
///
/// **INV-O-001 (identity consistency)**: `occurrence_id` MUST equal
///   `derive_occurrence_id(&OccurrenceIdInputs { finding_id, version_id,
///   byte_offset, byte_length })`.
///
/// **INV-O-002 (parent existence)**: The `finding_id` referenced by
///   this occurrence MUST exist in the findings store. The sink
///   enforces this by processing findings before occurrences within
///   a batch.
///
/// **INV-O-003 (finding scope)**: `finding_id` and `tenant` must be
///   consistent â€” the finding's tenant must match the occurrence's
///   tenant. This is enforced transitively by FindingId derivation
///   (which includes TenantId).
#[derive(Clone, Debug)]
pub struct OccurrenceRecord {
    // -- Identity fields --

    /// Deterministic occurrence identity. Primary key for upsert.
    pub occurrence_id: OccurrenceId,

    /// Parent finding identity. Foreign key to FindingRecord.
    pub finding_id: FindingId,

    /// The specific version in which this occurrence was observed.
    pub version_id: ObjectVersionId,

    /// Byte offset within the version's content where the match starts.
    pub byte_offset: u64,

    /// Byte length of the matched content.
    pub byte_length: u64,

    // -- Metadata fields --

    /// Tenant for query-time scoping. Redundant with FindingRecord's
    /// tenant (derivable from finding_id), but stored for efficient
    /// tenant-scoped queries without joining to the findings table.
    pub tenant: TenantId,

    /// Logical time when this occurrence was first observed.
    /// Meaningful only on first write.
    pub first_seen_at: LogicalTime,

    /// The run that first observed this occurrence.
    pub first_seen_run: RunId,

    /// Shard that processed this occurrence.
    pub shard_id: ShardId,
}

impl OccurrenceRecord {
    /// Validate identity consistency (INV-O-001).
    pub fn check_identity_consistency(&self) -> bool {
        let expected = derive_occurrence_id(&OccurrenceIdInputs {
            finding: self.finding_id,
            version: self.version_id,
            byte_offset: self.byte_offset,
            byte_length: self.byte_length,
        });
        self.occurrence_id == expected
    }

    /// Assert identity consistency. Panics on mismatch.
    pub fn assert_identity_consistency(&self) {
        let expected = derive_occurrence_id(&OccurrenceIdInputs {
            finding: self.finding_id,
            version: self.version_id,
            byte_offset: self.byte_offset,
            byte_length: self.byte_length,
        });
        assert!(
            self.occurrence_id == expected,
            "OccurrenceRecord identity mismatch: occurrence_id {:?} != expected {:?}",
            self.occurrence_id,
            expected,
        );
    }
}

// ---------------------------------------------------------------------------
// Â§5.26 OccurrenceRecordBuilder â€” validated construction
// ---------------------------------------------------------------------------

/// Builder for `OccurrenceRecord` with automatic identity derivation.
pub struct OccurrenceRecordBuilder {
    finding_id: FindingId,
    version_id: ObjectVersionId,
    byte_offset: u64,
    byte_length: u64,
    tenant: TenantId,
    first_seen_at: LogicalTime,
    first_seen_run: RunId,
    shard_id: ShardId,
}

impl OccurrenceRecordBuilder {
    /// Start building an occurrence record.
    pub fn new(
        finding_id: FindingId,
        version_id: ObjectVersionId,
        byte_offset: u64,
        byte_length: u64,
        tenant: TenantId,
        first_seen_at: LogicalTime,
        first_seen_run: RunId,
        shard_id: ShardId,
    ) -> Self {
        Self {
            finding_id,
            version_id,
            byte_offset,
            byte_length,
            tenant,
            first_seen_at,
            first_seen_run,
            shard_id,
        }
    }

    /// Build the `OccurrenceRecord`, computing identity and asserting
    /// consistency.
    pub fn build(self) -> OccurrenceRecord {
        let occurrence_id = derive_occurrence_id(&OccurrenceIdInputs {
            finding: self.finding_id,
            version: self.version_id,
            byte_offset: self.byte_offset,
            byte_length: self.byte_length,
        });

        let record = OccurrenceRecord {
            occurrence_id,
            finding_id: self.finding_id,
            version_id: self.version_id,
            byte_offset: self.byte_offset,
            byte_length: self.byte_length,
            tenant: self.tenant,
            first_seen_at: self.first_seen_at,
            first_seen_run: self.first_seen_run,
            shard_id: self.shard_id,
        };

        record.assert_identity_consistency();
        record
    }
}

// ---------------------------------------------------------------------------
// Â§5.27 FindingsUpsertBatch â€” combined findings + occurrences batch
// ---------------------------------------------------------------------------

/// A batch of finding and occurrence records to upsert atomically.
///
/// ## Structure
///
/// The batch contains two collections:
/// - `findings`: Parent records, keyed by `FindingId`.
/// - `occurrences`: Child records, keyed by `OccurrenceId`, each
///   referencing a parent `FindingId`.
///
/// ## Processing Order
///
/// The sink MUST process findings before occurrences to ensure
/// parent records exist when child records are inserted (INV-O-002).
///
/// ## Deduplication Within a Batch
///
/// If the same `FindingId` appears multiple times in the `findings`
/// vector, the sink keeps the first occurrence (first-write-wins).
/// This matches the cross-batch idempotency semantics.
///
/// Similarly for duplicate `OccurrenceId` values in `occurrences`.
///
/// In practice, the runtime deduplicates before batching, so
/// duplicates within a batch indicate a programming error.
///
/// ## Atomicity
///
/// All records in the batch are written atomically. Either all
/// findings and all occurrences are persisted, or none are.
/// This ensures that a crash during persistence doesn't leave
/// orphaned occurrences without their parent findings.
///
/// ## Size Bounds
///
/// The batch size is bounded by the enumeration page size Ã— max
/// findings per item Ã— max occurrences per finding. The runtime
/// configures these bounds. The batch types enforce capacity limits.
///
/// Reference: Scanner instructions Â§9.4 â€” "Do not use unbounded queues."
#[derive(Clone, Debug)]
pub struct FindingsUpsertBatch {
    findings: Vec<FindingRecord>,
    occurrences: Vec<OccurrenceRecord>,
    findings_capacity: usize,
    occurrences_capacity: usize,
}

impl FindingsUpsertBatch {
    /// Construct with pre-allocated capacities.
    ///
    /// # Panics
    ///
    /// Panics if either capacity is 0.
    pub fn with_capacity(
        findings_capacity: usize,
        occurrences_capacity: usize,
    ) -> Self {
        assert!(findings_capacity > 0, "findings capacity must be > 0");
        assert!(occurrences_capacity > 0, "occurrences capacity must be > 0");
        Self {
            findings: Vec::with_capacity(findings_capacity),
            occurrences: Vec::with_capacity(occurrences_capacity),
            findings_capacity,
            occurrences_capacity,
        }
    }

    /// Add a finding record to the batch.
    ///
    /// # Panics
    ///
    /// Panics if the findings capacity is exceeded.
    pub fn push_finding(&mut self, record: FindingRecord) {
        assert!(
            self.findings.len() < self.findings_capacity,
            "FindingsUpsertBatch findings exceeded capacity: {} >= {}",
            self.findings.len(),
            self.findings_capacity,
        );
        record.assert_identity_consistency();
        self.findings.push(record);
    }

    /// Add an occurrence record to the batch.
    ///
    /// # Panics
    ///
    /// Panics if the occurrences capacity is exceeded.
    pub fn push_occurrence(&mut self, record: OccurrenceRecord) {
        assert!(
            self.occurrences.len() < self.occurrences_capacity,
            "FindingsUpsertBatch occurrences exceeded capacity: {} >= {}",
            self.occurrences.len(),
            self.occurrences_capacity,
        );
        record.assert_identity_consistency();
        self.occurrences.push(record);
    }

    /// Number of finding records.
    #[inline]
    pub fn findings_len(&self) -> usize {
        self.findings.len()
    }

    /// Number of occurrence records.
    #[inline]
    pub fn occurrences_len(&self) -> usize {
        self.occurrences.len()
    }

    /// Total records (findings + occurrences).
    #[inline]
    pub fn total_len(&self) -> usize {
        self.findings.len() + self.occurrences.len()
    }

    /// Is the batch empty (no findings AND no occurrences)?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.occurrences.is_empty()
    }

    /// Access finding records.
    #[inline]
    pub fn findings(&self) -> &[FindingRecord] {
        &self.findings
    }

    /// Access occurrence records.
    #[inline]
    pub fn occurrences(&self) -> &[OccurrenceRecord] {
        &self.occurrences
    }

    /// Validate that all occurrences reference findings present in
    /// this batch or already persisted.
    ///
    /// This method checks against the **batch-local** finding IDs only.
    /// Occurrences referencing previously persisted findings will
    /// appear as "unmatched" â€” the sink resolves this at write time.
    ///
    /// Returns the count of occurrences whose `finding_id` is NOT
    /// found in this batch's findings list.
    pub fn count_unmatched_occurrences(&self) -> usize {
        let finding_ids: std::collections::HashSet<FindingId> = self
            .findings
            .iter()
            .map(|f| f.finding_id)
            .collect();

        self.occurrences
            .iter()
            .filter(|o| !finding_ids.contains(&o.finding_id))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Â§5.28 Findings sink error types
// ---------------------------------------------------------------------------

/// Error type for findings sink `upsert` operations.
///
/// Follows B2's pattern of operation-specific error types (D2.14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingsUpsertError {
    /// The persistence layer is temporarily unavailable.
    /// Caller should retry with backoff.
    Unavailable {
        reason: Box<str>,
    },

    /// The batch size exceeds the persistence layer's limit.
    BatchTooLarge {
        findings_count: usize,
        occurrences_count: usize,
        max_total: usize,
    },

    /// The write was rejected because the fencing epoch is stale.
    ///
    /// A newer worker has taken ownership of the shard. The current
    /// worker MUST stop processing and yield.
    FenceEpochStale {
        presented: FenceEpoch,
        required_minimum: FenceEpoch,
    },

    /// One or more occurrence records reference finding IDs that don't
    /// exist in the store and aren't in the current batch.
    ///
    /// This indicates a programming error: occurrences should always
    /// be batched with their parent findings, or the parent should
    /// already be persisted from a previous batch.
    OrphanedOccurrences {
        /// Finding IDs referenced by occurrences but not found.
        missing_finding_ids: Vec<FindingId>,
    },

    /// An internal error in the persistence layer.
    Internal {
        reason: Box<str>,
    },
}

impl fmt::Display for FindingsUpsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { reason } => {
                write!(f, "findings sink unavailable: {reason}")
            }
            Self::BatchTooLarge {
                findings_count,
                occurrences_count,
                max_total,
            } => {
                write!(
                    f,
                    "batch too large: {findings_count} findings + \
                     {occurrences_count} occurrences, max {max_total}",
                )
            }
            Self::FenceEpochStale { presented, required_minimum } => {
                write!(
                    f,
                    "fence epoch stale: presented {:?}, required >= {:?}",
                    presented, required_minimum,
                )
            }
            Self::OrphanedOccurrences { missing_finding_ids } => {
                write!(
                    f,
                    "orphaned occurrences: {} finding IDs not found",
                    missing_finding_ids.len(),
                )
            }
            Self::Internal { reason } => {
                write!(f, "findings sink internal error: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Â§5.29 FindingsSink trait â€” the persistence contract
// ---------------------------------------------------------------------------

/// Persistence contract for the findings sink.
///
/// The findings sink durably stores detection results: which secrets
/// were found, by which rules, in which items, at which locations.
///
/// ## Operations
///
/// One operation only: `upsert_findings`. This writes both finding
/// records and occurrence records atomically in a single batch.
///
/// ## Idempotency
///
/// `upsert_findings` is idempotent by deterministic content-addressed
/// identity:
/// - `FindingId` = `blake3(domain, tenant, item, rule, secret_hash)`
/// - `OccurrenceId` = `blake3(domain, finding, version, offset, length)`
///
/// Writing the same finding or occurrence twice is a no-op. This is
/// the sink-side guarantee that makes at-least-once delivery safe:
/// a retried scan produces the same FindingId/OccurrenceId values,
/// and the upsert detects them as duplicates.
///
/// Reference: Stripe's idempotency key pattern (Brandur Leach, 2017);
/// scanner instructions Â§3.1 â€” at-least-once + idempotent = exactly-once.
///
/// ## Fence-Gating
///
/// Like the done-ledger (B5C1), findings writes are fence-gated by
/// `(ShardId, FenceEpoch)`. The persistence layer rejects writes
/// from workers with stale epochs.
///
/// Both sinks (findings + done-ledger) participate in the same fencing
/// protocol. This is critical: if findings accepted stale-epoch writes
/// but the done-ledger rejected them, the system would have dangling
/// findings that the done-ledger doesn't know about. Worse, if the
/// done-ledger accepted but findings rejected, the done-ledger would
/// say "scanned" but findings would be missing.
///
/// Reference: Kleppmann, "How to do distributed locking" (2016) â€”
/// "it is not sufficient to use fencing only in one part of the system;
/// all services that participate in the protocol must check the token."
///
/// ## Ordering Contract
///
/// The caller (runtime) MUST call `upsert_findings` BEFORE updating
/// the done-ledger (`DoneLedger::batch_upsert`). This ordering is
/// the fundamental safety property of the persistence layer:
///
/// ```text
///   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///   â”‚ Scanner      â”‚       â”‚ FindingsSink  â”‚       â”‚ DoneLedger     â”‚
///   â”‚ produces     â”‚â”€â”€1â”€â”€â–¶â”‚ upsert_       â”‚â”€â”€2â”€â”€â–¶â”‚ batch_upsert   â”‚
///   â”‚ findings     â”‚       â”‚ findings()    â”‚       â”‚ (committed)    â”‚
///   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
///
///   Step 1: Findings are durably persisted.
///   Step 2: Done-ledger is updated ONLY AFTER step 1 succeeds.
///
///   Crash between 1 and 2: Findings are durable, done-ledger is not.
///   â†’ On retry, items are rescanned, findings are re-upserted (idempotent).
///   â†’ No data loss.
///
///   Crash before 1: Nothing is persisted.
///   â†’ On retry, full rescan of these items. Correct.
///
///   Violating this order (done-ledger before findings):
///   â†’ Done-ledger says "scanned" but findings are not persisted.
///   â†’ Items are skipped on retry. SILENT DATA LOSS.
/// ```
///
/// This is analogous to write-ahead logging (ARIES, Mohan et al. 1992):
/// durable effects (findings) must be written before the commit
/// record (done-ledger entry).
///
/// ## Synchronous API
///
/// Matching B2, B4, and B5C1: synchronous methods with explicit
/// `LogicalTime` for deterministic simulation.
///
/// ## Invariants (implementor obligations)
///
/// **INV-FS-1 (idempotent upsert)**: Upserting a finding/occurrence
///   with an existing ID is a no-op. The stored record is NOT modified.
///
/// **INV-FS-2 (parent-before-child)**: The sink processes finding
///   records before occurrence records within a batch. All occurrences'
///   parent findings MUST exist after the batch completes (either from
///   this batch or from a previous batch).
///
/// **INV-FS-3 (fence rejection)**: The sink MUST reject the entire
///   batch if `fence_epoch <= last_accepted_epoch[shard_id]`.
///
/// **INV-FS-4 (batch atomicity)**: All records in a batch are written
///   atomically. Either all findings and all occurrences are persisted,
///   or none are.
///
/// **INV-FS-5 (durability before ack)**: `upsert_findings` MUST NOT
///   return `Ok(())` until all records are durable (fsync'd or
///   equivalent).
///
/// **INV-FS-6 (tenant isolation)**: All records in a batch MUST belong
///   to the same tenant. The sink SHOULD assert this.
///
/// ## Verification Strategy
///
/// - Deterministic simulation: crash after `upsert_findings` but
///   before `batch_upsert` on done-ledger. Verify re-scan produces
///   idempotent results.
///
/// - Property-based test for INV-FS-1: upsert the same batch twice,
///   verify the store contains exactly one copy of each record.
///
/// - Property-based test for INV-FS-2: verify no orphaned occurrences
///   after any valid batch upsert.
pub trait FindingsSink {
    /// Upsert a batch of finding and occurrence records.
    ///
    /// The sink processes findings first (parent records), then
    /// occurrences (child records), all atomically.
    ///
    /// ## Idempotency
    ///
    /// Records with existing IDs are silently skipped (no-op).
    /// This makes the operation safe for at-least-once delivery.
    ///
    /// ## Fence-Gating
    ///
    /// The write is gated by `(shard_id, fence_epoch)`. The persistence
    /// layer rejects the entire batch if the epoch is stale.
    ///
    /// ## Return Value
    ///
    /// On success, returns `FindingsUpsertResult` with counts of
    /// how many records were newly inserted vs. deduplicated.
    fn upsert_findings(
        &self,
        batch: &FindingsUpsertBatch,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        now: LogicalTime,
    ) -> Result<FindingsUpsertResult, FindingsUpsertError>;
}

// ---------------------------------------------------------------------------
// Â§5.30 FindingsUpsertResult â€” upsert outcome metrics
// ---------------------------------------------------------------------------

/// Result of a findings upsert operation.
///
/// Provides counts for observability: how many records were newly
/// inserted vs. how many were deduplicated (already existed).
///
/// ## Why This Matters
///
/// These counts feed the runtime's scan statistics (B4 `ShardScanStats`):
/// - `findings_inserted` â†’ new detections this cycle.
/// - `findings_deduplicated` â†’ findings that already existed (re-scan hit).
/// - `occurrences_inserted` â†’ new version-specific sightings.
/// - `occurrences_deduplicated` â†’ sightings that already existed.
///
/// High deduplication rates indicate the done-ledger is working (items
/// are being correctly skipped). Low deduplication rates indicate
/// first-time scans or policy changes forcing rescans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsUpsertResult {
    /// Number of finding records newly inserted (not previously present).
    pub findings_inserted: u32,

    /// Number of finding records that already existed (deduplicated).
    pub findings_deduplicated: u32,

    /// Number of occurrence records newly inserted.
    pub occurrences_inserted: u32,

    /// Number of occurrence records that already existed.
    pub occurrences_deduplicated: u32,
}

impl FindingsUpsertResult {
    /// Total findings in the batch (inserted + deduplicated).
    #[inline]
    pub fn findings_total(&self) -> u32 {
        self.findings_inserted + self.findings_deduplicated
    }

    /// Total occurrences in the batch (inserted + deduplicated).
    #[inline]
    pub fn occurrences_total(&self) -> u32 {
        self.occurrences_inserted + self.occurrences_deduplicated
    }

    /// Were any new records inserted?
    #[inline]
    pub fn has_new_records(&self) -> bool {
        self.findings_inserted > 0 || self.occurrences_inserted > 0
    }

    /// Were all records deduplicated (no new inserts)?
    #[inline]
    pub fn fully_deduplicated(&self) -> bool {
        self.findings_inserted == 0 && self.occurrences_inserted == 0
    }
}

impl fmt::Display for FindingsUpsertResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "findings: {} new / {} dedup, occurrences: {} new / {} dedup",
            self.findings_inserted,
            self.findings_deduplicated,
            self.occurrences_inserted,
            self.occurrences_deduplicated,
        )
    }
}

// ============================================================================
// Â§ Invariant Catalog â€” Boundary â‘¤ Chunk 2
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.31 Invariant Catalog
// ---------------------------------------------------------------------------

/// Invariant catalog for Boundary â‘¤ Chunk 2.
///
/// ## Safety Invariants (data types)
///
/// **INV-B5-010**: TriageGroupKey is deterministic.
///   For any `(tenant, item)` pair,
///   `derive_triage_group_key(inputs)` always produces the same key.
///
/// **INV-B5-011**: TriageGroupKey is policy-independent.
///   The same `(tenant, item)` pair produces the same `TriageGroupKey`
///   regardless of which policy produced the finding.
///
/// **INV-B5-012**: FindingRecord identity consistency (INV-F-001).
///   `finding_id == derive_finding_id(tenant, item, rule, secret_hash)`.
///
/// **INV-B5-013**: FindingRecord triage group consistency (INV-F-002).
///   `triage_group_key == derive_triage_group_key(tenant, item)`.
///
/// **INV-B5-014**: OccurrenceRecord identity consistency (INV-O-001).
///   `occurrence_id == derive_occurrence_id(finding, version, offset, len)`.
///
/// **INV-B5-015**: FindingRecordBuilder produces consistent records.
///   Records built via the builder always satisfy INV-F-001 and INV-F-002.
///
/// **INV-B5-016**: OccurrenceRecordBuilder produces consistent records.
///   Records built via the builder always satisfy INV-O-001.
///
/// ## Implementor Invariants (FindingsSink trait)
///
/// **INV-FS-1**: Idempotent upsert (see trait doc).
/// **INV-FS-2**: Parent-before-child processing (see trait doc).
/// **INV-FS-3**: Fence rejection (see trait doc).
/// **INV-FS-4**: Batch atomicity (see trait doc).
/// **INV-FS-5**: Durability before ack (see trait doc).
/// **INV-FS-6**: Tenant isolation (see trait doc).
///
/// ## Design Decisions Summary
///
/// | ID    | Decision | Rationale |
/// |-------|----------|-----------|
/// | D5.10 | Upsert by FindingId | Content-addressed, immutable |
/// | D5.11 | Upsert by OccurrenceId | Content-addressed, immutable |
/// | D5.12 | Display metadata in record | Avoids joins at query time |
/// | D5.13 | TriageGroupKey for correlation | Survives policy changes |
/// | D5.14 | Batch-only API | Amortize latency |
/// | D5.15 | Fence-gated writes | Both sinks participate |
///
/// ## Cross-Boundary Dependencies
///
/// | This Type | Depends On | Boundary |
/// |-----------|------------|----------|
/// | FindingRecord | FindingId, FindingIdInputs | B1 Â§4.4 |
/// | FindingRecord | TenantId | B1 Â§2.2 |
/// | FindingRecord | StableItemId | B1 Â§3.4 |
/// | FindingRecord | RuleFingerprint | B1 Â§4.3 |
/// | FindingRecord | SecretHash | B1 Â§4.2 |
/// | FindingRecord | ItemLocation | B4 Â§1.4 |
/// | OccurrenceRecord | OccurrenceId, OccurrenceIdInputs | B1 Â§4.5 |
/// | OccurrenceRecord | ObjectVersionId | B1 Â§3.2 |
/// | FindingsSink | FenceEpoch, ShardId | B1 Â§2.2 |
/// | FindingsSink | LogicalTime | B1 Â§2.2 |
/// | TriageGroupKey | TenantId, StableItemId | B1 |
/// | RuleName | â€” (new type) | B5 Â§5.22 |
/// | TriageGroupKey | â€” (new type) | B5 Â§5.21 |
#[cfg(doc)]
pub struct _InvariantCatalogB5C2;

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper factories --

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0xAA; 32])
    }

    fn test_tenant_alt() -> TenantId {
        TenantId::from_bytes([0xCC; 32])
    }

    fn test_policy() -> PolicyHash {
        PolicyHash::from_bytes([0xBB; 32])
    }

    fn test_stable_item_id() -> StableItemId {
        StableItemId::from_bytes([0x22; 32])
    }

    fn test_stable_item_id_alt() -> StableItemId {
        StableItemId::from_bytes([0x44; 32])
    }

    fn test_rule() -> RuleFingerprint {
        RuleFingerprint::from_bytes([0x33; 32])
    }

    fn test_rule_alt() -> RuleFingerprint {
        RuleFingerprint::from_bytes([0x55; 32])
    }

    fn test_secret_hash() -> SecretHash {
        // Using from_bytes_internal (test-only access).
        SecretHash::from_bytes_internal([0x66; 32])
    }

    fn test_secret_hash_alt() -> SecretHash {
        SecretHash::from_bytes_internal([0x77; 32])
    }

    fn test_version() -> ObjectVersionId {
        ObjectVersionId::from_bytes([0x44; 32])
    }

    fn test_run_id() -> RunId {
        RunId {
            job: JobId(42),
            policy: test_policy(),
        }
    }

    fn test_location() -> ItemLocation {
        ItemLocation::new("github.com/org/repo/config.yml")
    }

    fn test_rule_name() -> RuleName {
        RuleName::new("aws-access-key-id")
    }

    // -- Â§5.21 TriageGroupKey tests --

    #[test]
    fn triage_group_key_deterministic() {
        let inputs = TriageGroupKeyInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
        };
        let k1 = derive_triage_group_key(&inputs);
        let k2 = derive_triage_group_key(&inputs);
        assert_eq!(k1, k2, "triage group key must be deterministic");
    }

    #[test]
    fn triage_group_key_changes_with_tenant() {
        let k1 = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
        });
        let k2 = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: test_tenant_alt(),
            item: test_stable_item_id(),
        });
        assert_ne!(k1, k2, "different tenant â†’ different triage group");
    }

    #[test]
    fn triage_group_key_changes_with_item() {
        let k1 = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
        });
        let k2 = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: test_tenant(),
            item: test_stable_item_id_alt(),
        });
        assert_ne!(k1, k2, "different item â†’ different triage group");
    }

    #[test]
    fn triage_group_key_independent_of_rule() {
        // Same (tenant, item) with different rules â†’ same triage group.
        // Rules don't participate in triage group derivation.
        let inputs = TriageGroupKeyInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
        };
        let key = derive_triage_group_key(&inputs);

        // If we could somehow pass a rule to the derivation (we can't),
        // it would still produce the same key. This test verifies the
        // derivation only uses tenant + item.
        let key2 = derive_triage_group_key(&inputs);
        assert_eq!(key, key2);
    }

    // -- Â§5.22 RuleName tests --

    #[test]
    fn rule_name_display() {
        let name = RuleName::new("generic-private-key");
        assert_eq!(name.as_str(), "generic-private-key");
        assert_eq!(format!("{}", name), "generic-private-key");
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn rule_name_empty_panics() {
        let _ = RuleName::new("");
    }

    // -- Â§5.23 FindingRecord tests --

    #[test]
    fn finding_record_builder_produces_consistent_record() {
        let record = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        // Builder computes finding_id and triage_group_key automatically.
        assert!(record.check_identity_consistency());

        // Verify finding_id matches manual derivation.
        let expected_finding = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
            rule: test_rule(),
            secret: test_secret_hash(),
        });
        assert_eq!(record.finding_id, expected_finding);

        // Verify triage_group_key matches manual derivation.
        let expected_triage = derive_triage_group_key(&TriageGroupKeyInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
        });
        assert_eq!(record.triage_group_key, expected_triage);
    }

    #[test]
    fn finding_record_identity_consistency_detects_mismatch() {
        let mut record = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        // Tamper with the finding_id.
        record.finding_id = FindingId::from_bytes([0xFF; 32]);
        assert!(!record.check_identity_consistency());
    }

    #[test]
    fn finding_records_same_item_different_rules_different_ids() {
        let r1 = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            RuleName::new("rule-a"),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        let r2 = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule_alt(),
            test_secret_hash(),
            RuleName::new("rule-b"),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        assert_ne!(r1.finding_id, r2.finding_id);
        // Same triage group (same tenant + item).
        assert_eq!(r1.triage_group_key, r2.triage_group_key);
    }

    #[test]
    fn finding_records_same_item_different_secrets_different_ids() {
        let r1 = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        let r2 = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash_alt(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        assert_ne!(r1.finding_id, r2.finding_id);
        // Same triage group (same tenant + item).
        assert_eq!(r1.triage_group_key, r2.triage_group_key);
    }

    // -- Â§5.25 OccurrenceRecord tests --

    #[test]
    fn occurrence_record_builder_produces_consistent_record() {
        let finding_id = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
            rule: test_rule(),
            secret: test_secret_hash(),
        });

        let record = OccurrenceRecordBuilder::new(
            finding_id,
            test_version(),
            1024,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();

        assert!(record.check_identity_consistency());

        let expected = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_id,
            version: test_version(),
            byte_offset: 1024,
            byte_length: 40,
        });
        assert_eq!(record.occurrence_id, expected);
    }

    #[test]
    fn occurrence_records_different_offsets_different_ids() {
        let finding_id = derive_finding_id(&FindingIdInputs {
            tenant: test_tenant(),
            item: test_stable_item_id(),
            rule: test_rule(),
            secret: test_secret_hash(),
        });

        let o1 = OccurrenceRecordBuilder::new(
            finding_id,
            test_version(),
            100,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();

        let o2 = OccurrenceRecordBuilder::new(
            finding_id,
            test_version(),
            500,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();

        assert_ne!(o1.occurrence_id, o2.occurrence_id);
        // Same parent finding.
        assert_eq!(o1.finding_id, o2.finding_id);
    }

    // -- Â§5.27 FindingsUpsertBatch tests --

    #[test]
    fn batch_push_findings_and_occurrences() {
        let mut batch = FindingsUpsertBatch::with_capacity(2, 4);
        assert!(batch.is_empty());

        let finding = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        let finding_id = finding.finding_id;
        batch.push_finding(finding);

        let occurrence = OccurrenceRecordBuilder::new(
            finding_id,
            test_version(),
            1024,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();
        batch.push_occurrence(occurrence);

        assert_eq!(batch.findings_len(), 1);
        assert_eq!(batch.occurrences_len(), 1);
        assert_eq!(batch.total_len(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn batch_count_unmatched_occurrences_all_matched() {
        let mut batch = FindingsUpsertBatch::with_capacity(1, 2);

        let finding = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        let finding_id = finding.finding_id;
        batch.push_finding(finding);

        let occ1 = OccurrenceRecordBuilder::new(
            finding_id,
            test_version(),
            100,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();
        batch.push_occurrence(occ1);

        let occ2 = OccurrenceRecordBuilder::new(
            finding_id,
            test_version(),
            500,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();
        batch.push_occurrence(occ2);

        assert_eq!(batch.count_unmatched_occurrences(), 0);
    }

    #[test]
    fn batch_count_unmatched_occurrences_with_orphan() {
        let mut batch = FindingsUpsertBatch::with_capacity(1, 1);

        let finding = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();
        batch.push_finding(finding);

        // Occurrence referencing a DIFFERENT finding (not in batch).
        let orphan_finding_id = FindingId::from_bytes([0xFF; 32]);
        let orphan = OccurrenceRecordBuilder::new(
            orphan_finding_id,
            test_version(),
            100,
            40,
            test_tenant(),
            LogicalTime(100),
            test_run_id(),
            ShardId(0),
        )
        .build();
        batch.push_occurrence(orphan);

        assert_eq!(batch.count_unmatched_occurrences(), 1);
    }

    #[test]
    #[should_panic(expected = "exceeded capacity")]
    fn batch_panics_on_findings_overflow() {
        let mut batch = FindingsUpsertBatch::with_capacity(1, 1);

        let f1 = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();
        batch.push_finding(f1);

        // Second push should panic.
        let f2 = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule_alt(),
            test_secret_hash(),
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();
        batch.push_finding(f2);
    }

    // -- Â§5.28 Error display tests --

    #[test]
    fn findings_error_display() {
        let err = FindingsUpsertError::Unavailable {
            reason: "disk full".into(),
        };
        assert!(err.to_string().contains("disk full"));

        let err = FindingsUpsertError::BatchTooLarge {
            findings_count: 100,
            occurrences_count: 500,
            max_total: 200,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("500"));

        let err = FindingsUpsertError::FenceEpochStale {
            presented: FenceEpoch(3),
            required_minimum: FenceEpoch(7),
        };
        assert!(err.to_string().contains("stale"));

        let err = FindingsUpsertError::OrphanedOccurrences {
            missing_finding_ids: vec![FindingId::from_bytes([0xFF; 32])],
        };
        assert!(err.to_string().contains("orphaned"));
    }

    // -- Â§5.30 FindingsUpsertResult tests --

    #[test]
    fn upsert_result_accessors() {
        let result = FindingsUpsertResult {
            findings_inserted: 3,
            findings_deduplicated: 2,
            occurrences_inserted: 7,
            occurrences_deduplicated: 1,
        };

        assert_eq!(result.findings_total(), 5);
        assert_eq!(result.occurrences_total(), 8);
        assert!(result.has_new_records());
        assert!(!result.fully_deduplicated());
    }

    #[test]
    fn upsert_result_fully_deduplicated() {
        let result = FindingsUpsertResult {
            findings_inserted: 0,
            findings_deduplicated: 5,
            occurrences_inserted: 0,
            occurrences_deduplicated: 10,
        };

        assert!(!result.has_new_records());
        assert!(result.fully_deduplicated());
    }

    #[test]
    fn upsert_result_display() {
        let result = FindingsUpsertResult {
            findings_inserted: 1,
            findings_deduplicated: 2,
            occurrences_inserted: 3,
            occurrences_deduplicated: 4,
        };
        let msg = format!("{}", result);
        assert!(msg.contains("1 new"));
        assert!(msg.contains("2 dedup"));
        assert!(msg.contains("3 new"));
        assert!(msg.contains("4 dedup"));
    }

    // -- Triage group key: policy-change resilience scenario --

    #[test]
    fn triage_correlation_across_policy_change() {
        // Scenario: Rule update changes FindingId but triage group survives.

        // Old policy: rule_v1 detects a secret.
        let finding_old = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),          // rule_v1
            test_secret_hash(),
            RuleName::new("aws-key-v1"),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        // New policy: rule_v2 detects the same secret (different fingerprint).
        let finding_new = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule_alt(),      // rule_v2 (different fingerprint!)
            test_secret_hash(),   // Same secret.
            RuleName::new("aws-key-v2"),
            test_location(),
            LogicalTime(200),
            test_run_id(),
        )
        .build();

        // FindingIds are different (rule changed).
        assert_ne!(finding_old.finding_id, finding_new.finding_id);

        // TriageGroupKeys are the same (same tenant + item).
        assert_eq!(
            finding_old.triage_group_key,
            finding_new.triage_group_key,
            "triage group key must survive rule changes",
        );
    }

    #[test]
    fn triage_correlation_across_hash_mode_change() {
        // Scenario: Hash mode change produces different SecretHash,
        // which changes FindingId, but triage group survives.

        let finding_old = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash(),      // Unkeyed hash.
            test_rule_name(),
            test_location(),
            LogicalTime(100),
            test_run_id(),
        )
        .build();

        let finding_new = FindingRecordBuilder::new(
            test_tenant(),
            test_stable_item_id(),
            test_rule(),
            test_secret_hash_alt(),  // Keyed hash (different!).
            test_rule_name(),
            test_location(),
            LogicalTime(200),
            test_run_id(),
        )
        .build();

        // FindingIds differ (secret_hash changed).
        assert_ne!(finding_old.finding_id, finding_new.finding_id);

        // TriageGroupKeys are the same.
        assert_eq!(
            finding_old.triage_group_key,
            finding_new.triage_group_key,
            "triage group key must survive hash mode changes",
        );
    }

    // -- Property test stubs --

    // TODO: proptest for INV-B5-010 (TriageGroupKey determinism):
    //   âˆ€ (tenant, item): derive_triage_group_key(t, i) == derive_triage_group_key(t, i)
    //
    // TODO: proptest for INV-B5-012 (FindingRecord identity via builder):
    //   âˆ€ inputs: FindingRecordBuilder::build().check_identity_consistency() == true
    //
    // TODO: proptest for INV-B5-014 (OccurrenceRecord identity via builder):
    //   âˆ€ inputs: OccurrenceRecordBuilder::build().check_identity_consistency() == true
    //
    // TODO: proptest for batch_count_unmatched:
    //   âˆ€ batch where all occurrences reference batch findings:
    //     count_unmatched_occurrences() == 0
    //
    // TODO: proptest for FindingsUpsertResult invariant:
    //   findings_total() == findings_inserted + findings_deduplicated
    //   occurrences_total() == occurrences_inserted + occurrences_deduplicated
}
