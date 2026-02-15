//! Boundary â‘¤ â€” Persistence Contract: Chunk 5 (DRAFT)
//!
//! Consolidated invariant catalog, cross-boundary dependency map,
//! integration helpers, and verification strategy for the entire
//! persistence boundary.
//!
//! This file is additive to all prior chunks (B1â€“B4, B5 chunks 1â€“4).
//! It contains NO new types or traits â€” only documentation, test
//! helpers, and integration tests that exercise the full persistence
//! pipeline.
//!
//! ## Purpose
//!
//! 1. **Single reference**: All persistence invariants, design
//!    decisions, and cross-boundary dependencies in one place.
//!    When reviewing or auditing the persistence layer, start here.
//!
//! 2. **Integration tests**: Tests that exercise the complete
//!    commit protocol pipeline using the in-memory implementations
//!    from chunk 4, validating that the typestate machine, done-ledger,
//!    and findings sink interact correctly.
//!
//! 3. **Verification roadmap**: What needs to be tested, how, and
//!    at what confidence level (property tests, simulation, TLA+).
//!
//! ## Document Structure
//!
//! - Â§5.60: Consolidated invariant catalog (all B5 invariants).
//! - Â§5.61: Consolidated design decision log (all D5.x decisions).
//! - Â§5.62: Cross-boundary dependency map.
//! - Â§5.63: Verification strategy and test roadmap.
//! - Â§5.64: Integration test helpers.
//! - Â§5.65: Integration tests.

// ============================================================================
// Â§5.60 Consolidated Invariant Catalog â€” Boundary â‘¤
// ============================================================================

/// # Boundary â‘¤ Invariant Catalog
///
/// Complete catalog of all safety and liveness invariants for the
/// persistence layer. Each invariant is tagged with its source chunk
/// and the enforcement mechanism.
///
/// ## Notation
///
/// - **INV-B5-NNN**: Boundary-level invariant (type/algorithm correctness).
/// - **INV-DL-N**: DoneLedger implementor obligation.
/// - **INV-FS-N**: FindingsSink implementor obligation.
/// - **INV-F-NNN**: FindingRecord structural invariant.
/// - **INV-O-NNN**: OccurrenceRecord structural invariant.
/// - **INV-CP-NNN**: CommitPlan structural invariant.
/// - **INV-PROOF-NNN**: CommitProof structural invariant.
/// - **INV-SCP-NNN**: ShardCompletionProof structural invariant.
///
/// ---
///
/// ## Identity & Hashing (Chunk 1)
///
/// **INV-B5-001** (OvidHash determinism):
///   `âˆ€ v: OvidInputs, derive_ovid_hash(v) == derive_ovid_hash(v)`
///   *Enforcement*: Pure function over BLAKE3. Tested.
///
/// **INV-B5-002** (OvidHash collision resistance):
///   `âˆ€ a â‰  b: P(derive_ovid_hash(a) == derive_ovid_hash(b)) < 2^-128`
///   *Enforcement*: BLAKE3 cryptographic guarantee.
///
/// **INV-B5-003** (DoneLedgerKey determinism):
///   Same `(tenant, policy, ovid_inputs)` â†’ same key.
///   *Enforcement*: Concatenation of fixed-width fields. Tested.
///
/// **INV-B5-004** (DoneLedgerStatus is a join-semilattice):
///   `merge` is commutative, associative, idempotent, with `Scanned`
///   as absorbing element.
///   *Enforcement*: `max(discriminant)`. Tested (commutativity,
///   idempotency, absorption).
///
/// **INV-B5-005** (Scanned is absorbing):
///   `âˆ€ sâ‚..sâ‚™, âˆƒ i: sáµ¢ == Scanned âŸ¹ fold(merge, sâ‚..sâ‚™) == Scanned`
///   *Enforcement*: Follows from INV-B5-004. Tested.
///
/// **INV-B5-006** (Entry merge provenance):
///   Status upgrade â†’ wholesale provenance replacement.
///   No upgrade â†’ existing provenance preserved.
///   *Enforcement*: `merge_with` implementation. Tested.
///
/// **INV-B5-007** (SubresourceKind discriminant stability):
///   Values 0â€“7 are assigned. Extension range 128â€“255 for connectors.
///   *Enforcement*: `repr(u8)`, documentation, review.
///
/// ## Findings & Triage Identity (Chunk 2)
///
/// **INV-B5-010** (TriageGroupKey determinism):
///   Same `(tenant, stable_item_id)` â†’ same key.
///   *Enforcement*: BLAKE3 domain-tagged hash. Tested.
///
/// **INV-B5-011** (TriageGroupKey policy independence):
///   Changing RuleFingerprint or SecretHash does NOT change the key.
///   *Enforcement*: Key inputs exclude rule and secret dimensions. Tested.
///
/// **INV-B5-012** (FindingRecord identity consistency â€” INV-F-001):
///   `finding_id == derive_finding_id(tenant, item, rule, secret_hash)`
///   *Enforcement*: `assert_identity_consistency()`, builder. Tested.
///
/// **INV-B5-013** (FindingRecord triage group â€” INV-F-002):
///   `triage_group_key == derive_triage_group_key(tenant, item)`
///   *Enforcement*: `assert_identity_consistency()`, builder. Tested.
///
/// **INV-B5-014** (OccurrenceRecord identity â€” INV-O-001):
///   `occurrence_id == derive_occurrence_id(finding, version, offset, length)`
///   *Enforcement*: `assert_identity_consistency()`, builder. Tested.
///
/// **INV-B5-015** (Builder consistency for FindingRecord):
///   Records built via `FindingRecordBuilder` always satisfy INV-F-001,
///   INV-F-002.
///   *Enforcement*: Builder computes IDs from inputs. Tested.
///
/// **INV-B5-016** (Builder consistency for OccurrenceRecord):
///   Records built via `OccurrenceRecordBuilder` always satisfy INV-O-001.
///   *Enforcement*: Builder computes IDs from inputs. Tested.
///
/// ## Commit Protocol (Chunk 3)
///
/// **INV-B5-020** (Commit ordering):
///   Findings flush â†’ done-ledger commit â†’ coordination checkpoint.
///   *Enforcement*: Typestate machine â€” compile-time. Untestable by
///   negative case (compile errors), tested via positive path.
///
/// **INV-B5-021** (Proof by construction):
///   `CommitProof` exists iff all three phases completed in order.
///   *Enforcement*: No public constructor. Only produced by
///   `PageCommit<LedgerCommitted>::record_checkpointed`.
///
/// **INV-B5-022** (Receipt consistency):
///   `entries_scanned + entries_failed == entries_committed`.
///   *Enforcement*: `LedgerCommitReceipt::assert_consistent()` at
///   construction. Tested (positive and negative).
///
/// **INV-B5-023** (Timing monotonicity):
///   `started_at <= completed_at` for every `CommitProof`.
///   *Enforcement*: `debug_assert` in `duration_logical()`.
///
/// **INV-B5-024** (Shard completion consistency):
///   For `Done` shards, `stats.is_fully_processed()` must hold.
///   *Enforcement*: `ShardCompletionProof::done()` calls
///   `assert_fully_processed()`. Tested.
///
/// **INV-B5-025** (Fence consistency across phases):
///   All three phases use the same `(shard_id, fence_epoch)`.
///   *Enforcement*: Values come from `CommitPlan`, immutable after
///   construction. Accessors expose the same values at each phase.
///
/// ## In-Memory Implementations (Chunk 4)
///
/// **INV-B5-030** (batch_get cardinality):
///   Returns exactly one `DoneLedgerLookup` per input key.
///   *Enforcement*: `assert_eq!(results.len(), batch.len())`. Tested.
///
/// **INV-B5-031** (Monotonic merge in InMemoryDoneLedger):
///   `merge(existing, incoming)` applied per entry on upsert.
///   *Enforcement*: `merge_with` in implementation. Tested.
///
/// **INV-B5-032** (Fence rejection in InMemoryDoneLedger):
///   Rejects batch if `epoch <= watermark[shard_id]`.
///   *Enforcement*: Watermark check before staging. Tested.
///
/// **INV-B5-033** (Batch atomicity in InMemoryDoneLedger):
///   All-or-nothing via stage-then-commit.
///   *Enforcement*: Implementation pattern. Tested (fence rejection
///   leaves store unchanged).
///
/// **INV-B5-034** (Idempotent upsert in InMemoryFindingsSink):
///   Existing records not modified on re-upsert.
///   *Enforcement*: `contains_key` check. Tested.
///
/// **INV-B5-035** (Parent-before-child in InMemoryFindingsSink):
///   Findings processed first; orphaned occurrences rejected.
///   *Enforcement*: Parent existence check. Tested.
///
/// **INV-B5-036** (Fence rejection in InMemoryFindingsSink):
///   Rejects batch if epoch <= watermark[shard_id].
///   *Enforcement*: Watermark check. Tested.
///
/// **INV-B5-037** (Batch atomicity in InMemoryFindingsSink):
///   Stage-then-commit. Orphan rejection rolls back findings.
///   *Enforcement*: Implementation pattern. Tested.
///
/// **INV-B5-038** (Tenant isolation in InMemoryFindingsSink):
///   All findings in a batch must have the same tenant.
///   *Enforcement*: `assert_eq` at batch processing. Tested.
///
/// ---
///
/// ## DoneLedger Implementor Obligations
///
/// | ID | Invariant | Mechanism |
/// |----|-----------|-----------|
/// | INV-DL-1 | Monotonic status merge | `merge(existing, incoming)` |
/// | INV-DL-2 | Fence epoch rejection | `epoch <= watermark â†’ reject` |
/// | INV-DL-3 | Batch atomicity | All-or-nothing |
/// | INV-DL-4 | Result cardinality | `result.len() == batch.len()` |
/// | INV-DL-5 | Durability before ack | fsync before `Ok(())` |
/// | INV-DL-6 | Tenant isolation | Key includes TenantId |
///
/// ## FindingsSink Implementor Obligations
///
/// | ID | Invariant | Mechanism |
/// |----|-----------|-----------|
/// | INV-FS-1 | Idempotent upsert | First-write-wins by content ID |
/// | INV-FS-2 | Parent-before-child | Process findings then occurrences |
/// | INV-FS-3 | Fence epoch rejection | `epoch <= watermark â†’ reject` |
/// | INV-FS-4 | Batch atomicity | All-or-nothing |
/// | INV-FS-5 | Durability before ack | fsync before `Ok(...)` |
/// | INV-FS-6 | Tenant isolation | Assert single-tenant batches |
#[cfg(doc)]
pub struct _ConsolidatedInvariantCatalog;

// ============================================================================
// Â§5.61 Consolidated Design Decision Log â€” Boundary â‘¤
// ============================================================================

/// # Boundary â‘¤ Design Decision Log
///
/// Complete log of all design decisions locked during B5 development.
/// Each decision is tagged with its source chunk.
///
/// ## Chunk 1: Done-Ledger Types
///
/// | ID   | Decision | Rationale |
/// |------|----------|-----------|
/// | D5.1 | OVID is a BLAKE3 hash | Fixed-width key, storage-agnostic |
/// | D5.2 | ConnectorInstanceId is 32-byte | Cross-installation isolation |
/// | D5.3 | SubresourceKind is u8 with extension range | Compact, extensible, stable discriminants |
/// | D5.4 | Monotonic status (join-semilattice) | CRDT-style zombie-safe merge |
/// | D5.5 | Batch-only API | Amortize latency, match TigerBeetle pattern |
/// | D5.6 | Fence-gated mutations | Zombie worker protection via fencing tokens |
/// | D5.7 | LogicalTime provenance | Clock-independent correctness (Â§9.5) |
///
/// ## Chunk 2: Findings Sink Types
///
/// | ID    | Decision | Rationale |
/// |-------|----------|-----------|
/// | D5.10 | Upsert by FindingId | Content-addressed, immutable (Git object model) |
/// | D5.11 | Upsert by OccurrenceId | Content-addressed, immutable |
/// | D5.12 | Display metadata in FindingRecord | Avoids joins at query time |
/// | D5.13 | TriageGroupKey for triage correlation | Survives policy changes (rule updates, hash mode) |
/// | D5.14 | Batch-only API for findings sink | Match done-ledger (D5.5), TigerBeetle |
/// | D5.15 | Fence-gated writes for both sinks | Both participate in fencing protocol (D5.6) |
///
/// ## Chunk 3: Commit Protocol
///
/// | ID    | Decision | Rationale |
/// |-------|----------|-----------|
/// | D5.20 | Typestate commit protocol | Compile-time ordering enforcement |
/// | D5.21 | Phase receipts as proof chain | Auditable, observable |
/// | D5.22 | Page-granularity commits | Balance latency vs. crash-window risk |
/// | D5.23 | Plan/proof framework, not executor | Decouple ordering from error/retry strategy |
/// | D5.24 | Uniform protocol for empty pages | Avoid special-case bugs |
///
/// ## Chunk 4: In-Memory Implementations
///
/// | ID    | Decision | Rationale |
/// |-------|----------|-----------|
/// | D5.30 | HashMap storage | O(1) point lookups, matches access pattern |
/// | D5.31 | Per-shard fence watermarks | Independent fence tracking per shard |
/// | D5.32 | Test inspection methods (non-trait) | Test-only affordances |
/// | D5.33 | Separate finding/occurrence maps | Mirrors logical separation |
/// | D5.34 | `!Send` / `!Sync` | Single-threaded test use |
/// | D5.35 | Trivial durability | In-memory write = durable |
#[cfg(doc)]
pub struct _ConsolidatedDesignDecisions;

// ============================================================================
// Â§5.62 Cross-Boundary Dependency Map
// ============================================================================

/// # Boundary â‘¤ Cross-Boundary Dependency Map
///
/// Complete listing of every type from Boundaries â‘ â€“â‘£ consumed by
/// Boundary â‘¤. This map enables impact analysis: if a type in B1
/// changes, which B5 types are affected?
///
/// ## From Boundary â‘  â€” Identity Spine
///
/// | B1 Type | Used By (B5) | Purpose |
/// |---------|-------------|---------|
/// | `TenantId` | DoneLedgerKey, FindingRecord, OccurrenceRecord, CommitPlan | Tenant scoping |
/// | `PolicyHash` | DoneLedgerKey | Policy-scoped done-ledger keys |
/// | `StableItemId` | FindingRecord, TriageGroupKey | Item-level identity |
/// | `ObjectVersionId` | OccurrenceRecord, OvidInputs | Version-specific identity |
/// | `RuleFingerprint` | FindingRecord | Rule identity for detection |
/// | `SecretHash` | FindingRecord | Secret identity (hash-mode-dependent) |
/// | `FindingId` | FindingRecord, OccurrenceRecord, FindingsUpsertBatch | Finding content address |
/// | `OccurrenceId` | OccurrenceRecord, FindingsUpsertBatch | Occurrence content address |
/// | `FindingIdInputs` | FindingRecordBuilder | Finding ID derivation |
/// | `OccurrenceIdInputs` | OccurrenceRecordBuilder | Occurrence ID derivation |
/// | `derive_finding_id` | FindingRecordBuilder | Finding ID computation |
/// | `derive_occurrence_id` | OccurrenceRecordBuilder | Occurrence ID computation |
/// | `FenceEpoch` | DoneLedger, FindingsSink, CommitPlan | Fencing token protocol |
/// | `ShardId` | DoneLedgerEntry, DoneLedger, FindingsSink, CommitPlan | Shard identity |
/// | `RunId` | DoneLedgerEntry | Provenance tracking |
/// | `JobId` | RunId (transitive) | Run identity component |
/// | `LogicalTime` | DoneLedgerEntry, FindingRecord, receipts | Deterministic timestamps |
/// | `ShardKey` | CommitPlan, CommitProof, ShardCompletionProof | Shard coordination key |
/// | `OpId` | CommitPlan, CheckpointReceipt | Idempotent operation identity |
/// | `Lease` | (runtime usage, not direct B5 type dep) | Fencing proof |
/// | `ConnectorTag` | OvidInputs | Connector kind identity |
/// | `CanonicalBytes` | SubresourceKindRaw, DoneLedgerStatus | Hashing trait |
/// | `domain_hasher` | OvidHash, TriageGroupKey derivation | Domain-tagged BLAKE3 |
/// | `finalize_32` | OvidHash, TriageGroupKey derivation | Hash finalization |
/// | `define_id_32!` | ConnectorInstanceId, OvidHash | 32-byte ID type macro |
///
/// ## From Boundary â‘¡ â€” Coordination Contracts
///
/// | B2 Type | Used By (B5) | Purpose |
/// |---------|-------------|---------|
/// | `Cursor` | CommitPlan, CheckpointReceipt | Shard progress position |
/// | `ShardStatus` | (informational dep for ShardTerminalOutcome) | Shard lifecycle |
/// | `ParkReason` | ShardTerminalOutcome | Park categorization |
/// | `CoordinationBackend` | (runtime usage for checkpoint/complete) | Coordination trait |
///
/// ## From Boundary â‘£ â€” Connector Contracts
///
/// | B4 Type | Used By (B5) | Purpose |
/// |---------|-------------|---------|
/// | `ItemLocation` | FindingRecord | Human-readable item path |
/// | `ShardScanStats` | CommitProof, ShardCompletionProof | Shard metrics |
/// | `EnumerationPage` | (runtime usage, not direct B5 dep) | Page processing |
///
/// ## Types Introduced by Boundary â‘¤
///
/// ### Chunk 1: Done-Ledger
/// - `ConnectorInstanceId` â€” 32-byte connector installation identity
/// - `SubresourceKind`, `SubresourceKindRaw` â€” item sub-resource classification
/// - `OvidHash`, `OvidInputs`, `derive_ovid_hash` â€” versioned object identity
/// - `DoneLedgerKey` â€” composite key (tenant, policy, ovid)
/// - `DoneLedgerStatus` â€” monotonic scan outcome lattice
/// - `DoneLedgerEntry` â€” status + provenance
/// - `DoneLedgerLookup` â€” batch_get response
/// - `DoneLedgerGetBatch`, `DoneLedgerGetResult` â€” batch read types
/// - `DoneLedgerUpsertBatch`, `DoneLedgerUpsertItem` â€” batch write types
/// - `DoneLedgerGetError`, `DoneLedgerUpsertError` â€” error types
/// - `DoneLedger` â€” persistence trait
///
/// ### Chunk 2: Findings Sink
/// - `TriageGroupKey`, `derive_triage_group_key` â€” policy-resilient triage correlation
/// - `RuleName` â€” human-readable rule label
/// - `FindingRecord`, `FindingRecordBuilder` â€” finding persistence record
/// - `OccurrenceRecord`, `OccurrenceRecordBuilder` â€” occurrence persistence record
/// - `FindingsUpsertBatch` â€” combined finding+occurrence batch
/// - `FindingsUpsertResult` â€” upsert outcome counts
/// - `FindingsUpsertError` â€” upsert error type
/// - `FindingsSink` â€” persistence trait
///
/// ### Chunk 3: Commit Protocol
/// - `CommitPhase` â€” named protocol phases
/// - `FindingsFlushReceipt` â€” step 1 receipt
/// - `LedgerCommitReceipt` â€” step 2 receipt
/// - `CheckpointReceipt` â€” step 3 receipt
/// - `CommitPlan` â€” page commit plan
/// - `PageCommit<S>` â€” typestate machine (Pending, FindingsFlushed, LedgerCommitted)
/// - `CommitProof` â€” terminal proof value
/// - `ShardCompletionProof`, `ShardTerminalOutcome` â€” shard lifecycle proof
/// - `CommitError`, `CommitErrorKind` â€” unified commit error
///
/// ### Chunk 4: In-Memory Implementations
/// - `InMemoryDoneLedger` â€” test implementation of DoneLedger
/// - `InMemoryFindingsSink` â€” test implementation of FindingsSink
#[cfg(doc)]
pub struct _CrossBoundaryDependencyMap;

// ============================================================================
// Â§5.63 Verification Strategy & Test Roadmap
// ============================================================================

/// # Boundary â‘¤ Verification Strategy
///
/// ## Confidence Tiers
///
/// | Tier | Method | What It Covers |
/// |------|--------|---------------|
/// | 1 (Highest) | TLA+ model checking | Commit ordering protocol, fence semantics |
/// | 2 | Deterministic simulation | Full pipeline with crash injection |
/// | 3 | Property-based testing | Algebraic properties, identity derivation |
/// | 4 | Unit tests | Individual type and function correctness |
///
/// ## Tier 1: TLA+ Specification (Recommended)
///
/// The commit ordering protocol (findings â†’ ledger â†’ checkpoint) should
/// be specified in TLA+ and model-checked for:
///
/// - **Safety**: No execution trace produces a state where the
///   done-ledger says "scanned" but findings are missing.
/// - **Safety**: No execution trace produces a state where the cursor
///   has advanced past items whose done-ledger entries are missing.
/// - **Liveness**: Every started commit eventually completes or the
///   shard is parked (under fair scheduling).
///
/// The spec should model:
/// - N workers competing for M shards.
/// - Crash-recovery at any point in the commit sequence.
/// - Fence epoch transitions (lease expiry, new worker acquires).
/// - Idempotent retry after crash.
///
/// Reference: Newcombe et al., "How Amazon Web Services Uses Formal
/// Methods" (CACM 2015); Lamport, *Specifying Systems* (2002).
///
/// ## Tier 2: Deterministic Simulation
///
/// Using the in-memory implementations (chunk 4) and the commit
/// protocol (chunk 3), build a deterministic simulator that:
///
/// 1. Generates random enumeration pages with random findings.
/// 2. Drives the commit protocol through all phases.
/// 3. Injects crashes at random points (between any two operations).
/// 4. On recovery, re-runs the commit from the beginning.
/// 5. Asserts the final state is consistent:
///    - Every finding in the sink has a corresponding done-ledger entry.
///    - Every done-ledger entry with `Scanned` has corresponding findings
///      (or the item produced no findings).
///    - The cursor position matches the last committed page.
///
/// Reference: FoundationDB simulation (Zhou et al., SIGMOD 2021);
/// TigerBeetle VOPR.
///
/// ## Tier 3: Property-Based Tests
///
/// | Property | Generator | Assertion |
/// |----------|-----------|-----------|
/// | OvidHash determinism | Random OvidInputs | `derive(x) == derive(x)` |
/// | DoneLedgerStatus lattice | Random status sequences | `fold(merge) == expected join` |
/// | FindingRecord builder consistency | Random inputs | `build().assert_identity_consistency()` |
/// | OccurrenceRecord builder consistency | Random inputs | `build().assert_identity_consistency()` |
/// | TriageGroupKey policy independence | Random rule/secret changes | Key unchanged |
/// | Fence rejection | Random (epoch_old, epoch_new) | `old >= new â†’ rejected` |
/// | Idempotent upsert | Same batch twice | `count == 1`, `dedup == 1` |
/// | Batch atomicity | Batch with one bad entry | Store unchanged on rejection |
/// | LedgerCommitReceipt consistency | Random (scanned, failed) | `scanned + failed == committed` |
///
/// Reference: Claessen & Hughes, "QuickCheck" (ICFP 2000); `proptest` crate.
///
/// ## Tier 4: Unit Tests (Implemented)
///
/// All unit tests are in chunks 1â€“4. Summary:
///
/// | Chunk | Tests | Coverage |
/// |-------|-------|----------|
/// | 1 | 20+ | OVID, DoneLedgerKey, DoneLedgerStatus lattice, SubresourceKind |
/// | 2 | 20+ | TriageGroupKey, FindingRecord, OccurrenceRecord, batch ops |
/// | 3 | 10+ | PageCommit typestate, CommitProof, ShardCompletionProof |
/// | 4 | 15+ | InMemoryDoneLedger, InMemoryFindingsSink, crash scenario |
/// | 5 | 5+ | Integration tests (this file) |
#[cfg(doc)]
pub struct _VerificationStrategy;

// ============================================================================
// Â§5.64 Integration Test Helpers
// ============================================================================

/// Builder for constructing a complete test scenario with pre-wired
/// in-memory implementations and a commit plan.
///
/// This is a test-only convenience that reduces boilerplate in
/// integration tests. It assembles the pieces that the runtime
/// would normally assemble.
pub struct PersistenceTestHarness {
    pub ledger: InMemoryDoneLedger,
    pub sink: InMemoryFindingsSink,
    pub tenant: TenantId,
    pub run_id: RunId,
    pub shard_key: ShardKey,
    pub shard_id: ShardId,
    pub fence_epoch: FenceEpoch,
    pub time: LogicalTime,
}

impl PersistenceTestHarness {
    /// Create a harness with default test values.
    pub fn new() -> Self {
        let policy = PolicyHash::from_bytes([0xBB; 32]);
        let run_id = RunId {
            job: JobId(1),
            policy,
        };
        Self {
            ledger: InMemoryDoneLedger::new(),
            sink: InMemoryFindingsSink::new(),
            tenant: TenantId::from_bytes([0xAA; 32]),
            run_id,
            shard_key: ShardKey {
                run: run_id,
                shard: ShardId(0),
            },
            shard_id: ShardId(0),
            fence_epoch: FenceEpoch(1),
            time: LogicalTime(1000),
        }
    }

    /// Advance logical time by `delta`.
    pub fn tick(&mut self, delta: u64) {
        self.time = LogicalTime(self.time.0 + delta);
    }

    /// Simulate a new worker acquiring the shard (bumps fence epoch).
    pub fn simulate_reacquire(&mut self) {
        self.fence_epoch = FenceEpoch(self.fence_epoch.0 + 1);
    }

    /// Execute a full commit protocol cycle for a page with findings.
    ///
    /// Returns the `CommitProof` on success.
    ///
    /// This is the "golden path" that the runtime would follow:
    /// 1. Build CommitPlan.
    /// 2. Begin PageCommit.
    /// 3. Flush findings â†’ record receipt.
    /// 4. Commit done-ledger â†’ record receipt.
    /// 5. Record checkpoint â†’ produce proof.
    pub fn commit_page(
        &mut self,
        findings_batch: FindingsUpsertBatch,
        ledger_batch: DoneLedgerUpsertBatch,
        cursor: Cursor,
        op_id: OpId,
    ) -> Result<CommitProof, CommitError> {
        let plan = CommitPlan::new(
            self.shard_key,
            findings_batch,
            ledger_batch,
            cursor,
            op_id,
            self.fence_epoch,
            self.shard_id,
        );

        let stats = ShardScanStats::new(); // Caller would pass real stats.
        let pending = PageCommit::begin(plan, stats, self.time);

        // Step 1: Flush findings.
        self.tick(1);
        let findings_result = if pending.findings_batch().is_empty() {
            None
        } else {
            let result = self
                .sink
                .upsert_findings_mut(
                    pending.findings_batch(),
                    pending.shard_id(),
                    pending.fence_epoch(),
                    self.time,
                )
                .map_err(|e| CommitError::internal(
                    CommitPhase::FlushFindings,
                    format!("{e:?}"),
                ))?;
            Some(result)
        };
        let flushed = pending.record_findings_flushed(findings_result, self.time);

        // Step 2: Commit done-ledger.
        self.tick(1);
        let ledger_batch = flushed.plan().ledger_batch.clone();
        let (scanned, failed) = if ledger_batch.is_empty() {
            (0u32, 0u32)
        } else {
            // Count scanned vs failed from the batch.
            let mut s = 0u32;
            let mut f = 0u32;
            for item in ledger_batch.items() {
                if item.entry.is_scanned() {
                    s += 1;
                } else {
                    f += 1;
                }
            }
            self.ledger
                .batch_upsert_mut(
                    &ledger_batch,
                    self.shard_id,
                    self.fence_epoch,
                    self.time,
                )
                .map_err(|e| CommitError::internal(
                    CommitPhase::CommitLedger,
                    format!("{e:?}"),
                ))?;
            (s, f)
        };
        let committed = flushed.record_ledger_committed(scanned, failed, self.time);

        // Step 3: Record checkpoint (simulated â€” no real coordination backend).
        self.tick(1);
        let proof = committed.record_checkpointed(false, self.time);

        Ok(proof)
    }
}

impl Default for PersistenceTestHarness {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Â§5.65 Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Shared fixtures --

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0xAA; 32])
    }

    fn test_policy() -> PolicyHash {
        PolicyHash::from_bytes([0xBB; 32])
    }

    fn test_run_id() -> RunId {
        RunId {
            job: JobId(1),
            policy: test_policy(),
        }
    }

    fn test_stable_item_id() -> StableItemId {
        StableItemId::from_bytes([0x22; 32])
    }

    fn test_version() -> ObjectVersionId {
        ObjectVersionId::from_bytes([0x44; 32])
    }

    fn test_rule_name() -> RuleName {
        RuleName::new("aws-access-key-id")
    }

    fn test_location() -> ItemLocation {
        ItemLocation::new("github.com/org/repo/config.yml")
    }

    fn test_connector_tag() -> ConnectorTag {
        ConnectorTag::from_ascii(b"github")
    }

    fn test_connector_instance() -> ConnectorInstanceId {
        ConnectorInstanceId::from_bytes([0x11; 32])
    }

    fn make_finding(rule_byte: u8, secret_byte: u8) -> FindingRecord {
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

    fn make_occurrence(finding_id: FindingId, offset: u64) -> OccurrenceRecord {
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

    fn test_cursor(key: &[u8]) -> Cursor {
        Cursor {
            last_key: Some(key.to_vec().into_boxed_slice()),
        }
    }

    // -- Integration: full commit protocol with harness --

    #[test]
    fn harness_empty_page_commit() {
        let mut h = PersistenceTestHarness::new();

        let proof = h
            .commit_page(
                FindingsUpsertBatch::with_capacity(1, 1),
                DoneLedgerUpsertBatch::with_capacity(1),
                test_cursor(b"page-1-end"),
                OpId(1),
            )
            .unwrap();

        assert!(proof.was_empty_commit());
        assert_eq!(proof.findings_inserted(), 0);
        assert_eq!(proof.ledger_entries_committed(), 0);
    }

    #[test]
    fn harness_page_with_findings_and_ledger() {
        let mut h = PersistenceTestHarness::new();

        // Build findings batch.
        let finding = make_finding(0x33, 0x66);
        let finding_id = finding.finding_id;
        let mut fb = FindingsUpsertBatch::with_capacity(1, 1);
        fb.push_finding(finding);
        fb.push_occurrence(make_occurrence(finding_id, 512));

        // Build ledger batch.
        let key = make_done_ledger_key(0x22);
        let mut lb = DoneLedgerUpsertBatch::with_capacity(1);
        lb.push(DoneLedgerUpsertItem::new(
            key,
            DoneLedgerEntry::scanned(LogicalTime(1000), test_run_id(), ShardId(0)),
        ));

        let proof = h
            .commit_page(fb, lb, test_cursor(b"page-1-end"), OpId(1))
            .unwrap();

        // Verify proof.
        assert!(!proof.was_empty_commit());
        assert_eq!(proof.findings_inserted(), 1);
        assert_eq!(proof.occurrences_inserted(), 1);
        assert_eq!(proof.ledger_entries_committed(), 1);

        // Verify stores.
        assert!(h.sink.contains_finding(&finding_id));
        assert_eq!(h.sink.occurrences_for_finding(finding_id).len(), 1);
        assert!(h.ledger.get_entry(&key).unwrap().is_scanned());
    }

    #[test]
    fn harness_multi_page_commit() {
        let mut h = PersistenceTestHarness::new();

        // Page 1: finding A.
        let fa = make_finding(0x33, 0x66);
        let fa_id = fa.finding_id;
        let mut fb1 = FindingsUpsertBatch::with_capacity(1, 1);
        fb1.push_finding(fa);
        fb1.push_occurrence(make_occurrence(fa_id, 100));

        let key1 = make_done_ledger_key(0x01);
        let mut lb1 = DoneLedgerUpsertBatch::with_capacity(1);
        lb1.push(DoneLedgerUpsertItem::new(
            key1,
            DoneLedgerEntry::scanned(h.time, test_run_id(), ShardId(0)),
        ));

        let proof1 = h
            .commit_page(fb1, lb1, test_cursor(b"page-1"), OpId(1))
            .unwrap();
        assert_eq!(proof1.findings_inserted(), 1);

        // Page 2: finding B + another occurrence of A (different version).
        let fb_ = make_finding(0x44, 0x77);
        let fb_id = fb_.finding_id;
        let mut fb2 = FindingsUpsertBatch::with_capacity(2, 2);
        fb2.push_finding(fb_);
        fb2.push_occurrence(make_occurrence(fb_id, 200));
        // Re-submit finding A occurrence at different offset.
        fb2.push_finding(make_finding(0x33, 0x66)); // Deduplicated.
        fb2.push_occurrence(make_occurrence(fa_id, 300));

        let key2 = make_done_ledger_key(0x02);
        let mut lb2 = DoneLedgerUpsertBatch::with_capacity(1);
        lb2.push(DoneLedgerUpsertItem::new(
            key2,
            DoneLedgerEntry::scanned(h.time, test_run_id(), ShardId(0)),
        ));

        let proof2 = h
            .commit_page(fb2, lb2, test_cursor(b"page-2"), OpId(2))
            .unwrap();

        // Finding A was deduplicated, Finding B was new.
        assert_eq!(proof2.findings_inserted(), 1);
        assert_eq!(
            proof2.findings_receipt.findings_deduplicated, 1,
            "finding A should be deduplicated"
        );

        // Total in stores.
        assert_eq!(h.sink.findings_count(), 2); // A + B
        assert_eq!(h.sink.occurrences_count(), 3); // A@100, B@200, A@300
        assert_eq!(h.ledger.entry_count(), 2);
    }

    // -- Crash recovery integration --

    #[test]
    fn crash_recovery_between_findings_and_ledger() {
        let mut h = PersistenceTestHarness::new();

        let finding = make_finding(0x33, 0x66);
        let finding_id = finding.finding_id;

        // Attempt 1: flush findings succeeds, then "crash" before ledger.
        let mut fb = FindingsUpsertBatch::with_capacity(1, 1);
        fb.push_finding(finding.clone());
        h.sink
            .upsert_findings_mut(&fb, h.shard_id, h.fence_epoch, h.time)
            .unwrap();
        // CRASH â€” ledger not updated.

        // Recovery: new worker acquires shard (new epoch).
        h.simulate_reacquire();
        h.tick(100);

        // Attempt 2: full commit protocol. Finding re-upserted (dedup).
        let mut fb2 = FindingsUpsertBatch::with_capacity(1, 1);
        fb2.push_finding(finding);
        fb2.push_occurrence(make_occurrence(finding_id, 512));

        let key = make_done_ledger_key(0x22);
        let mut lb = DoneLedgerUpsertBatch::with_capacity(1);
        lb.push(DoneLedgerUpsertItem::new(
            key,
            DoneLedgerEntry::scanned(h.time, test_run_id(), ShardId(0)),
        ));

        let proof = h
            .commit_page(fb2, lb, test_cursor(b"item-1"), OpId(10))
            .unwrap();

        // Finding was deduplicated (already existed from attempt 1).
        assert_eq!(proof.findings_receipt.findings_deduplicated, 1);
        assert_eq!(proof.findings_inserted(), 0);
        // But ledger and occurrence are new.
        assert_eq!(proof.occurrences_inserted(), 1);
        assert_eq!(proof.ledger_entries_committed(), 1);

        // Final state is consistent.
        assert_eq!(h.sink.findings_count(), 1);
        assert!(h.ledger.get_entry(&key).unwrap().is_scanned());
    }

    #[test]
    fn crash_recovery_between_ledger_and_checkpoint() {
        let mut h = PersistenceTestHarness::new();

        let finding = make_finding(0x33, 0x66);
        let finding_id = finding.finding_id;

        // Attempt 1: findings + ledger succeed, "crash" before checkpoint.
        let mut fb = FindingsUpsertBatch::with_capacity(1, 1);
        fb.push_finding(finding.clone());
        h.sink
            .upsert_findings_mut(&fb, h.shard_id, h.fence_epoch, h.time)
            .unwrap();

        let key = make_done_ledger_key(0x22);
        let mut lb = DoneLedgerUpsertBatch::with_capacity(1);
        lb.push(DoneLedgerUpsertItem::new(
            key,
            DoneLedgerEntry::scanned(h.time, test_run_id(), ShardId(0)),
        ));
        h.ledger
            .batch_upsert_mut(&lb, h.shard_id, h.fence_epoch, h.time)
            .unwrap();
        // CRASH â€” checkpoint not committed. Cursor not advanced.

        // Recovery: new epoch. Re-enumeration re-discovers the item.
        h.simulate_reacquire();
        h.tick(100);

        // Re-scan: done-ledger says "scanned" â†’ item skipped.
        // The runtime checks done-ledger, sees Scanned, skips the item.
        let mut check_batch = DoneLedgerGetBatch::with_capacity(1);
        check_batch.push(key);
        let lookup = h.ledger.batch_get_mut(&check_batch, h.time).unwrap();
        assert!(lookup.get(0).is_scanned());
        // â†’ Item would be skipped. No duplicate scanning.

        // Cursor advances past the already-scanned item (empty commit).
        let proof = h
            .commit_page(
                FindingsUpsertBatch::with_capacity(1, 1),
                DoneLedgerUpsertBatch::with_capacity(1),
                test_cursor(b"item-1"),
                OpId(20),
            )
            .unwrap();

        assert!(proof.was_empty_commit());
        // State is fully consistent.
        assert!(h.sink.contains_finding(&finding_id));
        assert!(h.ledger.get_entry(&key).unwrap().is_scanned());
    }

    // -- Fence rejection integration --

    #[test]
    fn zombie_worker_rejected_by_fence() {
        let mut h = PersistenceTestHarness::new();

        // Worker 1 writes at epoch 1.
        let finding = make_finding(0x33, 0x66);
        let mut fb = FindingsUpsertBatch::with_capacity(1, 1);
        fb.push_finding(finding);
        h.sink
            .upsert_findings_mut(&fb, h.shard_id, h.fence_epoch, h.time)
            .unwrap();

        // New worker acquires â†’ epoch bumps to 2.
        h.simulate_reacquire();

        // Worker 1 (zombie) tries to write with old epoch 1.
        let zombie_finding = make_finding(0x44, 0x77);
        let mut zombie_fb = FindingsUpsertBatch::with_capacity(1, 1);
        zombie_fb.push_finding(zombie_finding);
        let result = h.sink.upsert_findings_mut(
            &zombie_fb,
            h.shard_id,
            FenceEpoch(1), // Stale!
            h.time,
        );

        assert!(result.is_err());
        // Only the first finding should exist.
        assert_eq!(h.sink.findings_count(), 1);
    }

    // -- ShardCompletionProof integration --

    #[test]
    fn shard_completion_proof_after_all_pages() {
        let mut h = PersistenceTestHarness::new();

        // Simulate 3 pages.
        let mut total_commits = 0u32;
        let mut stats = ShardScanStats::new();

        for page_idx in 0..3u8 {
            let finding = make_finding(0x33 + page_idx, 0x66 + page_idx);
            let fid = finding.finding_id;
            let mut fb = FindingsUpsertBatch::with_capacity(1, 1);
            fb.push_finding(finding);
            fb.push_occurrence(make_occurrence(fid, page_idx as u64 * 100));

            let key = make_done_ledger_key(page_idx + 1);
            let mut lb = DoneLedgerUpsertBatch::with_capacity(1);
            lb.push(DoneLedgerUpsertItem::new(
                key,
                DoneLedgerEntry::scanned(h.time, test_run_id(), ShardId(0)),
            ));

            let cursor_key = format!("page-{}", page_idx);
            let _proof = h
                .commit_page(fb, lb, test_cursor(cursor_key.as_bytes()), OpId(page_idx as u64))
                .unwrap();
            total_commits += 1;

            stats.items_enumerated += 1;
            stats.items_scanned += 1;
            stats.findings_total += 1;
        }

        // All pages committed. Build completion proof.
        let completion = ShardCompletionProof::done(
            h.shard_key,
            stats.clone(),
            total_commits,
            test_cursor(b"page-2"),
            OpId(999),
            h.time,
        );

        assert!(completion.outcome().is_done());
        assert_eq!(completion.total_page_commits, 3);
        assert_eq!(completion.final_stats.items_enumerated, 3);
        assert_eq!(completion.final_stats.findings_total, 3);

        // Final stores.
        assert_eq!(h.sink.findings_count(), 3);
        assert_eq!(h.sink.occurrences_count(), 3);
        assert_eq!(h.ledger.entry_count(), 3);
    }

    // -- End-to-end: triage identity survives policy change --

    #[test]
    fn triage_identity_survives_policy_change_end_to_end() {
        let mut h = PersistenceTestHarness::new();

        // Policy v1: rule_v1, secret found.
        let finding_v1 = make_finding(0x33, 0x66);
        let triage_key_v1 = finding_v1.triage_group_key;

        let mut fb1 = FindingsUpsertBatch::with_capacity(1, 1);
        fb1.push_finding(finding_v1.clone());

        let key1 = make_done_ledger_key(0x22);
        let mut lb1 = DoneLedgerUpsertBatch::with_capacity(1);
        lb1.push(DoneLedgerUpsertItem::new(
            key1,
            DoneLedgerEntry::scanned(h.time, test_run_id(), ShardId(0)),
        ));

        h.commit_page(fb1, lb1, test_cursor(b"v1-end"), OpId(1))
            .unwrap();

        // Policy v2: different rule fingerprint, same secret.
        let finding_v2 = make_finding(0x44, 0x66); // Different rule, same secret.
        let triage_key_v2 = finding_v2.triage_group_key;

        // FindingId changed (rule changed), but TriageGroupKey is the same.
        assert_ne!(finding_v1.finding_id, finding_v2.finding_id);
        assert_eq!(triage_key_v1, triage_key_v2);

        // The triage system can correlate v1 and v2 findings via
        // TriageGroupKey, preserving dismiss/acknowledge state across
        // the policy change.
    }

    // -- Harness utility tests --

    #[test]
    fn harness_tick_advances_time() {
        let mut h = PersistenceTestHarness::new();
        let t0 = h.time;
        h.tick(42);
        assert_eq!(h.time, LogicalTime(t0.0 + 42));
    }

    #[test]
    fn harness_reacquire_bumps_epoch() {
        let mut h = PersistenceTestHarness::new();
        let e0 = h.fence_epoch;
        h.simulate_reacquire();
        assert_eq!(h.fence_epoch, FenceEpoch(e0.0 + 1));
    }

    // -- Property test stubs (integration-level) --

    // TODO: proptest for crash-recovery convergence:
    //   âˆ€ random page contents, âˆ€ random crash points:
    //   after recovery and retry, final state satisfies:
    //   - every finding has a done-ledger entry
    //   - every done-ledger entry with Scanned has findings (if produced)
    //   - no orphaned occurrences
    //
    // TODO: proptest for fence isolation:
    //   âˆ€ (epoch_a, epoch_b) where epoch_b > epoch_a:
    //   zombie writes at epoch_a fail after worker at epoch_b has written.
    //
    // TODO: proptest for multi-page idempotency:
    //   âˆ€ page sequences: replaying any committed page produces
    //   dedup counts only, no new inserts.
}
