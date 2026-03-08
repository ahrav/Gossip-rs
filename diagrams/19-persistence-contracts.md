# Persistence Contracts: Traits, Data Model, and Durability Semantics

The `gossip-contracts` persistence module defines the storage-agnostic contracts
that all persistence backends compile against. It specifies **what** is persisted
(record shapes), **how** durability is proven (commit handles and receipts), and
**what invariants** must hold (monotonic lattice merge, referential integrity,
content-addressed identity). The module is intentionally silent on transaction
boundaries, retry strategies, and batching semantics — those belong to the
backend implementation.

This diagram covers four related systems that together form the B5 Persistence
boundary's contract surface:

1. **Persistence trait hierarchy** — `CommitHandle`, `CommitReceipt`, `DoneLedger`,
   `FindingsSink`, and the conformance harness.
2. **Three-layer findings data model** — `FindingRecord`, `OccurrenceRecord`,
   `ObservationRecord`, and their content-addressed identity chains.
3. **Done-ledger status lattice** — the monotonic join-semilattice that makes
   deduplication safe under crash-recovery and at-least-once delivery.
4. **Object-Version Identity (OVID)** — domain-separated BLAKE3 hashing that
   derives the done-ledger join key from stable item identity and version claim.

The [PageCommit typestate machine](08-pagecommit-typestate.md) enforces the
cross-trait ordering contract (findings before done-ledger before checkpoint)
and is documented in its own diagram.

> **Notation.** Solid lines represent data flow and composition. Dashed lines
> represent trait bounds or type constraints. All diagrams use the B5 Persistence
> color palette (purple theme: fill `#8B5CF6`, light fill `#EDE9FE`, stroke
> `#5B21B6`). Identity types from B1 use blue (`#3B82F6` / `#DBEAFE` / `#1E40AF`).

---

## 1. Persistence Trait Hierarchy

The persistence surface is split into two durable sinks (findings and
done-ledger) unified by a shared two-phase durability protocol. Submission and
durability are intentionally separate: `Ok(handle)` means the backend accepted
the write; `handle.wait()` blocks until the write is durable and returns a typed
receipt. This separation lets backends coalesce writes (group-commit fsync) or
pipeline I/O without weakening the caller-visible contract.

The `CommitHandle` trait consumes `self` on `wait()`, preventing double-waits.
`ReadyCommitHandle` provides a zero-cost adapter for synchronous backends and
test doubles that already hold a pre-computed result.

```mermaid
%% Diagram: persistence-trait-hierarchy
graph TB
    subgraph traits ["B5: Persistence Contracts"]
        direction TB

        CR["CommitReceipt (marker trait)<br/>Clone + Debug + Send + Sync + 'static"]
        CH["CommitHandle<br/>type Receipt: CommitReceipt<br/>type Error: Error<br/>fn wait(self) → Result&lt;Receipt, Error&gt;"]
        RCH["ReadyCommitHandle&lt;R, E&gt;<br/>Pre-resolved adapter for sync backends"]

        DL["DoneLedger<br/>type Error<br/>type CommitHandle<br/>fn batch_get(tenant, policy, &amp;[OvidHash]) → Vec&lt;Option&lt;Record&gt;&gt;<br/>fn batch_upsert(&amp;[DoneLedgerRecord]) → CommitHandle"]
        FS["FindingsSink<br/>type Error<br/>type CommitHandle<br/>fn upsert_batch(FindingsUpsertBatch) → CommitHandle"]
        FCP["FindingsConformanceProbe (test-only)<br/>fn durable_counts() → DurableFindingsCounts"]

        CONF["run_conformance()<br/>Done-ledger checks (4)<br/>Findings checks (4)<br/>Redaction checks (3)"]

        CH -->|"Receipt: CommitReceipt"| CR
        RCH -.->|"implements"| CH
        DL -->|"CommitHandle::Receipt =<br/>DoneLedgerCommitReceipt"| CH
        FS -->|"CommitHandle::Receipt =<br/>FindingsCommitReceipt"| CH
        FCP -.->|"test surface for"| FS
        CONF -.->|"exercises"| DL
        CONF -.->|"exercises"| FS
        CONF -.->|"exercises"| FCP
    end

    subgraph receipts ["Receipt Composition Chain"]
        direction LR

        FCR["FindingsCommitReceipt<br/>finding/occurrence/<br/>observation counts"]
        DLCR["DoneLedgerCommitReceipt<br/>record_count,<br/>scanned_count,<br/>findings_count"]
        CCR["CheckpointCommitReceipt<br/>PageCommitScope +<br/>checkpointed_at"]
        ICR["ItemCommitReceipt<br/>= Findings + DoneLedger"]
        PCR["PageCommitReceipt<br/>= Item + Checkpoint"]

        FCR --> ICR
        DLCR --> ICR
        ICR --> PCR
        CCR --> PCR
    end

    FS -->|"produces"| FCR
    DL -->|"produces"| DLCR

    style CR fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style CH fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style RCH fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style DL fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style FS fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style FCP fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style CONF fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6

    style FCR fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style DLCR fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style CCR fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style ICR fill:#A78BFA,stroke:#5B21B6,color:#FFF
    style PCR fill:#8B5CF6,stroke:#5B21B6,color:#FFF
```

The trait hierarchy summarized:

| Trait / Type | Role | Associated Types |
|:---|:---|:---|
| `CommitReceipt` | Marker: proof of durability | (supertraits: `Clone + Debug + Send + Sync`) |
| `CommitHandle` | Two-phase durability handle | `Receipt: CommitReceipt`, `Error` |
| `ReadyCommitHandle<R, E>` | Sync adapter wrapping `Result<R, E>` | (implements `CommitHandle`) |
| `DoneLedger` | Deduplication store | `Error`, `CommitHandle` (receipt = `DoneLedgerCommitReceipt`) |
| `FindingsSink` | Findings persistence | `Error`, `CommitHandle` (receipt = `FindingsCommitReceipt`) |
| `FindingsConformanceProbe` | Test-only read surface | `Error` |

### Conformance harness

`run_conformance()` executes 11 checks across three suites:

| Suite | Checks | Validates |
|:---|:---|:---|
| Done-ledger (4) | Idempotent upsert, fail-then-scan dominance, scan-then-fail dominance, batch-get positional alignment | Lattice merge correctness |
| Findings (4) | Idempotent upsert, orphan occurrence rejection, orphan observation rejection, observation upsert merge | Referential integrity and idempotency |
| Redaction (3) | `NormHash`, `SecretHash`, and `FindingRecord` `Debug` output must not leak raw secret bytes | No secret leakage through debug formatting |

---

## 2. Three-Layer Findings Data Model

Scan results are persisted in three normalized layers with decreasing stability
and increasing scope:

- **Layer 1 (Finding)** — stable identity, version-independent,
  policy-independent. One per unique `(tenant, item, rule, secret)` triple.
- **Layer 2 (Occurrence)** — version-specific byte range. Pins a finding to
  a specific object version at an exact byte offset and length.
- **Layer 3 (Observation)** — policy- and run-scoped. Records that an
  occurrence was seen during a specific scan run, under a specific policy,
  in a specific shard and fence epoch. Display metadata (`Location`) lives
  here because it is presentation context, not stable identity.

All IDs are content-addressed via domain-separated BLAKE3: identical natural
key inputs always produce the same ID without coordination.

```mermaid
%% Diagram: three-layer-findings-model
graph TB
    subgraph layer1 ["Layer 1: Stable Finding Identity"]
        FR["FindingRecord<br/>tenant_id: TenantId<br/>finding_id: FindingId<br/>stable_item_id: StableItemId<br/>rule_fingerprint: RuleFingerprint<br/>secret_hash: SecretHash"]
        FID["FindingId = BLAKE3(<br/>  tenant_id,<br/>  stable_item_id,<br/>  rule_fingerprint,<br/>  secret_hash<br/>)"]
    end

    subgraph layer2 ["Layer 2: Version-Specific Occurrence"]
        OR["OccurrenceRecord<br/>finding_id: FindingId<br/>occurrence_id: OccurrenceId<br/>object_version_id: ObjectVersionId<br/>byte_offset: u64<br/>byte_length: NonZeroU64"]
        OID["OccurrenceId = BLAKE3(<br/>  finding_id,<br/>  object_version_id,<br/>  byte_offset,<br/>  byte_length<br/>)"]
    end

    subgraph layer3 ["Layer 3: Policy-Scoped Observation"]
        OBS["ObservationRecord<br/>tenant_id: TenantId<br/>policy_hash: PolicyHash<br/>observation_id: ObservationId<br/>occurrence_id: OccurrenceId<br/>run_id: RunId<br/>shard_id: ShardId<br/>fence_epoch: FenceEpoch<br/>observed_at: LogicalTime<br/>location: Option&lt;Location&gt;"]
        OBSID["ObservationId = BLAKE3(<br/>  tenant_id,<br/>  policy_hash,<br/>  occurrence_id<br/>)"]
    end

    subgraph batch ["FindingsUpsertBatch&lt;'a&gt; (zero-copy view)"]
        BATCH["&amp;[FindingRecord]<br/>&amp;[OccurrenceRecord]<br/>&amp;[ObservationRecord]"]
        VAL_OBS["validate_observation_identity()<br/>Checks ObservationId matches<br/>canonical derivation"]
        VAL_REF["validate_referential_integrity()<br/>Checks occurrence→finding and<br/>observation→occurrence references"]
    end

    FR --> FID
    OR --> OID
    OBS --> OBSID

    OR -->|"references"| FR
    OBS -->|"references"| OR

    BATCH --> VAL_OBS
    BATCH --> VAL_REF

    style FR fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style OR fill:#A78BFA,stroke:#5B21B6,color:#FFF
    style OBS fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6

    style FID fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style OID fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style OBSID fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF

    style BATCH fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style VAL_OBS fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style VAL_REF fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
```

| Layer | Record Type | Natural Key | ID Derivation | Stability |
|:---|:---|:---|:---|:---|
| 1 | `FindingRecord` | `(tenant, stable_item_id, rule_fingerprint, secret_hash)` | `FindingId` via BLAKE3 | Version- and policy-independent |
| 2 | `OccurrenceRecord` | `(finding_id, object_version_id, byte_offset, byte_length)` | `OccurrenceId` via BLAKE3 | Version-specific, policy-independent |
| 3 | `ObservationRecord` | `(tenant_id, policy_hash, occurrence_id)` | `ObservationId` via BLAKE3 | Policy- and run-scoped |

### Referential integrity

Each layer references the one above it:
- Every `OccurrenceRecord` carries a `FindingId` that must correspond to a
  `FindingRecord` in the same batch or already persisted.
- Every `ObservationRecord` carries an `OccurrenceId` that must correspond to
  an `OccurrenceRecord` in the same batch or already persisted.

`FindingsUpsertBatch::validate_referential_integrity()` checks these references
plus tenant consistency within the batch. Backends must either enforce
referential closure within a single upsert batch or via foreign key constraints.

### Observation-identity enforcement

`ObservationRecord::from_persisted()` rejects records whose `observation_id`
does not match the canonical derivation from `(tenant_id, policy_hash,
occurrence_id)`. This prevents callers from constructing records with arbitrary
IDs and is validated both at construction time and via
`FindingsUpsertBatch::validate_observation_identity()`.

---

## 3. Done-Ledger Status Lattice

The done-ledger tracks whether each object-version has been processed. Its
status field is a **monotonic join-semilattice**: once a status reaches a higher
rank, no concurrent or replayed write can downgrade it. This property is the
foundation of crash-safe deduplication under at-least-once delivery.

The lattice merge rule is `merge(a, b) = max(a.rank(), b.rank())`. The three
required semilattice properties (idempotence, commutativity, associativity) hold
by construction because `rank()` returns a `u8` discriminant and `max` over
integers satisfies all three.

```mermaid
%% Diagram: done-ledger-status-lattice
stateDiagram-v2
    direction TB

    [*] --> FailedRetryable : First write (failure)
    [*] --> Skipped : First write (skipped)
    [*] --> ScannedClean : First write (success, no findings)
    [*] --> ScannedWithFindings : First write (success, with findings)

    FailedRetryable --> FailedPermanent : merge(rank 1 → rank 2)
    FailedRetryable --> Skipped : merge(rank 1 → rank 3)
    FailedRetryable --> ScannedClean : merge(rank 1 → rank 10)
    FailedRetryable --> ScannedWithFindings : merge(rank 1 → rank 11)

    FailedPermanent --> Skipped : merge(rank 2 → rank 3)
    FailedPermanent --> ScannedClean : merge(rank 2 → rank 10)
    FailedPermanent --> ScannedWithFindings : merge(rank 2 → rank 11)

    Skipped --> ScannedClean : merge(rank 3 → rank 10)
    Skipped --> ScannedWithFindings : merge(rank 3 → rank 11)

    ScannedClean --> ScannedWithFindings : merge(rank 10 → rank 11)

    note right of FailedRetryable
        Rank 1 — temporary failure,
        item may be retried
    end note

    note right of Skipped
        Rank 3 — intentionally skipped
        (format, policy filter, size cap)
    end note

    note right of ScannedClean
        Rank 10 — success, no secrets found.
        Gap (3→10) reserves space for future
        non-terminal states.
    end note

    note right of ScannedWithFindings
        Rank 11 — success, secrets persisted.
        Highest rank — irrevocable.
    end note

    classDef failState fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    classDef skipState fill:#FEF9C3,stroke:#854D0E,color:#854D0E
    classDef scanState fill:#DCFCE7,stroke:#166534,color:#166534

    class FailedRetryable failState
    class FailedPermanent failState
    class Skipped skipState
    class ScannedClean scanState
    class ScannedWithFindings scanState
```

| Variant | Rank | Category | Merge behavior |
|:---|:---|:---|:---|
| `FailedRetryable` | 1 | Non-terminal failure | Any higher-rank write dominates |
| `FailedPermanent` | 2 | Terminal failure | Dominates retryable; dominated by skip/scan |
| `Skipped` | 3 | Intentional skip | Dominates all failures; dominated by scan |
| `ScannedClean` | 10 | Terminal success | Dominates all non-scan states |
| `ScannedWithFindings` | 11 | Terminal success | Highest rank — irrevocable |

The intentional gap between ranks 3 and 10 reserves discriminant space for
future non-terminal states without changing the relative ordering of existing
variants.

### Done-ledger record structure

```mermaid
%% Diagram: done-ledger-record-structure
graph LR
    subgraph key ["DoneLedgerKey (composite)"]
        TID["TenantId<br/>(32 bytes)"]
        PH["PolicyHash<br/>(32 bytes)"]
        OH["OvidHash<br/>(32 bytes)"]
    end

    subgraph record ["DoneLedgerRecord"]
        KEY["key: DoneLedgerKey"]
        STATUS["status: DoneLedgerStatus"]
        BYTES["bytes_scanned: u64"]
        FC["findings_count: u64"]
        PROV["provenance: DoneLedgerProvenance"]
        EC["error_code: Option&lt;DoneLedgerErrorCode&gt;"]
    end

    subgraph provenance ["DoneLedgerProvenance"]
        RID["run_id: RunId"]
        SID["shard_id: ShardId"]
        FE["fence_epoch: FenceEpoch"]
        SA["started_at: LogicalTime"]
        FA["finished_at: LogicalTime"]
    end

    TID --> KEY
    PH --> KEY
    OH --> KEY
    KEY --> record
    PROV --> record

    RID --> provenance
    SID --> provenance
    FE --> provenance
    SA --> provenance
    FA --> provenance

    style TID fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style PH fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style OH fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF

    style KEY fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style STATUS fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style BYTES fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style FC fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style PROV fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style EC fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6

    style RID fill:#DCFCE7,stroke:#166534,color:#166534
    style SID fill:#DCFCE7,stroke:#166534,color:#166534
    style FE fill:#DCFCE7,stroke:#166534,color:#166534
    style SA fill:#F3F4F6,stroke:#374151,color:#374151
    style FA fill:#F3F4F6,stroke:#374151,color:#374151
```

Cross-field validation enforced by `DoneLedgerRecord::validate()`:
- `ScannedWithFindings` requires `findings_count > 0`; `ScannedClean` requires
  `findings_count == 0`.
- Failure/skip statuses require a non-`None` `error_code`; scan statuses reject
  an `error_code`.
- `DoneLedgerErrorCode` is bounded to 128 bytes of safe ASCII characters.

---

## 4. Object-Version Identity (OVID) Hashing

The done-ledger join key is `(TenantId, PolicyHash, OvidHash)`. The `OvidHash`
component collapses `(StableItemId, VersionId)` into a single 32-byte BLAKE3
hash. This decouples the done-ledger key width from the connector's version
representation and makes strong vs. weak version claims produce distinct hashes.

```mermaid
%% Diagram: ovid-derivation
graph LR
    SID["StableItemId<br/>(32 bytes, connector-scoped)"]
    VER["VersionId<br/>Strong(ObjectVersionId) |<br/>Weak(ObjectVersionId)"]

    INPUTS["OvidHashInputs<br/>{ stable_item_id, version }"]

    HASHER["BLAKE3 derive-key<br/>domain = OVID_V1"]

    OVID["OvidHash<br/>(32 bytes)"]

    DLK["DoneLedgerKey<br/>(TenantId, PolicyHash, OvidHash)"]

    SID --> INPUTS
    VER --> INPUTS
    INPUTS --> HASHER
    HASHER --> OVID
    OVID --> DLK

    style SID fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style VER fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style INPUTS fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style HASHER fill:#F3F4F6,stroke:#374151,color:#374151
    style OVID fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style DLK fill:#8B5CF6,stroke:#5B21B6,color:#FFF
```

Key properties:
- **Deterministic**: same `(StableItemId, VersionId)` always produces the same
  `OvidHash`.
- **Strong/weak separation**: `VersionId::Strong(x)` and `VersionId::Weak(x)`
  produce different hashes even for the same `ObjectVersionId`, because a
  1-byte domain tag (0 for strong, 1 for weak) is written before the version
  bytes.
- **Cached hasher**: the BLAKE3 derive-key context (`OVID_V1`) is initialized
  once via `LazyLock` and reused across all derivations.

---

## 5. Full Persistence Contract Surface

How the persistence contracts connect to the broader system. Identity types
from B1, connector types from B4, and coordination types from B2 flow into
the persistence surface. The `PageCommit<S>` typestate machine (documented
in [08-pagecommit-typestate.md](08-pagecommit-typestate.md)) orchestrates the
cross-trait ordering.

```mermaid
%% Diagram: persistence-contract-surface
graph TB
    subgraph B1 ["B1: Identity"]
        IDS["TenantId, PolicyHash,<br/>FindingId, OccurrenceId,<br/>ObservationId, SecretHash,<br/>RuleFingerprint, StableItemId,<br/>RunId, ShardId, FenceEpoch"]
    end

    subgraph B4 ["B4: Connector"]
        CONN["Cursor, Location,<br/>VersionId, ItemKey"]
    end

    subgraph B2 ["B2: Coordination"]
        COORD["checkpoint() →<br/>CheckpointCommitReceipt"]
    end

    subgraph B5 ["B5: Persistence Contracts"]
        OVID_MOD["OVID hashing<br/>derive_ovid_hash()"]
        DL_MOD["DoneLedger trait<br/>batch_get / batch_upsert"]
        FS_MOD["FindingsSink trait<br/>upsert_batch"]
        PC_MOD["PageCommit&lt;S&gt; typestate<br/>findings → done-ledger → checkpoint"]
        RECEIPTS["Receipt chain<br/>Findings → Item → Page"]
        CONFORM["Conformance harness<br/>run_conformance()"]
    end

    subgraph backends ["Backends"]
        INMEM["InMemoryDoneLedger<br/>InMemoryFindingsSink<br/>(reference implementation)"]
        FUTURE["Production backends<br/>(etcd, ScyllaDB, PostgreSQL)"]
    end

    IDS --> B5
    CONN --> B5
    COORD -->|"CheckpointCommitReceipt"| PC_MOD
    OVID_MOD --> DL_MOD
    DL_MOD --> PC_MOD
    FS_MOD --> PC_MOD
    PC_MOD --> RECEIPTS
    CONFORM -.->|"exercises"| DL_MOD
    CONFORM -.->|"exercises"| FS_MOD

    INMEM -.->|"implements"| DL_MOD
    INMEM -.->|"implements"| FS_MOD
    FUTURE -.->|"implements"| DL_MOD
    FUTURE -.->|"implements"| FS_MOD

    style IDS fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style CONN fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style COORD fill:#DCFCE7,stroke:#166534,color:#166534

    style OVID_MOD fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style DL_MOD fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style FS_MOD fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style PC_MOD fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style RECEIPTS fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style CONFORM fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6

    style INMEM fill:#F3F4F6,stroke:#374151,color:#374151
    style FUTURE fill:#F3F4F6,stroke:#374151,color:#6B7280
```

### Key design invariants

1. **No raw secret bytes** in any public record shape. Secret-derived fields
   use fixed-width hash newtypes with redacted `Debug` output.
2. **Submission is not durability.** `Ok(handle)` means the backend accepted
   the write; `handle.wait()` establishes durability and returns a typed receipt.
3. **Cross-trait ordering.** Findings must be durable before done-ledger, and
   done-ledger must be durable before the cursor checkpoint. Enforced at compile
   time by the `PageCommit<S>` typestate.
4. **Monotonic status lattice.** Once an object-version reaches a scanned state,
   no concurrent or replayed failure/skip write can downgrade it.
5. **Content-addressed identity.** All IDs are derived from natural keys via
   domain-separated BLAKE3, ensuring deterministic deduplication without
   coordination.
6. **Backend neutrality.** Traits define contracts without committing to any
   specific storage technology's transaction or batching semantics.

---

## Cross-References

- [PageCommit Typestate Machine](08-pagecommit-typestate.md) — enforces the
  findings → done-ledger → checkpoint ordering at compile time
- [End-to-End Scan Flow](04-end-to-end-scan-flow.md) — shows where identity
  derivation and commit lifecycle occur in the scan pipeline
- [ID Derivation DAG](03-id-derivation-dag.md) — the full 19-type identity
  hierarchy that persistence record types depend on
- [Boundary Dependency Graph](02-boundary-dependency-graph.md) — how B5
  Persistence depends on B1 Identity and B2 Coordination

## Source Code References

| File | Purpose |
|:---|:---|
| `crates/gossip-contracts/src/persistence/mod.rs` | Module root, public re-exports, cross-trait ordering contract |
| `crates/gossip-contracts/src/persistence/commit.rs` | `CommitHandle`, `CommitReceipt`, all receipt types |
| `crates/gossip-contracts/src/persistence/findings.rs` | `FindingRecord`, `OccurrenceRecord`, `ObservationRecord`, `FindingsSink`, `FindingsUpsertBatch` |
| `crates/gossip-contracts/src/persistence/done_ledger.rs` | `DoneLedgerKey`, `DoneLedgerStatus`, `DoneLedgerRecord`, `DoneLedger` trait |
| `crates/gossip-contracts/src/persistence/ovid.rs` | `OvidHash`, `OvidHashInputs`, `derive_ovid_hash()` |
| `crates/gossip-contracts/src/persistence/page_commit.rs` | `PageCommit<S>` typestate, `PageCommitScope`, validation errors |
| `crates/gossip-contracts/src/persistence/error.rs` | `PersistenceInputError` shared validation errors |
| `crates/gossip-contracts/src/persistence/conformance.rs` | `run_conformance()`, `FindingsConformanceProbe`, conformance report |
| `crates/gossip-persistence-inmemory/src/` | Reference implementation: `InMemoryDoneLedger`, `InMemoryFindingsSink` |
