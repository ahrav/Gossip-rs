# 14 -- Connector Architecture

This document diagrams the B4 Connector boundary: trait contracts, core value
types, family-runtime integration, and error classification. Connectors bridge
external data sources into the shard-based enumeration and read model defined
in `gossip-contracts`.

**Color coding**: All B4 Connector components use fill `#EF4444` / `#FEE2E2`,
stroke `#991B1B` (red -- external I/O, highest risk). Cross-boundary
components use their respective boundary colors per [00-README.md](./00-README.md).

---

## 1. Connector Method Surface

Each concrete connector exposes read and split-point operations as inherent
methods. `ConnectorCapabilities` advertises which optional operations are
available per connector instance.

```mermaid
%% Diagram: connector-method-surface
graph TD
    subgraph Caps["ConnectorCapabilities"]
        CC["<b>ConnectorCapabilities</b><br/>seek_by_key: bool<br/>token_resume: bool<br/>range_read: bool<br/>split_hints: bool"]
    end

    subgraph Methods["Inherent method surface"]
        EM["<b>Split &amp; capability methods</b><br/>caps() → ConnectorCapabilities<br/>choose_split_point(&mut, &ShardSpec, &Cursor, Budgets)<br/>  → Result&lt;Option&lt;ItemKey&gt;, EnumerateError&gt;"]
        RM["<b>Read methods</b><br/>open(&mut, &ItemRef, Budgets)<br/>  → Result&lt;Box&lt;dyn Read + Send&gt;, ReadError&gt;<br/>read_range(&mut, &ItemRef, u64, &mut [u8], Budgets)<br/>  → Result&lt;usize, ReadError&gt;"]
    end

    EM -->|"caps() returns"| CC

    subgraph Connectors["Concrete implementations"]
        FS["<b>FilesystemConnector</b><br/>seek_by_key: ✓<br/>token_resume: ✗<br/>range_read: ✓<br/>split_hints: ✗ (caps)<br/><i>has choose_split_point<br/>via StreamingSplitEstimator</i>"]
        MEM["<b>InMemoryDeterministicConnector</b><br/>seek_by_key: ✓<br/>token_resume: configurable<br/>range_read: ✓<br/>split_hints: ✓"]
    end

    FS -->|provides| EM
    FS -->|provides| RM
    MEM -->|provides| EM
    MEM -->|provides| RM

    style CC fill:#FEE2E2,stroke:#991B1B
    style EM fill:#FEE2E2,stroke:#991B1B
    style RM fill:#FEE2E2,stroke:#991B1B
    style FS fill:#FEE2E2,stroke:#991B1B
    style MEM fill:#FEE2E2,stroke:#991B1B
```

**Key design decisions:**

- Reading payload bytes and selecting split points are separate method groups.
  Orchestration can apply different retry and circuit-breaker policies to each
  path.
- `choose_split_point` is only meaningful for connectors that advertise
  `split_hints: true`. `FilesystemConnector` reports `split_hints: false`
  via `caps()` but does implement `choose_split_point` backed by a
  `StreamingSplitEstimator` — the capability flag under-reports what the
  connector can do.
- `FilesystemConnector` keeps a simpler capability profile: key-based seek and
  range reads are available, while token resume is not. Split estimation is
  available via `StreamingSplitEstimator` even though `split_hints` reports
  `false` in `caps()`.
- `InMemoryDeterministicConnector` can expose token resume
  conditionally through `with_tokens(bool)`.

See also: [09-circuit-breaker.md](./09-circuit-breaker.md) for failure
isolation per connector, [13-shard-algebra-types.md](./13-shard-algebra-types.md)
for shard key encoding.

---

## 2. Core Type Relationships

Connector boundary types enforce invariants at construction time so downstream
code can operate on strongly typed values without repeating validation.

```mermaid
%% Diagram: connector-core-types
graph TD
    subgraph ToxicWrappers["Toxic-byte wrappers"]
        IK["<b>ItemKey</b><br/>max: 4 KiB<br/>ordered (Ord)<br/>enumeration position"]
        IR["<b>ItemRef</b><br/>max: 16 KiB<br/>unordered<br/>opaque read handle"]
        TB["<b>TokenBytes</b><br/>max: 16 KiB<br/>unordered<br/>pagination resume token"]
    end

    subgraph Paging["Paging state"]
        CUR["<b>Cursor</b><br/>last_key: Option&lt;ItemKey&gt;<br/>token: Option&lt;TokenBytes&gt;<br/><i>invariant: token implies last_key</i>"]
    end

    IK -->|"last_key field"| CUR
    TB -->|"token field"| CUR

    subgraph Enumeration["Connector output"]
        SI["<b>ScanItem</b><br/>item_key: ItemKey<br/>item_ref: ItemRef<br/>stable_item_id: StableItemId<br/>version: VersionId<br/>size_hint: Option&lt;u64&gt;<br/>content_hints: Option&lt;ContentHints&gt;<br/>location: Option&lt;Location&gt;"]
    end

    IK -->|"item_key field"| SI
    IR -->|"item_ref field"| SI

    subgraph Budgets["Scan budgets"]
        BU["<b>Budgets</b><br/>max_items: NonZeroUsize<br/>max_bytes: NonZeroU64<br/>deadline: Option&lt;Instant&gt;<br/><i>try_new(), is_expired_at()</i>"]
    end

    subgraph Errors["Error types"]
        EC2["<b>ErrorClass</b><br/>Retryable | Permanent"]
        EE["<b>EnumerateError</b><br/>class: ErrorClass<br/>message: String<br/>retry_after_ms: Option&lt;u64&gt;"]
        RE["<b>ReadError</b><br/>class: ErrorClass<br/>message: String<br/>retry_after_ms: Option&lt;u64&gt;"]
        CIE["<b>ConnectorInputError</b><br/>Empty { field }<br/>TooLarge { field, size, max }<br/>TokenWithoutLastKey<br/>ZeroBudget { field }"]
    end

    EC2 -->|"class field"| EE
    EC2 -->|"class field"| RE

    style IK fill:#EF4444,stroke:#991B1B,color:#fff
    style IR fill:#EF4444,stroke:#991B1B,color:#fff
    style TB fill:#EF4444,stroke:#991B1B,color:#fff
    style CUR fill:#FEE2E2,stroke:#991B1B
    style SI fill:#FEE2E2,stroke:#991B1B
    style BU fill:#FEE2E2,stroke:#991B1B
    style EC2 fill:#EF4444,stroke:#991B1B,color:#fff
    style EE fill:#FEE2E2,stroke:#991B1B
    style RE fill:#FEE2E2,stroke:#991B1B
    style CIE fill:#FEE2E2,stroke:#991B1B
```

**Design notes:**

- `ItemKey` has `Ord` because it participates in cursor progression and shard
  range membership. `ItemRef` and `TokenBytes` are looked up, not ranged.
- `Cursor` constructors make the `(None, Some(token))` state unrepresentable.
- `EnumerateError` and `ReadError` share the same shape but remain nominally
  distinct so orchestration cannot mix the two operation paths by accident.
- Pooled toxic-byte wrappers retain a shared slab so page-scoped data can
  escape a page boundary without copying raw bytes into ad hoc buffers.

See also: [03-id-derivation-dag.md](./03-id-derivation-dag.md) for
`StableItemId` and `VersionId` derivation, [08-pagecommit-typestate.md](./08-pagecommit-typestate.md)
for how `ScanItem` flows into persistence commits.

---

## 3. Connector-to-Runtime Family Bridge

Runtime orchestration imports shared connector nouns from
`gossip-contracts::connector` and selects a family module inside
`gossip-scanner-runtime`. Ordered-content work flows through
`OrderedContentRuntime`; Git repository work flows through `GitRepoRuntime`;
the distributed module contributes the concrete worker-loop foundation types
and talks directly to `gossip-coordination`.

```mermaid
%% Diagram: connector-runtime-family-bridge
graph LR
    subgraph Coordination["B2: Coordination"]
        CLAIM["<b>Claimed shard context</b><br/>Lease + run scope"]
    end

    subgraph Runtime["gossip-scanner-runtime"]
        OCR["<b>OrderedContentRuntime</b><br/>execute_source(...)<br/>scan_local_filesystem(...)"]
        GRR["<b>GitRepoRuntime</b><br/>execute_discovery(...)<br/>execute_repo(...)<br/>scan_local_repo(...)"]
        DRT["<b>distributed.rs worker loop</b><br/>WorkerIdentity<br/>ShardLease<br/>run_worker(...)<br/>CoordinationFacade"]
    end

    subgraph Contracts["gossip-contracts::connector"]
        OCS["<b>OrderedContentSource</b>"]
        GDS["<b>GitRepoDiscoverySource</b>"]
        GMM["<b>GitMirrorManager</b>"]
        GRE["<b>GitRepoExecutor</b>"]
    end

    subgraph Sources["gossip-connectors"]
        FSC["<b>FilesystemConnector</b>"]
        IMC["<b>InMemoryDeterministicConnector</b>"]
    end

    CLAIM --> OCR
    CLAIM --> GRR
    CLAIM --> DRT

    OCR --> OCS
    GRR --> GDS
    GRR --> GMM
    GRR --> GRE

    FSC --> OCS
    IMC --> OCS

    style CLAIM fill:#DCFCE7,stroke:#166534
    style OCR fill:#FEE2E2,stroke:#991B1B
    style GRR fill:#FEE2E2,stroke:#991B1B
    style DRT fill:#DCFCE7,stroke:#166534
    style OCS fill:#FEE2E2,stroke:#991B1B
    style GDS fill:#FEE2E2,stroke:#991B1B
    style GMM fill:#FEE2E2,stroke:#991B1B
    style GRE fill:#FEE2E2,stroke:#991B1B
    style FSC fill:#FEE2E2,stroke:#991B1B
    style IMC fill:#FEE2E2,stroke:#991B1B
```

**Runtime surface:**

| Runtime entry | Purpose |
| ------------- | ------- |
| `OrderedContentRuntime::execute_source` | Generic ordered-content execution hook |
| `ordered_content::scan_local_filesystem` | Filesystem-facing ordered-content entrypoint |
| `GitRepoRuntime::execute_discovery` | Generic repository-discovery hook |
| `GitRepoRuntime::execute_repo` | Generic mirror + executor hook |
| `git_repo::scan_local_repo` | Local repository entrypoint |
| `distributed.rs` worker loop | Worker identity, concrete lease payload, persistence, config, and error layer for the distributed worker loop |

**Boundary split.** `gossip-connectors` owns concrete source implementations;
`gossip-contracts` owns the family traits and value contracts; `gossip-scanner-runtime`
owns the orchestration modules that sit between callers and those family traits.

See also: [04-end-to-end-scan-flow.md](./04-end-to-end-scan-flow.md) for the
runtime entrypoints and commit-sink flow, [05-shard-and-run-state-machines.md](./05-shard-and-run-state-machines.md)
for shard lifecycle.

---

## 4. Error Classification Flow

I/O errors from the host OS are classified at the connector boundary into a
binary `ErrorClass` posture. Shared helpers in `gossip-connectors::common`
centralize this decision so all three connectors use identical permanence
logic.

```mermaid
%% Diagram: error-classification-flow
graph TD
    subgraph IO["Raw I/O layer"]
        IOE["<b>std::io::Error</b><br/>from filesystem / git / network"]
    end

    subgraph Classify["Classification (gossip-connectors::common)"]
        IPIE["<b>is_permanent_io_error()</b><br/>NotFound<br/>PermissionDenied<br/>InvalidInput<br/>InvalidFilename<br/>NotADirectory<br/>IsADirectory<br/>ReadOnlyFilesystem<br/>ELOOP (Unix raw_os_error<br/>via is_symlink_loop())"]
        CIE2["<b>classify_io_enumerate_error()</b><br/>op, path, &io::Error<br/>→ EnumerateError"]
        CIR["<b>classify_io_read_error()</b><br/>op, Option&lt;path&gt;, &io::Error<br/>→ ReadError"]
    end

    IOE -->|"enumerate path"| CIE2
    IOE -->|"read path"| CIR
    CIE2 -->|"delegates to"| IPIE
    CIR -->|"delegates to"| IPIE

    subgraph Redaction["Log-safe redaction"]
        TD2["<b>ToxicDigest</b><br/>BLAKE3 hash of path bytes<br/>no raw paths in error messages"]
    end

    CIE2 -->|"path_digest()"| TD2
    CIR -->|"path_digest()"| TD2

    subgraph Outcomes["Classified outcomes"]
        RET["<b>ErrorClass::Retryable</b><br/>transient / capacity failures<br/>→ retry with backoff"]
        PERM["<b>ErrorClass::Permanent</b><br/>structural failures<br/>→ park shard or skip item"]
    end

    IPIE -->|"false: transient"| RET
    IPIE -->|"true: structural"| PERM

    subgraph Actions["Orchestration response"]
        RETRY["Retry decision<br/>(backoff, circuit breaker)"]
        PARK["Park shard / skip item<br/>(coordination state transition)"]
    end

    RET --> RETRY
    PERM --> PARK

    style IOE fill:#F3F4F6,stroke:#374151
    style IPIE fill:#EF4444,stroke:#991B1B,color:#fff
    style CIE2 fill:#FEE2E2,stroke:#991B1B
    style CIR fill:#FEE2E2,stroke:#991B1B
    style TD2 fill:#FEE2E2,stroke:#991B1B
    style RET fill:#FEE2E2,stroke:#991B1B
    style PERM fill:#EF4444,stroke:#991B1B,color:#fff
    style RETRY fill:#DCFCE7,stroke:#166534
    style PARK fill:#DCFCE7,stroke:#166534
```

**Classification rules:**

| `io::ErrorKind` | Classification | Rationale |
| --------------- | -------------- | --------- |
| `NotFound` | Permanent | Resource does not exist |
| `PermissionDenied` | Permanent | Access control failure |
| `InvalidInput` | Permanent | Malformed argument |
| `InvalidFilename` | Permanent | OS-rejected filename |
| `NotADirectory` | Permanent | Type mismatch |
| `IsADirectory` | Permanent | Type mismatch |
| `ReadOnlyFilesystem` | Permanent | Read-only mount / filesystem state |
| `ELOOP` (Unix) | Permanent | Symlink cycle (detected via `raw_os_error`, not `ErrorKind`) |
| Everything else | Retryable | Interrupted, would-block, timeout, or capacity failure |

See also: [09-circuit-breaker.md](./09-circuit-breaker.md) for how classified
errors feed circuit-breaker state transitions, [10-failure-modes-and-recovery.md](./10-failure-modes-and-recovery.md)
for system-wide recovery patterns.

---

## Source Code References

| Crate | File | Key types / functions |
| ----- | ---- | --------------------- |
| `gossip-contracts` | `crates/gossip-contracts/src/connector/api.rs` | `ErrorClass`, `EnumerateError`, `ReadError`, `ConnectorCapabilities` |
| `gossip-contracts` | `crates/gossip-contracts/src/connector/types.rs` | `ItemKey`, `ItemRef`, `TokenBytes`, `Cursor`, `ScanItem`, `Budgets`, `ConnectorInputError`, `ContentHints`, `Location`, `VersionId`, `PooledByteSlab`, `ToxicDigest` |
| `gossip-contracts` | `crates/gossip-contracts/src/connector/ordered.rs` | `OrderedContentSource`, `OrderedContentCapabilities` |
| `gossip-contracts` | `crates/gossip-contracts/src/connector/git.rs` | `GitRepoDiscoverySource`, `GitMirrorManager`, `GitRepoExecutor`, `GitRepoTarget`, `LocalMirror`, `GitRunOutcome`, `GitRunError` |
| `gossip-contracts` | `crates/gossip-contracts/src/connector/mod.rs` | `FILESYSTEM_CONNECTOR_TAG`, `GIT_CONNECTOR_TAG`, `IN_MEMORY_CONNECTOR_TAG`, re-export hub |
| `gossip-connectors` | `crates/gossip-connectors/src/common.rs` | `is_permanent_io_error`, `classify_io_enumerate_error`, `classify_io_read_error`, `path_digest`, `path_buf_from_bytes`, `borrowed_shard_bound`, `resolve_bounds`, `key_resume_start`, `estimate_split_from_sorted`, `is_valid_split_candidate` |
| `gossip-connectors` | `crates/gossip-connectors/src/filesystem.rs` | `FilesystemConnector` |
| `gossip-connectors` | `crates/gossip-connectors/src/in_memory.rs` | `InMemoryDeterministicConnector`, `MemItem` |
| `gossip-scanner-runtime` | `crates/gossip-scanner-runtime/src/ordered_content.rs` | `OrderedContentRuntime`, `scan_local_filesystem` (pub(crate)) |
| `gossip-scanner-runtime` | `crates/gossip-scanner-runtime/src/git_repo.rs` | `GitRepoRuntime`, `scan_local_repo` (pub(crate)) |
| `gossip-scanner-runtime` | `crates/gossip-scanner-runtime/src/distributed.rs` | `WorkerIdentity`, concrete `ShardLease`, `DistributedPersistence<F, D>`, `DistributedRuntimeConfig`, `DistributedRunReport`, `DistributedRuntimeError`, `run_worker` |
