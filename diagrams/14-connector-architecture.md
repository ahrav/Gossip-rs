# 14 — Connector Architecture

This document diagrams the B4 Connector boundary: trait contracts, core value types, scan-driver integration, and error classification. Connectors bridge external data sources into the unified shard-based enumeration and read model defined in `gossip-contracts`.

**Color coding**: All B4 Connector components use fill `#EF4444` / `#FEE2E2`, stroke `#991B1B` (red — external I/O, highest risk). Cross-boundary components use their respective boundary colors per [00-README.md](./00-README.md).

---

## 1. Connector Method Surface

Each concrete connector exposes read and split-point operations as inherent methods (not trait dispatch). All three connectors share the same method signatures and advertise capabilities via `ConnectorCapabilities`, a four-flag struct that orchestration reads at registration time. All three connectors support `seek_by_key`, `range_read`, and `split_hints`; `token_resume` is configurable per instance.

```mermaid
%% Diagram: connector-method-surface
graph TD
    subgraph Caps["ConnectorCapabilities"]
        CC["<b>ConnectorCapabilities</b><br/>seek_by_key: bool<br/>token_resume: bool<br/>range_read: bool<br/>split_hints: bool"]
    end

    subgraph Methods["Inherent Method Surface"]
        EM["<b>Split &amp; Capability Methods</b><br/>caps() → ConnectorCapabilities<br/>choose_split_point(&mut, &ShardSpec, &Cursor, Budgets)<br/>  → Result&lt;Option&lt;ItemKey&gt;, EnumerateError&gt;"]
        RM["<b>Read Methods</b><br/>open(&mut, &ItemRef, Budgets)<br/>  → Result&lt;Box&lt;dyn Read + Send&gt;, ReadError&gt;<br/>read_range(&mut, &ItemRef, u64, &mut [u8], Budgets)<br/>  → Result&lt;usize, ReadError&gt;"]
    end

    EM -->|"caps() returns"| CC

    subgraph Connectors["Concrete Implementations"]
        FS["<b>FilesystemConnector</b><br/>seek_by_key: ✓<br/>token_resume: configurable<br/>range_read: ✓<br/>split_hints: ✓"]
        GIT["<b>GitConnector</b><br/>seek_by_key: ✓<br/>token_resume: configurable<br/>range_read: ✓<br/>split_hints: ✓"]
        MEM["<b>InMemoryDeterministicConnector</b><br/>seek_by_key: ✓<br/>token_resume: configurable<br/>range_read: ✓<br/>split_hints: ✓"]
    end

    FS -->|provides| EM
    FS -->|provides| RM
    GIT -->|provides| EM
    GIT -->|provides| RM
    MEM -->|provides| EM
    MEM -->|provides| RM

    style CC fill:#FEE2E2,stroke:#991B1B
    style EM fill:#FEE2E2,stroke:#991B1B
    style RM fill:#FEE2E2,stroke:#991B1B
    style FS fill:#FEE2E2,stroke:#991B1B
    style GIT fill:#FEE2E2,stroke:#991B1B
    style MEM fill:#FEE2E2,stroke:#991B1B
```

**Key design decisions:**

- Reading (payload I/O) and split-point selection are separate method groups from capability advertisement. Orchestration applies independent retry and circuit-breaker policies per operation.
- `choose_split_point` is provided by connectors that advertise `split_hints: true`. Only connectors with natural partition boundaries (tree objects, directory structure) implement it.
- Connectors without native random-access support must explicitly return `Err(ReadError::unsupported("range_read"))` from `read_range`. All three current connectors implement full range-read support.
- `token_resume` is instance-configurable via `with_tokens(bool)` on each connector rather than hardcoded, because some test scenarios disable tokens to exercise key-only resume.

See also: [09-circuit-breaker.md](./09-circuit-breaker.md) for failure isolation per connector, [13-shard-algebra-types.md](./13-shard-algebra-types.md) for shard key encoding.

---

## 2. Core Type Relationships

Connector boundary types enforce invariants at construction time so downstream code can operate on strongly-typed values without repeating validation. The toxic-byte wrappers (`ItemKey`, `ItemRef`, `TokenBytes`) never expose raw bytes in `Debug`/`Display` output — both produce an identical redacted format (`TypeName(len=N, hash=XXXXXXXX..)`) using a truncated BLAKE3 prefix.

```mermaid
%% Diagram: connector-core-types
graph TD
    subgraph ToxicWrappers["Toxic-Byte Wrappers"]
        IK["<b>ItemKey</b><br/>max: 4 KiB<br/>ordered (Ord)<br/>enumeration position"]
        IR["<b>ItemRef</b><br/>max: 16 KiB<br/>unordered<br/>opaque read handle"]
        TB["<b>TokenBytes</b><br/>max: 16 KiB<br/>unordered<br/>pagination resume token"]
    end

    subgraph Paging["Paging State"]
        CUR["<b>Cursor</b><br/>last_key: Option&lt;ItemKey&gt;<br/>token: Option&lt;TokenBytes&gt;<br/><i>invariant: token implies last_key</i>"]
    end

    IK -->|"last_key field"| CUR
    TB -->|"token field"| CUR

    subgraph Enumeration["Connector Output"]
        SI["<b>ScanItem</b><br/>item_key: ItemKey<br/>item_ref: ItemRef<br/>stable_item_id: StableItemId<br/>version: VersionId<br/>size_hint: Option&lt;u64&gt;<br/>content_hints: Option&lt;ContentHints&gt;<br/>location: Option&lt;Location&gt;"]
    end

    IK -->|"item_key field"| SI
    IR -->|"item_ref field"| SI

    subgraph Budgets["Scan Budgets"]
        BU["<b>Budgets</b><br/>max_items: NonZeroUsize<br/>max_bytes: NonZeroU64<br/>deadline: Option&lt;Instant&gt;"]
    end

    subgraph Errors["Error Types"]
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

- `ItemKey` has `Ord` (lexicographic byte comparison) because it participates in cursor progression and shard range membership. `ItemRef` and `TokenBytes` are unordered — they are looked up, not ranged.
- `MAX_ITEM_KEY_SIZE` (4 KiB) and `MAX_TOKEN_SIZE` (16 KiB) track coordination cursor field limits so connector paging state fits in cursor updates without truncation. `MAX_ITEM_REF_SIZE` (16 KiB) is independent — refs never enter cursor state.
- `Cursor` constructors make the `(None, Some(token))` state unrepresentable. `try_from_update` rejects `TokenWithoutLastKey`.
- `EnumerateError` and `ReadError` are structurally identical but distinct nominal types. This prevents accidental cross-assignment and lets orchestration apply different retry policies per operation path.
- All toxic-byte wrappers support both owned (`Box<[u8]>`) and pooled (`ByteSlot` + `Arc<PooledByteSlab>`) storage. Pooled values avoid per-item heap allocation on HOT enumeration paths.

See also: [03-id-derivation-dag.md](./03-id-derivation-dag.md) for `StableItemId` and `VersionId` derivation, [08-pagecommit-typestate.md](./08-pagecommit-typestate.md) for how `ScanItem` flows into the persistence commit protocol.

---

## 3. Connector-to-Driver Bridge

The scan-driver layer (`gossip-scan-driver`) defines a second trait surface that bridges connectors into the scan execution pipeline. `ConnectorKind` discriminates the source backend; `ScanSourceFactory` maps `Assignment`s to boxed `ScanDriver` instances. This separation keeps `gossip-contracts` a lightweight leaf crate while scan-driver concerns (engines, event sinks, cancellation) live in their own crate.

```mermaid
%% Diagram: connector-driver-bridge
graph LR
    subgraph Coordination["B2: Coordination"]
        AS["<b>Assignment</b><br/>job_id, connector_kind,<br/>connector_instance_id,<br/>shard_spec, cursor, source"]
    end

    subgraph ScanDriver["gossip-scan-driver"]
        CK["<b>ConnectorKind</b><br/>Filesystem | Git | InMemory"]
        SSF["<b>ScanSourceFactory</b><br/>driver_for_assignment(&Assignment)<br/>  → Result&lt;Box&lt;dyn ScanDriver&gt;&gt;<br/>capabilities()<br/>  → SourceCapabilities"]
        SD["<b>ScanDriver</b><br/>run(&mut, Engine, &ScanExecutionConfig,<br/>  &dyn EventOutput, Option&lt;&dyn GitEventOutput&gt;,<br/>  &dyn CommitSink, &CancellationToken)<br/>  → Result&lt;ScanReport&gt;"]
    end

    subgraph Factories["gossip-connectors (factories)"]
        FSF["<b>FilesystemScanSourceFactory</b><br/>→ FsScanDriver<br/>checkpoint: ✓  cancel: ✗"]
        GSF["<b>GitScanSourceFactory</b><br/>→ GitScanDriver<br/>checkpoint: ✗  cancel: ✗"]
        MSF["<b>InMemoryScanSourceFactory</b><br/>→ InMemoryScanDriver<br/>checkpoint: ✓  cancel: ✓"]
    end

    AS -->|"connector_kind selects"| CK
    CK -->|"routes to"| SSF
    SSF -->|"produces"| SD

    FSF -->|impl| SSF
    GSF -->|impl| SSF
    MSF -->|impl| SSF

    style AS fill:#DCFCE7,stroke:#166534
    style CK fill:#EF4444,stroke:#991B1B,color:#fff
    style SSF fill:#FEE2E2,stroke:#991B1B
    style SD fill:#FEE2E2,stroke:#991B1B
    style FSF fill:#FEE2E2,stroke:#991B1B
    style GSF fill:#FEE2E2,stroke:#991B1B
    style MSF fill:#FEE2E2,stroke:#991B1B
```

**Execution flow:**

1. The coordination layer builds an `Assignment` from a shard claim, including `ConnectorKind`, `ShardSpec`, `Cursor`, and source-specific payload (`AssignmentSource::Filesystem { root }`, `AssignmentSource::Git { repo_root }`, or `AssignmentSource::InMemory { dataset_id }`).
2. The runtime selects a `ScanSourceFactory` by `ConnectorKind` and calls `driver_for_assignment` to produce a boxed `ScanDriver`.
3. The driver's `run()` method receives a compiled `Engine`, execution config, event/commit sinks, and a `CancellationToken`, then returns a `ScanReport` with aggregate counters.

**Capability differences by factory:**

| Factory | Checkpoint hints | Cooperative cancel |
|---------|------------------|--------------------|
| `FilesystemScanSourceFactory` | Yes | No (`parallel_scan_dir` has no mid-scan cancel) |
| `GitScanSourceFactory` | No | No |
| `InMemoryScanSourceFactory` | Yes | Yes (polls `is_cancelled()` per item) |

See also: [04-end-to-end-scan-flow.md](./04-end-to-end-scan-flow.md) for the ScanDriver architecture and distributed worker loop, [05-shard-and-run-state-machines.md](./05-shard-and-run-state-machines.md) for shard assignment lifecycle.

---

## 4. Error Classification Flow

I/O errors from the host OS are classified at the connector boundary into a binary `ErrorClass` posture. The shared helpers in `gossip-connectors::common` centralize this decision so all three connectors use identical permanence logic. Classified errors carry a log-safe `ToxicDigest` of the affected path rather than raw filesystem paths.

```mermaid
%% Diagram: error-classification-flow
graph TD
    subgraph IO["Raw I/O Layer"]
        IOE["<b>std::io::Error</b><br/>from filesystem / git / network"]
    end

    subgraph Classify["Classification (gossip-connectors::common)"]
        IPIE["<b>is_permanent_io_error()</b><br/>NotFound<br/>PermissionDenied<br/>InvalidInput<br/>InvalidFilename<br/>NotADirectory<br/>IsADirectory<br/>ELOOP (symlink loop)"]
        CIE2["<b>classify_io_enumerate_error()</b><br/>op, path, &io::Error<br/>→ EnumerateError"]
        CIR["<b>classify_io_read_error()</b><br/>op, Option&lt;path&gt;, &io::Error<br/>→ ReadError"]
    end

    IOE -->|"enumerate path"| CIE2
    IOE -->|"read path"| CIR
    CIE2 -->|"delegates to"| IPIE
    CIR -->|"delegates to"| IPIE

    subgraph Redaction["Log-Safe Redaction"]
        TD2["<b>ToxicDigest</b><br/>BLAKE3 hash of path bytes<br/>no raw paths in error messages"]
    end

    CIE2 -->|"path_digest()"| TD2
    CIR -->|"path_digest()"| TD2

    subgraph Outcomes["Classified Outcomes"]
        RET["<b>ErrorClass::Retryable</b><br/>transient / capacity failures<br/>→ retry with backoff"]
        PERM["<b>ErrorClass::Permanent</b><br/>structural failures<br/>→ park shard or skip item"]
    end

    IPIE -->|"false: transient"| RET
    IPIE -->|"true: structural"| PERM

    subgraph Actions["Orchestration Response"]
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
|------------------|----------------|-----------|
| `NotFound` | Permanent | Resource does not exist |
| `PermissionDenied` | Permanent | Access control failure |
| `InvalidInput` | Permanent | Malformed argument |
| `InvalidFilename` | Permanent | OS-rejected filename |
| `NotADirectory` | Permanent | Type mismatch |
| `IsADirectory` | Permanent | Type mismatch |
| `ELOOP` (Unix) | Permanent | Symlink cycle |
| Everything else | Retryable | Network timeout, interrupted, would-block, etc. |

**Design notes:**

- `retry_after_ms` is advisory backoff metadata from the connector (e.g., HTTP `Retry-After` header). The runtime may enforce stricter global policies.
- `classify_io_enumerate_error` always includes a `ToxicDigest` of the path. `classify_io_read_error` accepts `Option<&Path>` because some read operations do not have an associated filesystem path.
- `enumerate_error_to_read` bridges an `EnumerateError` to a `ReadError` preserving retryability, used when a read operation requires enumeration-phase setup (e.g., `ensure_root_fd` in `FilesystemConnector::open`).
- Error `message` fields undergo control-character sanitization in `Display` (C0/C1 replaced with U+FFFD, preserving HT/LF/CR) to prevent log injection.

See also: [09-circuit-breaker.md](./09-circuit-breaker.md) for how classified errors feed circuit breaker state transitions, [10-failure-modes-and-recovery.md](./10-failure-modes-and-recovery.md) for system-wide failure recovery patterns.

---

## Source Code References

| Crate | File | Key Types / Functions |
|-------|------|----------------------|
| `gossip-contracts` | `crates/gossip-contracts/src/connector/api.rs` | `ErrorClass`, `EnumerateError`, `ReadError`, `ConnectorCapabilities` |
| `gossip-contracts` | `crates/gossip-contracts/src/connector/types.rs` | `ItemKey`, `ItemRef`, `TokenBytes`, `Cursor`, `ScanItem`, `Budgets`, `ConnectorInputError`, `ContentHints`, `Location`, `VersionId`, `PooledByteSlab` |
| `gossip-contracts` | `crates/gossip-contracts/src/connector/mod.rs` | Module structure and re-exports |
| `gossip-connectors` | `crates/gossip-connectors/src/lib.rs` | `connector_tag_for_kind`, re-exports of connectors and factories |
| `gossip-connectors` | `crates/gossip-connectors/src/common.rs` | `is_permanent_io_error`, `classify_io_enumerate_error`, `classify_io_read_error`, `path_digest`, `borrowed_shard_bound`, `resolve_bounds`, `key_resume_start`, `estimate_split_from_sorted` |
| `gossip-connectors` | `crates/gossip-connectors/src/filesystem.rs` | `FilesystemConnector` |
| `gossip-connectors` | `crates/gossip-connectors/src/git.rs` | `GitConnector` |
| `gossip-connectors` | `crates/gossip-connectors/src/in_memory.rs` | `InMemoryDeterministicConnector`, `MemItem` |
| `gossip-connectors` | `crates/gossip-connectors/src/scan_driver.rs` | `FilesystemScanSourceFactory`, `GitScanSourceFactory`, `InMemoryScanSourceFactory` |
| `gossip-scan-driver` | `crates/gossip-scan-driver/src/lib.rs` | `ConnectorKind`, `Assignment`, `AssignmentSource`, `ScanSourceFactory`, `ScanDriver`, `ScanReport`, `SourceCapabilities`, `CancellationToken`, `CommitSink` |
