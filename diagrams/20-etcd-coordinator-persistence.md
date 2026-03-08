# etcd Coordinator Persistence

The `gossip-coordination-etcd` crate implements the B2 Coordination backend
against an etcd cluster. It provides the keyspace layout, binary codecs,
connection management, and optimistic CAS transaction logic needed to persist
coordination records (runs, shards, leases, op-logs) to etcd.

This diagram covers four systems that together form the etcd coordination
persistence layer:

1. **Backend architecture** — the direct-persistence model, sync-async bridge,
   and connection lifecycle.
2. **Keyspace design** — the hierarchical etcd key layout with sibling
   separation, fixed-width hex encoding, and scan isolation.
3. **Codec wire format** — the hand-written binary encoding for `RunRecord`
   and `ShardRecord`, including two-phase decode with staged slab rollback.
4. **Integration** — how the etcd backend plugs into the coordination trait
   hierarchy and connects to the broader system.

> **Notation.** Solid lines represent data flow and composition. Dashed lines
> represent delegation, trait implementation, or future connections. Coordination
> types use the B2 green palette (fill `#22C55E`, light fill `#DCFCE7`, stroke
> `#166534`). Worker / cross-cutting components use grey.

---

## 1. Backend Architecture

`EtcdCoordinator` directly persists all coordination state to etcd using
optimistic CAS (compare-and-swap) transactions. Each mutating operation reads
the current record, validates preconditions locally, builds a CAS transaction
conditioned on the record's `mod_revision`, and retries with jittered
exponential backoff on CAS failure. There is no in-process delegation layer —
the etcd cluster is the single source of truth.

Shard ownership uses a dual-key design: a persistent shard record (keyed under
`/shards/{id}`) and an ephemeral `/owner` key with an etcd lease TTL. When the
lease expires (worker crash, network partition), etcd automatically deletes the
owner key, making the shard eligible for re-acquisition.

```mermaid
%% Diagram: etcd-backend-architecture
graph TB
    subgraph caller ["Caller (Scanner Runtime)"]
        SR["Coordination trait callers<br/>Sync &amp;mut self methods"]
    end

    subgraph etcd_coord ["EtcdCoordinator"]
        CONFIG["EtcdCoordinatorConfig<br/>endpoints: Vec&lt;String&gt;<br/>namespace_prefix: String"]
        KS["EtcdKeyspace<br/>Deterministic key builder<br/>rooted at namespace prefix"]
        RT["tokio::runtime::Runtime<br/>Current-thread, sync-async bridge"]
        CLIENT["etcd_client::Client<br/>Live gRPC connection"]
        SCRATCH["claim_candidates_scratch<br/>Reusable Vec&lt;ShardId&gt; buffer"]
    end

    subgraph bridge ["Sync-Async Bridge Helpers"]
        direction TB
        GET["etcd_get()"]
        TXN["etcd_txn()"]
        LG["etcd_lease_grant()"]
        LKA["etcd_lease_keep_alive_once()"]
        LR["etcd_lease_revoke()"]
    end

    subgraph etcd_cluster ["etcd Cluster"]
        ETCD["etcd v3 gRPC API<br/>CAS transactions, lease TTL,<br/>prefix scans"]
    end

    SR --> etcd_coord
    CONFIG --> KS
    RT -->|"block_on()"| bridge
    bridge -->|"client.get/txn/lease_*"| ETCD

    style SR fill:#F3F4F6,stroke:#374151,color:#374151

    style CONFIG fill:#DCFCE7,stroke:#166534,color:#166534
    style KS fill:#DCFCE7,stroke:#166534,color:#166534
    style RT fill:#F3F4F6,stroke:#374151,color:#374151
    style CLIENT fill:#F3F4F6,stroke:#374151,color:#374151
    style SCRATCH fill:#F3F4F6,stroke:#374151,color:#374151

    style GET fill:#DCFCE7,stroke:#166534,color:#166534
    style TXN fill:#DCFCE7,stroke:#166534,color:#166534
    style LG fill:#DCFCE7,stroke:#166534,color:#166534
    style LKA fill:#DCFCE7,stroke:#166534,color:#166534
    style LR fill:#DCFCE7,stroke:#166534,color:#166534

    style ETCD fill:#F3F4F6,stroke:#374151,color:#374151
```

### Connection lifecycle

`EtcdCoordinator::connect()` performs a two-phase fail-fast initialization:

| Phase | Action | Error |
|:---|:---|:---|
| 1. gRPC connect | Establishes a channel with a 5-second connect timeout | `EtcdCoordinatorError::Etcd { Connect }` |
| 2. Status probe | Round-trips a maintenance `Status` RPC to confirm reachability | `EtcdCoordinatorError::Etcd { Status }` |

On success the caller holds a validated config, a live etcd connection, and
a `EtcdKeyspace` for deterministic key generation. A `debug_assert!` prevents
nested `block_on` calls by verifying no Tokio runtime is already active.

### Sync-async bridge

The coordination traits are synchronous. The etcd client is async (tonic/gRPC).
A private current-thread Tokio runtime bridges the gap via `block_on()`. A
`debug_assert!` guard prevents calling trait methods from within an active Tokio
async context (nested `block_on` panics).

---

## 2. Keyspace Design

All coordination records map to deterministic ASCII etcd key paths rooted at a
configurable namespace prefix. The tree separates record keys from active-index
keys as **siblings** (not nested) to prevent prefix-scan cross-contamination.

```mermaid
%% Diagram: etcd-keyspace-tree
graph TB
    PREFIX["{prefix}<br/>(e.g. /gossip/v1)"]

    TENANTS["/tenants"]

    T_HEX["{tenant_hex}<br/>64 lowercase hex chars"]

    RUNS["/runs"]
    RUNS_ACTIVE["/runs_active"]

    R_HEX["{run_hex}<br/>16 zero-padded hex chars"]
    R_ACTIVE_HEX["{run_hex}<br/>active-run index entry"]

    SHARDS["/shards"]
    SHARDS_ACTIVE["/shards_active"]

    S_HEX["{shard_hex}<br/>shard record"]
    S_OWNER["{shard_hex}/owner<br/>ownership key"]
    S_ACTIVE_HEX["{shard_hex}<br/>active-shard index entry"]

    PREFIX --> TENANTS
    TENANTS --> T_HEX
    T_HEX --> RUNS
    T_HEX --> RUNS_ACTIVE
    RUNS --> R_HEX
    RUNS_ACTIVE --> R_ACTIVE_HEX
    R_HEX --> SHARDS
    R_HEX --> SHARDS_ACTIVE
    SHARDS --> S_HEX
    S_HEX --> S_OWNER
    SHARDS_ACTIVE --> S_ACTIVE_HEX

    style PREFIX fill:#DCFCE7,stroke:#166534,color:#166534
    style TENANTS fill:#DCFCE7,stroke:#166534,color:#166534
    style T_HEX fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF

    style RUNS fill:#22C55E,stroke:#166534,color:#FFF
    style RUNS_ACTIVE fill:#22C55E,stroke:#166534,color:#FFF
    style R_HEX fill:#22C55E,stroke:#166534,color:#FFF
    style R_ACTIVE_HEX fill:#22C55E,stroke:#166534,color:#FFF

    style SHARDS fill:#22C55E,stroke:#166534,color:#FFF
    style SHARDS_ACTIVE fill:#22C55E,stroke:#166534,color:#FFF
    style S_HEX fill:#22C55E,stroke:#166534,color:#FFF
    style S_OWNER fill:#22C55E,stroke:#166534,color:#FFF
    style S_ACTIVE_HEX fill:#22C55E,stroke:#166534,color:#FFF
```

### Key layout in full-path form

```text
{prefix}/tenants/{tenant_hex}/runs/{run_hex}                    → run record
{prefix}/tenants/{tenant_hex}/runs/{run_hex}/shards/{shard_hex} → shard record
{prefix}/tenants/{tenant_hex}/runs/{run_hex}/shards/{shard_hex}/owner → ownership
{prefix}/tenants/{tenant_hex}/runs/{run_hex}/shards_active/{shard_hex} → active index
{prefix}/tenants/{tenant_hex}/runs_active/{run_hex}             → active-run index
```

### Design rationale

| Decision | Why |
|:---|:---|
| **`runs/` vs `runs_active/` as siblings** | A prefix scan on `runs/` must not pull in active-index entries, and vice versa. Sibling placement under the tenant guarantees scan isolation. |
| **`shards/` vs `shards_active/` as siblings** | Same sibling separation under each run key. The trailing-slash convention on scan prefixes (`shards/`) prevents cross-category matches. |
| **Fixed-width hex encoding** | `RunId` and `ShardId` are zero-padded to 16 hex chars (u64), `TenantId` to 64 hex chars (32 bytes). Fixed width ensures lexicographic key order matches numeric order, making etcd range scans predictable. |
| **Lowercase-only hex** | All hex uses `[0-9a-f]`. No uppercase letters, so byte-level equality works for key comparison. |
| **Buffer-reuse `_into` API** | Every key method has a `_into` variant appending into a `&mut String`, enabling hot-path callers to reuse a single buffer across multiple key constructions. |

### Prefix validation

`EtcdKeyspace::new()` enforces:
- Must start with `/` (absolute etcd paths).
- Must not end with `/` (unless exactly `"/"`), preventing double-slash joins.
- No consecutive slashes (`//`) anywhere, preventing invisible empty path segments.

### Scan isolation

The trailing-slash convention is critical: `shard_records_scan_prefix()` returns
`.../shards/` (with trailing slash) while `shards_active_prefix()` returns
`.../shards_active` (without). An etcd prefix query on `.../shards/` matches
shard record keys but not the `shards_active` subtree, because `shards/` is not
a prefix of `shards_active`.

---

## 3. Codec Wire Format

The codec provides hand-written binary serialization for `RunRecord` and
`ShardRecord`. No serde is involved — every byte is explicit, and the decode
path interleaves validation with field reads, rejecting malformed blobs early
without wasted allocation.

### Wire format structure

```mermaid
%% Diagram: codec-wire-format
graph LR
    subgraph header ["3-Byte Header"]
        VER["version: 2 bytes<br/>(b'v1')"]
        KIND["kind: 1 byte<br/>(BlobKind discriminant)"]
    end

    subgraph encoding_rules ["Encoding Rules"]
        INT["Integers<br/>little-endian, no padding"]
        VAR["Variable-length<br/>u32 length prefix + bytes"]
        OPT["Optional fields<br/>1-byte bool presence tag"]
        ENUM["Enum discriminants<br/>raw u8 via as_u8()"]
        COLL["Collections<br/>u32 count + sequential elements"]
    end

    subgraph blob_kinds ["BlobKind Dispatch"]
        RUN["BlobKind::RunRecord (1)<br/>→ decode_run_record"]
        SHARD["BlobKind::ShardRecord (2)<br/>→ decode_shard_record"]
    end

    VER --> KIND
    KIND --> RUN
    KIND --> SHARD

    style VER fill:#DCFCE7,stroke:#166534,color:#166534
    style KIND fill:#DCFCE7,stroke:#166534,color:#166534

    style INT fill:#F3F4F6,stroke:#374151,color:#374151
    style VAR fill:#F3F4F6,stroke:#374151,color:#374151
    style OPT fill:#F3F4F6,stroke:#374151,color:#374151
    style ENUM fill:#F3F4F6,stroke:#374151,color:#374151
    style COLL fill:#F3F4F6,stroke:#374151,color:#374151

    style RUN fill:#22C55E,stroke:#166534,color:#FFF
    style SHARD fill:#22C55E,stroke:#166534,color:#FFF
```

### Two-phase decode: validate-then-materialize

Decoding separates wire-format parsing from domain-type construction. This
keeps codec concerns out of domain types and lets the decoder reject invalid
data before touching the caller's `ByteSlab`.

```mermaid
%% Diagram: two-phase-decode
sequenceDiagram
    autonumber
    participant C as Caller
    participant D as Decoder
    participant OWN as OwnedRecord<br/>(heap intermediate)
    participant VAL as validate()
    participant MAT as into_record()
    participant SLAB as ByteSlab

    C->>D: decode_shard_record(&bytes, &mut slab)
    D->>D: Read 3-byte header (version + kind)
    D->>D: Parse all fields into plain Vec<u8>

    D->>OWN: Construct OwnedShardRecord
    OWN->>VAL: validate()
    Note over VAL: Structural invariant checks:<br/>lease owner/deadline jointly present,<br/>terminal shards have no lease,<br/>parked shards have park_reason,<br/>split shards have spawned children

    alt Validation fails
        VAL-->>C: Err(InvariantViolation)
    end

    OWN->>MAT: into_record(&mut slab)
    Note over MAT: Allocate PooledShardSpec,<br/>PooledCursor, PooledSpawned<br/>into ByteSlab

    MAT->>SLAB: staged_alloc(spec_bytes)
    MAT->>SLAB: staged_alloc(cursor_bytes)
    MAT->>SLAB: staged_alloc(spawned_bytes)

    alt Any slab allocation fails
        MAT->>SLAB: rollback all staged allocations
        MAT-->>C: Err(SlabFull)
        Note over SLAB: Slab unchanged (strong exception guarantee)
    end

    MAT-->>C: Ok(ShardRecord)
```

### Staged slab allocation

`ShardRecord` fields live in a caller-provided `ByteSlab` to avoid per-decode
heap allocation on the hot path. The `StagedShardAllocations` guard tracks
every slab allocation made during decode. If any allocation fails, the guard
rolls back all previously staged allocations, leaving the slab unchanged. This
provides a **strong exception guarantee**: either the full `ShardRecord`
materializes into the slab, or the slab is untouched.

### Invariant enforcement (defense-in-depth)

Invariants are checked **twice** during decode:

| Check point | Phase | Purpose |
|:---|:---|:---|
| `OwnedRecord::validate()` | After wire parse | Catches wire corruption early, before slab allocation |
| Domain type construction | During materialization | Defense-in-depth against inconsistent intermediate state |

Invariants checked for `ShardRecord`:
- Active runs must have root shards; Initializing must not
- `completed_at` presence matches terminal status
- Lease owner and deadline must be jointly present or absent
- Terminal shards must not have leases
- Parked shards must have `park_reason`
- Split shards must have spawned children
- `parent` presence matches shard derived-bit
- Op-log entries: non-zero `payload_hash`, positive `executed_at`,
  non-decreasing timestamps, no duplicate `OpId`s

### Security bounds

`MAX_FIELD_SIZE = 1 MiB` prevents crafted length prefixes from triggering
unbounded allocations. Collection lengths are further bounded by domain
constants (`OP_LOG_CAP`, `MAX_SPAWNED_PER_SHARD`) and by structural upper
bounds derived from remaining wire bytes.

---

## 4. Error Hierarchy

```mermaid
%% Diagram: etcd-error-hierarchy
graph TB
    ECE["EtcdCoordinatorError"]

    CFG["Config(EtcdCoordinatorConfigError)<br/>Validation before I/O"]
    RTB["RuntimeBuild(io::Error)<br/>Tokio runtime creation failure"]
    CODEC_ERR["Codec { operation, source }<br/>Encode/decode failures"]
    ETCD["Etcd { operation, source }<br/>gRPC failures"]
    KSE["Keyspace(EtcdKeyspaceError)<br/>Namespace prefix validation"]

    OP_CONNECT["EtcdOperation::Connect"]
    OP_STATUS["EtcdOperation::Status"]

    CFGE_NE["NoEndpoints"]
    CFGE_EE["EmptyEndpoint { index }"]
    CFGE_IS["InvalidEndpointScheme { index }"]
    CFGE_EP["EmptyNamespacePrefix"]
    CFGE_SS["PrefixMustStartWithSlash"]
    CFGE_ES["PrefixMustNotEndWithSlash"]
    CFGE_DS["PrefixContainsDoubleSlash"]

    CODEC["EtcdCodecError (12 variants)<br/>Truncated, InvalidVersionPrefix,<br/>InvalidBlobKind, UnexpectedBlobKind,<br/>InvalidBool, InvalidEnum,<br/>InvalidSpec, InvalidCursor,<br/>SlabFull, TrailingBytes,<br/>InvariantViolation, FieldTooLarge"]

    ECE --> CFG
    ECE --> RTB
    ECE --> CODEC_ERR
    ECE --> ETCD
    ECE --> KSE

    ETCD --> OP_CONNECT
    ETCD --> OP_STATUS

    CFG --> CFGE_NE
    CFG --> CFGE_EE
    CFG --> CFGE_IS
    CFG --> CFGE_EP
    CFG --> CFGE_SS
    CFG --> CFGE_ES
    CFG --> CFGE_DS

    style ECE fill:#22C55E,stroke:#166534,color:#FFF
    style CFG fill:#DCFCE7,stroke:#166534,color:#166534
    style RTB fill:#F3F4F6,stroke:#374151,color:#374151
    style ETCD fill:#DCFCE7,stroke:#166534,color:#166534
    style KSE fill:#DCFCE7,stroke:#166534,color:#166534

    style OP_CONNECT fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_STATUS fill:#F3F4F6,stroke:#374151,color:#374151

    style CFGE_NE fill:#F3F4F6,stroke:#374151,color:#374151
    style CFGE_EE fill:#F3F4F6,stroke:#374151,color:#374151
    style CFGE_IS fill:#F3F4F6,stroke:#374151,color:#374151
    style CFGE_EP fill:#F3F4F6,stroke:#374151,color:#374151
    style CFGE_SS fill:#F3F4F6,stroke:#374151,color:#374151
    style CFGE_ES fill:#F3F4F6,stroke:#374151,color:#374151
    style CFGE_DS fill:#F3F4F6,stroke:#374151,color:#374151

    style CODEC_ERR fill:#DCFCE7,stroke:#166534,color:#166534
```

Config `Debug` output redacts credentials from endpoint URIs, showing
`***@host:port` instead of `user:pass@host:port`.

---

## 5. Integration with Coordination Traits

The etcd backend plugs into the same trait hierarchy used by all coordination
backends. The three traits define the full coordination surface:

```mermaid
%% Diagram: etcd-trait-integration
graph TB
    subgraph traits ["Coordination Trait Hierarchy"]
        direction TB
        CB_TRAIT["CoordinationBackend<br/>7 shard lifecycle methods:<br/>acquire_and_restore_into, renew, checkpoint,<br/>complete, park, split_replace,<br/>split_residual"]
        RM_TRAIT["RunManagement<br/>10 run lifecycle methods:<br/>create/complete/fail/cancel run,<br/>register_shards, get_run,<br/>get_run_progress, list_shards,<br/>collect_claim_candidates, unpark"]
        SC_TRAIT["ShardClaiming<br/>1 method:<br/>claim_next_available"]
    end

    subgraph backends ["Coordination Backends"]
        INMEM_BACK["InMemoryCoordinator<br/>(reference implementation)"]
        ETCD_BACK["EtcdCoordinator<br/>(etcd-backed, direct persistence)"]
    end

    subgraph etcd_modules ["EtcdCoordinator Modules"]
        MOD_CONFIG["config.rs<br/>Endpoint + prefix validation<br/>Credential redaction"]
        MOD_KS["keyspace.rs<br/>Deterministic key paths<br/>Buffer-reuse API"]
        MOD_CODEC["codec.rs<br/>Binary encode/decode<br/>Staged slab rollback"]
        MOD_ERR["error.rs<br/>Error hierarchy<br/>Operation labels"]
        MOD_BACK["backend.rs<br/>Direct etcd persistence +<br/>sync-async bridge"]
    end

    subgraph testing ["Testing Coverage"]
        UNIT["Unit tests<br/>Config, keyspace, error"]
        PROP["Property tests<br/>Key structural invariants,<br/>scan isolation"]
        CODEC_TEST["Codec round-trip tests<br/>All status combinations,<br/>error cases"]
        FUZZ["Fuzz targets (4)<br/>decode_shard_record,<br/>decode_run_record,<br/>round_trip_shard_record,<br/>round_trip_run_record"]
        INTEG["Integration test<br/>Live etcd Status probe"]
    end

    INMEM_BACK -.->|"implements"| CB_TRAIT
    INMEM_BACK -.->|"implements"| RM_TRAIT
    INMEM_BACK -.->|"implements"| SC_TRAIT

    ETCD_BACK -.->|"implements"| CB_TRAIT
    ETCD_BACK -.->|"implements"| RM_TRAIT
    ETCD_BACK -.->|"implements"| SC_TRAIT

    ETCD_BACK --> MOD_CONFIG
    ETCD_BACK --> MOD_KS
    ETCD_BACK --> MOD_CODEC
    ETCD_BACK --> MOD_ERR
    ETCD_BACK --> MOD_BACK

    style CB_TRAIT fill:#22C55E,stroke:#166534,color:#FFF
    style RM_TRAIT fill:#22C55E,stroke:#166534,color:#FFF
    style SC_TRAIT fill:#22C55E,stroke:#166534,color:#FFF

    style INMEM_BACK fill:#DCFCE7,stroke:#166534,color:#166534
    style ETCD_BACK fill:#22C55E,stroke:#166534,color:#FFF

    style MOD_CONFIG fill:#DCFCE7,stroke:#166534,color:#166534
    style MOD_KS fill:#DCFCE7,stroke:#166534,color:#166534
    style MOD_CODEC fill:#DCFCE7,stroke:#166534,color:#166534
    style MOD_ERR fill:#DCFCE7,stroke:#166534,color:#166534
    style MOD_BACK fill:#DCFCE7,stroke:#166534,color:#166534

    style UNIT fill:#F3F4F6,stroke:#374151,color:#374151
    style PROP fill:#F3F4F6,stroke:#374151,color:#374151
    style CODEC_TEST fill:#F3F4F6,stroke:#374151,color:#374151
    style FUZZ fill:#F3F4F6,stroke:#374151,color:#374151
    style INTEG fill:#F3F4F6,stroke:#374151,color:#374151
```

### Module readiness

| Module | Status | Notes |
|:---|:---|:---|
| `config.rs` | Complete | Endpoint validation, credential redaction, CSV parsing |
| `keyspace.rs` | Complete | Deterministic paths, buffer-reuse API, scan isolation |
| `codec.rs` | Complete | Binary encode/decode, staged rollback, fuzz-tested |
| `error.rs` | Complete | Full error hierarchy with operation labels |
| `backend.rs` | Mostly complete | Direct etcd persistence via CAS transactions; `complete`, `park_shard`, `complete_run`, `fail_run`, `cancel_run`, `unpark_shard` not yet implemented |

The keyspace and codec are shared infrastructure used by the CAS transaction
logic in `backend.rs`. Operations that are not yet implemented panic with
`fail_unimplemented` — they have clear protocol semantics from the in-memory
reference implementation and will be ported as the distributed runtime requires
them.

---

## Cross-References

- [Shard and Run State Machines](05-shard-and-run-state-machines.md) — the state
  machines that the coordination traits operate on
- [Fencing Protocol](06-fencing-protocol.md) — fence epoch validation performed
  by the coordination backend on every mutating operation
- [Lease Lifecycle](07-lease-lifecycle.md) — lease acquisition and renewal that
  the backend must enforce
- [System Overview](01-system-overview.md) — where the etcd backend fits in the
  five-boundary architecture
- [Persistence Contracts](19-persistence-contracts.md) — the B5 Persistence
  contracts that the etcd backend will need to integrate with for done-ledger
  and findings persistence

## Source Code References

| File | Purpose |
|:---|:---|
| `crates/gossip-coordination-etcd/src/lib.rs` | Crate root, public re-exports |
| `crates/gossip-coordination-etcd/src/backend.rs` | `EtcdCoordinator` struct, CAS transaction logic, sync-async bridge |
| `crates/gossip-coordination-etcd/src/keyspace.rs` | `EtcdKeyspace` deterministic key-path construction |
| `crates/gossip-coordination-etcd/src/codec.rs` | Binary encode/decode for `RunRecord` and `ShardRecord` |
| `crates/gossip-coordination-etcd/src/config.rs` | `EtcdCoordinatorConfig` validated connection parameters |
| `crates/gossip-coordination-etcd/src/error.rs` | `EtcdCoordinatorError` and `EtcdOperation` |
| `crates/gossip-coordination-etcd/src/tests.rs` | Config, keyspace, property tests, integration test |
| `crates/gossip-coordination-etcd/src/codec_tests.rs` | Codec round-trip and error-case tests |
| `crates/gossip-coordination-etcd/fuzz/fuzz_targets/` | 4 libfuzzer targets for decode/round-trip |
| `crates/gossip-coordination/src/traits.rs` | `CoordinationBackend`, `RunManagement`, `ShardClaiming` trait definitions |
| `crates/gossip-coordination/src/in_memory.rs` | `InMemoryCoordinator` reference implementation |
