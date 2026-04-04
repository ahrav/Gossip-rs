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

The etcd coordination backend has two entrypoints:

- **`EtcdCoordinator`** — sync wrapper that owns a single-threaded Tokio
  runtime. Wraps each etcd RPC in `block_on()`. Use when no async runtime
  is available.
- **`AsyncEtcdCoordinator`** — async core that implements
  `AsyncCoordinationBackend` and `AsyncRunManagement`. Callers provide
  their own async runtime. Use inside existing Tokio tasks.

Both directly persist all coordination state to etcd using optimistic CAS
(compare-and-swap) transactions. Each mutating operation reads the current
record, validates preconditions locally, builds a CAS transaction conditioned
on the record's `mod_revision`, and retries with jittered exponential backoff
on CAS failure. There is no in-process delegation layer — the etcd cluster is
the single source of truth.

Shard ownership uses a dual-key design: a persistent shard record (keyed under
`/shards/{id}`) and an ephemeral `/owner` key with an etcd lease TTL. When the
lease expires (worker crash, network partition), etcd automatically deletes the
owner key, making the shard eligible for re-acquisition.

```mermaid
%% Diagram: etcd-backend-architecture
graph TB
    subgraph caller ["Callers"]
        SR_SYNC["Sync callers<br/>&amp;mut self methods"]
        SR_ASYNC["Async callers<br/>async fn methods"]
    end

    subgraph sync_coord ["EtcdCoordinator (sync wrapper)"]
        CONFIG["EtcdCoordinatorConfig<br/>endpoints: Vec&lt;String&gt;<br/>namespace_prefix: String"]
        KS["EtcdKeyspace<br/>Deterministic key builder<br/>rooted at namespace prefix"]
        RT["tokio::runtime::Runtime<br/>Current-thread, sync-async bridge"]
        SCRATCH["claim_candidates_scratch<br/>Reusable Vec&lt;ShardId&gt; buffer"]
    end

    subgraph async_coord ["AsyncEtcdCoordinator (async core)"]
        A_CONFIG["EtcdCoordinatorConfig"]
        A_KS["EtcdKeyspace"]
        A_CLIENT["etcd_client::Client<br/>Live gRPC connection"]
        A_SCRATCH["claim_candidates_scratch"]
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

    SR_SYNC --> sync_coord
    SR_ASYNC --> async_coord
    CONFIG --> KS
    RT -->|"block_on()"| bridge
    bridge -->|"client.get/txn/lease_*"| ETCD
    A_CLIENT -->|"direct async calls"| ETCD

    style SR_SYNC fill:#F3F4F6,stroke:#374151,color:#374151
    style SR_ASYNC fill:#F3F4F6,stroke:#374151,color:#374151

    style CONFIG fill:#DCFCE7,stroke:#166534,color:#166534
    style KS fill:#DCFCE7,stroke:#166534,color:#166534
    style RT fill:#F3F4F6,stroke:#374151,color:#374151
    style SCRATCH fill:#F3F4F6,stroke:#374151,color:#374151

    style A_CONFIG fill:#DCFCE7,stroke:#166534,color:#166534
    style A_KS fill:#DCFCE7,stroke:#166534,color:#166534
    style A_CLIENT fill:#F3F4F6,stroke:#374151,color:#374151
    style A_SCRATCH fill:#F3F4F6,stroke:#374151,color:#374151

    style GET fill:#DCFCE7,stroke:#166534,color:#166534
    style TXN fill:#DCFCE7,stroke:#166534,color:#166534
    style LG fill:#DCFCE7,stroke:#166534,color:#166534
    style LKA fill:#DCFCE7,stroke:#166534,color:#166534
    style LR fill:#DCFCE7,stroke:#166534,color:#166534

    style ETCD fill:#F3F4F6,stroke:#374151,color:#374151
```

### Connection lifecycle

Both `EtcdCoordinator::connect()` and `AsyncEtcdCoordinator::connect()`
perform a two-phase fail-fast initialization:

| Phase | Action | Error |
|:---|:---|:---|
| 1. gRPC connect | Establishes a channel with a 5-second connect timeout | `EtcdCoordinatorError::Etcd { Connect }` |
| 2. Status probe | Round-trips a maintenance `Status` RPC to confirm reachability | `EtcdCoordinatorError::Etcd { Status }` |

On success the caller holds a validated config, a live etcd connection, and
a `EtcdKeyspace` for deterministic key generation. `EtcdCoordinator::connect()`
asserts that no Tokio runtime is already active (nested `block_on` panics).
`AsyncEtcdCoordinator::connect()` requires an existing async context.

### Sync-async bridge

The sync coordination traits (`CoordinationBackend`, `RunManagement`) are
synchronous. The etcd client is async (tonic/gRPC). `EtcdCoordinator` bridges
the gap with a private current-thread Tokio runtime via `block_on()`. An
assertion guard prevents calling trait methods from within an active Tokio
async context (nested `block_on` panics).

`AsyncEtcdCoordinator` bypasses this bridge entirely — its methods are native
`async fn` and callers provide their own runtime.

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
    SIM["Simulated { operation, source }<br/>Feature-gated simulated etcd failures"]
    KSE["Keyspace(EtcdKeyspaceError)<br/>Namespace prefix validation"]

    OP_CONNECT["EtcdOperation::Connect"]
    OP_STATUS["EtcdOperation::Status"]
    OP_GET["EtcdOperation::Get"]
    OP_PUT["EtcdOperation::Put"]
    OP_DELETE["EtcdOperation::Delete"]
    OP_TXN["EtcdOperation::Txn"]
    OP_LEASE_GRANT["EtcdOperation::LeaseGrant"]
    OP_LEASE_KEEP_ALIVE["EtcdOperation::LeaseKeepAlive"]
    OP_LEASE_REVOKE["EtcdOperation::LeaseRevoke"]

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
    ECE --> SIM
    ECE --> KSE

    ETCD --> OP_CONNECT
    ETCD --> OP_STATUS
    ETCD --> OP_GET
    ETCD --> OP_PUT
    ETCD --> OP_DELETE
    ETCD --> OP_TXN
    ETCD --> OP_LEASE_GRANT
    ETCD --> OP_LEASE_KEEP_ALIVE
    ETCD --> OP_LEASE_REVOKE

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
    style SIM fill:#F3F4F6,stroke:#374151,color:#374151
    style KSE fill:#DCFCE7,stroke:#166534,color:#166534

    style OP_CONNECT fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_STATUS fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_GET fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_PUT fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_DELETE fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_TXN fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_LEASE_GRANT fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_LEASE_KEEP_ALIVE fill:#F3F4F6,stroke:#374151,color:#374151
    style OP_LEASE_REVOKE fill:#F3F4F6,stroke:#374151,color:#374151

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
backends. The sync traits define the traditional surface; the async traits
provide the same semantics for I/O-bound contexts:

```mermaid
%% Diagram: etcd-trait-integration
graph TB
    subgraph sync_traits ["Sync Coordination Traits"]
        direction TB
        CB_TRAIT["CoordinationBackend<br/>7 shard lifecycle methods:<br/>acquire_and_restore_into, renew, checkpoint,<br/>complete, park_shard, split_replace,<br/>split_residual"]
        RM_TRAIT["RunManagement<br/>11 run/admin methods:<br/>create_run, register_shards,<br/>create_run_with_shards, get_run,<br/>get_run_progress, list_shards_into,<br/>collect_claim_candidates_into,<br/>complete_run, fail_run, cancel_run,<br/>unpark_shard"]
        SC_TRAIT["ShardClaiming<br/>1 method:<br/>claim_next_available"]
    end

    subgraph async_traits ["Async Coordination Traits"]
        direction TB
        ACB_TRAIT["AsyncCoordinationBackend<br/>7 async fn shard lifecycle methods<br/>(same semantics as sync)"]
        ARM_TRAIT["AsyncRunManagement<br/>11 async fn run/admin methods<br/>(same semantics as sync)"]
    end

    subgraph backends ["Coordination Backends"]
        INMEM_BACK["InMemoryCoordinator<br/>(reference implementation)"]
        ETCD_BACK["EtcdCoordinator<br/>(sync wrapper, block_on bridge)"]
        ASYNC_ETCD_BACK["AsyncEtcdCoordinator<br/>(async core, native futures)"]
    end

    subgraph etcd_modules ["Shared etcd Modules"]
        MOD_CONFIG["config.rs<br/>Endpoint + prefix validation<br/>Credential redaction"]
        MOD_KS["keyspace.rs<br/>Deterministic key paths<br/>Buffer-reuse API"]
        MOD_CODEC["codec.rs<br/>Binary encode/decode<br/>Staged slab rollback"]
        MOD_ERR["error.rs<br/>Error hierarchy<br/>Operation labels"]
        MOD_BACK["backend/<br/>coordinator.rs + run_management.rs +<br/>shard_coordination.rs"]
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

    ASYNC_ETCD_BACK -.->|"implements"| ACB_TRAIT
    ASYNC_ETCD_BACK -.->|"implements"| ARM_TRAIT

    ETCD_BACK --> MOD_CONFIG
    ETCD_BACK --> MOD_BACK
    ASYNC_ETCD_BACK --> MOD_CONFIG
    ASYNC_ETCD_BACK --> MOD_BACK

    MOD_BACK --> MOD_KS
    MOD_BACK --> MOD_CODEC
    MOD_BACK --> MOD_ERR

    style CB_TRAIT fill:#22C55E,stroke:#166534,color:#FFF
    style RM_TRAIT fill:#22C55E,stroke:#166534,color:#FFF
    style SC_TRAIT fill:#22C55E,stroke:#166534,color:#FFF
    style ACB_TRAIT fill:#22C55E,stroke:#166534,color:#FFF
    style ARM_TRAIT fill:#22C55E,stroke:#166534,color:#FFF

    style INMEM_BACK fill:#DCFCE7,stroke:#166534,color:#166534
    style ETCD_BACK fill:#22C55E,stroke:#166534,color:#FFF
    style ASYNC_ETCD_BACK fill:#22C55E,stroke:#166534,color:#FFF

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
| `backend/` | Complete | `coordinator.rs` owns the entrypoints, etcd RPC wrappers, and CAS retry helpers; `run_management.rs` and `shard_coordination.rs` implement the full sync and async run/shard lifecycle, including `complete` and `park_shard` |

The keyspace and codec are shared infrastructure used by the CAS transaction
logic in `backend/`. The durable path no longer delegates through an
`InMemoryCoordinator`; both `EtcdCoordinator` and `AsyncEtcdCoordinator`
persist coordination state directly in etcd and share the same validation and
transaction shapes across the sync and async entrypoints.

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
| `crates/gossip-coordination-etcd/src/backend.rs` | Module root for the `backend/` tree; shared free functions and backend-wide helpers |
| `crates/gossip-coordination-etcd/src/backend/coordinator.rs` | `EtcdCoordinator` (sync wrapper) and `AsyncEtcdCoordinator` (async core), sync-async bridge, low-level etcd RPC wrappers, CAS retry loop |
| `crates/gossip-coordination-etcd/src/backend/run_management.rs` | Sync and async `RunManagement` implementations: run lifecycle, claim candidate collection, and `unpark_shard` |
| `crates/gossip-coordination-etcd/src/backend/shard_coordination.rs` | Sync and async `CoordinationBackend` implementations: `acquire_and_restore_into`, `renew`, `checkpoint`, `complete`, `park_shard`, `split_replace`, and `split_residual` |
| `crates/gossip-coordination-etcd/src/backend/test_support.rs` | Feature-gated seeding, inspection, snapshot, and deterministic split fault-injection helpers |
| `crates/gossip-coordination-etcd/src/behavioral_conformance.rs` | Real-etcd behavioral conformance scenarios that mirror the shared coordination harness using protocol operations plus persisted read-back oracles |
| `crates/gossip-coordination-etcd/src/keyspace.rs` | `EtcdKeyspace` deterministic key-path construction |
| `crates/gossip-coordination-etcd/src/codec.rs` | Binary encode/decode for `RunRecord` and `ShardRecord` |
| `crates/gossip-coordination-etcd/src/config.rs` | `EtcdCoordinatorConfig` validated connection parameters |
| `crates/gossip-coordination-etcd/src/error.rs` | `EtcdCoordinatorError` and `EtcdOperation` |
| `crates/gossip-coordination-etcd/src/sim_coordinator.rs` | Feature-gated deterministic simulation adapter that runs the sync etcd backend over the in-memory KV model |
| `crates/gossip-coordination-etcd/src/sim_etcd_kv.rs` | Feature-gated in-memory model of the etcd KV subset used for deterministic simulation |
| `crates/gossip-coordination-etcd/src/test_support.rs` | Testcontainers-backed lifecycle helpers plus namespace-isolated coordinator builders for integration tests |
| `crates/gossip-coordination-etcd/src/tests.rs` | Config, keyspace, property tests, integration test |
| `crates/gossip-coordination-etcd/src/codec_tests.rs` | Codec round-trip and error-case tests |
| `crates/gossip-coordination-etcd/fuzz/fuzz_targets/` | 4 libfuzzer targets for decode/round-trip |
| `crates/gossip-coordination/src/traits.rs` | `CoordinationBackend`, `AsyncCoordinationBackend`, `RunManagement`, `AsyncRunManagement`, `ShardClaiming` trait definitions |
| `crates/gossip-coordination/src/in_memory.rs` | `InMemoryCoordinator` reference implementation |
