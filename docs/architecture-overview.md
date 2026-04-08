# Architecture Overview

High-level C4-style component diagram showing the gossip-rs secret scanning engine architecture.

```mermaid
graph TB
    subgraph CLI["CLI Layer"]
        Main["main.rs<br/>Entry Point"]
        Orch["gossip-scanner-runtime::scan_fs / scan_git<br/>Source Dispatcher"]
    end

    subgraph Core["Core Engine"]
        Engine["Engine<br/>Pattern Matching"]
        Rules["RuleSpec / RuleCompiled(hot) / RuleCold<br/>Detection Rules"]
        VS["Vectorscan<br/>Anchor Prefilter"]
        Transforms["TransformConfig<br/>URL/Base64 Decoding"]
        Tuning["Tuning<br/>DoS Protection"]
    end

    subgraph FsPath["Filesystem Scan Path"]
        PScan["parallel_scan_dir()<br/>High-level FS entry"]
        Walker["IterWalker<br/>File Discovery"]
        Scanner["scan_local()<br/>Owner-Compute Scan"]
        Events["EventOutput<br/>JSONL/Text/JSON/SARIF"]
        StoreProd["StoreProducer<br/>FS Persistence"]
    end

    subgraph GitPath["Git Scan Path"]
        GitRunner["run_git_scan()<br/>Git Pipeline Runner"]
    end

    subgraph Memory["Memory Management"]
        TsBufferPool["TsBufferPool<br/>Scheduler Buffer Pool"]
        BufferPool["BufferPool<br/>Runtime Buffer Pool"]
        NodePool["NodePoolType<br/>Pre-allocated Buffers"]
        DecodeSlab["DecodeSlab<br/>Decoded Output Storage"]
    end

    subgraph DataStructures["Data Structures"]
        RingBuffer["RingBuffer<br/>SPSC Queues"]
        BitSet["BitSet / DynamicBitSet<br/>Pool Tracking"]
        FileTable["FileTable<br/>Columnar Metadata"]
    end

    subgraph State["Per-Chunk State"]
        ScanScratch["ScanScratch<br/>Reusable Scratch Buffers"]
        StepArena["StepArena<br/>Decode Provenance"]
        FixedSet128["FixedSet128<br/>Deduplication"]
        TimingWheel["TimingWheel&lt;PendingWindow, 1&gt;<br/>Window Expiration Scheduler"]
    end

    Main --> Orch

    Orch --> |"scan fs"| PScan
    Orch --> |"scan git"| GitRunner

    PScan --> Walker
    PScan --> Scanner
    Walker --> Scanner
    Scanner --> Events
    Scanner --> StoreProd

    Scanner --> Engine
    Scanner --> TsBufferPool
    GitRunner --> Engine
    GitRunner --> Events

    Engine --> Rules
    Engine --> VS
    Engine --> Transforms
    Engine --> Tuning

    BufferPool --> FileTable
    BufferPool --> NodePool
    NodePool --> BitSet

    Scanner --> ScanScratch
    ScanScratch --> DecodeSlab
    ScanScratch --> StepArena
    ScanScratch --> FixedSet128
    ScanScratch --> TimingWheel

    RingBuffer --> |"Shared utility<br/>queue type"| FsPath

    style CLI fill:#e1f5fe
    style Core fill:#fff3e0
    style FsPath fill:#e8f5e9
    style GitPath fill:#ede7f6
    style Memory fill:#fce4ec
    style DataStructures fill:#f3e5f5
    style State fill:#fff8e1
```

## Component Descriptions

| Component                      | Location                                                                                 | Purpose                                                                                                         |
| ------------------------------ | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **CLI Layer**                  | `crates/scanner-rs-cli/src/main.rs`                                                      | Entry point that delegates to scan routing                                                                      |
| **Scan Dispatcher**            | `crates/gossip-scanner-runtime/src/lib.rs`                                               | Public `scan_fs()` / `scan_git()` entrypoints that validate requests and dispatch into the runtime family modules |
| **Events**                     | `crates/scanner-scheduler/src/events.rs`                                                 | Structured `CoreEvent` model and JSONL sink                                                                     |
| **parallel_scan_dir**          | `crates/scanner-scheduler/src/scheduler/parallel_scan.rs`                                | High-level FS scan entrypoint (walker + scheduler wiring)                                                       |
| **FS Owner-Compute Scheduler** | `crates/scanner-scheduler/src/scheduler/local_fs_owner.rs`                               | Round-robin file dispatch with per-worker owned I/O+scan state                                                  |
| **Engine**                     | `crates/scanner-engine/src/engine/core.rs`                                               | Compiled scanning engine with anchor patterns, rules, and transforms                                            |
| **RuleSpec**                   | `crates/scanner-engine/src/api.rs`                                                       | Rule definitions and specification for rule-based scanning                                                      |
| **RuleCompiled**               | `crates/scanner-engine/src/engine/rule_repr.rs`                                          | Hot compiled rule representation used in scan-loop validation                                                   |
| **RuleCold**                   | `crates/scanner-engine/src/engine/rule_repr.rs`                                          | Cold per-rule metadata (`name`, `min_confidence`) stored parallel to hot rules                                  |
| **Vectorscan**                 | `vectorscan-rs-sys` crate                                                                | Multi-pattern anchor prefilter (raw + UTF-16 variants)                                                          |
| **Vectorscan DB Cache**        | `crates/scanner-engine/src/engine/vs_cache.rs`                                           | Best-effort on-disk cache for serialized prefilter/stream DBs                                                   |
| **TransformConfig**            | `crates/scanner-engine/src/api.rs`                                                       | Transform stage configuration (URL percent, Base64)                                                             |
| **Pipeline Config/Stats**      | `crates/scanner-scheduler/src/pipeline.rs`                                               | Shared pipeline constants and reporting types used by runtime paths                                             |
| **Archive Core**               | `crates/scanner-scheduler/src/archive/` (`scan.rs`, `budget.rs`, `path.rs`, `formats/*`) | Archive scanning config, budgets, outcomes, path canonicalization, and sink-driven scan core                    |
| **IterWalker**                 | `crates/scanner-scheduler/src/scheduler/parallel_scan.rs`                                | Recursive file traversal with gitignore/hidden-file controls                                                    |
| **scan_local**                 | `crates/scanner-scheduler/src/scheduler/local_fs_owner.rs`                               | Worker-owned I/O + scanning with overlap dedupe                                                                 |
| **EventOutput**                | `crates/scanner-scheduler/src/events.rs`                                                 | Thread-safe structured event emission to stdout sinks                                                           |
| **BufferPool**                 | `crates/scanner-scheduler/src/runtime.rs`                                                | Fixed-capacity aligned buffer pool (single-threaded runtime path)                                               |
| **TsBufferPool**               | `crates/scanner-scheduler/src/scheduler/ts_buffer_pool.rs`                               | Thread-safe buffer pool used by scheduler workers                                                               |
| **Global Resource Pool**       | `crates/scanner-scheduler/src/scheduler/global_resource_pool.rs`                         | Global resource management for fat jobs                                                                         |
| **NodePoolType**               | `crates/scanner-engine/src/pool/node_pool.rs`                                            | Generic pre-allocated node pool                                                                                 |
| **RingBuffer**                 | `crates/gossip-stdx/src/ring_buffer.rs`                                                  | Fixed-capacity SPSC queue                                                                                       |
| **DynamicBitSet**              | `crates/gossip-stdx/src/bitset.rs`                                                       | Runtime-sized bitset for pool tracking                                                                          |
| **ScanScratch**                | `crates/scanner-engine/src/engine/scratch.rs`                                            | Per-scan reusable scratch state                                                                                 |
| **TimingWheel**                | `crates/gossip-stdx/src/timing_wheel.rs`                                                 | Hashed timing wheel for window expiration scheduling                                                            |
| **Git Preflight**              | `crates/scanner-git/src/preflight.rs`                                                    | Maintenance readiness check for commit-graph, MIDX, and pack count                                              |
| **ArtifactStatus**             | `crates/scanner-git/src/preflight.rs`                                                    | `Ready` vs `NeedsMaintenance` flag produced by Git preflight                                                    |
| **Repo Open**                  | `crates/scanner-git/src/repo_open.rs`                                                    | Repo discovery, object format detection, start set resolution, watermark load                                   |
| **RepoJobState**               | `crates/scanner-git/src/repo_open.rs`                                                    | Bundled repo metadata for downstream Git scan phases                                                            |
| **StartSetId**                 | `crates/scanner-git/src/start_set.rs`                                                    | Deterministic identity for start set configuration                                                              |
| **Watermark Keys**             | `crates/scanner-git/src/watermark_keys.rs`                                               | Stable ref watermark key/value encoding                                                                         |
| **CommitGraph trait**          | `crates/scanner-git/src/commit_walk.rs`                                                  | Deterministic commit graph interface used by traversal/topo planning                                            |
| **CommitGraphMem**             | `crates/scanner-git/src/commit_graph_mem.rs`                                             | In-memory commit graph built from loaded commits                                                                |
| **Commit Graph Index**         | `crates/scanner-git/src/commit_graph.rs`                                                 | Cache-friendly SoA tables for commit OIDs, root trees, and timestamps                                           |
| **Commit Walk**                | `crates/scanner-git/src/commit_walk.rs`                                                  | `(watermark, tip]` traversal for introduced-by commit selection                                                 |
| **Commit Walk Limits**         | `crates/scanner-git/src/commit_walk_limits.rs`                                           | Hard caps for commit traversal and ordering                                                                     |
| **Snapshot Plan**              | `crates/scanner-git/src/snapshot_plan.rs`                                                | Snapshot-mode commit selection (tips only)                                                                      |
| **Tree Object Store**          | `crates/scanner-git/src/object_store.rs`                                                 | Pack/loose tree loading for OID-only tree diffs                                                                 |
| **CacheCommon**                | `crates/scanner-git/src/cache_common.rs`                                                 | Generic set-associative cache framework with CLOCK eviction                                                     |
| **Tree Delta Cache**           | `crates/scanner-git/src/tree_delta_cache.rs`                                             | Set-associative cache for tree delta bases keyed by pack offset                                                 |
| **Tree Spill Arena**           | `crates/scanner-git/src/spill_arena.rs`                                                  | Preallocated mmapped file for large tree payload spill                                                          |
| **Tree Spill Index**           | `crates/scanner-git/src/object_store.rs`                                                 | Fixed-size OID index for reusing spilled tree payloads                                                          |
| **MIDX Mapping**               | `crates/scanner-git/src/midx.rs`, `crates/scanner-git/src/mapping_bridge.rs`             | MIDX parsing and blob-to-pack mapping                                                                           |
| **Tree Diff Walker**           | `crates/scanner-git/src/tree_diff.rs`                                                    | OID-only tree diffs that emit candidate blobs with context                                                      |
| **Blob Introducer**            | `crates/scanner-git/src/blob_introducer.rs`                                              | First-introduced blob walk for ODB-blob scan mode; supports parallel mode via `introduce_parallel`              |
| **BlobIntroWorker**            | `crates/scanner-git/src/blob_introducer.rs`                                              | Per-thread worker for parallel blob introduction with own `ObjectStore` and `PackCandidateCollector`            |
| **AtomicSeenSets**             | `crates/gossip-stdx/src/atomic_seen_sets.rs`                                             | Lock-free bitmap triple (trees, blobs, blobs_excluded) sized to MIDX object count for parallel dedup            |
| **Pack Candidate Collector**   | `crates/scanner-git/src/pack_candidates.rs`                                              | Direct blob-to-pack/loose candidate mapping for ODB-blob mode                                                   |
| **Tree Stream Parser**         | `crates/scanner-git/src/tree_stream.rs`                                                  | Streaming tree entry parser with bounded buffer                                                                 |
| **Pack Executor**              | `crates/scanner-git/src/pack_exec.rs`                                                    | Executes pack plans to decode candidate blobs with bounded buffers                                              |
| **Blob Spill**                 | `crates/scanner-git/src/blob_spill.rs`                                                   | Spill-backed mmaps for oversized blob payloads during pack exec                                                 |
| **Engine Adapter**             | `crates/scanner-git/src/engine_adapter.rs`                                               | Streams decoded blob bytes into the engine with overlap chunking                                                |
| **Pack I/O**                   | `crates/scanner-git/src/pack_io.rs`                                                      | MIDX-backed pack mmap loader for cross-pack REF delta bases                                                     |
| **Path Policy**                | `crates/scanner-git/src/path_policy.rs`                                                  | Fast path classification for candidate flags                                                                    |
| **Spill Limits**               | `crates/scanner-git/src/spill_limits.rs`                                                 | Hard caps for spill chunk sizing and on-disk run growth                                                         |
| **CandidateChunk**             | `crates/scanner-git/src/spill_chunk.rs`                                                  | Bounded candidate buffer + path arena with in-chunk dedupe                                                      |
| **Spill Runs**                 | `crates/scanner-git/src/run_writer.rs`, `crates/scanner-git/src/run_reader.rs`           | Stable on-disk encoding for sorted candidate runs                                                               |
| **Run Merger**                 | `crates/scanner-git/src/spill_merge.rs`                                                  | K-way merge of spill runs with canonical dedupe                                                                 |
| **Spiller**                    | `crates/scanner-git/src/spiller.rs`                                                      | Orchestrates chunking, spilling, and global merge                                                               |
| **Seen Blob Store**            | `crates/scanner-git/src/seen_store.rs`                                                   | Batched seen-blob checks for filtering already scanned blobs                                                    |
| **Finalize Builder**           | `crates/scanner-git/src/finalize.rs`                                                     | Builds stably ordered blob_ctx/finding/seen_blob + ref_watermark ops                                            |
| **Persistence Store**          | `crates/scanner-git/src/persist.rs`                                                      | Two-phase persistence contract for data ops then watermarks                                                     |
| **RocksDB Store**              | `crates/scanner-git/src/persist_rocksdb.rs`                                              | RocksDB adapter for persistence, seen-blob checks, and watermarks                                               |
| **Git Scan Runner**            | `crates/scanner-git/src/runner.rs`                                                       | End-to-end orchestration across all Git scan stages                                                             |
| **WorkItems**                  | `crates/scanner-git/src/work_items.rs`                                                   | SoA candidate metadata tables for sorting without moving structs                                                |
| **Policy Hash**                | `crates/scanner-git/src/policy_hash.rs`                                                  | Canonical BLAKE3 identity over rules, transforms, and tuning                                                    |
| **Store**                      | `crates/scanner-scheduler/src/store.rs`                                                  | `StoreProducer` trait, finding/batch/loss types, and built-in producer impls                                    |

## Distributed Coordination Layer

The architecture includes a full distributed coordination stack for shard-based
scanning. These crates are layered so that shared data-model types sit at the
leaf and runtime/binary crates depend inward. The distributed worker loop in
`gossip-scanner-runtime` now depends directly on `gossip-coordination` and
`gossip-frontier`; there is no intermediate bridge crate between claiming a
lease and executing a shard.

```text
gossip-contracts  (data model leaf -- identity, shard spec, connector types)
    │
    ├──► gossip-frontier       (shard algebra -- key encoding, range arithmetic, builder)
    ├──► gossip-coordination   (protocol -- state machine, lease/fence, in-memory backend)
    ├──► gossip-connectors     (source impls -- filesystem, git, in-memory connectors)
    └──► gossip-scanner-runtime  (family-oriented runtime -- scan_fs / scan_git dispatchers)
              │
              └──► gossip-worker  (binary -- CLI entry, tracing, exit codes)
```

| Component                          | Location                                                                  | Purpose                                                                                                    |
| ---------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **gossip-contracts**               | `crates/gossip-contracts/src/`                                            | Shared contract types: identity spine (BLAKE3 derivation chain), shard data model, connector boundary types |
| **Identity Module**                | `crates/gossip-contracts/src/identity/`                                   | `TenantId`, `WorkerId`, `ShardId`, `RunId`, `OpId`, `FenceEpoch`, `LogicalTime`, `JobId`, `ShardKey`, `SecretHash`, `FindingId`, `OccurrenceId`, `ObservationId`, `StableItemId`, `ObjectVersionId`, domain separation registry |
| **Coordination Contracts**         | `crates/gossip-contracts/src/coordination/`                               | `ShardSpec`, `Cursor`, `CursorSemantics`, `PooledShardSpec`, `PooledCursor`, capacity limits, manifest     |
| **Connector Contracts**            | `crates/gossip-contracts/src/connector/`                                  | `ConnectorCapabilities`, `ErrorClass`, `EnumerateError`, `ReadError`, `ItemKey`, `ScanItem`, `Budgets`                           |
| **gossip-frontier**                | `crates/gossip-frontier/src/`                                             | Shard algebra: byte-order-preserving key encoding, range arithmetic, hint metadata, `PreallocShardBuilder`  |
| **gossip-coordination**            | `crates/gossip-coordination/src/`                                         | Coordination protocol: `CoordinationBackend` trait (7 operations), `InMemoryCoordinator`, `WorkerSession`  |
| **CoordinationBackend**            | `crates/gossip-coordination/src/traits.rs`                                | Trait defining `acquire_and_restore_into`, `renew`, `checkpoint`, `complete`, `park_shard`, `split_replace`, `split_residual` |
| **InMemoryCoordinator**            | `crates/gossip-coordination/src/in_memory.rs`                             | Reference backend implementation (executable spec for testing and simulation)                               |
| **gossip-connectors**              | `crates/gossip-connectors/src/`                                           | Concrete connector implementations: `FilesystemConnector`, `InMemoryDeterministicConnector` |
| **gossip-scanner-runtime**         | `crates/gossip-scanner-runtime/src/lib.rs`                                | Family-oriented runtime: `scan_fs()`, `scan_git()` entry points; `ExecutionMode` (Direct/Connector) routing |
| **Distributed Runtime Surface**    | `crates/gossip-scanner-runtime/src/distributed.rs`                        | `WorkerIdentity`, concrete `ShardLease`, `DistributedPersistence<F, D>`, `DistributedRuntimeConfig`, `DistributedRunReport`, `DistributedRuntimeError`, `run_worker` |
| **gossip-worker**                  | `crates/gossip-worker/src/main.rs`                                        | Binary: CLI arg parsing, tracing init, dispatches to `scan_fs`/`scan_git` via runtime                      |


## Archive Scanning Notes

- Nested archive expansion is streaming-only and bounded by `ArchiveConfig::max_archive_depth`.
- Policy enforcement is deterministic: `FailArchive` stops the current container, `FailRun` aborts the scan.
- Archive entries use virtual `FileId` values (high-bit namespace) to isolate per-file engine state.
- Archive parsing and expansion are centralized in `crates/scanner-scheduler/src/archive/scan.rs` and delegated to a sink (`ArchiveEntrySink`) for entry scanning.
- Depth-budget enforcement and decompression-ratio guards live alongside the archive
  scanning implementation in `crates/scanner-scheduler/src/archive/`.

## Git Repo Open

Repo open resolves the repository layout, detects object format, and records
artifact paths (commit-graph, MIDX) for lock-file detection. It does not mmap
or parse disk-based artifacts; those are built in memory by `artifact_acquire`.
It also resolves the start set refs (via `StartSetResolver`) and loads per-ref
watermarks from `RefWatermarkStore` using the `StartSetId` and policy hash.
The resulting `RepoJobState` is the metadata contract for later Git phases.

## Git Commit Selection

Commit selection uses the commit-graph for deterministic `(watermark, tip]`
traversal in introduced-by mode and emits snapshot tips directly in snapshot
mode. Introduced-by plans are reordered topologically so ancestors appear
before descendants, ensuring first-introduction semantics across merges.

## Git Tree Diff

Tree diffing loads tree objects from the object store and walks them in Git tree
order to emit blob candidates with commit/parent context and path classification.
The walker skips unchanged subtrees, never reads blobs during diffing, and
preserves deterministic candidate ordering for downstream spill/dedupe. Outputs
flow through the `CandidateSink` interface so callers can stream directly into
spill/dedupe; `CandidateBuffer` remains as a buffered fallback for tests and
diagnostics.

The tree object store can spill large tree payloads into a preallocated,
memory-mapped spill arena. Spilled trees are indexed by OID for reuse and do not
count against the in-flight RAM budget.

To reduce repeated base inflations, the object store also maintains a fixed-size
tree delta cache keyed by `(pack_id, offset)`. Delta bases are stored in
fixed-size slots with CLOCK eviction so OFS/REF delta chains can reuse bases
without re-inflating the same pack entry.

For large or spill-backed trees, the walker switches to a streaming parser that
keeps only a bounded buffer of tree bytes in RAM while iterating entries.

## Git Scan Modes

**Diff-history mode** uses tree diffs across the commit plan to emit
candidate blobs with per-commit context. This path feeds the spill/dedupe and
mapping stages before pack planning and execution.

**ODB-blob mode** replaces per-commit diffs with a single pass that discovers
each unique blob once and then scans blobs in pack-offset order. In serial
introduction, attribution uses introducing-commit traversal context. In parallel
introduction (`blob_intro_workers > 1`), the blob set is unchanged but selected
`(commit_id, path, flags)` context is race-winner based and not deterministic
across worker counts. It reuses the same pack decode and engine adapter stages
but eliminates redundant tree diff work.

## Git Blob Introducer (ODB-blob mode)

The blob introducer walks commits in topological order and traverses trees
to discover each blob exactly once. It uses `CommitGraphIndex` for cache-friendly
root tree and commit metadata lookups, plus two seen-set bitmaps keyed by
MIDX index (trees + blobs) so repeated subtrees are skipped without parsing.
Loose blobs missing from the MIDX are deduped in fixed-capacity open-addressing
sets. Paths are assembled in a reusable buffer and classified via `PathClass`
to set candidate flags. Excluded paths are tracked separately so a blob can
still be emitted when it later appears under a non-excluded path. The
introducer emits candidates with `ChangeKind::Add`. Serial mode uses
introducing-commit attribution; parallel mode uses the context from whichever
worker first claims the blob/tree in shared seen sets.

## Pack Candidate Collector (ODB-blob mode)

The pack candidate collector receives blob introductions and maps each blob
OID directly to a pack id and offset via the MIDX. Paths are interned into a
local `ByteArena` so downstream pack execution can hold stable `ByteRef`s
without re-interning. Blobs missing from the MIDX are emitted as loose
candidates for `PackIo::load_loose_object`.

## Git Spill + Dedupe

Spill + dedupe buffers candidates in `CandidateChunk` until limits are reached,
then sorts and dedupes within the chunk before writing a spill run (`RunWriter`).
`Spiller` tracks spill run counts and bytes, and `RunMerger` performs a k-way
merge across runs to emit globally sorted, unique candidates. `WorkItems` stores
candidate metadata in SoA form so downstream sorting can shuffle indices without
moving large structs.

Spill chunks now reduce to a single canonical record per OID before writing
runs to disk, shrinking spill bytes without changing canonical context rules.

After global dedupe, sorted OID batches are sent to the seen-blob store so
previously scanned blobs can be filtered before decoding.

Mapping re-interns candidate paths into a shared arena that is kept alive
through pack execution and finalize; scan results retain those path refs to
avoid re-interning in the engine adapter.

## Pack Execution + Cache

Pack execution inflates and applies deltas for packed objects, emitting blob
payloads to the engine adapter. A tiered pack cache keeps decoded bases hot:
Tier A stores <=64 KiB objects, Tier B stores <=2 MiB objects. Both tiers
use fixed-size slots with CLOCK eviction and preallocated storage, so hot-path
lookups and inserts stay allocation-free and deterministic.

Oversized pack objects use a spill-backed mmap path: when the inflated payload
exceeds `PackDecodeLimits.max_object_bytes`, pack exec inflates into a
temporary spill file under the run `spill_dir` and scans from the mmap instead
of holding the bytes in RAM. Delta outputs can spill the same way, keeping the
RAM budget fixed even for very large blobs.

Parallel pack execution shards each pack plan into contiguous offset ranges.
Each worker owns its own pack cache and scratch state; cross-shard delta bases
are resolved via on-demand decode rather than shared caches. Results are merged
in shard order to preserve deterministic output.

## Git Finalize + Persist

Finalize converts scanned blob results into stably ordered write ops for
blob_ctx, finding, and seen_blob namespaces plus ref watermark updates.
Persistence writes data ops first, then advances ref watermarks only for
complete runs to avoid skipping unscanned blobs.

## Git Policy Hash

The policy hash is a canonical BLAKE3 identity over:
- Rule specs (canonicalized and order-invariant)
- Transform configs (order-preserving)
- Tuning parameters
- Merge diff mode
- Path policy version

## Testing Harnesses

The optional simulation harnesses provide deterministic simulation primitives and replayable traces
for both scanner and scheduler testing. See `docs/scanner-scheduler/scanner_test_harness_guide.md` and
`docs/scanner-scheduler/scheduler_test_harness_guide.md` for the full design and workflow.

### Scanner Simulation Harness (`sim-harness` feature)

Scanner harness code lives in `crates/scanner-scheduler/src/sim_scanner/` with shared primitives in `crates/scanner-scheduler/src/sim/`.

| Component             | Location                                                                               | Purpose                                                                |
| --------------------- | -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **SimExecutor**       | `crates/scanner-scheduler/src/sim/executor.rs`                                         | Deterministic single-thread work-stealing model for simulation         |
| **SimFs**             | `crates/scanner-scheduler/src/sim/fs.rs`                                               | Deterministic in-memory filesystem used by scenarios                   |
| **ScenarioGenerator** | `crates/scanner-scheduler/src/sim_scanner/generator.rs`                                | Synthetic scenario builder with expected-secret ground truth           |
| **SimArchive**        | `crates/scanner-scheduler/src/sim_archive/`                                            | Deterministic archive builders + virtual path materialization for sims |
| **Scanner Oracles**   | `crates/scanner-scheduler/src/sim_scanner/runner.rs`                                   | Ground-truth and differential checks for scanner simulations           |
| **SimRng / SimClock** | `crates/scanner-scheduler/src/sim/rng.rs`, `crates/scanner-scheduler/src/sim/clock.rs` | Stable RNG and simulated time source                                   |
| **TraceRing**         | `crates/scanner-scheduler/src/sim/trace.rs`                                            | Bounded trace buffer for replay and debugging                          |
| **Minimizer**         | `crates/scanner-scheduler/src/sim/minimize.rs`                                         | Deterministic shrink passes for failing scanner artifacts              |

### Git Simulation Harness (`sim-harness` feature)

Git simulation harness code lives in `crates/scanner-git/src/sim_git_scan/` with shared primitives in `crates/scanner-scheduler/src/sim/`.

| Component                  | Location                                              | Purpose                                                            |
| -------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------ |
| **Git Scenario Schema**    | `crates/scanner-git/src/sim_git_scan/scenario.rs`     | Repo model + artifact bytes schema for deterministic Git scenarios |
| **Git Scenario Generator** | `crates/scanner-git/src/sim_git_scan/generator.rs`    | Synthetic Git repo generator for bounded random tests              |
| **Git Runner**             | `crates/scanner-git/src/sim_git_scan/runner.rs`       | Deterministic stage runner and failure taxonomy                    |
| **Git Trace Ring**         | `crates/scanner-git/src/sim_git_scan/trace.rs`        | Bounded trace buffer for Git simulation replay                     |
| **Git Artifact Schema**    | `crates/scanner-git/src/sim_git_scan/artifact.rs`     | Reproducible artifact format for Git sim failures                  |
| **Git Fault Plan**         | `crates/scanner-git/src/sim_git_scan/fault.rs`        | Deterministic fault injection plan keyed by logical Git resources  |
| **Git Replay**             | `crates/scanner-git/src/sim_git_scan/replay.rs`       | Load + replay `.case.json` artifacts deterministically             |
| **Git Minimizer**          | `crates/scanner-git/src/sim_git_scan/minimize.rs`     | Deterministic shrink passes for failing Git artifacts              |
| **Git Persist Store**      | `crates/scanner-git/src/sim_git_scan/persist.rs`      | Two-phase persistence simulation with fault injection              |
| **Sim Commit Graph**       | `crates/scanner-git/src/sim_git_scan/commit_graph.rs` | In-memory commit-graph adapter for deterministic commit walks      |
| **Sim Start Set**          | `crates/scanner-git/src/sim_git_scan/start_set.rs`    | Start set + watermark adapters for simulated refs                  |
| **Sim Tree Source**        | `crates/scanner-git/src/sim_git_scan/tree_source.rs`  | Tree-source adapter that encodes semantic trees into raw bytes     |
| **Sim Pack Bytes**         | `crates/scanner-git/src/sim_git_scan/pack_bytes.rs`   | In-memory pack bytes and pack-view adapter                         |
| **Sim Pack I/O**           | `crates/scanner-git/src/sim_git_scan/pack_io.rs`      | External base resolver over in-memory pack bytes                   |
| **SimExecutor**            | `crates/scanner-scheduler/src/sim/executor.rs`        | Shared deterministic executor used for schedule control            |


### Scheduler Simulation Harness (`scheduler-sim` feature)

Scheduler harness code lives in `crates/scanner-scheduler/src/scheduler/sim_executor_harness.rs`.

| Component                   | Location                                                         | Purpose                                                             |
| --------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Scheduler Sim Harness**   | `crates/scanner-scheduler/src/scheduler/sim_executor_harness.rs` | Deterministic executor model for scheduler interleaving tests       |
| **Scheduler Sim Task VM**   | `crates/scanner-scheduler/src/scheduler/sim_executor_harness.rs` | Bytecode VM driving scheduler-only task effects in simulation       |
| **Scheduler Sim Resources** | `crates/scanner-scheduler/src/scheduler/sim_executor_harness.rs` | Deterministic resource accounting for permits/budgets in simulation |

## Data Flow

1. **Input**: CLI parses `scan fs`/`scan git` and builds unified config
2. **Dispatch**: Unified orchestrator routes to `parallel_scan_dir` or `run_git_scan`
3. **FS Discovery**: `IterWalker` discovers files and `scan_local` assigns work to workers
4. **Scanning**: Workers read overlap-aware chunks, run `Engine`, dedupe overlap findings, and apply cross-rule winner selection (keeping the highest-confidence rule per location)
5. **Output**: Findings stream through `EventOutput` implementations to stdout
6. **Persistence**: When enabled (`--persist-findings`), post-dedupe findings are emitted
   to a `StoreProducer` backend (default: SQLite star-schema with WAL mode);
   run-level loss accounting is recorded at scan end
7. **Memory**: Scheduler/runtime buffer pools and engine scratch structures are reused per run

## Design Principles

- **Anchor-first**: anchors keep regex work bounded to likely windows.
- **Deterministic memory**: fixed-capacity pools and rings make memory usage
  explicit and predictable.
- **Streaming decode**: transforms decode incrementally with budgets, so a
  single file cannot blow up CPU or memory.
- **Correctness over cleverness**: gates may allow false positives, but they
  never skip possible true matches; correctness is preserved by design.
