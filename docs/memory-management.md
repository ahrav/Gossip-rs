# Memory Management

Buffer lifecycle and pool management in scanner-rs.

## Unified FS Owner-Compute Model

The unified filesystem entrypoint (`scanner-rs scan fs`) now uses
`crates/scanner-scheduler/src/scheduler/local_fs_owner.rs`:

- One thread per worker.
- Discovery pushes file batches into a shared injector; workers pull tasks via
  work-stealing.
- Each worker owns and reuses its own chunk buffer, overlap state, pending
  findings vector, and scan scratch.
- There is no cross-thread chunk handoff between I/O and scan stages.

## Multi-Core Production Memory Model

The production multi-core scanner (`scan_local`) allocates memory at startup
and maintains zero allocations during the hot path. Memory scales with worker count.

### Memory Breakdown by Worker Count

| Workers | Per-Worker | Buffer Pool | **Total** |
| ------- | ---------- | ----------- | --------- |
| 4       | 75.3 MiB   | 5.0 MiB     | ~80 MiB   |
| 8       | 150.5 MiB  | 10.0 MiB    | ~161 MiB  |
| 12      | 225.8 MiB  | 15.0 MiB    | ~241 MiB  |
| 16      | 301.1 MiB  | 20.0 MiB    | ~321 MiB  |

These figures are from the diagnostic sizing model (`223` builtin rules,
`max_anchor_hits_per_rule_variant = 2048`, and a `64 KiB` overlap estimate).

### Per-Worker Allocation (~19.1 MiB each)

| Component                           | Size      | % of Total |
| ----------------------------------- | --------- | ---------- |
| **HitAccPool.windows**              | 15.68 MiB | 82.1%      |
| FixedSet128 (seen_findings)         | 768 KiB   | 3.9%       |
| FindingRec buffers (out + tmp)      | 640 KiB   | 3.3%       |
| DecodeSlab                          | 512 KiB   | 2.6%       |
| norm_hash_buf (RealEngineScratch)   | ~256 KiB  | 1.3%       |
| Other (ByteRing, TimingWheel, etc.) | ~1.2 MiB  | 6.8%       |

**Key insight**: HitAccPool dominates at 82.1% of per-worker memory. This is
sized for worst-case: 669 (rule,variant) pairs × 2048 max hits × 12 bytes/SpanU32.

> **Future optimization**: HitAccPool may be over-provisioned. Reducing
> `max_anchor_hits_per_rule_variant` from 2048 to 512 could save ~60% memory.

### Buffer Pool (System-Wide)

- **Buffers**: `workers × 4` (e.g., 32 buffers for 8 workers)
- **Buffer size (example)**: `chunk_size + overlap` = 256 KiB + 64 KiB = 320 KiB
- **Total (example)**: ~10 MiB for 8 workers

### Production Configuration (ParallelScanConfig)

```rust
ParallelScanConfig {
    workers: num_cpus::get().max(1), // Auto-detect CPU count
    chunk_size: 256 * 1024,       // 256 KiB chunks
    pool_buffers: workers * 4,    // 4 buffers per worker
    max_in_flight_objects: 1024,
    local_queue_cap: 4,
}
```

### Zero-Allocation Hot Path

After startup allocation, the scan phase is allocation-free:
- All per-worker scratch is pre-allocated (ScanScratch, LocalScratch)
- Unified FS owner-compute workers reuse worker-local I/O buffers
- Findings use pre-sized vectors that are reused across chunks
- Archive scanning reuses `archive::scan::ArchiveScratch` buffers (path builders, tar/zip cursors, gzip header/name buffers) and per-sink scratch for entry scanning

Startup may perform best-effort Vectorscan DB cache I/O (deserialize on hit,
serialize on miss) for raw prefilter and decoded-stream prefilter databases.
This affects startup latency only; hot-path scan memory behavior is unchanged.

**FS persistence allocation**: When a `StoreProducer` is configured,
`build_persistence_batch()` fills a per-worker `Vec<FsFindingRecord>` buffer
sized to the post-dedupe finding count. This buffer is reused across files
to avoid per-object allocation. The `emit_fs_batch()` call borrows the batch,
so backends must copy or serialize before returning. This is off the hot
chunk-scanning path (occurs once per scanned object, after all chunks are
processed).

With the SQLite backend (`crates/scanner-scheduler/src/store/db/writer.rs`), each worker calls
`emit_fs_batch` on the shared `SqliteStoreProducer`. A `Mutex` serializes
writes; each batch runs inside a `BEGIN IMMEDIATE … COMMIT` transaction.
WAL mode enables concurrent readers without blocking the writer.

These caps bound persistence-side memory independently of engine scanning
budgets.

Path storage is also bounded: `FileTable` maintains a fixed-capacity byte arena
for Unix paths. Archive expansion uses fallible `try_*` insertion APIs plus
per-archive path budgets so hostile inputs cannot panic the scanner.
See `crates/scanner-scheduler/src/archive/` for the release-mode capacity guards and archive-specific
allocation constraints.

Run diagnostic tests to verify: `cargo test --test diagnostic -- --ignored --nocapture --test-threads=1`

## Unified Event Output Memory Notes

The unified scanner writes findings through a streaming `EventSink`
(`crates/scanner-scheduler/src/unified/events.rs`) instead of building a run-global stdout buffer.
This keeps output-path memory bounded to sink/writer buffers plus per-worker
scratch vectors.

Git scanning still retains per-run metadata required for finalize/persist
(`ScannedBlobs`), but finding emission to stdout is streamed.

## Store Key Bootstrap Memory Notes

`crates/scanner-scheduler/src/store/keys.rs` runs key bootstrap once at startup:

- Persistent mode decodes `SCANNER_SECRET_KEY` (base64, 32 bytes).
- Missing/invalid input uses an ephemeral fallback key.
- Three subkeys are derived (`identity`, `secret`, `metadata`) and reused.

This flow is intentionally off the scan hot path and does not introduce
per-finding or per-chunk allocations in engine loops.
---

## Git Tree Loading Budgets

Git tree diffing has its own bounded memory envelope:

- **Tree bytes in-flight budget**: `TreeDiffLimits.max_tree_bytes_in_flight` caps
  the total decompressed tree payloads retained at any one time. This is a
  peak-memory guard, not a cumulative counter.
- **Pack access**: pack files are memory-mapped on demand only for packs
  referenced by mapping results; no pack data is copied unless inflated.
- **Inflate buffers**: tree payloads and delta instructions are inflated into
  bounded buffers capped by the tree bytes budget (plus a small header slack
  for loose objects).
- **Candidate storage**: candidate buffer and path arena sizes are explicitly
  bounded by `TreeDiffLimits.max_candidates` and `max_path_arena_bytes`. The
  runner streams candidates directly into the spill/dedupe sink to avoid
  buffering the entire plan in memory; `CandidateBuffer` uses a capped
  initial capacity and can be cleared between diffs when used.
- **Tree cache sizing**: tree payload cache uses fixed-size slots (4 KiB)
  with 4-way sets; total cache bytes are rounded down to a power-of-two
  set count. Entries larger than a slot are not cached. Cache hits return
  pinned handles so tree bytes can be borrowed without copying; pinned slots
  are skipped by eviction until the handle is dropped.
- **Tree delta cache**: delta base cache stores decompressed tree bases
  keyed by pack offset in fixed-size slots. It is sized by
  `TreeDiffLimits.max_tree_delta_cache_bytes` and avoids repeated base
  inflations in deep delta chains. Entries larger than a slot are not cached.
- **Tree spill arena**: large tree payloads can be written into a preallocated,
  memory-mapped spill file sized by `TreeDiffLimits.max_tree_spill_bytes`.
  Spilled bytes are referenced by `(offset, len)` handles and do not count
  against the in-flight RAM budget.
- **Spill index**: a fixed-size, open-addressed OID index (sized from the
  spill capacity and spill threshold) reuses spilled tree payloads without
  heap allocations after startup. When the index is full, spilling continues
  but reuse is disabled.
- **Streaming parser**: tree diffs switch to a streaming entry parser for
  spill-backed or large tree payloads. The parser retains a fixed-size
  buffer (`TREE_STREAM_BUF_BYTES`, currently 16 KiB) so tree iteration stays
  bounded in RAM while still preserving Git tree order.
- **Spill I/O hints**: on Unix, the spill arena applies `posix_fadvise` and
  `madvise(MADV_SEQUENTIAL)` hints to favor sequential access. On non-Unix
  platforms these calls are no-ops.

These limits make Git tree traversal deterministic and DoS-resistant while
keeping blob data out of memory during diffing.

## Git Spill + Dedupe Budgets

Spill/dedupe keeps candidate metadata in SoA tables sized to the spill chunk
limit. `WorkItems` allocates once up to `SpillLimits.max_chunk_candidates` and
stores:

- `oid_table`: one OID per candidate (20 or 32 bytes each)
- `ctx_table`: one `CandidateContext` per candidate (commit/parent/kind/flags + path ref)
- Index/attribute arrays: `oid_idx`, `ctx_idx`, `path_ref`, `flags`, `pack_id`, `offset`
- Sorting scratch: `order` + `scratch` (`u32` each)

Path bytes are stored separately in the chunk `ByteArena` and bounded by
`SpillLimits.max_chunk_path_bytes`, so total spill working set remains linear
in candidate count plus bounded path arena growth.

`ByteArena::clear_keep_capacity()` resets spill path arenas between flushes
without releasing capacity, keeping spill loops allocation-stable.

Run IO is allocation-aware: `RunWriter::write_resolved` writes borrowed paths
directly, `RunReader::read_next_into` reuses a scratch record buffer, and the
spill merger reuses record storage across runs to avoid per-record clones.

Seen filtering uses a per-batch arena capped by `SpillLimits.seen_batch_max_path_bytes`
and batches up to `SpillLimits.seen_batch_max_oids` OIDs before issuing a
seen-store query. Batches are flushed on either limit to keep memory bounded.

## Git Mapping Budgets

The mapping bridge re-interns candidate paths into a long-lived arena and
collects pack/loose candidates for downstream planning:

- **Path arena**: bounded by `MappingBridgeConfig.path_arena_capacity`.
- **Candidate caps**: `MappingBridgeConfig.max_packed_candidates` and
  `MappingBridgeConfig.max_loose_candidates` bound the in-memory vectors.
- **Overflow handling**: for default-or-higher packed caps, the runner scales
  packed-candidate capacity with `midx.object_count` before mapping.
- **Failure mode**: explicitly reduced caps are still hard limits; exceeding
  either cap returns `SpillError::MappingCandidateLimitExceeded` before
  watermark advancement.

## ODB-Blob Scan Budgets

ODB-blob mode allocates fixed-capacity data structures once at startup:

- **OID index**: open-addressed table mapping OID → MIDX index sized from
  `midx.object_count` with a ≤0.7 load factor. This is the primary O(1)
  lookup structure used by the blob introducer.
- **Commit graph index**: SoA arrays (commit OID, root tree OID, committer
  timestamp) sized to `commit_graph.num_commits` for cache-friendly lookups
  during blob attribution.
- **Seen sets**: two `DynamicBitSet`s (trees + blobs) sized to
  `midx.object_count` to guarantee each tree or blob is processed once.
- **Loose OID sets**: open-addressed tables for loose blob OIDs (seen +
  excluded) capped by `MappingBridgeConfig.max_loose_candidates` to match the
  loose candidate budget.
- **Path builder**: reusable path buffer + segment stack with a hard
  `MAX_PATH_LEN` guard (4096 bytes) to avoid per-entry allocation.
- **Path bytes storage**: path bytes are stored in `ByteArena` slabs for
  deterministic growth and reset behavior across large traversals.
- **Pack candidate collector**: bounded `Vec<PackCandidate>`/`Vec<LooseCandidate>`
  sized by `MappingBridgeConfig.max_*_candidates`. In ODB-blob mode the runner
  raises `max_packed_candidates` to at least `midx.object_count()` and scales
  the path arena with a fixed bytes-per-candidate heuristic to avoid cap
  failures on large repos.
- **Spill fallback**: if in-memory candidate caps or the path arena overflow,
  ODB-blob replays the introducer and streams candidates into the existing
  spill + dedupe pipeline, reusing `SpillLimits` for disk-backed buffering.

### Parallel ODB-Blob Mode (`blob_intro_workers > 1`)

When parallel blob introduction is enabled, the memory model changes:

- **AtomicSeenSets**: replaces the serial `DynamicBitSet` pair with a
  lock-free `AtomicBitSet` pair (trees + blobs) sized identically to
  `midx.object_count`. Memory footprint is the same (1 bit per object per
  set); the only overhead is atomic operations on the backing words.
- **Per-worker budget division**: global budgets are divided by
  `worker_count` with floor/cap clamping to avoid undersized allocations:

  | Budget | Division | Floor | Cap |
  | --- | --- | --- | --- |
  | `max_tree_cache_bytes` | `÷ workers` | 4 MiB | — |
  | `max_tree_delta_cache_bytes` | `÷ workers` | 4 MiB | — |
  | `max_tree_spill_bytes` | `÷ workers` | 64 MiB | — |
  | `max_tree_bytes_in_flight` | `÷ workers` | 64 MiB | — |
  | `max_packed_candidates` | `÷ workers` | 1024 | original cap |
  | `max_loose_candidates` | `÷ workers` (ceil) | 0 | original cap |
  | `path_arena_capacity` | `÷ workers` | 64 KiB | original cap |

- **Post-merge global cap re-validation**: after worker results are
  concatenated, `merge_worker_results` enforces the original global caps:
  - Packed candidates are truncated to `mapping_cfg_max_packed`.
  - Path arena bytes are bounded by `mapping_cfg_path_arena_capacity`
    (overflow during arena merge returns an error).
  - Loose candidates are deduplicated by OID, then truncated to
    `mapping_cfg_max_loose`.
- **Per-worker isolation**: each worker owns its own `ObjectStore` (with
  tree cache, delta cache, and spill arena) and `PackCandidateCollector`.
  No per-worker state is shared except the `AtomicSeenSets` and the
  work-stealing chunk counter.
- **Attribution semantics**: parallel mode keeps the same unique blob set as
  serial mode, but emitted context (`commit_id`, path, flags) is race-winner
  based and not deterministic across worker counts. This does not change any
  of the memory bounds above.

## Git Pack Planning Budgets

Pack planning builds per-pack `PackPlan` buffers sized to the candidate set
and the delta-base closure:

- Candidate list: one `PackCandidate` per packed blob.
- Candidate offsets: one `CandidateAtOffset` per candidate (sorted by offset).
- Need offsets: unique `u64` offsets for candidates plus pack-local bases,
  expanded up to `PackPlanConfig.max_delta_depth` and capped by
  `PackPlanConfig.max_worklist_entries`.
- Delta deps: one `DeltaDep` per delta entry in `need_offsets` (records
  internal base offsets or external base OIDs).
- Entry header cache: one cached `ParsedEntry` per offset in `need_offsets`
  during planning, bounded by the same worklist cap.
- Base lookups: `PackPlanConfig.max_base_lookups` bounds REF delta
  resolver calls to prevent unbounded MIDX lookups.
- Exec order: optional `Vec<u32>` of indices into `need_offsets` when forward
  dependencies exist.

Memory is linear in `candidates.len()` + `need_offsets.len()` with explicit
caps on closure expansion and header parsing.

In ODB-blob mode, the runner scales `max_worklist_entries` and
`max_base_lookups` to at least 2× the packed candidate count so large repos
do not trip the default 1M limits.

## Git Pack Decode Budgets

Pack decode uses bounded buffers and a fixed-size cache:

- **Inflate buffers**: in-memory output is capped by `PackDecodeLimits.max_object_bytes`
  for full objects and `PackDecodeLimits.max_delta_bytes` for delta payloads.
  When a full object or delta output exceeds `max_object_bytes`, pack exec
  inflates into a spill-backed mmap under the run `spill_dir` and scans from
  disk instead of growing RAM.
- **Scratch reuse**: pack exec reuses per-pack scratch buffers for delta maps,
  candidate ranges, and base/delta buffers (`inflate_buf`, `result_buf`,
  `base_buf`) to avoid per-plan allocations after warmup. Delta base cache
  misses re-decode base chains into `base_buf` to preserve correctness
  without requiring larger caches.
- **Header parsing**: entry headers are bounded by
  `PackDecodeLimits.max_header_bytes`.
- **Pack cache (tiered)**: `PackCache` stores decoded objects in two
  size-segregated fixed-slot tiers. The small tier uses 64 KiB slots; the
  large tier uses 2 MiB slots. Entries larger than 2 MiB are not cached.
  Each tier is 4-way set associative with CLOCK eviction, and all storage is
  preallocated.
- **Sequential hints**: pack mmaps use `posix_fadvise`/`madvise` (when
  available) to hint sequential access and improve readahead without
  changing memory caps.
- **ODB-blob cache sizing**: pack cache bytes are targeted from
  `total_used_pack_bytes / 16`, then clamped by per-worker/global bounds:
  `16 GiB / workers` aggregate cap, 32 MiB per-worker floor, and 2 GiB
  per-worker hard cap. The default split is roughly 2/3 small tier and 1/3
  large tier, with a minimum of 32 MiB reserved for the large tier when
  enabled.
- **Parallel pack exec memory**: each worker owns its own pack cache and
  scratch buffers. A global scheduler caps total workers and enforces
  per-repo memory ceilings: `workers * (pack_cache_bytes + scratch_bytes)`.

These limits keep pack decoding deterministic and bound memory to the
configured cache capacity plus temporary inflate buffers.

## Git Scan Hot-Loop Allocation Guard

Hot-loop allocations are prohibited after warmup in pack execution and
engine scanning:

- **Debug guard**: `git_scan::set_alloc_guard_enabled(true)` enables a
  debug-only `AllocGuard` around pack exec and engine adapter scan paths.
- **Findings arena**: per-blob findings are stored in a shared arena and
  referenced by spans (`FindingSpan`), avoiding per-blob `Vec` allocations.
- **Chunker reuse**: the engine adapter reuses a fixed-size ring chunker and
  findings buffer across blobs to keep scan hot loops allocation-free.

Use the allocation guard in debug tests with the counting allocator to
verify no heap activity after warmup.

## Single-Threaded Pipeline Memory Model

> **Note**: The diagrams below describe the single-threaded runtime types in
> `crates/scanner-scheduler/src/runtime.rs` (`ScannerRuntime`, `BufferPool`, `Chunk`), which use
> different sizing defaults than the owner-compute scheduler. For production
> multi-core scanning, see the section above.

```mermaid
flowchart TB
    subgraph Init["Initialization"]
        PoolInit["BufferPool::new(config.pool_capacity())"]
        NodeInit["NodePoolType::init(pool_cap)"]
        BitInit["DynamicBitSet::empty(pool_cap)"]
        Alloc["alloc(pool_cap * 8MiB, 4096)"]
    end

    subgraph Pool["BufferPool State"]
        Inner["BufferPoolInner"]
        NodePool["NodePoolType<br/>BUFFER_LEN_MAX nodes, 4KB align"]
        Available["available: Cell&lt;u32&gt;"]
        Bitset["DynamicBitSet<br/>free slot tracking"]
    end

    subgraph Acquire["Acquire Flow"]
        TryAcq["try_acquire()"]
        CheckAvail{{"available > 0?"}}
        FindFree["find_first_set()"]
        UnsetBit["free.unset(idx)"]
        CalcPtr["ptr = buffer + idx * NODE_SIZE"]
        Handle["BufferHandle { pool, ptr }"]
    end

    subgraph Release["Release Flow"]
        Drop["BufferHandle::drop()"]
        ValidatePtr["Validate ptr in range"]
        CalcIdx["idx = (ptr - buffer) / NODE_SIZE"]
        SetBit["free.set(idx)"]
        IncAvail["available += 1"]
    end

    subgraph Usage["Buffer Usage"]
        Reader["ReaderStage"]
        Chunk["Chunk { buf: BufferHandle }"]
        Scanner["ScanStage"]
    end

    PoolInit --> NodeInit
    NodeInit --> BitInit
    BitInit --> Alloc

    Inner --> NodePool
    Inner --> Available
    NodePool --> Bitset

    TryAcq --> CheckAvail
    CheckAvail --> |"no"| None["None"]
    CheckAvail --> |"yes"| FindFree
    FindFree --> UnsetBit
    UnsetBit --> CalcPtr
    CalcPtr --> Handle

    Handle --> Reader
    Reader --> Chunk
    Chunk --> Scanner
    Scanner --> Drop

    Drop --> ValidatePtr
    ValidatePtr --> CalcIdx
    CalcIdx --> SetBit
    SetBit --> IncAvail

    style Init fill:#e3f2fd
    style Pool fill:#fff3e0
    style Acquire fill:#e8f5e9
    style Release fill:#ffebee
    style Usage fill:#f3e5f5
```

## Pool Structure

```mermaid
classDiagram
    class BufferPool {
        -Rc~BufferPoolInner~ inner
        +new(capacity: usize) BufferPool
        +try_acquire() Option~BufferHandle~
        +acquire() BufferHandle
        +buf_len() usize
    }

    class BufferPoolInner {
        -UnsafeCell~NodePoolType~ pool
        -Cell~u32~ available
        -u32 capacity
        +acquire_slot() NonNull~u8~
        +release_slot(ptr: NonNull~u8~)
    }

    class NodePoolType {
        -NonNull~u8~ buffer
        -usize len
        -DynamicBitSet free
        +init(node_count: u32) Self
        +acquire() NonNull~u8~
        +release(node: NonNull~u8~)
    }

    class BufferHandle {
        -Rc~BufferPoolInner~ pool
        -NonNull~u8~ ptr
        +as_slice() &[u8]
        +as_mut_slice() &mut [u8]
        +clear()
    }

    class DynamicBitSet {
        -Vec~u64~ words
        -usize bit_length
        +is_set(idx: usize) bool
        +set(idx: usize)
        +unset(idx: usize)
        +iter_set() Iterator
    }

    BufferPool --> BufferPoolInner
    BufferPoolInner --> NodePoolType
    NodePoolType --> DynamicBitSet
    BufferHandle --> BufferPoolInner
```

## Memory Layout

```
┌─────────────────────────────────────────────────────────────────┐
│                    NodePoolType Buffer                           │
│                    (pool_cap * 8MiB)                            │
├─────────────┬─────────────┬─────────────┬───────┬─────────────┤
│   Node 0    │   Node 1    │   Node 2    │  ...  │   Node N-1  │
│   8MiB      │   8MiB      │   8MiB      │       │   8MiB      │
│   align=4K  │   align=4K  │   align=4K  │       │   align=4K  │
└─────────────┴─────────────┴─────────────┴───────┴─────────────┘

DynamicBitSet (pool_cap bits):
┌─────────────────────────────────────────────────────────────────┐
│ word[0..k]: free-slot bitmap                                   │
│ 1=free, 0=acquired                                             │
└─────────────────────────────────────────────────────────────────┘
```

## Rationale

The pool is deliberately large and aligned:

- **Fixed allocation**: all buffers are allocated up front so scanning never
  allocates on the hot path. This avoids allocator jitter and makes worst-case
  memory consumption explicit.
- **Alignment**: 4KB alignment keeps buffers page-aligned, which improves cache
  behavior and keeps the door open for direct I/O or SIMD-friendly access.
- **Predictable reclamation**: `BufferHandle` is RAII; dropping the chunk is the
  only way to return a buffer. This makes lifecycle bugs easy to spot.

To reduce memory footprint, tune pipeline `chunk_size` and
`PIPE_POOL_TARGET_BYTES` based on workload.

## Constants

```rust
pub const BUFFER_LEN_MAX: usize = 8 * 1024 * 1024;  // 8MiB per buffer
pub const BUFFER_ALIGN: usize = 4096;               // 4KB alignment

pub const PIPE_CHUNK_RING_CAP: usize = 128;         // Max chunks in flight
pub const PIPE_POOL_TARGET_BYTES: usize = 256 * 1024 * 1024;
pub const PIPE_POOL_MIN: usize = 16;
```

## Chunk Structure

```mermaid
graph TB
    subgraph ChunkLayout["Chunk Data Layout"]
        Prefix["prefix_len bytes<br/>(overlap from previous)"]
        Payload["payload bytes<br/>(new data read)"]
    end

    subgraph ChunkStruct["Chunk Fields"]
        FileId["file_id: FileId"]
        BaseOffset["base_offset: u64"]
        Len["len: u32 (total)"]
        PrefixLen["prefix_len: u32"]
        Buf["buf: BufferHandle"]
    end

    Prefix --> |"data()[..prefix_len]"| ChunkStruct
    Payload --> |"payload()[prefix_len..]"| ChunkStruct
```

```rust
pub struct Chunk {
    pub file_id: FileId,
    pub base_offset: u64,    // File offset where chunk starts
    pub len: u32,            // Total bytes (prefix + payload)
    pub prefix_len: u32,     // Overlap bytes from previous chunk
    pub buf: BufferHandle,   // Owned buffer handle
    pub buf_offset: u32,     // Start offset into buf where chunk data begins
}

impl Chunk {
    // Full data including overlap prefix
    pub fn data(&self) -> &[u8] {
        let start = self.buf_offset as usize;
        let end = start + self.len as usize;
        &self.buf.as_slice()[start..end]
    }

    // Payload only (excludes overlap)
    pub fn payload(&self) -> &[u8] {
        let start = self.buf_offset as usize + self.prefix_len as usize;
        let end = self.buf_offset as usize + self.len as usize;
        &self.buf.as_slice()[start..end]
    }
}
```

## DecodeSlab and Scratch Buffers

Scanning derived buffers (URL/Base64 decode) uses a fixed-capacity slab:

- **DecodeSlab** is append-only and sized to the global decode budget. It never
  reallocates, so ranges returned to work items stay valid for the scan.
- **ScanScratch** owns the slab and all other hot-path buffers; it is reused
  across chunks to avoid per-chunk allocations.

This is the core "no allocations during scan" mechanism: the scanner either
fits within the configured limits or it skips work.

## Overlap Preservation

```mermaid
sequenceDiagram
    participant File as File
    participant Reader as FileReader
    participant Tail as tail: Vec<u8>
    participant Buf as BufferHandle

    Note over Reader: Chunk 1 (offset=0)
    File->>Buf: read 1MB
    Buf->>Tail: copy last `overlap` bytes
    Reader->>Pipeline: emit Chunk { prefix_len: 0 }

    Note over Reader: Chunk 2 (offset=1MB)
    Tail->>Buf: copy to buf[0..overlap]
    File->>Buf: read 1MB at buf[overlap..]
    Buf->>Tail: copy last `overlap` bytes
    Reader->>Pipeline: emit Chunk { prefix_len: overlap }

    Note over Reader: Pattern spanning chunks
    Note over Reader: Original: [....PATTERN....]
    Note over Reader: Chunk 1:  [....PATT]
    Note over Reader: Chunk 2:  [PATTERN....] (prefix has PATT)
```

The overlap ensures patterns that span chunk boundaries are detected:
- `overlap = engine.required_overlap()`
- `required_overlap = max_window_diameter_bytes + max_prefilter_width - 1`

## ScanScratch Per-Chunk State

```rust
#[repr(C)]
pub struct ScanScratch {
    // Hot scan-loop region (always touched)
    out: ScratchVec<FindingRec>,
    norm_hash: ScratchVec<NormHash>,
    drop_hint_end: ScratchVec<u64>,
    work_q: ScratchVec<WorkItem>,
    hit_acc_pool: HitAccPool,
    touched_pairs: ScratchVec<u32>,
    windows: ScratchVec<SpanU32>,
    expanded: ScratchVec<SpanU32>,
    spans: ScratchVec<SpanU32>,
    step_arena: StepArena,
    utf16_buf: ScratchVec<u8>,
    steps_buf: ScratchVec<DecodeStep>,
    // ... additional hot fields omitted for brevity ...

    // Cache-line split between hot and cold regions.
    _cold_boundary: CachelineBoundary, // #[repr(align(64))]

    // Cold / conditional region (streaming, transform, instrumentation)
    slab: DecodeSlab,
    seen: FixedSet128,
    seen_findings: FixedSet128,
    decode_ring: ByteRing,
    pending_windows: TimingWheel<PendingWindow, 1>,
    entropy_scratch: Option<Box<EntropyScratch>>,
    root_span_map_ctx: Option<RootSpanMapCtx>,
    // ... additional cold fields omitted ...
}
```

All vectors are reused across chunks via `reset_for_scan()`:
- Vectors are cleared but retain capacity
- `seen` uses generation-based O(1) reset
- Avoids per-chunk allocation overhead
- `#[repr(C)]` + `_cold_boundary` guarantees the first cold field starts on a
  64-byte boundary, reducing hot/cold cache-line interference
- `entropy_scratch` is only allocated when the engine has entropy-gated rules
- Streaming scratch vectors/ring are pre-sized only when active transforms exist
