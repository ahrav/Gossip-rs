# Spill and Memory Management

This document describes the spill subsystem and memory management primitives
in `scanner-git`. These components handle candidate deduplication, on-disk
spillover for large blob sets, arena-based path allocation, and blob
introduction tracking.

## Overview

When a Git scan discovers blob candidates (via tree diff or blob introduction),
the candidate set can exceed available memory for large repositories. The spill
subsystem provides a bounded-memory pipeline:

1. Candidates are accumulated into an in-memory **chunk** (`CandidateChunk`).
2. When the chunk fills, it is sorted, deduped, and written to disk as a
   sorted **run** file.
3. At finalize, all runs are merged via a **k-way merge** that produces a
   globally sorted, deduplicated candidate stream.
4. The merged stream is filtered against a **seen-blob store**, emitted to a
   `UniqueBlobSink`, and optionally checkpointed into a durable seen bitmap
   after each flush batch.

For repositories where candidates fit in a single chunk, no disk I/O occurs.

## Key Types

### Spill Orchestration

| Type | Location | Description |
|------|----------|-------------|
| `Spiller` | `spiller.rs` | Top-level orchestrator. Owns the chunk, run file list, and spill directory. Single-threaded. Consumes itself on `finalize`. |
| `SpillStats` | `spiller.rs` | Statistics from spill + seen filtering: candidates received, unique blobs, run count, spill bytes, seen/emitted counts. |
| `SpillLimits` | `spill_limits.rs` | Hard caps for chunk size, run count, spill bytes, path length, and seen-store batching. 32-byte fixed layout. |
| `BatchBuffer` | `spiller.rs` | Internal bounded buffer for seen-store batch queries. Stores sorted OIDs and interned paths. |

### Chunk Storage

| Type | Location | Description |
|------|----------|-------------|
| `CandidateChunk` | `spill_chunk.rs` | Bounded in-memory candidate buffer with a `ByteArena` for paths. Supports sort, exact-match dedup, and per-OID canonical reduction. |
| `ResolvedIter` | `spill_chunk.rs` | Iterator over resolved candidates with path bytes borrowed from the chunk's arena. |

### Run File Format

| Type | Location | Description |
|------|----------|-------------|
| `RunHeader` | `run_format.rs` | 12-byte header: magic `SRUN`, version (1), OID length (20 or 32), record count. Big-endian encoding. |
| `RunContext` | `run_format.rs` | Per-record context: `commit_id`, `parent_idx`, `change_kind`, `ctx_flags`, `cand_flags`. |
| `RunRecord` | `run_format.rs` | Single spill record: OID + context + raw path bytes. Implements canonical `Ord`. |
| `RunWriter` | `run_writer.rs` | Writes sorted `RunRecord`s to a buffered output with header enforcement. |
| `RunReader` | `run_reader.rs` | Reads `RunRecord`s from a run file with max-path-length validation. |

### External Sort / Merge

| Type | Location | Description |
|------|----------|-------------|
| `RunMerger` | `spill_merge.rs` | K-way merge reader. Uses a `BinaryHeap` min-heap with per-cursor scratch records. Deduplicates by comparing against the last emitted key. |
| `merge_all` | `spill_merge.rs` | Convenience function that merges runs fully into memory (tests/small repos). |
| `validate_headers` | `spill_merge.rs` | Validates consistent OID length across run headers. |

### Arena Allocation

| Type | Location | Description |
|------|----------|-------------|
| `ByteArena` | `byte_arena.rs` | Bump allocator for variable-length byte sequences. Hard `u32` capacity limit (~4 GiB). Pre-allocation capped at 1 MiB. |
| `ByteRef` | `byte_arena.rs` | 8-byte copyable handle (offset `u32` + length `u16`). Offset-based, so `Vec` reallocation does not invalidate references. |

### Spill Arena (Memory-Mapped)

| Type | Location | Description |
|------|----------|-------------|
| `SpillArena` | `spill_arena.rs` | Append-only mmap-backed arena for tree payloads. Dual-mapping: `MmapMut` writer + `Arc<Mmap>` reader. Single-writer design. |
| `SpillSlice` | `spill_arena.rs` | Reference to spilled bytes. Holds `Arc<Mmap>` so it outlives the arena. |
| `SpillArenaError` | `spill_arena.rs` | IO errors or out-of-space conditions. |
| `SpillIndex` | `object_store.rs` | Open-addressing hash table for spilled tree payloads. Power-of-two sized (64..1,048,576 slots), linear probing, no tombstones. Best-effort: once full, new spills are not indexed. |
| `SpillIndexEntry` | `object_store.rs` | Fixed slot: OID key (up to 32 bytes), spill offset, and length. `key_len == 0` marks empty. |

### Blob Spill

| Type | Location | Description |
|------|----------|-------------|
| `BlobSpill` | `blob_spill.rs` | Fixed-size mmap-backed spill file for oversized blob payloads. Dual-mapping strategy. File deleted on drop (best-effort). |
| `BlobSpillWriter` | `blob_spill.rs` | Sequential append-only writer. Must write exactly `len` bytes before `finish`. |

### Blob Introduction

| Type | Location | Description |
|------|----------|-------------|
| `BlobIntroducer` | `blob_introducer.rs` | Serial blob introduction walker. Traverses commits in topo order, discovers each unique blob exactly once via `SeenSets` (packed) and `LooseOidSet` (loose). |
| `BlobIntroWorker` | `blob_introducer.rs` | Parallel worker variant. Shares `AtomicSeenSets` for lock-free dedup. Each worker owns its own `ObjectStore` and `PackCandidateCollector`. |
| `SeenSets` | `blob_introducer.rs` | Three independent `DynamicBitSet` bitmaps (trees, blobs, blobs_excluded) keyed by MIDX index. Non-atomic; used by the serial path. |
| `LooseOidSet` | `blob_introducer.rs` | Fixed-capacity open-addressing hash set for loose OIDs not in the MIDX. Linear probing, 70% load factor, power-of-two sizing. One-byte tag for early rejection. |
| `BlobIntroStats` | `blob_introducer.rs` | Counters: commits visited, trees loaded, tree bytes, peak in-flight, blobs emitted, subtrees skipped, max depth. |
| `ParallelIntroResult` | `blob_introducer.rs` | Merged output from parallel workers: packed/loose candidates, merged path arena, aggregated stats. |

### Seen Store and Sink Traits

| Type | Location | Description |
|------|----------|-------------|
| `SeenBlobStore` (trait) | `seen_store.rs` | Batch query interface for seen-blob filtering. Returns one bool per OID; inputs expected sorted. |
| `SeenBitmapPersister` (trait) | `seen_store.rs` | Incremental write interface for scope-scoped seen-bitmap updates. Inputs must already be sorted and unique. |
| `SeenBitmapDelta` | `roaring_seen.rs` | Finalize-time `sb\0` payload. Holds canonical OIDs as `Vec<OidBytes>` because batches are short-lived. |
| `RoaringSeenBitmap` | `roaring_seen.rs` | Durable per-scope seen snapshot. Keeps the sorted OID index flat-packed as `oid_count * oid_len` bytes in memory and overlays a roaring bitmap over positions in that table. |
| `NullSeenBitmapPersister` | `seen_store.rs` | No-op persister used when a scan has no durable mid-spill checkpoint target. |
| `NeverSeenStore` | `seen_store.rs` | Marks all blobs unseen (full-scan mode). |
| `AlwaysSeenStore` | `seen_store.rs` | Marks all blobs seen (testing). |
| `InMemorySeenStore` | `seen_store.rs` | `HashSet`-backed store for tests. |
| `UniqueBlobSink` (trait) | `unique_blob.rs` | Receives unique, unseen blobs. Path `ByteRef` is valid only for the `emit` call duration. |
| `UniqueBlob` | `unique_blob.rs` | OID + canonical `CandidateContext` with path reference. |
| `CollectingUniqueBlobSink` | `unique_blob.rs` | Test sink that stores blobs with owned path copies. |

## External Sort

The spill subsystem implements an external merge sort over blob candidates.

### Run Generation

When `Spiller::push` fills the in-memory `CandidateChunk` (exceeding
`SpillLimits::max_chunk_candidates` or `max_chunk_path_bytes`), the spiller
calls `spill_chunk` (`spiller.rs`):

1. The chunk is sorted by canonical key and deduped (`CandidateChunk::sort_and_dedupe`,
   `spill_chunk.rs`).
2. Dedup runs two passes: exact-match dedup on the full key, then per-OID
   reduction that keeps only the most canonical candidate for each distinct
   OID (lowest commit id, then path, then context fields).
3. A `RunWriter` serializes records to a buffered file under the spill directory.
4. The spill byte counter is updated and checked against `max_spill_bytes`.
5. The run count is checked against `max_spill_runs`.

### Canonical Ordering

Records are ordered by: OID, path bytes (raw, not arena offset), commit id,
parent index, change kind, context flags, candidate flags. This ordering is
defined in `compare_candidates` (`spill_chunk.rs`) and
`RunRecord::cmp_canonical` (`run_format.rs`).

Canonical **selection** for a given OID (which context wins) uses a different
priority: commit id (lowest wins), then path bytes, parent index, change
kind, context flags, candidate flags — implemented in `is_more_canonical`
(`spiller.rs`).

### K-Way Merge

`RunMerger` (`spill_merge.rs`) merges sorted run files into a single
sorted stream:

1. Each run file is opened as a `RunReader` wrapped in a `BufReader` (256 KB
   buffer, `spiller.rs`).
2. The merger creates one `RunCursor` per reader and seeds a `BinaryHeap`
   (min-heap via reversed `Ord`) with the first record from each cursor.
3. On each `next_unique` call (`spill_merge.rs`):
   - The smallest item is popped from the heap.
   - If it matches the last emitted key, it is skipped (dedupe).
   - Otherwise it is emitted and the cursor that produced it is advanced.
   - The advanced cursor's next record (if any) is pushed back onto the heap.
4. Each cursor reuses a single `RunRecord` scratch allocation to avoid
   per-record heap allocation.
5. Tie-breaking on cursor index ensures deterministic ordering when records
   from different runs compare equal.

### Finalize

`Spiller::finalize` (`spiller.rs`) consumes the spiller:

- **No runs on disk**: the in-memory chunk is sorted, deduped, and processed
   directly (`process_chunk_only`, `spiller.rs`).
- **Runs on disk**: the final chunk is spilled, then all runs are merged
   (`process_with_merge`, `spiller.rs`).

In both paths, unique OIDs are batched for seen-store queries (`BatchBuffer`
with `seen_batch_max_oids` and `seen_batch_max_path_bytes` limits). Unseen
blobs are emitted to the `UniqueBlobSink`, and the batch's sorted OIDs are
then forwarded to the seen-bitmap persister so crash recovery can resume from
the last flushed checkpoint. Temporary run files are deleted after finalize
(also deleted on drop as a safety net). Persisted scope snapshots keep those
OIDs in a flat-packed byte table, so the long-lived seen index does not pay the
per-entry padding cost of `OidBytes`.

## Arena Allocation

### ByteArena

`ByteArena` (`byte_arena.rs`) is a bump allocator for variable-length
byte sequences, primarily used to intern file paths. Key properties:

- **Append-only**: bytes are not removed; references stay valid until an
  explicit `clear_keep_capacity`.
- **Offset-based references**: `ByteRef` stores `(off: u32, len: u16)`.
  Because references are offsets (not pointers), `Vec` reallocation does not
  invalidate them.
- **No deduplication**: repeated inserts store repeated bytes.
- **Hard capacity**: bounded at creation by a `u32` limit. Pre-allocation is
   capped at 1 MiB (`PREALLOC_MAX_BYTES`, `byte_arena.rs`) to avoid large
  upfront reservations on small repos.
- **Complexity**: `intern` is O(n) in inserted length (memcpy); `get` is O(1).
- **Arena merging**: `append_arena` (`byte_arena.rs`) copies another
  arena's bytes and returns the base offset for rebasing `ByteRef` handles.

### SpillArena

`SpillArena` (`spill_arena.rs`) is a memory-mapped, append-only arena
for tree payloads that exceed the in-memory cache. Key properties:

- **Dual-mapping**: `MmapMut` for writes, `Arc<Mmap>` for reads. Kernel
  page-cache coherence ensures read visibility of prior writes.
- **Fixed capacity**: the backing file is preallocated to `capacity` bytes
  at creation and never resized.
- **SpillSlice**: returned handles hold an `Arc<Mmap>`, decoupling their
  lifetime from the arena itself.
- **Sequential access hints**: on Linux, `posix_fadvise(SEQUENTIAL)` and
   `madvise(SEQUENTIAL)` are issued (`spill_arena.rs`).
- **Unique file naming**: PID + timestamp + monotonic counter
   (`GLOBAL_SPILL_COUNTER`, `spill_path.rs`) prevent collisions during parallel
  blob introduction.

### SpillIndex

`SpillIndex` (`object_store.rs`) is a fixed-size open-addressing hash
table that maps OIDs to spill arena offsets/lengths:

- Power-of-two sized (64..1,048,576 slots).
- Linear probing with OID-derived hash (first 8 bytes as LE `u64`; no
  additional mixer because OIDs are already cryptographic hashes).
- No tombstones or deletions (append-only).
- Best-effort: once all slots are occupied, new spills are not indexed and
  lookups fall back to pack/loose reads.

## Blob Introduction

The blob introducer (`blob_introducer.rs`) walks commits in topological order
and discovers each unique blob exactly once, producing pack/loose candidate
lists for downstream pipeline stages.

### Serial Path

`BlobIntroducer` (`blob_introducer.rs`) processes all commits
sequentially:

1. For each commit, the root tree OID is resolved.
2. The tree is walked depth-first using an explicit stack of `TreeFrame`s
   (`blob_introducer.rs`).
3. **Packed objects** (present in MIDX) are deduped via `SeenSets`
   (`blob_introducer.rs`) — three independent `DynamicBitSet` bitmaps
   keyed by MIDX index:
   - `trees` — skip entire subtrees when the tree OID is already visited.
   - `blobs` — track emitted blob candidates.
   - `blobs_excluded` — track blobs matched by path-exclusion policy, kept
     separate so an excluded path does not suppress a legitimate non-excluded
     emit for the same OID.
4. **Loose objects** (not in MIDX) are deduped via `LooseOidSet`
   (`blob_introducer.rs`), a fixed-capacity open-addressing hash set
   with 70% load factor and one-byte tag for early rejection. Hashing uses
   `hash_oid` (`blob_introducer.rs`): XOR of head/tail 8 bytes + Stafford
   variant 13 finalizer.
5. Tree payloads are loaded via `TreeCursor` (`blob_introducer.rs`),
   which selects buffered (small trees below `stream_threshold`) vs streaming
   (large or spilled trees) parsing to keep the in-flight byte budget bounded.

### Parallel Path

`introduce_parallel` (`blob_introducer.rs`) spawns multiple
`BlobIntroWorker`s via `std::thread::scope`:

1. The commit plan is pre-partitioned into ~4x `worker_count` chunks.
2. Workers claim chunks via an `AtomicUsize` counter (work-stealing).
3. Dedup is shared through `AtomicSeenSets` (lock-free bitmap with
   `fetch_or`). Each tree/blob is claimed by exactly one worker.
4. Each worker has its own `ObjectStore`, `PackCandidateCollector`,
   `LooseOidSet`, and per-worker budget divisions.
5. Workers check an `AtomicBool` abort flag every 4096 tree entries for
   responsiveness.
6. After all workers finish, results are merged
   (`merge_worker_results`, `blob_introducer.rs`):
   - Path arenas are concatenated with offset rebasing.
   - Loose candidates are deduplicated by OID with deterministic context
      tie-breakers (`dedup_loose_by_oid`, `blob_introducer.rs`).
   - Global packed/loose caps are re-validated.
   - Stats use saturating sums for counters, max for peaks.

Commit attribution is **not deterministic** in parallel mode — the worker
that first claims a blob determines its context (race-winner). The blob
*set* is identical to the serial path.

## Blob Spill

`BlobSpill` (`blob_spill.rs`) handles oversized individual blob payloads
that should not be held entirely in memory:

- Fixed-size mmap-backed file created under the spill directory.
- Dual-mapping strategy (same as `SpillArena`): `MmapMut` writer, `Arc<Mmap>`
  reader.
- `BlobSpillWriter` (`blob_spill.rs`) fills the file sequentially and
  enforces that exactly `len` bytes are written before `finish`.
- The spill file is deleted on drop (best-effort via `fs::remove_file`).
- Unique naming uses the same PID + timestamp + monotonic counter pattern.

## Memory Budgets

Memory usage is controlled at multiple levels through explicit configuration
structs. All limits are enforced at runtime; violations produce errors (not
panics) so the scan can degrade gracefully.

### SpillLimits (`spill_limits.rs`)

Controls candidate chunk and run management:

| Field | Default | Hard Upper Bound | Purpose |
|-------|---------|------------------|---------|
| `max_spill_bytes` | 64 GB | 2 TB | Total on-disk spill run bytes |
| `max_chunk_candidates` | 1,048,576 | 100M | Candidates per in-memory chunk |
| `max_chunk_path_bytes` | 64 MB | 1 GB | Path arena per chunk |
| `max_spill_runs` | 128 | — | Maximum run files on disk |
| `max_path_len` | 8 KB | — | Maximum single path length |
| `seen_batch_max_oids` | 8,192 | 1M | OIDs per seen-store batch query |
| `seen_batch_max_path_bytes` | 512 KB | 64 MB | Path arena per batch |

A `RESTRICTIVE` preset (`spill_limits.rs`) is provided for tests (e.g.,
16K candidates, 512 MB spill, 16 runs).

### TreeDiffLimits (`tree_diff_limits.rs`)

Controls tree loading and candidate collection during blob introduction:

| Field | Default | Purpose |
|-------|---------|---------|
| `max_tree_bytes_in_flight` | 2 GB | Peak tree payload memory across active frames |
| `max_tree_spill_bytes` | 8 GB | Spill arena capacity for tree payloads |
| `max_tree_cache_bytes` | 64 MB | Decompressed tree cache |
| `max_tree_delta_cache_bytes` | 128 MB | Delta base cache |
| `max_candidates` | 1,048,576 | In-memory candidate buffer |
| `max_path_arena_bytes` | 64 MB | Path arena for candidate paths |
| `max_tree_depth` | 256 | Maximum tree recursion depth |

### Parallel Worker Budget Division

In parallel blob introduction (`introduce_parallel`,
`blob_introducer.rs`), global budgets are divided by `worker_count`
with per-worker floors:

| Budget | Division | Floor |
|--------|----------|-------|
| `max_tree_cache_bytes` | `÷ worker_count` | 4 MB |
| `max_tree_delta_cache_bytes` | `÷ worker_count` | 4 MB |
| `max_tree_spill_bytes` | `÷ worker_count` | 64 MB |
| `max_tree_bytes_in_flight` | `÷ worker_count` | 64 MB |
| `max_loose` | `÷ worker_count` (ceiling) | 1 |
| `path_arena_capacity` | `÷ worker_count` | 64 KB |
| `max_packed` | `÷ worker_count` | 1,024 |

Post-merge validation re-checks global caps because per-worker divisions
are approximate.

### Enforcement Points

| Check | Location | Consequence |
|-------|----------|-------------|
| Chunk candidate overflow | `spiller.rs` | Spill current chunk, retry push |
| Spill run limit | `spiller.rs` | `SpillError::SpillRunLimitExceeded` |
| Spill byte limit | `spiller.rs` | `SpillError::SpillBytesExceeded` |
| Path too long | `spill_chunk.rs` | `SpillError::PathTooLong` |
| Arena overflow | `byte_arena.rs` | `intern` returns `None` |
| SpillArena out of space | `spill_arena.rs` | `SpillArenaError::OutOfSpace` |
| Tree bytes in-flight | `blob_introducer.rs` | `TreeDiffError::TreeBytesBudgetExceeded` |
| Max tree depth | `blob_introducer.rs` | `TreeDiffError::MaxTreeDepthExceeded` |
| Loose candidate cap | `blob_introducer.rs` | `TreeDiffError::CandidateLimitExceeded` |
| Seen response mismatch | `spiller.rs` | `SpillError::SeenResponseMismatch` |
| OID length mismatch | `spill_merge.rs` | `SpillError::OidLengthMismatch` |

## Source of Truth

| Concept | Source File |
|---------|-------------|
| Spill orchestrator | `crates/scanner-git/src/spiller.rs` |
| Spill statistics | `crates/scanner-git/src/spiller.rs` |
| Batch seen-store buffer | `crates/scanner-git/src/spiller.rs` |
| Candidate chunk | `crates/scanner-git/src/spill_chunk.rs` |
| Canonical ordering | `crates/scanner-git/src/spill_chunk.rs` |
| Per-OID canonical reduction | `crates/scanner-git/src/spill_chunk.rs` |
| K-way merge | `crates/scanner-git/src/spill_merge.rs` |
| Run file format | `crates/scanner-git/src/run_format.rs` |
| Run writer | `crates/scanner-git/src/run_writer.rs` |
| Run reader | `crates/scanner-git/src/run_reader.rs` |
| Spill limits | `crates/scanner-git/src/spill_limits.rs` |
| Byte arena | `crates/scanner-git/src/byte_arena.rs` |
| Spill arena (mmap) | `crates/scanner-git/src/spill_arena.rs` |
| Spill index (hash table) | `crates/scanner-git/src/object_store.rs` |
| Blob spill | `crates/scanner-git/src/blob_spill.rs` |
| Serial blob introducer | `crates/scanner-git/src/blob_introducer.rs` |
| Parallel blob introduction | `crates/scanner-git/src/blob_introducer.rs` |
| Worker result merge | `crates/scanner-git/src/blob_introducer.rs` |
| Seen sets (non-atomic) | `crates/scanner-git/src/blob_introducer.rs` |
| Loose OID hash set | `crates/scanner-git/src/blob_introducer.rs` |
| Blob intro stats | `crates/scanner-git/src/blob_introducer.rs` |
| Seen-blob store trait | `crates/scanner-git/src/seen_store.rs` |
| Seen-bitmap persister trait | `crates/scanner-git/src/seen_store.rs` |
| No-op seen-bitmap persister | `crates/scanner-git/src/seen_store.rs` |
| Unique blob sink trait | `crates/scanner-git/src/unique_blob.rs` |
| Tree diff limits | `crates/scanner-git/src/tree_diff_limits.rs` |

## Related Docs

- `docs/scanner-git/git-scanning.md`
- `docs/scanner-git/git-pack-execution.md`
- `docs/architecture-overview.md`
