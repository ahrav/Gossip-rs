# Git Scanning Pipeline

This document describes the end-to-end Git scanning pipeline, its persistence
contract, and ODB-blob attribution semantics.

## Flow Diagram

```mermaid
flowchart LR
    Cancel["Abort Flag"] -.-> Mode
    Cancel -.-> PackExec
    Cancel -.-> Finalize
    Preflight["Optional Preflight (metadata only)"] -.-> RepoOpen["Repo Open + Watermarks"]
    RepoOpen --> ArtifactAcquire["Artifact Acquire"]
    ArtifactAcquire --> CommitWalk["Commit Walk"]
    CommitWalk --> Mode{"Scan Mode"}
    Mode --> Diff["Diff-History: Tree Diff -> Spill -> Mapping"]
    Mode --> Odb["ODB-Blob: Blob Introduction"]
    Diff --> PackPlan["Pack Planning"]
    Odb --> PackPlan
    PackPlan --> PackExec["Pack Decode + Exec"]
    PackExec --> EngineAdapter["Engine Adapter"]
    EngineAdapter --> Finalize["Finalize Ops"]
    Finalize --> Persist["Persist (Data then Watermarks)"]
```

## Pipeline Components

| Component             | Location                                                                       | Purpose                                                                                                |
| --------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Preflight             | `crates/scanner-git/src/preflight.rs`                                          | Standalone metadata-only readiness check for commit-graph, MIDX, locks, and pack-count recommendations |
| Repo Open             | `crates/scanner-git/src/repo_open.rs`                                          | Resolve repo layout, start set + watermarks, and artifact lock paths                                   |
| Artifact Acquire      | `crates/scanner-git/src/artifact_acquire.rs`                                   | Build MIDX + commit-graph in memory and capture artifact fingerprint                                   |
| Commit Walk           | `crates/scanner-git/src/commit_walk.rs`                                        | `(watermark, tip]` traversal and topo ordering                                                         |
| Tree Diff             | `crates/scanner-git/src/tree_diff.rs`                                          | OID-only tree diffs that emit blob candidates                                                          |
| Spill + Dedupe        | `crates/scanner-git/src/spiller.rs`                                            | Global dedupe + seen-blob filtering with incremental seen-bitmap checkpoints                           |
| MIDX Mapping          | `crates/scanner-git/src/mapping_bridge.rs`                                     | Map unique blobs to pack offsets or loose fallback                                                     |
| Pack Planning         | `crates/scanner-git/src/pack_plan.rs`                                          | Build per-pack decode plans with delta closure                                                         |
| Pack Exec             | `crates/scanner-git/src/runner_exec.rs`, `crates/scanner-git/src/pack_exec.rs` | Scheduler-driven pack execution and decode with bounded buffers                                        |
| Engine Adapter        | `crates/scanner-git/src/engine_adapter.rs`                                     | Overlap-safe chunked scanning with deterministic finding keys                                          |
| Finalize              | `crates/scanner-git/src/finalize.rs`                                           | Build write ops for blob_ctx, finding, seen_blob, and watermarks                                       |
| Persist               | `crates/scanner-git/src/persist.rs`                                            | Two-phase persistence (data ops then watermarks)                                                       |
| ODB-Blob Pipeline     | `crates/scanner-git/src/runner_odb_blob.rs`                                    | Blob introduction + pack pipeline for ODB-blob mode                                                    |
| Diff-History Pipeline | `crates/scanner-git/src/runner_diff_history.rs`                                | Tree-diff/spill/mapping + pack pipeline for diff-history mode                                          |
| Runner                | `crates/scanner-git/src/runner.rs`                                             | End-to-end orchestration of all stages                                                                 |

## Determinism and Safety Invariants

- `run_git_scan` starts at repo open; preflight is an optional standalone readiness check.
- Repo open reads metadata only; no blob payloads are read before pack decoding.
- MIDX and commit-graph artifacts are built in memory by `artifact_acquire` and stored as byte views.
- Artifact fingerprints are captured after MIDX acquisition; runner revalidates artifact stability after build, before pack execution, and after mode execution.
- Preflight reports pack-count maintenance recommendations separately; pack count does not block scans.
- Pack execution mmaps are bounded by explicit pack count and total byte limits.
- Candidate ordering is deterministic through mode-specific ordering
  (spill/merge where used) and pack-exec result reassembly.
- In ODB-blob mode with `blob_intro_workers > 1`, unique blob discovery is
  stable, but blob attribution context (`commit_id`, path, flags) is
  race-winner based and can vary across worker counts.
- Findings are deduped per blob and stored as `(start, end, rule_id, norm_hash)`.
- No raw secret bytes are persisted; only hashes and metadata are stored.
- Persistence is atomic at finalize: data ops and (when complete) watermark ops are committed together.
- When a persistence store is configured, spill flushing also writes the
  seen-bitmap incrementally without advancing ref watermarks.
- Incremental correctness depends on `seen_blob` markers and ref watermarks;
  `blob_ctx` is metadata and is not a deterministic contract in parallel
  ODB-blob mode.
- Loose candidates are scanned via bounded loose-object decode; non-blob or
  missing loose objects are recorded as explicit skips.
- Any decode skips or missing/corrupt loose objects result in `FinalizeOutcome::Partial`.
- Skipped candidates are reported with explicit reasons; pack exec reports contain detailed decode errors.
- Pack decoding can be driven via a read-at reader for deterministic fault injection.
- Cancellation is cooperative: the caller-owned abort flag is checked at
  runner phase boundaries, commit loops, tree-walk hot loops, scheduler task
  launch sites, and loose-object decode boundaries.
- An aborted scan returns `GitScanError::TreeDiff(TreeDiffError::Aborted)` and
  skips finalize persistence instead of emitting partial durable state.

## Cooperative Cancellation

`run_git_scan` accepts a borrowed `AtomicBool` rather than owning its own
runtime token type. The runtime layer bridges its `CancellationToken` into this
interface with `CancellationToken::as_atomic()`, so local scans and the
distributed lease watchdog both drive the same cooperative stop signal.

Cancellation checks are intentionally tiered:

- Runner boundaries stop work before entering expensive phases such as pack
  execution, loose-object decoding, and finalize persistence.
- Commit-level checks in `run_odb_blob`, `run_diff_history`, and serial blob
  introduction prevent new commit work from starting once cancellation is set.
- Tree-walk hot loops (`BlobIntroducer::walk_stack` and
  `TreeDiffWalker::diff_trees`) sample the flag every 4096 processed entries to
  bound latency on deep or wide trees without adding a per-entry atomic load.
- Scheduler task launch combines the external abort signal with the scheduler's
  internal error latch so lease expiry and worker failure both stop additional
  pack work.

## Concurrency and Backpressure

Most stages before pack execution (preflight, repo open, commit walk, tree diff,
spill/dedupe, mapping) run **single-threaded**. Blob introduction (ODB-blob
mode) and pack execution introduce parallelism:

- **Blob introduction** (ODB-blob mode only) can run in parallel when
  `blob_intro_workers > 1`. The commit plan is pre-partitioned into
  `~4 × worker_count` chunks. Workers claim chunks via an atomic counter
  (work-stealing pattern), each with its own `ObjectStore` and
  `PackCandidateCollector`. A shared `AtomicSeenSets` (lock-free bitmap)
  ensures each tree/blob is claimed by exactly one worker. Cache budgets
  (tree cache, delta cache, spill arena, packed cap, loose cap, path arena)
  are divided per worker with floor/cap clamping. After all workers finish,
  results are merged and global caps are re-validated. The worker that first
  claims a blob determines that blob's emitted context (`commit_id`, path,
  flags), so attribution is not deterministic across worker counts. The shared
  external abort flag is OR'd with a local worker-error latch so lease expiry
  stops new chunk work without letting one worker mutate the caller-owned
  cancellation state.

- **Pack planning** is built on the runner thread before execution
  (`build_pack_plans` in diff-history, per-pack planning in ODB-blob mode).
- **Pack execution** runs through scheduler tasks selected by
  `PackExecStrategy` (`Serial`, `PackParallel`, `IntraPackSharded`). In
  sharded mode, plans use `shard_ranges()` over execution indices. Each
  worker owns its own `PackCache` and `EngineAdapter`, and outputs are
  reassembled in deterministic plan/shard order.
- **Auto-sized pack worker width** applies when the CLI omits `--workers`.
  The function `auto_pack_exec_workers_for_in_pack` receives the in-pack
  object count and selects `pack_exec_workers` by tier:
  - `< 100,000` in-pack objects: `1x` logical cores
  - `< 2,000,000` in-pack objects: `3x` logical cores
  - `>= 2,000,000` in-pack objects: `6x` logical cores

There are no in-flight queues between the serial stages; instead, each stage
enforces explicit bounds:

- Spill/dedupe caps (`SpillLimits`) limit candidate count and spill bytes.
- Mapping caps (`MappingBridgeConfig`) bound packed/loose candidate buffers.
- Pack planning limits (`PackPlanConfig`) bound delta expansion worklists.
- Pack execution limits (`PackMmapLimits`, `PackDecodeLimits`) bound mmaps and
  inflate sizes.

## Persistence Contract

Finalize produces two batches:

- `data_ops`: `bc\0` (blob_ctx), `fn\0` (finding), `sb\0` (seen_blob)
- `watermark_ops`: `rw` (ref_watermark)

Persist commits `data_ops` and (when complete) `watermark_ops` in a single
atomic batch. If the run is partial, watermark ops are skipped to avoid
advancing ref tips past unscanned blobs.

`blob_ctx` (`bc\0`) values are persisted metadata. They are not used for seen
filtering or watermark advancement and are not a cross-worker determinism
contract in parallel ODB-blob mode.

Intermediate stage checkpoints are persisted as opaque blobs owned by
`crates/scanner-git/src/checkpoint.rs`. Each blob is framed as
`[magic: 4][crc32_le: 4][postcard payload]`. Resume loads verify the magic
bytes, payload size, and CRC32 before deserializing state, and corrupt blobs
are discarded instead of restoring unchecked runner state. CRC32 here detects
accidental corruption; it is not a tamper-resistance mechanism.

## Simulation Harness

The Git simulation harness exercises this pipeline deterministically using a
semantic repo model and optional pack artifacts. It replays `.case.json`
artifacts and supports bounded random runs.

```bash
# Replay Git simulation corpus
cargo test --features sim-harness --test simulation git_scan_corpus

# Run bounded random Git simulations
cargo test --features sim-harness --test simulation git_scan_random
```

Corpus cases live in `crates/scanner-engine-integration-tests/tests/corpus/git_scan/*.case.json`. Replay failures emit
artifacts to `crates/scanner-engine-integration-tests/tests/failures/` for triage and minimization.

## Performance Architecture

### Delta Resolution

Pack delta chains are resolved using a two-phase iterative approach rather
than recursion. **Phase 1 (walk forward)** follows OFS delta base offsets
through the chain, collecting a lightweight `TreeDeltaFrame` per hop without
inflating any payloads. The walk terminates when a non-delta root object, a
delta cache hit, or a cross-pack REF delta base is reached. **Phase 2
(unwind backward)** iterates the frame stack in reverse, inflating each
delta payload and applying it against the current base using a ping-pong
buffer swap (`base_buf` and `result_buf` alternate roles via
`std::mem::swap`). This eliminates the per-hop `Vec` allocations and
unbounded stack growth that a recursive implementation would incur, and the
chain depth is bounded by `MAX_DELTA_DEPTH` (64).

### Spill Arena

Tree payloads that exceed the in-memory cache capacity are written to a
preallocated, memory-mapped spill file (`SpillArena`). The arena uses a
dual-mapping strategy: a `MmapMut` writer for sequential appends and a
shared read-only `Mmap` for zero-copy reads. An open-addressing hash table
(`SpillIndex`) with linear probing provides O(1) lookups by OID. Slot count
is power-of-two and bounded (64..1,048,576), derived from spill budget and
spill threshold to cap RAM usage. Hashing uses the first 8 OID bytes
interpreted as little-endian `u64` (no Murmur/fmix finalizer). This is used
because OIDs are already cryptographic hashes with high byte entropy, so extra
mixing is unnecessary and would add hot-path work. The index is best-effort
and append-only: once probing can no longer find an empty slot, new spills are
not indexed and those lookups fall back to pack/loose reads.

### Pack Execution Strategy

The runner selects one of three execution strategies based on worker count
and plan structure (`select_pack_exec_strategy`):

- **Serial** -- single-threaded execution, chosen when `workers <= 1`, no
  plans exist, or total decode work falls below `MIN_TOTAL_NEED_FOR_PARALLEL`.
- **PackParallel** -- one plan per worker with deterministic sequence
  reassembly, chosen when the number of pack plans is at least the worker
  count (i.e. enough independent packs to keep all workers busy).
- **IntraPackSharded** -- large single-pack plans are split into
  index-range shards, each executed by a separate worker. Shard counts are
  chosen adaptively per plan using cost hints (forward and external delta
  dependency counts) and a locality pressure estimator that measures
  cross-shard dependency crossings.

### Buffer Reuse

Several buffer reuse patterns eliminate per-object allocation on hot paths:

- **TreeDecodeBufs** -- persistent `inflate_buf`, `result_buf`, and
  `base_buf` vectors plus a pooled `delta_stack` that are reused across
  `read_pack_object` calls in the tree-loading `ObjectStore`. The
  decompressor is reset between inflations; buffers retain their capacity
  across calls.
- **InflateScratch** -- a `thread_local!` struct that merges a `Decompress`
  handle and a 64 KiB scratch buffer into a single TLS slot, halving the
  borrow overhead compared to two separate thread-locals. The `_with`
  inflate variants accept a caller-owned `Decompress` to bypass TLS
  entirely on reentrant or hot paths.
- **PackExecScratch** -- caller-owned decode scratch (`DecodeBufs` plus
  hot delta-dep and candidate-range vectors) that is `prepare()`d once per
  plan to reserve capacity and then reused across all offsets within a pack
  execution pass, avoiding per-offset allocations on the decode hot path.

## Related Docs

- `docs/architecture-overview.md`
- `docs/scanner-engine/detection-engine.md`
- `docs/scanner-git/git_simulation_harness_guide.md`
