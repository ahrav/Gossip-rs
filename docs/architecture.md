# Scanner Architecture

## Overview

This crate scans byte streams for secret-like patterns using an anchor-first
approach. The design favors explicit memory budgets, bounded decoding, and
reusable scratch buffers so large scans do not trigger per-chunk allocations.

## Filesystem Flow (scan fs)

```
scanner-rs scan fs
  -> scan_fs (gossip-scanner-runtime)
  -> path + budget validation
  -> ordered_content::scan_local_filesystem (crates/gossip-scanner-runtime/src/ordered_content.rs)
```

The runtime crate owns the public filesystem entrypoint and validation surface.
The filesystem scan engine itself lives in `scanner-scheduler`:

```
filesystem engine backend
  -> parallel_scan_dir (crates/scanner-scheduler/src/scheduler/parallel_scan.rs)
  -> IterWalker (single-threaded discovery)
  -> scan_local (crates/scanner-scheduler/src/scheduler/local_fs_owner.rs)
       -> assign FileId per file task
       -> read chunk + overlap with TsBufferPool
       -> Engine::scan_chunk_into(...)
       -> drop_prefix_findings(...) for overlap dedupe
       -> emit CoreEvent::Finding via EventOutput
```

- `IterWalker` yields `LocalFile` values; `scan_local` assigns monotonic
  `FileId` values as work is enqueued.
- Workers do both file I/O and scanning in the same stage (no separate
  `ReaderStage`/`OutputStage` handoff in this path).
- Findings are written through `EventOutput` implementations
  (JSONL/Text/JSON/SARIF), and a final summary event is emitted by the
  orchestrator.

For direct synchronous library use,
`crates/scanner-scheduler/src/runtime.rs` still provides `ScannerRuntime` +
`read_file_chunks` with overlap-aware chunking.

## Engine Flow (per buffer)

```
Root buffer
  -> Anchor scan (raw + UTF-16 variants, Vectorscan)
  -> Window build and merge/coalesce
  -> Optional two-phase confirm + expand
  -> Regex validation (bytes regex)
  -> Transform worklist:
       - span detection
       - optional gate (anchors in decoded stream)
       - streaming decode into DecodeSlab
       - dedupe decoded output
       - enqueue WorkItem (bounded depth and count)
```

Key details:

- Anchors reduce work: regex is only applied inside windows around anchor hits.
- Two-phase rules (seed + confirm) keep noisy patterns cheaper: confirm in a
  smaller seed window, then expand to the full window.
- Transform decoding is gated by anchor checks in decoded output to avoid
  expensive full decodes when no anchors exist.
- Base64 adds an **encoded-space pre-gate** (YARA-style permutations) so spans
  that cannot possibly decode to an anchor are skipped before decoding.
- Budgets cap recursion depth, decoded bytes, and work items to prevent DoS.

## Core Data Structures

- TsBufferPool / TsBufferHandle
  Thread-safe fixed-capacity pool used by scheduler workers. Buffers are
  preallocated, worker-local queues are used on the fast path, and handles
  return buffers automatically on drop.

- BufferPool / BufferHandle (runtime path)
  Rc-backed single-threaded fixed-capacity pool used by `ScannerRuntime` and
  `read_file_chunks`.

- DecodeSlab
  Pre-allocated slab for decoded bytes. Transform decoders append into the slab
  and return ranges, so derived buffers are represented by offsets instead of
  heap allocations.

- StepArena and StepId
  Decode provenance is stored as a parent-linked arena. Findings carry a StepId
  that can be materialized into a DecodeStep chain without cloning vectors on
  the hot path.

- FixedSet128
  Small fixed-capacity hash set used to dedupe decoded buffers (128-bit keys).
  Generation counters make reset O(1) without clearing memory.

- HitAccPool (hit accumulator pool)
  Collects anchor hit windows for all (rule, variant) pairs and switches a pair
  to a single coalesced window when hit volume exceeds a configured limit.

## Findings and Spans

- FindingRec stores compact spans and a StepId. It is the hot-path format used
  during scanning.
- Finding is the materialized, user-facing format with DecodeStep chains and
  root-span hints for reporting.

## Extending the Scanner

- Add rules by supplying RuleSpec values (anchors + regex), optionally with
  TwoPhaseSpec to reduce false positives.
- Add transforms by extending TransformId and the transform dispatch helpers.
  Each transform should provide span detection, streaming decode, and gating
  where possible.
