# Scheduler Engine Abstraction Layer

## Module Purpose

The `scheduler::engine_trait` module defines a trait-based abstraction layer that decouples the scheduler from specific detection engine implementations. This abstraction enables the scheduler to work seamlessly with both **mock engines** (for testing) and **real production engines** (for actual secret scanning).

The module exports four core traits and one carrier type:
- **`ScanEngine`** - The primary scanning interface
- **`EngineScratch`** - Per-worker scratch state management
- **`FindingRecord`** - Finding representation abstraction
- **`FindingWithHashRecord`** - Extension of `FindingRecord` that carries normalized secret hash bytes
- **`FindingWithHash<F>`** - Generic carrier type that bundles a finding with its `NormHash`

This design allows the scheduler logic to remain engine-agnostic while supporting different underlying implementations with varying data types and behaviors.

---

## ScanEngine Trait

### Purpose

`ScanEngine` defines the primary interface that the scheduler uses to perform chunk-based scanning operations. It abstracts the core functionality without coupling to a specific engine implementation.

### Key Characteristics

- **Stateless Design**: The engine itself is immutable and can be safely shared across all worker threads (`Send + Sync`)
- **Per-Worker State**: All mutable state is isolated in the associated `Scratch` type, ensuring thread safety without synchronization overhead
- **Overlapping Chunks**: The engine declares a `required_overlap()` that the scheduler must respect when dividing work

### Core Methods

#### `required_overlap() -> usize`

**Purpose**: Returns the minimum byte overlap required between consecutive chunks.

**Contract**: The scheduler guarantees that if chunk N spans `[base, base + len)`, chunk N+1 will start no later than `base + len - overlap`, ensuring no findings are missed at boundaries.

**Example**: If a rule needs to match across boundaries, it might require 100 bytes of overlap to capture patterns that span chunk edges.

#### `new_scratch(&self) -> Self::Scratch`

**Purpose**: Creates a fresh `Scratch` instance for a worker thread.

**Contract**: Called once per worker at startup. The returned scratch is reused across all chunks processed by that worker, avoiding repeated allocations.

**Usage**: The scheduler calls this during worker thread initialization to set up per-thread state.

#### `scan_chunk_into(&self, data: &[u8], file_id: FileId, base_offset: u64, scratch: &mut Self::Scratch)`

**Purpose**: Scans a data buffer and appends findings to the scratch space.

**Parameters**:
- `data`: The chunk to scan
- `file_id`: Identifier of the file being scanned (for attribution)
- `base_offset`: Absolute byte offset of `data[0]` in the original file
- `scratch`: The worker's per-thread scratch space to accumulate findings

**Contract**: Findings are reported with absolute byte offsets (not relative to the chunk). The scheduler is responsible for deduplication via `scratch.drop_prefix_findings()`.

**Archive note**: When scanning archive entries, the scheduler supplies **virtual `FileId` values**
in a dedicated high‑bit namespace. This ensures per-entry engine state isolation and prevents
collisions with real filesystem file IDs.

#### `rule_name(&self, rule_id: u32) -> &str`

**Purpose**: Retrieves the human-readable name of a rule by its ID.

**Contract**: Returns the rule name on success; returns `"<unknown-rule>"` for invalid IDs. Used for output formatting and reporting.

---

## EngineScratch Trait

### Purpose

`EngineScratch` abstracts the per-worker scratch memory used to accumulate findings during scanning. Each worker thread has its own scratch instance, ensuring thread-safe finding collection without locks.

### Key Characteristics

- **Thread-Local**: One instance per worker, never shared across threads
- **Reusable**: Scratch is reused across chunks to minimize allocations
- **Deduplication-Aware**: Provides methods to manage findings at chunk boundaries

### Associated Type

#### `type Finding: FindingWithHashRecord`

Specifies the finding type produced by this scratch. The bound was elevated from `FindingRecord` to `FindingWithHashRecord` to ensure every finding carries a normalized secret hash for persistence plumbing. This associated type allows different engines to use their own finding representations while maintaining a common trait interface that includes hash access.

### Core Methods

#### `clear(&mut self)`

**Purpose**: Clears all accumulated findings, preparing the scratch for a new scan.

**Contract**: After calling `clear()`, `drain_findings_into()` yields no findings.

**Typical Usage**: Available as an implementation reset hook. Current scheduler scan loops call `scan_chunk_into()`, `drop_prefix_findings()`, and `drain_findings_into()` per chunk.

#### `drop_prefix_findings(&mut self, new_bytes_start: u64)`

**Purpose**: Implements overlap-based deduplication by removing findings that "belong" to the previous chunk.

**Parameters**:
- `new_bytes_start`: Absolute byte offset where "new" (non-overlapping) bytes begin

**Semantics**: A finding is dropped if `finding.root_hint_end() < new_bytes_start` because:
- That finding will already be detected by the chunk that covers those bytes
- Keeping it would result in duplicate reports

**Example**: If chunk 1 spans bytes [0, 1000) and chunk 2 spans [900, 1800):
- Overlap region: [900, 1000)
- Findings with `root_hint_end < 900` are dropped (duplicates from chunk 1)
- Findings with `root_hint_end >= 900` are kept (only found in chunk 2's new bytes)

#### `drain_findings_into(&mut self, out: &mut Vec<Self::Finding>)`

**Purpose**: Transfers all remaining findings from the scratch to an output vector.

**Contract**: Findings are **appended** to `out`; the caller is responsible for clearing `out` beforehand if a fresh batch is desired. The scratch's internal finding buffer is empty after this call. Implementations should transfer ownership without extra allocation when possible (e.g., `Vec::append` or `drain(..)` into `out`).

**Usage**: Called after processing each chunk to extract findings for output or further processing.

#### `dropped_findings(&self) -> u64`

**Purpose**: Returns the count of findings dropped by the engine due to per-scan capacity limits (e.g., `max_findings_per_chunk` tuning).

**Contract**: Default implementation returns 0. Used for run-level loss accounting in persistence backends via `FsRunLoss`.

---

## FindingRecord Trait

### Purpose

`FindingRecord` abstracts the representation of a single finding (a matched secret/pattern), allowing different engines to use their own finding types. It defines the common interface for querying finding metadata.

### Type Constraints

- **`Clone`**: Findings must be cloneable for efficient buffer accumulation
- **`Send`**: Findings must be sendable across thread boundaries (though used thread-locally)
- **`'static`**: No borrowed data; findings are self-contained

### Required Methods

#### `rule_id(&self) -> u32`

**Purpose**: Returns the ID of the rule that matched.

**Returns**: A `u32` rule ID (normalized across different engine types)

#### `root_hint_start(&self) -> u64`

**Purpose**: Returns the start byte offset of the finding in the original buffer.

**Usage**: Used for cross-chunk deduplication. Under the trait contract, findings with `root_hint_end < new_bytes_start` are dropped.

#### `root_hint_end(&self) -> u64`

**Purpose**: Returns the end byte offset (exclusive) of the finding's "root hint" region.

**Semantics**: This is the critical deduplication boundary. Findings are deduplicated using `root_hint_end < new_bytes_start`.

#### `span_start(&self) -> u64`

**Purpose**: Returns the start of the full match span (the actual matched content).

**Usage**: The span may differ from the root hint:
- Root hint: The region used for deduplication
- Span: The actual matched content (may be wider for context)

#### `span_end(&self) -> u64`

**Purpose**: Returns the end (exclusive) of the full match span.

**Contract**: Typically `span_end >= root_hint_end` to capture the full matched region.

### Deduplication Semantics

Findings use a two-level deduplication strategy:

1. **Cross-Chunk Deduplication** (`root_hint` fields):
   - Findings with `root_hint_end < new_bytes_start` are dropped
   - Prevents reporting the same finding multiple times across overlapping chunks

2. **Within-Chunk Uniqueness** (`span` + `norm_hash` fields):
   - Two findings with the same `root_hint` but different spans are distinct
   - Two findings at the same span but with different `norm_hash` values are preserved (different secrets at the same location)
   - Allows multiple matches or transformed variants of the same secret

---

## FindingWithHashRecord Trait

### Purpose

`FindingWithHashRecord` extends `FindingRecord` to carry normalized secret hash bytes alongside finding metadata. This trait enables persistence backends to deduplicate findings across runs without storing raw secret bytes.

### Type Constraints

Inherits all constraints from `FindingRecord` (`Clone`, `Send`, `'static`).

### Required Method

#### `norm_hash(&self) -> &NormHash`

**Purpose**: Returns the BLAKE3 digest of the normalized (whitespace-collapsed, case-folded) secret value.

**Semantics**: Two findings with the same `norm_hash` matched the same logical secret, even if their byte spans differ due to surrounding context or transform chains.

**Usage**: Used by within-chunk dedup (as an additional dedup key), persistence batch construction, and cross-run deduplication in the store backend.

---

## FindingWithHash Carrier Type

### Purpose

`FindingWithHash<F: FindingRecord>` is a generic wrapper that bundles a finding record with its normalized secret hash. It implements both `FindingRecord` (delegating to the inner finding) and `FindingWithHashRecord` (returning the hash).

### Structure

```rust
pub struct FindingWithHash<F: FindingRecord> {
    pub finding: F,
    pub norm_hash: NormHash,  // [u8; 32]
}
```

### Why Bundle the Hash with the Finding?

The engine computes a normalized hash of the matched secret at scan time (inside `scan_chunk_into`). This hash must travel with the finding through overlap dedup, within-chunk dedup, and final emission. Storing them in separate parallel vectors is fragile — any sort, filter, or drain would require coordinating two collections. Bundling into a single value type makes the 1:1 alignment structural and impossible to violate.

### Implementations

Both the real engine adapter and mock engine produce `FindingWithHash<F>` values:

| Engine | `F` type | Hash source |
|--------|----------|-------------|
| Real (`engine_impl`) | `api::FindingRec` | Engine-computed BLAKE3 of normalized secret |
| Mock (`engine_stub`) | `FindingRec` | Deterministic placeholder hash |

---

## Why Traits? Benefits of Abstraction

### 1. **Testability**

The trait abstraction enables **mock implementations** for testing:
- Mock engine and scratch provide deterministic, controllable behavior
- Scheduler logic can be tested without real scanning engines
- No need for expensive file I/O or secret detection in unit tests

**Example**: `engine_stub::MockEngine` and `engine_stub::ScanScratch` provide test implementations with minimal overhead.

### 2. **Implementation Flexibility**

Different engines can provide their own optimizations:
- Mock engine: Simple in-memory finding accumulation
- Real engine: Optimized SIMD scanning, specialized memory layouts
- Both work seamlessly with the same scheduler code

### 3. **Type Compatibility**

The traits bridge type differences between implementations:

| Aspect | Mock Engine | Real Engine |
|--------|-------------|-------------|
| Rule ID | `RuleId(u16)` | `u32` |
| Span Offsets | `u64` | `u32` (exposed as `u64` via trait) |
| Root Hint Offsets | `u64` | `u64` |
| Finding Type | `FindingWithHash<FindingRec>` | `FindingWithHash<api::FindingRec>` |
| Norm Hash | Deterministic placeholder | Engine-computed BLAKE3 |
| File ID in finding record | Not stored | `FileId` |
| Decode step/provenance | Not stored | `StepId` |

The traits normalize these via their method signatures (all return `u32` for rule IDs, `u64` for offsets).

### 4. **Thread Safety Without Locks**

The design separates concerns:
- `ScanEngine` is `Sync`: Can be safely shared across threads
- `EngineScratch` is thread-local: No synchronization needed
- No mutex/atomic operations in the hot path

### 5. **Separation of Concerns**

The scheduler doesn't need to know:
- How the engine represents findings internally
- What data structures the engine uses
- Engine-specific optimization details

The scheduler only cares about the trait contract.

---

## Key Methods: Purpose and Contracts

### Overlap-Based Chunking Contract

The scheduler and engine collaborate to ensure no findings are missed:

```
Chunk 1: [0 ────────── 1000)
Chunk 2:         [900 ────────── 1800)
            └─ overlap ─┘

Findings with root_hint_end < 900 → dropped (dedup)
Findings with root_hint_end >= 900 → kept (new in chunk 2)
```

### Scratch Reuse Pattern

```rust
for file in files {
    for chunk in file.chunks() {
        engine.scan_chunk_into(&chunk, file_id, offset, &mut scratch);
        scratch.drop_prefix_findings(new_bytes_start);  // Dedup
        scratch.drain_findings_into(&mut output);  // Extract findings
    }
}
```

This pattern achieves:
- Single allocation per worker (scratch reused)
- O(1) drain operations (no copying)
- Automatic deduplication at chunk boundaries

---

## Implementation Notes: How Traits Enable Flexibility

### 1. **Mock Implementation for Testing**

```rust
// tests use MockEngine which:
// - Uses simple substring matching
// - Requires no production engine wiring
// - Enables deterministic scheduler tests

let engine = MockEngine::new(vec![/* MockRule values */], 16);
let mut scratch = engine.new_scratch();
engine.scan_chunk_into(b"SECRET123", FileId(0), 0, &mut scratch);
```

### 2. **Real Engine Implementation**

```rust
// Production uses crate::engine::Engine with trait impls from engine_impl:
// - impl ScanEngine for Engine
// - impl EngineScratch for RealEngineScratch
// - impl FindingRecord for api::FindingRec

let engine = crate::engine::Engine::new(rules, transforms, tuning);
// Same scheduler code, different backend
```

### 3. **Custom Finding Deduplication**

Different engines can customize deduplication by varying `root_hint` fields:

- **Strict dedup**: Make `root_hint == span` to deduplicate similar matches
- **Lenient dedup**: Use wider `root_hint` to allow overlapping matches
- **Context-aware**: Adjust dedup based on transformed content

### 4. **Testability Features**

Trait methods enable targeted testing:

```rust
#[test]
fn test_overlap_deduplication() {
    let engine = MockEngine::new(vec![], 16);
    let mut scratch = engine.new_scratch();
    scratch.drop_prefix_findings(900);
    let mut out = Vec::new();
    scratch.drain_findings_into(&mut out);
    assert!(out.is_empty());
}
```

### 5. **Performance Optimization**

The trait design allows engines to optimize:

- **Memory layout**: Engine chooses finding struct layout
- **Copying strategy**: `drain_findings_into` can swap buffers
- **Dedup performance**: Engine optimizes `drop_prefix_findings` logic

### 6. **Future Extensibility**

New engines can be added without modifying:
- Scheduler logic
- Worker thread code
- Deduplication logic
- Output formatting

Only a new trait implementation is needed.

---

## Thread Safety Model Visualization

```
┌──────────────────────────────────────────────────────┐
│               ScanEngine (Sync, Shared)              │
│        (created once, used by all workers)           │
└──────────────────────────────────────────────────────┘
                    │         │         │
         ┌──────────┴─────────┼─────────┴──────────┐
         │                    │                    │
         ▼                    ▼                    ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │  Worker 0   │   │  Worker 1   │   │  Worker N   │
    │             │   │             │   │             │
    │ Scratch 0   │   │ Scratch 1   │   │ Scratch N   │
    │(thread-loc) │   │(thread-loc) │   │(thread-loc) │
    └─────────────┘   └─────────────┘   └─────────────┘
```

**Key Properties**:
- Engine is immutable and safely shared (no synchronization)
- Each worker has isolated scratch (no contention)
- Findings are accumulated locally, extracted after each chunk
- No data is shared between workers during scanning

---

## Summary

The engine trait abstraction provides:

1. **Decoupling**: Scheduler is independent of engine type
2. **Testability**: Mock implementations enable unit testing
3. **Flexibility**: Different engines with different optimizations
4. **Type Normalization**: Bridges implementation-specific types
5. **Thread Safety**: Lock-free design with per-worker state
6. **Performance**: Efficient finding accumulation and deduplication
7. **Extensibility**: New engines without modifying core logic
