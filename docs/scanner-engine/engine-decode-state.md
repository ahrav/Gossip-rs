# Engine Decode State Module

## Overview

The `decode_state` module is responsible for managing the decode step arena and decoded-byte slab during transform scanning. It provides memory-efficient infrastructure for tracking the provenance of findings (how they were derived through a chain of transforms) and storing the bytes produced by decode operations, without requiring per-finding memory allocations on the hot path.

## Module Purpose: Decode Step Arena Management

The decode state module serves two critical functions:

1. **Provenance Tracking**: Records how each decoded buffer was produced via a chain of transforms, so findings can be reported with their full transformation history without storing complete vectors per finding.

2. **Decoded Byte Storage**: Provides a bounded decode buffer for storing decoded output, allowing work items to carry references to decoded ranges instead of owning independent allocations.

Both data structures are reset between scans to maintain the correctness of `StepId` and range indices, and are sized to support bounded memory usage even under adversarial input.

## Step Chain Representation

### The Parent-Linked Arena Model

Decode steps are stored in a parent-linked arena (`StepArena`), where each node contains:
- A compact internal step payload (`CompactDecodeStep`) that round-trips to `DecodeStep`
- A back-pointer (`parent`) to the previous step in the chain
- An index (`StepId`) into the arena's nodes

Steps are chained from a leaf finding back to the root buffer via parent pointers. For example:
- Root (STEP_ROOT) → Transform 1 → Transform 2 → Found Finding

This chain is stored in leaf-to-root order naturally during scanning (as new steps are appended), and is reversed to root-to-leaf order when materialized for reporting.

### Why Parent-Linked?

The arena uses parent pointers rather than storing complete step vectors per finding because:

1. **Provenance Sharing**: Multiple findings from the same decoded buffer can share a single decode chain, reducing memory usage by an order of magnitude.

2. **Hot-Path Efficiency**: Findings record only a `StepId` (a single `u32`), not a full `Vec<DecodeStep>`. This keeps hot-path allocations constant.

3. **O(1) Recording**: Appending a new step to the arena is constant-time; materialization to a full sequence is O(depth), which is typically small (max 8 steps).

### Step Chain Example

```
Buffer hierarchy during scanning:
  Original Input (STEP_ROOT)
      ↓ [URL decode span 10..100]
  Decoded Buffer 1
      ↓ [Base64 decode span 20..80]
  Decoded Buffer 2 (finding discovered here)

Arena nodes:
  idx=0: DecodeStep::Transform { transform_idx: 0, parent_span: 10..100 },
         parent: STEP_ROOT
  idx=1: DecodeStep::Transform { transform_idx: 1, parent_span: 20..80 },
         parent: StepId(0)

Finding provenance: StepId(1)
Materialized chain (after reversal):
  [
    DecodeStep::Transform { transform_idx: 0, parent_span: 10..100 },  // root → buffer 1
    DecodeStep::Transform { transform_idx: 1, parent_span: 20..80 },   // buffer 1 → buffer 2
  ]
```

## Provenance Tracking

### Why Maintain Provenance?

Provenance allows:
1. **Reproducibility**: End users can manually re-apply transforms to verify findings.
2. **Debugging**: Security teams can trace how a malicious payload was discovered.
3. **Rule Optimization**: Analytics can show which transform chains are most productive.
4. **Correctness Assurance**: Findings carry evidence of their origin buffer.

### Types of Decode Steps

Two types of `DecodeStep` are tracked:

#### 1. Transform Steps
```rust
DecodeStep::Transform {
    transform_idx: usize,        // Which transform (index into Engine::transforms)
    parent_span: Range<usize>,   // Span in the parent buffer that was decoded
}
```
Represents a queued transform (e.g., Base64, URL percent) applied to a span.

#### 2. UTF-16 Variant Steps
```rust
DecodeStep::Utf16Window {
    endianness: Utf16Endianness,  // LE or BE
    parent_span: Range<usize>,    // Span interpreted as UTF-16
}
```
Represents a local UTF-16 reinterpretation used when an anchor variant (UTF-16LE or UTF-16BE) matches. This allows consumers to replay the same transformation locally.

### Provenance Materialization

When a finding is emitted, its `StepId` is traced through the arena:

```rust
pub(super) fn materialize(&self, mut id: StepId, out: &mut ScratchVec<DecodeStep>) {
    out.clear();
    while id != STEP_ROOT {
        let cur = id;
        let node = &self.nodes[cur.0 as usize];
        out.push(node.step.to_decode_step());
        id = node.parent;
    }
    // Reverse to root-to-leaf order
    let len = out.len();
    for i in 0..len / 2 {
        out.as_mut_slice().swap(i, len - 1 - i);
    }
}
```

This is O(depth), and depth is bounded by `MAX_DECODE_STEPS` (8).

## Arena Allocation

### StepArena Structure

```rust
pub(super) struct StepArena {
    pub(super) nodes: ScratchVec<StepNode>,
}
```

The arena stores nodes in a `ScratchVec`, which is a reusable allocation buffer. Key properties:

- **Append-Only**: Nodes are only ever appended; StepIds remain valid until reset.
- **Fixed Capacity**: Bounded by a scan-level limit to prevent unbounded memory growth.
- **Reset Between Scans**: All StepIds are invalidated when the arena is reset, preventing use-after-reset bugs.

### Memory Layout

Each `StepNode` contains:
```rust
pub(super) struct StepNode {
    pub(super) parent: StepId, // 4 bytes
    step: CompactDecodeStep,   // 12 bytes
}
```

Total: 16 bytes per step (`assert!(size_of::<StepNode>() == 16)` in code). `CompactDecodeStep` is used because public `DecodeStep` is larger on 64-bit targets.

### Performance Characteristics

- **Push Operation**: O(1), amortized; no allocations if capacity is pre-sized.
- **Materialize Operation**: O(depth), where depth ≤ 8. No allocations if the output buffer is pre-allocated.
- **Memory Usage**: Shared across all findings in a scan; reused entirely between scans.

## Decoded Byte Storage: DecodeSlab

### Purpose

The `DecodeSlab` stores decoded bytes in an append-first buffer with rollback truncation on failure/dedupe:

```rust
pub(super) struct DecodeSlab {
    pub(super) buf: Vec<u8>,
    pub(super) limit: usize,
}
```

Instead of each transform allocation returning a new `Vec<u8>`, decoders append into the slab and receive a `Range<usize>` pointing to their decoded output.

### Why a Slab?

1. **Allocation Consolidation**: One large buffer instead of many small allocations per transform.
2. **Deduplication**: Multiple work items can reference the same decoded span without duplication.
3. **Bounded Memory**: The slab's capacity is capped at the global decode budget, preventing unbounded growth.
4. **Cache Locality**: Contiguous storage improves cache performance for subsequent scans.

### Budget Enforcement

The slab enforces a three-level budget hierarchy:

```rust
pub(super) fn append_stream_decode(
    &mut self,
    tc: &TransformConfig,
    input: &[u8],
    max_out: usize,                             // Per-transform budget
    ctx_total_decode_output_bytes: &mut usize,  // Scan-level tracker
    global_limit: usize,                        // Scan-level budget
) -> Result<Range<usize>, ()>
```

Budgets checked (in order):
1. **Per-Transform Budget** (`max_out`): Maximum decoded bytes for a single transform application.
2. **Scan-Level Budget** (`global_limit`): Total decoded bytes across all transforms in a scan.
3. **Slab Capacity** (`self.limit`): Hard cap on the slab buffer itself.

All three must be satisfied for a decode to succeed.

### Rollback on Failure

If any budget is exceeded, or if decoding errors, the slab is rolled back to its pre-call state:

```rust
if res.is_err() || truncated || local_out == 0 || local_out > max_out {
    self.buf.truncate(start_len);
    *ctx_total_decode_output_bytes = start_ctx;
    return Err(());
}
```

This ensures partial decodes don't pollute the slab.

### Lifetime Guarantees

Ranges returned from `append_stream_decode` are valid:
- Until the slab is reset (between scans)
- Until explicit truncation (rollback/dedupe paths can truncate during a scan)

All ranges are invalidated atomically when `reset()` is called, preventing use-after-reset bugs.

## Integration with the Engine

### Ownership Model

Both `StepArena` and `DecodeSlab` are owned by `ScanScratch`, the per-scan scratch state:

```rust
pub struct ScanScratch {
    pub(super) slab: DecodeSlab,
    pub(super) step_arena: StepArena,
    pub(super) steps_buf: ScratchVec<DecodeStep>, // Temp buffer for materialization
    // ... other scan state
}
```

`ScanScratch` is reused across chunks and reset at the start of each new scan.

### Work Flow: Recording and Materialization

#### Hot Path (Recording)
1. Transform decoder appends bytes to `slab`, gets `Range<usize>` back.
2. Work item carries the range, not the bytes.
3. Finding detector records a compact `FindingRec` with:
   - A `StepId` (pointing into `step_arena`)
   - The span within the decoded range
   - Rule and variant IDs
4. No allocations or cloning on the hot path.

#### Cold Path (Materialization)
1. When findings are drained or reported, each `FindingRec` is expanded into a full `Finding`.
2. The `StepId` is materialized into a full step chain using `step_arena.materialize()`.
3. The `Finding` struct includes the materialized `DecodeSteps` sequence.

### Reset Sequence

Between scans (or chunks with independent decode budgets):
```rust
step_arena.reset();    // Clear all nodes; invalidate all StepIds
slab.reset();          // Clear all decoded bytes; invalidate all ranges
```

This atomically invalidates all references, preventing use-after-reset bugs.

## Key Types

### StepArena
- **Purpose**: Parent-linked arena for decode step provenance.
- **Lifetime**: Valid for one scan; reset at the beginning of the next.
- **Key Operations**:
  - `push(parent: StepId, step: DecodeStep) -> StepId`: Append a step and get its ID.
  - `materialize(id: StepId, out: &mut ScratchVec<DecodeStep>)`: Reconstruct the root-to-leaf chain.
  - `reset()`: Clear all nodes and invalidate all IDs.

### StepNode
- **Purpose**: Node in the arena, linking a decode step to its parent.
- **Contents**: `parent: StepId` and compact `step: CompactDecodeStep`.

### StepId
- **Purpose**: Opaque handle to a step in the arena.
- **Representation**: `u32` index into arena nodes.
- **Sentinel**: `STEP_ROOT` (u32::MAX) marks the root of a provenance chain.
- **Invariant**: Valid only while the originating arena is alive and not reset.

### DecodeStep
- **Purpose**: Represents a single decode operation in the provenance chain.
- **Variants**:
  - `Transform { transform_idx: usize, parent_span: Range<usize> }`: A queued transform.
  - `Utf16Window { endianness: Utf16Endianness, parent_span: Range<usize> }`: UTF-16 reinterpretation.

### DecodeSlab
- **Purpose**: Append-only buffer for all decoded output.
- **Lifetime**: Valid for one scan; ranges invalidated on reset.
- **Key Operations**:
  - `append_stream_decode(...)`: Decode input, enforce budgets, append to slab, return range.
  - `reset()`: Clear buffer and invalidate all ranges.
  - `slice(r: Range<usize>) -> &[u8]`: Access decoded bytes by range.

### DecodeSteps
- **Purpose**: Fixed-capacity container for a materialized decode chain.
- **Type**: `FixedVec<DecodeStep, MAX_DECODE_STEPS>` (8 steps max).
- **Storage**: Inline in each `Finding`, so no heap allocation.

## Performance Summary

| Operation | Complexity | Allocation | Notes |
|-----------|-----------|-----------|-------|
| `StepArena::push` | O(1) | No | Append to ScratchVec |
| `StepArena::materialize` | O(depth) | Temp (steps_buf) | Depth ≤ 8; no allocation if pre-sized |
| `DecodeSlab::append_stream_decode` | O(decoded_len) | No (if in budget) | Streaming decode; budgets enforced |
| `DecodeSlab::reset` | O(1) | No | Clears buffer; invalidates ranges |
| Finding materialization | O(depth) | Caller-dependent | Provenance chain reconstructed once |

## Design Rationale

### Why Not Store Steps Per-Finding?

**Problem**: If each `FindingRec` stored its own `Vec<DecodeStep>`, findings from the same decoded buffer would duplicate the provenance chain.

**Solution**: Shared parent-linked arena allows findings to record only a `StepId`, with lazy materialization on output.

**Benefit**: Reduces per-finding memory from ~100+ bytes (vector overhead) to 4 bytes (StepId).

### Why Not Pre-Allocate All Decoded Buffers?

**Problem**: Decode spans are data-dependent and unpredictable; pre-allocation wastes memory or fails.

**Solution**: A streaming slab appends decoded bytes and rolls back on errors/dedupe, enabling on-demand decode within strict budgets.

**Benefit**: Bounded memory usage and no per-span allocation overhead, with range lifetimes defined by reset/truncation boundaries.

### Why Reset Between Scans?

**Problem**: If IDs and ranges persisted across scans, old references could be misinterpreted after reuse.

**Solution**: Atomic reset invalidates all references; next scan starts fresh.

**Benefit**: Prevents subtle use-after-reset bugs; enables simple, fast reset (just `clear()`).

## Constraints and Limits

- **MAX_DECODE_STEPS**: Compile-time hard cap of 8 steps per finding chain. Engine build asserts `tuning.max_transform_depth + 1 <= MAX_DECODE_STEPS`.
- **Slab Capacity**: Set to the global decode budget; enforced at decode time.
- **Arena Capacity**: Pre-sized from tuning/rule counts in scratch setup; `ScratchVec` is fixed-capacity, so overrun is a logic error (debug-asserted).
- **Budget Overflow**: If any budget is exceeded during a decode, the decode is aborted and rolled back; no partial state is retained.

## Related Modules

- `scratch.rs`: Owns and manages `ScanScratch`, which embeds both `StepArena` and `DecodeSlab`.
- `work_items.rs`: Carries decoded spans (ranges) during work distribution.
- `transform.rs`: Implements `stream_decode`, which emits decode chunks consumed by `DecodeSlab::append_stream_decode`.
- `core.rs`: Orchestrates the scan loop and coordinates reset.
