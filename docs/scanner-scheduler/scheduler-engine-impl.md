# Scheduler Engine Implementation Module

**File**: `crates/scanner-scheduler/src/scheduler/engine_impl.rs`

This module implements the adapter layer connecting the scheduler's abstract engine traits to the production scanning engine. It enables the real `Engine` to work seamlessly with the scheduler's chunked scanning architecture.

---

## 1. Module Purpose

The `engine_impl` module provides **trait implementations** that bridge the gap between two different worlds:

- **Scheduler side**: Expects generic traits (`ScanEngine`, `EngineScratch`, `FindingRecord`, `FindingWithHashRecord`)
- **Engine side**: Has concrete types (`crate::engine::Engine`, `ScanScratch`, `FindingRec`, `NormHash`)

This decoupling allows:
- The scheduler to remain engine-agnostic (can work with mock or real engine)
- The engine implementation to evolve independently
- Testing to proceed in parallel (mock engine in `crates/scanner-scheduler/src/scheduler/engine_stub.rs`)
- Clear contract documentation through traits

**Key principle**: The scheduler doesn't directly call `Engine::scan_chunk_into()`. Instead, it calls through the `ScanEngine` trait, which is implemented here to forward to the real engine.

---

## 2. How Real Engine Wraps Traits

### Type Mapping

| Concept      | Scheduler Trait         | Real Engine Type                 | Wrapper                   |
| ------------ | ----------------------- | -------------------------------- | ------------------------- |
| Finding      | `FindingRecord`         | `crate::api::FindingRec`         | Direct impl (no wrapper)  |
| Finding+Hash | `FindingWithHashRecord` | `FindingWithHash<ApiFindingRec>` | `FindingWithHash` carrier |
| Scratch      | `EngineScratch`         | `crate::engine::ScanScratch`     | `RealEngineScratch`       |
| Engine       | `ScanEngine`            | `crate::engine::Engine`          | Direct impl               |

### Implementation Strategy

**For `FindingRecord` (lines 46-71)**:
```rust
impl FindingRecord for ApiFindingRec {
    fn rule_id(&self) -> u32 { self.rule_id }
    fn root_hint_start(&self) -> u64 { self.root_hint_start }
    fn root_hint_end(&self) -> u64 { self.root_hint_end }
    fn span_start(&self) -> u64 { u64::from(self.span_start) }
    fn span_end(&self) -> u64 { u64::from(self.span_end) }
    fn confidence_score(&self) -> i8 { self.confidence_score }
}
```

This is straightforward because `FindingRec` fields map directly to trait methods. The `span_start/end` conversion from `u32` to `u64` handles the real engine's compact representation.

**For `ScanEngine` (lines 181-208)**:
```rust
impl ScanEngine for Engine {
    type Scratch = RealEngineScratch;

    fn required_overlap(&self) -> usize { self.required_overlap() }
    fn new_scratch(&self) -> Self::Scratch {
        let scratch = self.new_scratch();
        RealEngineScratch::new(scratch, self.tuning.max_findings_per_chunk)
    }
    fn scan_chunk_into(&self, data, file_id, base_offset, scratch) {
        self.scan_chunk_into(data, file_id, base_offset, scratch.inner_mut())
    }
    fn rule_name(&self, rule_id) -> &str { self.rule_name(rule_id) }
}
```

The key insight: `RealEngineScratch` wraps the engine's native `ScanScratch` and adds the findings buffer for extraction.

---

## 3. Scratch Handoff: Per-Thread Management

### The Challenge

The real engine's scratch reset methods require an `&Engine` reference:

```rust
impl ScanScratch {
    fn reset_for_scan_after_prefilter(&mut self, engine: &Engine) {
        // Resets per-scan state using engine data while preserving prefilter hits
    }
}
```

But the trait method `clear()` doesn't have access to the engine:

```rust
pub trait EngineScratch {
    fn clear(&mut self);  // No engine reference available!
}
```

### The Solution: Lazy Reset Pattern

Instead of fighting the design, the module implements a **lazy reset** approach (lines 28-36, 148-154):

1. **In `RealEngineScratch::clear()`** (line 147-154):
   - Only clear the temporary `findings_buf` (our local drain buffer)
   - Do NOT reset the underlying engine scratch state
   - This is a no-op for the real scratch's internal state

2. **In `Engine::scan_chunk_into()`** (line 194-203):
   - The real engine owns scratch lifecycle internally (capacity validation + per-scan state reset on scan path)
   - This happens in the real engine code, not in the trait adapter
   - The engine has the `&Engine` reference needed for its reset methods

### Lifecycle Per Worker

```
Worker Thread Creation:
  ├─ Engine::new_scratch() → RealScanScratch
  ├─ RealEngineScratch::new(scratch, max_findings)
  │  ├─ Creates findings_buf with capacity
  │  └─ Creates norm_hash_buf with capacity
  └─ Stored in WorkerCtx (thread-local)

For Each File:
  ├─ Optional: scratch.clear() → clears findings_buf + norm_hash_buf only
  └─ For Each Chunk:
     ├─ scan_chunk_into()
     │  ├─ Engine handles internal scratch reset/validation as part of scan
     │  ├─ Scans chunk, appends findings + norm_hashes to real ScanScratch
     │  └─ Findings and hashes now in scratch.scratch
     ├─ drop_prefix_findings() → delegates to real scratch
     └─ drain_findings_into()
        ├─ Real scratch.drain_findings_with_hashes() → findings_buf + norm_hash_buf
        ├─ Zip findings with aligned hashes → FindingWithHash carriers
        └─ Append FindingWithHash values → out vector
```

### Why This Works

- **Zero adapter-level resets**: Scratch reset logic stays inside the engine scan path
- **Clean trait interface**: The scheduler doesn't need to know engine internals
- **Low overhead**: The drain buffer is reused across chunks to avoid repeated allocations

---

## 4. Adapter Pattern: Why and What It Bridges

### The Adapter Pattern in Action

This module is a classic **Adapter** pattern (also called **Wrapper**):

```
┌─────────────────────────────────────────────────────────────┐
│ Scheduler (uses ScanEngine trait)                          │
│ - new_scratch()                                             │
│ - scan_chunk_into()                                         │
│ - required_overlap()                                        │
└───────────────────────┬─────────────────────────────────────┘
                        │ implements
                        │ ScanEngine trait
                        ▼
    ┌──────────────────────────────────────┐
    │ Engine (with ScanEngine impl)        │
    │ from engine_impl.rs                  │
    └────────┬─────────────────────────────┘
             │ forwards to
             ▼
    ┌──────────────────────────────────────┐
    │ crate::engine::Engine (real impl)    │
    │ - new_scratch()                      │
    │ - scan_chunk_into()                  │
    │ - required_overlap()                 │
    └──────────────────────────────────────┘
```

### Impedance Mismatches Resolved

| Problem                                                                                | Solution                                                             |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Trait needs `&mut Self::Scratch` in `clear()`, but engine reset methods need `&Engine` | Lazy reset pattern                                                   |
| Finding types differ slightly (u32 vs u16 for rule_id)                                 | Type conversion in trait impl                                        |
| Engine returns `ScanScratch`, trait expects `RealEngineScratch`                        | `RealEngineScratch::new()` wrapper                                   |
| Findings need extraction from engine scratch                                           | `drain_findings_into()` buffer pattern                               |
| Findings and hashes stored in parallel vectors in engine scratch                       | `drain_findings_with_hashes()` + zip into `FindingWithHash` carriers |

### Benefits of This Approach

1. **Flexibility**: Scheduler works with any `ScanEngine` impl (mock or real)
2. **Maintainability**: Engine changes don't require scheduler changes
3. **Testability**: Mock engine can have different scratch behavior
4. **Clarity**: Trait defines the contract explicitly

---

## 5. Key Structures

### `RealEngineScratch` (lines 94-149)

```rust
pub struct RealEngineScratch {
    scratch: RealScanScratch,           // The real engine's native scratch
    findings_buf: Vec<ApiFindingRec>,   // Temporary drain buffer (findings)
    norm_hash_buf: Vec<NormHash>,       // Temporary drain buffer (hashes)
}
```

**Purpose**: Wraps the real `ScanScratch` and provides trait compliance.

**Fields**:
- `scratch`: Stores pattern match state, findings lists, etc. from the real engine
- `findings_buf`: A pre-allocated buffer used to extract findings from the real scratch
  - Reused across chunk drains to minimize allocations
  - Sized to `max_findings_per_chunk` at creation
- `norm_hash_buf`: A pre-allocated buffer for extracting `NormHash` values aligned with `findings_buf`
  - Sized identically to `findings_buf` at creation
  - Drained in lockstep with findings to construct `FindingWithHash` carriers

**Methods**:
- `new(scratch, max_findings)`: Wraps a real scratch with findings and hash buffers
- `inner_mut()`: Provides mutable access for the engine's `scan_chunk_into()`

### `RealScanScratch` (from `crate::engine`)

Not defined here, but conceptually:
- Holds internal Vectorscan pattern state
- Accumulates findings during scanning
- Provides reset/validation helpers (`reset_for_scan_after_prefilter()`, `ensure_capacity()`), plus finding APIs (`drop_prefix_findings()`, `drain_findings()`)

### `ApiFindingRec` (from `crate::api`)

The real engine's finding type:
```rust
pub struct FindingRec {
    pub rule_id: u32,
    pub root_hint_start: u64,
    pub root_hint_end: u64,
    pub span_start: u32,      // Note: u32, not u64
    pub span_end: u32,
    pub file_id: FileId,
    pub step_id: StepId,
    pub confidence_score: i8,
}
```

Maps directly to the `FindingRecord` trait methods.

---

## 6. Performance Considerations

### Buffered Findings Extraction

**The Pattern** (lines 168-197):

```rust
fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
    self.findings_buf.clear();
    self.norm_hash_buf.clear();
    let pending = self.scratch.pending_findings_len();
    // Ensure capacity for both buffers
    if self.findings_buf.capacity() < pending {
        self.findings_buf.reserve(pending);
    }
    if self.norm_hash_buf.capacity() < pending {
        self.norm_hash_buf.reserve(pending);
    }
    // Drain findings and hashes into separate buffers
    self.scratch.drain_findings_with_hashes(
        &mut self.findings_buf, &mut self.norm_hash_buf,
    );
    // Zip and append as FindingWithHash carriers
    out.reserve(self.findings_buf.len());
    for (finding, norm_hash) in self.findings_buf.drain(..)
        .zip(self.norm_hash_buf.drain(..))
    {
        out.push(FindingWithHash::new(finding, norm_hash));
    }
}
```

**How it works**:
1. `drain_findings_with_hashes()` moves findings and hashes into separate buffers
2. Zip iterator pairs each finding with its aligned hash
3. Each pair is wrapped in a `FindingWithHash` carrier and appended to `out`
4. Both buffers retain capacity for reuse across chunks

**Cost**: O(n) moves for `drain_findings_with_hashes()` + O(n) `FindingWithHash` construction, typically without extra allocations once buffers are sized

### Thread-Local Scratch Benefits

**Key insight** (lines 100-127): Each worker gets its own `RealEngineScratch`

**Advantages**:
- No lock contention (scratch is never shared)
- No cache line bouncing
- CPU-friendly access patterns (thread-local memory)
- Pattern state stays in L3 cache

**Safety note** (lines 100-127):
- Raw pointers in `VsScratch` (Vectorscan handles) are `!Send` by default
- But they're safe to transfer once (at worker startup) because:
  - Each scratch pinned to exactly one thread
  - Only one thread accesses the Vectorscan handles
  - Vectorscan doesn't require thread-safe handles, just exclusive access

### Scratch Reuse Efficiency

- `findings_buf` is pre-allocated and reused across chunks
- `Vec::with_capacity()` avoids repeated allocations
- `Vec::clear()` preserves capacity for next scan
- No per-chunk allocation if findings count stays under capacity

### Overlap Processing

- `drop_prefix_findings()` filters findings by offset (O(n) scan, but n is small)
- Happens after each chunk scan to keep per-worker state bounded
- Prevents memory growth over many chunks

---

## 7. Relationship to Mock Engine

### How They Differ

| Aspect           | `engine_impl.rs` (Real)                                      | `engine_stub.rs` (Mock)  |
| ---------------- | ------------------------------------------------------------ | ------------------------ |
| **Engine Type**  | `crate::engine::Engine`                                      | `MockEngine`             |
| **Scratch Type** | `RealEngineScratch` wrapping `ScanScratch`                   | `ScanScratch` directly   |
| **Finding Type** | `crate::api::FindingRec` (u32 spans)                         | `FindingRec` (u64 spans) |
| **Scanning**     | Vectorscan regex engine with anchors, transforms, validators | Simple substring search  |
| **Performance**  | Highly optimized, Vectorscan-backed                          | Slow but deterministic   |
| **Use Case**     | Production scanning                                          | Testing scheduler logic  |

### Parallel Implementations

Both modules implement the same traits:

```rust
// engine_impl.rs
impl FindingRecord for crate::api::FindingRec { ... }
impl ScanEngine for crate::engine::Engine { ... }
impl EngineScratch for RealEngineScratch {
    type Finding = FindingWithHash<ApiFindingRec>;
    ...
}

// engine_stub.rs
impl FindingRecord for FindingRec { ... }
impl ScanEngine for MockEngine { ... }
impl EngineScratch for ScanScratch {
    type Finding = FindingWithHash<FindingRec>;
    ...
}
```

### Key Differences

**Mock is simpler** because:
- `ScanScratch` directly contains findings (no intermediate extraction buffer needed)
- Finding types are simple and match trait exactly
- No engine reference complexity (no lazy reset needed)

**Real is more complex** because:
- Must wrap `ScanScratch` in `RealEngineScratch`
- Must handle lazy reset pattern for engine compliance
- Type conversions for finding fields

### Scheduler Doesn't Care

The scheduler code is identical for both:

```rust
fn scan_one_chunk<E: ScanEngine>(
    engine: &E,
    data: &[u8],
    file_id: FileId,
    offset: u64,
    new_bytes_start: u64,
    out: &mut Vec<<E::Scratch as EngineScratch>::Finding>,
) {
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(data, file_id, offset, &mut scratch);
    scratch.drop_prefix_findings(new_bytes_start);
    scratch.drain_findings_into(out);
}
```

This is the power of the adapter pattern.

---

## 8. Testing

The module includes tests (lines 214-296) that verify:

**`real_engine_implements_scan_engine()` (lines 251-271)**:
- Trait methods work through the adapter
- Findings are correctly extracted
- Rule names resolve properly

**`drop_prefix_findings_works()` (lines 274-295)**:
- Overlap deduplication works
- Findings in the overlap region are dropped

These tests confirm that the real engine works correctly through the trait interface.

---

## Summary

`engine_impl.rs` is a **small but crucial** module that:

1. **Enables production use** of the scheduler with the real scanning engine
2. **Maintains trait abstraction** so scheduler stays engine-agnostic
3. **Solves impedance mismatches** through lazy reset and buffer patterns
4. **Preserves performance** with buffer reuse and thread-local scratch
5. **Provides parallel testability** by coexisting with the mock engine
6. **Bridges hash plumbing** by zipping findings and norm_hashes into `FindingWithHash` carriers for persistence

The adapter pattern keeps concerns separated: the engine focuses on pattern matching, the scheduler focuses on chunking and deduplication, and this module keeps them talking.
