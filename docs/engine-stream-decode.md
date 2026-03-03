# Stream Decode Module Documentation

**Location:** `crates/scanner-engine/src/engine/stream_decode.rs`

## 1. Module Purpose

The `stream_decode` module implements incremental, streaming decoding of transform output (Base64, URL-encoded data) while simultaneously scanning for pattern matches. Instead of decoding entire encoded spans into memory before scanning, this module:

- Decodes transformations in **chunks** via streaming decoder callbacks
- Maintains decoded bytes in a **ring buffer** to avoid full materialization
- Emits candidate **pattern match windows** via Vectorscan stream databases
- Re-decodes windows on-demand when they fall outside the ring buffer
- Falls back to full decode only on `force_full` safety violations; truncation/error paths abort the current span

The module provides two primary paths:
1. **Streaming path** (`decode_stream_and_scan`): Preferred, memory-efficient streaming decode
2. **Fallback path** (`decode_span_fallback`): Full decode when streaming is unsafe or unavailable

## 2. Why Streaming Over Batch Decoding

### Memory Efficiency
- **Batch approach**: Decodes entire encoded spans into temporary buffers, requiring O(n) memory for decoded output
- **Streaming approach**: Maintains a fixed-size ring buffer, reducing peak memory from unbounded to bounded

### Throughput and Responsiveness
- Streaming processes decoded data as it arrives, enabling early pattern detection
- Eliminates waiting for full decode completion before scanning can begin
- Enables responsive handling of large encoded payloads

### Vectorscan Stream Mode Integration
- Vectorscan provides native **stream mode** APIs (`scan_stream`) designed for incremental input
- Streaming path leverages this, maintaining per-pattern state across chunks
- Reduces duplicate work across overlapping chunks

### Budget Enforcement
- Per-transform and per-scan decode budget checks on **every chunk**
- Prevents runaway decode operations that would saturate resources
- Budget exhaustion aborts the current stream decode and drops that span's staged output

### Gate Optimization (Base64 Anchors)
- For `Gate::AnchorsInDecoded` Base64 transforms, a decoded-space gate stream is scanned alongside the main stream
- Final gate enforcement can discard staged output when no anchor evidence is found

## 3. Bounds and Chunking

### Input Chunking Strategy

The streaming decoder processes encoded input through a **callback-based pattern**:

```rust
// From transform.rs
pub(super) fn stream_decode(tc: &TransformConfig, encoded: &[u8], on_bytes: F)
    -> Result<(), ()>
where
    F: FnMut(&[u8]) -> ControlFlow<()>,
```

Key characteristics:
- **Chunks are emitted incrementally** as the decoder progresses
- **Chunk boundaries** depend on the transformation (Base64, URL-percent decoding)
- **Chunk sizes vary** based on the transformation engine's internal buffering
- **Callback returns** `ControlFlow::Break(())` to stop early or `ControlFlow::Continue(())` to continue

### Ring Buffer Chunking

```rust
// From stream_decode.rs, line 485
scratch.decode_ring.push(chunk);
```

The ring buffer operates as a **circular buffer**:
- Each incoming chunk is pushed into the ring
- Decoded bytes are tracked with monotonically increasing offsets (`decoded_offset`)
- Old bytes are discarded when the ring wraps and overwrites them
- Ring size is bounded by `scratch.decode_ring` capacity

### Budget Constraints

Two budget layers are enforced:

1. **Per-transform budget** (`tc.max_decoded_bytes`):
   ```rust
   // Line 249
   let max_out = tc.max_decoded_bytes.min(remaining);
   ```
   - Limits total decoded output for a single transform
   - Per-transform configuration

2. **Per-scan budget** (`max_total_decode_output_bytes`):
   ```rust
   // Line 243-248
   let remaining = self.tuning.max_total_decode_output_bytes
       .saturating_sub(scratch.total_decode_output_bytes);
   if remaining == 0 {
       return;
   }
   ```
   - Global limit across all transforms in a single scan pass
   - Prevents unbounded decode work across multiple transforms

**Budget checking occurs on each chunk** (line 453-464):
- Local chunk count tracked in `local_out`
- Global total updated incrementally
- Truncation triggered if limits exceeded

## 4. State Management Across Chunks

### Invariants

The module maintains strict invariants to ensure correctness:

1. **Monotonic decoded offsets**:
   ```rust
   // Line 689
   decoded_offset = decoded_offset.saturating_add(chunk.len() as u64);
   ```
   - Offsets only increase; never reset or go backward
   - Enables predictable window scheduling

2. **Timing wheel for window scheduling**:
   ```rust
   // Line 658
   match scratch.pending_windows.push(pending.hi, pending) {
       Ok(PushOutcome::Scheduled) => {}
       Ok(PushOutcome::Ready(win)) => {
           // Window is immediately ready for processing
       }
   }
   ```
   - Windows are keyed by their end offset (`hi`) in a timing wheel
   - Windows only process once decoded offset reaches their `hi`
   - Ensures all bytes are decoded before window materialization

3. **Slab append-only semantics**:
   ```rust
   // Line 303, 840
   let slab_start = scratch.slab.buf.len();
   // ... streaming work ...
   // On abort or fallback:
   scratch.slab.buf.truncate(slab_start);
   ```
   - Decoded bytes appended to slab during streaming
   - On fallback or abort, slab truncated to pre-decode state
   - Ensures atomicity of the decode operation

4. **Per-rule window cap**:
   ```rust
   // Lines 615, 642
   let max_hits = self.tuning.max_windows_per_rule_variant as u32;
   if *hit > max_hits {
       force_full = true; // Fallback triggered
   }
   ```
   - Limits windows per rule/variant to prevent unbounded work
   - Exceeding cap forces fallback to full decode

### State Components

**Ring buffer state:**
```rust
scratch.decode_ring  // Circular buffer of decoded bytes
decoded_offset       // Current position in logical decoded stream
```

**Window scheduling:**
```rust
scratch.pending_windows     // Timing wheel for scheduled windows
scratch.stream_hit_counts   // Per-rule-variant window counter
scratch.stream_hit_touched  // Touched indices for efficient reset
```

**Vectorscan stream state:**
```rust
stream                  // Vectorscan stream handle
vs_scratch             // Vectorscan scratch space
vs_stream_matches      // Matches emitted by callback
```

**UTF-16 variant tracking:**
```rust
utf16_stream           // Optional UTF-16 stream handle
utf16_stream_scratch   // UTF-16-specific scratch space
utf16_stream_ctx       // UTF-16 match context
decoded_has_nul        // Flag indicating NUL bytes (UTF-16 marker)
```

**Gate state:**
```rust
gate_stream            // Optional gate database stream
gate_scratch           // Gate scratch space
gate_hit               // Flag indicating gate match
gate_db_active         // Whether gate is currently active
gate_db_failed         // Whether gate failed to open/scan
```

### Deduplication Without Full Buffering

Streaming achieves dedupe without materializing the full buffer using **AEGIS-128L MAC** (lines 439-484):

```rust
let key = [0u8; 16];
let mut mac = aegis::aegis128l::Aegis128LMac::<16>::new(&key);
// Per chunk:
mac.update(chunk);
// Final:
let h = mix_root_hint_hash(u128::from_le_bytes(mac.finalize()), &root_hint);
if !scratch.seen.insert(h) {
    // Duplicate detected; discard
}
```

- Incremental MAC computation over streaming chunks
- Final hash is mixed with `root_hint` so identical decoded bytes at different root spans are treated independently
- Mixed hash checked against seen set for deduplication
- No need to buffer entire decoded output for hashing

## 5. Integration with transform.rs

### Transform Configuration

Stream decode uses `TransformConfig` from the transform module:

```rust
// Lines 28, 69
pub(super) fn decode_span_fallback(
    &self,
    tc: &TransformConfig,
    transform_idx: usize,
    enc_ref: &EncRef,
    enc: &[u8],
    ...
)
```

**Key config fields:**
- `tc.id`: Transform type (Base64, UrlPercent, etc.)
- `tc.gate`: Gate mode (e.g., `Gate::AnchorsInDecoded`)
- `tc.min_len`: Minimum encoded length to process
- `tc.max_decoded_bytes`: Per-transform decode budget
- `tc.plus_to_space`: URL decode flag
- `tc.max_spans_per_buffer`: Span stream limits

### Transform Streaming Decoder Invocation

```rust
// Line 452
let res = stream_decode(tc, encoded, |chunk| {
    // Process chunk callbacks here
    // ...
});
```

**Transforms supported:**
- **URL-Percent** (`TransformId::UrlPercent`):
  - Calls `stream_decode_url_percent()` from transform.rs
  - Supports `plus_to_space` flag

- **Base64** (`TransformId::Base64`):
  - Calls `stream_decode_base64()` from transform.rs
  - Validates base64 alphabet and padding

### Span Stream Integration

Streaming detectors for child transforms emit spans as decoded bytes arrive:

```rust
// Lines 398-412
for (tidx, tcfg) in self.transforms.iter().enumerate() {
    let state = match tcfg.id {
        TransformId::UrlPercent => SpanStreamState::Url(UrlSpanStream::new(tcfg)),
        TransformId::Base64 => SpanStreamState::Base64(Base64SpanStream::new(tcfg)),
    };
    scratch.span_streams.push(SpanStreamEntry {
        transform_idx: tidx,
        state,
        spans_emitted: 0,
        max_spans: tcfg.max_spans_per_buffer,
    });
}
```

**Per-chunk span feeding:**
```rust
// Lines 778-782
match &mut entry.state {
    SpanStreamState::Url(state) => state.feed(chunk, chunk_start, &mut on_span),
    SpanStreamState::Base64(state) => state.feed(chunk, chunk_start, &mut on_span),
}
```

- `UrlSpanStream::feed()` detects percent-encoded sequences
- `Base64SpanStream::feed()` detects base64-like sequences
- Emitted spans become pending decode work items at end of stream

### Gate Database Integration

For `Gate::AnchorsInDecoded` Base64 transforms, a Vectorscan gate is applied:

```rust
// Lines 282-301
if gate_enabled {
    if let Some(db) = self.vs_gate.as_ref() {
        // Open a gate stream
        gate_db_active = true;
        gate_stream = Some(stream);
        gate_scratch = Some(vs_gate_scratch);
    }
}
```

**Per-chunk gate scanning:**
```rust
// Lines 501-521
if gate_db_active && gate_hit == 0 {
    if db.scan_stream(gstream, chunk, gscratch, gate_cb, ...).is_err() {
        gate_db_active = false;
        gate_db_failed = true;
    }
}
```

- Gate patterns checked in decoded space
- Early exit if gate patterns match (anchors found)
- Fallback logic if gate fails (lines 1251-1261)

## 6. Key Types and Functions

### Core Functions

#### `decode_stream_and_scan()`

**Signature:**
```rust
pub(super) fn decode_stream_and_scan(
    &self,
    vs_stream: &VsStreamDb,
    tc: &TransformConfig,
    transform_idx: usize,
    enc_ref: &EncRef,
    encoded: &[u8],
    step_id: StepId,
    root_hint: Option<Range<usize>>,
    root_hint_maps_encoded: bool,
    depth: usize,
    base_offset: u64,
    file_id: FileId,
    scratch: &mut ScanScratch,
)
```

**Responsibilities:**
1. Stream-decode `encoded` in chunks
2. Feed chunks to Vectorscan stream database
3. Collect windows from pattern matches
4. Schedule windows in timing wheel
5. Materialize and process windows as they become ready
6. Detect and emit child transform spans
7. Handle UTF-16 scanning if enabled
8. Apply gate filtering on Base64

**Return behavior:**
- Modifies `scratch` with findings and work items
- Falls back to `decode_span_fallback()` on safety violations
- Returns early on budget exhaustion or truncation

---

#### `decode_span_fallback()`

**Signature:**
```rust
pub(super) fn decode_span_fallback(
    &self,
    tc: &TransformConfig,
    transform_idx: usize,
    enc_ref: &EncRef,
    enc: &[u8],
    step_id: StepId,
    root_hint: Option<Range<usize>>,
    depth: usize,
    scratch: &mut ScanScratch,
)
```

**Responsibilities:**
1. Fully decode `enc` into slab
2. Check length and budget constraints
3. Apply gate filtering if enabled
4. Dedupe decoded output via 128-bit hash
5. Enqueue as batch `ScanBuf` work item

**Return behavior:**
- On dedupe match: truncates slab and returns early
- On decode error: returns early without enqueueing
- On success: enqueues for batch scanning

---

#### `redecode_window_into()`

**Signature:**
```rust
pub(super) fn redecode_window_into(
    &self,
    tc: &TransformConfig,
    encoded: &[u8],
    lo: u64,
    hi: u64,
    max_out: usize,
    out: &mut Vec<u8>,
) -> bool
```

**Responsibilities:**
1. Re-decode the window `[lo, hi)` from `encoded`
2. Extract only bytes in the range
3. Enforce max output limit
4. Clear and fill `out` with window bytes

**Returns:**
- `true` if exactly `hi - lo` bytes reconstructed
- `false` if decode fails, truncates, or exceeds limit

**Usage context:**
- Called when a window has fallen out of the ring buffer
- Enables lazy materialization of distant windows
- Fallback if re-decode fails (line 1039)

### Key Data Structures

#### `PendingWindow` (from work_items.rs)

```rust
pub(super) struct PendingWindow {
    pub(super) hi: u64,              // Window end offset (key in timing wheel)
    pub(super) lo: u64,              // Window start offset
    pub(super) rule_id: u32,         // Rule that matched
    pub(super) variant: Variant,     // Raw/UTF-16LE/UTF-16BE
    pub(super) anchor_hint: u64,     // Anchor position hint
}
```

**Role:** Represents a pattern match window ready for rule evaluation

---

#### `SpanStreamEntry` (from work_items.rs)

```rust
pub(super) struct SpanStreamEntry {
    pub(super) transform_idx: usize,        // Child transform index
    pub(super) state: SpanStreamState,      // UrlSpanStream or Base64SpanStream
    pub(super) spans_emitted: usize,        // Count of spans emitted
    pub(super) max_spans: usize,            // Max allowed spans per buffer
}
```

**Role:** Tracks a streaming span detector for child transforms

---

#### `SpanStreamState` (from work_items.rs)

```rust
pub(super) enum SpanStreamState {
    Url(UrlSpanStream),
    Base64(Base64SpanStream),
}
```

**Role:** Variant enumeration for URL and Base64 span detectors

---

#### `ScanScratch` Fields Used

```rust
pub struct ScanScratch {
    pub decode_ring: ByteRing,             // Circular buffer of decoded bytes
    pub pending_windows: TimingWheel<...>, // Windows scheduled for processing
    pub stream_hit_counts: Vec<u32>,       // Per-rule-variant window counter
    pub stream_hit_touched: Vec<u32>,      // Touched indices for reset
    pub vs_stream_matches: Vec<...>,       // Matches from Vectorscan callback
    pub vs_stream_scratch: Option<...>,    // Vectorscan scratch reuse
    pub pending_spans: Vec<...>,           // Child transform spans
    pub span_streams: Vec<...>,            // Span detector instances
    pub window_bytes: Vec<u8>,             // Temporary window materialization
    pub total_decode_output_bytes: usize,  // Running total across transforms
    pub slab: DecodeSlab,                  // Appended decoded output
    pub seen: FixedSet128,                 // Dedupe hashes
    pub tmp_findings: Vec<...>,            // Temporary findings buffer
    pub findings_dropped: usize,           // Count of dropped findings
}
```

### Vectorscan Integration Types

#### `VsStreamDb`
- Vectorscan stream database handle
- Provides `open_stream()`, `scan_stream()`, `close_stream()` methods
- Maintains per-pattern state and metadata

#### `VsStream`
- Stream handle for ongoing Vectorscan scanning
- Passed to callbacks for incremental matching
- Closed after all chunks processed

#### `VsStreamMatchCtx`
- Context passed to Vectorscan callback
- Contains pending match vector, metadata pointers
- Callback appends matches to `pending`

#### `VsUtf16StreamMatchCtx`
- UTF-16 variant of match context
- Tracks targets, pattern offsets, pattern lens
- Base offset for absolute positioning

## 7. Fallback and Abort Triggers

### `force_full` triggers (falls back to `decode_span_fallback`)

1. **Window cap exceeded** (line 642-648):
   ```rust
   if *hit > max_hits {
       force_full = true;
   }
   ```
   - Per-rule-variant window count exceeds `max_windows_per_rule_variant`
   - Prevents unbounded window materialization and processing

2. **Ring buffer unable to reconstruct window** (lines 329-342):
   ```rust
   if !scratch.decode_ring.extend_range_to(lo, hi, &mut scratch.window_bytes)
       && !self.redecode_window_into(tc, encoded, lo, hi, max_out, &mut scratch.window_bytes)
   {
       force_full = true;
   }
   ```
   - Ring buffer has overwritten window bytes
   - Re-decode also failed or exceeded limits
   - Cannot reliably materialize the window

3. **Child span cannot be materialized from ring** (stream/end-of-stream span emission):
   - Nested transform span bytes must be present in the decode ring
   - Missing bytes force `force_full = true` to preserve correctness

### Stream-abort triggers (no full-decode fallback for this span)

1. **Decode budget exceeded** (lines 453-464):
   ```rust
   if local_out.saturating_add(chunk.len()) > max_out {
       truncated = true;
   }
   ```
   - Per-transform budget exhausted
   - Further decoding halted

2. **Total decode budget exceeded** (lines 457-464):
   ```rust
   if scratch.total_decode_output_bytes.saturating_add(chunk.len())
       > self.tuning.max_total_decode_output_bytes
   {
       truncated = true;
   }
   ```
   - Per-scan global budget exhausted
   - No more decoding across any transform

3. **Stream decode/scan error** (lines 487-498):
   ```rust
   if vs_stream.scan_stream(...).is_err() {
       truncated = true;
   }
   ```
   - Vectorscan streaming failed
   - Cannot continue pattern matching

### Gate DB failure behavior (does not force fallback)

1. **Gate database failure** (lines 501-521):
   ```rust
   if db.scan_stream(...).is_err() {
       gate_db_active = false;
       gate_db_failed = true;
   }
   ```
   - Gate scanning failed; gate enforcement is relaxed to avoid false negatives

## 8. Gate Behavior (`Gate::AnchorsInDecoded`)

### Preferred Path: Decoded-Space Gating

For `Gate::AnchorsInDecoded` Base64 transforms:

```rust
// Lines 256, 282-301
let gate_enabled = tc.gate == Gate::AnchorsInDecoded;
if gate_enabled {
    if let Some(db) = self.vs_gate.as_ref() {
        gate_db_active = true;
        gate_stream = Some(stream);
    }
}
```

**Benefits:**
- Gate patterns evaluated in decoded space (more accurate)
- Gate stream scanning stops after first hit (`gate_hit != 0`)
- Prevents committing non-gated decoded output when enforcement is active

**Per-chunk gate scanning:**
- Gate database scanned alongside main pattern database
- Pattern scanning continues regardless; `gate_hit` drives final enforcement
- If gate is enforced and never matches, staged decoded output is discarded

### Fallback: Prefilter-Based Gating

If gate database unavailable or fails:

```rust
// Lines 1245-1261
let gate_satisfied = if gate_db_active || gate_hit != 0 {
    gate_hit != 0
} else {
    prefilter_gate_hit  // Fall back to prefilter hits
};
let enforce_gate = if gate_enabled {
    if gate_db_failed {
        false  // Don't enforce; be permissive
    } else if gate_db_active || gate_hit != 0 {
        true   // Enforce based on gate DB
    } else {
        !self.tuning.scan_utf16_variants || !self.has_utf16_anchors
    }
} else {
    false
};
```

**Logic:**
- If gate DB failed, don't enforce gate (avoid false negatives)
- Relax enforcement if UTF-16 scanning enabled (UTF-16 anchors may miss in prefilter)
- Otherwise, discard non-gated bytes (line 1274)

## 9. Flow Diagram

```
Entry: decode_stream_and_scan()
  |
  +-> Allocate/open Vectorscan stream
  |
  +-> Per-chunk loop: stream_decode(tc, encoded, |chunk| {
  |     |
  |     +-> Budget check (per-transform, per-scan)
  |     |
  |     +-> Feed to Vectorscan stream DB
  |     |
  |     +-> Feed to gate DB (if enabled)
  |     |
  |     +-> Feed to UTF-16 stream (if enabled)
  |     |
  |     +-> Feed chunk to span detectors
  |     |
  |     +-> Collect Vectorscan matches into timing wheel
  |     |
  |     +-> Advance timing wheel: process ready windows
  |     |   |
  |     |   +-> Materialize window (ring buffer or re-decode)
  |     |
  |     +-> Process window through rule evaluation
  |     |
  |     +-> Continue or Break based on conditions
  |   })
  |
  +-> Close stream, finalize matches
  |
  +-> Process end-of-stream spans
  |
  +-> UTF-16 scanning (if enabled, deferred)
  |
  +-> Gate satisfaction check
  |
  +-> Dedupe check (AEGIS-128L MAC)
  |
  +-> Enqueue findings
  |
  +-> Enqueue pending child transform spans
  |
  +-> Exit

On fallback (`force_full`):
  +-> Truncate slab to pre-decode state
  |
  +-> Reset state collections
  |
  +-> Call decode_span_fallback()

On stream abort (`truncated` or decode/scan error):
  +-> Truncate slab to pre-decode state
  |
  +-> Return without full-decode fallback
```

## 10. Performance Considerations

### Memory Overhead
- Ring buffer size is fixed and bounded
- Timing wheel overhead linear in window count (capped)
- State collections reset between spans

### CPU Efficiency
- Streaming enables early pattern matching
- Avoids redundant decoding for overlapping regions
- Vectorscan stream mode minimizes state transitions

### Allocation Strategy
- Reuse `vs_stream_scratch`, `gate_scratch`, `utf16_stream_scratch` across calls
- Slab append-only reduces allocation fragmentation
- Temporary `window_bytes` buffer reused per window

### Truncation/Abort Performance
- Slab rollback is O(1) truncate operation
- State reset via `clear()` and `reset()` methods
- No deep copying on fallback path
