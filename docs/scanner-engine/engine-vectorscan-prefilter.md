# Engine: Vectorscan Prefilter Module

## Module Purpose

The vectorscan prefilter module (`crates/scanner-engine/src/engine/vectorscan_prefilter.rs`) integrates Vectorscan/Hyperscan pattern matching into the scanner's three prefilter paths:

1. **Raw-byte scanning** (`VsPrefilterDb`) - Block mode for scanning raw bytes directly
2. **Decoded-stream scanning** (`VsStreamDb`) - Stream mode for scanning post-transform decoded output
3. **UTF-16 anchor scanning** (`VsAnchorDb`, `VsUtf16StreamDb`) - Anchor literal detection with variant (Raw, UTF-16LE, UTF-16BE) awareness

The core mission is **conservative window seeding**: use prefilter matches to identify candidate regions without risk of dropping true matches. All window math is saturating and clamped to available buffer length to prevent under-seeding on overflow.

## Pattern ID Layout

The compiled Vectorscan database assigns pattern IDs in a specific order:

```
Pattern IDs:
  0 to (raw_rule_count - 1)      Raw rule patterns (compiled with HS_FLAG_PREFILTER)
  anchor_id_base to               Anchor literal patterns (appended after raw rules)
  (anchor_id_base + anchor_pat_count - 1)
```

- `raw_meta` maps raw pattern array index -> (`rule_id`, `match_width`, `seed_radius`)
- `anchor_*` mapping tables resolve anchor patterns to their target (rule, variant) pairs
- `anchor_id_base` always equals `raw_rule_count` for easy arithmetic

## Database Compilation

### Raw Rule Compilation

Raw patterns are compiled with two stages:

1. **Multi-compile attempt**: All non-filtered rules compiled together with `hs_compile_multi`
2. **Fallback to per-rule compilation**: If multi-compile fails, each rule is compiled individually to pinpoint rejects

The `use_raw_prefilter` parameter allows selective inclusion: rules with `use_raw_prefilter[rid] == false` skip raw regex compilation and rely entirely on anchor patterns for window seeding.

### Anchor Pattern Compilation

Anchor patterns are literal byte sequences:

1. **Filtering**: Empty patterns are dropped; offsets are compacted
2. **Encoding**: Each pattern is converted to a `\xNN` regex literal so Vectorscan treats it as raw bytes
3. **Compilation**: Patterns are appended to raw rules in the same database

When `SCANNER_VS_UTF16_DEBUG` environment variable is set, runtime debug output logs pattern statistics (counts, min/max lengths, leading NUL bytes).

### DB Cache Integration

All Vectorscan DB constructors in this module use `VsDbCache` (`crates/scanner-engine/src/engine/vs_cache.rs`) for best-effort on-disk reuse of serialized databases.

- Environment controls:
  - `SCANNER_VS_DB_CACHE=0|false|off|no` disables cache use
  - `SCANNER_VS_DB_CACHE_DIR=/path` overrides cache directory
  - Default cache directory: `$HOME/.cache/scanner-rs/vsdb` (fallback: `$TMPDIR/scanner-rs-vsdb`)
- Cache key kind tags used by this module:
  - `vs-prefilter-db:block`
  - `vs-stream-db:stream`
  - `vs-anchor-db:block`
  - `vs-utf16-stream-db:stream`
  - `vs-gate-db:stream`

## Pattern Types

### Raw Rule Patterns

- **Flag**: `HS_FLAG_PREFILTER` (conservative, reduces false negatives)
- **Coordinate system**: Raw-byte offsets in the scanned buffer
- **Use case**: General regex-based prefiltering for all scanning modes

**Example flow:**
```
Rule: /hello.*world/
  ↓ hs_expression_info
max_width ≈ ??? (depends on regex complexity)
  ↓ compile with HS_FLAG_PREFILTER
Block-mode DB pattern with ID 0..N-1
```

### Anchor Literal Patterns

- **Format**: Literal byte sequences, encoded as `\xNN` regexes
- **Flag**: None (literal matching; `HS_FLAG_SINGLEMATCH` used only for gate databases)
- **Coordinate system**:
  - Block DBs (`VsPrefilterDb`, `VsAnchorDb`): raw-byte offsets
  - Stream DB (`VsUtf16StreamDb`): decoded-byte offsets
- **Mapping**: Multiple targets per pattern via prefix-sum offset table

**Example:**
```
Rule 5, variant Raw:
  Anchor pattern: b"SIGNATURE"
  → Pattern ID: anchor_id_base + 0
  → Target: rule_id=5, variant_idx=0

Rule 7, variant UTF-16LE:
  Anchor pattern: b"\x44\x00\x41\x00\x54\x00" (UTF-16LE encoding of "DAT")
  → Pattern ID: anchor_id_base + 2
  → Target: rule_id=7, variant_idx=1
```

## Callback Mechanism

### Window Seeding Philosophy

Vectorscan callbacks convert prefilter matches into candidate windows using saturating arithmetic:

```
Match (from, to) + max_width + radius → Window [lo, hi)

lo = to - (max_width + radius)  // saturating
hi = to + radius                // saturating, clamped to haystack end
```

### Stream Match Callback: `vs_on_stream_match`

Invoked during stream-mode scanning of decoded bytes:

1. **Whole-buffer fallback**: If `meta.whole_buffer_on_hit`, set `force_full=true` and scan entire stream
2. **Bounded windows**: Otherwise, compute window around match end using metadata
3. **Anchor hint preservation**: Clamp Vectorscan's `from` offset to window bounds for regex anchor point

**Decoded-byte coordinate system:**
```
VsStreamWindow {           // 32B, #[repr(C)], fields ordered for minimal padding
  lo: u64,              // Window start (decoded bytes)
  hi: u64,              // Window end (decoded bytes)
  anchor_hint: u64,     // Hint for regex search start
  rule_id: u32,         // Compiled rule identifier
  variant_idx: u8,      // Variant::idx() (Raw/UTF-16LE/UTF-16BE)
  force_full: bool,     // Request full decode scan if unbounded
}
```

### Raw Match Callback: `vs_on_match`

Invoked during raw-byte scanning. Handles both raw rule patterns and anchor patterns:

1. **Raw patterns** (id < raw_rule_count): Use metadata arrays indexed by raw pattern index
2. **Anchor patterns** (id ≥ anchor_id_base): Look up target slice via `pat_offsets` prefix-sum

Each match generates one or more window seeds (per target) pushed to `ScanScratch.hit_acc_pool`:

```rust
let pair = rid * 3 + vidx;  // (rule_id, variant_idx) packed coordinate
scratch.hit_acc_pool.push_span(pair, window);
```

### UTF-16 Stream Callback: `vs_utf16_stream_on_match`

Specialized for stream-mode anchor scanning with multi-chunk processing:

- **Base offset adjustment**: Converts stream-local offsets to absolute decoded offsets
- **Anchor length use**: Derives window start from pattern length (not max_width)
- **Per-target window expansion**: Each target gets individual seed radius applied

## Variant Handling

### Three Variants

Variants represent different text encodings:

```rust
Variant::Raw           // Raw bytes / ASCII (index=0)
Variant::Utf16Le       // UTF-16 Little-Endian (index=1)
Variant::Utf16Be       // UTF-16 Big-Endian (index=2)
```

### Variant Index Encoding in Callbacks

- Windows are indexed by `(rule_id, variant_idx)` as a packed coordinate: `pair = rid * 3 + vidx`
- Variant 0 always uses raw pattern prefiltering
- Variants 1 and 2 may use anchor patterns (when available) for window seeding
- The `saw_utf16` flag is set whenever a variant_idx of 1 or 2 is observed

### Seed Radius Selection

`VsAnchorTarget` includes variant-aware seed radius:

```rust
match variant {
    Variant::Raw => seed_radius_raw[rule_id],
    Variant::Utf16Le | Variant::Utf16Be => seed_radius_utf16[rule_id],
}
```

Different seed radii accommodate the different coordinate systems (raw bytes vs. decoded UTF-16 units).

## Gate Semantics

### Decoded-Space Gating

The `VsGateDb` optimizes common scenarios by gating downstream decoded-window validation on anchor presence:

```
Scan decoded stream for gate anchors
  ↓
No anchors found → Skip downstream window validation
  ↓
Anchors found → Proceed with downstream validation
```

### Gate Database Construction

1. **Pattern filtering**: Empty anchor patterns are dropped
2. **Compilation**: Patterns compiled with `HS_FLAG_SINGLEMATCH` in stream mode
   - Only the first match per pattern is reported (no repeated callbacks)
3. **Gate callback**: `vs_gate_on_match` sets a flag and returns 0 (continue)

### Gate Workflow Example

```rust
// Build gate DB from anchor patterns
gate_db = VsGateDb::try_new_gate(&anchor_patterns)?;

// Open stream and scan for anchors
gate_stream = gate_db.open_stream()?;
gate_hit = false;
gate_db.scan_stream(&mut gate_stream, chunk, &mut scratch,
    gate_match_callback(), (&mut gate_hit as *mut u8).cast())?;

// Only keep downstream decode-window work if anchors were found
if gate_hit {
    // Continue downstream validation
} else {
    // Drop/skip downstream validation work
}
```

## Key Functions

### VsPrefilterDb

**`try_new(rules, anchor, use_raw_prefilter)`**
- Compiles raw rules and optional anchor patterns into a single block-mode database
- Fallback per-rule compilation on multi-compile failure
- Returns error if no patterns survive compilation
- Stores metadata for window seeding: `max_width`, `seed_radius`, mappings

**`scan_raw(hay, scratch, vs_scratch)`**
- Block-mode scan of raw bytes
- Calls `vs_on_match` callback for each prefilter hit
- Returns `Ok(true)` if any UTF-16 anchor hit was observed
- Clamped to u32 buffer length; returns error if exceeded

**`alloc_scratch()`**
- Per-thread Vectorscan scratch allocation
- Must be used with this specific database instance
- Reuse across scans to amortize allocation cost

### VsStreamDb

**`try_new_stream(rules, max_decoded_cap)`**
- Compiles rules in stream mode with `HS_FLAG_PREFILTER`
- Estimates `max_width` per rule from `hs_expression_info`
- Unbounded widths (0 from expression info) capped by `max_decoded_cap` when nonzero
- Stores per-rule metadata (`VsStreamMeta`)

**`scan_stream(stream, data, scratch, on_event, ctx)`**
- Scans a stream chunk
- Delivers matches via `on_event` callback
- Treats `HS_SCAN_TERMINATED` as success (allows early termination)

**`open_stream()` / `close_stream(stream, ...)`**
- Open a new stream handle for multi-chunk scanning
- Close flushes end-of-stream matches

### VsAnchorDb

**`try_new_utf16(patterns, pat_targets, pat_offsets, seed_radius_raw, seed_radius_utf16)`**
- Builds block-mode database for UTF-16 anchor prefiltering
- Empty patterns filtered; offsets compacted
- Patterns encoded as `\xNN` literals
- Window math uses prefix-sum target mapping

**`scan_utf16(hay, scratch, vs_scratch)`**
- Block-mode scan for anchor hits
- Callback expands each anchor match to all target (rule, variant) pairs
- Returns `Ok(true)` if any UTF-16 variant was observed

### VsUtf16StreamDb

**`try_new_utf16_stream(...)`**
- Stream-mode variant of `VsAnchorDb`
- For multi-chunk decoded stream scanning

**`scan_stream(stream, chunk, scratch, on_event, ctx)`**
- Stream-mode anchor scanning
- Delivers `VsStreamWindow` entries via callback

### VsGateDb

**`try_new_gate(patterns)`**
- Simplified anchor DB: patterns only, no rule mapping
- Compiled with `HS_FLAG_SINGLEMATCH` for efficiency

**`scan_stream(stream, data, scratch, on_event, ctx)`**
- Stream-mode gate detection
- Callback sets a hit flag (`u8`)

### VsScratch

**`bound_db_ptr()`**
- Returns the database pointer this scratch is bound to
- Used for validation that scratch and DB match

Database wrappers (`VsPrefilterDb`, `VsStreamDb`, `VsGateDb`, `VsUtf16StreamDb`) are `Send + Sync` because compiled Vectorscan DBs are immutable post-compilation. `VsScratch` is `Send` only (not `Sync`).

## Design Tradeoffs

### 1. Saturating Arithmetic vs. Accuracy

**Tradeoff:** Use saturating math (no overflow) at the cost of potentially over-seeded windows

**Rationale:**
- Prefiltering is conservative; over-seeding is safe
- Window math uses saturating arithmetic and buffer-end clamps to avoid under-seeding on overflow
- Whole-buffer fallback (`force_full=true`) is used for unbounded stream-width cases
- Avoids underflow bugs that could miss matches

**Example:**
```rust
// If max_width + radius overflows u32:
hi = end.saturating_add(radius).min(haystack_len)
// Instead of wrapping (which risks under-seeding)
```

### 2. Compiled DB Reuse vs. Flexibility

**Tradeoff:** All raw rules + anchor patterns compiled into a single database

**Rationale:**
- Single database compilation reduces complexity and error paths
- Anchor patterns appended with separate ID range is efficient
- Trade flexibility for code simplicity and reduced FFI calls

### 3. Window Math: `to` as Match End vs. Match Start

**Tradeoff:** Use `to` (Vectorscan match end) as the window expansion center

**Rationale:**
- Match end is more conservative (avoids early false negatives)
- Derive start from `max_width` estimate when available
- Preserve anchor hint (`from`) for regex search positioning

### 4. Per-Thread Scratch Requirement

**Tradeoff:** Require caller to manage per-thread `VsScratch` allocation

**Rationale:**
- Vectorscan requires thread-local scratch for safety
- Caller sees thread affinity; can pool scratches efficiently
- Prevents silent data races from shared scratch across threads

### 5. Fallback to Per-Rule Compilation

**Tradeoff:** Fall back to individual rule compilation when multi-compile fails

**Rationale:**
- Pinpoint which rules are problematic (better error messages)
- Keeps compile diagnostics specific to the rejecting rules
- Return error early rather than masking issues

### 6. Two Seed Radius Types (Raw, UTF-16)

**Tradeoff:** Separate `seed_radius_raw` and `seed_radius_utf16` arrays

**Rationale:**
- Different coordinate systems (raw bytes ≠ UTF-16 code units)
- Allows tuning per-encoding for balanced window sizes
- Selected at compile time based on anchor variant

### 7. Gate Databases with SINGLEMATCH

**Tradeoff:** Use `HS_FLAG_SINGLEMATCH` for gate pattern compilation

**Rationale:**
- Only first match matters (presence of anchor, not count)
- Reduces callback overhead in stream scanning
- Simpler gate callback (just set a flag)

## Limits and Error Handling

### Buffer Size Constraints

- All scan APIs accept u32 lengths (Vectorscan constraint)
- Haystack exceeding u32::MAX returns error: "buffer too large for hs_scan"
- Callers must pre-chunk input if needed

### Compilation Fallback Strategy

1. Attempt multi-compile of all patterns
2. If fails, compile each pattern individually
3. Collect error messages from failing rules
4. Return aggregated error if any rule is rejected

**Error message format:**
```
"vectorscan raw db compile failed for N rules:
 rule='name1' pattern='regex1' error=...
 rule='name2' pattern='regex2' error=..."
```

### Empty Pattern Rejection

- `VsAnchorDb::try_new_utf16` returns error if all patterns are empty
- `VsGateDb::try_new_gate` returns error if all patterns are empty
- `VsStreamDb::try_new_stream` requires non-empty rule set

### Expression Info Constraints

- Patterns containing NUL bytes are rejected
- `hs_expression_info` returning 0 width is treated as "unbounded"
- Unbounded rules capped by `max_decoded_cap` when nonzero

## Thread Safety and Memory Management

### Immutable Database Sharing

- Compiled `hs_database_t` pointers are immutable post-compilation
- `VsPrefilterDb`, `VsStreamDb`, `VsGateDb`, `VsUtf16StreamDb` are Send/Sync
- May be safely shared across threads

### Per-Thread Scratch Requirement

- Each scanning thread must allocate its own `VsScratch`
- Scratch is bound to a specific database via `db` pointer
- Scratch must not be shared or used concurrently

### FFI Safety Invariants

- Match callbacks must never panic or unwind across FFI boundary
- Callback `ctx` pointers are valid only for scan duration
- Callback return value 0 = continue scanning, non-zero = terminate

### Memory Cleanup

All structures implement Drop to free Vectorscan allocations:
- `Drop::drop` calls `hs_free_database` for DB pointers
- `Drop::drop` calls `hs_free_scratch` for scratch pointers
- Safe to move/drop at any time (no use-after-free)

## Example: Complete Prefilter Workflow

```rust
use engine::vectorscan_prefilter::*;

// 1. Compile raw rules and anchors
let rules = vec![/* RuleSpec entries */];
let anchor_input = AnchorInput { /* ... */ };
let db = VsPrefilterDb::try_new(&rules, Some(anchor_input), None)?;

// 2. Allocate per-thread scratch
let mut scratch = db.alloc_scratch()?;

// 3. Scan raw buffer
let haystack = b"some binary data";
let saw_utf16 = db.scan_raw(haystack, &mut scan_scratch, &mut scratch)?;

// 4. Windows are seeded into scan_scratch.hit_acc_pool
// Caller processes hit_acc_pool/touched_pairs in the engine scan loop.
```

## Coordinate Systems Summary

| Database                    | Scan Input            | Match Coords         | Window Coords                      |
|-----------------------------|-----------------------|----------------------|------------------------------------|
| `VsPrefilterDb` (block)     | Raw bytes             | Raw-byte offsets     | Raw-byte offsets                   |
| `VsAnchorDb` (block)        | Raw bytes             | Raw-byte offsets     | Raw-byte offsets                   |
| `VsStreamDb` (stream)       | Decoded stream        | Decoded-byte offsets | Decoded-byte offsets               |
| `VsUtf16StreamDb` (stream)  | Decoded UTF-16 stream | Decoded-byte offsets | Decoded-byte offsets + base_offset |
| `VsGateDb` (stream)         | Any decoded stream    | N/A (presence only)  | N/A                                |
