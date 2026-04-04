# Engine Internal Data Structures

## Overview

The scanner engine's hot-path performance depends on four internal modules that provide allocation-free scanning, cache-friendly iteration, and bounded memory usage:

1. **ScanScratch** (`scratch.rs`): Per-scan scratch state that amortizes all allocations across chunks. Owns findings, work queues, decode slabs, dedup sets, and Vectorscan scratch memory. Uses a `#[repr(C)]` layout with an explicit 64-byte cache-line boundary separating hot fields from cold fields.

2. **HitAccPool** (`hit_pool.rs`): Fixed-stride hit accumulator pool that collects anchor windows for all (rule, variant) pairs. Uses raw pointers for bounds-check-free access on the hot path and pressure-based span coalescing when per-pair hit caps are exceeded.

3. **VsDbCache** (`vs_cache.rs`): On-disk cache for serialized Vectorscan databases. Reduces engine startup time by persisting compiled databases with BLAKE3-keyed integrity verification and AEGIS-128L MAC protection.

4. **RuleCompiled / RuleCold** (`rule_repr.rs`): Two-tier compiled rule representation that separates hot per-window gate data from cold per-finding emission metadata. Gate objects are pooled on the `Engine` and referenced by `u32` sentinel-indexed fields, keeping the hot struct compact for cache-friendly iteration.

These modules are internal to the engine (`pub(super)`) and are not part of the public API. They are designed to be reset and reused across scans, never allocated per-finding or per-window.

## ScanScratch

### Purpose

`ScanScratch` is the primary allocation amortization vehicle for scans. It pre-allocates all buffers at engine construction time and reuses them across chunks. The hot path never allocates; overflow increments `findings_dropped` instead of reallocating.

### `#[repr(C)]` Memory Layout

The struct uses `#[repr(C)]` to preserve declared field order, ensuring the explicit 64-byte cache-line boundary between hot and cold regions remains stable. A zero-sized `CachelineBoundary` marker (`#[repr(align(64))]` with `[u8; 0]`) forces the first cold field to begin on a fresh cache line.

```
┌─────────────────────────────────────────────────────────────────┐
│                     HOT SCAN-LOOP REGION                        │
│  (touched on every chunk — dominates L1/L2 cache residency)     │
├─────────────────────────────────────────────────────────────────┤
│  out: ScratchVec<FindingRec>           │ pending findings       │
│  norm_hash: ScratchVec<NormHash>       │ aligned 1:1 with out   │
│  drop_hint_end: ScratchVec<u64>        │ aligned 1:1 with out   │
│  max_findings: usize                   │ per-chunk emission cap  │
│  findings_dropped: usize               │ overflow counter        │
│  work_q: ScratchVec<WorkItem>          │ BFS buffer traversal    │
│  work_head: usize                      │ monotonic cursor        │
│  seen_findings_scan: FixedSet128       │ per-scan dedup          │
│  total_decode_output_bytes: usize      │ budget tracker          │
│  work_items_enqueued: usize            │ budget tracker          │
│  capture_locs: Vec<Option<CaptureLocations>>  │ per-rule regex   │
│  stream_hit_counts: Vec<u32>           │ per-(rule,variant)      │
│  stream_hit_touched: ScratchVec<u32>   │ sparse reset list       │
│  hit_acc_pool: HitAccPool              │ anchor hit windows      │
│  touched_pairs: ScratchVec<u32>        │ unique touched pairs    │
│  windows: ScratchVec<SpanU32>          │ merged windows          │
│  expanded: ScratchVec<SpanU32>         │ two-phase expanded      │
│  spans: ScratchVec<SpanU32>            │ transform candidates    │
│  step_arena: StepArena                 │ decode provenance       │
│  utf16_buf: ScratchVec<u8>             │ UTF-16 transcoding      │
│  steps_buf: ScratchVec<DecodeStep>     │ materialization temp    │
├───────────────── 64-byte boundary ──────────────────────────────┤
│  _cold_boundary: CachelineBoundary     │ [u8; 0] align(64)      │
├─────────────────────────────────────────────────────────────────┤
│                  COLD / CONDITIONAL REGION                       │
│  (touched only when transforms fire or findings emit)           │
├─────────────────────────────────────────────────────────────────┤
│  slab: DecodeSlab                      │ decoded output buffer   │
│  seen: FixedSet128                     │ decoded-buffer dedup    │
│  seen_findings: FixedSet128            │ cross-chunk file dedup  │
│  decode_ring: ByteRing                 │ streaming window capture│
│  window_bytes: Vec<u8>                 │ ring materialization    │
│  drain_batch: Vec<PendingWindow>       │ drained pending windows │
│  pending_windows: TimingWheel          │ exact timing wheel      │
│  pending_window_horizon_bytes: u64     │ timing wheel horizon    │
│  vs_stream_matches: Vec<VsStreamWindow>│ VS stream callback buf  │
│  pending_spans: Vec<PendingDecodeSpan> │ streaming decode spans  │
│  span_streams: Vec<SpanStreamEntry>    │ nested transform spans  │
│  tmp_findings: Vec<FindingRec>         │ transform scan findings │
│  tmp_drop_hint_end: Vec<u64>           │ aligned with tmp_*      │
│  tmp_norm_hash: Vec<NormHash>          │ aligned with tmp_*      │
│  entropy_scratch: Option<Box<EntropyScratch>> │ 1 KiB histogram  │
│  root_span_map_ctx: Option<RootSpanMapCtx>    │ decode→root map  │
│  last_chunk_start: u64                 │ file position tracking  │
│  last_chunk_len: usize                 │ file position tracking  │
│  last_file_id: Option<FileId>          │ file transition detect  │
├─────────────────────────────────────────────────────────────────┤
│             VECTORSCAN SCRATCH SLOTS                            │
├─────────────────────────────────────────────────────────────────┤
│  vs_scratch: Option<VsScratch>         │ unified prefilter DB    │
│  vs_utf16_scratch: Option<VsScratch>   │ UTF-16 anchor block     │
│  vs_utf16_stream_scratch: Option<VsScratch> │ UTF-16 stream      │
│  vs_stream_scratch: Option<VsScratch>  │ decoded-stream regex    │
│  vs_gate_scratch: Option<VsScratch>    │ decoded gate scanning   │
├─────────────────────────────────────────────────────────────────┤
│             PER-CHUNK / DEBUG REGION                             │
│  (set once per chunk or only under perf-stats/debug)            │
├─────────────────────────────────────────────────────────────────┤
│  safelist_suppressed: usize            │ context safelist count  │
│  secret_bytes_safelist_suppressed: usize │ secret safelist count │
│  uuid_format_suppressed: usize         │ UUID quick-reject count │
│  offline_suppressed: usize             │ offline validation count│
│  confidence_suppressed: usize          │ confidence filter count │
│  root_prefilter_done: bool             │ one-shot prefilter flag │
│  root_prefilter_saw_utf16: bool        │ UTF-16 anchor flag      │
│  chunk_overlap_backscan: usize         │ overlap inference       │
│  capacity_validated: bool              │ idempotent sentinel     │
│  base64_stats: Base64DecodeStats       │ (feature: b64-stats)    │
└─────────────────────────────────────────────────────────────────┘
```

### Parallel-Array Invariant

Three arrays are kept in lock-step at all times:

| Array | Type | Purpose |
|-------|------|---------|
| `out` | `ScratchVec<FindingRec>` | Compact finding records |
| `norm_hash` | `ScratchVec<NormHash>` | BLAKE3 hash of extracted secret bytes |
| `drop_hint_end` | `ScratchVec<u64>` | Absolute offset for overlap-prefix suppression |

Every push, truncation, or drain must maintain this lock-step relationship. Violating it corrupts finding deduplication and materialization. The `retain_findings_aligned` method compacts all three arrays simultaneously using a two-pass algorithm optimized for the common case where nothing is dropped.

### Finding Deduplication

Findings are deduplicated using a fixed 32-byte `DedupKey` (`#[repr(C)]`, `bytemuck::Pod`):

```rust
struct DedupKey {
    file_id: u32,                  //  4 bytes
    rule_id_with_variant: u32,     //  4 bytes (24-bit rule_id + 8-bit variant_disc)
    span_start: u32,               //  4 bytes
    span_end: u32,                 //  4 bytes
    root_hint_start: u64,          //  8 bytes
    root_hint_end: u64,            //  8 bytes
}                                  // 32 bytes total
```

The 32-byte size is chosen to align with the AEGIS-128L absorption rate (2 x 128-bit AES blocks), enabling single-step hashing with no trailing partial-block handling. The `hash128` function produces a 128-bit fingerprint used in two dedup layers:

- **`seen_findings`** (per-file): Suppresses cross-chunk repeats within the same file. Reset on file transitions.
- **`seen_findings_scan`** (per-scan): Enables within-scan replacement (e.g., preferring transform findings over raw findings) without re-emitting earlier chunks.

For transform-derived findings, span coordinates are zeroed when a precise root-span mapping is available (to handle varying decoded offsets across chunks). When mapping is unavailable, the decoded span is included to avoid collapsing distinct matches. Base64 `root_hint_end` values are normalized to the padding-free minimum (snapped by up to 3 bytes) to handle encoding length variance.

The variant discriminator (8-bit) distinguishes UTF-16 LE/BE findings that share the same span and root hint, preventing false dedup suppression.

### DedupKey Constants

| Name | Value | Purpose |
|------|-------|---------|
| `DEDUP_RULE_ID_BITS` | 24 | Bits reserved for rule IDs |
| `DEDUP_RULE_ID_MAX` | 16,777,215 | Maximum encodable rule ID |
| `FINDING_DEDUPE_MULTIPLIER` | 32 | Set sizing factor over `max_findings` |

### Supporting Types

#### EntropyScratch

A 1 KiB byte-frequency histogram (256 x `u32` bins) for entropy gating. Stored as `Option<Box<EntropyScratch>>` so engines without entropy gates pay zero heap cost. Reset via `memset` after each entropy check — O(256) constant cost eliminates the per-byte branch of the previous "touched list" approach.

#### RootSpanMapCtx

Maps decoded-byte spans back to root-buffer coordinates during transform scans. Stores raw `*const TransformConfig` and `*const u8` pointers to avoid lifetime entanglement with the engine and buffer references. Both pointers reference engine-owned data (immutable after construction) that outlives the scan context. Cleared to `None` after each buffer scan completes.

Key operations:
- `map_span(Range<usize>) -> Range<usize>`: Translates decoded-byte offsets to absolute root-buffer coordinates.
- `has_trigger_before_or_in_match(Range<usize>) -> Option<bool>`: Checks for URL-percent triggers within the overlap window.
- `drop_hint_end_for_match(Range<usize>) -> Option<usize>`: Extends drop boundaries past post-match triggers to prevent cross-chunk duplicates.

#### NormHash

`type NormHash = [u8; 32]` — BLAKE3 digest of the raw secret bytes. Used for cross-chunk and cross-run deduplication: two findings with the same `NormHash` are considered the same secret regardless of surrounding context or encoding transform.

## Hit Pool (HitAccPool)

### Purpose

`HitAccPool` accumulates anchor hit windows across all (rule, variant) pairs during prefilter scanning. It is the bridge between Vectorscan's callback-driven hit reporting and the engine's per-rule window validation loop.

### Architecture

Storage is fixed-stride with raw pointers to eliminate bounds-check loads on the hot path:

```
┌───────────────── HitAccPool Header (16 bytes) ──────────────────┐
│  max_hits: u32          │ per-pair cap                           │
│  pair_count: u32        │ total (rule, variant) pairs            │
│  touched_word_count: u32│ ceil(pair_count / 64)                  │
│  _pad: u32              │ alignment padding                      │
├──────────────────────────────────────────────────────────────────┤
│                    Raw Pointer Arrays                            │
├──────────────────────────────────────────────────────────────────┤
│  pair_meta: *mut PairMeta      │ per-pair len + coalesced flag   │
│  windows: *mut SpanU32         │ pair_count × max_hits flat grid │
│  coalesced: *mut SpanU32       │ pair_count fallback spans       │
│  touched_words: *mut u64       │ bitset for O(touched) reset     │
└──────────────────────────────────────────────────────────────────┘
```

### SpanU32

Compact half-open span with a Vectorscan anchor hint:

```rust
struct SpanU32 {
    start: u32,        // window start offset
    end: u32,          // window end offset (exclusive)
    anchor_hint: u32,  // VS `from` offset, clamped to [start, end]
}
```

The `anchor_hint` lets the regex engine start searching near the anchor instead of at window start. When windows are merged, the earliest (smallest) anchor hint is preserved.

### PairMeta

Per-pair hot metadata collocated into 4 bytes for single-load access:

```rust
#[repr(C)]
struct PairMeta {
    len: u16,       // accumulated window count (0..=max_hits)
    coalesced: u8,  // 1 if coalesced, 0 otherwise
    _pad: u8,       // explicit padding
}
```

16 consecutive `PairMeta` entries fit in one 64-byte cache line.

### Push / Coalesce Algorithm

The `push_span_unchecked_hot` method is the primary hot-path entry point:

1. **Mark touched**: Set the pair's bit in the `touched_words` bitset. If this is the first touch, append the pair index to `touched_pairs` for O(touched) reset.

2. **Already coalesced?** If `coalesced != 0`, expand the existing coalesced span (min start, max end, min anchor_hint). Return immediately.

3. **Below cap?** If `len < max_hits`, store the span at `windows[pair * max_hits + len]` and increment `len`. This is the fast path — a single store with no branching.

4. **Overflow** (`len >= max_hits`): Call `coalesce_overflow` (marked `#[cold] #[inline(never)]`). This scans all accumulated windows for the pair, computes the union bounding box (min start, max end, min anchor_hint), stores it in `coalesced[pair]`, sets `coalesced = 1`, and zeroes `len`.

### Drain and Reset

- `take_into(pair, out)`: If coalesced, returns a single superset span. Otherwise, copies the per-hit list in insertion order via `memcpy` and zeroes `len`.
- `reset_pair(pair)`: Zeroes `len` and `coalesced` without returning windows.
- `reset_touched(touched_pairs)`: Clears touched bits in O(#touched), not O(pair_count). Duplicate indices are harmless (bit clear is idempotent).

### Safety Model

All internal arrays are allocated via `Vec::into_boxed_slice()` → `Box::into_raw()`. `Drop` reconstructs `Box<[T]>` from the stored pointer and length. The `unsafe impl Send` is justified by exclusive ownership — the raw pointers are never aliased.

Constructor validation rejects:
- `max_hits == 0`
- `max_hits > u16::MAX` (PairMeta.len overflow)
- `pair_count > u32::MAX`
- `pair_count * max_hits` overflow

### Size Assertions

```rust
assert!(size_of::<PairMeta>() == 4);
```

## Vectorscan Cache (VsDbCache)

### Purpose

`VsDbCache` reduces repeated engine startup time by caching serialized Vectorscan `hs_database_t` objects to disk. Compiling hundreds of regex patterns into a Vectorscan database is expensive (hundreds of milliseconds); loading a cached serialized database is near-instant.

### File Format

```
┌────────────────────────────────────────┐
│ MAGIC (8B): b"VSDBCACH"               │
│ PAYLOAD_LEN (8B, little-endian u64)   │
│ KEY_HASH (32B): blake3(cache_key)     │
├────────────────────────────────────────┤
│ PAYLOAD (PAYLOAD_LEN bytes)           │  ← hs_serialize_database output
├────────────────────────────────────────┤
│ MAC_TAG (16B): AEGIS-128L MAC         │  ← over header ∥ payload
└────────────────────────────────────────┘

HEADER_LEN = 8 + 8 + 32 = 48 bytes
MAC_LEN = 16 bytes
Total overhead = 64 bytes per cached database
```

### Cache Key Computation

The cache key is a deterministic 64-character hex BLAKE3 hash over all compile inputs, length-prefixed to prevent concatenation ambiguity:

```
blake3(
    len_prefix(DOMAIN_TAG)          ← b"scanner-rs-vsdb-v2:blake3+aegis128l-mac"
  ∥ len_prefix(kind)                ← e.g., b"prefilter", b"stream"
  ∥ mode                            ← HS_MODE_BLOCK or HS_MODE_STREAM (u32)
  ∥ platform.tune                   ← u32
  ∥ platform.cpu_features           ← u64
  ∥ platform.reserved1              ← u64
  ∥ platform.reserved2              ← u64
  ∥ len_prefix(HS_VERSION_STRING)   ← Vectorscan library version
  ∥ pattern_count                   ← u64
  ∥ for each pattern:
      len_prefix(pattern_with_nul)
  ∥ flags_discriminator             ← u64::MAX if None, else flags.len()
  ∥ for each flag: flag             ← u32
  ∥ ids.len()                       ← u64
  ∥ for each id: id                 ← u32
)
```

The `DOMAIN_TAG` encodes structural assumptions about the file format and MAC scheme. Changing it automatically invalidates all previously cached files without requiring a manual version bump. The length-prefix ensures `["ab", "c"]` and `["a", "bc"]` hash differently.

`flags: None` is distinguished from `flags: Some(&[])` by using `u64::MAX` as the length discriminator for the `None` case.

### Integrity Verification

A 16-byte AEGIS-128L MAC covers the header and payload bytes:

1. **MAC key derivation**: `blake3(b"vsdb-mac-key" ∥ key_hash)[..16]`. The domain prefix prevents the MAC key from colliding with the cache key itself.
2. **MAC computation**: AEGIS-128L MAC-128 over `header ∥ payload`.
3. **Verification order** on load: magic → payload length → key hash → MAC → deserialize.

Any verification failure causes the corrupt file to be deleted and a cache miss returned.

### Atomic Writes

`try_store` uses write-to-tmp-file + rename for atomic file creation:

```
write → {key}.{pid}.tmp
rename → {key}.hsdb
cleanup tmp (idempotent)
```

If the target file already exists, `try_store` is a no-op (skip duplicate work). Any write failure is silently ignored — correctness never depends on cache persistence.

### Directory Resolution

Three-tier fallback:
1. `SCANNER_VS_DB_CACHE_DIR` environment variable (explicit override)
2. `$HOME/.cache/scanner-rs/vsdb` (XDG-style default)
3. `$TMPDIR/scanner-rs-vsdb` (last resort)

### Environment Controls

| Variable | Effect |
|----------|--------|
| `SCANNER_VS_DB_CACHE=0\|false\|off\|no` | Disables caching entirely |
| `SCANNER_VS_DB_CACHE_DIR=/path` | Overrides cache directory |
| `SCANNER_VS_DB_CACHE_TEST=1` | Enables caching under `cfg!(test)` (disabled by default) |

### Thread Safety

Each `VsDbCache` is used within a single thread during engine construction. Concurrent processes writing the same key are safe because the atomic rename ensures readers never observe partial writes.

## Rule Representation

### Two-Tier Compilation

Rule compilation is split into two stages to keep `RuleCompiled` compact:

```
RuleSpec (api.rs)
  │
  ├─ compile_rule() ──► (RuleCompiled, CompiledGates)
  │                          │               │
  │                          │   Engine::new() pools each gate into
  │                          │   a type-specific Vec on Engine and
  │                          │   patches the u32 index back onto
  │                          │   RuleCompiled.
  │                          │
  │                          ▼
  │                     RuleCompiled   ── hot array iterated per buffer
  │                     RuleCold       ── parallel cold array (name, min confidence)
  │
  ├─ add_pat_raw/owned() ──► anchor map (AHashMap<Vec<u8>, Vec<Target>>)
  │                              │
  │                              ▼
  │                         map_to_patterns() ──► (patterns, targets, offsets)
  │                              │
  │                              ▼
  │                         Vectorscan prefilter DB
  │
  └─ compile_confirm_all() ──► ConfirmAllCompiled (pooled in second pass)
```

### RuleCompiled (Hot)

Iterated for every merged window in the scan loop. Fields ordered by access frequency:

```rust
struct RuleCompiled {
    re: Regex,                       // precompiled regex
    must_contain: Option<&'static [u8]>, // quick-reject literal
    rule_meta: u32,                  // bit-packed metadata (see below)
    // Gate pool indices (NO_GATE = u32::MAX means absent):
    confirm_all: u32,
    keywords: u32,
    value_suppressors: u32,
    entropy: u32,
    char_class: u32,
    local_context: u32,
    two_phase: u32,
    offline_validation: u32,
}
```

Gate indices dereference through corresponding pool `Vec`s on `Engine`:

| Field | Pool on `Engine` |
|-------|------------------|
| `confirm_all` | `confirm_all_gates` |
| `keywords` | `keyword_gates` |
| `value_suppressors` | `value_suppressor_gates` |
| `entropy` | `entropy_gates` |
| `char_class` | `char_class_gates` |
| `local_context` | `local_context_gates` |
| `two_phase` | `two_phase_gates` |
| `offline_validation` | `offline_validation_gates` |

Using `u32::MAX` as a sentinel instead of `Option<u32>` saves 4 bytes per gate field (no discriminant padding), shrinking the struct by ~32 bytes across eight gate fields. Valid pool indices never reach `u32::MAX` because the rule count is bounded by practical memory limits.

### Bit-Packed `rule_meta`

```
bit layout of rule_meta: u32
┌──────────────┬──────────────────────────┬───────────────────────┬───────────────┬──────────┐
│ bits 19..=31 │ bit 18                   │ bit 17                │ bit 16        │ bits 0..=15 │
│ reserved (0) │ uuid_format_secret       │ has_secret_group      │ needs_assign  │ secret_group│
└──────────────┴──────────────────────────┴───────────────────────┴───────────────┴──────────┘
```

- **bits 0..=15**: `secret_group` value (meaningful only when bit 17 is set)
- **bit 16**: `needs_assignment_shape_check` — enables the `key = value` structural precheck
- **bit 17**: `has_secret_group_override` — disambiguates `None` from `Some(u16::MAX)`
- **bit 18**: `uuid_format_secret` — bypasses the UUID-format quick-reject in the safelist

Bit-packing rather than separate `bool` + `Option<u16>` fields saves 6+ bytes of padding per rule, which matters when the hot array is iterated for every merged window.

### RuleCold (Cold)

Stored in `Engine::rules_cold`, a parallel array indexed identically with `Engine::rules_hot`:

```rust
struct RuleCold {
    name: &'static str,   // human-readable rule name
    min_confidence: i8,    // effective minimum confidence threshold
}
```

Only read when a finding survives all gates and is about to be emitted. Separating cold metadata keeps the hot array compact — adding a pointer-sized `name` field would waste cache capacity on data read once per emitted finding, not once per candidate window.

The `min_confidence` threshold is precomputed by `derive_min_confidence` with the following priority cascade (first match wins):
1. Explicit `RuleSpec::min_confidence` override
2. Both keyword + entropy gates configured → `KEYWORD_PRESENT + ENTROPY_PASS` (3)
3. Assignment-shape check enabled → `ASSIGNMENT_SHAPE` (2)
4. Default → 0

### Variant Encoding

Three encoding variants are used throughout the compiled rule representation:

| Variant | `idx()` | `scale()` | Purpose |
|---------|---------|-----------|---------|
| `Raw` | 0 | 1 | Direct byte matching |
| `Utf16Le` | 1 | 2 | Little-endian UTF-16 |
| `Utf16Be` | 2 | 2 | Big-endian UTF-16 |

Variant-indexed `[_; 3]` arrays appear in `TwoPhaseCompiled`, `KeywordsCompiled`, and `ConfirmAllCompiled`. The stable index ordering is used for packed tables, array slots, and the low bits of `Target`.

### Target Mapping

Anchor patterns are deduplicated in a shared pattern table. Each pattern id fans out to multiple rules and variants via `Target`:

```
Target(u32) layout:
┌────────────────────────────────┬───────────┐
│ rule_id (30 bits)              │ variant   │
│                                │ (2 bits)  │
└────────────────────────────────┴───────────┘
```

The `map_to_patterns` function flattens the dedup map into three parallel arrays consumed by the Vectorscan prefilter pipeline:
- `patterns[i]`: the i-th unique anchor pattern (sorted lexicographically for deterministic Vectorscan id assignment)
- `flat_targets[offsets[i]..offsets[i+1]]`: fanout `Target` entries for pattern i
- `offsets`: prefix-sum index with length `patterns.len() + 1`

### PackedPatterns

Stores multiple byte patterns in a single contiguous allocation:

```rust
struct PackedPatterns {
    bytes: Box<[u8]>,     // all patterns back-to-back
    offsets: Box<[u32]>,  // prefix-sum (len = patterns + 1)
}
// size_of::<PackedPatterns>() == 32  (2 × Box<[T]> = 2 × 16)
```

Pattern `i` is `bytes[offsets[i]..offsets[i+1]]`. Uses `Box<[T]>` instead of `Vec<T>` since data is immutable after compilation, saving 8 bytes per field (no capacity word). Contiguous storage enables cache-friendly `memmem` gates without per-window allocations.

### Compiled Gate Types

| Gate | Struct | Per-Variant | Semantics |
|------|--------|-------------|-----------|
| Two-phase | `TwoPhaseCompiled` | `[PackedPatterns; 3]` | Seed → confirm (ANY) → expand |
| Keywords | `KeywordsCompiled` | `[PackedPatterns; 3]` | Any keyword must appear |
| Confirm-all | `ConfirmAllCompiled` | `[Option<Box<[u8]>>; 3]` primary + `[PackedPatterns; 3]` rest | Primary (longest) + ALL remaining |
| Value suppressors | `PackedPatterns` | Raw only | Checked on decoded/extracted bytes |
| Entropy | `EntropyCompiled` | N/A (post-regex) | Shannon + optional min-entropy |
| Char-class | `CharClassCompiled` | N/A | Max lowercase ASCII percentage |
| Local context | `LocalContextSpec` | N/A | Copied verbatim from spec |
| Offline validation | `OfflineValidationSpec` | N/A | Copied verbatim from spec |

Value suppressors are compiled raw-only because they run on extracted secret bytes (always decoded), not on raw UTF-16 window bytes.

## Memory Layout and Size Assertions

Compile-time size guards enforce that hot-path structures remain compact:

| Type | Assertion | Rationale |
|------|-----------|-----------|
| `DedupKey` | `== 32` bytes | Aligns with AEGIS-128L absorption rate |
| `PairMeta` | `== 4` bytes | 16 entries per cache line |
| `PackedPatterns` | `== 32` bytes | 2 × `Box<[T]>` |
| `EntropyCompiled` | `<= 32` bytes | Copied by value in `ResolvedGates` |
| `RuleCompiled` | `<= 88` bytes | Fits in ~1.4 cache lines |
| `RuleCold` | `<= 56` bytes | Minimal cold metadata |

## Lifecycle

### Construction

```
Engine::new()
  └─ ScanScratch::new(engine)
       ├─ Pre-allocates all ScratchVec buffers from tuning parameters
       ├─ Allocates HitAccPool for (rules × 3 variants) pairs
       ├─ Allocates Vectorscan scratch for each DB (5 possible)
       ├─ Creates DecodeSlab with max_total_decode_output_bytes limit
       ├─ Creates dedup sets (FixedSet128) sized to power-of-two
       └─ Conditionally allocates transform buffers (zero-cost when disabled)
```

### Per-Chunk Reset

Two reset variants exist to support the prefilter optimization:

1. **`reset_for_scan(engine)`**: Full reset — clears all transient state including `hit_acc_pool` and `touched_pairs`. Used when the prefilter will run as part of this scan.

2. **`reset_for_scan_after_prefilter(engine)`**: Partial reset — preserves `hit_acc_pool` and `touched_pairs` so the scan loop can immediately consume prefilter results. Used when `scan_chunk_into` runs the Vectorscan prefilter before the per-rule loop.

Both call `reset_common()` (shared logic) then `ensure_capacity(engine)`.

### Common Reset (`reset_common`)

Clears all per-scan transient state:
- Output arrays (`out`, `norm_hash`, `drop_hint_end`)
- Suppression counters
- Work queue and budget trackers
- Decode slab, decode ring, timing wheel
- Stream state vectors
- **Sparse stream-hit reset**: Only zeroes counters that were actually incremented, O(touched) instead of O(rules × 3)
- Step arena and UTF-16 buffer
- Entropy histogram (if allocated)
- Root span map context

### Capacity Validation (`ensure_capacity`)

Idempotent after the first call (guarded by `capacity_validated`). On first call:

1. **Vectorscan scratch rebinding**: Five DB/scratch pairs check whether the scratch is still bound to the current DB pointer and reallocate if not (macro `rebind_vs_scratch!`).
2. **Hit accumulator pool**: Rebuilds if `pair_count` or `max_hits` changed.
3. **Finding output buffers**: Grows `out`, `norm_hash`, `drop_hint_end` if `max_findings` increased.
4. **Work queue / decode arena**: Grows if tuning changed.
5. **Transform-conditional buffers**: Only resized when transforms are active.
6. **Entropy scratch / capture locations**: Allocated or deallocated based on gate presence and rule count.

Capacity policy is monotonic: buffers only grow (never shrink) to avoid allocation thrashing on long scans.

### Per-File State

The `update_chunk_overlap` method tracks file transitions:
- Resets `seen_findings` (cross-chunk dedup) when the file ID changes
- Infers overlap length from previous/current chunk positions
- Updates `chunk_overlap_backscan` for transform dedup boundary widening

### Drain

Two drain methods extract results:
- `drain_findings(out)`: Moves findings into `out`, clears sidecars
- `drain_findings_with_hashes(findings_out, norm_hash_out)`: Moves both findings and aligned hashes

Both assert output capacity is sufficient — they never allocate.

## Performance Considerations

### Why `#[repr(C)]` with a Cache-Line Boundary?

The hot region (findings, work queue, hit accumulators, capture locations) is touched on every scan chunk. The cold region (decode slab, ring buffer, pending windows, stream state) is only touched when transforms fire — the uncommon case for many file types. Separating them with a 64-byte boundary prevents cold-field access from evicting hot-path cache lines.

### Why Raw Pointers in HitAccPool?

`Vec`-backed arrays incur bounds-check loads on every access. Since `pair_count` and `max_hits` are invariant after construction, the bounds are known at construction time. Raw pointers with debug assertions give bounds-check-free access on the hot path while preserving safety verification under debug/Miri/Kani.

### Why Sentinel `NO_GATE` Instead of `Option<u32>`?

`Option<u32>` gets no niche optimization for `u32::MAX`, so it occupies 8 bytes (4 for the value, 4 for the discriminant with alignment). Using `u32::MAX` as a sentinel keeps each gate field at 4 bytes, saving ~32 bytes across eight gate fields in `RuleCompiled`.

### Why Sparse Reset for Stream Hit Counts?

Stream hit counts are indexed `rule_id * 3 + variant_idx` — potentially thousands of entries. Only a fraction are touched per scan. The `stream_hit_touched` list records which indices were incremented, enabling O(touched) reset instead of O(rules × 3) memset.

### Why Separate `RuleCompiled` / `RuleCold`?

The scan loop iterates `rules_hot` for every merged window. If cold metadata (name, min_confidence) were inlined, it would inflate the hot struct and waste cache capacity on data read once per emitted finding. The parallel-array design keeps the hot iteration tight.

### Why Atomic Rename for VsDbCache?

Readers must never observe partial writes. Write-to-tmp + rename is atomic on POSIX filesystems, so concurrent processes can safely share the same cache directory. If the rename fails, the stale tmp file is cleaned up and a cache miss is returned on the next load — no data corruption.

## Source of Truth

| Module | File | Purpose |
|--------|------|---------|
| ScanScratch | `crates/scanner-engine/src/engine/scratch.rs` | Per-scan scratch state, dedup, drain |
| DedupKey | `crates/scanner-engine/src/engine/scratch.rs` | Finding deduplication key |
| EntropyScratch | `crates/scanner-engine/src/engine/scratch.rs` | Entropy histogram |
| RootSpanMapCtx | `crates/scanner-engine/src/engine/scratch.rs` | Decoded→root coordinate mapping |
| CachelineBoundary | `crates/scanner-engine/src/engine/scratch.rs` | Hot/cold region separator |
| HitAccPool | `crates/scanner-engine/src/engine/hit_pool.rs` | Hit accumulator pool (raw pointers) |
| SpanU32 | `crates/scanner-engine/src/engine/hit_pool.rs` | Compact span with anchor hint |
| PairMeta | `crates/scanner-engine/src/engine/hit_pool.rs` | Per-pair collocated metadata |
| VsDbCache | `crates/scanner-engine/src/engine/vs_cache.rs` | On-disk Vectorscan DB cache |
| CacheKeyInput | `crates/scanner-engine/src/engine/vs_cache.rs` | Cache key computation inputs |
| RuleCompiled | `crates/scanner-engine/src/engine/rule_repr.rs` | Hot compiled rule (iterated per window) |
| RuleCold | `crates/scanner-engine/src/engine/rule_repr.rs` | Cold rule metadata (per emission) |
| Variant | `crates/scanner-engine/src/engine/rule_repr.rs` | Encoding variant (Raw/Utf16Le/Utf16Be) |
| Target | `crates/scanner-engine/src/engine/rule_repr.rs` | Packed (rule_id, variant) fanout entry |
| PackedPatterns | `crates/scanner-engine/src/engine/rule_repr.rs` | Contiguous pattern storage |
| TwoPhaseCompiled | `crates/scanner-engine/src/engine/rule_repr.rs` | Two-phase seed→confirm→expand gate |
| KeywordsCompiled | `crates/scanner-engine/src/engine/rule_repr.rs` | Keyword ANY gate |
| ConfirmAllCompiled | `crates/scanner-engine/src/engine/rule_repr.rs` | Mandatory literal ALL gate |
| EntropyCompiled | `crates/scanner-engine/src/engine/rule_repr.rs` | Entropy gate parameters |
| CharClassCompiled | `crates/scanner-engine/src/engine/rule_repr.rs` | Character-class distribution gate |
| NO_GATE | `crates/scanner-engine/src/engine/rule_repr.rs` | Sentinel for absent gate (`u32::MAX`) |
| CompiledGates | `crates/scanner-engine/src/engine/rule_repr.rs` | Transient gate bag from compile_rule |
| compile_rule | `crates/scanner-engine/src/engine/rule_repr.rs` | Rule compilation entry point |
| compile_confirm_all | `crates/scanner-engine/src/engine/rule_repr.rs` | Confirm-all gate compilation |
| map_to_patterns | `crates/scanner-engine/src/engine/rule_repr.rs` | Anchor dedup map → flat arrays |
| derive_min_confidence | `crates/scanner-engine/src/engine/rule_repr.rs` | Confidence threshold derivation |

## Related Modules

- `core.rs`: Orchestrates the scan loop, owns `ScanScratch`, coordinates reset.
- `decode_state.rs`: `DecodeSlab` and `StepArena` — owned by `ScanScratch`.
- `work_items.rs`: `WorkItem`, `PendingDecodeSpan`, `PendingWindow` — carried in scratch queues.
- `vectorscan_prefilter.rs`: `VsScratch`, `VsStreamWindow` — Vectorscan scratch bindings.
- `helpers/`: `hash128`, `pow2_at_least`, `contains_any_memmem`, `contains_all_memmem`.
- `transform.rs`: `STREAM_DECODE_CHUNK_BYTES`, `is_url_trigger`, `map_decoded_offset`.
- `window_validate.rs`: Consumes `RuleCompiled` gate indices to validate candidate windows.
- `safelist.rs`: Emit-time false-positive suppression (see below).
- `perf_counters.rs`: Feature-gated performance instrumentation (see below).

---

## Safelist Filtering (`engine/safelist.rs`)

Emit-time false-positive suppression for detected secrets. When a candidate
secret passes all detection gates, the safelist checks both the surrounding
context window and the bare extracted value against curated pattern sets to
identify synthetic, demo, and placeholder credentials.

**Architecture**: Three tiers evaluated in order:

1. **Context-window tier** (`SafelistFilter::matcher()`, 18 patterns):
   `RegexSet::is_match()` against the byte window surrounding a root finding.
   Any match suppresses. Patterns cover placeholder tokens (`hunter2`,
   `INSERT_YOUR_*`), infrastructure references (`${VAR}`, `localhost` URIs),
   metadata/schema noise (`changeme`, XML namespaces), redaction encodings
   (`***` runs, base64 of "example"/"test"), source control artifacts
   (`AKIA...EXAMPLE`, git conflict markers), and test paths
   (`__tests__`, `fixtures`).

2. **Secret-bytes tier** (`SafelistFilter::secret_bytes_matcher()`, 9 patterns):
   Matched against the bare extracted secret value. Uses `^...$` anchoring
   instead of `\b` word boundaries — `\b` treats hyphens/dots as boundaries,
   which would falsely match placeholder words inside composite secrets
   (e.g., `key-null-safety-9xK2mB` triggering on "null"). Excludes
   context-anchored patterns that require surrounding text to be meaningful.

3. **UUID quick-reject** (`is_uuid_format`): Procedural byte-level check for
   canonical 8-4-4-4-12 hyphenated hex UUID format. Per-rule gating via
   `RuleCompiled::uuid_format_secret()` so rules intentionally matching
   UUID-format secrets bypass suppression.

**Compile-time safety**: `const` assertions guard that pattern array lengths
match declared constants — adding/removing a pattern without updating counts
is a compile error.

Source: `crates/scanner-engine/src/engine/safelist.rs`

---

## Performance Counters (`perf_counters.rs`)

Feature-gated (`perf-counters`) global atomic counters for Git scanning
pipeline instrumentation. When disabled, all recording functions compile to
no-ops and `snapshot()` returns a zeroed struct — zero runtime cost.

**Key types**:
- `GitPerfStats`: `pub` snapshot struct (`Clone, Copy, Debug, Default`).
  Stable shape regardless of feature flag; see
  `crates/scanner-engine/src/perf_counters.rs` for the authoritative field list.

**Recording functions**:
- Public `record_*` helpers cover pack decode, blob scanning, mapping, cache,
  tree loading, and delta-chain histogram updates.
- See `crates/scanner-engine/src/perf_counters.rs` for the authoritative API
  list and bucket definitions.

**Control**:
- `reset()`: zeroes all counters
- `snapshot() -> GitPerfStats`: reads all atomics with `Relaxed` ordering
- `time(f) -> (R, u64)`: measures closure wall-clock nanos

**Design**: All loads/stores use `Relaxed` ordering — counters are for coarse
diagnostics, not exact accounting. Snapshots are not transactionally consistent.
Helper macros `perf_set!` and `perf_let!` let call sites conditionally assign
fields or declare timer bindings without `#[cfg]` wrappers.

Source: `crates/scanner-engine/src/perf_counters.rs`
