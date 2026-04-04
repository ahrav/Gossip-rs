# Shard Algebra — `gossip-frontier`

## 1. Module Purpose

`gossip-frontier` is the translation layer between typed connector keys (file
paths, manifest row IDs) and the opaque `&[u8]` range boundaries that the
coordination layer operates on. It provides byte-order-preserving key
encoding, range arithmetic for split planning, a versionless shard-hint wire
format, and a startup-preallocated shard builder. The crate is `#![forbid(unsafe_code)]`.

### Dependency direction

May depend on `gossip-contracts` (identity + shard data model).
Must **not** reference `gossip-coordination`, `connector`, or `persistence`.

---

## 2. Source File Map

| File | Purpose |
|------|---------|
| `src/lib.rs` | Module root, public `builder` / `hint` / `key_encoding` modules, and public re-exports from `key_encoding` and `hint` |
| `src/key_encoding.rs` | `KeyEncoding` trait, `KeyBuf`, `PathKey`, `ManifestRowKey`, key arithmetic (`prefix_successor`, `key_successor`, `byte_midpoint`), `ShardSpec` constructors from typed keys, `PrefixShardError` |
| `src/hint.rs` | `ShardHint` / `ShardMetadata` wire framing, `MetadataBuf`, `ShardSpecScratch`, typed shard-spec convenience constructors (`range_shard_ref`, `prefix_shard_ref`, `manifest_shard_ref` and `*_into` variants), split hint propagation, decode helpers |
| `src/builder.rs` | `PreallocShardBuilder` — startup-preallocated shard builder with two-phase stage/build workflow |
| `src/key_encoding_tests.rs` | Tests for key encoding and arithmetic |
| `src/hint_tests.rs` | Tests for hint encode/decode and shard-spec constructors |
| `src/builder_tests.rs` | Tests for the preallocated builder |
| `Cargo.toml` | Depends on `gossip-contracts`, `gossip-stdx`, and `thiserror`; dev-depends on `proptest` and `rstest` |

---

## 3. Key Concepts

### Half-open range model

Shards partition the keyspace into half-open intervals `[start, end)` over
lexicographically ordered byte strings — the same model used by Bigtable,
Spanner, FoundationDB, and CockroachDB. All key comparisons in this crate
are plain lexicographic byte comparisons.

### Byte-order-preserving key encoding

Connectors implement the `KeyEncoding` trait so their typed keys produce byte
encodings whose lexicographic order matches logical order:

```text
a < b  (logical ordering)  =>  encode(a) < encode(b)  (byte lex ordering)
```

This invariant is **load-bearing**: cursor monotonicity, shard
range-membership checks, and deterministic split planning all depend on it.
Violating it silently corrupts range boundaries. Implementations must also be
**canonical** (logically equal keys encode identically) and **deterministic**
(a key always encodes the same way).

The coordinator itself never calls `encode_into` directly — it operates on
raw `&[u8]` boundaries produced by the shard builder or split planner.

### Caller-owned buffer pattern

All submodules follow the same zero-allocation calling convention: callers
provide a reusable scratch buffer (`KeyBuf`, `MetadataBuf`, or
`ShardSpecScratch`) and receive borrowed output slices. The returned slices
remain valid only until the same buffer is written again. Callers that need
to retain values across later operations must copy them.

---

## 4. Key Types

### `KeyBuf`

Fixed-capacity stack buffer for shard-key arithmetic. Capacity is
`MAX_KEY_SIZE + 1` (4097 bytes) to accommodate `byte_midpoint`'s internal
carry-expanded arithmetic sum. Tracks the active key prefix via a `len`
field; bytes after `len` are scratch space.

Key methods: `new()`, `as_bytes()`, `len()`, `is_empty()`, `copy_from_slice(&[u8])`.

### `KeyEncoding` trait

```rust
pub trait KeyEncoding: Sized {
    fn encode_into(&self, buf: &mut KeyBuf);
}
```

Implementations must write a complete canonical encoding into `buf` whose
length does not exceed `KeyBuf::CAPACITY`. Calling `KeyBuf::copy_from_slice`
satisfies this contract.

### `PathKey<'a>`

UTF-8 path key encoded as identity bytes (`path.as_bytes()`). No separator
rewriting, Unicode normalization, or case folding is performed. Callers that
need canonical path semantics must normalize before constructing `PathKey`.

Panics if path is empty or exceeds `MAX_KEY_SIZE` (4096 bytes).

### `ManifestRowKey`

Fixed-width 16-byte key encoded as `(manifest_id: u64, row: u64)` in
big-endian. Lexicographic byte ordering matches tuple ordering: compare by
`manifest_id` first, then by `row`. The fixed layout avoids
delimiters/varints and keeps decode cost constant.

`decode_manifest_row_key(key: &[u8]) -> Option<ManifestRowKey>` decodes
exactly 16 bytes; returns `None` for any other length.

### `ShardHint<'a>`

Routing hint embedded in shard metadata. Three variants:

| Variant | Meaning | Wire tag |
|---------|---------|----------|
| `Range` | Generic byte-range shard, no extra narrowing | `0x00` |
| `Prefix { prefix: &[u8] }` | Prefix-bounded shard | `0x01` |
| `Manifest { manifest_id, start_row, end_row }` | Half-open row range within one manifest | `0x02` |

### `ShardMetadata<'a>`

Structured metadata envelope wrapping a `ShardHint` plus connector-opaque
`connector_extra` bytes. The hint is coordination-visible; `connector_extra`
is copied through untouched.

### `MetadataBuf`

Fixed-capacity (`MAX_METADATA_SIZE` = 16384 bytes) reusable scratch buffer
for metadata encoding. Allocate at startup or per-thread and reuse across
repeated `encode_into` calls to avoid per-encode heap allocation.

### `ShardSpecScratch`

Bundles a `KeyBuf` for the start bound, a `KeyBuf` for the end bound, and a
`MetadataBuf` for the encoded metadata envelope. One scratch can be reused
across many helper calls (`range_shard_ref`, `prefix_shard_ref`,
`manifest_shard_ref`). Returned borrowed `ShardSpecRef` values alias this
scratch and become stale once the scratch is mutated again.

### `SplitBoundary`

Simple enum (`Start`, `End`) identifying which child boundary failed
validation during hint propagation.

### `PreallocShardBuilder<'a, const CAP: usize>`

Startup-preallocated shard builder backed by a borrowed `ShardArena`. Tracks
entries in an `InlineVec<BuilderEntry, CAP>` that never spills. A
compile-time assertion rejects `CAP > 1024` to keep stack growth bounded.

---

## 5. Key Functions

### Key arithmetic

| Function | Purpose | Returns `None` when |
|----------|---------|---------------------|
| `prefix_successor(prefix, buf)` | Exclusive upper bound for a prefix scan. Finds rightmost non-`0xFF` byte, truncates trailing `0xFF` suffix, increments last remaining byte. Analogous to FoundationDB `strinc`. | Empty prefix, all-`0xFF`, or exceeds `MAX_KEY_SIZE`. |
| `key_successor(key, buf)` | Minimal strict successor of an arbitrary key. Appends `0x00` if `key.len() < MAX_KEY_SIZE`; delegates to `prefix_successor` if at `MAX_KEY_SIZE`. | Key exceeds `MAX_KEY_SIZE`, or exactly `MAX_KEY_SIZE` bytes and all `0xFF`. |
| `byte_midpoint(a, b, out)` | Approximate bisection point between two keys for split planning. Five-phase algorithm: (1) big-endian addition, (2) halving by long division, (3) overflow-normalized candidate check, (4) fixed-width candidate check, (5) `key_successor` fallback. | `a >= b`, either input exceeds `MAX_KEY_SIZE`, or no interior point exists. |

All three are `O(key.len())` time with no heap allocation.

### ShardSpec constructors (ref variants — zero allocation)

These build a borrowed `ShardSpecRef` from typed inputs using caller-owned
scratch buffers:

| Function | Inputs | Error type |
|----------|--------|------------|
| `shard_spec_from_keys_ref` | Two `KeyEncoding` values + metadata | `ShardSpecInputError` |
| `shard_spec_from_prefix_ref` | `&[u8]` prefix + metadata | `PrefixShardError` |
| `shard_spec_from_manifest_range_ref` | `manifest_id`, `start_row`, `end_row` + metadata | `ShardSpecInputError` |

### ShardSpec constructors (into variants — ref + arena alloc)

Each `*_into` variant combines the corresponding `*_ref` validation with
`ShardArena` allocation, returning a `ShardSpecHandle`:

| Function | Error type |
|----------|------------|
| `shard_spec_from_keys_into` | `ShardIntoError<ShardSpecInputError>` |
| `shard_spec_from_prefix_into` | `ShardIntoError<PrefixShardError>` |
| `shard_spec_from_manifest_range_into` | `ShardIntoError<ShardSpecInputError>` |

### Hint-aware shard constructors

These encode a `ShardHint` into the metadata envelope before building the
spec. Each has `_ref` (borrowed) and `_into` (arena-allocated) variants:

| Function pair | Hint variant | Error type (ref) |
|---------------|-------------|-------------------|
| `range_shard_ref` / `range_shard_into` | `ShardHint::Range` | `ShardSpecInputError` |
| `prefix_shard_ref` / `prefix_shard_into` | `ShardHint::Prefix` | `PrefixShardError` |
| `manifest_shard_ref` / `manifest_shard_into` | `ShardHint::Manifest` | `ShardSpecInputError` |

### Decode helpers

| Function | Purpose |
|----------|---------|
| `decode_metadata(spec)` | Full metadata envelope decode from a `ShardSpecRef` or similar |
| `decode_hint(spec)` | Decode only the `ShardHint` portion |
| `decode_connector_extra(spec)` | Decode only the connector-opaque trailing bytes |

All three validate the full envelope. Empty metadata is interpreted as
`ShardHint::Range` with empty `connector_extra`.

### Split propagation

`propagate_hint_on_split(parent_hint, child_start, child_end)` derives a
child hint from a parent hint and child key-range boundaries:

| Parent hint | Result |
|-------------|--------|
| `Range` | `Range` (no validation on child bounds) |
| `Prefix` | Validates child bounds fall within `[prefix, prefix_successor)`, then **demotes to `Range`** (arbitrary split points inside a prefix are not representable as a single child prefix) |
| `Manifest` | Validates row-key boundaries and returns a narrowed `Manifest` hint |

---

## 6. Hint Wire Format

### No-versioning policy

Hint encoding is intentionally versionless: there is no format version byte
and no compatibility shim. Unknown tags are rejected immediately. Format
evolution is additive by introducing new tags, not by in-band version
negotiation.

### Tag bytes and field layouts

**Range** (1 byte total):
```
[0x00]
```

**Prefix** (5 + N bytes total):
```
[0x01][prefix_len: u32 BE][prefix_bytes: N bytes]
```
`prefix_len` is the byte length of the prefix payload. Maximum prefix size
is capped by `u32` framing width and `MAX_METADATA_SIZE`.

**Manifest** (25 bytes total):
```
[0x02][manifest_id: u64 BE][start_row: u64 BE][end_row: u64 BE]
```
Both encode and decode enforce `start_row < end_row`.

### Metadata envelope

`ShardMetadata` wraps hints as:
```
[hint_len: u32 BE][hint_bytes][connector_extra]
```

- Empty metadata (zero bytes) is treated as absent and decodes to
  `ShardHint::Range` with empty `connector_extra`.
- Non-empty metadata must conform to this framing exactly.
- `connector_extra` is opaque — stored and retrieved verbatim, never
  interpreted by this module.

### Encode/decode protocol

Encoding is two-step:
1. `encoded_len()` performs preflight sizing checks (validates framing
   constraints, returns byte count or error).
2. `encode_into(buf)` writes into a caller-owned `MetadataBuf` and returns a
   borrowed slice.

Decoding is single-step: `ShardHint::decode(data)` returns
`(ShardHint, bytes_consumed)`. `ShardMetadata::decode(metadata)` parses the
envelope and returns the structured metadata. Both return borrowed views
into the input data.

---

## 7. Builder Workflow

### Two-phase stage/build pattern

`PreallocShardBuilder` implements a two-phase workflow:

1. **Stage** — `add_*` and `split_*` methods validate individual shard specs
   and append them to an `InlineVec` entry buffer, allocating arena-backed
   storage for each spec's key range and metadata.

2. **Finalize** — `build_inputs()` materializes `InitialShardInput` rows and
   re-checks manifest-level invariants (uniqueness, bounded ranges, overlap,
   cursor bounds) before handoff to run registration.

Error reporting is split by phase: add-time errors isolate entry-limit
violations, arena capacity failures, and invalid handle rejection.
Build-time errors surface manifest-shape violations.

### Capacity hierarchy

Three limits constrain how many entries can be staged, checked innermost to
outermost:

| Limit | Value | Enforced at |
|-------|-------|-------------|
| `entry_limit` | Caller-chosen, `<= CAP` | Construction |
| `CAP` (const generic) | `<= 1024` (compile-time assertion) | Compile time |
| `MAX_INITIAL_SHARDS` | 10,000 | Construction |

Bulk split helpers additionally enforce `MAX_SPLIT_CHILDREN` (256) as a
per-call fan-out cap before checking the remaining entry budget.

### Add methods

| Method | Shard type | Notes |
|--------|-----------|-------|
| `add_range` / `add_range_with_cursor` | Range | Accepts raw `&[u8]` start/end bounds |
| `add_prefix` / `add_prefix_with_cursor` | Prefix | Derives end bound via `prefix_successor` |
| `add_manifest` / `add_manifest_with_cursor` | Manifest row | Fixed-width `(manifest_id, row)` encoding |
| `add_spec_ref` | Any | Validates and copies a borrowed `ShardSpecRef` |
| `add_spec_handle` | Any | Zero-copy path for existing arena handles |

All `add_*` methods assign monotonically increasing `ShardId` values starting
from 0. Failed adds do not consume IDs.

### Bulk split helpers

| Method | Strategy |
|--------|----------|
| `split_range_by_boundaries(start, split_points, end, connector_extra)` | Interior boundary points yield N+1 contiguous range children. Two-pass: validation-only pass first (no state mutation on boundary error), then allocate-and-stage pass. |
| `split_manifest_by_rows(manifest_id, start_row, end_row, rows_per_shard, connector_extra)` | Fixed-width row chunking with final short tail. Uses saturating arithmetic near `u64::MAX`. |

Both enforce `MAX_SPLIT_CHILDREN` fan-out limit and preflight entry budget.
Neither is fully transactional for slab exhaustion: if a later child
allocation returns `SlabFull`, previously appended children remain staged.

### Lifecycle

- `reset()` frees all arena-backed specs, clears the entry buffer, restarts
  shard IDs at 0. Invalidates any prior handles and `InitialShardInput` slices.
- `Drop` clears the borrowed arena to release all slab-backed specs.

---

## 8. Allocation Discipline

This crate follows the project's tiered allocation policy:

- **HOT paths (per-shard/per-tick steady-state)**: All key arithmetic
  (`prefix_successor`, `key_successor`, `byte_midpoint`), hint encode/decode,
  and shard-spec construction use caller-owned reusable buffers (`KeyBuf`,
  `MetadataBuf`, `ShardSpecScratch`). No per-operation heap allocation.
  Stack-resident scratch buffers are bounded by `KeyBuf::CAPACITY`.

- **WARM paths (split planning, hint propagation)**: `propagate_hint_on_split`
  uses a local `KeyBuf` for the prefix successor computation — one
  stack-local allocation per call, no heap.

- **COLD paths (startup registration)**: `PreallocShardBuilder` preallocates
  entry tracking via `InlineVec` (stack-first, never spills when
  `entry_limit <= CAP`) and delegates spec storage to a caller-provided
  `ShardArena`. The arena itself is heap-allocated at startup, but individual
  add operations are allocation-silent.

### Infrastructure reuse

The crate reuses project-wide allocation infrastructure:

| Used type | From | Purpose |
|-----------|------|---------|
| `InlineVec<T, N>` | `gossip-stdx` | Stack-first entry buffer in builder |
| `ShardArena` / `ShardSpecHandle` | `gossip-contracts` | Slab-backed spec storage |
| `ByteSlab` (via `ShardArena`) | `gossip-stdx` | Underlying byte pool |

---

## 9. Error Types

### `PrefixShardError`

Failures when converting a prefix into a bounded key range.

| Variant | Condition |
|---------|-----------|
| `EmptyPrefix` | Prefix is empty |
| `PrefixTooLarge { size, max }` | Prefix exceeds `MAX_KEY_SIZE` (4096 bytes) |
| `NoSuccessor` | All bytes are `0xFF`; no exclusive upper bound exists |
| `InvalidShardSpec(ShardSpecInputError)` | Derived range failed downstream `ShardSpec` validation |

### `ShardIntoError<E>`

Two-phase `*_into` helper errors: build-time validation (`Build(E)`) vs.
arena capacity exhaustion (`SlabFull(SlabFull)`). The generic `E` varies by
constructor (e.g., `ShardSpecInputError` for range/manifest,
`PrefixShardError` for prefix).

### `ShardHintDecodeError`

Framing errors for standalone hint frame decode.

| Variant | Condition |
|---------|-----------|
| `EmptyData` | Input is empty where a tag byte is required |
| `UnknownTag(u8)` | Tag byte is not `0x00`, `0x01`, or `0x02` |
| `TruncatedPrefix { expected_min, actual }` | Prefix frame is shorter than header + declared length |
| `TruncatedManifest { expected_min, actual }` | Manifest frame is shorter than 25 bytes |
| `InvertedManifestRows { start_row, end_row }` | `start_row >= end_row` |

### `ShardMetadataDecodeError`

Metadata envelope decode failures.

| Field | Meaning |
|-------|---------|
| `hint_error: Option<ShardHintDecodeError>` | `Some(e)` when envelope parsed but inner hint did not; `None` for envelope-structural failures (short length prefix, length exceeds input, consumed bytes != declared hint length) |

### `ShardEncodeError`

Encode failures for both hint-level and metadata-level encoding.

| Variant | Condition |
|---------|-----------|
| `PrefixTooLarge { size, max }` | Prefix bytes exceed `u32` framing width |
| `HintTooLarge { size, max }` | Encoded hint exceeds `MAX_METADATA_SIZE` |
| `MetadataTooLarge { size, max }` | Total metadata (hint + connector_extra + framing) exceeds `MAX_METADATA_SIZE` |
| `InvertedManifestRows { start_row, end_row }` | `start_row >= end_row` |

### `HintPropagationError`

Failures during `propagate_hint_on_split`.

| Variant | Condition |
|---------|-----------|
| `InvalidPrefixBoundary { boundary }` | Child boundary falls outside the parent prefix range |
| `InvalidManifestBoundary { boundary }` | Child boundary is not decodable as `ManifestRowKey` or falls outside parent row bounds |
| `ManifestIdMismatch { parent, child }` | Child boundary uses a different manifest ID than the parent |
| `EmptyManifestRange { start_row, end_row }` | Child rows are inverted or degenerate (`start_row >= end_row`) |

### `PreallocShardBuilderError`

Builder construction, add, and build errors.

| Variant | Phase | Condition |
|---------|-------|-----------|
| `EntryLimitZero` | Construction | `entry_limit` was 0 |
| `CapMismatch { entry_limit, cap }` | Construction | `entry_limit > CAP` |
| `EntryLimitExceedsManifestMax { entry_limit, max }` | Construction | `entry_limit > MAX_INITIAL_SHARDS` |
| `CapacityExceeded { limit, current, additional }` | Add | Append would exceed configured entry budget |
| `FanOutExceeded { limit, requested }` | Add (bulk split) | Child count exceeds `MAX_SPLIT_CHILDREN` (256) |
| `SlabFull(SlabFull)` | Add | Arena handle table or byte slab exhausted |
| `RangeInvalid(ShardSpecInputError)` | Add | Range constructor rejected bounds or metadata |
| `PrefixInvalid(PrefixShardError)` | Add | Prefix constructor rejected prefix semantics |
| `ManifestCtorInvalid(ShardSpecInputError)` | Add | Manifest constructor rejected row bounds or metadata |
| `SpecInvalid(ShardSpecInputError)` | Add | Borrowed spec input failed `ShardSpec::validate_ref` |
| `InvalidSpecHandle` | Add / Build | Handle was stale, foreign, or not live in this arena |
| `ManifestInvalid(ManifestValidationError)` | Build | Staged entries failed manifest-level checks (uniqueness, overlap, unbounded ranges, cursor bounds) |

---

## 10. Source of Truth

| Concept | Authoritative source |
|---------|---------------------|
| Key encoding trait, key arithmetic, typed key schemas | `crates/gossip-frontier/src/key_encoding.rs` |
| Hint wire format, metadata envelope, shard-spec constructors, split propagation | `crates/gossip-frontier/src/hint.rs` |
| Preallocated shard builder | `crates/gossip-frontier/src/builder.rs` |
| `MAX_KEY_SIZE` (4096) | `crates/gossip-contracts/src/coordination/cursor.rs` |
| `MAX_METADATA_SIZE` (16384) | `crates/gossip-contracts/src/coordination/shard_spec.rs` |
| `MAX_INITIAL_SHARDS` (10000) | `crates/gossip-contracts/src/coordination/manifest.rs` |
| `MAX_SPLIT_CHILDREN` (256) | `crates/gossip-contracts/src/coordination/limits.rs` |
| `ShardArena`, `ShardSpec`, `ShardSpecRef`, `ShardSpecHandle` | `crates/gossip-contracts/src/coordination/shard_spec.rs` |
| `InlineVec`, `ByteSlab`, `SlabFull` | `crates/gossip-stdx/` |
