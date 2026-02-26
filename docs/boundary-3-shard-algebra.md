# Boundary 3 -- Shard Algebra

## 1. Overview

Boundary 3 (Shard Algebra) is the bridge between connectors -- which think
in typed keys like file paths or manifest rows -- and the coordination
layer -- which operates on opaque `&[u8]` range boundaries. It lives in
`crates/gossip-frontier/src/` across three modules. All submodules follow a
caller-owned-buffer pattern that eliminates per-operation heap allocation on
coordination hot paths (acquire, checkpoint, split).

The crate provides three core capabilities:

- **Byte-order-preserving key encoding** -- the `KeyEncoding` trait and its
  two implementations (`PathKey`, `ManifestRowKey`) map typed connector keys
  to byte slices whose lexicographic ordering matches the logical ordering
  of the source type. Range arithmetic helpers (`prefix_successor`,
  `key_successor`, `byte_midpoint`) support split planning without heap
  allocation.

- **Shard hint metadata** -- a versionless wire framing for routing hints
  (`ShardHint`) and connector-private metadata (`ShardMetadata`), plus
  allocation-free shard-spec constructors (`range_shard_ref`,
  `prefix_shard_ref`, `manifest_shard_ref`) and split-propagation logic
  (`propagate_hint_on_split`).

- **Startup-preallocated shard builder** -- a `PreallocShardBuilder` that
  stages shard registrations into a borrowed arena with bounded capacity,
  transactional add semantics, and build-time manifest validation.

### Source files

| File               | Role                                                                                       |
|--------------------|--------------------------------------------------------------------------------------------|
| `lib.rs`           | Crate root, `#![forbid(unsafe_code)]`, public re-exports                                  |
| `key_encoding.rs`  | `KeyEncoding` trait, `PathKey`, `ManifestRowKey`, range arithmetic, `ShardSpec` constructors |
| `hint.rs`          | `ShardHint` / `ShardMetadata` wire framing, shard-spec builders, split propagation          |
| `builder.rs`       | `PreallocShardBuilder` -- staged manifest construction with arena backing                  |

---

## 2. Architectural Layering

```text
                ┌───────────────────────┐
                │     connectors        │  typed keys (PathKey, ManifestRowKey)
                └───────────┬───────────┘
                            │ encode
                            ▼
         ┌──────────────────────────────────┐
         │  gossip-frontier (Boundary 3)    │  key encoding, hints, builder
         └──────────┬───────────────────────┘
                    │ depends on
                    ▼
         ┌──────────────────────────────────┐
         │  gossip-contracts::coordination  │  ShardSpec, Cursor, split planning
         │  (Boundary 2 data model)         │  core, limits, validation
         └──────────────────────────────────┘
                    ▲
                    │ depends on
         ┌──────────┴───────────────────────┐
         │  gossip-coordination             │  split execution, protocol,
         │  (Boundary 2 protocol)           │  state machine, sim harness
         └──────────────────────────────────┘
```

### Ownership boundaries

| Concern                        | Owner                           | Examples                                                                       |
|--------------------------------|---------------------------------|--------------------------------------------------------------------------------|
| Split planning core            | `gossip-contracts::coordination` | `SplitReplacePlan`, `SplitResidualPlan`, `plan_split_replace*`, `plan_split_residual*` |
| Split execution                | `gossip-coordination`           | `derive_split_shard_id`, payload hashing, `SplitReplaceResult`, `SplitResidualResult` |
| Key encoding + range arithmetic | `gossip-frontier`               | `KeyEncoding`, `PathKey`, `byte_midpoint`, `prefix_successor`                   |
| Hint metadata + shard builders | `gossip-frontier`               | `ShardHint`, `ShardMetadata`, `range_shard_ref`, `PreallocShardBuilder`         |
| Shard data model               | `gossip-contracts::coordination` | `ShardSpec`, `ShardSpecRef`, `Cursor`, `CursorUpdate`, limits constants         |

### Dependency direction

`gossip-frontier` and `gossip-coordination` are **siblings** -- they share
the same parent dependency (`gossip-contracts`) but must never reference
each other. Neither crate may import the other. Both depend on
`gossip-contracts` for identity types (`TenantId`, `ShardId`, `RunId`) and
the coordination data model (`ShardSpec`, `Cursor`, split planning types).

```text
  gossip-frontier ──────────┐
                            ├──► gossip-contracts
  gossip-coordination ──────┘
```

`gossip-frontier` must NOT reference `gossip-coordination`, `connector`,
or `persistence`.

---

## 3. Key Encoding

### KeyEncoding trait

```rust
pub trait KeyEncoding: Sized {
    fn encode_into(&self, buf: &mut KeyBuf);
}
```

Two load-bearing contracts:

1. **Order preservation** -- `a < b` (logical) implies
   `encode(a) < encode(b)` (byte lexicographic). This is required for
   cursor monotonicity, shard range-membership checks, and split planning
   correctness.

2. **Canonicality** -- logically equal keys encode to identical byte
   strings. A single key must not encode differently across calls.

### PathKey

UTF-8 file-system path encoded as identity bytes (`path.as_bytes()`).
No separator rewriting, no Unicode normalization, no case folding. The
constructor panics on empty paths or paths exceeding `MAX_KEY_SIZE`.

### ManifestRowKey

Fixed-width 16-byte key: `(manifest_id: u64, row: u64)` in big-endian.
Lexicographic byte ordering matches tuple ordering -- compare by
`manifest_id` first, then `row`. The fixed layout avoids delimiters and
varints.

### Range arithmetic

| Function           | Purpose                                                        | Complexity  |
|--------------------|----------------------------------------------------------------|-------------|
| `prefix_successor` | Lexicographic successor of a byte prefix (FoundationDB `strinc`) | O(n)        |
| `key_successor`    | Smallest key strictly greater, bounded by `MAX_KEY_SIZE`       | O(n)        |
| `byte_midpoint`    | Interior midpoint in `(a, b)` for split planning              | O(max(m,n)) |

All three write into caller-owned `KeyBuf` scratch and perform zero heap
allocation.

**`prefix_successor` algorithm:** Find rightmost non-`0xFF` byte, truncate
to include it, increment by one. Returns `None` for empty or all-`0xFF`
prefixes. Analogous to FoundationDB `strinc` / CockroachDB
`Key.PrefixEnd`.

**`key_successor` strategy:** Below `MAX_KEY_SIZE`, append `0x00`
(infallible, tightest possible successor). At `MAX_KEY_SIZE`, delegate to
`prefix_successor`. Above `MAX_KEY_SIZE`, return `None`.

**`byte_midpoint` algorithm (4 phases):**
1. Pad shorter input to `max_len`, compute `a + b` from LSB with carry.
2. Halve the sum by long division from MSB.
3. Try overflow-normalized candidate (drop leading `0x00` if
   `len == max_len + 1`).
4. Fallback to `key_successor(a)` if it remains `< b`.

Returns `None` when `a >= b`, either input exceeds `MAX_KEY_SIZE`, or no
interior point can be represented within the size bound.

### ShardSpec constructors

Six functions construct `ShardSpecRef` or `ShardSpecHandle` from typed
inputs. Each has a `_ref` variant (borrowed, zero-alloc) and an `_into`
variant (arena-allocated):

| Function pair                       | Input                                    | Key range                                   |
|-------------------------------------|------------------------------------------|---------------------------------------------|
| `shard_spec_from_keys_{ref,into}`   | `(Start: KeyEncoding, End: KeyEncoding)` | `[encode(start), encode(end))`              |
| `shard_spec_from_prefix_{ref,into}` | prefix bytes                             | `[prefix, prefix_successor(prefix))`        |
| `shard_spec_from_manifest_range_{ref,into}` | `(manifest_id, start_row, end_row)` | `[ManifestRowKey(id,start), ManifestRowKey(id,end))` |

---

## 4. Hint Metadata

### Wire format

Hint encoding is intentionally **versionless** -- no format version byte,
no compatibility shim. Unknown tags are rejected immediately. Evolution is
additive via new tags only.

#### Hint tags

| Tag    | Variant    | Wire form                                                   | Size    |
|:------:|------------|-------------------------------------------------------------|---------|
| `0x00` | `Range`    | `[0x00]`                                                    | 1 B     |
| `0x01` | `Prefix`   | `[0x01][prefix_len: u32 BE][prefix_bytes]`                  | 5 + n B |
| `0x02` | `Manifest` | `[0x02][manifest_id: u64 BE][start_row: u64 BE][end_row: u64 BE]` | 25 B    |

`Manifest` enforces `start_row < end_row` on both encode and decode.

#### Metadata envelope

```text
[hint_len: u32 BE][hint_bytes][connector_extra]
```

Empty metadata decodes to `ShardHint::Range` with empty `connector_extra`.
Non-empty metadata must match this framing exactly.

### ShardHint

Routing hint embedded in shard metadata. Three variants (`Range`, `Prefix`,
`Manifest`) corresponding to the three tag encodings. Provides
`encode_into` (writes into `MetadataBuf`) and `decode` (returns
`(hint, bytes_consumed)`).

### ShardMetadata

Structured metadata envelope pairing a `ShardHint` with opaque
`connector_extra` bytes. Provides `encode_into` and `decode` for the
full envelope.

### Convenience constructors

Six allocation-free shard-spec builders pair hint encoding with
`ShardSpec` construction:

| Function pair                     | Hint variant | Key range derivation                     |
|-----------------------------------|:------------:|------------------------------------------|
| `range_shard_{ref,into}`          | `Range`      | Caller-provided `[start, end)`           |
| `prefix_shard_{ref,into}`        | `Prefix`     | `[prefix, prefix_successor(prefix))`     |
| `manifest_shard_{ref,into}`      | `Manifest`   | `[ManifestRowKey(id,start), ManifestRowKey(id,end))` |

### Decode helpers

| Function               | Returns                                     |
|------------------------|---------------------------------------------|
| `decode_metadata`      | Full `ShardMetadata` (hint + connector_extra) |
| `decode_hint`          | `ShardHint` only                            |
| `decode_connector_extra` | Connector-opaque trailing bytes only       |

All three accept any `impl IntoShardSpecRef` and return borrowed views.

### Split propagation

`propagate_hint_on_split` derives a child hint from a parent hint and the
child's key-range boundaries:

| Parent hint | Child hint  | Rule                                                              |
|:-----------:|:-----------:|-------------------------------------------------------------------|
| `Range`     | `Range`     | Unconditional passthrough                                         |
| `Prefix`    | `Range`     | Validates child bounds within prefix range, then **demotes** to `Range` because arbitrary split boundaries inside one prefix are not representable as a single child prefix |
| `Manifest`  | `Manifest`  | Validates row-key boundaries and returns narrowed `Manifest` with adjusted `start_row` / `end_row` |

---

## 5. Builder

### PreallocShardBuilder

Startup-preallocated shard builder that stages shard registrations into a
borrowed arena with bounded capacity. The const-generic `CAP` parameter
controls the inline buffer size (compile-time assertion rejects `CAP > 1024`).

### Two-phase workflow

1. **Stage** -- `add_range`, `add_prefix`, `add_manifest` (and
   `*_with_cursor` variants), `add_spec_ref`, `add_spec_handle`,
   `split_range_by_boundaries`, `split_manifest_by_rows`.
2. **Finalize** -- `build_inputs` materializes borrowed manifest rows,
   re-validates handle liveness, and runs `validate_manifest`.

### Transactional semantics

- Successful `add_*` appends exactly one entry and consumes one shard ID.
- Failed `add_*` leaves the manifest unchanged.
- Bulk splits (`split_range_by_boundaries`, `split_manifest_by_rows`)
  preflight fan-out and entry budget before staging.
- `split_range_by_boundaries` performs a two-pass approach: (1) validation-only
  via `range_shard_ref`, (2) allocate-and-stage. Boundary errors leave the
  builder unchanged.
- `build_inputs` is read-only and idempotent.

### Capacity hierarchy

| Limit                  | Scope          | Value       | Purpose                                      |
|------------------------|----------------|-------------|----------------------------------------------|
| `entry_limit`          | Per-builder    | Caller-set  | Logical cap on staged entries                |
| `CAP`                  | Const-generic  | <= 1024     | Inline buffer size (compile-time bound)      |
| `MAX_INITIAL_SHARDS`   | System-wide    | From contracts | Absolute ceiling for initial shard count   |
| `MAX_SPLIT_CHILDREN`   | Per-split      | 256         | Maximum children in a single bulk split      |

### Shard ID assignment

IDs are assigned sequentially from 0 via `ShardId::from_raw(n)`.
`reset()` restarts the counter at 0 and frees all arena-backed specs.

### Drop behavior

The `Drop` impl clears the borrowed arena, releasing all slab-backed specs.
This prevents arena leaks when a builder goes out of scope without
`build_inputs` being called.

---

## 6. Zero-Allocation Design

All submodules follow the same caller-owned-buffer pattern: callers provide
a reusable scratch buffer and receive borrowed output slices. This
eliminates per-operation heap allocation on coordination hot paths.

### Buffer types

| Type              | Capacity           | Module         | Purpose                                        |
|-------------------|--------------------|----------------|-------------------------------------------------|
| `KeyBuf`          | `MAX_KEY_SIZE + 1` | `key_encoding` | Reusable stack buffer for key arithmetic        |
| `MetadataBuf`     | `MAX_METADATA_SIZE` | `hint`        | Reusable buffer for hint/metadata encoding      |
| `ShardSpecScratch` | 2 `KeyBuf` + 1 `MetadataBuf` | `hint` | Composite scratch for shard-spec construction |

All three implement `Default` and can be reused across operations without
reallocation.

### Ref vs Into pattern

Every shard-spec constructor exists in two forms:

- **`*_ref`** -- returns a borrowed `ShardSpecRef<'a>` that aliases the
  caller's scratch buffers. Zero heap allocation. Returned references
  become stale once the scratch is mutated.

- **`*_into`** -- calls the `_ref` variant, then copies bytes into a
  `ShardArena`. Returns an owned `ShardSpecHandle`. One arena allocation
  per call.

The `_ref` form is preferred on hot paths where the caller controls scratch
lifetime. The `_into` form is used when specs must outlive the scratch
buffer (e.g., builder staging).

---

## 7. Allocation Tier Classification

Following the project's tiered allocation policy:

| Tier   | Functions / Paths                                                    | Policy                                |
|--------|----------------------------------------------------------------------|---------------------------------------|
| **HOT**  | `key_encoding::encode_into`, `prefix_successor`, `key_successor`, `byte_midpoint`, `ShardHint::encode_into`, `ShardHint::decode`, `decode_hint`, `decode_metadata`, `decode_connector_extra` | Allocation-silent. Caller-owned `KeyBuf` / `MetadataBuf` scratch only. No heap allocation. |
| **WARM** | `range_shard_ref`, `prefix_shard_ref`, `manifest_shard_ref`, `shard_spec_from_*_ref`, `propagate_hint_on_split`, `*_into` arena allocation paths, split planning (`plan_split_replace*`, `plan_split_residual*` in contracts) | Simpler contracts. Arena allocation via `ShardArena` is bounded and pooled. Split planning is WARM -- allocation via `InlineVec` on stack. |
| **COLD** | `PreallocShardBuilder::new`, `build_inputs`, `reset`, startup shard registration | Startup-only. Inline buffer allocation (`InlineVec<BuilderEntry, CAP>`), manifest validation. Optimizes for clarity and atomicity over preallocation plumbing. |

---

## 8. Type Reference Table

| Type                         | Width / Capacity       | Construction                              | Module         | Key Traits                              |
|------------------------------|------------------------|-------------------------------------------|----------------|-----------------------------------------|
| `KeyBuf`                     | `MAX_KEY_SIZE + 1` B   | `new()` / `Default`                       | `key_encoding` | Clone, Debug, Default                   |
| `KeyEncoding`                | (trait)                | --                                        | `key_encoding` | Sized                                   |
| `PathKey<'a>`                | variable (str ref)     | `new(path)` (panics if empty/oversized)   | `key_encoding` | Clone, Copy, Debug, Eq, Ord, Hash       |
| `ManifestRowKey`             | 16 B (2 x u64 BE)     | `new(manifest_id, row)`                   | `key_encoding` | Clone, Copy, Debug, Eq, Ord, Hash       |
| `PrefixShardError`           | enum (4 variants)      | from constructor errors                   | `key_encoding` | Clone, Debug, Eq, Display, Error        |
| `ShardIntoError<E>`          | enum (2 variants)      | from `*_into` functions                   | `key_encoding` | Clone, Debug, Eq, Display, Error        |
| `MetadataBuf`                | `MAX_METADATA_SIZE` B  | `new()` / `Default`                       | `hint`         | Debug, Default                          |
| `ShardSpecScratch`           | composite              | `new()` / `Default`                       | `hint`         | Debug, Default                          |
| `ShardHint<'a>`              | enum (3 variants)      | variant constructors                      | `hint`         | Clone, Copy, Debug, Eq                  |
| `ShardMetadata<'a>`          | struct (hint + extra)  | `from_hint(h)` / `new(h, extra)`          | `hint`         | Clone, Copy, Debug, Eq                  |
| `ShardHintDecodeError`       | enum (5 variants)      | from `ShardHint::decode`                  | `hint`         | Clone, Copy, Debug, Eq, Display, Error  |
| `ShardMetadataDecodeError`   | struct                 | from `ShardMetadata::decode`              | `hint`         | Clone, Copy, Debug, Eq, Display, Error  |
| `ShardEncodeError`           | enum (4 variants)      | from encode operations                    | `hint`         | Clone, Copy, Debug, Eq, Display, Error  |
| `SplitBoundary`              | enum (2 variants)      | `Start` / `End`                           | `hint`         | Clone, Copy, Debug, Eq, Display         |
| `HintPropagationError`       | enum (4 variants)      | from `propagate_hint_on_split`            | `hint`         | Clone, Copy, Debug, Eq, Display, Error  |
| `PreallocShardBuilder<'a, CAP>` | inline `CAP` entries | `new(arena, entry_limit)`                 | `builder`      | (Drop)                                  |
| `PreallocShardBuilderError`  | enum (12 variants)     | from builder operations                   | `builder`      | Clone, Debug, Eq, Display, Error        |

---

## 9. Invariant-to-Test Matrix

### Key Encoding Invariants

| #  | Invariant                                  | Enforcement          | Test Name(s)                                                                          | Source File             |
|----|--------------------------------------------|----------------------|---------------------------------------------------------------------------------------|-------------------------|
| 1  | `PathKey` order preservation               | proptest             | `path_key_encoding_preserves_logical_order`                                           | `key_encoding_tests.rs` |
| 2  | `PathKey` identity encoding                | unit test            | `path_key_uses_identity_utf8_encoding`                                                | `key_encoding_tests.rs` |
| 3  | `PathKey` rejects empty/oversized          | `#[should_panic]`    | `path_key_new_rejects_empty_path`, `path_key_new_rejects_oversized_path`              | `key_encoding_tests.rs` |
| 4  | `PathKey` accepts max-size path            | unit test            | `path_key_new_accepts_path_at_max_size`                                               | `key_encoding_tests.rs` |
| 5  | `ManifestRowKey` order preservation        | proptest             | `manifest_row_key_encoding_preserves_logical_order`                                   | `key_encoding_tests.rs` |
| 6  | `ManifestRowKey` fixed-width roundtrip     | unit + proptest      | `manifest_row_key_is_fixed_width_and_decodes`, `manifest_row_key_encode_decode_roundtrip` | `key_encoding_tests.rs` |
| 7  | `ManifestRowKey` rejects non-16B inputs    | unit test            | `decode_manifest_row_key_rejects_non_fixed_width_inputs`                              | `key_encoding_tests.rs` |
| 8  | `prefix_successor` strictly greater        | proptest             | `prefix_successor_is_strictly_greater`                                                | `key_encoding_tests.rs` |
| 9  | `prefix_successor` is tight upper bound    | proptest             | `prefix_successor_is_upper_bound_for_prefixed_keys`                                   | `key_encoding_tests.rs` |
| 10 | `prefix_successor` edge cases              | unit test            | `prefix_successor_basic`                                                              | `key_encoding_tests.rs` |
| 11 | `key_successor` strictly greater           | proptest             | `key_successor_is_strictly_greater`                                                   | `key_encoding_tests.rs` |
| 12 | `key_successor` strategy correctness       | proptest             | `key_successor_none_only_when_expected`, `key_successor_appends_zero_when_below_max`, `key_successor_delegates_to_prefix_successor_at_max` | `key_encoding_tests.rs` |
| 13 | `byte_midpoint` strictly between           | proptest             | `byte_midpoint_is_strictly_between_when_present`, `byte_midpoint_different_lengths_strictly_between` | `key_encoding_tests.rs` |
| 14 | `byte_midpoint` respects `MAX_KEY_SIZE`    | unit test            | `byte_midpoint_output_respects_max_key_size`, `byte_midpoint_rejects_oversized_inputs` | `key_encoding_tests.rs` |
| 15 | `byte_midpoint` edge cases                 | rstest parameterized | `byte_midpoint_edge_cases` (8 cases)                                                  | `key_encoding_tests.rs` |
| 16 | `byte_midpoint` carry regression           | unit test            | `byte_midpoint_carry_regression`                                                      | `key_encoding_tests.rs` |
| 17 | Prefix shard produces valid half-open range | proptest            | `shard_spec_from_prefix_produces_valid_half_open_range`                                | `key_encoding_tests.rs` |
| 18 | Manifest range rejects inverted/degenerate | proptest             | `shard_spec_from_manifest_range_rejects_inverted_or_degenerate`                        | `key_encoding_tests.rs` |
| 19 | Error Display formatting                   | rstest parameterized | `prefix_shard_error_display_contains` (3 cases)                                       | `key_encoding_tests.rs` |
| 20 | Error source delegation                    | unit test            | `prefix_shard_error_source_delegates_for_invalid_shard_spec`                           | `key_encoding_tests.rs` |

### Hint Metadata Invariants

| #  | Invariant                                  | Enforcement          | Test Name(s)                                                                          | Source File      |
|----|--------------------------------------------|----------------------|---------------------------------------------------------------------------------------|------------------|
| 21 | `ShardHint` encode/decode roundtrip        | unit + proptest      | `shard_hint_range_roundtrip`, `shard_hint_prefix_roundtrip`, `shard_hint_manifest_roundtrip`, `shard_hint_proptest_roundtrip` | `hint_tests.rs`  |
| 22 | `ShardHint` decode rejects malformed       | unit test            | `shard_hint_decode_rejects_empty_data`, `shard_hint_decode_rejects_unknown_tag`, `shard_hint_decode_rejects_truncated_prefix_header`, `shard_hint_decode_rejects_truncated_prefix_payload`, `shard_hint_decode_rejects_truncated_manifest` | `hint_tests.rs`  |
| 23 | Manifest `start_row < end_row` enforced    | unit test            | `shard_hint_decode_rejects_inverted_manifest_rows`, `shard_hint_decode_rejects_equal_manifest_rows`, `shard_hint_encode_rejects_inverted_manifest_rows`, `shard_hint_encode_rejects_equal_manifest_rows`, `shard_hint_decode_rejects_raw_inverted_manifest` | `hint_tests.rs`  |
| 24 | Trailing bytes returned as consumed length | unit test            | `shard_hint_decode_returns_consumed_length_with_trailing_bytes`                        | `hint_tests.rs`  |
| 25 | `ShardMetadata` envelope roundtrip         | unit + proptest      | `shard_metadata_encode_decode_roundtrip`, `shard_metadata_proptest_roundtrip`          | `hint_tests.rs`  |
| 26 | Empty metadata defaults to Range           | unit test            | `shard_metadata_decode_empty_defaults_to_range_hint`                                  | `hint_tests.rs`  |
| 27 | `ShardMetadata` rejects malformed envelope | unit test            | `shard_metadata_decode_rejects_non_empty_non_conforming_input`, `shard_metadata_encode_rejects_oversized_payload` | `hint_tests.rs`  |
| 28 | Convenience constructors roundtrip         | unit test            | `range_shard_roundtrip_with_decode_helpers`, `prefix_shard_roundtrip_with_decode_helpers`, `manifest_shard_roundtrip_with_decode_helpers` | `hint_tests.rs`  |
| 29 | Prefix shard rejects invalid prefixes      | unit test            | `prefix_shard_rejects_oversized_prefix_with_prefix_too_large`, `prefix_shard_rejects_all_ff_prefix`, `prefix_shard_rejects_empty_prefix` | `hint_tests.rs`  |
| 30 | Prefix shard contains all prefixed keys    | proptest             | `prefix_shard_contains_all_keys_with_prefix`                                          | `hint_tests.rs`  |
| 31 | Range propagation stays Range              | unit test            | `propagate_hint_on_split_range_stays_range`                                           | `hint_tests.rs`  |
| 32 | Prefix propagation demotes to Range        | unit test            | `propagate_hint_on_split_prefix_demotes_to_range`                                     | `hint_tests.rs`  |
| 33 | Prefix propagation validates bounds        | unit test            | `propagate_hint_on_split_prefix_rejects_out_of_range_start`, `propagate_hint_on_split_prefix_rejects_out_of_range_end` | `hint_tests.rs`  |
| 34 | Manifest propagation narrows rows          | unit test            | `propagate_hint_on_split_manifest_adjusts_child_rows`, `propagate_hint_on_split_manifest_child_end_at_parent_end` | `hint_tests.rs`  |
| 35 | Manifest propagation rejects invalid       | unit test            | `propagate_hint_on_split_manifest_rejects_non_manifest_boundaries`, `propagate_hint_on_split_manifest_rejects_manifest_id_mismatch`, `propagate_hint_on_split_manifest_rejects_out_of_parent_bounds`, `propagate_hint_on_split_manifest_rejects_empty_child_range`, `propagate_hint_on_split_manifest_rejects_non_manifest_end_boundary`, `propagate_hint_on_split_manifest_rejects_end_manifest_id_mismatch`, `propagate_hint_on_split_manifest_rejects_end_row_beyond_parent` | `hint_tests.rs`  |
| 36 | Decode helpers propagate errors            | unit test            | `decode_helpers_propagate_malformed_metadata_errors`                                  | `hint_tests.rs`  |

### Builder Invariants

| #  | Invariant                                  | Enforcement          | Test Name(s)                                                                          | Source File        |
|----|--------------------------------------------|----------------------|---------------------------------------------------------------------------------------|--------------------|
| 37 | Mixed shard types build valid manifest     | unit test            | `mixed_range_prefix_manifest_builds_valid_manifest`                                   | `builder_tests.rs` |
| 38 | IDs assigned sequentially from 0           | unit test            | `ids_are_assigned_in_insertion_order`                                                  | `builder_tests.rs` |
| 39 | Default add uses initial cursor            | unit test            | `default_add_methods_use_initial_cursor`                                              | `builder_tests.rs` |
| 40 | `*_with_cursor` preserves explicit cursor  | unit test            | `with_cursor_methods_preserve_non_initial_cursor`, `add_manifest_with_cursor_preserves_initial_cursor`, `add_manifest_with_cursor_preserves_explicit_cursor` | `builder_tests.rs` |
| 41 | Cursor-out-of-bounds fails at build time   | unit test            | `cursor_outside_range_fails_manifest_validation`                                      | `builder_tests.rs` |
| 42 | Overlapping ranges fail at build time      | unit test            | `overlapping_ranges_fail_on_build_validation`                                         | `builder_tests.rs` |
| 43 | Empty builder fails at build time          | unit test            | `build_inputs_on_empty_builder_returns_manifest_empty`                                | `builder_tests.rs` |
| 44 | `build_inputs` is idempotent               | unit test            | `build_inputs_is_idempotent`                                                          | `builder_tests.rs` |
| 45 | Entry limit enforced                       | unit test            | `entry_limit_exhaustion_returns_capacity_exceeded`                                    | `builder_tests.rs` |
| 46 | Arena exhaustion surfaced as `SlabFull`     | unit test            | `arena_slot_exhaustion_returns_slab_full`, `arena_byte_exhaustion_returns_slab_full`, `add_spec_ref_slab_full` | `builder_tests.rs` |
| 47 | Stale/foreign handles rejected             | unit test            | `stale_or_foreign_handle_is_rejected_without_panic`                                   | `builder_tests.rs` |
| 48 | `reset` restores builder to fresh state    | unit test            | `reset_allows_fresh_reuse_and_resets_ids`                                             | `builder_tests.rs` |
| 49 | `add_spec_ref` validates and allocates     | unit test            | `add_spec_ref_happy_path`, `add_spec_ref_rejects_inverted_range`                      | `builder_tests.rs` |
| 50 | Config rejects invalid limits              | unit test            | `config_rejects_zero_entry_limit`, `config_rejects_entry_limit_exceeding_cap`         | `builder_tests.rs` |
| 51 | Error mapping for invalid inputs           | unit test            | `add_range_with_inverted_bounds_returns_range_invalid`, `add_prefix_with_empty_prefix_returns_prefix_invalid`, `add_manifest_with_inverted_rows_returns_manifest_ctor_invalid` | `builder_tests.rs` |
| 52 | `split_range_by_boundaries` atomicity      | unit test            | `split_range_by_boundaries_exact_capacity_preserves_ordering`, `split_range_by_boundaries_under_capacity_succeeds`, `split_range_capacity_exceeded_has_no_partial_writes`, `split_range_fan_out_exceeded_has_no_partial_writes` | `builder_tests.rs` |
| 53 | `split_manifest_by_rows` atomicity         | unit test            | `split_manifest_by_rows_exact_capacity_tiles_manifest_rows`, `split_manifest_by_rows_under_capacity_succeeds`, `split_manifest_by_rows_capacity_exceeded_has_no_partial_writes`, `split_manifest_by_rows_fan_out_exceeded_has_no_partial_writes` | `builder_tests.rs` |
| 54 | Manifest split handles u64 boundary        | unit test            | `split_manifest_by_rows_handles_u64_boundary_without_wrap`                             | `builder_tests.rs` |

---

## 10. Running Tests

```bash
# All frontier tests
cargo test -p gossip-frontier

# Individual modules
cargo test -p gossip-frontier --lib key_encoding_tests
cargo test -p gossip-frontier --lib hint_tests
cargo test -p gossip-frontier --lib builder_tests
```

---

## 11. Design Decisions

| ID   | Decision                                                                                  |
|------|-------------------------------------------------------------------------------------------|
| D3.1 | `KeyEncoding` trait requires order-preserving, canonical encoding                         |
| D3.2 | `PathKey` uses identity encoding (no normalization, no case folding)                       |
| D3.3 | `ManifestRowKey` uses fixed-width big-endian encoding (no delimiters, no varints)          |
| D3.4 | Hint wire format is intentionally versionless (additive evolution via new tags only)       |
| D3.5 | Prefix split propagation demotes to `Range` (arbitrary sub-prefix boundaries not representable) |
| D3.6 | All buffer types are caller-owned (`KeyBuf`, `MetadataBuf`, `ShardSpecScratch`)           |
| D3.7 | `_ref` / `_into` dual API: borrowed for hot paths, arena-allocated for persistence        |
| D3.8 | `PreallocShardBuilder` uses const-generic `CAP` with compile-time bound (`<= 1024`)       |
| D3.9 | Builder uses two-phase workflow (stage then build) with transactional add semantics       |
| D3.10 | Builder drop clears arena to prevent slab leaks                                          |
| D3.11 | `byte_midpoint` uses integer arithmetic (add-then-halve) with overflow-normalized fallback |
| D3.12 | `key_successor` prefers append-zero over increment for tightest possible successor        |
| D3.13 | `prefix_successor` follows FoundationDB `strinc` / CockroachDB `Key.PrefixEnd` semantics |
| D3.14 | Empty metadata decodes to `ShardHint::Range` (backward-compatible default)                |
| D3.15 | `propagate_hint_on_split` validates child boundaries against parent hint before deriving   |
| D3.16 | `#![forbid(unsafe_code)]` -- entire crate is safe Rust                                    |

---

## 12. References

- Chang, F. et al. "Bigtable: A Distributed Storage System for Structured
  Data." OSDI 2006. (Half-open `[start, end)` byte-key ranges.)
- Corbett, J. et al. "Spanner: Google's Globally-Distributed Database."
  OSDI 2012. (Key encoding and range splitting.)
- Zhou, J. et al. "FoundationDB: A Distributed Unbundled Transactional Key
  Value Store." SIGMOD 2021. (`strinc` / prefix successor semantics.)
- CockroachDB. `Key.PrefixEnd` implementation. (Prefix successor
  algorithm.)
