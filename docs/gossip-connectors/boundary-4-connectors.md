# Boundary 4 -- Connectors

## 1. Overview

Boundary 4 (Connectors) defines the contract surface and reference
implementations for bridging external data sources into the shard-based
enumeration and read model. The contract lives in
`crates/gossip-contracts/src/connector/`; concrete implementations live in
`crates/gossip-connectors/`.

The crate provides four core capabilities:

- **Shared paging vocabulary** -- reusable page-shape contracts
  (`PageBuf`, `PageState`, `PagingCapabilities`, `KeyedPageItem`) and
  validation helpers (`validate_filled_page`) for ordered enumeration
  families.

- **Toxic-byte value types** -- validated wrappers (`ItemKey`, `ItemRef`,
  `TokenBytes`) that enforce non-empty bytes, hard size bounds, and
  redacted formatting. `Debug`/`Display` output is always
  `TypeName(len=N, hash=XXXXXXXX..)` via truncated BLAKE3, never raw
  bytes.

- **Family contract modules** -- `ordered.rs` defines the
  `OrderedContentSource` trait and its family-specific capability flags.
  `fill_page` returns `Result<Option<PageBuf<ScanItem>>, EnumerateError>`:
  `Ok(Some(page))` delivers a non-empty page, `Ok(None)` signals terminal
  completion when no in-scope items remain (`PageBuf` enforces non-empty,
  so the `Option` wrapper carries the empty-terminal signal).
  `conformance.rs` provides a reusable ordered-content harness for
  sequence-level checks such as monotonic drain progression,
  determinism across fresh sources, corrupt-token fallback, and
  forbidden-fragment validation on emitted `ItemRef` values.
  `git.rs` defines the Git family's three-trait pipeline:
  `GitRepoDiscoverySource` (frontier discovery), `GitMirrorManager`
  (local mirror acquisition), and `GitRepoExecutor` (whole-repo
  execution). These operate on repositories rather than individual items.

- **Connector method surface** -- `FilesystemConnector` directly
  implements `OrderedContentSource` while preserving matching inherent
  helper methods (`fill_page`, `choose_split_point`, `open`,
  `read_range`). `ConnectorCapabilities` advertises optional
  features at registration time, and the other reference connectors keep
  the same inherent `caps` / `choose_split_point` / `open` /
  `read_range` signatures.

### Source files (excluding `*_tests.rs`)

#### Contract layer (`crates/gossip-contracts/src/connector/`)

| File                | Role                                                                         |
| ------------------- | ---------------------------------------------------------------------------- |
| `mod.rs`            | Module root, re-exports all public types from sub-modules                    |
| `common.rs`         | Shared paging vocabulary: `PageBuf`, `PageState`, `PagingCapabilities`, `KeyedPageItem`, page validation |
| `conformance.rs`    | Reusable ordered-content conformance harness: drain snapshots, structured errors, and helper probes |
| `types.rs`          | Toxic-byte wrappers, `Cursor`, `ScanItem`, `Budgets`, `ToxicDigest`         |
| `api.rs`            | `ErrorClass`, `EnumerateError`, `ReadError`, `ConnectorCapabilities`         |
| `ordered.rs`        | Ordered-content family contract: `OrderedContentSource` trait (`fill_page` → `Ok(None)` terminal), `OrderedContentCapabilities` flags |
| `git.rs`            | Git family contract: `GitRepoDiscoverySource`, `GitMirrorManager`, `GitRepoExecutor` traits; `RepoKey`, `RepoLocator`, `GitSelection`, `LocalMirror`, `GitExecutionLimits`, `GitRunOutcome`, `GitRunError` types |

#### Implementation layer (`crates/gossip-connectors/`)

| File             | Role                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `lib.rs`         | Crate root, exports `FilesystemConnector`, `InMemoryDeterministicConnector`, `GitConnector`, `MemItem`, `path_buf_from_bytes`, `FILESYSTEM_CONNECTOR_TAG`, `GIT_CONNECTOR_TAG`, `IN_MEMORY_CONNECTOR_TAG` |
| `common.rs`      | Shared utilities: shard-bound validation, binary search, deadline checks, I/O error classification, path conversion |
| `in_memory.rs`   | `InMemoryDeterministicConnector` -- deterministic in-memory fixture                                           |
| `filesystem.rs`  | `FilesystemConnector` -- Unix-only filesystem connector                                                       |
| `split_estimator.rs` | `StreamingSplitEstimator` -- bounded-memory byte-weighted split-point estimation                          |
| `git.rs`         | `GitConnector` -- Git repository connector with ref enumeration and blob reading                              |

---

## 2. Architectural Layering

```text
gossip-scanner-runtime / scanner-rs-cli / gossip-worker
    source-family orchestration and entry points
                        │
                        ▼
gossip-connectors
    concrete family implementations
    - FilesystemConnector
    - InMemoryDeterministicConnector
    - GitConnector
                        │
                        ▼
gossip-contracts::connector
    family contracts + paging/value types
    - OrderedContentSource
    - GitRepoDiscoverySource
    - GitMirrorManager
    - GitRepoExecutor
    - PageBuf / Cursor / ScanItem / ItemKey
                        │
                        ▼
gossip-contracts::identity + gossip-contracts::coordination
    ConnectorTag / StableItemId / ShardSpec
```

### Ownership boundaries

| Concern                        | Owner                            | Examples                                                                           |
| ------------------------------ | -------------------------------- | ---------------------------------------------------------------------------------- |
| Toxic-byte validation + paging | `gossip-contracts::connector`    | `ItemKey`, `ItemRef`, `TokenBytes`, `Cursor`, `Budgets`                            |
| Connector error types + caps   | `gossip-contracts::connector`    | `ConnectorCapabilities`, `ErrorClass`, `EnumerateError`, `ReadError`                |
| Reference connectors           | `gossip-connectors`              | `FilesystemConnector`, `GitConnector`, `InMemoryDeterministicConnector` |
| Shared connector utilities     | `gossip-connectors::common`      | `lower_bound`, `upper_bound`, `resolve_bounds`                                     |
| Streaming split estimation     | `gossip-connectors::split_estimator` | `StreamingSplitEstimator` (bounded-memory byte-weighted median)             |
| Family runtime entry points    | `gossip-scanner-runtime`         | `scan_fs()`, `scan_git()`, execution-mode dispatch over source families             |

### Dependency direction

`gossip-connectors` depends on `gossip-contracts` for trait definitions and
value types. It must NOT depend on `gossip-coordination`,
`gossip-persistence`, or `gossip-frontier`.

```text
  gossip-connectors ──► gossip-contracts
```

The legacy universal driver layer has been removed from the workspace.
Higher-level runtime crates now integrate directly with the source-family
contracts in `gossip-contracts::connector` and the concrete family
implementations in `gossip-connectors`.

---

## 3. Toxic-Byte Value Types

### Core wrappers

All three wrappers are generated by the `define_toxic_bytes!` macro
(`types.rs`), which produces validated constructors (`try_from_vec`,
`try_from_slice`), accessors (`as_bytes`, `len`, `AsRef<[u8]>`), and
redacted `Debug`/`Display` (identical output: `TypeName(len=N, hash=XXXXXXXX..)`
using first 4 bytes of BLAKE3).

| Type         | Ordered? | Limit                              | Purpose                                                  |
| ------------ | -------- | ---------------------------------- | -------------------------------------------------------- |
| `ItemKey`    | Yes      | `MAX_ITEM_KEY_SIZE` (4,096 bytes)  | Enumeration position for sharding and cursor progression |
| `ItemRef`    | No       | `MAX_ITEM_REF_SIZE` (16,384 bytes) | Opaque connector handle for read/open                    |
| `TokenBytes` | No       | `MAX_TOKEN_SIZE` (16,384 bytes)    | Pagination/resume token round-tripped by coordinator     |

`ItemKey` derives `Ord` for lexicographic comparison. `ItemRef` and
`TokenBytes` do not -- they are looked up, not ranged.

Size constants are hardcoded values. `MAX_ITEM_KEY_SIZE` and
`MAX_TOKEN_SIZE` are kept in lock-step with coordination cursor limits
(`coordination::cursor::MAX_KEY_SIZE` and `CursorMaxTokenSize`).
Alignment is verified by the `constants_align_with_coordination_limits`
test in `types_tests.rs`.

### Cursor

`Cursor` (`types.rs`) owns paging state as
`(Option<ItemKey>, Option<TokenBytes>)` with the invariant that `token`
is only meaningful when paired with `last_key` -- the `(None, Some(_))`
state is structurally prevented by all constructors.

Three named constructors:

- `Cursor::initial()` -- no progress key, no token.
- `Cursor::with_last_key(key)` -- progress key only.
- `Cursor::with_token(key, token)` -- progress key + resume token.

`as_update()` projects the owned cursor into coordination's borrowed
`CursorUpdate` without allocation. `try_from_update()` copies from a
borrowed coordination cursor, normalizing empty tokens to `None`.

### ScanItem

`ScanItem` (`types.rs`) bundles required identity fields
(`item_key`, `item_ref`, `stable_item_id`, `version`) with optional
metadata (`size_hint`, `content_hints`, `location`). All fields are
private with accessor methods. Builder-style `with_*` methods set
optional fields.

`VersionId` is a `VersionId` enum (`gossip-contracts/src/connector/types.rs`)
with two variants:

- `Strong(ObjectVersionId)` -- reliable immutability signal (e.g., content-hash).
- `Weak(ObjectVersionId)` -- best-effort version (e.g., mtime-derived).

`object_version_id()` extracts the inner `ObjectVersionId` regardless of
strength. `is_strong()` lets callers gate trust-sensitive decisions.

`ContentHints` (`gossip-contracts/src/connector/types.rs`) carries
advisory `media_type` and `encoding` strings, both optional and size-bounded.
Empty strings are normalized to `None`.

`Location` (`gossip-contracts/src/connector/types.rs`) pairs a required
`display` string with an optional `url`, both size-bounded. Provides
human-readable provenance safe for logs and UI.

### PooledByteSlab

`PooledByteSlab` (`gossip-contracts/src/connector/types.rs`) wraps a
`ByteSlab` for staged byte allocation during connector page assembly.
Two-phase usage: connectors call `allocate()` repeatedly in a mutable phase,
then wrap the slab in `Arc` for shared read access via `get()`.

On `Drop`, it calls `zeroize_used()` and `clear()` to scrub secret material,
including mid-loop staging failures that return early.

### Budgets

`Budgets` (`types.rs`) carries three stop conditions:

- `max_items: NonZeroUsize`
- `max_bytes: NonZeroU64`
- `deadline: Option<Instant>`

Constructed via `Budgets::try_new()`, which returns
`Err(ConnectorInputError::ZeroBudget)` for zero values.
`is_expired_at(now: Instant)` accepts an explicit instant for
simulation determinism.

---

## 4. Connector Method Surface

### Capability and split methods (inherent on each connector)

Each concrete connector (`FilesystemConnector`, `GitConnector`,
`InMemoryDeterministicConnector`) exposes the same set of inherent methods:

```rust
impl FilesystemConnector {  // same signatures on all three connectors
    pub fn caps(&self) -> ConnectorCapabilities;

    pub fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError>;
}
```

Key design points:

- `choose_split_point` takes all three parameters (`shard`, `cursor`,
  `budgets`) for interface consistency, even though some connectors ignore
  the budget.
- `FilesystemConnector` rejects expired split deadlines directly; the other
  reference connectors may still treat split budgets as advisory when the
  operation is metadata-only.

### Read methods (inherent on each connector)

```rust
impl FilesystemConnector {  // same signatures on all three connectors
    pub fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError>;

    pub fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError>;
}
```

The boxed `dyn Read + Send` return from `open` is intentional: it sits
on the WARM read path (once per item, not per byte), and the IO cost of
subsequent reads dominates the heap allocation. `FilesystemConnector`
wraps the returned reader in a byte-budget guard, while higher runtime
layers can still compose their own outer limits.

### ConnectorCapabilities (`api.rs`)

Feature-flag struct with four `bool` fields:

| Field          | Meaning                                       |
| -------------- | --------------------------------------------- |
| `seek_by_key`  | Can resume from an arbitrary key position     |
| `token_resume` | Supports opaque token-based pagination        |
| `range_read`   | Can serve byte-range reads                    |
| `split_hints`  | Emits split hints alongside enumeration pages |

`Default` is all-false (conservative "no features" profile).

---

## 5. Error Taxonomy

### ErrorClass (`api.rs`)

Binary retry posture:

- `Retryable` -- transient; same request may succeed on retry (HTTP
  429/503, timeouts).
- `Permanent` -- will not succeed until something external changes
  (HTTP 401/403/404, malformed identifiers).

### EnumerateError and ReadError (`api.rs`)

Both generated by `define_connector_error!` with identical structure:

| Field            | Type          | Purpose                              |
| ---------------- | ------------- | ------------------------------------ |
| `class`          | `ErrorClass`  | Binary retry posture                 |
| `message`        | `String`      | Connector-originated diagnostic text |
| `retry_after_ms` | `Option<u64>` | Advisory backoff hint                |

Named constructors: `retryable(msg)`, `rate_limited(msg, ms)`,
`permanent(msg)`. `Display` sanitizes control characters via
`fmt_sanitized_message` to prevent log injection.

`ReadError` adds `unsupported(feature)` for capability mismatches.

### ConnectorInputError (`types.rs`)

Validation errors from boundary-crossing constructors:

- `Empty { field }` -- required field was zero-length.
- `TooLarge { field, size, max }` -- field exceeded hard limit.
- `TokenWithoutLastKey` -- cursor had token but no `last_key`.
- `ZeroBudget { field }` -- budget field was zero.

---

## 6. Reference Connectors

### InMemoryDeterministicConnector (`in_memory.rs`)

Deterministic in-memory connector for tests and simulation workloads.
Cheaply `Clone`-able via `Arc`. Takes `Vec<MemItem>` at construction,
pre-sorts items, and precomputes lightweight `PreparedItem` metadata
(`key`, `bytes`, `size_hint`).

Capabilities: `seek_by_key: true`, `token_resume: true` (default,
configurable via `with_tokens()`), `split_hints: true`,
`range_read: true`.

Enumeration uses binary search (`common::lower_bound` /
`common::upper_bound`) for seek and resume. Split hints reuse
`StreamingSplitEstimator` via `from_sorted_entries`, bulk-loading the
already-sorted in-memory range without a persistent estimator field.

### FilesystemConnector (`filesystem.rs`, Unix-only)

Real-IO ordered-content connector for local filesystem directories or a
single canonical file. Enumeration uses a bounded stack of per-directory
sorted entry buffers and walks the live filesystem view in lexicographic
relative-path order without building a whole-tree snapshot. `openat`-based
reads with `O_NOFOLLOW` keep directory roots confined, and single-file
roots open the canonical file path directly with the same regular-file
validation.

Capabilities: `seek_by_key: true`, `token_resume: false`,
`split_hints: false`, `range_read: true`.

`FilesystemConnector` directly implements `OrderedContentSource` and
emits `PageBuf<ScanItem>` pages with relative-path `ItemKey` /
`ItemRef` values, root-scoped filesystem `StableItemId` derivation, weak
metadata-based `VersionId` values, and metadata-backed `size_hint`s.
Page fill applies connector-side `max_items`, `max_bytes`, and deadline
budgets. Resume is key-authoritative: enumeration rescans the live root
view and skips entries at or below `Cursor::last_key()`. Incoming cursor
tokens are ignored because the connector does not advertise
`token_resume`. The first in-scope item is still emitted even when its
`size_hint` alone exceeds `max_bytes`, which preserves forward progress
for oversized files. Full reads reject expired deadlines and return a
bounded reader, while `read_range` clamps bytes to `max_bytes`.

The `StreamingSplitEstimator` field has no internal observation
feed from page enumeration, so `split_hints` remains `false`. The
connector exposes `choose_split_point`, but it returns `Ok(None)`
until an external caller populates the estimator with observations.

### GitConnector (`git.rs`)

Real-IO connector for Git repository tracked files. Lazy indexing
via `git ls-files -z` deferred until first connector call or read
call. Item keys and item refs are both the raw repository-relative path
bytes.

Capabilities: `seek_by_key: true`, `token_resume: true` (default,
configurable via `with_tokens()`), `split_hints: true`,
`range_read: true`.

Version model is weak: BLAKE3 digest over `(path, file_size,
mtime_nanos)` — sufficient for change-detection but not content
identity. Security hardening includes path-component filtering (rejects
`..`), canonicalize + containment checks, and symlink rejection via
`symlink_metadata`. Read-time opens re-canonicalize and check the repo
boundary to prevent read-time escapes.

Split hints reuse `StreamingSplitEstimator` via `from_sorted_entries`,
bulk-loading the already-indexed sorted range on demand. Token fast-path
provides O(1) resume when the positional token agrees with the
key-derived position; falls back to O(log N) key-based resume on
mismatch.

### Connector tags and public constants

Each connector type carries a domain-separating `ConnectorTag` constant
that ensures `StableItemId` derivations are disjoint across connector
types:

| Constant                   | Value       | Used by                            |
| -------------------------- | ----------- | ---------------------------------- |
| `FILESYSTEM_CONNECTOR_TAG` | `"fslocal"` | `FilesystemConnector`              |
| `GIT_CONNECTOR_TAG`        | `"gitlocal"`| `GitConnector`                     |
| `IN_MEMORY_CONNECTOR_TAG`  | `"inmem"`   | `InMemoryDeterministicConnector`   |

All three constants are defined via `ConnectorTag::from_ascii` and re-exported
from the crate root.

### Public utility: `path_buf_from_bytes`

`path_buf_from_bytes(bytes: &[u8]) -> PathBuf` (`common.rs`)
converts raw path bytes to a `PathBuf`. On Unix, the conversion is
lossless via `OsString::from_vec`. On non-Unix platforms, invalid UTF-8
sequences are replaced with U+FFFD (lossy but non-panicking). This
function is re-exported from the crate root and used by `GitConnector`
to convert `git ls-files` output to filesystem paths.

### Shared utilities (`common.rs`)

`common.rs` contains shared connector infrastructure for shard-bound
validation, binary search, split-candidate validation, deadline checks,
I/O error classification, and path conversion. This keeps connector
implementations thin and ensures bound resolution and retry posture stay
consistent across the reference connectors.

#### Core search and split utilities

| Function                   | Purpose                                                          |
| -------------------------- | ---------------------------------------------------------------- |
| `borrowed_shard_bound`     | Validate + borrow shard key-range bound (empty = unbounded)      |
| `lower_bound`              | Binary search: first index with key >= target                    |
| `upper_bound`              | Binary search: first index with key > target                     |
| `is_valid_split_candidate` | Post-selection guard: split advances past cursor, stays below end |
| `deadline_expired`         | Shared monotonic deadline check for connector-local budget gates |

Filesystem, git, and in-memory connectors all use
`StreamingSplitEstimator` (`split_estimator.rs`) for byte-weighted split
selection. Git and in-memory connectors bulk-load their already-sorted
ranges via `from_sorted_entries`. `FilesystemConnector` keeps the same
estimator field for future split-hint plumbing, but it does not feed the
estimator internally yet, so split hints remain disabled.

#### Bound resolution and cursor resume

| Function           | Purpose                                                           |
| ------------------ | ----------------------------------------------------------------- |
| `resolve_bounds`   | Map shard byte bounds to half-open index range via binary search  |
| `key_resume_start` | Key-authoritative cursor resume: first index past last emitted key |

#### I/O error classification

| Function                       | Purpose                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| `is_permanent_io_error`        | Classify I/O errors as permanent vs retryable                |
| `classify_io_enumerate_error`  | Map I/O error to `EnumerateError` with path redaction        |
| `classify_io_read_error`       | Map I/O error to `ReadError` with path redaction             |
| `enumerate_error_to_read`      | Bridge `EnumerateError` → `ReadError`, preserving retryability |

#### Trait abstractions

| Trait          | Purpose                                            |
| -------------- | -------------------------------------------------- |
| `KeyedEntry`   | Key byte slice access for generic binary search    |

---

## 6a. Source-Family Integration

Boundary 4 no longer routes through a universal driver abstraction.
Integration now happens through the family contracts themselves:

- ordered content sources implement `OrderedContentSource`
- Git repository discovery implements `GitRepoDiscoverySource`
- local mirror preparation implements `GitMirrorManager`
- repo-native execution implements `GitRepoExecutor`

The practical migration guide for new source work lives in
`docs/source-families.md`.

---

## 7. Runtime Integration

Runtime entry points live in `gossip-scanner-runtime`. They expose both
`Direct` and `Connector` execution modes, but both modes currently cross
the same family-oriented runtime boundary rather than a separate universal
driver layer.

- Ordered-content paths compose connector enumeration/read behavior with
  scheduler and engine infrastructure.
- Git paths compose repository discovery, mirror preparation, and
  repo-native execution with `scanner-git`.
- The connector boundary remains responsible for source semantics,
  identity derivation, cursor handling, and split-point selection.

---

## 8. Cross-Boundary Dependencies

### What B4 imports

| Boundary                     | Types imported                                                       |
| ---------------------------- | -------------------------------------------------------------------- |
| B1 (Identity)                | `ConnectorTag`, `ItemIdentityKey`, `ObjectVersionId`, `StableItemId` |
| B2 (Coordination data model) | `ShardSpec`, `CursorUpdate`                                          |

### What B4 does NOT depend on

- `gossip-coordination` (B2 protocol) -- no runtime coordination logic.
- `gossip-frontier` (B3) -- no key encoding or shard builder logic.
- `gossip-persistence` (B5) -- no storage layer.

### Compilation tier

B4 (`gossip-connectors`) sits in **Tier 1** of the build DAG, compiling
in parallel with B2 (`gossip-coordination`) after Tier 0 (`gossip-stdx`,
`gossip-contracts`, `gossip-frontier`).

---

## 9. Design Principles

### Toxic-byte policy

All connector-originated bytes (`ItemKey`, `ItemRef`, `TokenBytes`) are
never shown as raw bytes in logs. Constructors validate, and formatters
redact. Raw access requires explicit `.as_bytes()` or `AsRef<[u8]>`.

### Read method isolation

Reading is a separate method group because it has
independent scaling characteristics from split-point selection:
reading is bandwidth-bound. Orchestration applies independent retry and
circuit-breaker policies per operation.

### Two-layer cursor with key-only resume

Cursors carry both `last_key` and optional `token`, but `last_key` is
the only durable resumption primitive. If a token is lost, stale, or
corrupt, the connector must be able to resume from `last_key` alone.
Token-perturbation tests verify this property.

### Budget ownership

`Budgets` give the runtime the authoritative outer policy, but
connectors can enforce local safety limits directly. `FilesystemConnector`
rejects expired deadlines, bounds page assembly with `max_items` and
`max_bytes`, and clamps full or ranged reads. Other connectors may
treat some budget fields as advisory when their operations are
metadata-only or already bounded by an in-memory snapshot.
