# Boundary 4 -- Connectors

## 1. Overview

Boundary 4 (Connectors) defines the contract surface and reference
implementations for bridging external data sources into the shard-based
enumeration and read model. The contract lives in
`crates/gossip-contracts/src/connector/`; concrete implementations live in
`crates/gossip-connectors/`.

The crate provides four core capabilities:

- **Toxic-byte value types** -- validated wrappers (`ItemKey`, `ItemRef`,
  `TokenBytes`) that enforce non-empty bytes, hard size bounds, and
  redacted formatting. `Debug`/`Display` output is always
  `TypeName(len=N, hash=XXXXXXXX..)` via truncated BLAKE3, never raw
  bytes.

- **Connector method surface** -- each concrete connector exposes `caps`,
  `enumerate_page`, `choose_split_point`, `open`, and `read_range` as
  inherent methods with shared signatures. `ConnectorCapabilities`
  advertises optional features at registration time.

- **Page validation** -- a pure, allocation-free validator
  (`validate_page`, `validate_page_range`) that enforces 9 invariants on
  every connector page: spec sanity, cursor membership, item membership,
  ordering, cursor progression, monotonicity, continuation presence,
  empty-page stability, and cursor consistency.

- **Conformance harness** -- `check_connector_conforms` runs baseline
  enumeration, cross-run determinism comparison, token-perturbation
  resume checks, and secret-pattern scanning against `ItemRef` bytes.

### Source files (excluding `*_tests.rs`)

#### Contract layer (`crates/gossip-contracts/src/connector/`)

| File                | Role                                                                         |
| ------------------- | ---------------------------------------------------------------------------- |
| `mod.rs`            | Module root, re-exports all public types from four sub-modules               |
| `types.rs`          | Toxic-byte wrappers, `Cursor`, `ScanItem`, `EnumerationPage`, `Budgets`      |
| `api.rs`            | `ErrorClass`, `EnumerateError`, `ReadError`, `ConnectorCapabilities`, traits |
| `page_validator.rs` | `ToxicDigest`, `PageValidationError`, `validate_page`, `validate_page_range` |
| `conformance.rs`    | `ConformanceConfig`, `ConformanceError`, `check_connector_conforms`          |

#### Implementation layer (`crates/gossip-connectors/`)

| File             | Role                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `lib.rs`         | Crate root, exports `FilesystemConnector`, `InMemoryDeterministicConnector`, `GitConnector`, `MemItem`, `path_buf_from_bytes`, `FILESYSTEM_CONNECTOR_TAG`, `GIT_CONNECTOR_TAG`, `IN_MEMORY_CONNECTOR_TAG` |
| `common.rs`      | Shared utilities: binary search, identity derivation, split-point selection, pooled page assembly, I/O error classification, path conversion |
| `in_memory.rs`   | `InMemoryDeterministicConnector` -- deterministic in-memory fixture                                           |
| `filesystem.rs`  | `FilesystemConnector` -- Unix-only filesystem connector                                                       |
| `split_estimator.rs` | `StreamingSplitEstimator` -- bounded-memory byte-weighted split-point estimation                          |
| `git.rs`         | `GitConnector` -- Git repository connector with ref enumeration and blob reading                              |
| `scan_driver.rs` | `ScanSourceFactory` impls: `FilesystemScanSourceFactory`, `GitScanSourceFactory`, `InMemoryScanSourceFactory` |

---

## 2. Architectural Layering

```text
         ┌──────────────────────────────────────────────────┐
         │  gossip-scanner-runtime                          │  scan_fs(), scan_git()
         │  (top-level scan dispatchers)                    │  entry points
         └──────────────┬───────────────────────────────────┘
                        │ uses ScanSourceFactory + ScanDriver::run()
                        ▼
         ┌──────────────────────────────────────────────────┐
         │  gossip-scan-driver (traits + types)             │  ScanDriver, ScanSourceFactory,
         │                                                  │  Assignment, ScanExecutionConfig
         └──────────────┬───────────────────────────────────┘
                        │ implemented by
                        ▼
         ┌──────────────────────────────────────────────────┐
         │  gossip-connectors (Boundary 4 implementations)  │  FilesystemConnector,
         │  + scan_driver.rs (ScanSourceFactory impls)      │  InMemoryDeterministicConnector,
         │                                                  │  Fs/Git/InMemoryScanSourceFactory
         └──────────────┬───────────────────────────────────┘
                        │ depends on
                        ▼
         ┌──────────────────────────────────────────────────┐
         │  gossip-contracts::connector (Boundary 4 contracts) │  traits, types,
         │                                                  │  page_validator,
         │                                                  │  conformance
         └──────────────┬───────────────────────────────────┘
                        │ depends on
                        ▼
         ┌──────────────────────────────────────────────────┐
         │  gossip-contracts::identity (B1) +               │  ConnectorTag,
         │  gossip-contracts::coordination (B2 data model)  │  StableItemId,
         │                                                  │  ShardSpec, CursorUpdate
         └──────────────────────────────────────────────────┘
```

### Ownership boundaries

| Concern                        | Owner                            | Examples                                                                           |
| ------------------------------ | -------------------------------- | ---------------------------------------------------------------------------------- |
| Toxic-byte validation + paging | `gossip-contracts::connector`    | `ItemKey`, `ItemRef`, `TokenBytes`, `Cursor`, `Budgets`                            |
| Connector error types + caps   | `gossip-contracts::connector`    | `ConnectorCapabilities`, `ErrorClass`, `EnumerateError`, `ReadError`                |
| Page validation                | `gossip-contracts::connector`    | `validate_page`, `validate_page_range`, `PageValidationError`                      |
| Conformance testing            | `gossip-contracts::connector`    | `check_connector_conforms`, `ConformanceConfig`                                    |
| Reference connectors           | `gossip-connectors`              | `FilesystemConnector`, `GitConnector`, `InMemoryDeterministicConnector` |
| Shared connector utilities     | `gossip-connectors::common`      | `lower_bound`, `upper_bound`, `resolve_bounds`                                     |
| Streaming split estimation     | `gossip-connectors::split_estimator` | `StreamingSplitEstimator` (bounded-memory byte-weighted median)             |
| Scan driver traits             | `gossip-scan-driver`             | `ScanDriver::run()`, `ScanSourceFactory`, `Assignment`                             |
| Scan source factory impls      | `gossip-connectors::scan_driver` | `FilesystemScanSourceFactory`, `GitScanSourceFactory`, `InMemoryScanSourceFactory` |
| Scan runtime entry points      | `gossip-scanner-runtime`         | `scan_fs()`, `scan_git()`, execution-mode dispatch                                 |

### Dependency direction

`gossip-connectors` depends on `gossip-contracts` for trait definitions and
value types. It must NOT depend on `gossip-coordination`,
`gossip-persistence`, or `gossip-frontier`.

```text
  gossip-connectors ──► gossip-contracts
```

`gossip-scan-driver` defines the `ScanDriver` and `ScanSourceFactory` traits
that bridge assignments to source-specific execution backends.
`gossip-connectors::scan_driver` provides concrete factory implementations
(`FilesystemScanSourceFactory`, `GitScanSourceFactory`,
`InMemoryScanSourceFactory`). `gossip-scanner-runtime` provides the top-level
entry points (`scan_fs()`, `scan_git()`) that compose driver execution with
engine and event infrastructure.

---

## 3. Toxic-Byte Value Types

### Core wrappers

All three wrappers are generated by the `define_toxic_bytes!` macro
(`types.rs`), which produces validated constructors (`try_from_vec`,
`try_from_slice`), accessors (`as_bytes`, `len`, `into_bytes`), and
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

### ScanItem and EnumerationPage

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

`EnumerationPage` (`types.rs`) pairs `items: Vec<ScanItem>` with
`next_cursor: Cursor`. Fields are private; accessors are `items()`,
`next_cursor()`, `into_parts()`, and `into_next_cursor()`.

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

### Enumeration methods (inherent on each connector)

Each concrete connector (`FilesystemConnector`, `GitConnector`,
`InMemoryDeterministicConnector`) exposes the same set of inherent methods:

```rust
impl FilesystemConnector {  // same signatures on all three connectors
    pub fn caps(&self) -> ConnectorCapabilities;

    pub fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError>;

    pub fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError>;
}
```

Key design points:

- A single `enumerate_page` method serves both initial and resume
  requests, distinguished by cursor state (`Cursor::initial()` vs
  non-initial).
- `Budgets` values are advisory at the connector layer. Enforcement is the
  runtime's responsibility.
- `choose_split_point` takes all three parameters (`shard`, `cursor`,
  `budgets`) for interface consistency, even though some connectors ignore
  the budget.

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
subsequent reads dominates the heap allocation.

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

## 6. Page Validation

### validate_page_range (`page_validator.rs`)

Generic, allocation-free validator with 9 ordered checks:

1. **Spec range sanity** -- `start <= end` for bounded ranges.
2. **Input cursor in range** -- `[start, end]` (closed).
3. **Next cursor in range** -- `[start, end]` (closed).
4. **Item membership + ordering** -- single pass; items in `[start, end)`
   (half-open) and non-decreasing order.
5. **Empty-page cursor stability** -- empty pages must not advance cursor.
6. **Continuation cursor presence** -- non-empty pages require
   `next_cursor.last_key`.
7. **First item after input cursor** -- strictly greater than input
   cursor key.
8. **Cursor monotonicity** -- next cursor must not regress behind input.
9. **Next cursor consistency** -- next cursor `last_key >= last item key`.

Returns first failure as `PageValidationError`.

### validate_page (`page_validator.rs`)

Thin adapter: extracts `ShardSpec` range bounds and cursor keys, then
delegates to `validate_page_range::<[u8], ScanItem>`.

### Range convention trade-off

Item keys use half-open `[start, end)` matching shard semantics. Cursor
keys use closed `[start, end]`, deliberately more permissive at the
upper boundary to accommodate connectors that park continuation state
at the shard boundary.

### ToxicDigest (`page_validator.rs`)

Hash-only, `Copy`-able (40 bytes) representation of toxic bytes for
log-safe diagnostics. Stores `len: usize` + `hash: [u8; 32]` (full
BLAKE3). Display shows first 8 bytes as 16 hex characters -- longer
than `types.rs` wrappers (8 hex from 4 bytes) for better log-line
correlation in error contexts.

### PageValidationError (`page_validator.rs`)

Two-field design:

- `violation: PageValidationViolation` -- `Copy`-able discriminant (10
  variants, `#[non_exhaustive]`) for match-based dispatch and metrics.
- `details: PageValidationDetails` -- redacted diagnostic context with
  `ToxicDigest` values and positional indices.

Compile-time guard (`page_validator.rs`) asserts size <= 256 bytes.

---

## 7. Conformance Harness

### Entry point: `check_connector_conforms` (`conformance.rs`)

Four-phase cross-run verification:

1. **Baseline enumeration** -- full shard traversal collecting
   `ItemObservation`s (key digest + fingerprint digest from `ItemRef`)
   and cursor checkpoints into an `EnumerationTrace`.
2. **Determinism comparison** (optional) -- second full run, item-by-item
   digest equality check. Controlled by `DeterminismExpectation`
   (`Deterministic` or `BestEffort`).
3. **Resume checks** -- selects restart points from baseline trace,
   performs token-perturbation runs (`ResumeMode::DropToken`,
   `ResumeMode::CorruptToken`), verifies suffix of items matches baseline.
4. **Secret scanning** -- scans every `ItemRef` for forbidden byte
   patterns (AWS keys, GCP identifiers, PEM markers, GitHub tokens,
   JWT prefixes, etc.) via `DEFAULT_FORBIDDEN_ITEMREF_PATTERNS`.

### ConformanceConfig (`conformance.rs`)

Strict-by-default knobs:

| Field            | Default         | Purpose                            |
| ---------------- | --------------- | ---------------------------------- |
| `max_pages`      | `NonZeroUsize`  | Upper bound on pages per run       |
| `determinism`    | `Deterministic` | Cross-run consistency expectation  |
| `resume_checks`  | Both enabled    | Token drop + corrupt perturbation  |
| `restart_points` | `Auto(4)`       | Four evenly-spaced resume points   |
| `secret_scan`    | Enabled         | Scan `ItemRef` for secret patterns |

### ConformanceError (`conformance.rs`)

Flat enum (intentionally exhaustive) covering all failure modes: capability
gates, page validation failures, determinism mismatches (length and
element), resume suffix mismatches, cursor key inconsistencies, and
secret-scan findings. Error payloads use `ToxicDigest` exclusively.

---

## 8. Reference Connectors

### InMemoryDeterministicConnector (`in_memory.rs`)

Deterministic in-memory connector for tests and conformance harness.
Cheaply `Clone`-able via `Arc`. Takes `ConnectorTag` + `Vec<MemItem>`
at construction; pre-sorts items and precomputes `StableItemId` and
`PreparedItem` metadata.

Capabilities: `seek_by_key: true`, `token_resume: true` (default,
configurable via `with_tokens()`), `split_hints: true`,
`range_read: true`.

Enumeration uses binary search (`common::lower_bound` /
`common::upper_bound`) for seek and resume. Split hints reuse
`StreamingSplitEstimator` via `from_sorted_entries`, bulk-loading the
already-sorted in-memory range without a persistent estimator field.

### FilesystemConnector (`filesystem.rs`, Unix-only)

Real-IO connector for local filesystem directories. Streaming sorted
DFS walk (per-directory sorted frames, no full-tree materialization).
`openat`-based reads with `O_NOFOLLOW` for read confinement.
Symlinks are skipped during walk and rejected at open time.

Capabilities: `seek_by_key: true`, `token_resume: false` (default,
configurable via `with_tokens()`), `split_hints: true`,
`range_read: true`.

Split hints are provided by a `StreamingSplitEstimator` integrated into
the pagination walk. The estimator is fed `(key, file_size)` pairs as
each file is emitted during `enumerate_page`, and `choose_split_point`
reads the byte-weighted median estimate without a separate walk pass.
Memory is bounded by the configured sample cap. Walk issues (permission
denied, non-regular files) are captured as `WalkWarning`s rather than
fatal errors.

### GitConnector (`git.rs`)

Real-IO connector for Git repository tracked files. Lazy indexing
via `git ls-files -z` deferred until first `enumerate_page` or read
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

`common.rs` contains all shared connector infrastructure.
This keeps connector implementations thin and ensures binary search,
bound resolution, page assembly, and I/O error classification stay
consistent across `FilesystemConnector`, `GitConnector`, and
`InMemoryDeterministicConnector`.

#### Core search and split utilities

| Function                | Purpose                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| `derive_stable_item_id` | BLAKE3 domain-separated identity from `ConnectorTag` + `ItemKey` |
| `borrowed_shard_bound`  | Validate + borrow shard key-range bound (empty = unbounded)      |
| `lower_bound`           | Binary search: first index with key >= target                    |
| `upper_bound`           | Binary search: first index with key > target                     |
| `is_valid_split_candidate` | Post-selection guard: split advances past cursor, stays below end |

Filesystem, git, and in-memory connectors all use
`StreamingSplitEstimator` (`split_estimator.rs`) for byte-weighted split
selection. The filesystem connector feeds it incrementally during the
pagination walk; git and in-memory connectors bulk-load their
already-materialized sorted ranges via `from_sorted_entries`.
Count-balanced midpoint is the fallback when all entries are zero-size
or weight concentrates in the leading entry.

#### Bound resolution and cursor resume

| Function              | Purpose                                                               |
| --------------------- | --------------------------------------------------------------------- |
| `resolve_bounds`      | Map shard byte bounds to half-open index range via binary search       |
| `resolve_page_bounds` | `resolve_bounds` + budget deadline gate for page enumeration           |
| `key_resume_start`    | Key-authoritative cursor resume: first index past last emitted key     |
| `cursor_token_index`  | Decode optional cursor token as an absolute next-index                 |
| `is_valid_split_candidate` | Post-selection guard: split advances past cursor, stays below end |
| `build_next_cursor`   | Build continuation cursor with optional token encoding                 |
| `build_next_cursor_from_staged` | Build cursor preserving staged pooled token when available  |

#### Pooled page assembly

| Function / Type                       | Purpose                                                          |
| ------------------------------------- | ---------------------------------------------------------------- |
| `StagedPage`                          | Materialized `(ItemKey, ItemRef)` pairs + optional token         |
| `assemble_pooled_page`                | Generic two-slot path: separate key/ref slab slots per item      |
| `assemble_pooled_page_shared_key_ref` | Shared-slot path: key==ref connectors (filesystem, git)          |
| `page_slab_capacity`                  | Pre-size slab using `ByteSlab` size classes (avoids partial staging) |

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

## 8a. Scan Source Factories (`scan_driver.rs`)

`scan_driver.rs` provides concrete `ScanSourceFactory`
implementations that bridge coordination-layer assignments to
source-specific scan execution backends. Each factory validates the
assignment's `ConnectorKind`, extracts the source payload, and returns a
boxed `ScanDriver` that runs the actual scan.

### Factory types

| Factory                        | `ConnectorKind` | Driver                | Backend                       |
| ------------------------------ | --------------- | --------------------- | ----------------------------- |
| `FilesystemScanSourceFactory`  | `Filesystem`    | `FsScanDriver`        | `parallel_scan_dir`           |
| `GitScanSourceFactory`         | `Git`           | `GitScanDriver`       | `run_git_scan`                |
| `InMemoryScanSourceFactory`    | `InMemory`      | `InMemoryScanDriver`  | Sequential item iteration     |

All three factory types are re-exported from the crate root.

### `FilesystemScanSourceFactory`

Zero-sized, `Copy`-able factory. Creates `FsScanDriver` which wraps
`parallel_scan_dir` from `scanner-scheduler`. Event and commit forwarding
use scoped threads with crossbeam channels to bridge the scheduler's
`EventOutput` / `StoreProducer` interfaces to the coordination layer's
`CommitSink`. Does not support cooperative cancellation (only pre-check).
Supports checkpoint hints.

### `GitScanSourceFactory`

Zero-sized, `Copy`-able factory. Creates `GitScanDriver` which wraps
`run_git_scan` from `scanner-git`. Resolves refs via `CliRefResolver`
(shells out to `git for-each-ref`), treats all refs as unseen
(`EmptyWatermarkStore`), performing a full scan on each run. The
`CommitSink` is intentionally unused -- git scans use a commit-graph
persistence model rather than the per-item begin/finish lifecycle. Does
not support checkpoint hints or cooperative cancellation.

### `InMemoryScanSourceFactory`

Cloneable factory backed by `Arc<[MemItem]>`. Items are sorted at
construction time for deterministic scan order. Creates
`InMemoryScanDriver` which iterates items sequentially, driving the
commit-sink lifecycle (`begin_item` / `finish_item`) and emitting
checkpoint hints at configured intervals. Does not invoke the scanner
engine. Supports both checkpoint hints and cooperative cancellation.

### Channel-based event and commit forwarding

The scan drivers use crossbeam channels to forward events and findings
across thread boundaries:

- `ChannelEventOutput` -- serializes `CoreEvent`s as owned values
  (`OwnedCoreEvent`) for cross-thread forwarding to `EventOutput`.
- `ChannelGitEventOutput` -- extends `ChannelEventOutput` with
  `GitEvent` forwarding for git-aware sinks.
- `ChannelStoreProducer` -- normalizes scheduler paths (absolute OS
  paths from `FsFindingBatch`) to connector-relative `/`-separated key
  encoding via `normalize_scheduler_path`, then forwards batches through
  the commit channel.
- `forward_commits` drains the commit channel, mapping
  `OwnedFsFindingBatch` to `CommitSink` lifecycle calls
  (`begin_item` → `upsert_findings` → `finish_item`). On error, the
  first failure is captured but draining continues to prevent deadlock.

---

## 9. Scan Execution Path

Scan execution flows through three crates that compose connectors with
the scanner engine and coordination layer:

- **`gossip-scan-driver`** (`crates/gossip-scan-driver/src/lib.rs`) --
  defines `ScanDriver::run()` and `ScanSourceFactory` traits.
- **`gossip-connectors::scan_driver`** (`crates/gossip-connectors/src/scan_driver.rs`) --
  provides `FilesystemScanSourceFactory`, `GitScanSourceFactory`, and
  `InMemoryScanSourceFactory` (see Section 8a).
- **`gossip-scanner-runtime`** (`crates/gossip-scanner-runtime/src/lib.rs`) --
  provides `scan_fs()` and `scan_git()` top-level entry points that
  compose driver execution with engine and event infrastructure.

---

## 10. Cross-Boundary Dependencies

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

## 11. Design Principles

### Toxic-byte policy

All connector-originated bytes (`ItemKey`, `ItemRef`, `TokenBytes`) are
never shown as raw bytes in logs. Constructors validate, and formatters
redact. Raw access requires explicit `.as_bytes()` or `.into_bytes()`.

### Enumeration/read method split rationale

Enumeration and reading are separate method groups because they have
independent scaling characteristics: enumeration is metadata-bound,
reading is bandwidth-bound. Orchestration applies independent retry and
circuit-breaker policies per operation.

### Two-layer cursor with key-only resume

Cursors carry both `last_key` and optional `token`, but `last_key` is
the only durable resumption primitive. If a token is lost, stale, or
corrupt, the connector must be able to resume from `last_key` alone.
The conformance harness verifies this via token-perturbation resume
checks.

### Budgets are advisory

`Budgets` values are advisory at the connector trait layer. Connectors
should honor them but callers must not assume compliance. The runtime
orchestration layer is responsible for enforcement.
