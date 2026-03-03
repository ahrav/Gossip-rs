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

- **Connector trait contracts** -- `EnumerationConnector` for page-oriented
  listing and `ReadConnector` for item-level reads, with a
  `ConnectorInstance` convenience supertrait. Traits include conservative
  defaults (`choose_split_point` returns `Ok(None)`;
  `read_range` returns `Err(ReadError::unsupported("range_read"))`).

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
| `lib.rs`         | Crate root, exports `FilesystemConnector`, `InMemoryDeterministicConnector`, `GitConnector`, `MemItem`        |
| `common.rs`      | Shared utilities: binary search, identity derivation, split-point selection                                   |
| `in_memory.rs`   | `InMemoryDeterministicConnector` -- deterministic in-memory fixture                                           |
| `filesystem.rs`  | `FilesystemConnector` -- Unix-only filesystem connector                                                       |
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
| Connector traits + error types | `gossip-contracts::connector`    | `EnumerationConnector`, `ReadConnector`, `ErrorClass`                              |
| Page validation                | `gossip-contracts::connector`    | `validate_page`, `validate_page_range`, `PageValidationError`                      |
| Conformance testing            | `gossip-contracts::connector`    | `check_connector_conforms`, `ConformanceConfig`                                    |
| Reference connectors           | `gossip-connectors`              | `FilesystemConnector`, `InMemoryDeterministicConnector`                            |
| Shared connector utilities     | `gossip-connectors::common`      | `lower_bound`, `upper_bound`, `choose_split_index`                                 |
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
(`types.rs:208-303`), which produces validated constructors (`try_from_vec`,
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

`Cursor` (`types.rs:384-496`) owns paging state as
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

`ScanItem` (`types.rs:694-837`) bundles required identity fields
(`item_key`, `item_ref`, `stable_item_id`, `version`) with optional
metadata (`size_hint`, `content_hints`, `location`). All fields are
private with accessor methods. Builder-style `with_*` methods set
optional fields.

`EnumerationPage` (`types.rs:852-897`) pairs `items: Vec<ScanItem>` with
`next_cursor: Cursor`. Fields are private; accessors are `items()`,
`next_cursor()`, `into_parts()`, and `into_next_cursor()`.

### Budgets

`Budgets` (`types.rs:910-973`) carries three stop conditions:

- `max_items: NonZeroUsize`
- `max_bytes: NonZeroU64`
- `deadline: Option<Instant>`

Constructed via `Budgets::try_new()`, which returns
`Err(ConnectorInputError::ZeroBudget)` for zero values.
`is_expired_at(now: Instant)` accepts an explicit instant for
simulation determinism.

---

## 4. Connector Traits

### EnumerationConnector (`api.rs:351-407`)

```rust
pub trait EnumerationConnector: Send {
    fn caps(&self) -> ConnectorCapabilities;

    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError>;

    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        // Default: no hint. debug_assert fires if caps().split_hints is true.
        Ok(None)
    }
}
```

Key design points:

- A single `enumerate_page` method serves both initial and resume
  requests, distinguished by cursor state (`Cursor::initial()` vs
  non-initial).
- `Budgets` values are advisory at the trait layer. Enforcement is the
  runtime's responsibility.
- `choose_split_point` takes all three parameters (`shard`, `cursor`,
  `budgets`) for interface consistency, even though the default ignores
  them.

### ReadConnector (`api.rs:414-486`)

```rust
pub trait ReadConnector: Send {
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError>;

    fn read_range(
        &mut self,
        _item_ref: &ItemRef,
        _offset: u64,
        _dst: &mut [u8],
        _budgets: Budgets,
    ) -> Result<usize, ReadError> {
        Err(ReadError::unsupported("range_read"))
    }
}
```

The boxed `dyn Read + Send` return from `open` is intentional: it sits
on the WARM read path (once per item, not per byte), and the IO cost of
subsequent reads dominates the heap allocation.

### ConnectorInstance (`api.rs:503-505`)

Pure bound alias: `EnumerationConnector + ReadConnector`. Blanket-
implemented for all `T: EnumerationConnector + ReadConnector + ?Sized`.
No additional methods -- it is not an extension point.

### ConnectorCapabilities (`api.rs:314-342`)

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

### ErrorClass (`api.rs:69-88`)

Binary retry posture:

- `Retryable` -- transient; same request may succeed on retry (HTTP
  429/503, timeouts).
- `Permanent` -- will not succeed until something external changes
  (HTTP 401/403/404, malformed identifiers).

### EnumerateError and ReadError (`api.rs:253-301`)

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

### ConnectorInputError (`types.rs:102-133`)

Validation errors from boundary-crossing constructors:

- `Empty { field }` -- required field was zero-length.
- `TooLarge { field, size, max }` -- field exceeded hard limit.
- `TokenWithoutLastKey` -- cursor had token but no `last_key`.
- `ZeroBudget { field }` -- budget field was zero.

---

## 6. Page Validation

### validate_page_range (`page_validator.rs:548-715`)

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

### validate_page (`page_validator.rs:735-752`)

Thin adapter: extracts `ShardSpec` range bounds and cursor keys, then
delegates to `validate_page_range::<[u8], ScanItem>`.

### Range convention trade-off

Item keys use half-open `[start, end)` matching shard semantics. Cursor
keys use closed `[start, end]`, deliberately more permissive at the
upper boundary to accommodate connectors that park continuation state
at the shard boundary.

### ToxicDigest (`page_validator.rs:142-196`)

Hash-only, `Copy`-able (40 bytes) representation of toxic bytes for
log-safe diagnostics. Stores `len: usize` + `hash: [u8; 32]` (full
BLAKE3). Display shows first 8 bytes as 16 hex characters -- longer
than `types.rs` wrappers (8 hex from 4 bytes) for better log-line
correlation in error contexts.

### PageValidationError (`page_validator.rs:373-490`)

Two-field design:

- `violation: PageValidationViolation` -- `Copy`-able discriminant (10
  variants, `#[non_exhaustive]`) for match-based dispatch and metrics.
- `details: PageValidationDetails` -- redacted diagnostic context with
  `ToxicDigest` values and positional indices.

Compile-time guard (`page_validator.rs:758`) asserts size <= 256 bytes.

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
`common::upper_bound`) for seek and resume, and byte-weighted median
split selection via `common::choose_split_index`.

### FilesystemConnector (`filesystem.rs`, Unix-only)

Real-IO connector for local filesystem directories. Lazy indexing
(directory walk deferred until first `enumerate_page` call).
`openat`-based reads with `O_NOFOLLOW` for read confinement.
Symlinks are skipped during walk and rejected at open time.

Capabilities: `seek_by_key: true`, `token_resume: false` (default,
configurable via `with_tokens()`), `split_hints: true`,
`range_read: true`.

Split selection uses prefix-sum arrays for O(log n) byte-weighted median
selection (`byte_weighted_split_idx`). Walk issues (permission denied,
non-regular files) are captured as `WalkWarning`s rather than fatal
errors.

### Shared utilities (`common.rs`)

| Function                | Purpose                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| `derive_stable_item_id` | BLAKE3 domain-separated identity from `ConnectorTag` + `ItemKey` |
| `shard_bound`           | Decode shard key-range bound (empty = unbounded)                 |
| `lower_bound`           | Binary search: first index with key >= target                    |
| `upper_bound`           | Binary search: first index with key > target                     |
| `choose_split_index`    | Byte-weighted median split with count-balanced fallback          |

Both connectors use `choose_split_index` (or its prefix-sum equivalent)
for byte-weighted median split selection. Count-balanced midpoint is the
fallback when all entries are zero-size or weight concentrates in the
leading entry.

---

## 9. Scan Loop Integration

> **Status: Aspirational** — The subsections below titled "Loop structure",
> "Key scan-loop invariants", "Current scope", and "Retry and failure
> handling" describe a planned `gossip-scan-pipeline` crate and its
> `run_scan_loop` API which have **not been implemented**. The constants
> `DEFAULT_MAX_TRANSIENT_RETRIES` and `DEFAULT_RENEW_AT_FRACTION` do not
> exist in the codebase. The `connector-pipeline` feature flag referenced
> elsewhere does not exist in any `Cargo.toml`.
>
> The **current** scan execution path is:
>
> - **`gossip-scan-driver`** — defines `ScanDriver::run()` and
>   `ScanSourceFactory` traits
>   (`crates/gossip-scan-driver/src/lib.rs`).
> - **`gossip-connectors::scan_driver`** — provides
>   `FilesystemScanSourceFactory`, `GitScanSourceFactory`, and
>   `InMemoryScanSourceFactory`
>   (`crates/gossip-connectors/src/scan_driver.rs`).
> - **`gossip-scanner-runtime`** — provides `scan_fs()` and `scan_git()`
>   top-level entry points
>   (`crates/gossip-scanner-runtime/src/lib.rs`).

The following describes the **planned** page-level scan loop that would
drive one shard from its current cursor to completion by repeatedly calling
`EnumerationConnector::enumerate_page` and validating each page via
`validate_page` before checkpointing progress through the coordination
backend. None of the functions or constants below exist yet.

### Loop structure (planned)

```text
pre-loop: bridge ShardSpec + Cursor from coordination domain
    │
    ▼
enumerate_page(spec, cursor, budgets)
    │
    ├─ Ok(page) ──► validate_page ──► process_page_hook? ──► checkpoint ──► renew? ──► loop
    ├─ Err(retryable) ──► retry budget ──► park TooManyErrors
    └─ Err(permanent) ──► park (heuristic reason)
```

### Key scan-loop invariants (planned)

- **SL1 -- Validate-before-persist:** pages are always validated before
  any checkpoint or complete call.
- **SL2 -- Consecutive retry accounting:** transient-failure counter
  resets to zero after every successful `enumerate_page`. The planned
  budget is `DEFAULT_MAX_TRANSIENT_RETRIES = 3` (not yet defined).
- **SL3 -- Poisoned state never retried:** invalid spec bytes,
  unconvertible cursors, and failed validations are parked `Poisoned`
  immediately.
- **SL7 -- Renewal-after-checkpoint ordering:** lease renewal is
  attempted only after successful checkpoint, preserving forward progress.
- **SL8 -- Process-before-persist ordering:** when using a page hook,
  non-empty pages are processed after validation and before checkpoint.
  Hook failure aborts without persisting cursor progress for that page.

### Current scope (planned)

The planned default APIs (`run_scan_loop`, `run_scan_loop_with_policy`)
would advance coordination cursor state only. They would **not** perform
item reads, detection fan-out, or finding derivation.

The planned hook-enabled APIs (`run_scan_loop_with_page_processor`,
`run_scan_loop_with_policy_and_page_processor`) would inject non-empty
page processing before checkpoint for shadow-mode integration and
adapter composition.

### Retry and failure handling (planned)

The planned retry model is a simple consecutive-failure counter (not a
circuit breaker). When `transient_failures >= max_transient_retries`,
the shard would be parked with `ParkReason::TooManyErrors`. Permanent
errors would be parked with a heuristic-classified `ParkReason`. Lease
renewal would use `DEFAULT_RENEW_AT_FRACTION = 0.5` (half-life trigger).
Neither constant exists in the codebase yet.

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

### Trait split rationale

Enumeration and reading are separate traits because they have independent
scaling characteristics: enumeration is metadata-bound, reading is
bandwidth-bound. Orchestration can compose them independently while
`ConnectorInstance` provides a shorthand bound when both are needed.

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
