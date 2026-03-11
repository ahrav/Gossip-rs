# gossip-scan-driver — Unified Scan-Driver Boundary

## Module Purpose

The `gossip-scan-driver` crate defines the trait-based execution boundary that decouples scan orchestration from source-specific scanning backends. It is the single integration seam shared by both CLI and distributed scanner runtimes, providing a uniform `Assignment → ScanSourceFactory → ScanDriver::run()` pipeline regardless of whether the underlying source is a filesystem directory, a git repository, or an in-memory test dataset.

The crate intentionally contains no concrete implementations — only trait definitions, configuration structs, and shared value types. Concrete drivers live in `gossip-connectors` (see `crates/gossip-connectors/src/scan_driver.rs`), keeping the contracts crate lightweight and preventing reverse dependencies from scanner internals into orchestration logic.

---

## Source File Map

| File | Role |
|------|------|
| `crates/gossip-scan-driver/src/lib.rs` | All types, traits, and enums — single-file crate |
| `crates/gossip-scan-driver/Cargo.toml` | Crate manifest and dependency declarations |

---

## Architecture Diagram

```
                          ┌──────────────────────┐
                          │     Assignment        │
                          │  (job_id, source,     │
                          │   cursor, shard_spec) │
                          └──────────┬───────────┘
                                     │
                                     ▼
                          ┌──────────────────────┐
                          │  ScanSourceFactory    │
                          │  .driver_for_         │
                          │   assignment()        │
                          │  .capabilities()      │
                          └──────────┬───────────┘
                                     │
                                     ▼
               ┌─────────────────────────────────────────┐
               │            ScanDriver::run()            │
               │                                         │
               │  engine: Arc<Engine>                     │
               │  cfg: &ScanExecutionConfig               │
               │  out: &dyn GitEventOutput               │
               │  commit: &dyn CommitSink                │
               │  cancel: &CancellationToken             │
               │                                         │
               │  → ScanReport                           │
               └─────────────────────────────────────────┘
```

The pipeline works as follows:

1. The orchestration layer constructs an `Assignment` describing the work unit (source location, cursor position, shard boundaries, policy hash).
2. A `ScanSourceFactory` inspects the assignment and produces a boxed `ScanDriver` appropriate for the source type.
3. The driver's `run()` method executes the scan, consuming engine resources, emitting core and git-specific events through `GitEventOutput`, and respecting the `CancellationToken`. Filesystem and in-memory drivers also forward per-item lifecycle calls through `CommitSink`; the git driver currently does not use the commit sink (git persistence is handled separately via the scanner's `PersistenceStore`).

---

## Key Traits

### `ScanDriver`

Source-specific execution backend. Drivers are `Send` (created on one thread, run on another) but not required to be `Sync`.

| Method | Signature | Description |
|--------|-----------|-------------|
| `run` | `(&mut self, engine, cfg, out, commit, cancel) → Result<ScanReport>` | Execute the scan. Receives the shared detection engine, runtime configuration, unified event sink, commit sink, and cancellation token. Returns aggregate metrics on success. |
| `checkpoint_hint` | `(&self) → Option<CursorUpdate>` | Returns the latest cursor checkpoint produced during scanning. Default returns `None` (no checkpoint support). |
| `debug_output` | `(&self) → Option<String>` | Returns optional diagnostic text collected during the scan (e.g., git stage timings). Default returns `None`. |

### `ScanSourceFactory`

Factory that maps assignments to source-specific drivers. Factories are `Send` so they can be moved into worker threads.

| Method | Signature | Description |
|--------|-----------|-------------|
| `driver_for_assignment` | `(&self, assignment: &Assignment) → Result<Box<dyn ScanDriver>>` | Validate the assignment and produce a driver. Returns an error if the assignment's `ConnectorKind` or `AssignmentSource` variant does not match the factory's source type. |
| `capabilities` | `(&self) → SourceCapabilities` | Declare what the produced drivers support (checkpoint hints, cooperative cancellation) so the orchestration layer can adapt scheduling decisions. |

### `CommitSink`

Per-item commit lifecycle sink (`Send + Sync`). The orchestration layer uses this to track item-level progress for persistence and coordination.

| Method | Signature | Description |
|--------|-----------|-------------|
| `begin_item` | `(&self, item_key: &ItemKey, meta: &ItemMeta) → Result<()>` | Signal that scanning has started for a given item. |
| `upsert_findings` | `(&self, item_key: &ItemKey, batch: &FindingsBatch) → Result<()>` | Deliver a batch of findings detected in the item. |
| `finish_item` | `(&self, item_key: &ItemKey) → Result<()>` | Signal that scanning is complete for the item. |

A no-op implementation `NoOpCommitSink` is provided for CLI mode where per-item commit tracking is unnecessary.

---

## Key Types

### `Assignment`

Work unit handed to a `ScanSourceFactory`. Contains everything needed to construct a driver and resume a scan from a prior checkpoint.

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | `String` | Unique identifier for this scan job. |
| `connector_kind` | `ConnectorKind` | Source family discriminator (Filesystem, Git, InMemory). |
| `connector_instance_id` | `String` | Identifies the specific connector instance within a kind. |
| `policy_hash` | `PolicyHash` | Hash of the detection policy (rule set) used for this scan. |
| `shard_spec` | `ShardSpec` | Key-range shard boundaries from the coordination layer. |
| `cursor` | `Cursor` | Resume position from a prior scan (or `Cursor::initial()` for a fresh start). |
| `source` | `AssignmentSource` | Source-specific payload (filesystem root, git repo root, or dataset ID). |

### `AssignmentSource`

Tagged enum carrying source-specific configuration for each connector family.

| Variant | Fields | Description |
|---------|--------|-------------|
| `Filesystem` | `root: PathBuf` | Absolute path to the directory tree to scan. |
| `Git` | `repo_root: PathBuf` | Absolute path to the git repository root. |
| `InMemory` | `dataset_id: String` | Identifier matching a pre-loaded in-memory dataset. |

### `ConnectorKind`

Simple discriminator enum with three variants: `Filesystem`, `Git`, `InMemory`. Used by factories for assignment validation and by the orchestration layer for routing.

### `ScanExecutionConfig`

Top-level runtime knobs shared across all driver implementations.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `workers` | `usize` | `1` | Number of parallel scan worker threads. |
| `checkpoint_every_items` | `u64` | `1_000` | Emit a checkpoint hint every N items. |
| `filesystem` | `FilesystemExecutionConfig` | (see below) | Filesystem-specific knobs. |
| `git` | `GitExecutionConfig` | (see below) | Git-specific knobs. |

### `FilesystemExecutionConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `skip_archives` | `bool` | `false` | Disable archive expansion. |
| `skip_binary` | `bool` | `true` | Skip binary-looking files. |
| `emit_findings_to_commit_sink` | `bool` | `false` | Forward findings through the commit sink bridge. |

### `GitExecutionConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `repo_id` | `u64` | `1` | Stable repository identifier for namespacing persisted keys. |
| `scan_mode` | `GitScanMode` | `OdbBlobFast` | Git scan strategy (diff-history vs ODB-blob fast-path). |
| `merge_diff_mode` | `MergeDiffMode` | `AllParents` | Merge-diff strategy for merge commits. |
| `pack_exec_workers` | `Option<usize>` | `None` | Pack execution worker override; falls back to `ScanExecutionConfig::workers`. |
| `scan_binary` | `bool` | `false` | Scan all blobs including binary-class files. |
| `enrich_identities` | `bool` | `false` | Emit identity-dictionary and enriched commit metadata. |
| `debug_level` | `GitDebugLevel` | `Off` | Diagnostic output level (`Off`, `Stats`, `Perf`). |
| `tree_delta_cache_mb` | `Option<u32>` | `None` | Tree delta cache size override in MiB. |
| `engine_chunk_mb` | `Option<u32>` | `None` | Engine chunk size override in MiB. |

### `ScanReport`

Aggregate metrics returned by `ScanDriver::run()`.

| Field | Type | Description |
|-------|------|-------------|
| `items_scanned` | `u64` | Total items (files, blobs) processed. |
| `bytes_scanned` | `u64` | Total bytes read and scanned. |
| `findings_emitted` | `u64` | Total findings emitted to event sinks. |

### `CursorUpdate`

Checkpoint hint produced by drivers that support resumable scans.

| Field | Type | Description |
|-------|------|-------------|
| `cursor` | `Cursor` | Resume cursor (last processed key + optional token). |
| `committed_items` | `u64` | Number of items committed up to this cursor position. |

### `SourceCapabilities`

Coarse capability flags declared by `ScanSourceFactory::capabilities()`. These tell the orchestration layer what a driver supports so it can adapt scheduling and lifecycle decisions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `supports_checkpoint_hints` | `bool` | `false` | Driver produces meaningful `CursorUpdate` values from `checkpoint_hint()`. |
| `supports_cooperative_cancel` | `bool` | `false` | Driver polls `CancellationToken::is_cancelled()` at regular intervals during execution (not just before starting). |

### `CancellationToken`

Cooperative cancellation primitive backed by an `Arc<AtomicBool>`. Drivers check `is_cancelled()` at source-specific scheduling boundaries (e.g., between batch submissions or between items).

| Method | Description |
|--------|-------------|
| `new()` | Create a token in the non-cancelled state. |
| `cancel()` | Request cancellation (`Release` store). |
| `is_cancelled()` | Check whether cancellation was requested (`Acquire` load). |

### `ItemMeta`

Metadata associated with a single committed item, passed to `CommitSink::begin_item`.

| Field | Type | Description |
|-------|------|-------------|
| `version` | `Option<VersionId>` | Optional version identifier (commit SHA, S3 ETag, etc.). |
| `size_hint` | `Option<u64>` | Optional size hint in bytes. |

### `FindingRecord`

Single finding record used by commit sinks.

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | `u32` | Detection rule that matched. |
| `start` | `u64` | Start byte offset of the finding. |
| `end` | `u64` | End byte offset of the finding (exclusive). |
| `norm_hash` | `[u8; 32]` | BLAKE3 digest of the normalized secret. |
| `confidence_score` | `i8` | Confidence score assigned by the detection engine. |

### `FindingsBatch`

Batch of findings for one item, passed to `CommitSink::upsert_findings`.

| Field | Type | Description |
|-------|------|-------------|
| `findings` | `Vec<FindingRecord>` | Zero or more finding records for the item. |

---

## Lifecycle — How an Assignment Flows Through the Driver

```
 Orchestration Layer                ScanSourceFactory              ScanDriver
 ──────────────────                ──────────────────             ──────────
        │                                  │                          │
        │  1. Build Assignment             │                          │
        │     (job_id, source, cursor,     │                          │
        │      shard_spec, policy_hash)    │                          │
        │                                  │                          │
        ├──► 2. driver_for_assignment() ──►│                          │
        │                                  │                          │
        │  3. Validate kind + source       │                          │
        │     variant match                │                          │
        │                                  │                          │
        │◄── 4. Box<dyn ScanDriver> ──────┤                          │
        │                                  │                          │
        │  5. Construct engine, cfg,       │                          │
        │     event/commit sinks, token    │                          │
        │                                  │                          │
        ├────────────────────────────────────────► 6. run() ─────────►│
        │                                  │                          │
        │                                  │     7. Scan execution:   │
        │                                  │        - Read items      │
        │                                  │        - Engine scan     │
        │                                  │        - Emit events     │
        │                                  │        - begin/finish    │
        │                                  │          items via       │
        │                                  │          CommitSink      │
        │                                  │        - Check cancel    │
        │                                  │          token           │
        │                                  │                          │
        │◄──────────────────────────────────────── 8. ScanReport ────┤
        │                                  │                          │
        │  9. checkpoint_hint() ──────────────────────────────────────►│
        │◄──── Option<CursorUpdate> ──────────────────────────────────┤
        │                                  │                          │
        │  10. Persist cursor + report     │                          │
        │      for resumable scanning      │                          │
```

**Step-by-step:**

1. The orchestration layer (CLI or distributed runtime) constructs an `Assignment` from coordination metadata.
2. The assignment is passed to the appropriate `ScanSourceFactory`.
3. The factory validates that `connector_kind` and `source` variant match (e.g., `ConnectorKind::Filesystem` with `AssignmentSource::Filesystem`).
4. On success, the factory returns a boxed `ScanDriver`.
5. The caller prepares shared resources: the detection `Engine`, `ScanExecutionConfig`, unified `GitEventOutput` sink, `CommitSink`, and `CancellationToken`.
6. `ScanDriver::run()` is called with all resources.
7. The driver executes the scan. Filesystem drivers use `parallel_scan_dir`, git drivers use `run_git_scan`, and in-memory drivers iterate pre-loaded items. Core and git-specific events are emitted through `GitEventOutput`. Filesystem and in-memory drivers forward per-item commit lifecycle calls through `CommitSink`; the git driver does not currently use the commit sink.
8. `run()` returns a `ScanReport` with aggregate metrics.
9. The caller may query `checkpoint_hint()` for a resume cursor (if `SourceCapabilities::supports_checkpoint_hints` is true).
10. The orchestration layer persists the cursor and report for future resumable scans.

---

## Concrete Implementations

The crate defines only traits and types. Concrete implementations live in `gossip-connectors`:

| Factory | Driver | Source | Backend |
|---------|--------|--------|---------|
| `FilesystemScanSourceFactory` | `FsScanDriver` | `AssignmentSource::Filesystem` | `parallel_scan_dir` from `scanner-scheduler` |
| `InMemoryScanSourceFactory` | `InMemoryScanDriver` | `AssignmentSource::InMemory` | Direct iteration over `MemItem` slices |

> **Git scans** bypass the factory/trait path entirely. The standalone
> `execute_git_assignment()` function handles git assignments directly,
> accepting `&dyn GitEventOutput` for git-specific events that the
> source-neutral `ScanDriver` trait cannot express.

### Capability Matrix

| Factory | `supports_checkpoint_hints` | `supports_cooperative_cancel` |
|---------|:---------------------------:|:-----------------------------:|
| Filesystem | no | no |
| InMemory | yes | yes |

---

## Extension Guide — Adding a New Source Type

To add a new source type (e.g., S3, cloud storage):

### 1. Add variants to `gossip-scan-driver`

In `crates/gossip-scan-driver/src/lib.rs`:

- Add a variant to `ConnectorKind` (e.g., `S3`).
- Add a variant to `AssignmentSource` (e.g., `S3 { bucket: String, prefix: String }`).

### 2. Implement the factory and driver in `gossip-connectors`

In `crates/gossip-connectors/src/scan_driver.rs`:

- Create a factory struct implementing `ScanSourceFactory`:
  - `driver_for_assignment`: validate `ConnectorKind` match, extract source fields, construct driver.
  - `capabilities`: declare checkpoint and cancellation support.

- Create a driver struct implementing `ScanDriver`:
  - `run`: execute the source-specific scan loop, using the provided `engine`, emitting events through `out`, and calling `commit.begin_item` / `commit.finish_item` for each scanned item.
  - `checkpoint_hint`: return `Some(CursorUpdate)` if the driver tracks cursor progress.
  - `debug_output`: return optional diagnostic text.

### 3. Wire into orchestration

Register the new factory in the CLI or distributed runtime entry point so that assignments with the new `ConnectorKind` are routed to the correct factory.

### Key contracts to uphold

- **Kind validation**: `driver_for_assignment` must reject assignments whose `connector_kind` does not match the factory's source type.
- **Cancellation**: if `supports_cooperative_cancel` is true, `run()` must poll `cancel.is_cancelled()` at regular intervals (not just before starting).
- **Commit lifecycle**: call `begin_item` before scanning an item and `finish_item` after, even if no findings are produced. Call `upsert_findings` between begin and finish when findings exist.
- **Event emission**: emit `CoreEvent::Progress` at regular intervals and `CoreEvent::Finding` for each detection.

---

## Dependencies

| Crate | Role |
|-------|------|
| `gossip-contracts` | `Cursor`, `ItemKey`, `VersionId`, `ShardSpec`, `PolicyHash` |
| `scanner-engine` | `Engine` (the detection engine passed to `ScanDriver::run`) |
| `scanner-git` | `GitEventOutput`, `GitScanMode`, `MergeDiffMode` |
| `scanner-scheduler` | `EventOutput` (event emission trait) |
| `anyhow` | Error handling |

---

## Source of Truth

| Item | Authoritative path |
|------|--------------------|
| Trait definitions and all types | `crates/gossip-scan-driver/src/lib.rs` |
| Concrete driver implementations | `crates/gossip-connectors/src/scan_driver.rs` |
| Crate manifest | `crates/gossip-scan-driver/Cargo.toml` |
