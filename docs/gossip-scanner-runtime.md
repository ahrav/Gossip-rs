# gossip-scanner-runtime

## 1. Module Purpose

The `gossip-scanner-runtime` crate provides the unified runtime
orchestration layer for scanner execution. It bridges CLI argument
parsing and distributed coordination into a single scan-driver seam,
routing both filesystem and git scans through the same
`Assignment -> ScanSourceFactory -> ScanDriver::run` pipeline. The crate
also owns finding identity derivation, output format sinks, and JSONL
parity testing infrastructure.

---

## 2. Source File Map

| File | Purpose |
|------|---------|
| `src/lib.rs` | Core wiring: config types (`FsScanConfig`, `GitScanConfig`, `ScanBudgets`), execution-mode dispatch (`scan_fs`, `scan_git`), engine construction, assignment building, path validation |
| `src/cli.rs` | CLI argument parser (`parse_args`), `CliConfig` struct, `run()` entrypoint that builds event sinks and dispatches scans |
| `src/commit_sink.rs` | `DurableCommitSink` for distributed mode: derives full finding identity chain (`norm_hash -> secret_hash -> finding_id -> occurrence_id`) and persists records through the coordinator recorder |
| `src/coordination_sink.rs` | `CoordinationEventSink` implementing `EventOutput` + `GitEventOutput`, owned event representations (`StoredCoreEvent`, `StoredGitEvent`), `CoordinationEventRecorder` trait, `IdentityChainRecord` |
| `src/distributed.rs` | Distributed worker loop (`run_worker`), `DistributedCoordinator` trait, `ShardLease`, done-ledger gating, `InMemoryCoordinator` test harness |
| `src/event_sink.rs` | Output format sinks: `JsonlEventSink`, `TextEventSink`, `JsonEventSink`, `SarifEventSink`; hand-rolled JSON encoding with broken-pipe tolerance |
| `src/parity.rs` | JSONL parity testing: `canonicalize_jsonl_events` parses scanner output into `CanonicalFinding` tuples with commit-meta joining, path normalization, and sorted deterministic comparison |
| `Cargo.toml` | Dependencies: `gossip-contracts`, `gossip-scan-driver`, `gossip-connectors`, `scanner-engine`, `scanner-scheduler`, `scanner-git`, `regex`, `serde_json` |

---

## 3. Architecture

### Unified execution seam

Both CLI and distributed execution paths route through the same
assignment-to-driver seam. The mode flag (`ExecutionMode`) is retained
for CLI compatibility and telemetry but does not alter scan behavior:

```text
CLI args ──► CliConfig ──► FsScanConfig / GitScanConfig
                                │
Distributed ──► ShardLease ─────┤
                                ▼
                   build_assignment()
                        │
                        ▼
              driver_for_assignment()
                        │
                        ▼
             ScanSourceFactory::driver_for_assignment()
                        │
                        ▼
               ScanDriver::run(engine, config, out, git_out, commit, cancel)
                        │
                        ▼
                 AssignmentOutcome { report, checkpoint_hint, debug_output }
```

### Key wiring functions

| Function | Role |
|----------|------|
| `scan_fs` / `scan_git` | Top-level dispatchers that delegate to direct/connector variants |
| `scan_fs_with_runtime` / `scan_git_with_runtime` | Internal entrypoints that accept event output, commit sink, and cancellation token |
| `execute_assignment_with_config` | Shared driver seam: builds engine, runs driver, returns `AssignmentOutcome` |
| `driver_for_assignment` | Maps `ConnectorKind` to `ScanSourceFactory` (`FilesystemScanSourceFactory` or `GitScanSourceFactory`) |
| `runtime_engine` | Builds or caches the scanner `Engine` with rules, transforms, and tuning |
| `build_assignment` | Constructs an `Assignment` from connector kind, instance ID, and source |

### Engine construction

`runtime_engine` caches the default engine configuration in a `OnceLock`
for reuse across scans. Non-default configurations (custom rules file,
decode depth override, transform filter) build a fresh engine each time.

The engine is assembled from:

- **Rules** -- loaded from an external YAML file via `load_runtime_rules`,
  or a built-in default rule (`runtime-secret`) matching
  `SECRET`/`password`/`token` anchors with a 64-byte radius.
- **Transforms** -- `UrlPercent` and `Base64` decoders, each with
  `AnchorsInDecoded` gating, 64 KiB limits, and 8 max spans per buffer.
- **Tuning** -- default `Tuning` with `merge_gap=64`,
  `max_transform_depth=3`, `max_findings_per_chunk=8192`.
- **Anchor policy** -- `ManualOnly` (default) or `DerivedOnly`, selected
  by `AnchorMode`.

---

## 4. Key Types

### ExecutionMode

```rust
pub enum ExecutionMode {
    Direct,    // default
    Connector,
}
```

Retained for CLI compatibility and telemetry. Both variants currently
execute the same unified scan path.

### AnchorMode

```rust
pub enum AnchorMode {
    Manual,   // default -- ManualOnly anchor policy
    Derived,  // DerivedOnly anchor policy
}
```

Controls whether the engine uses manually specified anchors or derives
them from rule patterns.

### EventFormat

```rust
pub enum EventFormat {
    Jsonl,  // default
    Text,
    Json,
    Sarif,
}
```

Selects the output sink for CLI scans. See section 6 for format details.

### TransformFilter

```rust
pub enum TransformFilter {
    All,                    // default -- all configured transforms
    None,                   // disable all transforms
    Only(Vec<TransformId>), // enable only the listed transforms
}
```

Controls which transform decoders (URL-percent, Base64) are active
during scanning.

### ScanBudgets

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `max_items` | `usize` | 256 | Maximum items processed between checkpoints |
| `max_bytes` | `u64` | 1,000,000 | Runtime-level byte budget knob (must be non-zero) |

Converted to `ScanExecutionConfig` via `to_execution_config()`, which
also sets worker count from `available_parallelism()`.

### FsScanConfig

Builder-pattern configuration for filesystem scans.

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `path` | `PathBuf` | required | Filesystem root or file path to scan |
| `workers` | `usize` | CPU count | Number of worker threads |
| `decode_depth` | `Option<usize>` | `None` | Transform decode depth override |
| `skip_archives` | `bool` | `false` | Disable archive expansion |
| `scan_binary` | `bool` | `false` | Scan binary files |
| `persist_findings` | `bool` | `false` | Persist findings via commit sink bridge |
| `anchor_mode` | `AnchorMode` | `Manual` | Anchor extraction policy |
| `rules_file` | `Option<PathBuf>` | `None` | External rules file path |
| `transform_filter` | `TransformFilter` | `All` | Transform decoder filter |
| `execution_mode` | `ExecutionMode` | `Direct` | Retained for compatibility |
| `budgets` | `ScanBudgets` | default | Scan execution budget controls |

### GitScanConfig

Builder-pattern configuration for git scans.

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `repo` | `PathBuf` | required | Repository root path |
| `workers` | `usize` | CPU count | Number of pack-exec worker threads |
| `decode_depth` | `Option<usize>` | `None` | Transform decode depth override |
| `scan_binary` | `bool` | `false` | Scan binary blobs |
| `debug_level` | `GitDebugLevel` | `Off` | Git debug output level (`Off`, `Stats`, `Perf`) |
| `enrich_identities` | `bool` | `false` | Enrich commit metadata with identity dictionary IDs |
| `anchor_mode` | `AnchorMode` | `Manual` | Anchor extraction policy |
| `rules_file` | `Option<PathBuf>` | `None` | External rules file path |
| `transform_filter` | `TransformFilter` | `All` | Transform decoder filter |
| `repo_id` | `u64` | 1 | Stable repository identifier for persistence keys |
| `scan_mode` | `GitScanMode` | `OdbBlobFast` | Diff-history vs ODB-blob fast path |
| `merge_mode` | `MergeDiffMode` | `AllParents` | Merge-diff strategy for merge commits |
| `tree_delta_cache_mb` | `Option<u32>` | `None` | Tree delta cache size override in MiB |
| `engine_chunk_mb` | `Option<u32>` | `None` | Engine chunk size override in MiB |
| `execution_mode` | `ExecutionMode` | `Direct` | Retained for compatibility |
| `budgets` | `ScanBudgets` | default | Scan execution budget controls |

### AssignmentOutcome

| Field | Type | Purpose |
|-------|------|---------|
| `report` | `ScanReport` | Scan-driver report (items scanned, findings, etc.) |
| `checkpoint_hint` | `Option<CursorUpdate>` | Driver-provided checkpoint to hand back to coordinators |
| `debug_output` | `Option<String>` | Driver-generated debug diagnostics (for CLI stderr) |

### ScanRuntimeError

Flat error enum covering all runtime wiring failures:

| Variant | Cause |
|---------|-------|
| `InvalidPath { source, path, message }` | Path validation failure (does not exist, not a directory, not repo root) |
| `UnsupportedConnectorKind(ConnectorKind)` | `InMemory` connector requested at runtime |
| `GitCommandFailed { repo, status_code, stderr }` | `git rev-parse --show-toplevel` failure |
| `Io { op, path, error }` | Filesystem canonicalization or git command spawn failure |
| `RulesConfig { path, message }` | Rules file read or parse error |
| `ConnectorInput(ConnectorInputError)` | Zero-budget or invalid connector input |
| `Driver(anyhow::Error)` | Scan driver execution failure |

---

## 5. Execution Modes

### CLI mode (`src/cli.rs`)

The CLI entrypoint parses `scanner-rs scan {fs|git}` commands with flag
and positional arguments. The parser is hand-rolled (no clap dependency)
to keep the binary small and startup fast.

**Usage patterns:**

```text
scanner-rs scan fs  --path <dir|file> [FS OPTIONS] [COMMON OPTIONS]
scanner-rs scan git --repo <path>     [GIT OPTIONS] [COMMON OPTIONS]
```

**Common flags:**

| Flag | Values | Default |
|------|--------|---------|
| `--execution-mode` | `direct`, `connector` | `direct` |
| `--max-items` | integer | 256 |
| `--max-bytes` | integer | 1000000 |
| `--workers` | integer >= 1 | CPU count |
| `--decode-depth` | integer | engine default |
| `--anchors` | `manual`, `derived` | `manual` |
| `--rules` | file path | built-in rules |
| `--transforms` | `all`, `none`, or comma-separated list | `all` |
| `--event-format` | `jsonl`, `text`, `json`, `sarif` | `jsonl` |
| `--null-sink` | flag | off |
| `--verbose` | flag | off |

**FS-specific flags:** `--skip-archives`, `--scan-archives`,
`--scan-binary`, `--skip-binary`, `--persist-findings`

**Git-specific flags:** `--debug[=perf|stats]`, `--enrich-identities`

**Git hidden flags (parsed but excluded from help text):**
`--x-repo-id`, `--x-mode`, `--x-merge`, `--x-pack-exec-workers`,
`--x-tree-delta-cache-mb`, `--x-engine-chunk-mb`

The `cli::run` function:

1. Builds an event sink from `EventFormat` + `null_sink` + `verbose`.
2. Constructs `FsScanConfig` or `GitScanConfig` from `CliConfig`.
3. Calls `scan_fs_with_runtime` or `scan_git_with_runtime` with a
   `CliNoOpCommitSink` (no finding persistence in CLI mode).
4. Flushes the event sink and returns the `ScanReport`.

### Distributed mode (`src/distributed.rs`)

The distributed worker loop processes shards from a coordinator:

1. **Acquire** -- `coordinator.acquire_shard()` returns the next
   `ShardLease` or `None` when no work remains.
2. **Done-ledger gate** -- `coordinator.is_shard_done()` checks whether
   the shard was already completed. If done, the lease is released and
   skipped.
3. **Scan** -- Builds a `CoordinationEventSink` and `DurableCommitSink`
   from the lease's tenant credentials, then calls
   `execute_assignment_with_config` with `emit_findings_to_commit_sink`
   enabled.
4. **Complete** -- `coordinator.complete_shard()` with checkpoint hint
   and report, then `coordinator.mark_shard_done()`.
5. **Loop** until `acquire_shard()` returns `None`.

### Direct vs Connector

`ExecutionMode::Direct` and `ExecutionMode::Connector` are retained as
separate enum variants for CLI flag compatibility and telemetry tagging.
Both variants currently execute the identical scan path: connector-mode
functions (`scan_fs_connector`, `scan_git_connector`) delegate directly
to their direct-mode counterparts.

---

## 6. Output Sinks (`src/event_sink.rs`)

All sinks implement both `EventOutput` (core scheduler events) and
`GitEventOutput` (git-specific events). Broken-pipe errors are silently
tolerated for CLI piping compatibility.

### JSONL (`JsonlEventSink`)

One JSON object per line, newline-delimited. Finding records intentionally
omit a `type` field for scanner-rs parity. Progress, summary, and
diagnostic records include `"type":"progress"`, `"type":"summary"`, and
`"type":"diagnostic"` respectively.

Git events use `"type":"commit_meta"` and `"type":"identity_dictionary"`.

### Text (`TextEventSink`)

Human-readable output. Non-verbose mode emits compact single-line
findings:

```text
path/to/file:10-40  rule-name  (fs)
```

Verbose mode emits multi-line blocks with labeled fields. Progress events
are only emitted in verbose mode. Diagnostics are written to stderr.

### JSON (`JsonEventSink`)

Streaming JSON array. Opens with `[`, emits comma-separated elements,
and closes with `]` on flush. Double-flush is safe (guarded by an
`AtomicBool` closed flag).

### SARIF (`SarifEventSink`)

SARIF 2.1.0 format. Emits a complete SARIF document with tool metadata
(`scanner-rs` + crate version), a single run, and results array. Only
finding events are included; progress and diagnostic events are ignored.
Git events are also ignored. Double-flush is safe.

Each result includes `ruleId`, `message`, `locations` (with
`byteOffset` and `byteLength`), and `rank` (confidence score normalized
to 0-100 scale).

---

## 7. Identity Chain (`src/commit_sink.rs`)

`DurableCommitSink` implements the `CommitSink` trait for distributed
mode, deriving the full finding identity chain at commit time so the
scan loop remains focused on detection.

### Derivation flow

```text
FindingRecord.norm_hash
       │
       ▼
NormHash::from_digest(norm_hash)
       │
       ▼
key_secret_hash(tenant_secret_key, &norm_hash)  ──►  secret_hash
       │
       ▼
derive_finding_id(FindingIdInputs {
    tenant, item: stable_item, rule: rule_fingerprint, secret: secret_hash
})  ──►  finding_id
       │
       ▼
derive_occurrence_id(OccurrenceIdInputs {
    finding: finding_id, version: object_version, byte_offset, byte_length
})  ──►  occurrence_id
```

### CommitSink protocol

| Method | Behavior |
|--------|----------|
| `begin_item(item_key, meta)` | Stores per-item metadata in `in_flight_meta` map; records `CommitProgressRecord::Begin` |
| `upsert_findings(item_key, batch)` | For each finding in batch: derives `IdentityChainRecord` and records it via `recorder.record_identity_chain` |
| `finish_item(item_key)` | Removes item from `in_flight_meta`; records `CommitProgressRecord::Finish` |

### Version ID resolution

When connector-provided `ItemMeta.version` is present, the sink uses
`version.object_version_id()` for occurrence derivation. Otherwise, it
falls back to `ObjectVersionId::from_version_bytes(item_key)`.

### Rule fingerprint

`rule_fingerprint_from_rule_id` converts the `u32` rule ID into a
`RuleFingerprint` by zero-padding the LE bytes into a 32-byte array.

---

## 8. Distributed Mode (`src/distributed.rs`)

### DistributedCoordinator trait

```rust
pub trait DistributedCoordinator: Send + Sync {
    fn acquire_shard(&self) -> Result<Option<ShardLease>>;
    fn release_shard(&self, lease: &ShardLease) -> Result<()>;
    fn complete_shard(
        &self, lease: &ShardLease,
        checkpoint: Option<CursorUpdate>, report: ScanReport,
    ) -> Result<()>;
    fn is_shard_done(&self, shard_id: &str) -> Result<bool>;
    fn mark_shard_done(&self, shard_id: &str) -> Result<()>;
    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder>;
}
```

| Method | Purpose |
|--------|---------|
| `acquire_shard` | Get next lease to process, or `None` when queue is empty |
| `release_shard` | Release lease without marking complete (done-ledger skip path) |
| `complete_shard` | Mark lease complete with optional checkpoint and report |
| `is_shard_done` | Query done-ledger before scanning |
| `mark_shard_done` | Persist done-ledger entry after successful scan |
| `event_recorder` | Shared recorder for event and commit sinks |

### ShardLease

| Field | Type | Purpose |
|-------|------|---------|
| `shard_id` | `String` | Unique shard identifier for done-ledger and event recording |
| `assignment` | `Assignment` | Scan-driver assignment (job ID, connector kind, source, cursor, shard spec) |
| `tenant_id` | `TenantId` | Tenant identity for finding ID derivation |
| `tenant_secret_key` | `TenantSecretKey` | Tenant secret for secret hash derivation |

### Worker loop lifecycle

```text
loop {
    lease = coordinator.acquire_shard()?
    if lease is None → break

    if coordinator.is_shard_done(lease.shard_id)? {
        coordinator.release_shard(&lease)?
        report.shards_skipped_done += 1
        continue
    }

    sink = CoordinationEventSink::new(recorder, shard_id)
    commit = DurableCommitSink::new(recorder, shard_id, tenant_id, tenant_secret_key, connector_tag)

    outcome = execute_assignment_with_config(
        &lease.assignment, runtime, &engine_config, &sink, Some(&sink), &commit, &cancel
    )?

    coordinator.complete_shard(&lease, outcome.checkpoint_hint, outcome.report)?
    coordinator.mark_shard_done(lease.shard_id)?
    report.shards_scanned += 1
}
```

### DistributedRunReport

| Field | Type | Purpose |
|-------|------|---------|
| `leases_seen` | `u64` | Total leases acquired from coordinator |
| `shards_scanned` | `u64` | Shards that completed scanning |
| `shards_skipped_done` | `u64` | Shards skipped by done-ledger gate |

### InMemoryCoordinator

Test harness implementing `DistributedCoordinator` +
`CoordinationEventRecorder` backed by `Arc<Mutex<State>>`. Provides
inspection methods: `done_set()`, `released_shards()`,
`completed_shards()`, `core_events()`, `identity_records()`.

### CoordinationEventRecorder trait

```rust
pub trait CoordinationEventRecorder: Send + Sync {
    fn record_core_event(&self, shard_id: &str, event: StoredCoreEvent) -> Result<()>;
    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()>;
    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()>;
    fn record_identity_chain(&self, shard_id: &str, record: IdentityChainRecord) -> Result<()>;
}
```

Recorder failures are intentionally non-fatal for event emission:
commit durability is enforced by `DurableCommitSink`, while event
recording remains best-effort telemetry.

---

## 9. Coordination Event Types (`src/coordination_sink.rs`)

### StoredCoreEvent

Owned representation of scheduler core events, persisted by distributed
sinks.

| Variant | Key Fields |
|---------|------------|
| `Finding` | `source`, `object_path`, `start`, `end`, `rule_id`, `rule_name`, `commit_id`, `change_kind`, `confidence_score` |
| `Progress` | `source`, `stage`, `objects_scanned`, `bytes_scanned`, `findings_emitted` |
| `Summary` | `source`, `status`, `elapsed_ms`, `bytes_scanned`, `findings_emitted`, `errors`, `throughput_mib_s` |
| `Diagnostic` | `level`, `message` |

### StoredGitEvent

| Variant | Key Fields |
|---------|------------|
| `CommitMeta` | `commit_id`, `oid_hex`, `timestamp`, `author_name_id`, `author_email_id`, `committer_name_id`, `committer_email_id` |
| `IdentityDictionary` | `id`, `value` |

### CommitProgressRecord

| Variant | Fields |
|---------|--------|
| `Begin` | `item_key`, `size_hint` |
| `Finish` | `item_key` |

### IdentityChainRecord

| Field | Type | Purpose |
|-------|------|---------|
| `item_key` | `Vec<u8>` | Source item key bytes |
| `rule_id` | `u32` | Matched rule identifier |
| `start` | `u64` | Finding start byte offset |
| `end` | `u64` | Finding end byte offset |
| `confidence_score` | `i8` | Detection confidence score |
| `norm_hash` | `[u8; 32]` | BLAKE3 hash of normalized secret bytes |
| `secret_hash` | `[u8; 32]` | Keyed hash of norm_hash with tenant secret |
| `finding_id` | `[u8; 32]` | Deterministic finding identity |
| `occurrence_id` | `[u8; 32]` | Deterministic occurrence identity |

---

## 10. JSONL Parity Testing (`src/parity.rs`)

The parity module enables deterministic comparison between gossip-rs
and scanner-rs output. It canonicalizes JSONL event streams into sorted
finding tuples, abstracting over format differences between the two
scanner implementations.

### Canonicalization rules

- Both scanner-rs shapes (`"type":"finding"` + `rule` field) and
  gossip-rs shapes (no `type` field, `rule_name` field) are accepted.
- Git findings with `commit_id` are joined to `commit_meta` events to
  resolve commit OID and timestamp.
- A summary event with `throughput_mib_s` is required.
- Path prefixes can be stripped via `canonicalize_jsonl_events_with_roots`
  for stable cross-machine comparison.
- Output findings are sorted for deterministic assertion.

### CanonicalFinding

| Field | Type | Purpose |
|-------|------|---------|
| `path` | `String` | Source-displayed path (optionally root-normalized) |
| `rule` | `String` | Rule identity |
| `start` | `u64` | Inclusive start offset |
| `end` | `u64` | Exclusive end offset |
| `source` | `String` | Source kind (`fs`, `git`) |
| `change_kind` | `Option<String>` | Git change kind (omitted for FS) |
| `commit_oid` | `Option<String>` | Git commit OID resolved from commit_meta |
| `commit_timestamp` | `Option<u64>` | Git commit timestamp from commit_meta |

### CanonicalRun

| Field | Type | Purpose |
|-------|------|---------|
| `findings` | `Vec<CanonicalFinding>` | Sorted canonical finding identities |
| `throughput_mib_s` | `f64` | Throughput from summary event |

---

## 11. Source of Truth

| Concern | Authoritative Path |
|---------|--------------------|
| Execution-mode dispatch and config types | `crates/gossip-scanner-runtime/src/lib.rs` |
| CLI argument parsing and `run()` | `crates/gossip-scanner-runtime/src/cli.rs` |
| Durable finding identity derivation | `crates/gossip-scanner-runtime/src/commit_sink.rs` |
| Coordinator event types and recorder trait | `crates/gossip-scanner-runtime/src/coordination_sink.rs` |
| Distributed worker loop and coordinator trait | `crates/gossip-scanner-runtime/src/distributed.rs` |
| Output format sinks (JSONL, Text, JSON, SARIF) | `crates/gossip-scanner-runtime/src/event_sink.rs` |
| JSONL parity canonicalization | `crates/gossip-scanner-runtime/src/parity.rs` |
| Crate dependencies and feature flags | `crates/gossip-scanner-runtime/Cargo.toml` |
| Scan driver traits (`ScanDriver`, `ScanSourceFactory`) | `crates/gossip-scan-driver/src/lib.rs` |
| Scan source factory implementations | `crates/gossip-connectors/src/scan_driver.rs` |
| Scanner engine construction | `crates/scanner-engine/` |
| Identity derivation primitives | `crates/gossip-contracts/src/identity/` |

---

## 12. Known Limitations

- **GitScanDriver does not use the commit sink.** The git scan driver
  takes a `_commit` parameter but does not call it. Findings discovered
  during git scans in distributed mode are emitted as events but never
  persisted through the identity chain. The shard is still marked done.
  The fix belongs in `gossip-connectors/src/scan_driver.rs`. There is
  an ignored integration test documenting this:
  `distributed::tests::git_shard_produces_identity_records_through_commit_sink`.

- **Upsert without begin_item is silently tolerated.** Calling
  `DurableCommitSink::upsert_findings` without a prior `begin_item` falls
  back to `ItemMeta::default()`, using an item-key-based version ID
  instead of the connector-provided one. The protocol violation is not
  surfaced as an error.
