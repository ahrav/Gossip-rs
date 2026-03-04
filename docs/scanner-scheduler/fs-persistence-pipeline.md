# FS Persistence Pipeline

Write-side plumbing that carries post-dedupe findings from the scheduler's
FS scan loops into a persistence backend.

**Source**: `crates/scanner-scheduler/src/store.rs`,
`crates/scanner-scheduler/src/scheduler/local_fs_owner.rs`, `crates/scanner-scheduler/src/scheduler/parallel_scan.rs`

## Purpose

The detection engine emits findings during scanning, but those findings are
transient — they flow through the `EventOutput` to stdout and are gone. The
FS persistence pipeline adds a **durable write path** so post-dedupe findings
are persisted to a SQLite database for cross-run deduplication, diff analysis,
tracking, and reporting.

This module defines the **producer-side contracts** (what the scheduler
emits). The consumer side (actual backend storage) is plugged in via the
`StoreProducer` trait.

## Relationship to Other Persistence Modules

| Module                                  | Scope           | Purpose                                                                                                         |
| --------------------------------------- | --------------- | --------------------------------------------------------------------------------------------------------------- |
| `crates/scanner-scheduler/src/store.rs` | FS persistence  | `StoreProducer` trait, finding/batch/loss types, and built-in producer impls |
| `crates/scanner-git/src/persist.rs`     | Git persistence | Two-phase persist contract for Git blob scan results                                                            |

The `StoreProducer` trait in `store.rs` defines *how findings flow from
scan workers into a backend*. Concrete producers receive `FsFindingRecord`
batches. Identity chain derivation (stable finding IDs, occurrence IDs,
rule fingerprints) is handled by `DurableCommitSink` in `gossip-scanner-runtime`.

## Data Flow

```text
                     ┌─────────────────────────────────────────────────────────────┐
                     │                    Per-Worker Scan Loop                      │
                     │                                                             │
  Engine             │   scan_chunk_into()                                         │
  ──────────────────►│──────────┬──────────────────────────────────────────────────►│
                     │          │                                                   │
                     │          ▼                                                   │
                     │   drop_prefix_findings()      (cross-chunk overlap dedupe)   │
                     │          │                                                   │
                     │          │  Vec<FindingWithHash<F>>                          │
                     │          ▼                                                   │
                     │   drain_findings_into()                                      │
                     │          │                                                   │
                     │          ▼                                                   │
                     │   apply_cross_rule_dedupe()    (cross-rule winner dedupe)    │
                     │          │                     includes norm_hash in key    │
                     │          ▼                                                   │
                     │   ┌──────┴──────────────┐                                   │
                     │   │                     │                                   │
                     │   ▼                     ▼                                   │
                     │  emit_findings()   emit_persistence_batch()                 │
                     │  (EventOutput)            │                                   │
                     │                         │  build_persistence_batch()        │
                     │                         │  converts to FsFindingRecord[]    │
                     │                         │  wraps in FsFindingBatch          │
                     │                         ▼                                   │
                     │                  StoreProducer::emit_fs_batch()             │
                     │                         │                                   │
                     │           ┌─────────────┼──────────────┬─────────────┐      │
                     │           ▼             ▼              ▼             ▼      │
                      │   SqliteStoreProd  InMemoryProd  NullProducer   (custom)    │
                      │    (planned)        (test/diag)    (discard)                │
                     └─────────────────────────────────────────────────────────────┘

                     At run end:
                     ┌─────────────────────────────────────────────────┐
                     │  Aggregate worker metrics                        │
                     │  ──► FsRunLoss { dropped, failures }            │
                     │  ──► StoreProducer::record_fs_run_loss()        │
                     │  ──► StoreProducer::end_run(had_coverage_limits)│
                     └─────────────────────────────────────────────────┘
```

## Key Types

### FsFindingRecord

Backend-agnostic representation of one post-dedupe finding. All offsets are
absolute byte positions within the scanned object.

```text
┌──────────────────────────────────────┐
│         FsFindingRecord              │
├──────────────────────────────────────┤
│  rule_id: u32                        │  ◄── engine rule that matched
│  root_hint_start: u64                │  ◄── dedup region start
│  root_hint_end: u64                  │  ◄── dedup region end (excl.)
│  span_start: u64                     │  ◄── matched span start
│  span_end: u64                       │  ◄── matched span end (excl.)
│  norm_hash: [u8; 32]                 │  ◄── BLAKE3 of normalized secret
│  confidence_score: i8                │  ◄── additive 0–10 from gate signals
└──────────────────────────────────────┘
```

The `norm_hash` is the BLAKE3 digest of the normalized secret value
(whitespace-collapsed, case-folded). Two findings with the same `norm_hash`
matched the same logical secret, regardless of surrounding context.

### FsFindingBatch

Groups all post-dedupe findings for a single scanned object (plain file or
archive entry).

```text
┌──────────────────────────────────────┐
│         FsFindingBatch<'a>           │
├──────────────────────────────────────┤
│  object_path: &'a [u8]              │  ◄── FS path or virtual archive path
│  findings: &'a [FsFindingRecord]    │  ◄── deduplicated findings
└──────────────────────────────────────┘
```

The batch borrows from per-worker scratch buffers. Implementations must
copy or serialize before returning from `emit_fs_batch()`.

### FsRunLoss

Run-level loss accounting emitted once at scan end.

```text
┌──────────────────────────────────────┐
│           FsRunLoss                  │
├──────────────────────────────────────┤
│  dropped_findings: u64               │  ◄── engine cap drops
│  persistence_emit_failures: u64      │  ◄── batch emit errors
├──────────────────────────────────────┤
│  fn incomplete(&self) -> bool        │  ◄── derived: any loss?
└──────────────────────────────────────┘
```

`incomplete()` is a derived method (not a stored field) that returns `true`
when `dropped_findings > 0 || persistence_emit_failures > 0`.

### StoreProducer Trait

```rust
pub trait StoreProducer: Send + Sync + 'static {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError>;
    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError>;
    fn end_run(&self, had_coverage_limits: bool) -> Result<(), FsStoreError>;
}
```

**Contract:**
- `emit_fs_batch` is called zero or more times during a scan, once per
  scanned object that produced findings. Batches may arrive out of file
  order when workers run in parallel.
- `record_fs_run_loss` is called exactly once at the end of a scan run.
- `end_run` is called once after `record_fs_run_loss` to finalize the run
  (set end time and derive final status). The default implementation is a
  no-op, suitable for backends that don't need run finalization.
- Errors from either method are counted but do **not** abort the scan.

### Implementations

| Type                    | Purpose                                              |
| ----------------------- | ---------------------------------------------------- |
| `NullStoreProducer`     | Default no-op — CLI default, feature-off, benchmarks |
| `InMemoryStoreProducer` | Collects batches in memory for tests and diagnostics |

> **Note:** SQLite persistence backend is not yet implemented. See `StoreProducer` trait in `store.rs`.

### SQLite Backend (Design Specification -- Not Yet Implemented)

The following describes the planned SQLite persistence backend. None of the
code described in this section exists yet. It is retained as the design
specification for the eventual implementation.

When `--persist-findings` is enabled for FS scans, the orchestrator wires
a `StoreProducer` implementation as the persistence backend.

#### Store Root Resolution

The store root directory is currently fixed to a sibling of the scan root:
`<scan_root>/.scanner-store/`.

Example: scanning `/data/repos/myproject` creates
`/data/repos/myproject/.scanner-store/findings.db`.

#### On-Disk Layout

```text
<store_root>/
  ├── findings.db       ← SQLite database (WAL mode)
  ├── findings.db-wal   ← WAL journal (transient, auto-managed by SQLite)
  └── findings.db-shm   ← shared-memory index (transient, auto-managed by SQLite)
```

A single `findings.db` file contains all runs, findings, and metadata.
Multiple runs accumulate in the same database; dimension rows (roots, rules,
paths, secrets) are deduplicated via `INSERT OR IGNORE` on their natural keys.

#### Star Schema

The schema follows a star-schema layout with two fact tables and four
dimension tables, defined in `crates/scanner-scheduler/src/store.rs`:

```text
                  ┌──────────┐
                  │  roots   │  ← dimension: scan target identity
                  └────┬─────┘
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
  ┌─────────┐    ┌──────────┐    ┌──────────┐
  │  paths  │    │   runs   │    │occurrences│ ← fact: per-object findings
  └────┬────┘    └────┬─────┘    └──┬──┬──┬──┘
       │              │             │  │  │
       │              ▼             │  │  ▼
       │         ┌────────────┐    │  │ ┌─────────┐
       │         │observations│    │  │ │ secrets │  ← dimension: normalised
       │         └────────────┘    │  │ └─────────┘    secret identity
       │              ▲            │  │
       │         ┌────────┐       │  ▼
       │         │run_rules│◄─────┤ ┌─────────┐
       │         └────────┘       └►│  rules  │  ← dimension: detection rule
       │                            └─────────┘
       │                                ▲
       └────────────────────────────────┘
                 (paths ← occurrences → rules)
```

**Dimension tables:**

| Table     | Natural key                         | Purpose                                            |
| --------- | ----------------------------------- | -------------------------------------------------- |
| `roots`   | `root_id` (32-byte BLAKE3)          | Scan target identity (FS path, git remote, etc.)   |
| `paths`   | `path_id` (32-byte BLAKE3)          | Canonical file path within a root                  |
| `rules`   | `rule_fingerprint` (32-byte BLAKE3) | Detection rule identity                            |
| `secrets` | `secret_hash` (32-byte BLAKE3)      | Normalized secret identity with aggregate counters |

**Fact tables:**

| Table         | Keys                      | Purpose                                                           |
| ------------- | ------------------------- | ----------------------------------------------------------------- |
| `runs`        | `run_pk` (auto-increment) | One row per scan execution, with timestamps, status, and counters |
| `occurrences` | `occ_pk` (auto-increment) | One row per unique finding (path + rule + secret + offsets)       |

**Junction tables (WITHOUT ROWID):**

| Table          | Composite PK        | Purpose                                        |
| -------------- | ------------------- | ---------------------------------------------- |
| `observations` | `(run_pk, occ_pk)`  | Links runs to their observed occurrences (M:N) |
| `run_rules`    | `(run_pk, rule_pk)` | Tracks which rules were active in each run     |

**Indexes:**

| Index                     | Column(s)                        | Purpose                                       |
| ------------------------- | -------------------------------- | --------------------------------------------- |
| `idx_runs_root`           | `runs(root_pk)`                  | Filter runs by root                           |
| `idx_runs_status_started` | `runs(status, started_at DESC)`  | Status-filtered run listing without temp sort |
| `idx_secrets_occ_count`   | `secrets(occurrence_count DESC)` | Ordered secret listing without temp sort      |
| `idx_occ_secret`          | `occurrences(secret_pk)`         | Secret-based occurrence lookup                |
| `idx_occ_rule`            | `occurrences(rule_pk)`           | Rule-based occurrence lookup                  |
| `idx_obs_occ`             | `observations(occ_pk)`           | Occurrence → observation lookup               |
| `idx_paths_root`          | `paths(root_pk)`                 | Path → root lookup                            |

#### Connection Configuration

| PRAGMA         | Value  | Rationale                                                   |
| -------------- | ------ | ----------------------------------------------------------- |
| `journal_mode` | WAL    | Concurrent readers + single writer without blocking         |
| `synchronous`  | NORMAL | Durability with WAL (fsync on checkpoint, not every commit) |
| `foreign_keys` | ON     | Enforce referential integrity at runtime                    |
| `busy_timeout` | 5000ms | Retry on `SQLITE_BUSY` instead of failing immediately       |
| `cache_size`   | -64000 | ~64 MB page cache (negative = KiB)                          |

Read-only connections (for CLI query commands) skip `journal_mode` and
`synchronous` pragmas to avoid requiring write access.

#### Write Path

The SQLite writer implements the `StoreProducer` trait:

1. **`open(config)`** — Opens (or creates) the database, applies schema
   migrations via `PRAGMA user_version`, resolves or inserts the root
   dimension row, and creates a new `runs` record with `status = InProgress`.

2. **`emit_fs_batch(batch)`** — Runs inside a `BEGIN IMMEDIATE … COMMIT`
   transaction:
   - Resolves or inserts the `paths` dimension row.
   - For each finding: resolves or inserts `rules` (with in-memory cache),
     `secrets`, and `occurrences` dimension rows.
   - Inserts `observations` junction rows linking the run to occurrences.
   - Updates secret aggregate counters (`occurrence_count`, `first_seen_run`,
     `last_seen_run`) via `touch_secret_observation`.
   - On any DML failure, the entire transaction is rolled back.

3. **`record_fs_run_loss(loss)`** — Accumulates drop/failure counters in
   the writer's in-memory `RunCounters`.

4. **`end_run(had_coverage_limits)`** — Derives final run status from
   counters and updates the `runs` row with `ended_at`, `status`, and
   all counter columns.

#### Run Status Derivation

Run status is derived from `RunCounters` at `end_run` time:

| Status code | Name                         | Condition                                      |
| ----------- | ---------------------------- | ---------------------------------------------- |
| 0           | `InProgress`                 | Set at `open()`, before `end_run()` is called  |
| 1           | `Complete`                   | No drops, no emit failures, no coverage limits |
| 2           | `CompleteWithCoverageLimits` | No drops/failures, but coverage caps applied   |
| 3           | `Incomplete`                 | Any dropped findings or emit failures          |
| 4           | `Failed`                     | Reserved for scan-level errors                 |

Precedence: Incomplete > CompleteWithCoverageLimits > Complete.

#### Query Path

Read-path queries in `crates/scanner-scheduler/src/store.rs`:

| Function           | CLI command           | Description                                                      |
| ------------------ | --------------------- | ---------------------------------------------------------------- |
| `list_runs()`      | `store list-runs`     | List runs ordered by `started_at DESC`, optional status filter   |
| `list_findings()`  | `store list-findings` | Findings for a run, with optional rule/path LIKE filters         |
| `diff_runs()`      | `store diff`          | Set-difference between two runs (new, resolved, unchanged count) |
| `list_secrets()`   | `store list-secrets`  | Unique secrets ordered by occurrence count                       |
| `resolve_run_pk()` | (internal)            | Resolve hex prefix to `run_pk` (exact or LIKE match)             |

#### Schema Migration

`PRAGMA user_version` tracks the current schema version. Each migration
function (`apply_v1`, `apply_v2`, …) is idempotent (`CREATE IF NOT EXISTS`)
and runs inside a single `BEGIN IMMEDIATE` transaction. Concurrent callers
are serialized via the busy timeout.

#### Identity Derivation

The writer derives all 32-byte identifiers using BLAKE3 domain-separated hashes:

| Identity           | Domain prefix                          | Inputs                                                     |
| ------------------ | -------------------------------------- | ---------------------------------------------------------- |
| `rule_fingerprint` | `scanner.store.db.v1.rule_fingerprint` | `rule_id`                                                  |
| `path_id`          | `scanner.store.db.v1.path_id`          | `root_id`, `canonical_path`                                |
| `occurrence_id`    | `scanner.store.db.v1.occurrence_id`    | `path_id`, `rule_fingerprint`, `secret_hash`, byte offsets |

#### Thread Safety

All mutable state is behind a `Mutex<WriterState>`. The scheduler calls
`emit_fs_batch` from multiple worker threads; the mutex serializes writes.
Lock acquisition uses `map_err` to return `FsStoreError` instead of
panicking on poisoned locks.

## Loss Accounting

Findings can be lost at two points, and both are tracked:

```text
  Per-chunk:                              Per-run:
  ┌──────────────────────┐               ┌────────────────────────────────┐
  │ Engine scan caps     │               │  FsRunLoss                     │
  │ (max_findings/chunk) │──aggregate───►│    dropped_findings            │
  │ → dropped_findings() │               │                                │
  └──────────────────────┘               │                                │
  ┌──────────────────────┐               │                                │
  │ emit_fs_batch()      │──on error────►│    persistence_emit_failures   │
  │ backend failure      │               │                                │
  └──────────────────────┘               │    incomplete = drops > 0      │
                                         │              OR failures > 0   │
                                         └────────────────────────────────┘
                                                       │
                                                       ▼
                                              record_fs_run_loss()
                                              ──► end_run()
                                              Status: Complete / Incomplete
                                              / CompleteWithCoverageLimits
```

### Metrics Rollup

Worker-level counters are aggregated into `MetricsSnapshot`:

| Worker counter              | Snapshot counter            | Rollup             |
| --------------------------- | --------------------------- | ------------------ |
| `findings_dropped`          | `findings_dropped`          | sum across workers |
| `persistence_emit_failures` | `persistence_emit_failures` | sum across workers |

These feed into `LocalStats` and then into `FsRunLoss` at run end.

## Scan Site Coverage

The `emit_persistence_batch()` call is inserted at every scan site that
produces findings:

| Scan site              | Function                    | File                  |
| ---------------------- | --------------------------- | --------------------- |
| Plain file chunk loop  | `process_file()`            | `local_fs_owner.rs`   |
| Binary text extraction | `extract_and_scan_file()`   | `local_fs_extract.rs` |
| Top-level gzip         | `process_gzip_file()`       | `local_fs_gzip.rs`    |
| Nested compressed stream | `scan_compressed_stream_nested()` | `local_fs_archive_ctx.rs` |
| Tar entry stream       | `scan_tar_stream_nested()`  | `local_fs_tar.rs`     |
| Zip entry              | `process_zip_file()`        | `local_fs_zip.rs`     |

## Configuration and Wiring

### CLI Flag

```bash
scanner scan fs --path=/some/dir --persist-findings
```

The `--persist-findings` flag sets `FsScanConfig.persist_findings = true`,
which causes the orchestrator to wire a `StoreProducer` into the
`ParallelScanConfig`. The default producer is the SQLite writer, which
writes to `findings.db` under the store root.

#### Environment Variables

| Variable             | Purpose                                                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `SCANNER_SECRET_KEY` | Stable secret key for BLAKE3-keyed identity hashes; if unset, an ephemeral key is generated (cross-run dedup disabled) |

### Wiring Path

```text
CLI --persist-findings
  │
  ▼
FsScanConfig { persist_findings: true }
  │
  ▼
scan_fs() / parallel_scan_dir() in scheduler
  │  creates Arc<dyn StoreProducer>
  ▼
ParallelScanConfig { store_producer: Some(Arc<dyn StoreProducer>) }
  │
  ▼
LocalConfig { store_producer: Some(Arc<dyn StoreProducer>) }
  │
  ▼
Per-worker LocalScratch {
    store_producer: Some(Arc<dyn StoreProducer>),
    persist_batch: Vec<FsFindingRecord>,   ◄── reusable buffer
}
```

### Per-Worker Scratch Layout

Each worker carries a `persist_batch: Vec<FsFindingRecord>` buffer that is
reused across scan iterations to avoid per-file allocation. The
`store_producer` reference is `Arc`-cloned so all workers share the same
producer instance.

## Deduplication Changes

The cross-rule dedupe function `apply_cross_rule_dedupe()` includes
`norm_hash` in the dedup key:

**Before**: `(root_hint_start, root_hint_end, span_start, span_end)`
**After**: `(root_hint_start, root_hint_end, span_projection, norm_hash)` where `span_projection` is `(span_start, span_end)` when `dedupe_with_span()` is `true`, or `(0, 0)` otherwise.

Note: `rule_id` is intentionally excluded from the dedup key — the purpose
of cross-rule dedup is to collapse duplicate matches across different rules,
keeping only the highest-confidence winner.

This ensures two findings at the same byte span but with different
normalized secret hashes are preserved (not incorrectly collapsed). This
aligns the FS path with the git-scan path, which already uses `norm_hash`
in its `FindingKey`.

## Output Changes

The orchestrator now reports persistence-related counters in the summary
line:

```
files=N chunks=N bytes=N findings=N errors=N dropped_findings=N persist_emit_failures=N persist_incomplete=false ...
```

The `SummaryEvent.status` field is set to `"partial"` when
`persistence_incomplete` is true, instead of the default `"complete"`.

## Related Documentation

| Document                                                               | Relevance                                                      |
| ---------------------------------------------------------------------- | -------------------------------------------------------------- |
| [persistence-identity.md](../gossip-contracts/persistence-identity.md) | Identity contracts (RuleFingerprint, SecretHash, OccurrenceId) |
| [pipeline-flow.md](../pipeline-flow.md)                                | FS pipeline stages and buffer lifecycle                        |
| [scheduler-engine-abstraction.md](scheduler-engine-abstraction.md)     | FindingWithHashRecord trait, EngineScratch changes             |
| [scheduler-engine-impl.md](scheduler-engine-impl.md)                   | Real engine adapter, drain_findings_with_hashes                |
| [architecture-overview.md](../architecture-overview.md)                | Component diagram and FS scan path                             |
| [data-types.md](../data-types.md)                                      | Class diagrams for store::fs types                             |
