# Scanner-RS → Gossip-RS Consolidation Plan

| Field            | Value                                                                                                                                                     |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Date             | 2026-03-01                                                                                                                                                |
| Status           | Final                                                                                                                                                     |
| Version          | v5.4                                                                                                                                                      |
| Rounds completed | 3 (plan-forge) + 1 (Option A) + 1 (ScanDriver + parity) + 1 (layering + contracts) + 1 (item commit protocol + parity fix) + 1 (Phase III/IV/V alignment) |
| Task             | Consolidate scanner-rs engine + git into gossip-rs workspace                                                                                              |

## Problem Statement

gossip-rs is the distributed version of scanner-rs. Today the two projects are
separate repositories with a thin bridge: `scanner-rs-cli` in gossip-rs calls
into `scanner_rs_lib` as a path dependency, and scanner-rs's
`connector_pipeline` feature optionally depends on `gossip_contracts` /
`gossip_connectors`.

The end goal is to **sunset scratch-scanner-rs** entirely. All detection engine
code, git scanning, rule management, and supporting infrastructure must live
inside the gossip-rs workspace. gossip-rs must then support two execution modes:

1. **CLI mode** — equivalent to today's standalone scanner-rs binary. Identical
   findings and performance. scanner-rs standalone output is the source of truth
   we always match.
2. **Distributed mode** — the same detection engine runs inside gossip-rs's
   coordination-managed scanning infrastructure.

**Both modes use the same execution path.** Performance is a north star —
scanner-rs was purposefully designed to be the fastest secret scanner on the
market. The distributed mode must preserve that performance edge. There is ONE
scanning approach with two entry points, not two approaches.

Parity between these modes is the primary acceptance gate.

## Architecture: Unified Execution Model (Option A)

The scanner-scheduler executor is THE execution engine for all scanning. Both
CLI and distributed modes call `scan_local()` through the same work-stealing
executor. The only differences between modes are:

1. **Where work comes from**: CLI args vs coordinator shard assignments
2. **Where results go**: JSONL stdout vs distributed persistence + checkpoint
3. **Lifecycle management**: none (CLI) vs leases, fencing, checkpoint (distributed)

Everything between "here's what to scan" and "here are the findings" is shared.

```
Work assignment
    CLI: parse args → root path / repo path
    Distributed: coordinator → shard lease → scan range
        │
        ▼
ScanSourceFactory (translates assignment → ScanDriver)
    factory.driver_for_assignment(&assignment) → Box<dyn ScanDriver>
        │
        ▼
ScanDriver::run() ← source-specific execution, shared executor core
    FS driver:  parallel_scan_dir() / scan_local(FileSource)
                Work-stealing, io_uring, CPU affinity
    Git driver: run_git_scan()
                Pack parse, commit walk, tree diff, blob dedup
                Dispatches blob scanning through executor
    S3 driver:  (future) list_objects + range reads
        │
        ├── Executor (scanner-scheduler) — shared work-stealing core
        │   Per-worker: scratch, engine instance, allocation tracking
        │
        └── Detection (scanner-engine)
            vectorscan → regex → transform → validate
        │
        ▼
EventOutput (mode-specific output)
    CLI: JSONL to stdout (path/rule/span — no NormHash in output)
    Distributed: identity chain (NormHash → SecretHash → FindingId)
                 + coordination checkpoint + persistence
```

### Why this model

The executor's performance comes from how its pieces interact: io_uring
completions feeding work-stealing queues, buffers recycled without allocation,
threads pinned to cores. These are not decomposable primitives — the
performance is in the integration. Having distributed mode bypass the executor
through per-item `ReadConnector::open()` would create a performance cliff.

### What this replaces

v4 had a dual-path design:

- CLI mode used `scanner-scheduler` directly (fast path)
- Distributed mode used `gossip-scan-pipeline` page loop + `ReadConnector::open()`
  per item + `DetectionProcessor` (slow path)

v5 eliminates the slow path. The page-driven scan loop is absorbed. The
`DetectionProcessor`, `ReadConnector`, and `EnumerationConnector` traits are
replaced by a consolidated `ScanSourceFactory` + executor model.

## Decisions

### Carried from v4 (unchanged)

1. **scanner-engine depends on gossip-stdx.** The engine uses `ByteRing`,
   `FixedSet128`, `TimingWheel`, and `PushOutcome` from scanner-rs stdx.
   These must be merged into gossip-stdx before engine extraction.

2. **CLI-mode identity: two-tier approach.** CLI mode emits findings as
   JSONL with `rule_name` + `path` + `start`/`end` + `source` +
   `confidence_score` (and optional git fields `commit_id`/`change_kind`).
   **NormHash is NOT in the JSONL output** — it exists only internally in
   `FindingRec` at the engine layer. No `TenantSecretKey` or `TenantId`.
   The full identity chain (`NormHash → SecretHash → FindingId →
OccurrenceId`) is only activated in distributed mode. CLI-vs-CLI parity
   tests compare at the **JSONL byte-identical output** level. CLI-vs-
   distributed parity tests compare at the **finding set** level
   (rule_id + path + span) since output formats differ.

3. **scanner-rs `unified/parity.rs` is NOT the same as
   `gossip-engine/src/parity.rs`.** Different modules solving different
   problems. scanner-rs's version is needed for the parity test suite (Step 6).

4. **NormHash type conversion at the EventSink boundary.** scanner-engine
   uses `type NormHash = [u8; 32]`. gossip-rs uses a newtype with
   `from_digest(bytes: [u8; 32])`. Conversion happens in the distributed
   EventSink (once per finding), not in the scan path. scanner-engine does
   NOT depend on gossip-contracts.

5. **ScanEvent split: CoreEvent + GitEvent.** `ScanEvent` imports git-specific
   types (`CommitIdentityIds`, `OidBytes`). Split into:
   - `CoreEvent` (Finding, Progress, Summary, Diagnostic) — git-free, in
     scanner-scheduler
   - `GitEvent` (CommitMeta, IdentityDictionary) — in scanner-git
   - `EventOutput` trait with `emit_core()` — all crates
   - `GitEventOutput: EventOutput` with `emit_git()` — scanner-git only
   - ~3000 LOC refactoring (Step 2b)

6. **`connector_pipeline.rs` is superseded.** Deleted after consolidation.

### Revised from v4

7. **Unified execution path via ScanDriver (replaces v4 Decision 5).**
   The scanner-scheduler executor is the shared execution core for both CLI
   and distributed modes. There is no `run_scan_loop_with_detection`, no
   `DetectionProcessor` reading through `ReadConnector::open()`, no dual
   connector instances. Each source type provides a **`ScanDriver`** that
   owns its execution model while sharing the underlying executor:
   - **FS driver**: calls `scan_local()` / `parallel_scan_dir()` (existing
     fast path using `FileSource` + io_uring)
   - **Git driver**: calls `run_git_scan()` (existing fast path using custom
     pack parsing + commit walking + executor work dispatch)
   - **Future drivers** (S3/GitHub): get their own `ScanDriver::run()`
     without contaminating the FS or git hot paths
     The `ScanDriver` boundary preserves "one executor engine" while
     acknowledging that different sources have fundamentally different I/O
     and discovery patterns. `FileSource` remains the FS-specific discovery
     abstraction within the FS driver — it is NOT the universal integration
     seam.

### New in v5

8. **gossip-scan-pipeline absorbed.** The page-driven scan loop
   (`run_scan_loop_with_policy_and_page_processor`) is removed. Its
   coordination concerns (lease management, checkpointing, fencing) move to
   `gossip-scanner-runtime` as a thin wrapper around the executor. The
   `gossip-scan-pipeline` crate is deleted from the workspace.

9. **Distributed execution consolidated via ScanDriver + ScanSourceFactory.**
   The distributed execution interface is a `ScanSourceFactory` trait
   (formerly `SourceConnector`, renamed to avoid collision with the Phase
   III "enumerate/open" connector contract) that produces a **`ScanDriver`**
   for a given work assignment. `EnumerationConnector` + `ReadConnector` +
   `ConnectorInstance` remain in `gossip-contracts` for the item-level
   connector API and conformance harness. The factory's role is "translate
   work assignments into source-specific scan drivers." Each driver owns
   its entire execution lifecycle (I/O, discovery, engine invocation) while
   sharing the executor core.

10. **Lease loss → cooperative drop.** On lease expiry in distributed mode:
    - Stop scheduling new work (set executor `done` flag)
    - Stop committing outputs immediately (sink refuses writes without
      current fencing token)
    - **Never checkpoint on/after uncertain ownership**
    - Best-effort abort in-flight work (cooperative — threads may be in
      syscalls)
    - `join()` returns promptly after shutdown signal
      "Immediately" means cooperative, not preemptive. The invariant is:
      no durable side-effects after lease loss is detected.

11. **Progress/checkpoint granularity is source-specific.** Different sources
    checkpoint at different granularities (per-directory for FS, per-commit
    for git, per-batch for S3). The `ScanSourceFactory` defines checkpoint
    semantics, not the framework.

### New in v5.2

12. **ScanDriver/ScanSourceFactory traits live in `gossip-scan-driver`, not
    `gossip-contracts`.** gossip-contracts is a lightweight leaf crate
    (gossip-stdx + blake3 + subtle). gossip-coordination depends on it.
    ScanDriver::run() references scanner-engine + scanner-scheduler types.
    Placing traits in gossip-contracts would drag the entire scanner stack
    into gossip-coordination. The new `gossip-scan-driver` crate isolates
    this dependency. `gossip-contracts` keeps `EnumerationConnector` /
    `ReadConnector` / conformance harness (Phase III item-level API).

13. **Assignment keyspace contract + contiguous committed prefix are
    normative.** Assignment carries `[start_key, end_key)` shard_spec.
    `checkpoint_hint()` returns cursor monotonic in that keyspace.
    Checkpoint = highest contiguous committed prefix, not latest seen.
    Implementation mechanism deferred; semantic rule is fixed.

14. **Distributed sink implements Phase V commit ordering.**
    `FindingsUpsert → DoneLedgerUpsert → ItemCommitted → checkpoint`.
    No checkpoint without `ItemCommitted` ack. Done-ledger must not say
    "scanned" unless findings are already durable.

15. **v5.3 CLI parity scope is JSONL-only.** Text/SARIF/JSON sinks
    explicitly deferred. Parity gates use **canonicalized** finding
    comparison (parse JSONL → canonical sorted set → compare), not raw
    byte comparison of whole-run output. Whole-run JSONL ordering is
    non-deterministic under parallel execution. **Separate encoder golden
    tests** ensure per-event JSONL bytes match scanner-rs (field names,
    escaping, field ordering).

16. **Baseline strategy: golden output corpus.** Canonicalized JSONL
    output frozen from scanner-rs at pinned commit. Golden files checked
    into gossip-rs. Per-event encoder golden tests use byte-identical
    single-line comparison. Survives scratch-scanner-rs deletion.

17. **Future ScanDriver implementations require conformance tests.**
    The Phase III "enumerate/open" connector contract
    (`EnumerationConnector`, `ReadConnector`) and its conformance harness
    (`gossip-contracts/src/connector/conformance.rs`, 1140 lines) remain
    in `gossip-contracts`. These traits are NOT removed — they serve as
    the item-level connector API for remote sources. The new
    `SourceConnector` trait (renamed to **`ScanSourceFactory`** to avoid
    semantic collision) is the _distributed execution_ interface that
    produces `ScanDriver` instances. Remote/future `ScanDriver`
    implementations MUST either (a) use `EnumerationConnector` /
    `ReadConnector` internally and pass the conformance harness, or
    (b) implement equivalent conformance tests (range membership,
    ordering, resume, budget, toxic data logging).

18. **Bounded-cardinality metrics rule.** Forbid labels like `stable_id`,
    `shard_id`, `finding_id`. High-cardinality identifiers go to
    traces/logs, not metrics.

### New in v5.3

19. **Item commit protocol is the driver↔sink contract (normative).**
    Distributed mode requires an item lifecycle protocol so the sink can
    enforce Phase V ordering and produce `ItemCommitted(item_key,
cursor_prefix)` acknowledgements. The protocol:
    - Driver calls `sink.begin_item(item_key, meta)`
    - Driver streams `sink.upsert_findings(batch)` zero or more times
    - Driver calls `sink.finish_item(item_key)` and receives
      `ItemCommitted(item_key, cursor_prefix)` ack
    - Only after ack does `checkpoint_hint()` advance
      Items with zero findings MUST still complete the lifecycle
      (`begin_item` → `finish_item` → `ItemCommitted`). `checkpoint_hint()`
      is derived from committed acks, not from scan completion.
      CLI mode uses a no-op `CommitSink` that immediately acks.

20. **Done-ledger gate is required and batched (normative).**
    `ShardRunner` (or driver) MUST batch-query the done ledger for
    `(tenant, policy_hash, ovid_hash)` before scheduling scan work.
    Skipped items still complete the item lifecycle (producing
    `ItemCommitted`) and advance the committed-prefix frontier.
    Without this, distributed mode will re-scan content bytes on every
    lease churn or crash recovery. Budget semantics apply to the lookup.

21. **Source keyspaces are normatively defined per source type.**
    The keyspace contract (Decision 13) requires concrete definitions:
    - **FS (CLI)**: `ItemKey = normalized relative path bytes` (lexicographic
      order). No done-ledger skip required (no persistence). Split points
      are path prefixes.
    - **FS (distributed)**: same keyspace. Sharding is by path range.
      `VersionId` MUST use at least the Phase III weak tuple
      `(mtime_ns, size, inode)` (or platform equivalent). The connector
      MUST declare this as `Weak` versioning. If stronger guarantees are
      needed (e.g., file generation numbers where available), use them; if
      only weak versioning is available, the done-ledger gate is advisory
      and false negatives on modified-same-size files are a known trade-off.
    - **Git**: `ItemKey = CommitKey` where CommitKey matches the driver's
      ordered enumeration (e.g., topological generation order). Paths
      within a commit are **internal parallelism**, not part of the shard
      keyspace. Cursor = completed commit position. Split points are
      commit boundaries. `checkpoint_hint()` advances only on committed
      commits (atomic at commit boundary). This aligns with the Phase IV
      "one item completes → ItemCommitted → cursor advances" model.
      NOTE: This is a commit-walk-order keyspace, not a blob-OID keyspace.
      Blob-level dedup is handled within the driver, not by the shard
      keyspace. If Phase III blob-OID mapping is needed for a future
      "blob-as-item" mode, it would be a separate driver with its own
      keyspace.
    - **Future sources** (S3, GitHub): define keyspace at driver
      registration time. Must satisfy: ordered, splittable, cursor
      monotonicity.
      Even if initial implementations use coarse checkpoint units
      (per-directory, per-commit), the keyspace that cursor monotonicity
      refers to MUST be defined.

22. **`PolicyHash` must incorporate all detection knobs (normative).**
    The `policy_hash` used in done-ledger lookups MUST hash every
    configuration parameter that can change findings: rule set, decode
    budgets, recursion depth limits, allow/deny path filters, content
    policy settings, and transform chain configuration. If any detection
    knob changes, `policy_hash` changes, and previously-scanned items are
    re-scanned. This matches Phase V's requirement that the ledger gate
    never produces false negatives due to policy drift.

23. **`CommitSink::finish_item()` must not block scan hot paths (normative).**
    Phase V's "ResultCommitter stage" exists to isolate slow I/O behind
    bounded queues and a small pool. The `CommitSink` implementation MUST
    ensure:
    - Scan threads enqueue `ItemScanResult` and return quickly (bounded
      queue, not synchronous DB writes)
    - A separate committer pool performs durability work and emits
      `ItemCommitted` acks asynchronously
    - The frontier tracker advances based on those acks
      This matches Phase IV's "bounded completion queue" model. The semantic
      contract (checkpoint derives from committed acks) is unchanged; the
      operational requirement is that `finish_item()` does not turn scan
      threads into DB client threads. `NoOpCommitSink` (CLI) trivially
      satisfies this.

24. **Driver wrappers live in gossip-side crates, not scanner-\* crates
    (normative).** `scanner-git` exports `run_git_scan()` and types.
    `scanner-scheduler` exports `scan_local()` and types. Neither crate
    implements `ScanDriver` directly. The `GitScanDriver` and
    `FsScanDriver` wrappers that implement `ScanDriver` live in
    `gossip-connectors` (or `gossip-scanner-runtime`). This preserves the
    no-cycle invariant: scanner-\* crates never depend on
    `gossip-scan-driver`.

## Current State of Each Codebase

### scanner-rs (~184K lines, single crate)

| Module              | Lines  | What it does                                                                    |
| ------------------- | ------ | ------------------------------------------------------------------------------- |
| `engine/`           | 30,693 | Vectorscan prefilter → regex validation → transform decode → offline validation |
| `git_scan/`         | 47,524 | Custom git pack parser, commit walker, tree diff, blob dedup                    |
| `scheduler/`        | 37,068 | Work-stealing parallel executor, io_uring, archive expansion                    |
| `archive/`          | 10,999 | Zip, tar, gzip, bzip2 expansion                                                 |
| `unified/`          | 9,402  | CLI argument parsing, event sinks (JSONL/text/JSON/SARIF), orchestrator         |
| `store/`            | 6,928  | SQLite findings persistence, identity derivation, triage                        |
| `stdx/`             | 6,469  | Bitset, ring buffer, timing wheel, fixed_vec, spsc                              |
| `sim*/`             | 13,836 | Simulation harnesses for scanner, git, archive, scheduler                       |
| `rules/`            | 3,763  | YAML rule loading and parsing                                                   |
| `content_policy/`   | 2,985  | Binary detection, text extraction (ipynb, java, pyc, dotenv)                    |
| `api.rs`            | 1,812  | RuleSpec, FindingRec (48B), Finding, Tuning, transforms                         |
| `regex2anchor.rs`   | 1,560  | Regex-to-literal anchor derivation                                              |
| `b64_yara_gate.rs`  | 1,268  | Base64 encoded-space anchor pre-gate                                            |
| `lsm/`              | 1,971  | Set-associative cache for cross-chunk dedup                                     |
| `pool/`             | 711    | Arena-style node pool                                                           |
| `scratch_memory.rs` | 974    | Mmap-backed scratch allocator                                                   |
| `runtime.rs`        | 1,288  | FileTable, BufferPool, chunk reader                                             |
| `pipeline.rs`       | 97     | PipelineConfig, PipelineStats, capacity constants                               |

**Key dependencies**: vectorscan-rs-sys (C FFI), regex, aegis, memchr, flate2,
bzip2, zip, rusqlite, crossbeam-\*, ignore, memmap2. **No libgit2** — git is
fully custom.

**Cross-module coupling (critical for extraction)**:

- `engine/` → `git_scan/perf.rs` (reverse dep: 7 call sites)
- `git_scan/` → `scheduler/` (Executor, WorkerCtx, AllocGuard — 9 files)
- `git_scan/` → `unified/` (EventSink, ScanEvent — 6 files)
- `scheduler/` → `engine/` (engine_impl.rs wraps Engine)
- `scheduler/` → `store/` (StoreProducer, FsFindingBatch — 4 files)
- `scheduler/` → `unified/` (EventSink — 12 files)
- `scheduler/` → `archive/` (6 local*fs*\* files)

### gossip-rs (~78K lines, 10-crate workspace)

| Crate                    | Lines  | What it does                                                 |
| ------------------------ | ------ | ------------------------------------------------------------ |
| `gossip-coordination`    | 35,233 | Shard lifecycle, leases, fencing, splits, run management     |
| `gossip-contracts`       | 17,199 | Connector traits, identity system, persistence boundary      |
| `gossip-connectors`      | 7,211  | Filesystem (openat), git (ls-files), in-memory deterministic |
| `gossip-stdx`            | 5,136  | ByteSlab, InlineVec, RingBuffer, FNV                         |
| `gossip-frontier`        | 4,538  | Key encoding, range arithmetic, shard hint metadata          |
| `gossip-scan-pipeline`   | 3,455  | Scan loop state machine — **absorbed in Step 4**             |
| `gossip-engine`          | 2,937  | **Scaffold only** — page signatures, finding fingerprints    |
| `gossip-scanner-runtime` | 1,811  | Bridges connectors to engine; CLI dispatch                   |
| `gossip-worker`          | 515    | Placeholder binary                                           |
| `scanner-rs-cli`         | 27     | Thin shell calling `scanner_rs_lib::unified::cli`            |

### Scanner-scheduler executor (the core execution engine)

The executor is the performance-critical component that both modes share.
Key APIs:

```rust
// Top-level entry: monolithic scan of a directory
pub fn parallel_scan_dir(root: impl AsRef<Path>, engine: Arc<Engine>,
    config: ParallelScanConfig) -> io::Result<ParallelScanReport>

// Lower-level: pluggable file source + engine
pub fn scan_local<E, S>(engine: Arc<E>, mut source: S, cfg: LocalConfig) -> LocalReport
where E: ScanEngine, S: FileSource

// Pluggable file discovery
pub trait FileSource: Send + 'static {
    fn next_file(&mut self) -> Option<LocalFile>;
}

// Executor: owns worker threads, work-stealing, task dispatch
pub struct Executor<T> { shared: Arc<Shared<T>>, threads: Vec<JoinHandle<...>> }
impl<T: Send + 'static> Executor<T> {
    pub fn new<S, ScratchInit, Runner>(cfg: ExecutorConfig,
        scratch_init: ScratchInit, runner: Runner) -> Self
    pub fn spawn_external_batch(&self, tasks: Vec<T>) -> Result<(), Vec<T>>
    pub fn join(mut self) -> MetricsSnapshot
}

// Per-worker context with work-stealing
pub struct WorkerCtx<T, S> {
    pub worker_id: usize, pub scratch: S, pub rng: XorShift64, ...
}
impl<T, S> WorkerCtx<T, S> {
    pub fn spawn_local(&mut self, task: T)   // local LIFO deque
    pub fn spawn_global(&mut self, task: T)  // global injector
}
```

Extension points that enable the unified model:

- `ScanDriver` trait — source-specific execution (the coordination bridge)
- `FileSource` trait — pluggable item discovery (FS-specific, within scan_local)
- `ScanEngine` trait — pluggable detection engine
- `EventOutput` (dyn) — pluggable finding/event output
- `StoreProducer` (dyn) — pluggable persistence
- `ExecutorHandle` — external spawn + shutdown signal
- `worker_step()` — simulation/test harness seam

## Proposed Crate Structure

### New crates (4)

| Crate                | Source                                                                                                                                                     | ~Lines | Purpose                                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `scanner-engine`     | `engine/` + `api.rs` + `regex2anchor.rs` + `b64_yara_gate.rs` + `content_policy/` + `rules/` + `lsm/` + `pool/` + `scratch_memory.rs` + `git_scan/perf.rs` | ~43K   | Core detection: vectorscan prefilter, regex, transforms, rules, content policy                                                               |
| `scanner-scheduler`  | `scheduler/` (subset) + `archive/` + `pipeline.rs` + `runtime.rs` + `alloc.rs` + `affinity.rs`                                                             | ~49K   | Parallel executor: work-stealing, io_uring, archive expansion, chunking, CPU affinity                                                        |
| `scanner-git`        | `git_scan/` (minus perf.rs)                                                                                                                                | ~47K   | Custom git: pack parser, commit walker, tree diff, blob dedup                                                                                |
| `gossip-scan-driver` | New (thin trait crate)                                                                                                                                     | ~800   | `ScanDriver` + `ScanSourceFactory` + `CommitSink` traits, `Assignment`, `ScanExecutionConfig`, `ScanReport`, `CursorUpdate`, `ItemCommitted` |

### Existing crates that change

| Crate                    | What changes                                                                                                                                                                                                                                                                                                          |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gossip-contracts`       | `EnumerationConnector` + `ReadConnector` + `ConnectorInstance` + conformance harness **remain** (Phase III item-level API). Keeps identity system, persistence boundary, connector value types (`ItemKey`, `Cursor`, `Budgets`). Does NOT gain `ScanDriver`/`ScanSourceFactory` — those live in `gossip-scan-driver`. |
| `gossip-connectors`      | All three implementations gain `ScanSourceFactory` impl (new dep on `gossip-scan-driver`). Existing `EnumerationConnector`/`ReadConnector` impls remain for conformance and item-level use.                                                                                                                           |
| `gossip-scan-pipeline`   | **Removed from workspace** — coordination logic absorbed into `gossip-scanner-runtime`                                                                                                                                                                                                                                |
| `gossip-engine`          | Simplified — `ScannerCore` stays (page signatures); no `DetectionProcessor`. Identity conversion utils only.                                                                                                                                                                                                          |
| `gossip-scanner-runtime` | Major expansion — gains coordination wrapper, CLI + distributed entry points, JSONL + coordination EventSinks                                                                                                                                                                                                         |
| `scanner-rs-cli`         | Stops depending on `scanner_rs_lib`. Thin shell calling `gossip-scanner-runtime`                                                                                                                                                                                                                                      |

### ScanDriver + ScanSourceFactory trait design (distributed execution interface)

The distributed execution boundary uses two traits: `ScanDriver` (source-specific
execution) and `ScanSourceFactory` (assignment → driver factory). These supplement
(not replace) the Phase III `EnumerationConnector`/`ReadConnector` item-level API.

```rust
/// A source-specific scan execution backend. Each source type (FS, git, S3)
/// implements this to own its execution lifecycle while sharing the
/// underlying scanner-scheduler executor and scanner-engine detection.
///
/// Why not FileSource for everything: git scanning uses run_git_scan() which
/// manages commit walking, tree diffing, pack parsing — fundamentally
/// different from FS's "yield LocalFile items" model. Forcing git through
/// FileSource would either lose performance or require a fake adapter.
pub trait ScanDriver: Send {
    /// Execute the scan. The driver owns I/O, discovery, and engine
    /// invocation. Cancellation is cooperative via the token.
    ///
    /// `commit` receives item lifecycle signals (begin/upsert/finish).
    /// CLI mode passes `NoOpCommitSink` (immediate ack).
    /// Distributed mode passes a durable sink enforcing Phase V ordering.
    fn run(
        &mut self,
        engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn EventOutput,
        commit: &dyn CommitSink,
        cancel: &CancellationToken,
    ) -> anyhow::Result<ScanReport>;

    /// Optional checkpoint hint for the coordination wrapper.
    /// Returns the most recent contiguous progress point that is safe
    /// to checkpoint. None if no progress since last call.
    ///
    /// MUST return a cursor monotonic in the shard's ordered keyspace
    /// (same keyspace used for shard membership and splitting).
    /// Checkpoint cursor = highest contiguous committed prefix in key
    /// order, not "latest seen."
    fn checkpoint_hint(&self) -> Option<CursorUpdate>;
}

/// Translates work assignments into source-specific scan drivers.
/// Named ScanSourceFactory (not SourceConnector) to avoid collision with
/// the Phase III EnumerationConnector/ReadConnector "connector" concept.
pub trait ScanSourceFactory: Send {
    /// Create a ScanDriver for the given assignment.
    /// CLI mode: assignment covers everything (from CLI args).
    /// Distributed mode: assignment is a shard from the coordinator.
    fn driver_for_assignment(
        &self,
        assignment: &Assignment,
    ) -> anyhow::Result<Box<dyn ScanDriver>>;

    /// Source-specific capabilities and configuration hints.
    fn capabilities(&self) -> SourceCapabilities;
}
```

**FS driver** internally uses `scan_local()` with `FileSource` — the existing
fast path. **Git driver** internally uses `run_git_scan()` — the existing fast
path. Neither contaminates the other. Future S3/GitHub drivers implement
`ScanDriver::run()` with their own I/O model.

`FileSource` remains the FS-specific item discovery abstraction within
`scan_local()`. It is NOT promoted to a universal integration seam.

**Driver wrapper placement (normative):** `scanner-git` exports
`run_git_scan()` and supporting types but does NOT implement `ScanDriver`
directly (that would require depending on `gossip-scan-driver`, violating
the no-cycle invariant). The `GitScanDriver` wrapper that implements
`ScanDriver` lives in `gossip-connectors` (or `gossip-scanner-runtime`),
calling `scanner_git::run_git_scan()` internally. Same pattern applies to
`FsScanDriver` wrapping `scanner_scheduler::scan_local()`.

### Trait placement: gossip-scan-driver crate

**`ScanDriver` and `ScanSourceFactory` MUST NOT live in `gossip-contracts`.**

`gossip-contracts` is a lightweight leaf crate (depends only on `gossip-stdx` +
`blake3` + `subtle`). `gossip-coordination` depends on `gossip-contracts`. Since
`ScanDriver::run()` takes `Arc<scanner_engine::Engine>` and `&dyn EventOutput`
from `scanner-scheduler`, placing these traits in `gossip-contracts` would force:

```
gossip-contracts → scanner-engine (vectorscan C FFI!) + scanner-scheduler
gossip-coordination → gossip-contracts → entire scanner stack
```

This blows up compile times and creates a layering violation.

**Decision**: A new thin crate `crates/gossip-scan-driver/` holds:

- `ScanDriver`, `ScanSourceFactory` traits
- `CommitSink` trait (item lifecycle protocol, Decision 19)
- `Assignment`, `ScanExecutionConfig`, `ScanReport`, `CursorUpdate` types
- Depends on `scanner-engine` + `scanner-scheduler` (for type references)
- Does NOT contain identity/persistence/coordination types

`gossip-contracts` stays lightweight and **keeps** `EnumerationConnector` /
`ReadConnector` / conformance harness (Phase III item-level API).
`gossip-coordination` depends on `gossip-contracts` but NOT on
`gossip-scan-driver`. The scanner stack is only pulled in by crates that
actually need it (`gossip-connectors`, `gossip-scanner-runtime`).

### Dependency invariant (normative)

**No dependency cycles in the workspace.** Specifically:

- `gossip-scan-driver` depends on `scanner-engine` + `scanner-scheduler`
- `scanner-engine`, `scanner-scheduler`, `scanner-git` do NOT depend on
  `gossip-scan-driver`
- `gossip-contracts` does NOT depend on any `scanner-*` crate
- `gossip-coordination` does NOT transitively depend on any `scanner-*` crate

### Assignment keyspace contract (normative)

**Assignment is keyed in a connector-defined ordered keyspace.**
Each `Assignment` MUST include:

- `job_id`, `policy_hash`, `connector_kind`, `connector_instance_id`
- `enumeration_view` (snapshot/continuous) as part of job config
- `shard_spec` as a key-range domain `[start_key, end_key)` (or
  prefix→range projection)
- `cursor` representing "next key to enumerate/scan" (Completed semantics
  by default)

**`ScanDriver::checkpoint_hint()` MUST return a cursor that is monotonic in
the same keyspace used for shard membership and splitting.**

**Checkpoint cursor equals "highest contiguous committed prefix" in key
order, not "latest seen."** The executor processes items out-of-order via
work-stealing. The safe checkpoint is the contiguous prefix of committed
items, not the maximum key seen. This is the same semantic as Phase IV
"offset of next message to consume."

Implementation mechanism (frontier tracker vs atomic checkpoint units)
remains deferred, but the semantic rule is a hard contract.

### EventOutput as unified output sink

Both CLI and distributed modes implement the same `EventOutput` +
`GitEventOutput` traits:

```rust
// CLI mode: JSONL EventSink → stdout
//   Emits: path, rule_name, start, end, source, confidence_score
//   (plus commit_id/change_kind for git). NO NormHash in JSONL output.
//
// Distributed mode: Coordination EventSink
//   Internal: NormHash::from_digest(raw_bytes) → SecretHash → FindingId
//   Output: persistence + checkpoint
```

NormHash conversion happens in the distributed EventSink implementation,
not in the scan path. scanner-engine never depends on gossip-contracts.
The CLI JSONL format does not include NormHash — this matches the current
scanner-rs output schema exactly.

### Crates that do NOT move

| scanner-rs code           | Why it stays / gets dropped                              |
| ------------------------- | -------------------------------------------------------- |
| `unified/cli.rs`          | CLI parsing → ported to `gossip-scanner-runtime`         |
| `unified/orchestrator.rs` | CLI orchestration → replaced by `gossip-scanner-runtime` |
| `unified/text_sink.rs`    | Output format → added later as output adapter            |
| `unified/sarif_sink.rs`   | Output format → added later                              |
| `unified/parity.rs`       | Finding comparison → ported in Step 6                    |
| `store/`                  | SQLite persistence → gossip-rs has own persistence       |
| `sim*/`                   | Simulation harnesses → gossip-rs has own sim infra       |
| `tools/`                  | Python CI tooling → gossip-rs builds own CI              |
| `src/bin/`                | Benchmark binaries → gossip-rs has own bench infra       |

### stdx overlap resolution

| scanner-rs stdx              | gossip-rs stdx equivalent | Action                 |
| ---------------------------- | ------------------------- | ---------------------- |
| `byte_ring.rs` (ByteRing)    | —                         | Move to gossip-stdx    |
| `timing_wheel.rs`            | —                         | Move to gossip-stdx    |
| `fixed_set.rs` (FixedSet128) | —                         | Move to gossip-stdx    |
| `atomic_bitset.rs`           | —                         | Move to gossip-stdx    |
| `spsc.rs`                    | —                         | Move to gossip-stdx    |
| `fastrange.rs`               | —                         | Move to gossip-stdx    |
| `ring_buffer.rs`             | `RingBuffer<T, N>`        | Keep gossip-rs version |
| `fixed_vec.rs` (FixedVec)    | `InlineVec<T, N>`         | Keep gossip-rs version |

## Steps

### Step 0: Merge stdx types into gossip-stdx

**Task**: `gossip-rs-8r9.17`

- **What**: Merge scanner-rs `stdx/` types into `gossip-stdx`. MUST happen
  first — scanner-engine depends on these types.
- **Files**: `crates/gossip-stdx/`
  - Move in: `ByteRing`, `TimingWheel`, `FixedSet128`, `AtomicBitSet`,
    `AtomicSeenSets`, `DynamicBitSet`, `spsc`, `fastrange`, `perf_stats`
  - Keep gossip-rs `RingBuffer` and `InlineVec`, document adapter mappings
- **Acceptance criteria**:
  - gossip-stdx exports all types needed by scanner-engine
  - No duplicate data structures
  - New types pass Miri strict-provenance checks

### Step 1: Extract scanner-engine crate

**Task**: `gossip-rs-8r9.18` · Blocked by: Step 0

- **What**: Extract detection engine into standalone `crates/scanner-engine/`.
- **Files**:
  - Move: `engine/` (all files), `api.rs`, `regex2anchor.rs`,
    `b64_yara_gate.rs`, `content_policy/`, `rules/`, `lsm/`, `pool/`,
    `scratch_memory.rs`
  - Move: `git_scan/perf.rs` → `perf_counters.rs` (severs engine→git reverse dep)
  - Integration-level engine tests → workspace integration test crate
- **Acceptance criteria**:
  - `cargo check -p scanner-engine` succeeds
  - No dependency on scheduler, unified, git_scan, or store
  - `Engine::new()` + `ScanScratch::new()` + `scan_chunk()` end-to-end

### Step 2a: Extract scanner-scheduler crate

**Task**: `gossip-rs-8r9.19` · Blocked by: Step 1

- **What**: Extract parallel executor + archive into `crates/scanner-scheduler/`.
  **This is the execution engine for both CLI and distributed modes.**
- **Files**: See task description for complete 40+ file list. Key additions:
  - `alloc.rs` (668 lines), `affinity.rs` (~600 lines)
  - `StoreProducer` + companion types from `store/fs.rs`
  - Do NOT move: `connector_pipeline.rs` (superseded)
- **Option A requirements** (executor as shared core):
  - `ExecutorHandle::shutdown()` — external signal for lease-loss abandonment
  - Progress callback mechanism — streaming progress for coordination checkpointing
  - `FileSource` remains the FS-specific discovery seam within `scan_local()` —
    it is NOT the universal integration seam (git uses `run_git_scan()` directly)
  - The universal integration seam is `ScanDriver::run()` (defined in Step 4)
  - I/O strategy seam — `process_file()` must not foreclose source-specific I/O
- **Acceptance criteria**:
  - `parallel_scan_dir()` works end-to-end with scanner-engine
  - `Executor`, `WorkerCtx`, `AllocGuard` public for scanner-git
  - `EventOutput` trait is git-free
  - Shutdown signal and progress callback exist

### Step 2b: Split ScanEvent into CoreEvent + GitEvent (~3000 LOC)

**Task**: `gossip-rs-8r9.20` · Blocked by: Step 2a

- **What**: Refactor `events.rs` (1065 lines) and `json_write.rs` (2039 lines)
  to split git-specific event variants from core events.
- **EventOutput is the unified output sink**: Both CLI JSONL sink and
  distributed coordination sink implement `EventOutput` + `GitEventOutput`.
  NormHash conversion happens in the coordination EventSink, not in the scan
  path.
- **Files**: See task description for encoder split details
- **Acceptance criteria**:
  - `CoreEvent` compiles with no git imports
  - JSONL output byte-identical to pre-split output
  - Golden-file test validates encoder correctness

### Step 3: Extract scanner-git crate (~47K LOC, 83 files)

**Task**: `gossip-rs-8r9.21` · Blocked by: Steps 1, 2a, 2b

- **What**: Move custom git implementation into `crates/scanner-git/`.
- **Option A integration**: scanner-git exports `run_git_scan()` but does
  NOT implement `ScanDriver` directly (no dep on gossip-scan-driver). The
  `GitScanDriver` wrapper lives in `gossip-connectors`, calling
  `run_git_scan()` internally. This is NOT a `FileSource` — git scanning
  has its own top-level runner that manages commit walking, tree diffing,
  pack parsing, and blob dedup, dispatching work through the executor
  internally. In distributed mode, the `ScanSourceFactory` for git creates
  a `GitScanDriver` scoped to the shard's commit range.
- **Files**: All 83 git_scan files minus perf.rs. Import rewrites across all.
- **Acceptance criteria**:
  - Full git pipeline works end-to-end
  - Depends only on scanner-engine and scanner-scheduler
  - `GitEventOutput` trait defined locally

### Step 4: Unified execution model

**Task**: `gossip-rs-8r9.25` · Blocked by: Steps 1, 2a

**This is the core integration step.** Consolidates connector traits, absorbs
gossip-scan-pipeline, and wires the executor as the single execution path.

- **Create `gossip-scan-driver` crate**: New thin trait crate holding
  `ScanDriver`, `ScanSourceFactory`, `CommitSink`, `Assignment`,
  `ScanExecutionConfig`, `ScanReport`, `CursorUpdate`, `ItemCommitted`.
  Depends on `scanner-engine` + `scanner-scheduler`. Keeps
  `gossip-contracts` and `gossip-coordination` free of scanner deps.
  **No cycles**: scanner-\* crates do NOT depend on gossip-scan-driver.
- **Add distributed execution traits**: `ScanSourceFactory` trait (not
  `SourceConnector` — renamed to avoid Phase III collision) produces a
  `ScanDriver` for a given work assignment. Phase III
  `EnumerationConnector`/`ReadConnector` + conformance harness remain in
  `gossip-contracts` for item-level use.
- **Define ScanDriver trait**: Source-specific execution boundary. FS driver
  wraps `scan_local()`, git driver wraps `run_git_scan()`. Each owns its
  execution lifecycle while sharing the executor core.
- **Define CommitSink trait (Decision 19)**: Item lifecycle protocol for
  Phase V ordering. `begin_item` → `upsert_findings` (0+) → `finish_item`
  → `ItemCommitted` ack. CLI uses no-op sink; distributed uses real sink
  with durability enforcement.
- **Assignment keyspace contract**: Each `Assignment` carries `shard_spec`
  as `[start_key, end_key)` in a connector-defined ordered keyspace.
  `checkpoint_hint()` returns a cursor monotonic in that keyspace.
  Checkpoint cursor = highest contiguous committed prefix, not latest seen.
- **Absorb gossip-scan-pipeline**: Page loop removed. Coordination concerns
  (lease, checkpoint, fencing) move to `gossip-scanner-runtime` as a
  `ShardRunner` wrapper. The `gossip-scan-pipeline` crate is deleted.
- **Wire ScanDriver**: Both CLI and distributed modes create a `ScanDriver`
  and call `driver.run()`. Distributed mode wraps with coordination lifecycle:
  ```
  acquire_lease → connector.driver_for_assignment()
               → driver.run(engine, cfg, sink, cancel)
               → checkpoint/complete via driver.checkpoint_hint()
  on lease_loss → cancel token → cooperative shutdown → abandon in-flight
  ```
- **Preserve scan loop invariants via ShardRunner**: SL1-SL8 re-expressed:
  - SL1: validate assignment/spec + cursor monotonicity before checkpoint
  - SL5: ShardRunner::run() returns terminal enum (Completed/Parked/LeaseLost/Error)
  - SL7: renew lease only after successful checkpoint
  - SL8: enforce Phase V commit ordering (see below)
- **Phase V commit ordering via CommitSink (normative, Decision 19)**:
  Distributed `CommitSink` MUST implement:
  1. `begin_item(item_key, meta)` — register item for processing
  2. `upsert_findings(batch)` — write findings (idempotent), 0+ times
  3. `finish_item(item_key)` → `DoneLedgerUpsert` → `ItemCommitted` ack
     `checkpoint_hint()` derived from `ItemCommitted` acks only. Items with
     zero findings MUST still complete lifecycle. CLI mode: no-op `CommitSink`
     that immediately acks.
- **Done-ledger gate (normative, Decision 20)**: `ShardRunner` MUST
  batch-query the done ledger for `(tenant, policy_hash, ovid_hash)` before
  scheduling scan work. Skipped items still produce `ItemCommitted` and
  advance the committed-prefix frontier. Budget semantics apply.
- **Source keyspace definitions (normative, Decision 21)**: FS uses
  normalized relative path bytes (lex order), git uses `(commit_oid, path)`
  tuples. See Decision 21 for full table.
- **Future driver conformance (Decision 17)**: Remote/future ScanDriver
  implementations MUST either (a) use `EnumerationConnector`/`ReadConnector`
  internally and pass the Phase III conformance harness
  (`gossip-contracts/src/connector/conformance.rs`), or (b) implement
  equivalent conformance tests (range membership, ordering, resume, budget,
  toxic data logging).
- **Files**: gossip-scan-driver (NEW crate), gossip-contracts (Phase III
  traits REMAIN: EnumerationConnector/ReadConnector/conformance harness),
  gossip-connectors (rewrite all 3 — add ScanSourceFactory impls),
  gossip-scan-pipeline (remove crate), gossip-scanner-runtime (add
  ShardRunner), gossip-engine (simplify), scanner-scheduler (executor hooks),
  workspace Cargo.toml
- **Acceptance criteria**:
  - `gossip-scan-driver` crate created with `ScanDriver` + `ScanSourceFactory`
    - `CommitSink`
  - **No dependency cycles**: scanner-\* do NOT depend on gossip-scan-driver
  - `gossip-contracts` has NO dependency on scanner-engine or scanner-scheduler
  - `gossip-contracts` KEEPS `EnumerationConnector`/`ReadConnector`/conformance
  - `gossip-coordination` has NO transitive dep on scanner-engine or scheduler
  - `ScanSourceFactory` + `ScanDriver` defined as distributed execution interface
  - gossip-scan-pipeline removed
  - `ScanDriver::run()` callable from both CLI and distributed entry points
  - FS driver uses `scan_local()`, git driver uses `run_git_scan()`
  - Assignment carries `[start_key, end_key)` keyspace domain
  - `checkpoint_hint()` returns cursor monotonic in shard keyspace
  - Checkpoint cursor = contiguous committed prefix (not latest seen)
  - `CommitSink` trait implements item lifecycle (Decision 19)
  - Distributed `CommitSink` implements Phase V ordering
  - `ShardRunner` implements batched done-ledger gate (Decision 20)
  - Skipped items produce `ItemCommitted` and advance frontier
  - FS keyspace = normalized relative path bytes (lex); FS distributed
    VersionId = (mtime_ns, size, inode) weak tuple (Decision 21)
  - Git keyspace = CommitKey in driver enumeration order; paths are
    internal parallelism, not shard keyspace (Decision 21)
  - Executor shutdown works for lease-loss (cooperative)
  - Sink refuses writes without current fencing token after lease loss
  - Never checkpoints on/after uncertain ownership
  - ShardRunner returns terminal enum (Completed/Parked/LeaseLost/Error)
  - Progress callback works for checkpointing
  - Future drivers reuse Stage 3 conformance or implement equivalent
  - `CommitSink::finish_item()` is non-blocking on scan threads (Decision 23)
  - Driver wrappers (`GitScanDriver`, `FsScanDriver`) live in gossip-side crates (Decision 24)
  - `PolicyHash` incorporates all detection knobs (Decision 22)
  - No performance regression vs standalone scanner-scheduler

### Step 5: Wire CLI and distributed entry points

**Task**: `gossip-rs-8r9.26` · Blocked by: Steps 4, 2b, 3

- **What**: Wire both entry points through the unified model. Remove
  `scanner_rs_lib` path dependency.
- **CLI entry point**:
  ```rust
  // scanner-rs-cli → gossip-scanner-runtime::cli
  let factory = scan_source_factory_for_cli(&args);  // FS or Git
  let mut driver = factory.driver_for_assignment(&assignment)?;
  let event_sink = JsonlEventSink::new(io::stdout());
  let commit_sink = NoOpCommitSink;  // CLI: immediate ack
  driver.run(engine, &cfg, &event_sink, &commit_sink, &cancel)?
  ```
- **Distributed entry point**:
  ```rust
  // gossip-worker → gossip-scanner-runtime::distributed
  let lease = coordinator.acquire_shard();
  let factory = scan_source_factory_from_spec(lease.spec());
  let mut driver = factory.driver_for_assignment(&lease.assignment())?;
  let event_sink = CoordinationEventSink::new(coordinator, &lease);
  let commit_sink = DurableCommitSink::new(coordinator, &lease);
  // done-ledger gate: batch query before scan
  driver.run(engine, &cfg, &event_sink, &commit_sink, &cancel)?
  // checkpoint via driver.checkpoint_hint() (derived from ItemCommitted acks)
  ```
- **Both create a ScanDriver and call `driver.run()`.** Same executor core,
  same engine. FS driver internally uses `scan_local()`, git driver uses
  `run_git_scan()`. `CommitSink` differs: CLI uses no-op, distributed uses
  durable sink with Phase V ordering.
- **Port JSONL encoder**: From `unified/events.rs` + `json_write.rs` into
  `gossip-scanner-runtime`. Implements `EventOutput` + `GitEventOutput`.
- **v5.3 parity scope: JSONL only.** Text sink, JSON sink, and SARIF sink
  are explicitly deferred to follow-up tasks. JSONL is the first hard gate.
- **Files**: gossip-scanner-runtime (major expansion), scanner-rs-cli (rewrite)
- **Acceptance criteria**:
  - Canonical JSONL finding parity vs golden corpus (parse → canonicalize
    → sorted set compare). Per-event encoder golden tests for byte-identical
    single-line output. (Decision 21/15)
  - CLI uses `NoOpCommitSink`; distributed uses `DurableCommitSink`
  - No dependency on `../scratch-scanner-rs`
  - `cargo build -p scanner-rs-cli` works without scanner-rs checkout
  - Both FS and git work through both entry points via ScanDriver
  - v5.3 scope: JSONL output only; text/SARIF/JSON sinks explicitly deferred

### Step 6: Parity test suite and CI gates

**Task**: `gossip-rs-8r9.24` · Blocked by: Step 5

- **What**: Prove finding parity and performance equivalence.
- **v5.3 parity scope: JSONL only.** Text/SARIF/JSON sinks are deferred.
  JSONL is the first hard gate. Other formats are follow-up tasks.
- **Baseline strategy**: Canonicalized JSONL output frozen from scanner-rs
  at a pinned commit for a reference corpus. Golden files checked into
  gossip-rs under `tests/parity/golden/`. Once scratch-scanner-rs is
  deleted, parity tests compare against these golden files.
- **CLI-vs-CLI parity**: New scanner-rs-cli vs golden JSONL output.
  Comparison uses **canonical finding equivalence** (parse JSONL →
  `CanonicalFinding` → sorted set → compare), matching scanner-rs's own
  `unified/parity.rs` approach. Whole-run JSONL byte ordering is
  non-deterministic under parallel execution. **Separate encoder golden
  tests** verify per-event JSONL bytes are byte-identical (field names,
  escaping, field ordering). (Decision 15/21)
- **CLI-vs-distributed parity**: Uses InMemoryCoordinator. Since both modes
  use the same `ScanDriver::run()`, this primarily verifies the coordination
  wrapper doesn't affect findings. Comparison is at the **finding set** level
  (rule_id + path + span) since output formats differ between CLI and
  distributed modes.
- **Lease-loss safety**: Verify checkpoint stops after lease expiry, sink
  rejects writes without fencing token, executor cancels cooperatively.
- **Phase V commit ordering property test**: If done ledger says scanned
  for `(tenant, policy_hash, ovid_hash)`, then findings exist (in simulated
  stores). Validates the `FindingsUpsert → DoneLedgerUpsert → ItemCommitted
→ checkpoint` ordering.
- **No secrets in telemetry**: Every public error/loggable type tested to
  ensure no raw input bytes or decoded transform payload appears.
- **Multi-tenant isolation**: Two tenants scanning identical content must
  produce different FindingId/SecretHash (tenant-keyed); cross-tenant
  queries must never return the other tenant's findings.
- **Bounded-cardinality metrics rule**: Forbid metric labels like
  `stable_id`, `shard_id`, `finding_id`. High-cardinality identifiers go
  to traces/logs (hashed), not metrics.
- **Done-ledger gate skip test (Decision 20)**: If done ledger already
  contains `(tenant, policy, ovid_hash)`, driver must NOT read content
  bytes (use a fake reader that panics if called). Cursor must still
  advance correctly via committed-prefix logic via `ItemCommitted`.
- **Contiguous prefix correctness under out-of-order completion**: DST:
  schedule items 0..N, commit in adversarial order, verify cursor only
  advances on contiguous prefix. This is Phase IV's window/ring model.
- **Keyspace membership + split correctness** for FS/Git (Decision 21):
  For any item emitted by driver in shard range,
  `start_key <= item_key < end_key`. After split, children ranges are
  disjoint and cover the parent. Cursor monotonicity within each child.
- **Throughput**: ≤2% median regression, ≤5% per-case
- **Port**: `unified/parity.rs` (JSONL canonicalization + comparison)
- **Fuzz targets**: Port from scanner-rs, run nightly
- **Acceptance criteria**:
  - Canonical JSONL finding parity on reference corpus (parsed → sorted
    set comparison, NOT raw byte comparison of whole-run output)
  - Per-event encoder golden tests (byte-identical single-line)
  - Parity scope explicitly JSONL-only for v5.3
  - Baseline: canonicalized golden JSONL output from pinned scanner-rs commit
  - Phase V property test: done ledger scanned implies findings exist
  - Done-ledger gate skip test: skipped items don't read content bytes
  - Contiguous prefix test: out-of-order completion, cursor only advances
    on contiguous prefix
  - Keyspace membership test: items in range, split correctness
  - Bounded-cardinality metrics: no unbounded ID labels
  - Throughput within threshold
  - Fuzz targets ported
  - CI runs on every push/PR

## Dependency Graph After Consolidation

**Invariant: no dependency cycles.** `gossip-scan-driver` depends on
`scanner-engine` + `scanner-scheduler`. Scanner-_ crates do NOT depend on
`gossip-scan-driver`. `gossip-contracts` has NO scanner-_ deps.

```
gossip-stdx                   (ByteSlab, InlineVec, RingBuffer, FNV,
    │                          ByteRing, TimingWheel, FixedSet128,
    │                          AtomicBitSet, spsc, fastrange)
    │
    ├── scanner-engine        (detection: vectorscan, regex, transforms,
    │       │                  rules, content_policy, perf_counters)
    │       │
    │       ├── scanner-scheduler  (THE execution engine: work-stealing,
    │       │       │               io_uring, archive, chunking, CPU
    │       │       │               affinity, CoreEvent, EventOutput)
    │       │       │
    │       │       └── scanner-git (pack parser, commit walker,
    │       │                        tree diff, blob dedup,
    │       │                        GitEvent, GitEventOutput)
    │       │
    │       └── gossip-engine (ScannerCore for page signatures,
    │                          identity conversion utils)
    │
    ├── gossip-scan-driver    (ScanDriver, ScanSourceFactory, CommitSink,
    │                          Assignment, ScanReport, CursorUpdate,
    │                          ItemCommitted — thin trait crate.
    │                          Deps: scanner-engine + scanner-scheduler)
    │
    ├── gossip-contracts      (identity system, NormHash newtype,
    │       │                  persistence boundary, connector value
    │       │                  types: ItemKey, Cursor, Budgets.
    │       │                  EnumerationConnector, ReadConnector,
    │       │                  conformance harness — Phase III API.
    │       │                  NO scanner deps — stays lightweight)
    │       │
    │       └── gossip-coordination (shard lifecycle, leases, splits.
    │                                NO scanner-engine/scheduler deps)
    │
    ├── gossip-connectors     (FS, git, in-memory ScanSourceFactory impls.
    │                          Deps: gossip-scan-driver + gossip-contracts)
    │
    ├── gossip-frontier       (key encoding, range algebra)
    │
    ├── gossip-scanner-runtime (unified orchestration:
    │       │                   CLI entry point + distributed entry point,
    │       │                   ShardRunner (lease, checkpoint, Phase V,
    │       │                   done-ledger gate),
    │       │                   JSONL + coordination EventSinks,
    │       │                   CommitSink implementations.
    │       │                   Deps: gossip-scan-driver + gossip-contracts
    │       │                         + gossip-coordination + scanner-*)
    │       │
    │       ├── scanner-rs-cli (thin CLI binary)
    │       └── gossip-worker  (distributed worker binary)
    │
    [gossip-scan-pipeline]     ← REMOVED (absorbed into runtime)
```

## Phasing

| Phase | Step                  | Task      | What you can validate after                                            | Depends on        |
| ----- | --------------------- | --------- | ---------------------------------------------------------------------- | ----------------- |
| 0     | stdx merge            | `.20`     | gossip-stdx exports all types                                          | —                 |
| 1     | Engine extraction     | `.21`     | scanner-engine compiles standalone                                     | Phase 0           |
| 2a    | Scheduler extraction  | `.22`     | Executor + archive work with engine                                    | Phase 1           |
| 2b    | Event split           | `.23`     | CoreEvent/GitEvent split, EventOutput git-free                         | Phase 2a          |
| 3     | Git extraction        | `.24`     | Full git pipeline end-to-end                                           | Phases 1+2a+2b    |
| **4** | **Unified execution** | **`.17`** | **ScanSourceFactory + CommitSink, pipeline absorbed, executor wired**  | **Phases 1+2a**   |
| **5** | **Entry points**      | **`.18`** | **CLI + distributed both work through ScanDriver::run() + CommitSink** | **Phases 4+2b+3** |
| 6     | Parity & CI           | `.19`     | Canonical finding parity proven, CI gates live                         | Phase 5           |

**Critical path**: 0 → 1 → 2a → 4 → 5 → 6

**Parallel with (2a → 4)**: Steps 2b → 3 can proceed concurrently with Steps 4.

Note: Step 4 depends on both Step 1 (scanner-engine) and Step 2a
(scanner-scheduler). It can NOT proceed in parallel with Step 2a (unlike v4
where Step 4 only needed Step 1). This is the trade-off of the unified model —
we need the executor before we can wire the integration.

## Risk Areas

1. **Vectorscan FFI**: scanner-engine depends on vectorscan-rs-sys (C library).
   Build complexity (C compiler, cmake, platform-specific).

2. **Feature flag explosion**: scanner-rs has ~20 feature flags. Careful
   unification needed.

3. **Test infrastructure**: ~65K lines of test code need porting. Phased.

4. **Git module coupling**: 47K lines with dependencies on both engine and
   scheduler. Import rewriting across 83 files.

5. **Performance parity**: The unified execution model preserves scanner-rs
   performance by design (same executor, same I/O). The risk is in the
   coordination wrapper overhead (lease checks, checkpoint callbacks). Must
   verify zero overhead on the hot scan path.

6. **ScanEvent refactoring scope**: ~3000 LOC encoder split (Step 2b) touches
   the JSONL hot path. Must verify byte-identical output.

7. **gossip-scan-pipeline absorption**: The page loop has 8 formal invariants
   (SL1-SL8). These must be preserved in the new coordination wrapper. Risk
   of losing safety guarantees during the migration.

8. **ScanDriver + ScanSourceFactory trait design**: Affects all existing connector
   implementations and their tests. Two new abstractions (`ScanDriver` +
   `ScanSourceFactory`) — may need iteration to get right. The ScanDriver
   boundary is validated by the fact that FS and git already have separate
   top-level entry points (`scan_local` vs `run_git_scan`).

9. **Executor lifecycle**: Adding shutdown() and progress callbacks to the
   executor is new code in a performance-critical component. Must not add
   overhead to the steady-state hot path.

10. **Checkpoint ordering under parallel execution**: Work-stealing processes
    items out-of-order. Naive "checkpoint after every item" would produce
    gaps. Requires frontier tracking or atomic checkpoint units.

## Open Questions

1. **SQLite store**: scanner-rs has SQLite persistence. gossip-rs designs for
   etcd/ScyllaDB/Postgres. Keep SQLite as CLI-only option?

2. **Simulation harness**: scanner-rs has its own sim infrastructure. gossip-rs
   has a separate sim harness. Merge or independent?

3. **~~Future source I/O genericization~~ RESOLVED**: The `ScanDriver` trait
   (introduced in v5.1) resolves this. Each source type owns its I/O within
   `ScanDriver::run()`. FS driver uses `process_file()` with `File::open()` /
   io_uring. Git driver uses pack parsing. Future S3/GitHub drivers implement
   their own I/O without touching `process_file()`. No need to genericize
   `process_file()` itself — the abstraction is one level up at `ScanDriver`.

4. **~~Checkpoint ordering under parallel execution~~ RESOLVED**: The semantic
   rule is now normative: **checkpoint cursor = highest contiguous committed
   prefix in key order, not "latest seen."** `ScanDriver::checkpoint_hint()`
   MUST return a cursor monotonic in the shard's ordered keyspace.
   Implementation mechanism (frontier tracker vs atomic checkpoint units)
   remains deferred to Step 4, but the contract is fixed.

## Revision Log

### v5.3 → v5.4 (Phase III/IV/V alignment + signature fix + keyspace precision)

External review validated v5.3 architecture as "very close to complete and
internally consistent." Remaining work was tightening contradictions and
making two design points precise enough to preserve Phase III/IV/V invariants.

| Finding                                                     | Action                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`ScanDriver::run()` signature inconsistent**              | Trait block lacked `CommitSink` parameter but Step 5 examples included it. Updated signature to `fn run(&mut self, engine, cfg, out, commit, cancel)`. Without this, implementers would smuggle commit semantics through `EventOutput`, recreating the original Phase V bug.                   |
| **Step 4 "Files" still said "remove old connector traits"** | Contradicted Decision 17 (Phase III traits remain). Fixed to explicitly say "Phase III traits REMAIN."                                                                                                                                                                                         |
| **scanner-git ScanDriver impl vs no-cycle invariant**       | Plan said scanner-git "provides its own ScanDriver impl" but also said scanner-_ never depends on gossip-scan-driver. Resolved: driver wrappers (`GitScanDriver`, `FsScanDriver`) live in gossip-side crates, not scanner-_ crates. Decision 24.                                               |
| **Remaining `SourceConnector` mentions**                    | Cleaned up stale references in Risk Areas and revision log.                                                                                                                                                                                                                                    |
| **Git keyspace under-specified**                            | v5.3 said `(commit_oid, path)` but that conflicted with Phase III blob-OID mapping and didn't match the driver's actual enumeration order. Chose commit-walk-order keyspace: `ItemKey = CommitKey`, paths are internal parallelism, checkpoint atomic at commit boundary. Decision 21 revised. |
| **FS OVID too weak**                                        | v5.3 said `(mtime, size)` but Phase III recommends `(mtime_ns, size, inode)`. Tightened: distributed FS VersionId MUST use at least the Phase III weak tuple. Decision 21 revised.                                                                                                             |
| **`CommitSink::finish_item()` could block scan threads**    | Phase V ResultCommitter exists to isolate slow I/O. Added normative requirement: `finish_item()` must be non-blocking; durability via bounded queue + committer pool. Decision 23.                                                                                                             |
| **`PolicyHash` knob coverage**                              | Phase V requires ledger gate never produces false negatives from policy drift. Added: `PolicyHash` MUST hash all detection knobs (rules, budgets, filters, transforms). Decision 22.                                                                                                           |
| **Task ID references corrected**                            | Restored original ID mapping from PR 83 base branch (.17=Step 0, .18=Step 1, etc.).                                                                                                                                                                                                            |

### v5.2 → v5.3 (item commit protocol + parity fix + naming)

External review validated v5.2 architecture but identified four actionable gaps:

| Finding                                          | Action                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Dependency graph implied cycle**               | `gossip-scan-driver` was drawn as child of `scanner-scheduler` in ASCII graph, implying scheduler→driver dep. Fixed graph placement; added explicit "no dependency cycles" invariant. Finding A.                                                                                                                                                            |
| **Two "connector" concepts conflated**           | Decision 9 removed `EnumerationConnector`/`ReadConnector` while Decision 17 referenced the conformance harness that depends on them. Resolved: Phase III connector traits + conformance harness (1140 lines) remain in `gossip-contracts`. Renamed `SourceConnector` → `ScanSourceFactory` to avoid semantic collision. Finding B.                          |
| **Phase V ordering requires item lifecycle API** | `EventOutput` + `checkpoint_hint()` is insufficient for Phase V: items with zero findings need done-ledger records; `ItemCommitted` ack must come from sink after durability; checkpoint must reflect committed, not scanned. Added `CommitSink` trait with `begin_item`/`upsert_findings`/`finish_item`/`ItemCommitted` lifecycle. Decision 19. Finding C. |
| **Done-ledger gate (skip path) missing**         | Distributed mode re-scans on every lease churn without pre-scan done-ledger check. Added normative requirement: ShardRunner batch-queries done ledger; skipped items still produce `ItemCommitted`. Decision 20. Finding D.                                                                                                                                 |
| **JSONL byte-identical parity unstable**         | Whole-run JSONL byte comparison flaky under parallel execution (non-deterministic ordering). scanner-rs's own `parity.rs` uses `CanonicalFinding` + sort. Changed to: canonical set comparison for whole-run parity + byte-identical per-event encoder golden tests. Decision 15 revised, Decision 21 (parity was renumbered). Finding E.                   |
| **Keyspace undefined for FS/Git**                | Decision 13 contract correct but untestable without defining `ItemKey`, ordering, split points per source. Added normative keyspace table: FS = normalized relative path bytes (lex), Git = (commit_oid, path) tuples. Decision 21. Finding F.                                                                                                              |
| **Missing test coverage**                        | Added: done-ledger gate skip test, contiguous prefix under adversarial ordering, keyspace membership + split correctness.                                                                                                                                                                                                                                   |

### v5.1 → v5.2 (layering fix + normative contracts)

External review validated v5.1 direction but identified structural and
correctness gaps:

| Finding                                                          | Action                                                                                                                                                                                                                        |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ScanDriver/SourceConnector must not live in gossip-contracts** | gossip-contracts is lightweight (gossip-stdx + blake3 + subtle). ScanDriver references scanner-engine + scheduler types. Created new `gossip-scan-driver` crate. gossip-coordination stays free of scanner deps. Decision 12. |
| **Ordered keyspace + cursor contract missing**                   | Assignment must carry `[start_key, end_key)` shard_spec. `checkpoint_hint()` must be monotonic in same keyspace. Added normative section + Decision 13.                                                                       |
| **Phase V commit ordering not explicit**                         | SL8 said "commit findings → checkpoint" but didn't specify done-ledger chain. Added: `FindingsUpsert → DoneLedgerUpsert → ItemCommitted → checkpoint`. Decision 14.                                                           |
| **Checkpoint prefix was open question, not normative**           | Promoted from Open Question 4 to Decision 13: "contiguous committed prefix, not latest seen."                                                                                                                                 |
| **CLI parity scope ambiguous**                                   | Plan said "equivalent" but steps implemented JSONL-only. Now explicit: v5.2 = JSONL-only. Text/SARIF/JSON deferred. Decision 15.                                                                                              |
| **No baseline strategy post-sunset**                             | Added golden output corpus strategy. Decision 16.                                                                                                                                                                             |
| **Future drivers lack conformance gate**                         | Stage 3 connector conformance harness must be reused or equivalently tested. Decision 17.                                                                                                                                     |
| **Bounded-cardinality metrics not explicit**                     | Added rule: no unbounded ID labels in metrics. Decision 18.                                                                                                                                                                   |
| **Dependency graph updated**                                     | gossip-scan-driver added. gossip-contracts annotation corrected. gossip-coordination explicitly no scanner deps.                                                                                                              |

### v5 → v5.1 (ScanDriver boundary + parity corrections)

External review validated Option A direction but identified critical corrections:

| Finding                                | Action                                                                                                                                                                                                                                |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **NormHash NOT in JSONL output**       | `FindingEvent` has path/rule/span/source/confidence — no NormHash. Decision 2 corrected: CLI-vs-CLI parity is at JSONL byte-identical level, not NormHash level.                                                                      |
| **FileSource not universal**           | `run_git_scan()` is a separate entry point from `scan_local()`. Git doesn't use `FileSource`. Introduced `ScanDriver` trait: each source owns its execution model. FS driver wraps `scan_local()`, git driver wraps `run_git_scan()`. |
| **SourceConnector returns ScanDriver** | `SourceConnector::driver_for_assignment()` replaces `file_source()`. Connector is now a factory for source-specific scan drivers.                                                                                                     |
| **Lease-loss: cooperative**            | "Immediately" clarified as cooperative. Added: sink refuses writes without fencing token, never checkpoint after uncertain ownership.                                                                                                 |
| **SL1-SL8 mapping added**              | Concrete invariant mapping: SL1→cursor monotonicity, SL5→terminal enum, SL7→renew-after-checkpoint, SL8→commit-then-checkpoint.                                                                                                       |
| **ShardRunner structure**              | Coordination wrapper now modeled as ShardRunner owning Session + ScanDriver + EventSink + progress channel.                                                                                                                           |
| **Checkpoint ordering**                | Added Open Question 4: parallel execution requires frontier tracking or atomic checkpoint units. `ScanDriver::checkpoint_hint()` returns safe contiguous prefix.                                                                      |
| **Test gaps filled**                   | Added lease-loss safety tests, "no secrets in telemetry" tests, multi-tenant isolation tests to Step 6 parity suite.                                                                                                                  |
| **Open Question 3 resolved**           | ScanDriver pattern resolves future source I/O genericization — each source owns its I/O within `run()`.                                                                                                                               |

### v4 → v5 (Option A unified execution model)

| Finding                                  | Action                                                                                                                                                                      |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Dual-path performance cliff**          | v4 had CLI mode (fast, scanner-scheduler) and distributed mode (slow, ReadConnector::open per item). v5 eliminates the slow path — both modes use the executor.             |
| **DetectionProcessor removed**           | No longer needed. The executor calls scanner-engine directly via ScanEngine trait. NormHash conversion moves to EventSink.                                                  |
| **run_scan_loop_with_detection removed** | No longer needed. The page-driven scan loop is absorbed entirely.                                                                                                           |
| **ReadConnector role changed**           | No longer the distributed execution interface. Remains in gossip-contracts for item-level API. The executor handles I/O via ScanDriver.                                     |
| **EnumerationConnector role changed**    | No longer the distributed execution interface. Remains in gossip-contracts for item-level API + conformance harness. ScanSourceFactory replaces as execution-level factory. |
| **gossip-scan-pipeline absorbed**        | Coordination logic (lease, checkpoint, fence) moves to gossip-scanner-runtime. Crate deleted.                                                                               |
| **Step 4 rewritten**                     | From "wire DetectionProcessor" to "unified execution model: consolidate connectors, absorb pipeline, wire executor."                                                        |
| **Step 5 rewritten**                     | From "separate CLI rewire" to "wire both entry points through unified model."                                                                                               |
| **Step 4 dependencies changed**          | Now requires Step 2a (executor) in addition to Step 1 (engine). No longer parallelizable with Steps 2-3.                                                                    |
| **Lease loss: drop**                     | In-flight work abandoned on lease expiry. No drain.                                                                                                                         |
| **Progress: source-specific**            | Checkpoint granularity determined by ScanSourceFactory, not framework.                                                                                                      |

### v1 → v4 (plan-forge rounds 1-3)

See v4 revision log for complete C1-C13, R2.1-R2.10, R3.C.F1-F8 history.
