# gossip-scanner-runtime

## Module Purpose

`gossip-scanner-runtime` is the shared runtime crate behind the
`scanner-rs` CLI surface and the `gossip-worker` binary. It owns:

- typed scan configuration for filesystem and git entrypoints
- CLI parsing and summary rendering
- path and budget validation before runtime execution
- owned report, checkpoint, cancellation, commit-model, commit-pipeline,
  result-translation, result-committer, checkpoint-aggregator, commit-sink,
  and coordination-recorder types
- local filesystem and git execution through family-oriented runtime modules
- distributed runtime types: lease payloads, coordinator callbacks, persistence handles, runtime configuration, run reports, and error layering

The crate no longer depends on a separate scan-driver abstraction. Its
public surface stays stable for callers while direct and connector-mode
entrypoints share the same local runtime execution paths.

---

## Source File Map

| File | Purpose |
|------|---------|
| `src/lib.rs` | Core types and entrypoints: configs, reports, validation, `scan_fs`, `scan_git`, `scan_fs_with_runtime`, `scan_git_with_runtime`, and `scan_fs_with_prebuilt_engine` (crate-internal entrypoint that reuses a caller-provided engine for distributed scans) |
| `src/cli.rs` | `scanner-rs scan fs / git` parsing, sink selection, runtime dispatch, stderr summary rendering |
| `src/commit_model.rs` | Frozen runtime commit vocabulary: `CompletedUnit`, `CommitRequest`, `UnitCommitReceipt`, `CheckpointAggregatorInput`, and shared `WriteContext` threading into commit requests |
| `src/commit_pipeline.rs` | Bounded execution -> commit worker that owns authoritative durable completion, backpressures scan execution through bounded queues, and emits receipt-ready checkpoint input. `CommitPipeline::split()` decomposes the pipeline into a `CommitPipelineSender` (for execution threads) and a `CommitPipelineDrainer` (for concurrent receipt draining) |
| `src/checkpoint_aggregator.rs` | Receipt-driven prefix checkpoint aggregator that buffers out-of-order durable receipts, reconstructs contiguous item-level proofs, strips connector tokens from durable checkpoint boundaries, and finalizes progress only after a matching checkpoint receipt |
| `src/commit_sink.rs` | `CommitSink` trait, `CliNoOpCommitSink` (no-op), and lightweight bridge record types (`ItemMeta`, `FindingRecord`, `FindingsBatch`) for scan-loop lifecycle |
| `src/coordination_sink.rs` | Owned event records (`StoredGitEvent`, `CommitProgressRecord`) and `CoordinationEventRecorder` trait for distributed scan telemetry |
| `src/distributed.rs` | Foundational distributed worker-loop types: `ShardLease<A>`, `DistributedCoordinator<A>`, `DistributedPersistence<F, D>`, config/report types, layered runtime errors, `ReceiptCommitSink` (CommitSink adapter for receipt-driven execution), `drain_commit_stage` (receipt-driven checkpoint builder), `run_filesystem_lease` (single-shard execution entrypoint), `run_worker` (lease loop), and `InMemoryCoordinator` (test-support coordinator harness) |
| `src/event_sink.rs` | JSONL, text, JSON, and SARIF event sinks |
| `src/git_repo.rs` | Git-repository local scan execution and generic-family marker types |
| `src/ordered_content.rs` | Ordered-content local filesystem execution and generic-family marker types |
| `src/result_translation.rs` | Deterministic translation from completed item results into persistence rows (findings, occurrences, observations, done-ledger) |
| `src/result_committer.rs` | Authoritative findings -> done-ledger durability stage for one completed unit, with request validation and `UnitCommitReceipt` construction |
| `src/parity.rs` | JSONL canonicalization and parity helpers |
| `src/lib_tests.rs` | Validation and local scan execution tests for the runtime core |
| `src/cli_tests.rs` | CLI parsing and summary-rendering tests |
| `Cargo.toml` | Runtime crate dependencies and feature flags |

---

## Architecture

### Runtime entrypoints

The crate exposes two public scan entrypoints:

- `scan_fs(&FsScanConfig) -> Result<ScanReport, ScanRuntimeError>`
- `scan_git(&GitScanConfig) -> Result<ScanReport, ScanRuntimeError>`

Each entrypoint dispatches on `ExecutionMode`, but both `Direct` and
`Connector` currently converge on the same local family-facing runtime
surface. The execution-mode flag is retained so callers can preserve
their existing CLI and worker flows while the public runtime API stays
stable.

### Validation-first execution

The runtime performs setup work in a fixed order:

1. Validate the requested path.
2. Validate runtime budgets (distributed path only; local paths skip budget validation).
3. Normalize source-specific inputs.
4. Call the source family boundary.

Current behavior after validation:

- filesystem scans route to `ordered_content::scan_local_filesystem`
- git scans route to `git_repo::scan_local_repo`
- distributed worker assembly uses the foundational types in `distributed.rs`

Filesystem scans build a runtime engine, forward scheduler events through
owned channel bridges, optionally forward persisted findings through the
local commit sink surface, and convert scheduler counters into the local
`ScanReport`.

Git scans build the same runtime engine family, bridge git/core events
through owned channel forwarding, invoke `run_git_scan`, and convert the
git report into the local `ScanReport` plus optional debug output.

The distributed module exports foundational types consumed by the worker loop:
`ShardLease`, `DistributedCoordinator`, `DistributedPersistence`,
`DistributedRuntimeConfig`, `DistributedRunReport`, and `DistributedRuntimeError`.

### Family split

The runtime is organized around source families rather than driver traits:

- `ordered_content` covers sources that behave like forward-only item streams
- `git_repo` covers repository discovery and repository execution paths
- `distributed` exposes the worker-loop nouns for distributed shard execution

This keeps the public orchestration types available without requiring the
old cross-crate driver seam.

---

## Validation Rules

### Filesystem scans

- `FsScanConfig::path` must exist
- the runtime canonicalizes the path before dispatch

### Git scans

- `GitScanConfig::repo` must exist
- the path must be a git repository root
- subdirectories of a git repository are rejected so the runtime has a
  stable repository anchor

### Distributed runs

- `DistributedRuntimeConfig` stores the budgets that the worker loop threads
  into receipt-driven shard execution

---

## Key Types

### ExecutionMode

```rust
pub enum ExecutionMode {
    Direct,
    Connector,
}
```

Caller-visible mode selector retained for compatibility with existing CLI
and worker surfaces.

### CancellationToken

```rust
pub struct CancellationToken { ... }
```

Cooperative cancellation token backed by `Arc<AtomicBool>`. Runtime callers
can request cancellation through `cancel()` and poll it through
`is_cancelled()`.

### ScanBudgets

```rust
pub struct ScanBudgets {
    pub max_items: usize,
    pub max_bytes: u64,
}
```

Runtime-level budget controls. Validation rejects zero values for either
field.

### FsScanConfig and GitScanConfig

Builder-style request structs used by both binaries. They preserve the
full caller-facing scan surface:

- worker counts
- decode depth
- binary-scan toggles
- rules file override
- transform filter
- anchor mode
- git debug and enrichment options
- execution mode
- runtime budgets

### ScanReport

```rust
pub struct ScanReport {
    pub items_scanned: u64,
    pub bytes_scanned: u64,
    pub chunks_scanned: u64,
    pub findings_emitted: u64,
    pub errors: u64,
    ...
}
```

Owned runtime summary returned by CLI-facing and worker-facing scan
entrypoints. It carries the counters used by summary rendering, parity
tests, and caller logging.

### ScanCheckpoint

```rust
pub struct ScanCheckpoint {
    pub cursor: Cursor,
    pub committed_units: u64,
}
```

Incremental progress hint for future resumable runtime loops. The type is
local to this crate and avoids name collisions with other cursor-related
types.

### AssignmentOutcome

```rust
pub struct AssignmentOutcome {
    pub report: ScanReport,
    pub checkpoint_hint: Option<ScanCheckpoint>,
    pub debug_output: Option<String>,
}
```

Return shape for the sink-aware runtime entrypoints. Callers receive the
main report plus optional checkpoint and debug payloads. The `checkpoint_hint`
field remains a non-authoritative hint; the durable commit pipeline is modeled
separately in `src/commit_model.rs`.

### Runtime commit model

`src/commit_model.rs` freezes the family-neutral durability vocabulary that the
future runtime commit stages build on:

- `CompletedUnit` couples a monotonically increasing in-shard sequence number
  with a tagged `CheckpointBoundary`.
- `CommitRequest<'a>` carries one `WriteContext` plus borrowed findings and
  done-ledger payloads so the runtime keeps buffer ownership outside the commit
  stage while keeping routing/fencing scope aligned across writes.
- `UnitCommitReceipt` proves findings and done-ledger durability for one
  completed unit without implying checkpoint advancement.
- `CheckpointAggregatorInput` wraps only durable unit receipts so the future
  checkpoint stage never consumes raw scan completion signals.

`src/result_committer.rs` is the concrete runtime stage that applies this
vocabulary. It validates the request before any write, builds a single-unit
`CommitScope`, drives `PageCommit` through findings durability and then
done-ledger durability, and returns the resulting `UnitCommitReceipt`.
Request validation covers cross-record consistency that individual persistence
records cannot enforce on their own:

- exactly one done-ledger row per completed unit
- tenant consistency across findings, occurrences, and the shared write context
- observation `WriteContext` and `ovid_hash` alignment with the request and
  done-ledger row
- done-ledger `WriteContext` alignment with the request
- findings-count agreement between scanned done-ledger statuses and the
  distinct stable findings in the batch
- rejection of findings payloads for unscanned terminal statuses
- observation-identity consistency within the findings batch
- referential integrity of the findings batch (every observation references
  an existing occurrence, every occurrence references an existing finding)

`src/commit_pipeline.rs` wraps `ResultCommitter` in the next structural layer:
execution threads submit owned `QueuedCommit` values to a bounded
`sync_channel`, one dedicated worker drains that queue, and the worker emits
either `CommitStageOutput::Committed { checkpoint_input, .. }` or
`CommitStageOutput::Failed { .. }` on a second bounded channel. This is the
runtime's backpressure boundary: slow persistence or a slow downstream
checkpoint stage eventually fills one of the bounded queues, which pauses
execution instead of buffering unbounded translated work in memory.

The commit pipeline also reuses `CancellationToken` for lease loss and
shutdown. New submissions check cancellation before attempting a blocking send,
and the worker re-checks cancellation after dequeue so at most the current
in-flight commit can finish once cancellation is observed. Any item dequeued
but not yet committed attempts to emit a `Failed` outcome with `Cancelled`;
delivery is best-effort because the outcome queue may be full or disconnected
at cancellation time. Buffered items still in
the channel queue are abandoned during shutdown instead of opening new durable
writes after lease loss, which keeps the pipeline responsive without risking
half-committed state.

`src/checkpoint_aggregator.rs` implements the next stage in that pipeline. It
keeps a shard-local reorder buffer keyed by completed-unit sequence number,
prepares only the highest contiguous durable prefix, normalizes checkpoint
boundaries to key-only durable progress, and waits for a matching
`CheckpointCommitReceipt` before it releases buffered receipts and advances the
authoritative checkpoint floor. Durable checkpoint boundaries carry only the
item key, not the connector resume token, because tokens are ephemeral and not
stable across process restarts.

### CommitPipeline decomposition: `split()`

`CommitPipeline::split()` consumes the pipeline and returns two handles:

- `CommitPipelineSender` — a cloneable execution-side handle that submits
  owned `QueuedCommit` values into the bounded queue. It checks the
  `CancellationToken` before each blocking send so cancelled pipelines reject
  new work immediately.
- `CommitPipelineDrainer` — an outcome-drain handle that owns the outcome
  receiver and the worker `JoinHandle`. It exposes `recv()` and
  `recv_timeout()` for consuming `CommitStageOutput` values, a `cancel()`
  method for stopping the worker, and `join()` for waiting on the worker
  thread after draining completes.

Dropping the sender closes the submission channel. Once the commit worker
drains all remaining queued items, it exits, allowing the drainer to consume
the outcomes and join the thread. This separation lets distributed
runtimes run scan execution and receipt draining on concurrent scoped
threads: one thread holds the sender and feeds translated scan results,
while another thread holds the drainer and builds the checkpoint prefix from
durable receipts.

### Receipt-driven execution path

The distributed module provides a complete receipt-driven execution path for
single-shard filesystem scans, built on top of the commit pipeline
decomposition.

#### `ReceiptCommitSink`

`ReceiptCommitSink` implements the `CommitSink` trait to bridge scan-driver
item lifecycle callbacks into the receipt-driven commit pipeline. It tracks
in-flight items in a `BTreeMap<ItemKey, InFlightItem>`:

- `begin_item` assigns a monotonically increasing sequence number and
  inserts an `InFlightItem` into the in-flight map.
- `upsert_findings` appends `FsFindingRecord` entries to the in-flight
  item's accumulated findings vector.
- `finish_item` removes the item from the in-flight map, runs deterministic
  result translation (via `translate_item_result`) to produce persistence
  rows, wraps them in a `QueuedCommit`, and submits to the pipeline through
  `CommitPipelineSender`. On translation or submission failure, the item is
  re-inserted into the in-flight map so the caller can retry.

The sink derives logical timing from sequence numbers (`2n, 2n+1` intervals)
and uses a weak object-version derived from item-key bytes when the source
does not provide an explicit version. It records begin/finish progress events
through the coordination recorder for telemetry, but recorder errors are
intentionally non-fatal because durability flows through the commit pipeline.

#### `drain_commit_stage`

`drain_commit_stage` consumes a `CommitPipelineDrainer` and builds a
`CommitStageDrainResult` containing:

- a `PrefixCheckpointAggregator` that tracks the contiguous committed prefix
- the sequence numbers of committed items (for cross-checking against the
  submitted list); the committed count is derived from this list's length

The function loops over `CommitStageOutput` values from the drainer. On
`Committed` outcomes, it feeds the checkpoint input to the aggregator. On
`Failed` outcomes or aggregation errors, it cancels the pipeline worker to
stop scan execution from queuing further work, then continues draining to
consume remaining buffered outcomes before joining the worker thread. Any
failure aborts the shard.

#### `run_filesystem_lease`

`run_filesystem_lease` orchestrates single-shard filesystem execution under
the receipt-driven durability model:

1. Validates budgets and extracts the filesystem scan config from the lease
   assignment. Forces single-worker execution so `ReceiptCommitSink` sequence
   assignment remains deterministic.
2. Builds the runtime engine and a rule-fingerprint resolver closure from the
   same engine instance (shared via `Arc`).
3. Starts a `CommitPipeline` and splits it into sender and drainer.
4. Constructs a `ReceiptCommitSink` with the sender handle.
5. Uses `std::thread::scope` to run scan execution and commit-stage draining
   concurrently: scan execution calls `scan_fs_with_prebuilt_engine` with
   the `ReceiptCommitSink`, while a second thread calls
   `drain_commit_stage` with the drainer.
6. After both threads complete, cross-checks submitted vs. committed
   sequence numbers via `wait_for_submitted_commits` and verifies that the
   durable receipt count matches the number of items submitted to the commit
   pipeline.
7. Prepares a checkpoint prefix from the aggregator, persists the checkpoint
   cursor via `complete_shard`, acknowledges the checkpoint to advance the
   aggregator watermark, and marks the shard done. Zero-item shards
   (empty directories) complete without a checkpoint cursor.

If any step fails, the shard is not marked done and will be retried on the
next lease acquisition.

#### `run_worker`

`run_worker` is the top-level distributed lease loop. It acquires leases until
the coordinator returns `None`, counts every lease in
`DistributedRunReport`, releases already-done shards without scanning them,
routes filesystem leases through `run_filesystem_lease`, and rejects
assignments that do not expose a filesystem scan config instead of advancing
them without receipt-derived durability.

#### `InMemoryCoordinator`

`InMemoryCoordinator<A>` is available in test builds and under the
`test-support` feature. It keeps the lease queue, completion bookkeeping, and
recorded coordination events behind one `Arc<Mutex<...>>` state bundle so
tests can exercise the worker loop without a real coordination backend.

The coordinator intentionally does not deduplicate `complete_shard` calls.
Crash-retry tests can therefore observe duplicate completion records when a
shard is re-leased after completion but before done-marking.

### ScanRuntimeError

The runtime error surface has six current categories:

- `InvalidPath`
- `GitCommandFailed`
- `Io`
- `RulesConfig`
- `ConnectorInput`
- `Driver`

`Driver(anyhow::Error)` is the catch-all for runtime execution failures such
as scan-loop errors and event-forwarder join failures.

---

## Commit Sink Surface

`src/commit_sink.rs` defines the scan-loop lifecycle sink used by the
runtime:

- `ItemMeta`
- `FindingRecord`
- `FindingsBatch`
- `CommitSink`
- `CliNoOpCommitSink`

Distributed receipt-driven execution implements that surface with
`ReceiptCommitSink` in `src/distributed.rs`. The adapter accumulates compact
finding batches, reconstructs the richer translation inputs expected by
`translate_item_result`, and submits the resulting persistence work to the
bounded commit pipeline. That translation path computes:

- tenant-scoped secret hash (derived from the bridge batch's `norm_hash`)
- finding ID (using the rule-fingerprint resolver for position-independent rule identity)
- occurrence ID

The distributed adapter stores one `WriteContext` per shard-scoped runtime
instance and a rule-fingerprint resolver (`Arc<dyn Fn(u32) -> RuleFingerprint>`).
It uses the shared scope when translating item results for durable persistence
and forwards the same context on every `CommitProgressRecord`. The
rule-fingerprint resolver translates positional `rule_id` values into stable
`RuleFingerprint` values derived from the rule name.

When a source does not provide an explicit version, `ReceiptCommitSink`
derives a stable surrogate object version from the item-key bytes before
calling `translate_item_result`.

The sink's compact `FindingRecord` and `FindingsBatch` types are local bridge
shapes. They are not the persistence-layer `FindingRecord`,
`OccurrenceRecord`, `ObservationRecord`, or `DoneLedgerRecord` types.

---

## Result Translation Surface

`src/result_translation.rs` translates one completed `ScanItem` result into
the persistence rows consumed by durable findings and done-ledger backends.
The module owns:

- `ScanTiming`
- `ItemResult<'a>`
- `PersistenceTranslation` (crate-visible constructor; only `translate_item_result` can build one)
- `ResultTranslationError`
- `translate_item_result`

The translation is deterministic for its inputs. Stable item
identity, version claim, write scope, tenant secret key, a rule-fingerprint
resolver callback, and scan findings fully determine the resulting OVID,
finding IDs, occurrence IDs, observation IDs, and done-ledger key.

`translate_item_result` accepts a `&dyn Fn(u32) -> RuleFingerprint` callback
that resolves positional `rule_id` values to stable, name-derived
`RuleFingerprint` values. This decouples translation from compilation
order: the same rule always maps to the same fingerprint regardless of its
position in the rule list.

Input order is preserved while each persistence layer is deduplicated by its
own identity:

- findings by `FindingId`
- occurrences by `OccurrenceId`
- observations by `ObservationId`

The module validates the translated batch before returning so runtime callers
only see observation-consistent, referentially closed persistence payloads.

---

## Result Commit Surface

`src/result_committer.rs` turns a validated `CommitRequest<'_>` or
`PersistenceTranslation` into one authoritative durable runtime receipt. The
module owns:

- `ResultCommitRequestError`
- `ResultCommitError<FindingsError, DoneLedgerError>`
- `ResultCommitter<F, D>`

`ResultCommitter<F, D>` is generic over `F: FindingsSink` and `D: DoneLedger`.
Its responsibilities are intentionally narrow:

1. validate the request shape before any sink call;
2. submit the findings batch and wait for durability;
3. submit the done-ledger row only after findings durability is confirmed;
4. return `UnitCommitReceipt` only after both stages complete durably.

This keeps the runtime's authoritative write ordering in one place and makes
"no early ACK" structural: the runtime cannot construct a durable unit receipt
before both persistence layers confirm success.

The module also exposes `commit_translation(...)`, which reuses pre-translated
persistence rows directly instead of re-deriving them inside the commit stage. Idempotency comes from deterministic IDs plus the sink contracts,
not from runtime-side dedup caches.

---

## CLI Surface

`src/cli.rs` owns the full `scanner-rs scan {fs|git}` grammar. Its
responsibilities are:

- parse raw `OsString` arguments into `CliConfig`
- choose the requested event sink
- auto-size git workers when the caller does not supply `--workers`
- invoke `scan_fs_with_runtime` or `scan_git_with_runtime`
- print a compact `key=value` summary to stderr

The CLI summary reads from the local `ScanReport` type, not a report type
imported from another crate.

---

## Distributed Runtime Foundation

`src/distributed.rs` exposes the type layer that the receipt-driven worker loop
builds on.

```rust
pub struct ShardLease<A> {
    shard_id: Arc<str>,
    assignment: A,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
}
```

```rust
pub trait DistributedCoordinator<A>: Send + Sync
where
    A: ShardLeaseAssignment,
{
    fn acquire_shard(&self) -> anyhow::Result<Option<ShardLease<A>>>;
    fn release_shard(&self, lease: &ShardLease<A>) -> anyhow::Result<()>;
    fn complete_shard(
        &self,
        lease: &ShardLease<A>,
        checkpoint: Option<Cursor>,
        report: ScanReport,
    ) -> anyhow::Result<()>;
    fn is_shard_done(&self, lease: &ShardLease<A>) -> anyhow::Result<bool>;
    fn mark_shard_done(&self, lease: &ShardLease<A>) -> anyhow::Result<()>;
    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder>;
}
```

```rust
pub struct DistributedRuntimeConfig {
    pub budgets: ScanBudgets,
    pub commit_queue_capacity: NonZeroUsize,
}
```

`ShardLease<A>` is the hand-off object from coordination into the worker loop.
It keeps the string shard label used for recorder routing separate from the
numeric shard identity carried inside `WriteContext`. Construction via
`ShardLease::new` validates that the assignment and write context agree on
policy scope, returning `PolicyMismatchError` on divergence so the worker
loop can skip the shard instead of crashing.

`DistributedCoordinator<A>` defines the coordination callbacks the runtime
needs around a single lease: acquire, release, receipt-derived completion,
done checks, done marking, and event recording.

`DistributedPersistence<F, D>` (where `F` and `D` are `Clone + Send + Sync`)
groups the findings sink and done-ledger handle that the worker loop clones
per shard, while `DistributedRuntimeError`
distinguishes coordinator failures, scan-runtime failures, local durability
pipeline failures, and unsupported assignment types.

`run_worker` ties those types together into the lease loop, and
`InMemoryCoordinator<A>` provides a harness implementation for unit tests and
feature-gated downstream test support.

---

## Tests

The runtime tests focus on the behavior that exists today:

- execution-mode parsing
- cancellation-token state transitions
- budget validation
- filesystem path validation
- git repository root validation
- successful filesystem and git scans with custom rules
- event forwarding for filesystem and git runtime entrypoints
- commit forwarding for filesystem scans with persistence enabled
- deterministic result translation into findings and done-ledger persistence rows
- lease policy-scope assertions
- distributed config defaults
- distributed persistence handle cloning
- distributed runtime error layering
- distributed worker-loop lease accounting, done-ledger skips, and
  receipt-derived completion
- in-memory coordinator snapshots for completed shards and recorded events
- CLI parsing and summary formatting
- receipt-driven identity derivation via translate_item_result
- authoritative findings -> done-ledger commit ordering and item-level receipt
  construction
- bounded execution -> commit backpressure and cancellation semantics

These tests exercise the live local runtime paths for valid filesystem and
git sources and verify the distributed type surface (lease construction,
persistence cloning, config defaults, error layering, worker-loop accounting,
and in-memory coordinator observations).

---

## Source of Truth

| Concern | Path |
|---------|------|
| Core runtime types and validation | `crates/gossip-scanner-runtime/src/lib.rs` |
| CLI parsing and summary rendering | `crates/gossip-scanner-runtime/src/cli.rs` |
| Commit sink trait and bridge record types | `crates/gossip-scanner-runtime/src/commit_sink.rs` |
| Deterministic result-to-persistence translation | `crates/gossip-scanner-runtime/src/result_translation.rs` |
| Durable findings -> done-ledger commit stage | `crates/gossip-scanner-runtime/src/result_committer.rs` |
| Bounded execution -> commit worker and outcome queues | `crates/gossip-scanner-runtime/src/commit_pipeline.rs` |
| Coordination recorder payloads | `crates/gossip-scanner-runtime/src/coordination_sink.rs` |
| Distributed worker-loop foundation types | `crates/gossip-scanner-runtime/src/distributed.rs` |
| Ordered-content local filesystem runtime | `crates/gossip-scanner-runtime/src/ordered_content.rs` |
| Git-repo local scan runtime | `crates/gossip-scanner-runtime/src/git_repo.rs` |
| Event sinks | `crates/gossip-scanner-runtime/src/event_sink.rs` |
| Frozen runtime commit vocabulary | `crates/gossip-scanner-runtime/src/commit_model.rs` |
| Receipt-driven prefix checkpoint aggregation | `crates/gossip-scanner-runtime/src/checkpoint_aggregator.rs` |
| JSONL parity helpers | `crates/gossip-scanner-runtime/src/parity.rs` |
