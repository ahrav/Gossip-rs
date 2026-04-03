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
- contract-level mirror-backed Git execution via a concrete repo executor adapter
- runtime-backed Git persistence adapters and repo-frontier durability helpers
- distributed runtime worker-loop support: `WorkerIdentity`, concrete shard
  leases, direct coordination claim/complete helpers, persistence handles,
  runtime configuration, run reports, and error layering

The crate no longer depends on a separate scan-driver abstraction.
Execution mode selects the family boundary: direct mode runs the local
scan pipeline, filesystem connector mode performs ordered page acquisition
and validation, and Git connector mode uses the direct path.

---

## Source File Map

| File | Purpose |
|------|---------|
| `src/lib.rs` | Core types and entrypoints: configs, reports, validation, `scan_fs`, `scan_git`, mode-specific dispatchers (`scan_fs_direct`, `scan_fs_connector`, `scan_git_direct`, `scan_git_connector`), and crate-internal `scan_fs_with_runtime`, `scan_git_with_runtime` |
| `src/cli.rs` | `scanner-rs scan fs / git` parsing, sink selection, runtime dispatch, stderr summary rendering |
| `src/commit_model.rs` | Frozen runtime commit vocabulary: `CompletedUnit`, `CommitRequest`, `UnitCommitReceipt`, `CheckpointAggregatorInput`, and shared `WriteContext` threading into commit requests |
| `src/commit_pipeline.rs` | Bounded execution -> commit worker that owns authoritative durable completion, backpressures scan execution through bounded queues, and emits receipt-ready checkpoint input. `CommitPipeline::split()` decomposes the pipeline into a `CommitPipelineSender` (for execution threads) and a `CommitPipelineDrainer` (for concurrent receipt draining) |
| `src/checkpoint_aggregator.rs` | Receipt-driven prefix checkpoint aggregator that buffers out-of-order durable receipts, reconstructs contiguous item-level proofs, strips connector tokens from durable checkpoint boundaries, and finalizes progress only after a matching checkpoint receipt |
| `src/commit_sink.rs` | `CommitSink` trait, `CliNoOpCommitSink` (no-op), and lightweight bridge record types (`ItemMeta`, `FindingRecord`, `FindingsBatch`) for scan-loop lifecycle |
| `src/coordination_sink.rs` | Owned event records (`StoredGitEvent`, `CommitProgressRecord`) and `CoordinationEventRecorder` trait for distributed scan telemetry |
| `src/distributed.rs` | Distributed worker-loop runtime: `WorkerIdentity`, concrete `ShardLease`, `DistributedPersistence<F, D>`, config/report/error types, `ReceiptCommitSink` (receipt-driven execution adapter), and `run_worker` (lease loop). Internal helpers: `drain_commit_stage` (receipt-driven checkpoint builder), ordered-content filesystem lease execution, and direct `CoordinationFacade` claim/complete helpers |
| `src/event_sink.rs` | JSONL, text, JSON, and SARIF event sinks |
| `src/git_discovery.rs` | Static single-target Git repository discovery source for payload-backed repo-frontier shards |
| `src/git_executor.rs` | Contract-level adapter that implements `GitRepoExecutor` for mirror-backed repo scans by translating `GitSelection` + `GitExecutionLimits` into `scanner-git` config and reusing the shared runtime runner |
| `src/git_persistence.rs` | Runtime-backed adapters for `scanner-git` watermark/seen/finalize seams plus repo-frontier receipt/checkpoint helpers. Non-atomic backends use a two-phase commit (data+seen before watermarks) so a mid-commit failure cannot expose watermarks without matching data writes |
| `src/git_mirror.rs` | Worker-local Git mirror lifecycle, deterministic cache-path derivation, and stale control-file cleanup |
| `src/git_repo.rs` | Git-repository local scan execution and generic-family marker types |
| `src/ordered_content.rs` | Ordered-content page validation, explicit terminal page / exhausted-empty outcomes, scan-miss execution, and direct local filesystem execution helpers |
| `src/result_translation.rs` | Deterministic translation from completed item results into persistence rows (findings, occurrences, observations, done-ledger) |
| `src/result_committer.rs` | Authoritative findings -> done-ledger durability stage for one completed unit, with request validation and `UnitCommitReceipt` construction |
| `src/parity.rs` | JSONL canonicalization and parity helpers |
| `src/lib_tests.rs` | Validation and local scan execution tests for the runtime core |
| `src/cli_tests.rs` | CLI parsing and summary-rendering tests |
| `src/test_fixtures.rs` | Shared test fixtures (write contexts, timings, findings builders, rule fingerprints, and git repository setup helpers) used by runtime test modules |
| `src/runtime_durability_tests.rs` | Integration tests that stitch together translation, findings -> done-ledger durability, and receipt-driven checkpoint aggregation to prove explicit-receipt gating, contiguous-prefix advancement, and reassignment-safe retry invariants |
| `Cargo.toml` | Runtime crate dependencies and feature flags |

---

## Architecture

### Runtime entrypoints

The crate exposes two public scan entrypoints:

- `scan_fs(&FsScanConfig) -> Result<ScanReport, ScanRuntimeError>`
- `scan_git(&GitScanConfig) -> Result<ScanReport, ScanRuntimeError>`

Each entrypoint dispatches on `ExecutionMode`. `Direct` runs the
local scan implementation. `Connector` selects the family
boundary instead: filesystem scans execute one ordered connector page
acquisition/validation step, while Git scans use the direct
path.

### Validation-first execution

The runtime performs setup work in a fixed order:

1. Validate the requested path.
2. Validate runtime budgets (distributed path and filesystem connector-mode
   local path via `Budgets`; direct local scans and Git connector mode skip
   budget validation).
3. Normalize source-specific inputs.
4. Call the source family boundary.

Current behavior after validation:

- direct filesystem scans route to `ordered_content::scan_local_filesystem`
- connector-mode filesystem scans instantiate `FilesystemConnector` and route
  through ordered-content page validation (done-ledger prefiltering and bounded
  scan-miss execution are available as library APIs but are not wired into the
  live dispatcher)
- git scans route to `git_repo::scan_local_repo`
- contract-level mirror-backed repo execution routes through
  `git_executor::ScannerGitExecutor`, which reuses the same lower-level runner
  setup after mirror preparation
- worker-local mirror preparation and deterministic mirror-cache naming live in `git_mirror::LocalMirrorManager`
- distributed worker assembly uses the foundational types in `distributed.rs`

Direct filesystem scans build a runtime engine, forward scheduler events
through owned channel bridges, optionally forward persisted findings
through the local commit sink surface, and convert scheduler counters
into the local `ScanReport`. When persistence is enabled, the runtime
derives each filesystem `StableItemId` from the filesystem connector tag,
a connector-instance hash of the canonicalized scan root, and the
normalized root-relative path (the locator in `ItemIdentityKey`). The
commit forwarder (`forward_commits`) uses a `DiscoveryOrderBuffer` to
reorder finding batches from executor processing order (LIFO-reversed)
back into file-path-sorted discovery order before calling `begin_item`.
This ensures checkpoint sequence numbers are monotonically consistent
with `ItemKey` ordering, preventing `BoundaryRegression` errors in the
prefix checkpoint aggregator for ordered-content shards with multiple
files.

Connector-mode filesystem scans acquire one ordered page through
`OrderedContentRuntime::execute_source` from the real
`FilesystemConnector`, validate shard bounds and cursor monotonicity,
and classify enumerate failures from the connector error taxonomy. The
runtime maps the ordered filesystem path onto explicit
`ShardCompletionOutcome` variants: `ExhaustedEmpty` only after
the connector confirms exhausted-empty (`Ok(None)` at the page-fill
boundary), `Complete { checkpoint }` after a terminal non-empty page is
followed by that exhausted-empty suffix call, and `Checkpoint {
checkpoint }` when the scan stops early after receipt-backed progress
exists. This lets distributed callers require the exhausted-empty suffix
before they treat a shard as fully enumerated, while still preserving
checkpointable progress on retryable stops. The current
`scan_fs_connector` entry point returns the validated page report without
performing content reads. Done-ledger prefiltering and
`OrderedContentRuntime::execute_scan_misses` (which bridges runtime
`ScanBudgets` into connector read budgets, scans each item through the
shared chunked engine path, preserves retryable versus permanent read
failures, and returns ordered non-durable outcomes) are available as
library APIs but are not wired into the live dispatcher.

Git scans build the same runtime engine family, bridge git/core events
through owned channel forwarding, invoke `run_git_scan`, and convert the
git report into the local `ScanReport` plus optional debug output.
When the caller owns durable Git state, `git_persistence::GitPersistenceAdapter`
implements `scanner-git`'s ref-watermark, seen-blob, and finalize seams and
plugs into `git_repo::run_runtime_git_scan_with_stores`. A complete finalize
can then be mapped onto the existing repo-frontier `UnitCommitReceipt` and
`CheckpointAggregatorInput` path without inventing a Git-only outer receipt
stack.

The distributed module exports the concrete worker-loop types and helpers:
`WorkerIdentity`, `ShardLease`, `DistributedPersistence`,
`DistributedRuntimeConfig`, `DistributedRunReport`, and
`DistributedRuntimeError`. The runtime depends directly on
`gossip-coordination` for claim and completion operations and on
`gossip-frontier` for shard metadata decoding. Filesystem lease
execution starts a lease-deadline watchdog that drives the shared
`CancellationToken` when the claimed lease is no longer trustworthy.
The watchdog compares against a monotonic `Instant`-based deadline
(converted from the coordinator-provided logical lease deadline at
claim time) so `CLOCK_REALTIME` jumps from NTP corrections or VM
migration cannot cause false-positive or false-negative expiry
detection. The
watchdog uses `std::thread::park_timeout` instead of `thread::sleep`
so the main thread can wake it immediately via `unpark()` when shard
execution finishes, avoiding up to one polling interval of exit
latency. Successful receipt-drain completion seals the local deadline
signal before the watchdog joins. This ensures any lease rejection
after durable local completion is decided by the coordinator
`complete`/`checkpoint` call rather than by a late local watchdog tick.
Coordinator-side `StaleFence` and `LeaseExpired` rejections from both
`checkpoint` and `complete` are normalized to
`DistributedRuntimeError::LeaseUncertain`, preserving the lease-loss
classification after local durable progress exists.
The ordered page loop polls that token between page acquisitions and
before queueing new commit work so expiry stops the shard before more
items are enqueued. Claim retry delays honor coordinator-provided
`retry_after` and `earliest_deadline` floors directly, falling back to
the fixed race-retry delay only when no logical wakeup hint is
available. Successful filesystem lease execution returns an
explicit `ShardCompletionOutcome`: `Complete { checkpoint }` transitions
the shard to `Done` using either the receipt-backed committed-prefix
cursor or, when no new receipts were produced but prior durable progress
exists, the recovered resume cursor rebuilt by replaying that durable coverage.
`Checkpoint { checkpoint }` preserves non-terminal progress through
coordination `checkpoint`, and `ExhaustedEmpty` signals that the scan
observed exhausted-empty without producing a new receipt-backed
checkpoint in this claim. Completion preserves the restored resume
cursor when the shard already had prior progress and falls back to a
range-safe cursor only for truly initial empty shards. If the deadline elapses
first, or if `complete` rejects a stale or expired lease, the worker
surfaces `DistributedRuntimeError::LeaseUncertain` and leaves the
shard for a higher-fence reassignment to resume from durable receipt
and done-ledger state.

### Family split

The runtime is organized around source families rather than driver traits:

- `ordered_content` covers sources that behave like forward-only item streams
- `git_discovery` owns static payload-backed repository discovery for
  repo-frontier shards
- `git_repo` covers direct local repository execution helpers
- `git_executor` adapts mirror-backed contract execution onto the shared git runner
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
    pub items_deferred: u64,
    pub bytes_scanned: u64,
    pub chunks_scanned: u64,
    pub findings_emitted: u64,
    pub errors: u64,
    pub binary_skipped: u64,
    pub ext_skipped: u64,
    pub lock_skipped: u64,
    pub binary_extracted: u64,
    pub dropped_findings: u64,
    pub persist_emit_failures: u64,
    pub persist_incomplete: bool,
    pub scan_ns: u64,
    pub persist_ns: u64,
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
types. Distributed workers derive shard advancement from receipt-backed
contiguous-prefix aggregation before surfacing any checkpoint cursor.

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
field remains an advisory runtime-local cursor for direct callers; it does not
prove durable distributed progress. Coordinator-backed execution advances shard
state only from receipt-backed commit outcomes that flow through
`src/commit_model.rs`, `src/commit_pipeline.rs`, and `src/distributed.rs`.

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

`ReceiptCommitSink` bridges runtime item execution into the receipt-driven
commit pipeline. It supports both the scan-loop `CommitSink` lifecycle and
direct ordered-content item submission. The scan-loop path tracks in-flight
items in a `BTreeMap<ItemKey, InFlightItem>`:

- `begin_item` assigns a monotonically increasing sequence number and
  inserts an `InFlightItem` into the in-flight map.
- `upsert_findings` appends `FsFindingRecord` entries to the in-flight
  item's accumulated findings vector.
- `finish_item` removes the item from the in-flight map, runs deterministic
  result translation (via `translate_item_result`) to produce persistence
  rows, wraps them in a `QueuedCommit`, and submits to the pipeline through
  `CommitPipelineSender`. On translation or submission failure, the item is
  re-inserted into the in-flight map so the caller can retry.

For ordered-content execution, `submit_ordered_item` derives `ItemMeta`,
translates the `OrderedContentItemOutcome` into the same persistence rows,
and submits the resulting `QueuedCommit` directly. Both surfaces converge on
the same bounded commit pipeline, so durable receipt handling and checkpoint
aggregation stay identical regardless of how the runtime discovered the item.

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
   payload. Forces single-worker execution so `ReceiptCommitSink` sequence
   assignment remains deterministic.
2. Builds the runtime engine and a rule-fingerprint resolver closure from the
   same engine instance (shared via `Arc`).
3. Starts a `CommitPipeline` and splits it into sender and drainer.
4. Constructs a `ReceiptCommitSink` with the sender handle.
5. Uses `std::thread::scope` to run scan execution and commit-stage draining
   concurrently: scan execution instantiates a `FilesystemConnector`,
   loops through ordered pages (each prefiltered against the done ledger),
   executes the remaining scan-miss items with the shared engine, emits
   scheduler-compatible finding and summary events, and submits each ordered
   item outcome to `ReceiptCommitSink`. A second thread calls
   `drain_commit_stage` with the drainer.
6. After both threads complete, resolves the scan, submission, and drain
   outcomes in diagnostic order. Scan-runtime failures surface
   before downstream submission or drain failures because a broken scan often
   cascades into receipt-drain errors. Once outcome resolution succeeds, the
   runtime cross-checks submitted vs. committed sequence numbers via
   `wait_for_submitted_commits` and verifies that the durable receipt count
   matches the number of items submitted to the commit pipeline.
7. Prepares a checkpoint prefix from the aggregator, acknowledges the
   checkpoint to advance the aggregator watermark, and returns an explicit
   `ShardCompletionOutcome` to the caller. Receipt-backed progress yields
   `Complete { checkpoint }` or `Checkpoint { checkpoint }`, while replay-only
   recovery can still return either outcome from the recovered resume cursor
   when this claim produced no new durable receipts but did recover durable
   coverage from earlier committed work. `ExhaustedEmpty` indicates that the
   scan observed exhausted-empty without producing a new receipt-backed
   checkpoint in this claim; completion preserves the restored resume cursor
   when prior progress exists and falls back to a range-safe cursor only for
   truly initial empty shards.

If any step fails, the shard is not completed in coordination and will be
retried when the lease expires.

#### `run_worker`

`run_worker` is the top-level distributed lease loop. It acquires leases until
the coordinator returns no more active work, counts every claimed lease in
`DistributedRunReport`, routes each lease through `run_filesystem_lease`, and
then advances it directly against the coordination backend. `advance_shard`
uses the explicit `ShardCompletionOutcome`: `Complete` and `Checkpoint`
forward their cursor, while `ExhaustedEmpty` preserves the restored
resume cursor when the shard has prior progress, uses a synthetic
sentinel key (`b"\x00"`) for unbounded empty shards, and falls back to
`range_start()` for bounded empty shards.

Unit tests exercise this loop through `gossip_coordination::InMemoryCoordinator`,
which is the same reference backend used elsewhere in the coordination layer.

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
`ReceiptCommitSink` in `src/distributed.rs`. The adapter accepts either
compact scan-loop finding batches or direct ordered-content item outcomes,
reconstructs the richer translation inputs expected by `translate_item_result`,
and submits the resulting persistence work to the bounded commit pipeline.
That translation path computes:

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
pub struct WorkerIdentity {
    pub tenant: TenantId,
    pub run: RunId,
    pub worker: WorkerId,
    pub policy_hash: PolicyHash,
    pub tenant_secret_key: TenantSecretKey,
    pub scan_template: FsScanConfig,
    pub recorder: Arc<dyn CoordinationEventRecorder>,
}
```

```rust
pub struct ShardLease {
    /// String shard label used for routing recorder events.
    shard_id: Arc<str>,
    /// Authoritative coordination-layer lease used for terminal completion.
    lease: Lease,
    /// Authoritative shard bounds, resume cursor, and cursor semantics.
    state: RestoredShardState,
    /// Hydrated filesystem source configuration plus explicit source mode.
    filesystem_source: HydratedFilesystemSource,
    /// Shared routing and fencing metadata for all writes emitted under the lease.
    write_context: WriteContext,
    /// Tenant secret key used for secret-hash derivation.
    tenant_secret_key: TenantSecretKey,
    /// Wall-clock timestamp captured at claim time, used to anchor the
    /// lease deadline to the monotonic clock without NTP skew.
    claim_wall_clock: LogicalTime,
    /// Monotonic instant captured alongside `claim_wall_clock`.
    claim_instant: Instant,
}
```

```rust
pub fn run_worker<C, F, D>(
    coordinator: &mut C,
    identity: WorkerIdentity,
    persistence: DistributedPersistence<F, D>,
    config: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError>
where
    C: CoordinationFacade,
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    ...
}
```

```rust
pub struct DistributedRuntimeConfig {
    pub budgets: ScanBudgets,
    pub commit_queue_capacity: NonZeroUsize,
}
```

`WorkerIdentity` bundles the stable coordination and durability scope for one
worker invocation. It threads tenant/run/worker identity, the policy hash used
for `WriteContext`, the tenant secret key used during translation, a template
filesystem config, and the shared coordination recorder into the claim and
completion helpers.

`ShardLease` is the hand-off object from `gossip-coordination` into the worker
loop. It keeps the string shard label used for recorder routing separate from
the numeric shard identity carried inside `Lease` and `WriteContext`, stores
the authoritative restored shard state (`RestoredShardState`, including shard
bounds plus any resume cursor and cursor semantics), and carries the hydrated
filesystem source state (`HydratedFilesystemSource`) that pairs the per-shard
scan configuration with the explicit source mode decoded from shard metadata.

`DistributedPersistence<F, D>` (where `F` and `D` are `Clone + Send + Sync`)
groups the findings sink and done-ledger handle that the worker loop clones
per shard, while `DistributedRuntimeError`
distinguishes coordinator failures, scan-runtime failures, and local
durability pipeline failures. When scan execution and downstream submission or
drain paths fail in the same lease, `run_filesystem_lease` reports the runtime
failure first so the caller sees the closest cause instead of a cascaded
durability symptom.

`run_worker` ties those types together into the lease loop. It claims shards
directly through `CoordinationFacade::claim_next_available`, retries on
throttling or live-lease contention, executes one filesystem shard at a time,
and completes successful shards through `CoordinationFacade::complete` with a
deterministic `OpId`.

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
- distributed config defaults
- distributed persistence handle cloning
- distributed runtime error layering, including runtime-first precedence when
  scan and submission or drain failures race
- distributed worker-loop lease accounting, claim retry, and receipt-derived
  completion
- `gossip_coordination::InMemoryCoordinator` snapshots for completed shards
  and run progress
- CLI parsing and summary formatting
- local-vs-distributed filesystem finding-set parity after JSONL path
  normalization
- receipt-driven identity derivation via translate_item_result
- authoritative findings -> done-ledger commit ordering and item-level receipt
  construction
- explicit receipt gating before checkpoint advancement, including clean scans
  that emit zero findings
- contiguous-prefix checkpoint advancement from out-of-order durable receipts
- stale-fence receipt rejection followed by reassignment-safe idempotent retry
- bounded execution -> commit backpressure and cancellation semantics
- crash-before-ledger fault injection with idempotent retry and checkpoint blocking
- crash-before-findings-durability with empty-store verification
- multi-item partial-prefix recovery under mid-stream fault

These tests exercise the live local runtime paths for valid filesystem and
git sources and verify the distributed worker loop (lease construction,
persistence cloning, config defaults, error layering, claim/completion flow,
and coordination-backend observations).

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
| Static Git repo discovery source | `crates/gossip-scanner-runtime/src/git_discovery.rs` |
| Git-repo local scan runtime | `crates/gossip-scanner-runtime/src/git_repo.rs` |
| Event sinks | `crates/gossip-scanner-runtime/src/event_sink.rs` |
| Frozen runtime commit vocabulary | `crates/gossip-scanner-runtime/src/commit_model.rs` |
| Receipt-driven prefix checkpoint aggregation | `crates/gossip-scanner-runtime/src/checkpoint_aggregator.rs` |
| JSONL parity helpers | `crates/gossip-scanner-runtime/src/parity.rs` |
| Shared test fixtures | `crates/gossip-scanner-runtime/src/test_fixtures.rs` |
| Runtime durability integration tests | `crates/gossip-scanner-runtime/src/runtime_durability_tests.rs` |
