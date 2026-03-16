# gossip-scanner-runtime

## Module Purpose

`gossip-scanner-runtime` is the shared runtime crate behind the
`scanner-rs` CLI surface and the `gossip-worker` binary. It owns:

- typed scan configuration for filesystem and git entrypoints
- CLI parsing and summary rendering
- path and budget validation before runtime execution
- owned report, checkpoint, cancellation, commit-model, commit-sink, and
  coordination-recorder types
- local filesystem and git execution through family-oriented runtime modules
- distributed runtime placeholder nouns for future worker-loop wiring

The crate no longer depends on a separate scan-driver abstraction. Its
public surface stays stable for callers while direct and connector-mode
entrypoints share the same local runtime execution paths.

---

## Source File Map

| File | Purpose |
|------|---------|
| `src/lib.rs` | Core types and entrypoints: configs, reports, validation, `scan_fs`, `scan_git`, `scan_fs_with_runtime`, `scan_git_with_runtime` |
| `src/cli.rs` | `scanner-rs scan fs / git` parsing, sink selection, runtime dispatch, stderr summary rendering |
| `src/commit_model.rs` | Frozen runtime commit vocabulary: `CompletedUnit`, `CommitRequest`, `UnitCommitReceipt`, `CheckpointAggregatorInput`, and shared `WriteContext` threading into commit requests |
| `src/commit_sink.rs` | Local `CommitSink` trait, no-op sink, and durable identity-deriving sink that stamps one shared `WriteContext` onto emitted records |
| `src/coordination_sink.rs` | Owned event records and recorder trait used by durable persistence plumbing, including write-scoped progress and identity-chain records |
| `src/distributed.rs` | Distributed runtime family placeholders, `ShardLease<A>`, and shared config/report types |
| `src/event_sink.rs` | JSONL, text, JSON, and SARIF event sinks |
| `src/git_repo.rs` | Git-repository local scan execution and generic-family marker types |
| `src/ordered_content.rs` | Ordered-content local filesystem execution and generic-family marker types |
| `src/result_translation.rs` | Deterministic translation from completed item results into persistence rows (findings, occurrences, observations, done-ledger) |
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
- distributed runs route to `distributed::run_distributed`

Filesystem scans build a runtime engine, forward scheduler events through
owned channel bridges, optionally forward persisted findings through the
local commit sink surface, and convert scheduler counters into the local
`ScanReport`.

Git scans build the same runtime engine family, bridge git/core events
through owned channel forwarding, invoke `run_git_scan`, and convert the
git report into the local `ScanReport` plus optional debug output.

The distributed entrypoint returns `ScanRuntimeError` directly.

### Family split

The runtime is organized around source families rather than driver traits:

- `ordered_content` covers sources that behave like forward-only item streams
- `git_repo` covers repository discovery and repository execution paths
- `distributed` exposes the future worker-loop nouns for family-based execution

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

- `DistributedRunConfig.budgets` must validate before the family placeholder runs

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

### ScanRuntimeError

The runtime error surface has six current categories:

- `InvalidPath`
- `GitCommandFailed`
- `Io`
- `RulesConfig`
- `ConnectorInput`
- `Driver`

`Driver(anyhow::Error)` is the catch-all for runtime execution failures such
as scan-loop errors, event-forwarder join failures, and the still-unwired
distributed family path.

---

## Commit Sink Surface

`src/commit_sink.rs` defines the scan-loop lifecycle sink used by the
runtime:

- `ItemMeta`
- `FindingRecord`
- `FindingsBatch`
- `CommitSink`
- `CliNoOpCommitSink`
- `DurableCommitSink`

`DurableCommitSink` is the bridge between scan-loop item lifecycle events
and identity-chain recording for coordination diagnostics. It computes:

- normalized secret hash input
- tenant-scoped secret hash
- finding ID
- occurrence ID

The sink stores one `WriteContext` per shard-scoped runtime instance. It uses
that shared scope when deriving tenant-bound finding identity and forwards the
same context on every `CommitProgressRecord` and `IdentityChainRecord`.

When a source does not provide an explicit version, the sink derives a
stable surrogate object version from the item-key bytes.

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
- `PersistenceTranslation`
- `ResultTranslationError`
- `translate_item_result`

The translation is pure with respect to its inputs. Stable item identity,
version claim, write scope, tenant secret key, and scan findings fully
determine the resulting OVID, finding IDs, occurrence IDs, observation IDs,
and done-ledger key.

Input order is preserved while each persistence layer is deduplicated by its
own identity:

- findings by `FindingId`
- occurrences by `OccurrenceId`
- observations by `ObservationId`

The module validates the translated batch before returning so runtime callers
only see observation-consistent, referentially closed persistence payloads.

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

## Distributed Placeholder Surface

`src/distributed.rs` keeps the future distributed runtime nouns available
without exposing the removed worker-loop implementation.

```rust
pub enum DistributedFamily {
    OrderedContent,
    GitRepo,
}
```

```rust
pub struct DistributedRunConfig {
    pub family: DistributedFamily,
    pub budgets: ScanBudgets,
}
```

```rust
pub struct ShardLease<A> {
    shard_id: Arc<str>,
    assignment: A,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
}
```

```rust
pub fn run_distributed(
    config: &DistributedRunConfig,
) -> Result<DistributedRunReport, ScanRuntimeError>
```

`ShardLease<A>` is the hand-off object from coordination into the worker loop.
It keeps the string shard label used for recorder routing separate from the
numeric shard identity carried inside `WriteContext`. Construction via
`ShardLease::new` enforces that `assignment.policy_hash()` equals
`write_context.policy_hash()`, returning `Err(PolicyMismatchError)` on
mismatch. Fields are private; callers access them through getter methods.
`run_distributed` validates budgets and then returns a family-specific runtime
placeholder error.

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
- distributed placeholder error routing
- CLI parsing and summary formatting
- durable commit-sink identity derivation

These tests exercise the live local runtime paths for valid filesystem and
git sources while keeping the distributed placeholder surface covered until
that worker-loop API is fully wired.

---

## Source of Truth

| Concern | Path |
|---------|------|
| Core runtime types and validation | `crates/gossip-scanner-runtime/src/lib.rs` |
| CLI parsing and summary rendering | `crates/gossip-scanner-runtime/src/cli.rs` |
| Commit sink types and durable identity derivation | `crates/gossip-scanner-runtime/src/commit_sink.rs` |
| Deterministic result-to-persistence translation | `crates/gossip-scanner-runtime/src/result_translation.rs` |
| Coordination recorder payloads | `crates/gossip-scanner-runtime/src/coordination_sink.rs` |
| Distributed family placeholders and lease metadata | `crates/gossip-scanner-runtime/src/distributed.rs` |
| Ordered-content local filesystem runtime | `crates/gossip-scanner-runtime/src/ordered_content.rs` |
| Git-repo local scan runtime | `crates/gossip-scanner-runtime/src/git_repo.rs` |
| Event sinks | `crates/gossip-scanner-runtime/src/event_sink.rs` |
| Frozen runtime commit vocabulary | `crates/gossip-scanner-runtime/src/commit_model.rs` |
| JSONL parity helpers | `crates/gossip-scanner-runtime/src/parity.rs` |
