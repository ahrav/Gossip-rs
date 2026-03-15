# gossip-scanner-runtime

## Module Purpose

`gossip-scanner-runtime` is the shared runtime crate behind the
`scanner-rs` CLI surface and the `gossip-worker` binary. It owns:

- typed scan configuration for filesystem and git entrypoints
- CLI parsing and summary rendering
- path and budget validation before runtime execution
- owned report, checkpoint, cancellation, and commit-sink types
- placeholder family boundaries for ordered-content, git-repo, and distributed execution

The crate no longer depends on a separate scan-driver abstraction. Its
public surface stays stable for callers while the family-specific runtime
loops are wired in behind placeholder entrypoints.

---

## Source File Map

| File | Purpose |
|------|---------|
| `src/lib.rs` | Core types and entrypoints: configs, reports, validation, `scan_fs`, `scan_git`, `scan_fs_with_runtime`, `scan_git_with_runtime` |
| `src/cli.rs` | `scanner-rs scan {fs|git}` parsing, sink selection, runtime dispatch, stderr summary rendering |
| `src/commit_sink.rs` | Local `CommitSink` trait, no-op sink, and durable identity-deriving sink |
| `src/coordination_sink.rs` | Owned event records and recorder trait used by durable persistence plumbing |
| `src/distributed.rs` | Distributed runtime family placeholders and shared config/report types |
| `src/event_sink.rs` | JSONL, text, JSON, and SARIF event sinks |
| `src/git_repo.rs` | Git-repository family placeholder boundary |
| `src/ordered_content.rs` | Ordered-content family placeholder boundary |
| `src/parity.rs` | JSONL canonicalization and parity helpers |
| `src/lib_tests.rs` | Validation and placeholder behavior tests for the runtime core |
| `src/cli_tests.rs` | CLI parsing and summary-rendering tests |
| `Cargo.toml` | Runtime crate dependencies and feature flags |

---

## Architecture

### Runtime entrypoints

The crate exposes two public scan entrypoints:

- `scan_fs(&FsScanConfig) -> Result<ScanReport, ScanRuntimeError>`
- `scan_git(&GitScanConfig) -> Result<ScanReport, ScanRuntimeError>`

Each entrypoint dispatches on `ExecutionMode`, but both `Direct` and
`Connector` currently converge on the same family-facing runtime surface.
The execution-mode flag is retained so callers can preserve their existing
CLI and worker flows while the underlying family loops are implemented.

### Validation-first execution

The runtime performs setup work in a fixed order:

1. Validate the requested path.
2. Validate runtime budgets.
3. Normalize source-specific inputs.
4. Call the source family boundary.

Current behavior after validation:

- filesystem scans route to `ordered_content::filesystem_placeholder`
- git scans route to `git_repo::local_repo_placeholder`
- distributed runs route to `distributed::run_distributed`

Each placeholder returns `ScanRuntimeError::Driver(anyhow::Error)`. The
runtime never uses `todo!()` for unimplemented family paths.

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
- `ScanBudgets.max_items` and `ScanBudgets.max_bytes` must both be non-zero

### Git scans

- `GitScanConfig::repo` must exist
- the path must be a git repository root
- subdirectories of a git repository are rejected so the runtime has a
  stable repository anchor
- `ScanBudgets.max_items` and `ScanBudgets.max_bytes` must both be non-zero

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
    pub committed_items: u64,
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
main report plus optional checkpoint and debug payloads.

### ScanRuntimeError

The runtime error surface has six current categories:

- `InvalidPath`
- `GitCommandFailed`
- `Io`
- `RulesConfig`
- `ConnectorInput`
- `Driver`

`Driver(anyhow::Error)` is the catch-all for family placeholder failures and
other runtime wiring problems.

---

## Commit Sink Surface

`src/commit_sink.rs` defines the local persistence-facing types used by the
runtime:

- `ItemMeta`
- `FindingRecord`
- `FindingsBatch`
- `CommitSink`
- `CliNoOpCommitSink`
- `DurableCommitSink`

`DurableCommitSink` is the bridge between scan-loop item lifecycle events
and persisted identity derivation. It computes:

- normalized secret hash input
- tenant-scoped secret hash
- finding ID
- occurrence ID

When a source does not provide an explicit version, the sink derives a
stable surrogate object version from the item-key bytes.

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
pub fn run_distributed(
    config: &DistributedRunConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError>
```

`run_distributed` validates budgets and then returns a family-specific
placeholder runtime error.

---

## Tests

The runtime tests focus on the behavior that exists today:

- execution-mode parsing
- cancellation-token state transitions
- budget validation
- filesystem path validation
- git repository root validation
- placeholder error routing for filesystem, git, and distributed entrypoints
- CLI parsing and summary formatting
- durable commit-sink identity derivation

These tests intentionally verify placeholder behavior for valid sources so
the crate can evolve without depending on the removed driver stack.

---

## Source of Truth

| Concern | Path |
|---------|------|
| Core runtime types and validation | `crates/gossip-scanner-runtime/src/lib.rs` |
| CLI parsing and summary rendering | `crates/gossip-scanner-runtime/src/cli.rs` |
| Commit sink types and durable identity derivation | `crates/gossip-scanner-runtime/src/commit_sink.rs` |
| Distributed family placeholders | `crates/gossip-scanner-runtime/src/distributed.rs` |
| Ordered-content placeholder boundary | `crates/gossip-scanner-runtime/src/ordered_content.rs` |
| Git-repo placeholder boundary | `crates/gossip-scanner-runtime/src/git_repo.rs` |
| Event sinks | `crates/gossip-scanner-runtime/src/event_sink.rs` |
| JSONL parity helpers | `crates/gossip-scanner-runtime/src/parity.rs` |
