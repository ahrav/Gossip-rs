# gossip-worker

## 1. Module Purpose

The `gossip-worker` crate is the **distributed worker binary** for the
gossip-rs secret scanning system. It is one of two top-level binaries in
the workspace (the other being `scanner-rs-cli`), sitting at **Tier 3** of
the build DAG.

The binary is intentionally minimal (~306 lines including tests). It accepts
a scan source type, a target path, and an execution mode, then delegates all
scanning logic to `gossip-scanner-runtime`. It owns only CLI argument
parsing, process lifecycle (exit codes), and tracing initialization.

### Distinction from scanner-rs-cli

| Aspect | `gossip-worker` | `scanner-rs-cli` |
|--------|-----------------|-------------------|
| Role | Distributed worker entrypoint | Standalone user-facing CLI |
| Default mode | `Connector` | `Direct` |
| CLI grammar | Minimal positional args | Full flag/subcommand parser |
| Output | Structured tracing logs | JSONL/Text/JSON/SARIF to stdout |
| Finding output | Log summary only | Per-finding event stream |
| Designed for | Orchestration-invoked scans | Interactive developer use |

The worker defaults to `Connector` execution mode so that both entrypoints
exercise the same scan-driver seam. In the future, it will evolve to consume
shard leases from a coordinator (the `DistributedCoordinator` trait and
`run_worker` loop already exist in `gossip-scanner-runtime::distributed`).

---

## 2. Source File Map

| File | Purpose |
|------|---------|
| `src/main.rs` | Entire crate: CLI parsing, scan dispatch, tracing, error handling, tests (~306 lines) |
| `Cargo.toml` | Manifest: depends on `gossip-scanner-runtime`, `tracing`, `tracing-subscriber` |

There is no `lib.rs` -- this is a pure binary crate with no public API.

---

## 3. Architecture

```text
gossip-worker (Tier 3 binary)
  --> gossip-scanner-runtime (Tier 2: unified scan orchestration)
       --> gossip-scan-driver (traits: Assignment, ScanDriver, ScanSourceFactory)
       --> gossip-connectors (concrete FS/Git scan drivers)
       --> scanner-engine (detection rules, transforms, engine)
       --> scanner-scheduler (execution scheduling)
       --> scanner-git (git-specific scanning)
       --> gossip-contracts (identity types, coordination types, connector types)
```

### Execution flow

```text
CLI invocation:  gossip-worker [--mode=direct|connector] [fs|git] [path]

main()
  |
  +--> init_tracing()          -- tracing-subscriber with RUST_LOG env filter
  |
  +--> parse_args(args)        -- parse CLI into WorkerConfig
  |     |
  |     +--> parse_mode_flag() -- if --mode= prefix present
  |     +--> parse_source()    -- if source positional present
  |
  +--> run_worker(&cfg)
  |     |
  |     +--> (Fs) scan_fs(&FsScanConfig { path, mode, budgets })
  |     |
  |     +--> (Git) scan_git(&GitScanConfig { repo, mode, budgets })
  |
  +--> log_report()            -- structured tracing::info! with scan metrics
```

### Exit codes

| Code | Meaning |
|:----:|---------|
| 0 | Scan completed successfully |
| 1 | Scan execution failed |
| 2 | Invalid CLI arguments |

---

## 4. CLI Grammar

```text
gossip-worker [--mode=direct|connector] [fs|git] [path]
```

**Defaults:** `--mode=connector fs .`

| Form | Example | Behavior |
|------|---------|----------|
| No arguments | `gossip-worker` | Connector mode, FS scan, current directory |
| Path only | `gossip-worker /data` | Connector mode, FS scan at `/data` |
| Source + path | `gossip-worker git /repo` | Connector mode, Git scan at `/repo` |
| Full | `gossip-worker --mode=direct fs /data` | Direct mode, FS scan at `/data` |

More than 2 positional arguments produces an error (exit code 2).

---

## 5. Key Types

All types are **crate-private** (no `pub` visibility outside the binary).

### WorkerSource

```rust
enum WorkerSource { Fs, Git }
```

Selects between filesystem and git repository scanning.

### WorkerConfig

```rust
struct WorkerConfig {
    source: WorkerSource,          // Fs or Git
    path: PathBuf,                 // Target path to scan
    execution_mode: ExecutionMode, // Direct or Connector (default: Connector)
}
```

### WorkerError

```rust
enum WorkerError {
    Usage(String),                 // CLI argument parsing errors
    Runtime(ScanRuntimeError),     // Scan execution errors
}
```

Implements `Display`, `Error`, and `From<ScanRuntimeError>`.

---

## 6. Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `init_tracing()` | `fn init_tracing()` | Initialize tracing-subscriber with compact format and `RUST_LOG` env filter (default: `info`) |
| `usage()` | `fn usage() -> &'static str` | Return help string |
| `parse_mode_flag(flag)` | `fn parse_mode_flag(&str) -> Result<ExecutionMode, WorkerError>` | Parse `--mode=direct\|connector` flag |
| `parse_source(value)` | `fn parse_source(&str) -> Result<WorkerSource, WorkerError>` | Map `"fs"` / `"git"` to `WorkerSource` |
| `parse_args(args)` | `fn parse_args<I: IntoIterator>(I) -> Result<WorkerConfig, WorkerError>` | Parse CLI arguments into config |
| `run_worker(cfg)` | `fn run_worker(&WorkerConfig) -> Result<(u64, u64, u64), WorkerError>` | Execute one scan, return `(items, bytes, findings)` |
| `log_report(cfg, report)` | `fn log_report(&WorkerConfig, (u64, u64, u64))` | Emit structured `tracing::info!` log |
| `main()` | `fn main()` | Binary entrypoint: init, parse, scan, report |

---

## 7. Dependencies

### Direct

| Dependency | Purpose |
|------------|---------|
| `gossip-scanner-runtime` (workspace) | `ExecutionMode`, `FsScanConfig`, `GitScanConfig`, `ScanRuntimeError`, `ScanBudgets`, `scan_fs`, `scan_git` |
| `tracing` (workspace) | Structured logging macros |
| `tracing-subscriber` (workspace) | Tracing initialization with env-filter |

### Dev

| Dependency | Purpose |
|------------|---------|
| `tempfile = "3"` | Temporary directories for integration tests |

### Feature Flags

| Feature | Effect |
|---------|--------|
| `aegis-pure-rust` | Cascades to `gossip-scanner-runtime/aegis-pure-rust` for pure-Rust engine (no vectorscan FFI) |

---

## 8. Tests

Five tests in an inline `#[cfg(test)]` module:

| Test | Verifies |
|------|----------|
| `parse_args_defaults_to_connector_fs_current_dir` | Default config: `Fs`, `.`, `Connector` |
| `parse_args_supports_explicit_git_path_and_mode` | `--mode=direct git /tmp/repo` parsed correctly |
| `parse_args_rejects_unknown_source` | `unknown /tmp/path` returns `WorkerError` |
| `run_worker_scans_filesystem_path` | FS scan of temp dir with secret produces findings |
| `run_worker_scans_git_repo_path` | Git scan of temp repo with committed secret produces findings |

All tests use `tempfile::tempdir()` for isolated filesystem state.

---

## 9. Design Notes

- **Minimal binary, maximal delegation.** All scan logic lives in
  `gossip-scanner-runtime`. The worker owns only CLI parsing, process
  lifecycle, and tracing.
- **Connector mode by default.** Ensures parity with distributed
  deployment expectations.
- **Single-shot design (current).** Runs exactly one scan per invocation.
  The distributed worker loop in `gossip-scanner-runtime::distributed`
  is not yet wired in.
- **Default scan budgets.** Uses `ScanBudgets::default()` (256 max items,
  1 MB max bytes), appropriate for integration testing.

---

## 10. Source of Truth

| Concern | Path |
|---------|------|
| Binary entrypoint, CLI parsing, tests | `crates/gossip-worker/src/main.rs` |
| Scan orchestration | `crates/gossip-scanner-runtime/src/lib.rs` |
| Distributed worker loop (planned) | `crates/gossip-scanner-runtime/src/distributed.rs` |
