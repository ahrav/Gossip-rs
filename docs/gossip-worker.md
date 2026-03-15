# gossip-worker

## Module Purpose

`gossip-worker` is the lightweight worker binary that drives one scan
request through `gossip-scanner-runtime`. It owns only:

- a minimal positional CLI grammar
- tracing initialization
- exit-code policy
- mapping runtime results into structured logs

The binary does not implement its own scan loop. It delegates filesystem
and git requests directly to the runtime crate.

---

## Current Behavior

The worker accepts valid filesystem and git scan requests, forwards them to
the runtime, and surfaces runtime errors unchanged through `WorkerError`.

Today that means:

- invalid CLI arguments fail with exit code `2`
- valid scan requests reach the runtime and currently fail with a
  family-specific placeholder error
- successful logging paths remain available for when the family runtime
  loops are implemented

This keeps the worker binary aligned with the current runtime surface
instead of preserving a removed driver-based execution path.

---

## Architecture

```text
gossip-worker
  --> gossip-scanner-runtime
       --> ordered-content family placeholder
       --> git-repo family placeholder
       --> distributed runtime placeholder types
       --> event and commit sink support types
```

### Execution flow

```text
gossip-worker [--mode=direct|connector] [fs|git] [path]

main()
  -> init_tracing()
  -> parse_args(...)
  -> run_worker(&cfg)
     -> scan_fs(...) or scan_git(...)
  -> log_report(...) on success
```

The default configuration is still `connector fs .`, which keeps the worker
and CLI entrypoints aligned on the same runtime-family surface.

---

## Key Types

### WorkerSource

```rust
enum WorkerSource {
    Fs,
    Git,
}
```

Selects which runtime entrypoint the worker will call.

### WorkerConfig

```rust
struct WorkerConfig {
    source: WorkerSource,
    path: PathBuf,
    execution_mode: ExecutionMode,
}
```

Small, crate-private config assembled from worker CLI arguments.

### WorkerError

```rust
enum WorkerError {
    Usage(String),
    Runtime(ScanRuntimeError),
}
```

Encodes the two failure classes the worker cares about: local argument
errors and delegated runtime failures.

---

## Functions

| Function | Purpose |
|----------|---------|
| `init_tracing()` | Initialize compact tracing output with `RUST_LOG` support |
| `usage()` | Return the stable worker help text |
| `parse_mode_flag()` | Parse `--mode=direct` or `--mode=connector` |
| `parse_source()` | Parse `fs` or `git` into `WorkerSource` |
| `parse_args()` | Build `WorkerConfig` from positional worker arguments |
| `run_worker()` | Call `scan_fs` or `scan_git` and map the result into `(items, bytes, findings)` |
| `log_report()` | Emit success metrics through `tracing::info!` |
| `main()` | Wire together tracing, parsing, execution, logging, and exit codes |

---

## Tests

The worker test module currently checks:

- default parsing
- explicit `git` path parsing with mode override
- rejection of unknown sources
- placeholder runtime error for a valid filesystem path
- placeholder runtime error for a valid git repository root

The runtime-placeholder assertions are intentional. They confirm that the
worker is wired to the current runtime behavior rather than to the removed
driver-backed scan path.

---

## Source of Truth

| Concern | Path |
|---------|------|
| Worker entrypoint, parsing, and tests | `crates/gossip-worker/src/main.rs` |
| Runtime scan entrypoints | `crates/gossip-scanner-runtime/src/lib.rs` |
| Distributed runtime placeholders | `crates/gossip-scanner-runtime/src/distributed.rs` |
