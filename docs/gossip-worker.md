# gossip-worker

## Module Purpose

`gossip-worker` is the worker package that contains:

- a lightweight binary entrypoint for local filesystem and git scans
- a library surface that exposes the production composition root for real
  etcd and PostgreSQL backends

The package owns only:

- a minimal positional CLI grammar
- tracing initialization
- exit-code policy
- mapping runtime results into structured logs
- construction of concrete real backends for the generic distributed runtime

Neither the binary nor the library implements a scan loop. The binary
delegates local filesystem and git requests directly to the runtime crate,
and the library delegates distributed execution to
`gossip-scanner-runtime::distributed::run_worker`.

---

## Behavior

The local binary accepts valid filesystem and git scan requests, forwards
them to the runtime, and surfaces runtime errors unchanged through
`WorkerError`.

Specifically:

- invalid CLI arguments fail with exit code `2`
- valid filesystem and git scan requests execute through the runtime's
  local scan loops
- successful runs log `(items_scanned, bytes_scanned, findings_emitted)`
  through `tracing`
- the package also exposes a production-only composition module that
  constructs `EtcdCoordinator`, `DoneLedgerPg`, and `FindingsSinkPg`
  without coupling those concrete types into the runtime crate

The binary remains a thin local CLI shell, and the library holds the
real-backend bootstrap layer for distributed execution.

---

## Architecture

```text
gossip-worker
  --> src/main.rs
       --> gossip-scanner-runtime local scan entrypoints
  --> src/lib.rs
       --> src/production.rs
            --> gossip-coordination-etcd
            --> gossip-done-ledger-postgres
            --> gossip-findings-postgres
            --> gossip-scanner-runtime distributed runtime
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

The default configuration is `connector fs .`, which keeps the worker
and CLI entrypoints aligned on the same runtime-family surface.

### Production composition flow

Two entry points serve different levels of control:

**Convenience path** — `run_production_worker` handles connection,
migration, and execution in one call:

```text
caller
  -> ProductionBackendConfig::new(...)
  -> run_production_worker(config, identity, runtime)
     -> build_production_backends(config)
        -> EtcdCoordinator::connect(...)
        -> connect_postgres_client(...) [done-ledger, 30 s timeout fallback]
        -> connect_postgres_client(...) [findings, 30 s timeout fallback]
     -> apply_migrations() on done_ledger and findings_sink
     -> distributed::run_worker(...)
  -> DistributedRunReport
```

**Manual path** — callers that need TLS, custom clients, or separate
migration tooling compose the steps themselves:

```text
caller
  -> build_production_backends(config)
     or build_production_backends_from_clients(etcd_config, done_ledger_client, findings_client)
  -> backends.persistence().done_ledger.apply_migrations()
  -> backends.persistence().findings_sink.apply_migrations()
  -> backends.run(identity, runtime)
     -> distributed::run_worker(...)
  -> DistributedRunReport
```

The production module is additive only. The binary uses the local scan
path; the composition root is available for callers that build the
distributed worker externally.

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

### ProductionBackendConfig

Validated startup bundle containing the etcd coordination config plus the
two PostgreSQL DSNs used to build the real persistence backends. Debug
output redacts both DSNs so credentials do not leak into logs.

### ProductionBootstrapError

Typed startup failure classification for the production composition root.
Each variant identifies which backend failed during construction or
migration (`done-ledger`, `findings`, or `etcd`).

### ProductionWorkerError

Top-level error returned by `run_production_worker`. Distinguishes startup
failures (before any shard work) from runtime failures (after backends
connected successfully).

### ProductionBackendConfigError

Validation error returned by `ProductionBackendConfig::new` when either
PostgreSQL DSN is empty after trimming whitespace.

### ProductionRuntimeBackends

Concrete bundle of the live etcd coordinator and persistence handles
passed to the generic distributed runtime.

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
| `build_production_backends()` | Connect the real etcd and PostgreSQL backends from DSNs |
| `build_production_backends_from_clients()` | Wrap caller-supplied PostgreSQL clients with the real runtime backends |
| `run_production_worker()` | Build backends, apply migrations, and run the distributed runtime |

---

## Tests

The worker binary test module checks:

- default parsing
- explicit `git` path parsing with mode override
- rejection of unknown sources
- successful filesystem scans for a valid local path
- successful git scans for a valid repository root

These assertions confirm that the worker stays wired to the runtime's live
filesystem and git execution paths rather than to a removed driver-backed
scan path.

The production module adds:

- config validation for empty PostgreSQL DSNs
- DSN whitespace trimming validation
- debug redaction coverage for secret-bearing DSNs
- error-chain preservation for bootstrap and worker error conversions
- ignored live-backend bootstrap tests that require either Docker-backed
  testcontainers or externally configured etcd/PostgreSQL endpoints

---

## Source of Truth

| Concern | Path |
|---------|------|
| Worker binary entrypoint, parsing, and tests | `crates/gossip-worker/src/main.rs` |
| Worker library surface | `crates/gossip-worker/src/lib.rs` |
| Production composition root | `crates/gossip-worker/src/production.rs` |
| Runtime scan entrypoints | `crates/gossip-scanner-runtime/src/lib.rs` |
| Distributed runtime API | `crates/gossip-scanner-runtime/src/distributed.rs` |
