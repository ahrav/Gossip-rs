# gossip-worker

## Module Purpose

`gossip-worker` is the worker package that contains:

- a binary entrypoint that resolves environment variables plus CLI overrides
  into an explicit local or distributed launch path
- a library surface that exposes the worker config module and the production
  composition root for real etcd and PostgreSQL backends

The package owns only:

- worker launch configuration resolution
- tracing initialization
- exit-code policy
- mapping runtime results into structured logs
- construction of concrete real backends for the generic distributed runtime

Neither the binary nor the library implements a scan loop. Local scans
delegate to `gossip-scanner-runtime::{scan_fs, scan_git}`, and distributed
execution delegates to `gossip-scanner-runtime::distributed::run_worker`
through the production composition root.

---

## Behavior

The worker resolves one typed launch configuration from the current process
environment plus CLI overrides.

Specifically:

- invalid configuration fails with exit code `2`
- `ExecutionMode::Direct` always resolves to a local scan path
- `ExecutionMode::Connector` requires explicit backend selection
- `backend=local` resolves to the existing local runtime path
- `backend=production` requires all identity fields plus etcd and PostgreSQL
  backend settings
- `backend=production` never falls back to local or in-memory doubles
- successful local runs log `(items_scanned, bytes_scanned, findings_emitted)`
- successful distributed runs log `(leases_seen, shards_scanned)`

The worker remains a thin shell around the runtime boundary. It parses and
validates launch intent, then dispatches either to local `scan_fs` / `scan_git`
or to `run_production_worker`.

---

## Architecture

```text
gossip-worker
  --> src/main.rs
       --> gossip-worker::config
            --> resolve_worker_config_from_env_and_args(...)
       --> local path:
            --> gossip-scanner-runtime::{scan_fs, scan_git}
       --> distributed path:
            --> gossip-worker::production::run_production_worker(...)
  --> src/lib.rs
       --> src/config.rs
       --> src/production.rs
            --> gossip-coordination-etcd
            --> gossip-done-ledger-postgres
            --> gossip-findings-postgres
            --> gossip-scanner-runtime distributed runtime
```

### Execution flow

```text
gossip-worker [--mode=direct|connector] [--backend=local|production] [fs|git] [path]

main()
  -> init_tracing()
  -> resolve_worker_config_from_env_and_args(...)
  -> match resolved config
     -> Local(cfg)
        -> run_local_worker(&cfg)
           -> scan_fs(...) or scan_git(...)
        -> log_local_report(...)
     -> Distributed(cfg)
        -> run_production_worker(...)
        -> log_distributed_report(...)
```

The default mode and source are `connector fs .`, but connector mode requires
explicit backend selection (`--backend=local` or `--backend=production`).
Omitting the backend fails closed with a configuration error.

### Production composition flow

`run_production_worker` handles connection, migration, and execution in one
call:

```text
caller
  -> ProductionBackendConfig::new(...)
  -> DistributedWorkerConfig::worker_identity()
  -> DistributedWorkerConfig::runtime_config()
  -> run_production_worker(config, identity, runtime)
     -> build_production_backends(config)
        -> EtcdCoordinator::connect(...)
        -> connect_postgres_client(...) [done-ledger]
        -> connect_postgres_client(...) [findings]
     -> apply_migrations() on done_ledger and findings_sink
     -> distributed::run_worker(...)
  -> DistributedRunReport
```

Callers that need more control can build the backends manually with
`build_production_backends` or `build_production_backends_from_clients`.

---

## Environment Variables

All variables are read from the process environment at startup. CLI flags
override environment values when both are present.

| Variable | Format | Default | Required | Description |
|----------|--------|---------|----------|-------------|
| `GOSSIP_WORKER_MODE` | `direct` or `connector` | `connector` | No | Selects the execution mode family. |
| `GOSSIP_WORKER_BACKEND` | `local` or `production` | *(none)* | Yes (connector mode) | Selects the backend for connector mode. Connector mode fails closed without an explicit backend. |
| `GOSSIP_WORKER_SOURCE` | `fs` or `git` | `fs` | No | Selects the source family. Production backend supports only `fs`. |
| `GOSSIP_WORKER_PATH` | filesystem path | `.` | No | Filesystem or git repository path to scan. |
| `GOSSIP_ETCD_ENDPOINTS` | comma-separated URLs | *(none)* | Yes (production) | etcd endpoint CSV for the coordination backend. |
| `GOSSIP_ETCD_NAMESPACE` | string | *(none)* | Yes (production) | etcd namespace prefix for key isolation. |
| `GOSSIP_DONE_LEDGER_POSTGRES_DSN` | PostgreSQL DSN | *(none)* | Yes (production) | Connection string for the done-ledger database. |
| `GOSSIP_FINDINGS_POSTGRES_DSN` | PostgreSQL DSN | *(none)* | Yes (production) | Connection string for the findings database. |
| `GOSSIP_TENANT_ID` | 64 hex chars (32 bytes) | *(none)* | Yes (production) | Tenant identity. Accepts optional `0x` prefix. |
| `GOSSIP_RUN_ID` | unsigned 64-bit integer | *(none)* | Yes (production) | Run identity. |
| `GOSSIP_WORKER_ID` | unsigned 64-bit integer | *(none)* | Yes (production) | Worker identity. |
| `GOSSIP_POLICY_HASH` | 64 hex chars (32 bytes) | *(none)* | Yes (production) | Policy hash for the scan ruleset. Accepts optional `0x` prefix. |
| `GOSSIP_TENANT_SECRET_KEY` | 64 hex chars (32 bytes) | *(none)* | Yes (production) | Tenant secret key. Must not be all zeros. Accepts optional `0x` prefix. |
| `GOSSIP_MAX_ITEMS` | positive integer | `256` | No | Maximum items processed between checkpoints. |
| `GOSSIP_MAX_BYTES` | positive integer | `1000000` | No | Maximum bytes processed between checkpoints (1 MB default). |
| `GOSSIP_COMMIT_QUEUE_CAPACITY` | positive integer | `64` | No | Bounded commit queue capacity for the distributed runtime. |
| `GOSSIP_WORKER_RULES_FILE` | filesystem path | *(none)* | No | Path to an optional rules file. |
| `GOSSIP_WORKER_DECODE_DEPTH` | non-negative integer | *(none)* | No | Maximum decode depth for nested content extraction. |
| `GOSSIP_WORKER_SCAN_BINARY` | boolean | `false` | No | Enable binary file scanning. Accepts `true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`. |
| `GOSSIP_FS_SKIP_ARCHIVES` | boolean | `false` | No | Skip archive expansion during filesystem scans. Same boolean tokens as above. |
| `GOSSIP_WORKER_ANCHOR_MODE` | `manual` or `derived` | `manual` | No | Anchor extraction mode for rule planning. |

---

## CLI Flags

All flags use `--name=value` syntax (equals-sign required; space-separated
`--name value` is rejected). CLI flags override environment variables.

| Flag | Env Variable | Accepted Values |
|------|-------------|-----------------|
| `--mode` | `GOSSIP_WORKER_MODE` | `direct`, `connector` |
| `--backend` | `GOSSIP_WORKER_BACKEND` | `local`, `production` |
| `--source` | `GOSSIP_WORKER_SOURCE` | `fs`, `git` |
| `--path` | `GOSSIP_WORKER_PATH` | filesystem path |
| `--etcd-endpoints` | `GOSSIP_ETCD_ENDPOINTS` | comma-separated URLs |
| `--etcd-namespace` | `GOSSIP_ETCD_NAMESPACE` | string |
| `--done-ledger-postgres-dsn` | `GOSSIP_DONE_LEDGER_POSTGRES_DSN` | PostgreSQL DSN |
| `--findings-postgres-dsn` | `GOSSIP_FINDINGS_POSTGRES_DSN` | PostgreSQL DSN |
| `--tenant-id` | `GOSSIP_TENANT_ID` | 64 hex chars |
| `--run-id` | `GOSSIP_RUN_ID` | u64 |
| `--worker-id` | `GOSSIP_WORKER_ID` | u64 |
| `--policy-hash` | `GOSSIP_POLICY_HASH` | 64 hex chars |
| `--tenant-secret-key` | `GOSSIP_TENANT_SECRET_KEY` | 64 hex chars |
| `--max-items` | `GOSSIP_MAX_ITEMS` | positive integer |
| `--max-bytes` | `GOSSIP_MAX_BYTES` | positive integer |
| `--commit-queue-capacity` | `GOSSIP_COMMIT_QUEUE_CAPACITY` | positive integer |
| `--rules-file` | `GOSSIP_WORKER_RULES_FILE` | filesystem path |
| `--decode-depth` | `GOSSIP_WORKER_DECODE_DEPTH` | non-negative integer |
| `--scan-binary` | `GOSSIP_WORKER_SCAN_BINARY` | boolean |
| `--skip-archives` | `GOSSIP_FS_SKIP_ARCHIVES` | boolean |
| `--anchor-mode` | `GOSSIP_WORKER_ANCHOR_MODE` | `manual`, `derived` |

### Positional arguments

Two optional positional arguments follow the flags:

```text
gossip-worker [flags...] [source] [path]
```

- **`[source]`** -- `fs` or `git`. Conflicts with `--source` if both are given.
- **`[path]`** -- Scan target path. Conflicts with `--path` if both are given.

### Precedence

CLI flags override environment variables unconditionally. When a CLI flag
supplies a valid value, the corresponding environment variable is ignored even
if the environment value is malformed.

---

## Key Types

### BackendSelection

```rust
enum BackendSelection {
    Local,
    Production,
}
```

Selects whether connector mode routes to the local runtime path or to the real
distributed worker path.

### WorkerSourceSettings

```rust
enum WorkerSourceSettings {
    Fs(FsSourceSettings),
    Git(GitSourceSettings),
}
```

Typed source-family settings used by local launches.

### LocalWorkerConfig

```rust
struct LocalWorkerConfig {
    execution_mode: ExecutionMode,
    source: WorkerSourceSettings,
    budgets: ScanBudgets,
}
```

Resolved local launch configuration for filesystem or git scans.

### DistributedWorkerRuntimeSettings

```rust
struct DistributedWorkerRuntimeSettings {
    budgets: ScanBudgets,
    commit_queue_capacity: NonZeroUsize,
}
```

Runtime tuning extracted from worker configuration for the distributed worker
loop.

### DistributedWorkerConfig

```rust
struct DistributedWorkerConfig {
    backends: ProductionBackendConfig,
    identity: WorkerIdentityConfig,
    source: FsSourceSettings,
    runtime: DistributedWorkerRuntimeSettings,
}
```

Resolved real-backend launch configuration. Identity fields (tenant, run,
worker, policy hash, secret key) are grouped in `WorkerIdentityConfig` and
accessible through the `identity()` accessor or individual delegation methods
(`tenant()`, `run()`, etc.). Backend is always `Production` by construction.

### ResolvedWorkerConfig

```rust
enum ResolvedWorkerConfig {
    Local(LocalWorkerConfig),
    Distributed(Box<DistributedWorkerConfig>),
}
```

Final output of configuration resolution. The binary must handle both cases
explicitly.

### WorkerConfigError

```rust
enum WorkerConfigError {
    Usage(String),
    MissingRequiredValue { .. },
    InvalidValue { .. },
    InvalidEtcdConfig(..),
    InvalidBackendConfig(..),
    UnsupportedCombination { .. },
}
```

Typed configuration errors used for argument mistakes, missing required
production fields, validation failures, and unsupported launch combinations.

### NoopCoordinationEventRecorder

No-op implementation of `CoordinationEventRecorder` used when building a
default `WorkerIdentity` from a resolved distributed config.

### ProductionBackendConfig

Validated startup bundle containing the etcd coordination config plus the two
PostgreSQL DSNs used to build the real persistence backends. Debug output
redacts both DSNs so credentials do not leak into logs.

### ProductionRuntimeBackends

Concrete bundle of the live etcd coordinator and persistence handles passed to
the generic distributed runtime.

---

## Functions

| Function | Purpose |
|----------|---------|
| `resolve_worker_config_from_env_and_args()` | Resolve the current environment plus CLI args into one typed launch config |
| `resolve_worker_config_from()` | Resolve a caller-supplied environment provider plus CLI args |
| `run_local_worker()` | Call `scan_fs` or `scan_git` from a resolved local config |
| `log_local_report()` | Emit local success metrics through `tracing::info!` |
| `log_distributed_report()` | Emit distributed success metrics through `tracing::info!` |
| `main()` | Wire together tracing, config resolution, execution, logging, and exit codes |
| `build_production_backends()` | Connect the real etcd and PostgreSQL backends from DSNs |
| `build_production_backends_from_clients()` | Wrap caller-supplied PostgreSQL clients with the real runtime backends |
| `run_production_worker()` | Build backends, apply migrations, and run the distributed runtime |

---

## Tests

The config module checks:

- resolution of a full production config from environment variables alone
- CLI override precedence over environment values
- backend selection failure in connector mode when no backend is configured
- direct-mode fallback to local execution without backend selection
- missing required production identity fields
- rejection of `source=git` for real distributed launches
- secret-key redaction in error and debug output
- hex parsing, prefix handling, length checks, and non-hex rejection
- construction of a valid runtime `WorkerIdentity`

The binary test module checks:

- successful filesystem scans for a valid local path
- successful git scans for a valid repository root

The production module adds:

- config validation for empty PostgreSQL DSNs
- DSN whitespace trimming validation
- debug redaction coverage for secret-bearing DSNs
- error-chain preservation for bootstrap and worker error conversions
- ignored live-backend bootstrap tests that require configured etcd and
  PostgreSQL endpoints

---

## Security Notes

### Secret delivery

Pass secrets exclusively through environment variables. CLI flags like
`--tenant-secret-key`, `--done-ledger-postgres-dsn`, and
`--findings-postgres-dsn` are visible in process listings (`ps aux`,
`/proc/<pid>/cmdline`). Environment variables avoid this exposure.

### TLS for PostgreSQL

The default `connect_postgres_client` connects with `NoTls` and emits a
warning when the target host is not local. For TLS-capable connections, use
`build_production_backends_from_clients`, which accepts pre-configured
`postgres::Client` instances where the caller controls the TLS configuration.

### Debug output

Config types redact sensitive fields (DSNs, tenant secret key) in their
`Debug` implementations. The `TenantSecretKey` type uses constant-time
equality comparison (`subtle::ConstantTimeEq`) to prevent timing
side-channel leakage of key material.

---

## Source of Truth

| Concern | Path |
|---------|------|
| Worker binary entrypoint | `crates/gossip-worker/src/main.rs` |
| Worker config surface | `crates/gossip-worker/src/config.rs` |
| Worker library surface | `crates/gossip-worker/src/lib.rs` |
| Production composition root | `crates/gossip-worker/src/production.rs` |
| Runtime scan entrypoints | `crates/gossip-scanner-runtime/src/lib.rs` |
| Distributed runtime API | `crates/gossip-scanner-runtime/src/distributed.rs` |
