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
       --> src/recorder.rs
            --> CoordinationTelemetrySink (pub(crate) sink trait)
            --> TracingCoordinationTelemetrySink (default structured tracing sink)
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
  -> DistributedWorkerConfig::worker_identity_noop()
     (worker_identity_with_recorder() is available for callers that opt into production telemetry recording)
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

### Coordination telemetry recorder

The `recorder` module provides a production-safe implementation of
`CoordinationEventRecorder` that emits structured telemetry for the
distributed coordination lifecycle. All telemetry output is best-effort:
the distributed runtime continues making progress through the durable commit
pipeline even if the telemetry sink is unavailable.

**Event families.** The recorder handles three categories of coordination
events, each with independent error-suppression tracking:

- **Core** -- scanner-level findings, progress snapshots, summaries, and
  diagnostics.
- **Git** -- commit metadata and identity dictionary entries.
- **Progress** -- commit lifecycle markers (begin/finish).

**Redaction boundary.** Raw events from the runtime contain tenant data, file
paths, git identity bytes, and diagnostic text. Before emission, the recorder
converts every event into a `SanitizedCoordinationRecord` where all such
toxic fields are replaced by `RedactedDigest` values. A `RedactedDigest`
stores `(original_length, 64-bit BLAKE3 hash)` -- enough to correlate
records across workers and gauge payload size without exposing raw bytes.
The digest is a deterministic correlation token, not a cryptographic
secrecy mechanism: the derive-key context is public, so low-entropy fields
are theoretically brute-forceable by someone with log access. The hash is
domain-separated by a fixed derive-key context and further keyed by a
field-level label (e.g. `"shard_id"`, `"item_key"`), so identical byte
sequences in different field positions produce distinct digests.

**Telemetry target.** All recorder output is emitted under the tracing target
`gossip_worker::coordination`, enabling subscribers to filter coordination
telemetry independently from other worker logs.

**Error suppression.** The first sink failure per category (core, git,
progress) emits a warning through the tracing target. Subsequent failures
for the same category are silently absorbed to prevent log flooding during
sustained sink outages.

**Sink extensibility.** The `CoordinationTelemetrySink` trait is `pub(crate)`
and accepts only pre-sanitized records. The default implementation
(`TracingCoordinationTelemetrySink`) emits structured `tracing` events at
appropriate severity levels. Alternative sink backends (metrics, file, etc.)
can be added by implementing this trait without changing the runtime-facing
`CoordinationEventRecorder` contract.

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
| `GOSSIP_RUN_ID` | u64, must be >= 1 | *(none)* | Yes (production) | Run identity. Zero is the unassigned sentinel and is rejected. |
| `GOSSIP_WORKER_ID` | u64, must be >= 1 | *(none)* | Yes (production) | Worker identity. Zero is the unassigned sentinel and is rejected. |
| `GOSSIP_POLICY_HASH` | 64 hex chars (32 bytes) | *(none)* | Yes (production) | Policy hash for the scan ruleset. Accepts optional `0x` prefix. |
| `GOSSIP_TENANT_SECRET_KEY` | 64 hex chars (32 bytes) | *(none)* | Yes (production) | Tenant secret key. Must not be all zeros. Accepts optional `0x` prefix. |
| `GOSSIP_MAX_ITEMS` | 1..10,000,000 | `256` | No | Maximum items processed between checkpoints. |
| `GOSSIP_MAX_BYTES` | 1..64 GiB | `1000000` | No | Maximum bytes processed between checkpoints (1 MB default). |
| `GOSSIP_COMMIT_QUEUE_CAPACITY` | 1..65,536 | `64` | No | Bounded commit queue capacity for the distributed runtime. |
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
| `--run-id` | `GOSSIP_RUN_ID` | u64, >= 1 |
| `--worker-id` | `GOSSIP_WORKER_ID` | u64, >= 1 |
| `--policy-hash` | `GOSSIP_POLICY_HASH` | 64 hex chars |
| `--tenant-secret-key` | `GOSSIP_TENANT_SECRET_KEY` | 64 hex chars |
| `--max-items` | `GOSSIP_MAX_ITEMS` | 1..10,000,000 |
| `--max-bytes` | `GOSSIP_MAX_BYTES` | 1..64 GiB |
| `--commit-queue-capacity` | `GOSSIP_COMMIT_QUEUE_CAPACITY` | 1..65,536 |
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

### ProductionCoordinationEventRecorder

Production recorder implementing `CoordinationEventRecorder`. Sanitizes all
incoming events through the redaction boundary before forwarding to the
configured `CoordinationTelemetrySink`. Sink failures are absorbed with
once-per-category warning suppression so the distributed runtime never blocks
on telemetry availability.

### SanitizedCoordinationRecord

```rust
pub(crate) enum SanitizedCoordinationRecord {
    CoreFinding { .. },
    CoreProgress { .. },
    CoreSummary { .. },
    CoreDiagnostic { .. },
    GitCommitMeta { .. },
    GitIdentityDictionary { .. },
    CommitBegin { .. },
    CommitFinish { .. },
}
```

Eight-variant enum mirroring the three event families of
`CoordinationEventRecorder`. Every field that could contain tenant data, file
paths, git identity bytes, or diagnostic text is stored as a `RedactedDigest`.
Scalar metrics, `&'static str` labels, and integer IDs pass through unchanged.

### RedactedDigest

```rust
pub(crate) struct RedactedDigest {
    len: usize,
    hash64: u64,
}
```

`Copy` type storing `(original_length, 64-bit BLAKE3 hash)`. A deterministic
correlation token that prevents inadvertent exposure of raw field values in
telemetry; not a cryptographic secrecy mechanism (the derive-key context is
public). The hash uses BLAKE3 derive-key mode with a fixed domain context,
and the update stream includes a field-level label so identical payloads in
different field positions produce distinct digests. Display format:
`len=<n>,hash=<016x>`.

### CoordinationTelemetrySink

```rust
pub(crate) trait CoordinationTelemetrySink: Send + Sync {
    fn emit(&self, record: SanitizedCoordinationRecord) -> Result<()>;
}
```

Crate-internal sink trait for sanitized telemetry records. The recorder owns
the sanitization contract: callers outside the crate interact only with
`CoordinationEventRecorder` (which accepts raw events). Alternative sink
backends can be added by implementing this trait without changing the
runtime-facing API.

### TracingCoordinationTelemetrySink

Default sink used by `ProductionCoordinationEventRecorder`. Emits each
`SanitizedCoordinationRecord` variant as a structured `tracing` event at an
appropriate severity level (`info!` for summaries, `debug!` for findings and
progress, `trace!` for git metadata and commit lifecycle, and level-matched
output for diagnostics).

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

The production module includes:

- config validation for empty PostgreSQL DSNs
- DSN whitespace trimming validation
- debug redaction coverage for secret-bearing DSNs
- error-chain preservation for bootstrap and worker error conversions
- ignored live-backend bootstrap tests that require configured etcd and
  PostgreSQL endpoints

The recorder module checks:

- `redacted_digest_distinguishes_same_length_inputs_and_field_labels` --
  verifies that same-length inputs with different content produce distinct
  hashes, and that identical content under different field labels produces
  distinct hashes (digest separation across the label/payload domain)
- `sanitized_records_hash_toxic_fields` -- exhaustive variant coverage
  confirming every toxic field across all eight `SanitizedCoordinationRecord`
  variants is replaced by a `RedactedDigest` that does not contain the raw input
- `tracing_sink_never_logs_raw_canary_bytes` -- end-to-end canary test that
  exercises all event types through the default `TracingCoordinationTelemetrySink`,
  captures the tracing output, and asserts the canary string never appears in
  the log stream while all expected event names are present
- `recorder_suppresses_repeated_sink_failures_per_category` -- injects a
  `FailingSink` that always returns `Err`, fires four events per category
  (core, git, progress), and asserts exactly three warning lines appear (one
  per category) with no raw canary leakage

---

## Security Notes

### Secret delivery

Pass secrets exclusively through environment variables. CLI flags like
`--tenant-secret-key`, `--done-ledger-postgres-dsn`, and
`--findings-postgres-dsn` are visible in process listings (`ps aux`,
`/proc/<pid>/cmdline`). Environment variables avoid this exposure.

### TLS for PostgreSQL

The default `connect_postgres_client` connects with `NoTls` and performs a
best-effort warning when the parsed target host appears non-local. For
TLS-capable connections, use
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
| Coordination telemetry recorder | `crates/gossip-worker/src/recorder.rs` |
| Production composition root | `crates/gossip-worker/src/production.rs` |
| Runtime scan entrypoints | `crates/gossip-scanner-runtime/src/lib.rs` |
| Distributed runtime API | `crates/gossip-scanner-runtime/src/distributed.rs` |
