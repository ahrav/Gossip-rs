//! Production composition root for the distributed worker.
//!
//! This module is the thin outer layer that binds the generic distributed
//! runtime to the real infrastructure backends used in production:
//!
//! - [`gossip_coordination_etcd::EtcdCoordinator`]
//! - [`gossip_done_ledger_postgres::DoneLedgerPg`]
//! - [`gossip_findings_postgres::FindingsSinkPg`]
//!
//! The core runtime stays generic over `CoordinationFacade`, `DoneLedger`, and
//! `FindingsSink`. This module owns startup wiring, schema readiness
//! validation, and typed startup error classification.
//!
//! The DSN-based convenience constructor in this module uses
//! [`postgres::NoTls`]. That is appropriate for local deployments and
//! integration tests where the worker talks to a trusted local PostgreSQL
//! instance. Callers that need TLS or custom PostgreSQL connection handling
//! should connect clients themselves and use
//! [`build_production_backends_from_clients`].

use std::error::Error;
use std::fmt;

use crate::config::ProductionBackendConfig;
use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig, EtcdCoordinatorError};
use gossip_done_ledger_postgres::{
    DoneLedgerPg, DoneLedgerPgMigrationError, EmbeddedMigration,
    MIGRATIONS as DONE_LEDGER_MIGRATIONS, apply_all_migrations as apply_done_ledger_migrations,
    schema as done_ledger_schema,
};
use gossip_findings_postgres::{
    FindingsPgMigrationError, FindingsSinkPg, MIGRATIONS as FINDINGS_MIGRATIONS,
    apply_all_migrations as apply_findings_migrations, schema as findings_schema,
};
use gossip_scanner_runtime::distributed::{
    DistributedPersistence, DistributedRunReport, DistributedRuntimeConfig,
    DistributedRuntimeError, WorkerIdentity, run_worker,
};
use postgres::{Client, NoTls};

/// Schema-readiness mode applied during backend bootstrap.
///
/// `Validate` is the production default. It fails closed when the required
/// tables or migration history are absent. `DevAutoMigrate` is intended for
/// local development and integration workflows where applying the embedded
/// migrations on boot is acceptable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StartupSchemaMode {
    /// Require both PostgreSQL schemas to already exist and match the embedded
    /// migration history.
    #[default]
    Validate,
    /// Apply embedded migrations before validating readiness.
    DevAutoMigrate,
}

impl fmt::Display for StartupSchemaMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validate => f.write_str("validate"),
            Self::DevAutoMigrate => f.write_str("dev-auto-migrate"),
        }
    }
}

/// Startup-time readiness and migration policy for real backend boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionStartupSettings {
    schema_mode: StartupSchemaMode,
}

impl ProductionStartupSettings {
    /// Construct one startup policy bundle.
    #[must_use]
    pub fn new(schema_mode: StartupSchemaMode) -> Self {
        Self { schema_mode }
    }

    /// Fail-closed startup: both PostgreSQL schemas and their migration
    /// history must already exist and match the embedded checksums.
    #[must_use]
    pub fn validate_only() -> Self {
        Self::new(StartupSchemaMode::Validate)
    }

    /// Development startup: apply embedded migrations first, then validate.
    /// Not intended for production — external migration tooling should own
    /// schema state there.
    #[must_use]
    pub fn dev_auto_migrate() -> Self {
        Self::new(StartupSchemaMode::DevAutoMigrate)
    }

    /// Selected schema-readiness mode.
    #[inline]
    #[must_use]
    pub fn schema_mode(self) -> StartupSchemaMode {
        self.schema_mode
    }
}

/// Readiness failure for a PostgreSQL schema.
///
/// Readiness validation checks two things: (1) every required table exists
/// in the current schema, and (2) the migration history table contains a row
/// for every embedded migration version whose BLAKE3 checksum matches the
/// compiled-in digest.
#[derive(Debug)]
pub enum ProductionSchemaReadinessError {
    /// A SQL query required for readiness validation failed.
    Query(postgres::Error),
    /// An expected table is missing from the current schema.
    MissingTable { table: &'static str },
    /// An expected migration history row is absent.
    MissingAppliedMigration {
        history_table: &'static str,
        version: &'static str,
    },
    /// A stored checksum row is not the expected 32 bytes.
    CorruptedAppliedMigration {
        history_table: &'static str,
        version: &'static str,
        found_len: usize,
    },
    /// A stored checksum does not match the embedded migration source.
    MigrationChecksumMismatch {
        history_table: &'static str,
        version: &'static str,
    },
}

impl fmt::Display for ProductionSchemaReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(source) => write!(f, "schema readiness query failed: {source}"),
            Self::MissingTable { table } => {
                write!(
                    f,
                    "required table '{table}' is missing from the current schema"
                )
            }
            Self::MissingAppliedMigration {
                history_table,
                version,
            } => write!(
                f,
                "migration history table '{history_table}' is missing required version '{version}'"
            ),
            Self::CorruptedAppliedMigration {
                history_table,
                version,
                found_len,
            } => write!(
                f,
                "migration history table '{history_table}' stores a corrupted checksum for version '{version}' ({found_len} bytes)"
            ),
            Self::MigrationChecksumMismatch {
                history_table,
                version,
            } => write!(
                f,
                "migration history table '{history_table}' does not match the embedded checksum for version '{version}'"
            ),
        }
    }
}

impl Error for ProductionSchemaReadinessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Query(source) => Some(source),
            Self::MissingTable { .. }
            | Self::MissingAppliedMigration { .. }
            | Self::CorruptedAppliedMigration { .. }
            | Self::MigrationChecksumMismatch { .. } => None,
        }
    }
}

impl From<postgres::Error> for ProductionSchemaReadinessError {
    fn from(value: postgres::Error) -> Self {
        Self::Query(value)
    }
}

/// Typed startup failures for the production composition root.
///
/// Each variant identifies which backend connection or migration step
/// failed during construction.
pub enum ProductionBootstrapError {
    /// Establishing the done-ledger PostgreSQL connection failed.
    DoneLedgerConnect(postgres::Error),
    /// Establishing the findings PostgreSQL connection failed.
    FindingsConnect(postgres::Error),
    /// Connecting the etcd coordinator failed.  `EtcdCoordinator::connect`
    /// validates cluster health as part of the connection handshake, so this
    /// variant also covers unreachable-after-connect scenarios.
    EtcdConnect(EtcdCoordinatorError),
    /// The done-ledger schema is not ready for worker startup.
    DoneLedgerSchemaReadiness(ProductionSchemaReadinessError),
    /// The findings schema is not ready for worker startup.
    FindingsSchemaReadiness(ProductionSchemaReadinessError),
    /// Development auto-migration of the done-ledger schema failed.
    DoneLedgerAutoMigrate(DoneLedgerPgMigrationError),
    /// Development auto-migration of the findings schema failed.
    FindingsAutoMigrate(FindingsPgMigrationError),
}

impl fmt::Display for ProductionBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Connection-error arms intentionally omit the inner source.
            // Driver error messages may echo DSN fragments (hostname, port,
            // username) that the config layer redacts elsewhere. Both Display
            // and Error::source() suppress the inner value so that error chain
            // formatters (anyhow, eyre, tracing-error) cannot bypass redaction.
            Self::DoneLedgerConnect(_) => {
                f.write_str("failed to connect done-ledger PostgreSQL backend")
            }
            Self::FindingsConnect(_) => {
                f.write_str("failed to connect findings PostgreSQL backend")
            }
            Self::EtcdConnect(_) => f.write_str("failed to connect etcd coordination backend"),
            Self::DoneLedgerSchemaReadiness(source) => write!(
                f,
                "done-ledger PostgreSQL schema is not ready for worker startup: {source}"
            ),
            Self::FindingsSchemaReadiness(source) => write!(
                f,
                "findings PostgreSQL schema is not ready for worker startup: {source}"
            ),
            // Auto-migrate variants expose the inner error without redaction:
            // DevAutoMigrate runs only in local development environments where
            // DSN exposure is acceptable, and the full migration error context
            // is essential for diagnosing schema application failures.
            Self::DoneLedgerAutoMigrate(source) => {
                write!(f, "done-ledger PostgreSQL auto-migrate failed: {source}")
            }
            Self::FindingsAutoMigrate(source) => {
                write!(f, "findings PostgreSQL auto-migrate failed: {source}")
            }
        }
    }
}

impl Error for ProductionBootstrapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            // Connection variants return `None` to prevent DSN fragment leakage
            // through error chain formatters (anyhow, eyre, tracing-error).
            // Display already redacts the inner source for these variants;
            // returning it here would let `.source()` walkers bypass that.
            Self::DoneLedgerConnect(_) => None,
            Self::FindingsConnect(_) => None,
            Self::EtcdConnect(_) => None,
            Self::DoneLedgerSchemaReadiness(source) => Some(source),
            Self::FindingsSchemaReadiness(source) => Some(source),
            Self::DoneLedgerAutoMigrate(source) => Some(source),
            Self::FindingsAutoMigrate(source) => Some(source),
        }
    }
}

impl fmt::Debug for ProductionBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Connection variants redact the inner error to prevent DSN fragment
            // leakage through `{:?}` formatting (logs, anyhow, panic output).
            Self::DoneLedgerConnect(_) => f
                .debug_tuple("DoneLedgerConnect")
                .field(&"[redacted]")
                .finish(),
            Self::FindingsConnect(_) => f
                .debug_tuple("FindingsConnect")
                .field(&"[redacted]")
                .finish(),
            Self::EtcdConnect(_) => f.debug_tuple("EtcdConnect").field(&"[redacted]").finish(),
            Self::DoneLedgerSchemaReadiness(e) => {
                f.debug_tuple("DoneLedgerSchemaReadiness").field(e).finish()
            }
            Self::FindingsSchemaReadiness(e) => {
                f.debug_tuple("FindingsSchemaReadiness").field(e).finish()
            }
            Self::DoneLedgerAutoMigrate(e) => {
                f.debug_tuple("DoneLedgerAutoMigrate").field(e).finish()
            }
            Self::FindingsAutoMigrate(e) => f.debug_tuple("FindingsAutoMigrate").field(e).finish(),
        }
    }
}

/// Error returned by the real worker entrypoint.
pub enum ProductionWorkerError {
    /// Backend construction failed before any shard work started.
    Startup(ProductionBootstrapError),
    /// The generic distributed runtime failed after startup succeeded.
    Runtime(DistributedRuntimeError),
}

impl fmt::Display for ProductionWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Startup(source) => write!(f, "worker startup failed: {source}"),
            Self::Runtime(source) => write!(f, "worker runtime failed: {source}"),
        }
    }
}

impl Error for ProductionWorkerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Startup(source) => Some(source),
            Self::Runtime(source) => Some(source),
        }
    }
}

impl fmt::Debug for ProductionWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Startup(e) => f.debug_tuple("Startup").field(e).finish(),
            Self::Runtime(e) => f.debug_tuple("Runtime").field(e).finish(),
        }
    }
}

impl From<ProductionBootstrapError> for ProductionWorkerError {
    fn from(value: ProductionBootstrapError) -> Self {
        Self::Startup(value)
    }
}

impl From<DistributedRuntimeError> for ProductionWorkerError {
    fn from(value: DistributedRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// Concrete real backend handles ready to be passed into the generic runtime.
#[derive(Debug)]
pub struct ProductionRuntimeBackends {
    coordinator: EtcdCoordinator,
    persistence: DistributedPersistence<FindingsSinkPg, DoneLedgerPg>,
}

impl ProductionRuntimeBackends {
    /// Borrow the live etcd coordinator.
    #[inline]
    #[must_use]
    pub fn coordinator(&self) -> &EtcdCoordinator {
        &self.coordinator
    }

    /// Borrow the live etcd coordinator mutably.
    #[inline]
    pub fn coordinator_mut(&mut self) -> &mut EtcdCoordinator {
        &mut self.coordinator
    }

    /// Borrow the live PostgreSQL persistence handles.
    #[inline]
    #[must_use]
    pub fn persistence(&self) -> &DistributedPersistence<FindingsSinkPg, DoneLedgerPg> {
        &self.persistence
    }

    /// Borrow the live PostgreSQL persistence handles mutably.
    #[inline]
    pub fn persistence_mut(&mut self) -> &mut DistributedPersistence<FindingsSinkPg, DoneLedgerPg> {
        &mut self.persistence
    }

    /// Consume the bundle into its concrete backend parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        EtcdCoordinator,
        DistributedPersistence<FindingsSinkPg, DoneLedgerPg>,
    ) {
        (self.coordinator, self.persistence)
    }

    /// Run the generic distributed worker loop on the real backends.
    ///
    /// # Errors
    ///
    /// Returns [`DistributedRuntimeError`] when shard claiming, scan
    /// execution, durable commit handling, or lease completion fails.
    pub fn run(
        mut self,
        identity: WorkerIdentity,
        runtime: DistributedRuntimeConfig,
    ) -> Result<DistributedRunReport, DistributedRuntimeError> {
        run_worker(&mut self.coordinator, identity, self.persistence, runtime)
    }
}

/// Build the real backend bundle from a DSN-based config.
///
/// This helper uses [`postgres::NoTls`]. Callers that need TLS or custom
/// connection setup should use [`build_production_backends_from_clients`].
///
/// Every code path is fail-closed: no branch falls back to in-memory
/// coordination, in-memory persistence, or a no-op commit path.
/// The supplied startup policy determines whether PostgreSQL schemas must
/// already exist (`Validate`) or may be auto-migrated first
/// (`DevAutoMigrate`).
///
/// # Errors
///
/// Returns [`ProductionBootstrapError`] when either PostgreSQL connection
/// fails, the etcd coordinator cannot be constructed or remain healthy, or
/// the selected schema-readiness policy fails.
///
/// # Panics
///
/// Panics if called from within an active Tokio runtime.
/// [`EtcdCoordinator::connect`] asserts that no Tokio runtime is active
/// before building its own single-threaded runtime.
pub fn build_production_backends(
    config: &ProductionBackendConfig,
    startup: ProductionStartupSettings,
) -> Result<ProductionRuntimeBackends, ProductionBootstrapError> {
    // Connect both PostgreSQL databases in parallel. Each connection carries
    // a 5-second default timeout, so overlapping them cuts worst-case
    // connection time from 10s to 5s.
    let dl_dsn = config.done_ledger_postgres_dsn().to_owned();
    let f_dsn = config.findings_postgres_dsn().to_owned();

    let dl_handle = std::thread::spawn(move || connect_postgres_client(&dl_dsn));
    let f_handle = std::thread::spawn(move || connect_postgres_client(&f_dsn));

    // Join both threads before propagating errors. If only the first result
    // were inspected with `?`, an early return would drop the second
    // `JoinHandle`, detaching a thread that may still be blocked in
    // `Client::connect`. Under repeated startup retries the leaked threads
    // accumulate and consume process resources.
    let dl_result = dl_handle
        .join()
        .expect("done-ledger connection thread should not panic");
    let f_result = f_handle
        .join()
        .expect("findings connection thread should not panic");

    let done_ledger_client = dl_result.map_err(ProductionBootstrapError::DoneLedgerConnect)?;
    let findings_client = f_result.map_err(ProductionBootstrapError::FindingsConnect)?;

    build_production_backends_from_clients(
        config.etcd().clone(),
        done_ledger_client,
        findings_client,
        startup,
    )
}

/// Build the real backend bundle from already-connected PostgreSQL clients.
///
/// This is the preferred constructor when the caller needs TLS, custom socket
/// options, or connection pooling policy outside this crate.
///
/// Every code path is fail-closed: no branch falls back to in-memory
/// coordination, in-memory persistence, or a no-op commit path.
///
/// # Errors
///
/// Returns [`ProductionBootstrapError`] when the etcd coordinator rejects
/// the config (connection includes a cluster health check) or either
/// PostgreSQL schema does not satisfy the supplied startup policy.
///
/// # Panics
///
/// Panics if called from within an active Tokio runtime.
/// [`EtcdCoordinator::connect`] asserts that no Tokio runtime is active
/// before building its own single-threaded runtime.
pub fn build_production_backends_from_clients(
    etcd: EtcdCoordinatorConfig,
    mut done_ledger_client: Client,
    mut findings_client: Client,
    startup: ProductionStartupSettings,
) -> Result<ProductionRuntimeBackends, ProductionBootstrapError> {
    tracing::info!(schema_mode = %startup.schema_mode(), "applying startup schema policy");

    let coordinator = EtcdCoordinator::connect(etcd).map_err(|err| {
        tracing::warn!(error = %err, "etcd coordinator connection failed");
        ProductionBootstrapError::EtcdConnect(err)
    })?;
    prepare_done_ledger_backend(&mut done_ledger_client, startup)?;
    prepare_findings_backend(&mut findings_client, startup)?;
    let persistence = DistributedPersistence::new(
        FindingsSinkPg::from_client(findings_client),
        DoneLedgerPg::from_client(done_ledger_client),
    );

    Ok(ProductionRuntimeBackends {
        coordinator,
        persistence,
    })
}

/// Production worker entrypoint for the real backend path.
///
/// Connects the real backends, applies the selected startup schema policy,
/// then delegates to the generic distributed runtime.
///
/// This function never falls back to in-memory doubles or the CLI no-op commit
/// path. Either the real backends are built successfully and the generic
/// distributed runtime runs, or the function returns a typed error.
///
/// # Errors
///
/// Returns [`ProductionWorkerError::Startup`] when backend construction or
/// startup readiness fails before any shard work begins, or
/// [`ProductionWorkerError::Runtime`] when the generic distributed worker
/// loop fails after startup succeeds.
///
/// # Panics
///
/// Panics if called from within an active Tokio runtime.
/// [`EtcdCoordinator::connect`] asserts that no Tokio runtime is active
/// before building its own single-threaded runtime.
pub fn run_production_worker(
    config: &ProductionBackendConfig,
    startup: ProductionStartupSettings,
    identity: WorkerIdentity,
    runtime: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, ProductionWorkerError> {
    let backends = build_production_backends(config, startup)?;
    backends
        .run(identity, runtime)
        .map_err(ProductionWorkerError::Runtime)
}

/// Default TCP-level connect timeout (seconds) injected when the caller DSN
/// does not include an explicit `connect_timeout` parameter. Without this
/// fallback the `postgres` crate defaults to *no timeout*, which can block
/// the calling thread for minutes on an unreachable host.
///
/// Kept low (5 s) so that worst-case startup stays under 15 s: both
/// PostgreSQL connections open in parallel (~5 s), then etcd connects
/// (~5 s), then schema validation queries run. This fits well within
/// typical container liveness probe windows. Callers that need a longer
/// timeout should set `connect_timeout=N` in their DSN explicitly.
const DEFAULT_CONNECT_TIMEOUT_SECS: u32 = 5;

/// Check whether a DSN already contains an explicit `connect_timeout` parameter.
///
/// For URI-format DSNs (`postgresql://` / `postgres://`), the parameter must
/// appear in the query string (after `?`, delimited by `&`). For keyword-value
/// DSNs, parameters are whitespace-delimited, so `connect_timeout=` must appear
/// at the start of the string or immediately after whitespace. This avoids
/// false positives when the substring appears inside a password, database name,
/// or other opaque field.
fn has_connect_timeout(dsn: &str) -> bool {
    if dsn.starts_with("postgresql://") || dsn.starts_with("postgres://") {
        dsn.split_once('?').is_some_and(|(_, query)| {
            query
                .split('&')
                .any(|param| param.starts_with("connect_timeout="))
        })
    } else {
        dsn.split_whitespace()
            .any(|param| param.starts_with("connect_timeout="))
    }
}

/// Extract the host component from a PostgreSQL DSN, if parseable.
///
/// Handles both URI format (`postgresql://user:pass@HOST:port/db`) and
/// keyword-value format (`host=HOST user=... dbname=...`). Returns `None`
/// when the host cannot be determined — callers should assume local in
/// that case.
fn extract_pg_host(dsn: &str) -> Option<&str> {
    if dsn.starts_with("postgresql://") || dsn.starts_with("postgres://") {
        // URI format: scheme://[userinfo@]host[:port][/dbname][?params]
        let after_scheme = dsn.split_once("://").map(|(_, rest)| rest)?;
        // Strip optional userinfo (everything before the last `@`).
        let host_and_rest = after_scheme
            .rfind('@')
            .map_or(after_scheme, |idx| &after_scheme[idx + 1..]);

        // Bracketed IPv6 addresses (e.g. `[::1]:5432/db`) must be handled
        // before the `:` split, because `:` appears inside the brackets.
        if host_and_rest.starts_with('[') {
            let close = host_and_rest.find(']')?;
            let host = &host_and_rest[..=close]; // e.g. "[::1]"
            if host.len() <= 2 {
                // Just "[]" — no actual address.
                None
            } else {
                Some(host)
            }
        } else {
            // Plain hostname or IPv4 — trim port, path, and query string.
            let host = host_and_rest
                .split_once(':')
                .or_else(|| host_and_rest.split_once('/'))
                .or_else(|| host_and_rest.split_once('?'))
                .map_or(host_and_rest, |(h, _)| h);
            if host.is_empty() { None } else { Some(host) }
        }
    } else {
        // Keyword-value format: `host=HOST port=... dbname=...`
        dsn.split_whitespace()
            .find_map(|param| param.strip_prefix("host="))
            .filter(|h| !h.is_empty())
    }
}

/// Returns `true` when the host refers to the local machine or a Unix socket.
///
/// Recognized local patterns: `localhost`, `127.0.0.1`, `::1`, Unix socket
/// paths (starting with `/`), and the empty/absent case (PostgreSQL defaults
/// to a local Unix socket when no host is specified).
fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") || host.starts_with('/')
}

fn connect_postgres_client(dsn: &str) -> Result<Client, postgres::Error> {
    // Best-effort warning when connecting without TLS to a non-local host.
    // If host extraction fails, assume local and stay silent.
    if let Some(host) = extract_pg_host(dsn)
        && !is_local_host(host)
    {
        tracing::warn!(
            "connecting to PostgreSQL without TLS \
             — use build_production_backends_from_clients for TLS-capable connections"
        );
    }

    if has_connect_timeout(dsn) {
        return Client::connect(dsn, NoTls).map_err(|err| {
            // Log a generic message at warn; the raw driver error may echo
            // DSN fragments (hostname, port, username). Diagnostics are
            // available at debug level only.
            tracing::warn!("PostgreSQL connection failed");
            tracing::debug!(error = %err, "PostgreSQL connection diagnostic");
            err
        });
    }

    // Append the timeout using the correct separator for the DSN format.
    // URI format (`postgresql://...`) requires `?` / `&` query parameters;
    // keyword-value format (`host=... port=...`) uses whitespace.
    let timed = if dsn.starts_with("postgresql://") || dsn.starts_with("postgres://") {
        let sep = if dsn.contains('?') { '&' } else { '?' };
        format!("{dsn}{sep}connect_timeout={DEFAULT_CONNECT_TIMEOUT_SECS}")
    } else {
        format!("{dsn} connect_timeout={DEFAULT_CONNECT_TIMEOUT_SECS}")
    };
    tracing::debug!(
        timeout_secs = DEFAULT_CONNECT_TIMEOUT_SECS,
        "DSN omitted connect_timeout; injecting default"
    );
    Client::connect(&timed, NoTls).map_err(|err| {
        tracing::warn!("PostgreSQL connection failed");
        tracing::debug!(error = %err, "PostgreSQL connection diagnostic");
        err
    })
}

/// Apply the startup policy to the done-ledger database: auto-migrate first
/// when `DevAutoMigrate` is selected, then validate table existence and
/// migration-history integrity in both modes.
fn prepare_done_ledger_backend(
    client: &mut Client,
    startup: ProductionStartupSettings,
) -> Result<(), ProductionBootstrapError> {
    if startup.schema_mode() == StartupSchemaMode::DevAutoMigrate {
        apply_done_ledger_migrations(client)
            .map_err(ProductionBootstrapError::DoneLedgerAutoMigrate)?;
    }
    validate_schema_readiness(
        client,
        &[
            done_ledger_schema::DONE_LEDGER_ENTRIES_TABLE,
            done_ledger_schema::SCHEMA_MIGRATIONS_TABLE,
        ],
        DONE_LEDGER_MIGRATIONS,
        done_ledger_schema::SCHEMA_MIGRATIONS_TABLE,
    )
    .map_err(ProductionBootstrapError::DoneLedgerSchemaReadiness)
}

/// Apply the startup policy to the findings database: auto-migrate first
/// when `DevAutoMigrate` is selected, then validate table existence and
/// migration-history integrity in both modes.
fn prepare_findings_backend(
    client: &mut Client,
    startup: ProductionStartupSettings,
) -> Result<(), ProductionBootstrapError> {
    if startup.schema_mode() == StartupSchemaMode::DevAutoMigrate {
        apply_findings_migrations(client).map_err(ProductionBootstrapError::FindingsAutoMigrate)?;
    }
    validate_schema_readiness(
        client,
        &[
            findings_schema::FINDINGS_TABLE,
            findings_schema::OCCURRENCES_TABLE,
            findings_schema::OBSERVATIONS_TABLE,
            findings_schema::SCHEMA_MIGRATIONS_TABLE,
        ],
        FINDINGS_MIGRATIONS,
        findings_schema::SCHEMA_MIGRATIONS_TABLE,
    )
    .map_err(ProductionBootstrapError::FindingsSchemaReadiness)
}

/// Verify that all expected tables exist and every embedded migration version
/// is recorded with a matching checksum.
fn validate_schema_readiness(
    client: &mut Client,
    expected_tables: &[&'static str],
    migrations: &[EmbeddedMigration],
    history_table: &'static str,
) -> Result<(), ProductionSchemaReadinessError> {
    debug_assert!(
        expected_tables.contains(&history_table),
        "history_table '{history_table}' must be included in expected_tables \
         so that a missing table produces MissingTable, not a raw Query error"
    );
    ensure_expected_tables_exist(client, expected_tables)?;
    let required = migrations
        .iter()
        .map(|m| (m.version(), *m.checksum().as_bytes()))
        .collect::<Vec<_>>();
    ensure_migration_history_ready(client, history_table, &required)
}

/// Check that every table in `expected_tables` exists in the current schema.
///
/// Uses a single `ANY($1)` query to batch the existence check, reducing
/// round trips from N to 1.
fn ensure_expected_tables_exist(
    client: &mut Client,
    expected_tables: &[&'static str],
) -> Result<(), ProductionSchemaReadinessError> {
    if expected_tables.is_empty() {
        return Ok(());
    }
    let rows = client.query(
        "SELECT tablename::text
           FROM pg_catalog.pg_tables
          WHERE schemaname = current_schema()
            AND tablename = ANY($1)",
        &[&expected_tables],
    )?;
    let found: std::collections::HashSet<&str> =
        rows.iter().map(|row| row.get::<_, &str>(0)).collect();
    for &table in expected_tables {
        if !found.contains(table) {
            return Err(ProductionSchemaReadinessError::MissingTable { table });
        }
    }
    Ok(())
}

/// Verify that every required migration version is present in the history
/// table with a matching checksum.
///
/// Uses a single `ANY($1)` query to fetch all matching rows at once,
/// reducing round trips from N to 1. Detects missing migrations, truncated
/// checksums, and checksum drift from out-of-band schema edits.
///
/// **Forward-compatibility**: the check is intentionally one-directional.
/// Extra rows in the history table (migrations applied by a newer binary)
/// are ignored. This allows rolling deployments where an updated worker
/// applies new migrations while older workers still pass validation against
/// their known set. If strict version pinning is ever needed, add a
/// separate `UnexpectedMigration` variant; do not change this function's
/// contract without considering the rolling-deploy impact.
///
/// **Precondition:** the history table must already exist. Callers should
/// run [`ensure_expected_tables_exist`] first; calling this function against
/// a missing table produces a [`ProductionSchemaReadinessError::Query`]
/// error rather than a [`ProductionSchemaReadinessError::MissingTable`].
fn ensure_migration_history_ready(
    client: &mut Client,
    history_table: &'static str,
    required_migrations: &[(&'static str, [u8; 32])],
) -> Result<(), ProductionSchemaReadinessError> {
    if required_migrations.is_empty() {
        return Ok(());
    }

    let versions: Vec<&str> = required_migrations.iter().map(|(v, _)| *v).collect();
    // SAFETY (sql-injection): `history_table` is `&'static str`, so only
    // compile-time string literals can reach this interpolation — no runtime
    // input path exists. Both call sites pass module-level constants
    // (`done_ledger_schema::SCHEMA_MIGRATIONS_TABLE` and
    //  `findings_schema::SCHEMA_MIGRATIONS_TABLE`).
    let rows = client.query(
        &format!("SELECT version, checksum FROM {history_table} WHERE version = ANY($1)"),
        &[&versions],
    )?;

    let stored: std::collections::HashMap<String, Vec<u8>> = rows
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, Vec<u8>>(1)))
        .collect();

    for &(version, expected_checksum) in required_migrations {
        let Some(stored_checksum) = stored.get(version) else {
            return Err(ProductionSchemaReadinessError::MissingAppliedMigration {
                history_table,
                version,
            });
        };
        if stored_checksum.len() != expected_checksum.len() {
            return Err(ProductionSchemaReadinessError::CorruptedAppliedMigration {
                history_table,
                version,
                found_len: stored_checksum.len(),
            });
        }
        if stored_checksum.as_slice() != &expected_checksum[..] {
            return Err(ProductionSchemaReadinessError::MigrationChecksumMismatch {
                history_table,
                version,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };

    use crate::{
        config::ProductionBackendConfigError, recorder::ProductionCoordinationEventRecorder,
    };
    use gossip_contracts::identity::{PolicyHash, RunId, TenantId, TenantSecretKey, WorkerId};
    use gossip_coordination_etcd::test_support::test_async_coordinator_config;
    use gossip_pg_common::test_support::create_test_db;
    use gossip_scanner_runtime::{ExecutionMode, FsScanConfig, ScanBudgets, ScanRuntimeError};
    use tempfile::tempdir;

    fn fresh_backend_config() -> ProductionBackendConfig {
        ProductionBackendConfig::new(
            test_async_coordinator_config(),
            create_test_db(),
            create_test_db(),
        )
        .expect("test backend config should be valid")
    }

    fn migrate_done_ledger_database(dsn: &str) {
        apply_done_ledger_migrations(
            &mut Client::connect(dsn, NoTls)
                .expect("done-ledger test database should accept connections"),
        )
        .expect("done-ledger migrations should succeed");
    }

    fn migrate_findings_database(dsn: &str) {
        apply_findings_migrations(
            &mut Client::connect(dsn, NoTls)
                .expect("findings test database should accept connections"),
        )
        .expect("findings migrations should succeed");
    }

    fn migrated_backend_config() -> ProductionBackendConfig {
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        migrate_done_ledger_database(&done_ledger_dsn);
        migrate_findings_database(&findings_dsn);
        ProductionBackendConfig::new(
            test_async_coordinator_config(),
            done_ledger_dsn,
            findings_dsn,
        )
        .expect("test backend config should be valid")
    }

    fn production_worker_identity(path: &Path) -> WorkerIdentity {
        WorkerIdentity::new(
            TenantId::from_bytes([0x11; 32]),
            RunId::from_raw(42),
            WorkerId::from_raw(7),
            PolicyHash::from_bytes([0x22; 32]),
            TenantSecretKey::from_bytes([0x33; 32]),
            FsScanConfig::new(path.to_path_buf())
                .with_execution_mode(ExecutionMode::Connector)
                .with_budgets(ScanBudgets::default()),
            Arc::new(ProductionCoordinationEventRecorder::default()),
        )
    }

    #[test]
    fn config_rejects_empty_done_ledger_dsn() {
        let error = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "   ",
            "host=127.0.0.1 port=5432 dbname=gossip",
        )
        .expect_err("empty done-ledger DSN must be rejected");

        assert_eq!(
            error,
            ProductionBackendConfigError::EmptyDoneLedgerPostgresDsn,
        );
        assert_eq!(
            error.to_string(),
            "done-ledger PostgreSQL DSN must not be empty",
        );
    }

    #[test]
    fn config_rejects_empty_findings_dsn() {
        let error = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "host=127.0.0.1 port=5432 dbname=gossip",
            "   ",
        )
        .expect_err("empty findings DSN must be rejected");

        assert_eq!(
            error,
            ProductionBackendConfigError::EmptyFindingsPostgresDsn
        );
        assert_eq!(
            error.to_string(),
            "findings PostgreSQL DSN must not be empty",
        );
    }

    #[test]
    fn config_debug_redacts_postgres_dsns() {
        let cfg = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/v1")
                .expect("hard-coded etcd config should be valid"),
            "postgresql://scanner:super-secret@db.example.internal:5432/done_ledger",
            "host=db.example.internal user=scanner password=ultra-secret dbname=findings",
        )
        .expect("backend config should be valid");

        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("super-secret"),
            "Debug output must not leak the done-ledger DSN"
        );
        assert!(
            !debug.contains("ultra-secret"),
            "Debug output must not leak the findings DSN"
        );
        assert!(
            debug.contains("[redacted]"),
            "Debug output should indicate that DSNs were redacted"
        );
    }

    #[test]
    fn bootstrap_error_from_etcd_redacts_source_chain() {
        let inner = EtcdCoordinatorError::RuntimeBuild(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "synthetic etcd failure",
        ));
        let bootstrap = ProductionBootstrapError::EtcdConnect(inner);

        assert!(matches!(
            bootstrap,
            ProductionBootstrapError::EtcdConnect(_)
        ));
        // Connection variants suppress source() to prevent DSN leakage
        // through error chain formatters.
        assert!(bootstrap.source().is_none());
        assert!(bootstrap.to_string().contains("etcd coordination backend"));
    }

    fn unreachable_postgres_connect_error() -> postgres::Error {
        match Client::connect(
            "host=127.0.0.1 port=1 user=postgres password=postgres dbname=postgres connect_timeout=1",
            NoTls,
        ) {
            Ok(_) => panic!("port 1 should refuse PostgreSQL connections during tests"),
            Err(error) => error,
        }
    }

    #[test]
    fn bootstrap_error_from_done_ledger_connect_redacts_source_chain() {
        let bootstrap =
            ProductionBootstrapError::DoneLedgerConnect(unreachable_postgres_connect_error());

        assert!(matches!(
            bootstrap,
            ProductionBootstrapError::DoneLedgerConnect(_)
        ));
        assert!(bootstrap.source().is_none());
        let message = bootstrap.to_string();
        assert!(message.contains("done-ledger PostgreSQL backend"));
        assert!(!message.contains("127.0.0.1"));
        assert!(!message.contains("postgres"));
    }

    #[test]
    fn bootstrap_error_from_findings_connect_redacts_source_chain() {
        let bootstrap =
            ProductionBootstrapError::FindingsConnect(unreachable_postgres_connect_error());

        assert!(matches!(
            bootstrap,
            ProductionBootstrapError::FindingsConnect(_)
        ));
        assert!(bootstrap.source().is_none());
        let message = bootstrap.to_string();
        assert!(message.contains("findings PostgreSQL backend"));
        assert!(!message.contains("127.0.0.1"));
        assert!(!message.contains("postgres"));
    }

    #[test]
    fn bootstrap_error_debug_redacts_connection_variants() {
        let pg_err = unreachable_postgres_connect_error();
        let done = ProductionBootstrapError::DoneLedgerConnect(pg_err);
        let debug = format!("{done:?}");
        assert!(
            debug.contains("[redacted]"),
            "Debug must show [redacted] for connection variants: {debug}"
        );
        // The inner postgres::Error must not appear in the Debug output.
        assert!(
            !debug.contains("127.0.0.1"),
            "Debug must not leak host: {debug}"
        );

        let etcd_err = EtcdCoordinatorError::RuntimeBuild(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "synthetic etcd failure",
        ));
        let etcd = ProductionBootstrapError::EtcdConnect(etcd_err);
        let debug = format!("{etcd:?}");
        assert!(
            debug.contains("[redacted]"),
            "Debug must show [redacted] for etcd connection variant: {debug}"
        );
        assert!(
            !debug.contains("synthetic etcd failure"),
            "Debug must not leak inner error details: {debug}"
        );
    }

    #[test]
    fn worker_error_debug_redacts_bootstrap_connection_variants() {
        let pg_err = unreachable_postgres_connect_error();
        let bootstrap = ProductionBootstrapError::FindingsConnect(pg_err);
        let worker: ProductionWorkerError = bootstrap.into();
        let debug = format!("{worker:?}");
        assert!(
            debug.contains("[redacted]"),
            "Worker error Debug must propagate redaction from bootstrap: {debug}"
        );
        assert!(
            !debug.contains("127.0.0.1"),
            "Worker error Debug must not leak host: {debug}"
        );
    }

    #[test]
    fn worker_error_from_bootstrap_preserves_source_chain() {
        let inner = EtcdCoordinatorError::RuntimeBuild(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "synthetic",
        ));
        let bootstrap = ProductionBootstrapError::EtcdConnect(inner);
        let worker: ProductionWorkerError = bootstrap.into();

        assert!(matches!(worker, ProductionWorkerError::Startup(_)));
        assert!(worker.source().is_some());
        assert!(worker.to_string().contains("worker startup failed"));
    }

    #[test]
    fn worker_error_from_runtime_preserves_source_chain() {
        let scan_err = ScanRuntimeError::InvalidPath {
            source: "test",
            path: PathBuf::from("/nonexistent"),
            message: "synthetic runtime failure".into(),
        };
        let runtime_err = DistributedRuntimeError::from(scan_err);
        let worker: ProductionWorkerError = runtime_err.into();

        assert!(matches!(worker, ProductionWorkerError::Runtime(_)));
        assert!(worker.source().is_some());
        assert!(worker.to_string().contains("worker runtime failed"));
    }

    #[test]
    fn config_new_trims_and_stores_valid_dsns() {
        let cfg = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "  host=127.0.0.1 dbname=done  ",
            "  host=127.0.0.1 dbname=findings  ",
        )
        .expect("valid DSNs with surrounding whitespace should be accepted");

        assert_eq!(cfg.done_ledger_postgres_dsn(), "host=127.0.0.1 dbname=done");
        assert_eq!(
            cfg.findings_postgres_dsn(),
            "host=127.0.0.1 dbname=findings"
        );
        assert_eq!(cfg.etcd().namespace_prefix(), "/gossip/v1");
    }

    #[test]
    fn validate_only_fails_when_done_ledger_schema_is_missing() {
        let config = fresh_backend_config();
        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("validate-only boot must fail on a fresh done-ledger database");

        assert!(matches!(
            error,
            ProductionBootstrapError::DoneLedgerSchemaReadiness(
                ProductionSchemaReadinessError::MissingTable { .. }
            )
        ));
    }

    #[test]
    fn validate_only_fails_when_findings_schema_is_missing() {
        let done_ledger_dsn = create_test_db();
        migrate_done_ledger_database(&done_ledger_dsn);
        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            done_ledger_dsn,
            create_test_db(),
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("validate-only boot must fail when the findings schema is missing");

        assert!(matches!(
            error,
            ProductionBootstrapError::FindingsSchemaReadiness(
                ProductionSchemaReadinessError::MissingTable { .. }
            )
        ));
    }

    #[test]
    fn validate_only_fails_when_done_ledger_checksum_mismatches() {
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        migrate_done_ledger_database(&done_ledger_dsn);
        migrate_findings_database(&findings_dsn);
        let version = DONE_LEDGER_MIGRATIONS[0].version();
        let mut client = Client::connect(&done_ledger_dsn, NoTls)
            .expect("done-ledger test database should accept connections");
        client
            .execute(
                "UPDATE done_ledger_schema_migrations SET checksum = $1 WHERE version = $2",
                &[&vec![0_u8; 32], &version],
            )
            .expect("checksum corruption update should succeed");
        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            done_ledger_dsn,
            findings_dsn,
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("validate-only boot must reject mismatched done-ledger checksums");

        assert!(matches!(
            error,
            ProductionBootstrapError::DoneLedgerSchemaReadiness(
                ProductionSchemaReadinessError::MigrationChecksumMismatch {
                    history_table,
                    version: found_version,
                }
            ) if history_table == done_ledger_schema::SCHEMA_MIGRATIONS_TABLE
                && found_version == version
        ));
    }

    #[test]
    fn validate_only_fails_when_findings_checksum_mismatches() {
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        migrate_done_ledger_database(&done_ledger_dsn);
        migrate_findings_database(&findings_dsn);
        let version = FINDINGS_MIGRATIONS[0].version();
        let mut client = Client::connect(&findings_dsn, NoTls)
            .expect("findings test database should accept connections");
        client
            .execute(
                "UPDATE findings_schema_migrations SET checksum = $1 WHERE version = $2",
                &[&vec![0_u8; 32], &version],
            )
            .expect("checksum corruption update should succeed");
        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            done_ledger_dsn,
            findings_dsn,
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("validate-only boot must reject mismatched findings checksums");

        assert!(matches!(
            error,
            ProductionBootstrapError::FindingsSchemaReadiness(
                ProductionSchemaReadinessError::MigrationChecksumMismatch {
                    history_table,
                    version: found_version,
                }
            ) if history_table == findings_schema::SCHEMA_MIGRATIONS_TABLE
                && found_version == version
        ));
    }

    #[test]
    fn validate_only_fails_when_done_ledger_checksum_is_corrupted() {
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        migrate_done_ledger_database(&done_ledger_dsn);
        migrate_findings_database(&findings_dsn);

        let version = DONE_LEDGER_MIGRATIONS[0].version();
        let mut client = Client::connect(&done_ledger_dsn, NoTls)
            .expect("done-ledger test database should accept connections");

        // Drop inline CHECK constraints so a wrong-length checksum can be stored.
        client
            .batch_execute(
                "DO $$ DECLARE r RECORD; BEGIN \
                   FOR r IN SELECT conname FROM pg_constraint \
                     WHERE conrelid = 'done_ledger_schema_migrations'::regclass \
                       AND contype = 'c' LOOP \
                     EXECUTE 'ALTER TABLE done_ledger_schema_migrations DROP CONSTRAINT ' || r.conname; \
                   END LOOP; \
                 END $$",
            )
            .expect("dropping CHECK constraints should succeed");
        client
            .execute(
                "UPDATE done_ledger_schema_migrations SET checksum = $1 WHERE version = $2",
                &[&vec![0_u8; 16], &version],
            )
            .expect("corrupted checksum update should succeed");

        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            done_ledger_dsn,
            findings_dsn,
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("validate-only boot must reject a wrong-length done-ledger checksum");

        assert!(matches!(
            error,
            ProductionBootstrapError::DoneLedgerSchemaReadiness(
                ProductionSchemaReadinessError::CorruptedAppliedMigration { found_len: 16, .. }
            )
        ));
    }

    #[test]
    fn dev_auto_migrate_bootstraps_fresh_databases() {
        let config = fresh_backend_config();
        let backends =
            build_production_backends(&config, ProductionStartupSettings::dev_auto_migrate())
                .expect("development auto-migrate should make fresh databases ready");

        backends
            .persistence()
            .findings_sink
            .validate_connection(Duration::from_secs(1))
            .expect("findings connection should remain usable after startup readiness");
    }

    #[test]
    fn dev_auto_migrate_is_idempotent() {
        let config = fresh_backend_config();
        let first =
            build_production_backends(&config, ProductionStartupSettings::dev_auto_migrate())
                .expect("first auto-migrate boot should succeed");
        drop(first);

        let second =
            build_production_backends(&config, ProductionStartupSettings::dev_auto_migrate())
                .expect("second auto-migrate boot should also succeed");
        second
            .persistence()
            .findings_sink
            .validate_connection(Duration::from_secs(1))
            .expect("findings connection should remain usable after repeated auto-migrate");
    }

    #[test]
    fn build_production_backends_from_clients_connects_live_backends() {
        let etcd = test_async_coordinator_config();
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        migrate_done_ledger_database(&done_ledger_dsn);
        migrate_findings_database(&findings_dsn);
        let done_ledger_client = Client::connect(&done_ledger_dsn, NoTls)
            .expect("done-ledger test database should accept connections");
        let findings_client = Client::connect(&findings_dsn, NoTls)
            .expect("findings test database should accept connections");

        let backends = build_production_backends_from_clients(
            etcd,
            done_ledger_client,
            findings_client,
            ProductionStartupSettings::validate_only(),
        )
        .expect("live backend construction from explicit clients should succeed");

        backends
            .persistence()
            .findings_sink
            .validate_connection(Duration::from_secs(1))
            .expect("findings connection should remain valid after bootstrap");
    }

    #[test]
    fn run_production_worker_uses_real_backends_and_never_falls_back() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("secret.txt"),
            "token=worker-real-backend-proof",
        )
        .expect("write fixture");
        let error = run_production_worker(
            &migrated_backend_config(),
            ProductionStartupSettings::validate_only(),
            production_worker_identity(dir.path()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("missing run should fail after real backend bootstrap");

        assert!(matches!(
            error,
            ProductionWorkerError::Runtime(DistributedRuntimeError::Coordinator(_))
        ));
        assert!(
            error.to_string().contains("run not found"),
            "runtime error should come from the real coordinator path: {error}"
        );
    }

    #[test]
    fn run_production_worker_fails_before_runtime_when_schema_is_not_ready() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("secret.txt"),
            "token=worker-readiness-proof",
        )
        .expect("write fixture");
        let error = run_production_worker(
            &fresh_backend_config(),
            ProductionStartupSettings::validate_only(),
            production_worker_identity(dir.path()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("startup readiness must fail before the runtime claims any shard");

        assert!(matches!(error, ProductionWorkerError::Startup(_)));
        assert!(
            !matches!(error, ProductionWorkerError::Runtime(_)),
            "schema readiness failure must not escape as a runtime error"
        );
    }

    #[test]
    fn build_production_backends_returns_typed_done_ledger_startup_error() {
        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            "host=127.0.0.1 port=1 user=postgres password=postgres dbname=postgres connect_timeout=1",
            create_test_db(),
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("invalid done-ledger DSN should fail startup");

        assert!(
            matches!(error, ProductionBootstrapError::DoneLedgerConnect(_)),
            "expected typed done-ledger startup error, got {error:?}"
        );
    }

    #[test]
    fn build_production_backends_returns_typed_findings_startup_error() {
        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            create_test_db(),
            "host=127.0.0.1 port=1 user=postgres password=postgres dbname=postgres connect_timeout=1",
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("invalid findings DSN should fail startup");

        assert!(
            matches!(error, ProductionBootstrapError::FindingsConnect(_)),
            "expected typed findings startup error, got {error:?}"
        );
    }

    #[test]
    fn build_production_backends_returns_typed_etcd_startup_error() {
        let config = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::new(["http://127.0.0.1:1"], "/gossip/test")
                .expect("syntactically valid etcd config should build"),
            create_test_db(),
            create_test_db(),
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("unreachable etcd endpoint should fail startup");

        assert!(
            matches!(error, ProductionBootstrapError::EtcdConnect(_)),
            "expected typed etcd startup error, got {error:?}"
        );
    }

    #[test]
    fn extract_pg_host_parses_bracketed_ipv6_uri() {
        let dsn = "postgresql://scanner:secret@[::1]:5432/done";
        let host = extract_pg_host(dsn);
        assert_eq!(
            host,
            Some("[::1]"),
            "bracketed IPv6 in URI format must extract as '[::1]', not '['",
        );
    }

    #[test]
    fn extract_pg_host_parses_ipv4_uri() {
        let dsn = "postgresql://scanner:pass@127.0.0.1:5432/done";
        assert_eq!(extract_pg_host(dsn), Some("127.0.0.1"));
    }

    #[test]
    fn extract_pg_host_parses_hostname_uri() {
        let dsn = "postgres://user@db.example.com:5432/mydb";
        assert_eq!(extract_pg_host(dsn), Some("db.example.com"));
    }

    #[test]
    fn extract_pg_host_parses_keyword_value_ipv6() {
        let dsn = "host=::1 port=5432 dbname=done";
        assert_eq!(extract_pg_host(dsn), Some("::1"));
    }

    #[test]
    fn is_local_host_recognizes_bracketed_ipv6_loopback() {
        assert!(is_local_host("[::1]"));
        assert!(is_local_host("::1"));
        assert!(is_local_host("127.0.0.1"));
        assert!(is_local_host("localhost"));
    }

    // ---- has_connect_timeout tests ----

    #[test]
    fn has_connect_timeout_uri_with_param_in_query_string() {
        let dsn = "postgresql://user:pass@host:5432/db?connect_timeout=5&sslmode=require";
        assert!(has_connect_timeout(dsn));
    }

    #[test]
    fn has_connect_timeout_uri_without_param() {
        let dsn = "postgresql://user:pass@host:5432/db?sslmode=require";
        assert!(!has_connect_timeout(dsn));
    }

    #[test]
    fn has_connect_timeout_uri_as_only_query_param() {
        let dsn = "postgres://user@host/db?connect_timeout=10";
        assert!(has_connect_timeout(dsn));
    }

    #[test]
    fn has_connect_timeout_keyword_value_with_param() {
        let dsn = "host=db.example.com port=5432 connect_timeout=5 dbname=mydb";
        assert!(has_connect_timeout(dsn));
    }

    #[test]
    fn has_connect_timeout_keyword_value_without_param() {
        let dsn = "host=db.example.com port=5432 dbname=mydb";
        assert!(!has_connect_timeout(dsn));
    }

    #[test]
    fn has_connect_timeout_uri_embedded_in_password_is_not_detected() {
        // The substring appears in the password, not as a query-string parameter.
        let dsn = "postgresql://user:connect_timeout=secret@host:5432/db?sslmode=require";
        assert!(!has_connect_timeout(dsn));
    }

    #[test]
    fn has_connect_timeout_keyword_value_in_value_position_is_not_detected() {
        // "connect_timeout=3" appears as the *value* of password, not as its own key.
        let dsn = "host=db.example.com password=connect_timeout=3 dbname=mydb";
        assert!(!has_connect_timeout(dsn));
    }

    // ---- extract_pg_host edge-case tests ----

    #[test]
    fn extract_pg_host_uri_without_userinfo() {
        let dsn = "postgresql://myhost:5432/db";
        assert_eq!(extract_pg_host(dsn), Some("myhost"));
    }

    #[test]
    fn extract_pg_host_uri_without_port() {
        let dsn = "postgresql://user@myhost/db";
        assert_eq!(extract_pg_host(dsn), Some("myhost"));
    }

    #[test]
    fn extract_pg_host_keyword_value_with_hostname() {
        let dsn = "host=db.example.com port=5432";
        assert_eq!(extract_pg_host(dsn), Some("db.example.com"));
    }

    #[test]
    fn extract_pg_host_empty_brackets_returns_none() {
        let dsn = "postgresql://user@[]:5432/db";
        assert_eq!(extract_pg_host(dsn), None);
    }

    #[test]
    fn extract_pg_host_missing_host_in_uri_returns_none() {
        // Triple-slash means no authority component — host is empty.
        let dsn = "postgresql:///mydb";
        assert_eq!(extract_pg_host(dsn), None);
    }

    // ---- is_local_host edge-case tests ----

    #[test]
    fn is_local_host_unix_socket_path() {
        assert!(is_local_host("/var/run/postgresql"));
    }

    #[test]
    fn is_local_host_non_local_hostname() {
        assert!(!is_local_host("db.example.com"));
    }

    #[test]
    fn extract_pg_host_uri_with_at_in_password() {
        // `rfind('@')` correctly finds the userinfo delimiter even when the
        // password contains a literal unencoded `@`.
        let dsn = "postgresql://user:p@ss@db.example.com:5432/mydb";
        assert_eq!(extract_pg_host(dsn), Some("db.example.com"));
    }

    #[test]
    fn dev_auto_migrate_then_validate_only_succeeds() {
        let config = fresh_backend_config();
        let first =
            build_production_backends(&config, ProductionStartupSettings::dev_auto_migrate())
                .expect("auto-migrate should bootstrap fresh databases");
        drop(first);

        let _second =
            build_production_backends(&config, ProductionStartupSettings::validate_only())
                .expect("validate-only should succeed after auto-migrate populated the schema");
    }

    #[test]
    fn validate_only_fails_when_done_ledger_checksum_is_truncated() {
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        migrate_done_ledger_database(&done_ledger_dsn);
        migrate_findings_database(&findings_dsn);

        let version = DONE_LEDGER_MIGRATIONS[0].version();
        let mut client = Client::connect(&done_ledger_dsn, NoTls)
            .expect("done-ledger test database should accept connections");

        // Drop the inline CHECK constraint so we can insert a truncated
        // checksum that would normally be rejected by the schema.
        client
            .batch_execute(
                "DO $$ DECLARE r RECORD; BEGIN \
                   FOR r IN SELECT conname FROM pg_constraint \
                     WHERE conrelid = 'done_ledger_schema_migrations'::regclass \
                       AND contype = 'c' LOOP \
                     EXECUTE 'ALTER TABLE done_ledger_schema_migrations DROP CONSTRAINT ' || r.conname; \
                   END LOOP; \
                 END $$",
            )
            .expect("dropping CHECK constraints should succeed");
        client
            .execute(
                "UPDATE done_ledger_schema_migrations SET checksum = $1 WHERE version = $2",
                &[&vec![0_u8; 16], &version],
            )
            .expect("truncated checksum update should succeed");

        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            done_ledger_dsn,
            findings_dsn,
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("validate-only boot must reject a truncated done-ledger checksum");

        assert!(
            matches!(
                error,
                ProductionBootstrapError::DoneLedgerSchemaReadiness(
                    ProductionSchemaReadinessError::CorruptedAppliedMigration { found_len: 16, .. }
                )
            ),
            "expected CorruptedAppliedMigration with 16 bytes, got {error:?}"
        );
    }
}
