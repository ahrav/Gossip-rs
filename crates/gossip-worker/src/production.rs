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
//! `FindingsSink`. This module owns only startup wiring and typed startup error
//! classification.
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
use gossip_done_ledger_postgres::{DoneLedgerPg, DoneLedgerPgError};
use gossip_findings_postgres::{FindingsPgError, FindingsSinkPg};
use gossip_scanner_runtime::distributed::{
    DistributedPersistence, DistributedRunReport, DistributedRuntimeConfig,
    DistributedRuntimeError, WorkerIdentity, run_worker,
};
use postgres::{Client, NoTls};

/// Typed startup failures for the production composition root.
///
/// Each variant identifies which backend connection or migration step
/// failed during construction.
pub enum ProductionBootstrapError {
    /// Establishing the done-ledger PostgreSQL connection failed.
    DoneLedgerConnect(postgres::Error),
    /// Establishing the findings PostgreSQL connection failed.
    FindingsConnect(postgres::Error),
    /// Connecting the etcd coordinator failed.
    EtcdConnect(EtcdCoordinatorError),
    /// Done-ledger schema migration failed after a successful connection.
    DoneLedgerMigration(DoneLedgerPgError),
    /// Findings schema migration failed after a successful connection.
    FindingsMigration(FindingsPgError),
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
            Self::DoneLedgerMigration(source) => {
                write!(f, "done-ledger schema migration failed: {source}")
            }
            Self::FindingsMigration(source) => {
                write!(f, "findings schema migration failed: {source}")
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
            Self::DoneLedgerMigration(source) => Some(source),
            Self::FindingsMigration(source) => Some(source),
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
            Self::DoneLedgerMigration(e) => f.debug_tuple("DoneLedgerMigration").field(e).finish(),
            Self::FindingsMigration(e) => f.debug_tuple("FindingsMigration").field(e).finish(),
        }
    }
}

impl From<EtcdCoordinatorError> for ProductionBootstrapError {
    fn from(value: EtcdCoordinatorError) -> Self {
        Self::EtcdConnect(value)
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
///
/// # Errors
///
/// Returns [`ProductionBootstrapError`] when either PostgreSQL connection
/// fails or the etcd coordinator cannot be constructed.
///
/// # Caller Obligations
///
/// **Schema migrations are required before calling
/// [`ProductionRuntimeBackends::run`].** Access the backends via
/// [`ProductionRuntimeBackends::persistence`] and call
/// `apply_migrations()` on both `done_ledger` and `findings_sink`.
/// Calling `run()` on un-migrated backends is a hard runtime error
/// (missing tables / columns), not a silent degradation.
///
/// [`run_production_worker`] is the convenience entrypoint that handles
/// migrations automatically. Use `build_production_backends` only when
/// you need to separate the migration step from execution (e.g.,
/// dedicated migration tooling or staged rollouts).
///
/// # Panics
///
/// Panics if called from within an active Tokio runtime.
/// [`EtcdCoordinator::connect`] asserts that no Tokio runtime is active
/// before building its own single-threaded runtime.
pub fn build_production_backends(
    config: &ProductionBackendConfig,
) -> Result<ProductionRuntimeBackends, ProductionBootstrapError> {
    // Connect etcd first — it is the most likely to fail in misconfigured
    // environments, and this avoids opening Postgres connections that would
    // be immediately discarded on etcd failure.
    let coordinator = EtcdCoordinator::connect(config.etcd().clone()).map_err(|err| {
        tracing::warn!(error = %err, "etcd coordinator connection failed");
        ProductionBootstrapError::EtcdConnect(err)
    })?;

    let done_ledger_client = connect_postgres_client(config.done_ledger_postgres_dsn())
        .map_err(ProductionBootstrapError::DoneLedgerConnect)?;
    let findings_client = connect_postgres_client(config.findings_postgres_dsn())
        .map_err(ProductionBootstrapError::FindingsConnect)?;

    let persistence = DistributedPersistence::new(
        FindingsSinkPg::from_client(findings_client),
        DoneLedgerPg::from_client(done_ledger_client),
    );

    Ok(ProductionRuntimeBackends {
        coordinator,
        persistence,
    })
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
/// Returns [`ProductionBootstrapError::EtcdConnect`] when the etcd
/// coordinator rejects the config or cannot establish a healthy connection.
///
/// # Caller Obligations
///
/// **Schema migrations are required before calling
/// [`ProductionRuntimeBackends::run`].** Access the backends via
/// [`ProductionRuntimeBackends::persistence`] and call
/// `apply_migrations()` on both `done_ledger` and `findings_sink`.
/// Calling `run()` on un-migrated backends is a hard runtime error
/// (missing tables / columns), not a silent degradation.
///
/// [`run_production_worker`] is the convenience entrypoint that handles
/// migrations automatically. Use `build_production_backends_from_clients`
/// only when you need to separate the migration step from execution
/// (e.g., dedicated migration tooling or staged rollouts) and also need
/// TLS or custom connection handling.
///
/// # Panics
///
/// Panics if called from within an active Tokio runtime.
/// [`EtcdCoordinator::connect`] asserts that no Tokio runtime is active
/// before building its own single-threaded runtime.
pub fn build_production_backends_from_clients(
    etcd: EtcdCoordinatorConfig,
    done_ledger_client: Client,
    findings_client: Client,
) -> Result<ProductionRuntimeBackends, ProductionBootstrapError> {
    let coordinator = EtcdCoordinator::connect(etcd).map_err(|err| {
        tracing::warn!(error = %err, "etcd coordinator connection failed");
        ProductionBootstrapError::EtcdConnect(err)
    })?;
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
/// Connects the real backends, applies schema migrations on both PostgreSQL
/// databases (idempotent and concurrency-safe), then delegates to the generic
/// distributed runtime.
///
/// This function never falls back to in-memory doubles or the CLI no-op commit
/// path. Either the real backends are built successfully and the generic
/// distributed runtime runs, or the function returns a typed error.
///
/// Callers that need to separate migration from execution (e.g., dedicated
/// migration tooling or staged rollouts) should use
/// [`build_production_backends`] directly and manage the migration step
/// themselves.
///
/// # Errors
///
/// Returns [`ProductionWorkerError::Startup`] when backend construction or
/// schema migration fails before any shard work begins, or
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
    identity: WorkerIdentity,
    runtime: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, ProductionWorkerError> {
    let backends = build_production_backends(config)?;

    // Apply schema migrations before any shard work. Both calls are
    // idempotent and serialized by advisory locks, so concurrent workers
    // converge safely.
    backends
        .persistence()
        .done_ledger
        .apply_migrations()
        .map_err(|e| {
            ProductionWorkerError::Startup(ProductionBootstrapError::DoneLedgerMigration(e))
        })?;
    backends
        .persistence()
        .findings_sink
        .apply_migrations()
        .map_err(|e| {
            ProductionWorkerError::Startup(ProductionBootstrapError::FindingsMigration(e))
        })?;

    backends
        .run(identity, runtime)
        .map_err(ProductionWorkerError::Runtime)
}

/// Default TCP-level connect timeout (seconds) injected when the caller DSN
/// does not include an explicit `connect_timeout` parameter. Without this
/// fallback the `postgres` crate defaults to *no timeout*, which can block
/// the calling thread for minutes on an unreachable host.
///
/// Kept low (5 s) so that worst-case startup failure (etcd + two PostgreSQL
/// connections) stays under 20 s — well within typical container liveness
/// probe windows. Callers that need a longer timeout should set
/// `connect_timeout=N` in their DSN explicitly.
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
            tracing::warn!(error = %err, "PostgreSQL connection failed");
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
        tracing::warn!(error = %err, "PostgreSQL connection failed");
        err
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::time::Duration;

    use crate::config::ProductionBackendConfigError;
    use gossip_coordination_etcd::test_support::test_async_coordinator_config;
    use gossip_pg_common::test_support::create_test_db;
    use gossip_scanner_runtime::ScanRuntimeError;

    fn valid_backend_config() -> ProductionBackendConfig {
        ProductionBackendConfig::new(
            test_async_coordinator_config(),
            create_test_db(),
            create_test_db(),
        )
        .expect("test backend config should be valid")
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
        let bootstrap: ProductionBootstrapError = inner.into();

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
    #[ignore = "requires live etcd and PostgreSQL backends or Docker-backed testcontainers"]
    fn build_production_backends_connects_live_backends_from_dsns() {
        let config = valid_backend_config();
        let mut backends =
            build_production_backends(&config).expect("live backend construction should succeed");

        backends
            .persistence()
            .done_ledger
            .apply_migrations()
            .expect("done-ledger migrations should succeed on the connected backend");
        backends
            .persistence()
            .findings_sink
            .apply_migrations()
            .expect("findings migrations should succeed on the connected backend");
        backends
            .persistence()
            .findings_sink
            .validate_connection(Duration::from_secs(1))
            .expect("findings connection should remain usable after bootstrap");

        // Verify mutable access compiles and does not panic.
        assert!(
            !format!("{:?}", backends.coordinator_mut()).is_empty(),
            "mutable coordinator borrow should produce non-empty Debug output"
        );
    }

    #[test]
    #[ignore = "requires live etcd and PostgreSQL backends or Docker-backed testcontainers"]
    fn build_production_backends_from_clients_connects_live_backends() {
        let etcd = test_async_coordinator_config();
        let done_ledger_client = Client::connect(&create_test_db(), NoTls)
            .expect("done-ledger test database should accept connections");
        let findings_client = Client::connect(&create_test_db(), NoTls)
            .expect("findings test database should accept connections");

        let backends =
            build_production_backends_from_clients(etcd, done_ledger_client, findings_client)
                .expect("live backend construction from explicit clients should succeed");

        backends
            .persistence()
            .findings_sink
            .validate_connection(Duration::from_secs(1))
            .expect("findings connection should remain valid after bootstrap");
    }

    #[test]
    #[ignore = "requires live etcd and PostgreSQL backends or Docker-backed testcontainers"]
    fn build_production_backends_returns_typed_done_ledger_startup_error() {
        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            "host=127.0.0.1 port=1 user=postgres password=postgres dbname=postgres connect_timeout=1",
            create_test_db(),
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config)
            .expect_err("invalid done-ledger DSN should fail startup");

        assert!(
            matches!(error, ProductionBootstrapError::DoneLedgerConnect(_)),
            "expected typed done-ledger startup error, got {error:?}"
        );
    }

    #[test]
    #[ignore = "requires live etcd and PostgreSQL backends or Docker-backed testcontainers"]
    fn build_production_backends_returns_typed_findings_startup_error() {
        let config = ProductionBackendConfig::new(
            test_async_coordinator_config(),
            create_test_db(),
            "host=127.0.0.1 port=1 user=postgres password=postgres dbname=postgres connect_timeout=1",
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config)
            .expect_err("invalid findings DSN should fail startup");

        assert!(
            matches!(error, ProductionBootstrapError::FindingsConnect(_)),
            "expected typed findings startup error, got {error:?}"
        );
    }

    #[test]
    #[ignore = "requires live etcd and PostgreSQL backends or Docker-backed testcontainers"]
    fn build_production_backends_returns_typed_etcd_startup_error() {
        let config = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::new(["http://127.0.0.1:1"], "/gossip/test")
                .expect("syntactically valid etcd config should build"),
            create_test_db(),
            create_test_db(),
        )
        .expect("backend config should be valid");

        let error = build_production_backends(&config)
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
}
