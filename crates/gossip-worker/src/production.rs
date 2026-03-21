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

use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig, EtcdCoordinatorError};
use gossip_done_ledger_postgres::{DoneLedgerPg, DoneLedgerPgError};
use gossip_findings_postgres::{FindingsPgError, FindingsSinkPg};
use gossip_scanner_runtime::distributed::{
    DistributedPersistence, DistributedRunReport, DistributedRuntimeConfig,
    DistributedRuntimeError, WorkerIdentity, run_worker,
};
use postgres::{Client, NoTls};

/// Configuration for the real backend composition root.
///
/// The etcd config already performs its own validation when it is created.
/// This type adds only the PostgreSQL routing inputs needed to build the real
/// persistence backends.
#[derive(Clone)]
pub struct ProductionBackendConfig {
    etcd: EtcdCoordinatorConfig,
    done_ledger_postgres_dsn: String,
    findings_postgres_dsn: String,
}

impl ProductionBackendConfig {
    /// Construct one validated production-backend configuration bundle.
    ///
    /// DSNs are trimmed before storage so accidental surrounding whitespace in
    /// environment variables or config files does not survive into the startup
    /// path.
    ///
    /// See [`EtcdCoordinatorConfig::new`] for endpoint and namespace
    /// configuration, and [`EtcdCoordinatorConfig::with_auth`] for
    /// authentication setup.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionBackendConfigError`] when either PostgreSQL DSN is
    /// empty after trimming whitespace.
    pub fn new(
        etcd: EtcdCoordinatorConfig,
        done_ledger_postgres_dsn: impl Into<String>,
        findings_postgres_dsn: impl Into<String>,
    ) -> Result<Self, ProductionBackendConfigError> {
        let done_ledger_postgres_dsn = done_ledger_postgres_dsn.into().trim().to_owned();
        if done_ledger_postgres_dsn.is_empty() {
            return Err(ProductionBackendConfigError::EmptyDoneLedgerPostgresDsn);
        }

        let findings_postgres_dsn = findings_postgres_dsn.into().trim().to_owned();
        if findings_postgres_dsn.is_empty() {
            return Err(ProductionBackendConfigError::EmptyFindingsPostgresDsn);
        }

        Ok(Self {
            etcd,
            done_ledger_postgres_dsn,
            findings_postgres_dsn,
        })
    }

    /// Validated etcd coordination config.
    #[inline]
    #[must_use]
    pub fn etcd(&self) -> &EtcdCoordinatorConfig {
        &self.etcd
    }

    /// PostgreSQL connection string for the done-ledger backend.
    #[inline]
    #[must_use]
    pub(crate) fn done_ledger_postgres_dsn(&self) -> &str {
        &self.done_ledger_postgres_dsn
    }

    /// PostgreSQL connection string for the findings backend.
    #[inline]
    #[must_use]
    pub(crate) fn findings_postgres_dsn(&self) -> &str {
        &self.findings_postgres_dsn
    }
}

impl fmt::Debug for ProductionBackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProductionBackendConfig")
            .field("etcd", &self.etcd)
            .field("done_ledger_postgres_dsn", &"[redacted]")
            .field("findings_postgres_dsn", &"[redacted]")
            .finish()
    }
}

/// Validation errors for [`ProductionBackendConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionBackendConfigError {
    /// The done-ledger PostgreSQL DSN was empty after trimming whitespace.
    EmptyDoneLedgerPostgresDsn,
    /// The findings PostgreSQL DSN was empty after trimming whitespace.
    EmptyFindingsPostgresDsn,
}

impl fmt::Display for ProductionBackendConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDoneLedgerPostgresDsn => {
                f.write_str("done-ledger PostgreSQL DSN must not be empty")
            }
            Self::EmptyFindingsPostgresDsn => {
                f.write_str("findings PostgreSQL DSN must not be empty")
            }
        }
    }
}

impl Error for ProductionBackendConfigError {}

/// Typed startup failures for the production composition root.
///
/// Each variant identifies which backend connection or migration step
/// failed during construction.
#[derive(Debug)]
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
            Self::DoneLedgerConnect(source) => {
                write!(
                    f,
                    "failed to connect done-ledger PostgreSQL backend: {source}"
                )
            }
            Self::FindingsConnect(source) => {
                write!(f, "failed to connect findings PostgreSQL backend: {source}")
            }
            Self::EtcdConnect(source) => {
                write!(f, "failed to connect etcd coordination backend: {source}")
            }
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
            Self::DoneLedgerConnect(source) => Some(source),
            Self::FindingsConnect(source) => Some(source),
            Self::EtcdConnect(source) => Some(source),
            Self::DoneLedgerMigration(source) => Some(source),
            Self::FindingsMigration(source) => Some(source),
        }
    }
}

impl From<EtcdCoordinatorError> for ProductionBootstrapError {
    fn from(value: EtcdCoordinatorError) -> Self {
        Self::EtcdConnect(value)
    }
}

/// Error returned by the real worker entrypoint.
#[derive(Debug)]
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
/// Schema migrations must be applied on both persistence backends before
/// the first call to [`ProductionRuntimeBackends::run`]. Access the
/// backends via [`ProductionRuntimeBackends::persistence`] and call
/// `apply_migrations()` on both `done_ledger` and `findings_sink`.
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
    let coordinator = EtcdCoordinator::connect(config.etcd().clone())
        .map_err(ProductionBootstrapError::EtcdConnect)?;

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
/// Schema migrations must be applied on both persistence backends before
/// the first call to [`ProductionRuntimeBackends::run`]. Access the
/// backends via [`ProductionRuntimeBackends::persistence`] and call
/// `apply_migrations()` on both `done_ledger` and `findings_sink`.
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
    let coordinator =
        EtcdCoordinator::connect(etcd).map_err(ProductionBootstrapError::EtcdConnect)?;
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
const DEFAULT_CONNECT_TIMEOUT_SECS: u32 = 30;

fn connect_postgres_client(dsn: &str) -> Result<Client, postgres::Error> {
    if dsn.contains("connect_timeout") {
        Client::connect(dsn, NoTls)
    } else {
        let timed = format!("{dsn} connect_timeout={DEFAULT_CONNECT_TIMEOUT_SECS}");
        Client::connect(&timed, NoTls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::time::Duration;

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
    fn bootstrap_error_from_etcd_preserves_source_chain() {
        let inner = EtcdCoordinatorError::RuntimeBuild(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "synthetic etcd failure",
        ));
        let bootstrap: ProductionBootstrapError = inner.into();

        assert!(matches!(
            bootstrap,
            ProductionBootstrapError::EtcdConnect(_)
        ));
        assert!(bootstrap.source().is_some());
        assert!(bootstrap.to_string().contains("etcd coordination backend"));
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
}
