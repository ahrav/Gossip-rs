//! Production composition root for the distributed worker.
//!
//! This module is the thin outer layer that binds the generic distributed
//! runtime to the real infrastructure backends used by MVP-A:
//!
//! - [`gossip_coordination_etcd::EtcdCoordinator`]
//! - [`gossip_done_ledger_postgres::DoneLedgerPg`]
//! - [`gossip_findings_postgres::FindingsSinkPg`]
//!
//! The core runtime stays generic over `CoordinationFacade`, `DoneLedger`, and
//! `FindingsSink`. This module owns startup wiring, deterministic backend
//! readiness checks, and typed startup error classification.
//!
//! The DSN-based convenience constructor in this module uses
//! [`postgres::NoTls`]. That is appropriate for local MVP-A deployments and
//! integration tests where the worker talks to a trusted local PostgreSQL
//! instance. Callers that need TLS or custom PostgreSQL connection handling
//! should connect clients themselves and use
//! [`build_production_backends_from_clients`].

use std::error::Error;
use std::fmt;

use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig, EtcdCoordinatorError};
use gossip_done_ledger_postgres::{
    DoneLedgerPg, DoneLedgerPgMigrationError, MIGRATIONS as DONE_LEDGER_MIGRATIONS,
    apply_all_migrations as apply_done_ledger_migrations, schema as done_ledger_schema,
};
use gossip_findings_postgres::{
    FindingsPgMigrationError, FindingsSinkPg, MIGRATIONS as FINDINGS_MIGRATIONS,
    apply_all_migrations as apply_findings_migrations, schema as findings_schema,
};
use gossip_scanner_runtime::distributed::{
    DistributedPersistence, DistributedRunReport, DistributedRuntimeConfig, DistributedRuntimeError,
    WorkerIdentity, run_worker,
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
    pub fn done_ledger_postgres_dsn(&self) -> &str {
        &self.done_ledger_postgres_dsn
    }

    /// PostgreSQL connection string for the findings backend.
    #[inline]
    #[must_use]
    pub fn findings_postgres_dsn(&self) -> &str {
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

    /// Validate-only startup policy.
    #[must_use]
    pub fn validate_only() -> Self {
        Self::new(StartupSchemaMode::Validate)
    }

    /// Development-only auto-migrate startup policy.
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

/// Deterministic readiness failure for a PostgreSQL schema.
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
                write!(f, "required table '{table}' is missing from the current schema")
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
/// Every variant is fail-closed. No branch falls back to in-memory
/// coordination, in-memory persistence, or a no-op commit path.
#[derive(Debug)]
pub enum ProductionBootstrapError {
    /// Establishing the done-ledger PostgreSQL connection failed.
    DoneLedgerConnect(postgres::Error),
    /// Establishing the findings PostgreSQL connection failed.
    FindingsConnect(postgres::Error),
    /// Connecting the etcd coordinator failed.
    EtcdConnect(EtcdCoordinatorError),
    /// The etcd backend did not remain healthy during startup validation.
    EtcdReadiness(EtcdCoordinatorError),
    /// The done-ledger schema is not ready for validate-only boot.
    DoneLedgerSchemaReadiness(ProductionSchemaReadinessError),
    /// The findings schema is not ready for validate-only boot.
    FindingsSchemaReadiness(ProductionSchemaReadinessError),
    /// Development auto-migration of the done-ledger schema failed.
    DoneLedgerAutoMigrate(DoneLedgerPgMigrationError),
    /// Development auto-migration of the findings schema failed.
    FindingsAutoMigrate(FindingsPgMigrationError),
}

impl fmt::Display for ProductionBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoneLedgerConnect(source) => {
                write!(f, "failed to connect done-ledger PostgreSQL backend: {source}")
            }
            Self::FindingsConnect(source) => {
                write!(f, "failed to connect findings PostgreSQL backend: {source}")
            }
            Self::EtcdConnect(source) => {
                write!(f, "failed to connect etcd coordination backend: {source}")
            }
            Self::EtcdReadiness(source) => {
                write!(f, "etcd coordination backend failed startup readiness: {source}")
            }
            Self::DoneLedgerSchemaReadiness(source) => {
                write!(
                    f,
                    "done-ledger PostgreSQL schema is not ready for worker startup: {source}"
                )
            }
            Self::FindingsSchemaReadiness(source) => {
                write!(
                    f,
                    "findings PostgreSQL schema is not ready for worker startup: {source}"
                )
            }
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
            Self::DoneLedgerConnect(source) => Some(source),
            Self::FindingsConnect(source) => Some(source),
            Self::EtcdConnect(source) => Some(source),
            Self::EtcdReadiness(source) => Some(source),
            Self::DoneLedgerSchemaReadiness(source) => Some(source),
            Self::FindingsSchemaReadiness(source) => Some(source),
            Self::DoneLedgerAutoMigrate(source) => Some(source),
            Self::FindingsAutoMigrate(source) => Some(source),
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
    #[must_use]
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
    #[must_use]
    pub fn persistence_mut(
        &mut self,
    ) -> &mut DistributedPersistence<FindingsSinkPg, DoneLedgerPg> {
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
    pub fn run(
        mut self,
        identity: WorkerIdentity,
        runtime: DistributedRuntimeConfig,
    ) -> Result<DistributedRunReport, DistributedRuntimeError> {
        run_worker(&mut self.coordinator, identity, self.persistence, runtime)
    }
}

/// Build the real backend bundle from the DSN-based MVP-A config path.
///
/// This helper uses [`postgres::NoTls`]. Callers that need TLS or custom
/// connection setup should use [`build_production_backends_from_clients`].
pub fn build_production_backends(
    config: &ProductionBackendConfig,
    startup: ProductionStartupSettings,
) -> Result<ProductionRuntimeBackends, ProductionBootstrapError> {
    let done_ledger_client = connect_postgres_client(config.done_ledger_postgres_dsn())
        .map_err(ProductionBootstrapError::DoneLedgerConnect)?;
    let findings_client = connect_postgres_client(config.findings_postgres_dsn())
        .map_err(ProductionBootstrapError::FindingsConnect)?;

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
pub fn build_production_backends_from_clients(
    etcd: EtcdCoordinatorConfig,
    mut done_ledger_client: Client,
    mut findings_client: Client,
    startup: ProductionStartupSettings,
) -> Result<ProductionRuntimeBackends, ProductionBootstrapError> {
    let coordinator =
        EtcdCoordinator::connect(etcd).map_err(ProductionBootstrapError::EtcdConnect)?;
    validate_etcd_readiness(&coordinator)?;
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
/// This function never falls back to in-memory doubles or the CLI no-op commit
/// path. Either the real backends are built successfully and the generic
/// distributed runtime runs, or the function returns a typed error.
pub fn run_production_worker(
    config: &ProductionBackendConfig,
    startup: ProductionStartupSettings,
    identity: WorkerIdentity,
    runtime: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, ProductionWorkerError> {
    let backends = build_production_backends(config, startup)?;
    backends.run(identity, runtime).map_err(ProductionWorkerError::Runtime)
}

fn connect_postgres_client(dsn: &str) -> Result<Client, postgres::Error> {
    Client::connect(dsn, NoTls)
}

fn validate_etcd_readiness(coordinator: &EtcdCoordinator) -> Result<(), ProductionBootstrapError> {
    coordinator
        .status()
        .map(|_| ())
        .map_err(ProductionBootstrapError::EtcdReadiness)
}

fn prepare_done_ledger_backend(
    client: &mut Client,
    startup: ProductionStartupSettings,
) -> Result<(), ProductionBootstrapError> {
    match startup.schema_mode() {
        StartupSchemaMode::Validate => validate_done_ledger_schema_readiness(client)
            .map_err(ProductionBootstrapError::DoneLedgerSchemaReadiness),
        StartupSchemaMode::DevAutoMigrate => {
            apply_done_ledger_migrations(client)
                .map_err(ProductionBootstrapError::DoneLedgerAutoMigrate)?;
            validate_done_ledger_schema_readiness(client)
                .map_err(ProductionBootstrapError::DoneLedgerSchemaReadiness)
        }
    }
}

fn prepare_findings_backend(
    client: &mut Client,
    startup: ProductionStartupSettings,
) -> Result<(), ProductionBootstrapError> {
    match startup.schema_mode() {
        StartupSchemaMode::Validate => validate_findings_schema_readiness(client)
            .map_err(ProductionBootstrapError::FindingsSchemaReadiness),
        StartupSchemaMode::DevAutoMigrate => {
            apply_findings_migrations(client)
                .map_err(ProductionBootstrapError::FindingsAutoMigrate)?;
            validate_findings_schema_readiness(client)
                .map_err(ProductionBootstrapError::FindingsSchemaReadiness)
        }
    }
}

fn validate_done_ledger_schema_readiness(
    client: &mut Client,
) -> Result<(), ProductionSchemaReadinessError> {
    ensure_expected_tables_exist(
        client,
        &[
            done_ledger_schema::DONE_LEDGER_ENTRIES_TABLE,
            done_ledger_schema::SCHEMA_MIGRATIONS_TABLE,
        ],
    )?;

    let required_migrations = DONE_LEDGER_MIGRATIONS
        .iter()
        .map(|migration| (migration.version(), *migration.checksum().as_bytes()))
        .collect::<Vec<_>>();
    ensure_migration_history_ready(
        client,
        done_ledger_schema::SCHEMA_MIGRATIONS_TABLE,
        &required_migrations,
    )
}

fn validate_findings_schema_readiness(
    client: &mut Client,
) -> Result<(), ProductionSchemaReadinessError> {
    ensure_expected_tables_exist(
        client,
        &[
            findings_schema::FINDINGS_TABLE,
            findings_schema::OCCURRENCES_TABLE,
            findings_schema::OBSERVATIONS_TABLE,
            findings_schema::SCHEMA_MIGRATIONS_TABLE,
        ],
    )?;

    let required_migrations = FINDINGS_MIGRATIONS
        .iter()
        .map(|migration| (migration.version(), *migration.checksum().as_bytes()))
        .collect::<Vec<_>>();
    ensure_migration_history_ready(
        client,
        findings_schema::SCHEMA_MIGRATIONS_TABLE,
        &required_migrations,
    )
}

fn ensure_expected_tables_exist(
    client: &mut Client,
    expected_tables: &[&'static str],
) -> Result<(), ProductionSchemaReadinessError> {
    for &table in expected_tables {
        ensure_table_exists(client, table)?;
    }
    Ok(())
}

fn ensure_table_exists(
    client: &mut Client,
    table: &'static str,
) -> Result<(), ProductionSchemaReadinessError> {
    let exists = client
        .query_one(
            "SELECT EXISTS (\
                 SELECT 1\
                   FROM pg_catalog.pg_tables\
                  WHERE schemaname = current_schema()\
                    AND tablename = $1\
             )",
            &[&table],
        )
        .map_err(ProductionSchemaReadinessError::Query)?
        .get::<_, bool>(0);

    if exists {
        Ok(())
    } else {
        Err(ProductionSchemaReadinessError::MissingTable { table })
    }
}

fn ensure_migration_history_ready(
    client: &mut Client,
    history_table: &'static str,
    required_migrations: &[(&'static str, [u8; 32])],
) -> Result<(), ProductionSchemaReadinessError> {
    let statement = client
        .prepare(&format!(
            "SELECT checksum FROM {history_table} WHERE version = $1"
        ))
        .map_err(ProductionSchemaReadinessError::Query)?;

    for &(version, expected_checksum) in required_migrations {
        let maybe_row = client
            .query_opt(&statement, &[&version])
            .map_err(ProductionSchemaReadinessError::Query)?;
        let Some(row) = maybe_row else {
            return Err(ProductionSchemaReadinessError::MissingAppliedMigration {
                history_table,
                version,
            });
        };

        let stored_checksum: Vec<u8> = row.get(0);
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

    use std::{fs, path::Path, sync::Arc, time::Duration};

    use gossip_contracts::identity::{PolicyHash, RunId, TenantId, TenantSecretKey, WorkerId};
    use gossip_coordination_etcd::test_support::test_async_coordinator_config;
    use gossip_pg_common::test_support::create_test_db;
    use gossip_scanner_runtime::{ExecutionMode, FsScanConfig, ScanBudgets};
    use tempfile::tempdir;

    use crate::recorder::ProductionCoordinationEventRecorder;

    fn fresh_backend_config() -> ProductionBackendConfig {
        ProductionBackendConfig::new(
            test_async_coordinator_config(),
            create_test_db(),
            create_test_db(),
        )
        .expect("test backend config should be valid")
    }

    fn migrated_backend_config() -> ProductionBackendConfig {
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        apply_done_ledger_migrations(
            &mut Client::connect(&done_ledger_dsn, NoTls)
                .expect("done-ledger test database should accept connections"),
        )
        .expect("done-ledger test migrations should succeed");
        apply_findings_migrations(
            &mut Client::connect(&findings_dsn, NoTls)
                .expect("findings test database should accept connections"),
        )
        .expect("findings test migrations should succeed");
        ProductionBackendConfig::new(test_async_coordinator_config(), done_ledger_dsn, findings_dsn)
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
    }

    #[test]
    fn config_rejects_empty_findings_dsn() {
        let error = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "host=127.0.0.1 port=5432 dbname=gossip",
            "   ",
        )
        .expect_err("empty findings DSN must be rejected");

        assert_eq!(error, ProductionBackendConfigError::EmptyFindingsPostgresDsn);
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
    fn validate_only_fails_when_done_ledger_schema_is_missing() {
        let config = fresh_backend_config();
        let error = build_production_backends(&config, ProductionStartupSettings::validate_only())
            .expect_err("validate-only boot must fail on a fresh done-ledger database");

        assert!(matches!(
            error,
            ProductionBootstrapError::DoneLedgerSchemaReadiness(
                ProductionSchemaReadinessError::MissingTable { .. }
                    | ProductionSchemaReadinessError::MissingAppliedMigration { .. }
            )
        ));
    }

    #[test]
    fn validate_only_fails_when_findings_schema_is_missing() {
        let done_ledger_dsn = create_test_db();
        apply_done_ledger_migrations(
            &mut Client::connect(&done_ledger_dsn, NoTls)
                .expect("done-ledger test database should accept connections"),
        )
        .expect("done-ledger migrations should succeed");
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
                    | ProductionSchemaReadinessError::MissingAppliedMigration { .. }
            )
        ));
    }

    #[test]
    fn dev_auto_migrate_bootstraps_fresh_databases() {
        let config = fresh_backend_config();
        let backends = build_production_backends(&config, ProductionStartupSettings::dev_auto_migrate())
            .expect("development auto-migrate should make fresh databases ready");

        backends
            .persistence()
            .findings_sink
            .validate_connection(Duration::from_secs(1))
            .expect("findings connection should remain usable after startup readiness");
    }

    #[test]
    fn build_production_backends_from_clients_connects_live_backends() {
        let etcd = test_async_coordinator_config();
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        apply_done_ledger_migrations(
            &mut Client::connect(&done_ledger_dsn, NoTls)
                .expect("done-ledger test database should accept connections"),
        )
        .expect("done-ledger migrations should succeed");
        apply_findings_migrations(
            &mut Client::connect(&findings_dsn, NoTls)
                .expect("findings test database should accept connections"),
        )
        .expect("findings migrations should succeed");
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
        fs::write(dir.path().join("secret.txt"), "token=step6-real-backend-proof")
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
        fs::write(dir.path().join("secret.txt"), "token=step6-readiness-proof")
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
}
