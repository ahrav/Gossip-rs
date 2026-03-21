//! Typed configuration surface for worker launches.
//!
//! This module resolves environment variables plus CLI overrides into one of
//! two explicit launch paths:
//!
//! - local scans (`ExecutionMode::Direct` or explicit `--backend=local`)
//! - real distributed scans (`--backend=production`)
//!
//! Connector mode never silently falls back to a local or fake backend. The
//! caller must select a backend explicitly.

use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result as AnyhowResult;
use gossip_contracts::identity::{PolicyHash, RunId, TenantId, TenantSecretKey, WorkerId};
use gossip_coordination_etcd::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
use gossip_scanner_runtime::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, StoredGitEvent,
};
use gossip_scanner_runtime::distributed::{DistributedRuntimeConfig, WorkerIdentity};
use gossip_scanner_runtime::{
    AnchorMode, ExecutionMode, FsScanConfig, GitScanConfig, OwnedCoreEvent, ScanBudgets,
};

/// Environment variable selecting the worker runtime family.
pub const ENV_WORKER_MODE: &str = "GOSSIP_WORKER_MODE";
/// Environment variable selecting the worker backend.
pub const ENV_WORKER_BACKEND: &str = "GOSSIP_WORKER_BACKEND";
/// Environment variable selecting the source family.
pub const ENV_WORKER_SOURCE: &str = "GOSSIP_WORKER_SOURCE";
/// Environment variable supplying the filesystem path or git repository path.
pub const ENV_WORKER_PATH: &str = "GOSSIP_WORKER_PATH";
/// Environment variable supplying the etcd endpoint CSV.
pub const ENV_ETCD_ENDPOINTS: &str = "GOSSIP_ETCD_ENDPOINTS";
/// Environment variable supplying the etcd namespace prefix.
pub const ENV_ETCD_NAMESPACE: &str = "GOSSIP_ETCD_NAMESPACE";
/// Environment variable supplying the done-ledger PostgreSQL DSN.
pub const ENV_DONE_LEDGER_POSTGRES_DSN: &str = "GOSSIP_DONE_LEDGER_POSTGRES_DSN";
/// Environment variable supplying the findings PostgreSQL DSN.
pub const ENV_FINDINGS_POSTGRES_DSN: &str = "GOSSIP_FINDINGS_POSTGRES_DSN";
/// Environment variable supplying the tenant id as a 32-byte hex string.
pub const ENV_TENANT_ID: &str = "GOSSIP_TENANT_ID";
/// Environment variable supplying the run id as a `u64`.
pub const ENV_RUN_ID: &str = "GOSSIP_RUN_ID";
/// Environment variable supplying the worker id as a `u64`.
pub const ENV_WORKER_ID: &str = "GOSSIP_WORKER_ID";
/// Environment variable supplying the policy hash as a 32-byte hex string.
pub const ENV_POLICY_HASH: &str = "GOSSIP_POLICY_HASH";
/// Environment variable supplying the tenant secret key as a 32-byte hex string.
pub const ENV_TENANT_SECRET_KEY: &str = "GOSSIP_TENANT_SECRET_KEY";
/// Environment variable supplying the maximum items processed between checkpoints.
pub const ENV_MAX_ITEMS: &str = "GOSSIP_MAX_ITEMS";
/// Environment variable supplying the maximum bytes processed between checkpoints.
pub const ENV_MAX_BYTES: &str = "GOSSIP_MAX_BYTES";
/// Environment variable supplying the bounded commit queue capacity.
pub const ENV_COMMIT_QUEUE_CAPACITY: &str = "GOSSIP_COMMIT_QUEUE_CAPACITY";
/// Environment variable supplying an optional rules file.
pub const ENV_WORKER_RULES_FILE: &str = "GOSSIP_WORKER_RULES_FILE";
/// Environment variable supplying an optional decode depth override.
pub const ENV_WORKER_DECODE_DEPTH: &str = "GOSSIP_WORKER_DECODE_DEPTH";
/// Environment variable enabling or disabling binary scanning.
pub const ENV_WORKER_SCAN_BINARY: &str = "GOSSIP_WORKER_SCAN_BINARY";
/// Environment variable enabling or disabling archive expansion for filesystem scans.
pub const ENV_FS_SKIP_ARCHIVES: &str = "GOSSIP_FS_SKIP_ARCHIVES";
/// Environment variable selecting the anchor extraction mode.
pub const ENV_WORKER_ANCHOR_MODE: &str = "GOSSIP_WORKER_ANCHOR_MODE";

/// Ceiling for max_items to prevent resource exhaustion from misconfiguration.
const MAX_ITEMS_CEILING: usize = 10_000_000;
/// Ceiling for max_bytes to prevent resource exhaustion from misconfiguration.
const MAX_BYTES_CEILING: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB
/// Ceiling for commit_queue_capacity to prevent resource exhaustion from misconfiguration.
const MAX_COMMIT_QUEUE_CEILING: usize = 65_536;

/// Backend selection for connector-mode launches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendSelection {
    /// Existing local/non-production worker path.
    Local,
    /// Real etcd + PostgreSQL production path.
    Production,
}

impl FromStr for BackendSelection {
    type Err = WorkerConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            _ => Err(WorkerConfigError::invalid_value(
                "backend",
                value,
                "expected 'local' or 'production'",
            )),
        }
    }
}

impl fmt::Display for BackendSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("local"),
            Self::Production => f.write_str("production"),
        }
    }
}

/// Source family selected by the worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerSource {
    /// Filesystem scan.
    Fs,
    /// Local Git repository scan.
    Git,
}

impl FromStr for WorkerSource {
    type Err = WorkerConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "fs" => Ok(Self::Fs),
            "git" => Ok(Self::Git),
            _ => Err(WorkerConfigError::invalid_value(
                "source",
                value,
                "expected 'fs' or 'git'",
            )),
        }
    }
}

/// Scan tuning shared by both filesystem and git source types.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommonScanSettings {
    decode_depth: Option<usize>,
    scan_binary: bool,
    rules_file: Option<PathBuf>,
    anchor_mode: AnchorMode,
}

impl CommonScanSettings {
    #[inline]
    #[must_use]
    pub fn decode_depth(&self) -> Option<usize> {
        self.decode_depth
    }

    #[inline]
    #[must_use]
    pub fn scan_binary(&self) -> bool {
        self.scan_binary
    }

    #[inline]
    #[must_use]
    pub fn rules_file(&self) -> Option<&Path> {
        self.rules_file.as_deref()
    }

    #[inline]
    #[must_use]
    pub fn anchor_mode(&self) -> AnchorMode {
        self.anchor_mode
    }

    #[must_use]
    pub fn with_decode_depth(mut self, decode_depth: Option<usize>) -> Self {
        self.decode_depth = decode_depth;
        self
    }

    #[must_use]
    pub fn with_scan_binary(mut self, scan_binary: bool) -> Self {
        self.scan_binary = scan_binary;
        self
    }

    #[must_use]
    pub fn with_rules_file(mut self, rules_file: Option<PathBuf>) -> Self {
        self.rules_file = rules_file;
        self
    }

    #[must_use]
    pub fn with_anchor_mode(mut self, anchor_mode: AnchorMode) -> Self {
        self.anchor_mode = anchor_mode;
        self
    }
}

/// Filesystem-specific source settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsSourceSettings {
    path: PathBuf,
    skip_archives: bool,
    common: CommonScanSettings,
}

impl FsSourceSettings {
    /// Construct one filesystem source settings bundle.
    ///
    /// This constructor does not validate the path. When used through the
    /// resolution pipeline ([`resolve_worker_config_from`]), path validation
    /// (non-empty, trimmed) is handled by the parser layer. Direct callers
    /// are responsible for supplying a meaningful path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            skip_archives: false,
            common: CommonScanSettings::default(),
        }
    }

    #[inline]
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    #[must_use]
    pub fn decode_depth(&self) -> Option<usize> {
        self.common.decode_depth()
    }

    #[inline]
    #[must_use]
    pub fn skip_archives(&self) -> bool {
        self.skip_archives
    }

    #[inline]
    #[must_use]
    pub fn scan_binary(&self) -> bool {
        self.common.scan_binary()
    }

    #[inline]
    #[must_use]
    pub fn rules_file(&self) -> Option<&Path> {
        self.common.rules_file()
    }

    #[inline]
    #[must_use]
    pub fn anchor_mode(&self) -> AnchorMode {
        self.common.anchor_mode()
    }

    #[must_use]
    pub fn with_decode_depth(mut self, decode_depth: Option<usize>) -> Self {
        self.common = self.common.with_decode_depth(decode_depth);
        self
    }

    #[must_use]
    pub fn with_skip_archives(mut self, skip_archives: bool) -> Self {
        self.skip_archives = skip_archives;
        self
    }

    #[must_use]
    pub fn with_scan_binary(mut self, scan_binary: bool) -> Self {
        self.common = self.common.with_scan_binary(scan_binary);
        self
    }

    #[must_use]
    pub fn with_rules_file(mut self, rules_file: Option<PathBuf>) -> Self {
        self.common = self.common.with_rules_file(rules_file);
        self
    }

    #[must_use]
    pub fn with_anchor_mode(mut self, anchor_mode: AnchorMode) -> Self {
        self.common = self.common.with_anchor_mode(anchor_mode);
        self
    }

    /// Convert the typed source settings into a runtime scan config.
    #[must_use]
    pub fn to_scan_config(
        &self,
        execution_mode: ExecutionMode,
        budgets: ScanBudgets,
    ) -> FsScanConfig {
        FsScanConfig::new(self.path.clone())
            .with_decode_depth(self.common.decode_depth)
            .with_skip_archives(self.skip_archives)
            .with_scan_binary(self.common.scan_binary)
            .with_rules_file(self.common.rules_file.clone())
            .with_anchor_mode(self.common.anchor_mode)
            .with_execution_mode(execution_mode)
            .with_budgets(budgets)
    }
}

/// Git-specific source settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitSourceSettings {
    repo: PathBuf,
    common: CommonScanSettings,
}

impl GitSourceSettings {
    /// Construct one git source settings bundle.
    ///
    /// This constructor does not validate the repo path. When used through
    /// the resolution pipeline ([`resolve_worker_config_from`]), path
    /// validation (non-empty, trimmed) is handled by the parser layer.
    /// Direct callers are responsible for supplying a meaningful path.
    #[must_use]
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self {
            repo: repo.into(),
            common: CommonScanSettings::default(),
        }
    }

    #[inline]
    #[must_use]
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    #[inline]
    #[must_use]
    pub fn decode_depth(&self) -> Option<usize> {
        self.common.decode_depth()
    }

    #[inline]
    #[must_use]
    pub fn scan_binary(&self) -> bool {
        self.common.scan_binary()
    }

    #[inline]
    #[must_use]
    pub fn rules_file(&self) -> Option<&Path> {
        self.common.rules_file()
    }

    #[inline]
    #[must_use]
    pub fn anchor_mode(&self) -> AnchorMode {
        self.common.anchor_mode()
    }

    #[must_use]
    pub fn with_decode_depth(mut self, decode_depth: Option<usize>) -> Self {
        self.common = self.common.with_decode_depth(decode_depth);
        self
    }

    #[must_use]
    pub fn with_scan_binary(mut self, scan_binary: bool) -> Self {
        self.common = self.common.with_scan_binary(scan_binary);
        self
    }

    #[must_use]
    pub fn with_rules_file(mut self, rules_file: Option<PathBuf>) -> Self {
        self.common = self.common.with_rules_file(rules_file);
        self
    }

    #[must_use]
    pub fn with_anchor_mode(mut self, anchor_mode: AnchorMode) -> Self {
        self.common = self.common.with_anchor_mode(anchor_mode);
        self
    }

    /// Convert the typed source settings into a runtime scan config.
    #[must_use]
    pub fn to_scan_config(
        &self,
        execution_mode: ExecutionMode,
        budgets: ScanBudgets,
    ) -> GitScanConfig {
        GitScanConfig::new(self.repo.clone())
            .with_decode_depth(self.common.decode_depth)
            .with_scan_binary(self.common.scan_binary)
            .with_rules_file(self.common.rules_file.clone())
            .with_anchor_mode(self.common.anchor_mode)
            .with_execution_mode(execution_mode)
            .with_budgets(budgets)
    }
}

/// Typed source settings for worker launches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerSourceSettings {
    /// Filesystem settings.
    Fs(FsSourceSettings),
    /// Git settings.
    Git(GitSourceSettings),
}

/// Typed local worker launch configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWorkerConfig {
    execution_mode: ExecutionMode,
    source: WorkerSourceSettings,
    budgets: ScanBudgets,
}

impl LocalWorkerConfig {
    /// Construct one local worker launch configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerConfigError`] when `max_items` or `max_bytes` is zero,
    /// or when either value exceeds the configured validation ceiling
    /// (`max_items` > 10,000,000 or `max_bytes` > 64 GiB).
    pub fn new(
        execution_mode: ExecutionMode,
        source: WorkerSourceSettings,
        budgets: ScanBudgets,
    ) -> Result<Self, WorkerConfigError> {
        validate_budgets(&budgets)?;
        Ok(Self {
            execution_mode,
            source,
            budgets,
        })
    }

    #[inline]
    #[must_use]
    pub fn execution_mode(&self) -> ExecutionMode {
        self.execution_mode
    }

    #[inline]
    #[must_use]
    pub fn source(&self) -> &WorkerSourceSettings {
        &self.source
    }

    #[inline]
    #[must_use]
    pub fn budgets(&self) -> ScanBudgets {
        self.budgets
    }
}

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

impl std::error::Error for ProductionBackendConfigError {}

/// Distributed runtime tuning parsed from worker config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DistributedWorkerRuntimeSettings {
    budgets: ScanBudgets,
    commit_queue_capacity: NonZeroUsize,
}

impl Default for DistributedWorkerRuntimeSettings {
    fn default() -> Self {
        let defaults = DistributedRuntimeConfig::default();
        Self {
            budgets: defaults.budgets,
            commit_queue_capacity: defaults.commit_queue_capacity,
        }
    }
}

impl DistributedWorkerRuntimeSettings {
    /// Construct one runtime tuning bundle.
    #[must_use]
    pub fn new(budgets: ScanBudgets, commit_queue_capacity: NonZeroUsize) -> Self {
        Self {
            budgets,
            commit_queue_capacity,
        }
    }

    #[inline]
    #[must_use]
    pub fn budgets(&self) -> ScanBudgets {
        self.budgets
    }

    #[inline]
    #[must_use]
    pub fn commit_queue_capacity(&self) -> NonZeroUsize {
        self.commit_queue_capacity
    }

    #[inline]
    #[must_use]
    pub fn to_runtime_config(self) -> DistributedRuntimeConfig {
        DistributedRuntimeConfig {
            budgets: self.budgets,
            commit_queue_capacity: self.commit_queue_capacity,
        }
    }
}

/// Grouped identity fields for a distributed worker.
///
/// These five fields map to the identity-bearing fields of [`WorkerIdentity`]
/// at runtime. The remaining `WorkerIdentity` fields (scan template and
/// recorder) are supplied separately.
///
/// # Invariants
///
/// `tenant_secret_key` must not be all zeros (validated at construction).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WorkerIdentityConfig {
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
    policy_hash: PolicyHash,
    tenant_secret_key: TenantSecretKey,
}

impl WorkerIdentityConfig {
    /// Construct a validated identity config.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerConfigError`] when `run` or `worker` is the zero
    /// sentinel, or when `tenant_secret_key` is all zeros.
    pub fn new(
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        policy_hash: PolicyHash,
        tenant_secret_key: TenantSecretKey,
    ) -> Result<Self, WorkerConfigError> {
        if run == RunId::ZERO {
            return Err(WorkerConfigError::invalid_value(
                "run_id",
                "0",
                "must be > 0 (0 is the unassigned sentinel)",
            ));
        }
        if worker == WorkerId::ZERO {
            return Err(WorkerConfigError::invalid_value(
                "worker_id",
                "0",
                "must be > 0 (0 is the unassigned sentinel)",
            ));
        }
        if !tenant_secret_key.is_valid() {
            return Err(WorkerConfigError::invalid_redacted_value(
                "tenant_secret_key",
                "must not be all zeros",
            ));
        }
        Ok(Self {
            tenant,
            run,
            worker,
            policy_hash,
            tenant_secret_key,
        })
    }

    #[inline]
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[inline]
    #[must_use]
    pub fn run(&self) -> RunId {
        self.run
    }

    #[inline]
    #[must_use]
    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    #[inline]
    #[must_use]
    pub fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    #[inline]
    #[must_use]
    pub fn tenant_secret_key(&self) -> TenantSecretKey {
        self.tenant_secret_key
    }
}

impl fmt::Debug for WorkerIdentityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerIdentityConfig")
            .field("tenant", &self.tenant)
            .field("run", &self.run)
            .field("worker", &self.worker)
            .field("policy_hash", &self.policy_hash)
            .field("tenant_secret_key", &"[redacted]")
            .finish()
    }
}

/// Typed real-backend distributed worker launch configuration.
#[derive(Clone, Debug)]
pub struct DistributedWorkerConfig {
    backends: ProductionBackendConfig,
    identity: WorkerIdentityConfig,
    source: FsSourceSettings,
    runtime: DistributedWorkerRuntimeSettings,
}

impl DistributedWorkerConfig {
    /// Construct one validated distributed worker configuration bundle.
    ///
    /// Enforces non-zero budget invariants and resource-exhaustion ceilings as
    /// defense-in-depth. The secret-key and zero-ID invariants are enforced by
    /// [`WorkerIdentityConfig::new`].
    pub fn new(
        backends: ProductionBackendConfig,
        identity: WorkerIdentityConfig,
        source: FsSourceSettings,
        runtime: DistributedWorkerRuntimeSettings,
    ) -> Result<Self, WorkerConfigError> {
        validate_budgets(&runtime.budgets)?;
        if runtime.commit_queue_capacity().get() > MAX_COMMIT_QUEUE_CEILING {
            return Err(WorkerConfigError::invalid_value(
                "commit_queue_capacity",
                runtime.commit_queue_capacity().get().to_string(),
                format!("exceeds maximum of {MAX_COMMIT_QUEUE_CEILING}"),
            ));
        }
        Ok(Self {
            backends,
            identity,
            source,
            runtime,
        })
    }

    /// The distributed config is always the production backend path.
    #[inline]
    #[must_use]
    pub fn backend(&self) -> BackendSelection {
        BackendSelection::Production
    }

    #[inline]
    #[must_use]
    pub fn production_backends(&self) -> &ProductionBackendConfig {
        &self.backends
    }

    #[inline]
    #[must_use]
    pub fn identity(&self) -> &WorkerIdentityConfig {
        &self.identity
    }

    #[inline]
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.identity.tenant()
    }

    #[inline]
    #[must_use]
    pub fn run(&self) -> RunId {
        self.identity.run()
    }

    #[inline]
    #[must_use]
    pub fn worker(&self) -> WorkerId {
        self.identity.worker()
    }

    #[inline]
    #[must_use]
    pub fn policy_hash(&self) -> PolicyHash {
        self.identity.policy_hash()
    }

    #[inline]
    #[must_use]
    pub fn tenant_secret_key(&self) -> TenantSecretKey {
        self.identity.tenant_secret_key()
    }

    #[inline]
    #[must_use]
    pub fn source(&self) -> &FsSourceSettings {
        &self.source
    }

    #[inline]
    #[must_use]
    pub fn runtime(&self) -> DistributedWorkerRuntimeSettings {
        self.runtime
    }

    /// Build the runtime `WorkerIdentity` with a no-op recorder that discards
    /// all coordination events.
    ///
    /// Use [`Self::worker_identity_with_recorder`] to supply a real recorder.
    #[must_use]
    pub fn worker_identity_noop(&self) -> WorkerIdentity {
        self.worker_identity_with_recorder(Arc::new(NoopCoordinationEventRecorder))
    }

    /// Build the runtime `WorkerIdentity` using a caller-supplied recorder.
    #[must_use]
    pub fn worker_identity_with_recorder(
        &self,
        recorder: Arc<dyn CoordinationEventRecorder>,
    ) -> WorkerIdentity {
        WorkerIdentity::new(
            self.identity.tenant(),
            self.identity.run(),
            self.identity.worker(),
            self.identity.policy_hash(),
            self.identity.tenant_secret_key(),
            self.source
                .to_scan_config(ExecutionMode::Connector, self.runtime.budgets()),
            recorder,
        )
    }

    /// Convert the parsed runtime settings into the runtime struct expected by the worker loop.
    #[inline]
    #[must_use]
    pub fn runtime_config(&self) -> DistributedRuntimeConfig {
        self.runtime.to_runtime_config()
    }
}

/// Fully resolved worker launch configuration.
#[derive(Clone, Debug)]
pub enum ResolvedWorkerConfig {
    /// Local scan path (direct or explicit local connector mode).
    Local(LocalWorkerConfig),
    /// Real etcd + PostgreSQL distributed worker path.
    Distributed(Box<DistributedWorkerConfig>),
}

/// Error returned when parsing or validating worker configuration.
#[derive(Debug)]
pub enum WorkerConfigError {
    /// Invalid CLI usage or unknown flags.
    Usage(String),
    /// A required field was missing.
    MissingRequiredValue {
        field: &'static str,
        flag: &'static str,
        env: &'static str,
    },
    /// A field value was present but invalid.
    InvalidValue {
        field: &'static str,
        value: String,
        reason: String,
    },
    /// The etcd configuration was syntactically invalid.
    InvalidEtcdConfig(EtcdCoordinatorConfigError),
    /// The production backend configuration was invalid.
    InvalidBackendConfig(ProductionBackendConfigError),
    /// The provided combination of mode, backend, and source is unsupported.
    UnsupportedCombination { message: String },
}

impl WorkerConfigError {
    fn invalid_value(
        field: &'static str,
        value: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InvalidValue {
            field,
            value: value.into(),
            reason: reason.into(),
        }
    }

    fn invalid_redacted_value(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidValue {
            field,
            value: "[redacted]".to_owned(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for WorkerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::MissingRequiredValue { field, flag, env } => write!(
                f,
                "missing required value for {field} (set {flag}=... or {env}=...)"
            ),
            Self::InvalidValue {
                field,
                value,
                reason,
            } => write!(f, "invalid value for {field}: {value} ({reason})"),
            Self::InvalidEtcdConfig(source) => {
                write!(f, "invalid etcd worker configuration: {source}")
            }
            Self::InvalidBackendConfig(source) => {
                write!(f, "invalid production backend configuration: {source}")
            }
            Self::UnsupportedCombination { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for WorkerConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEtcdConfig(source) => Some(source),
            Self::InvalidBackendConfig(source) => Some(source),
            _ => None,
        }
    }
}

impl From<EtcdCoordinatorConfigError> for WorkerConfigError {
    fn from(value: EtcdCoordinatorConfigError) -> Self {
        Self::InvalidEtcdConfig(value)
    }
}

impl From<ProductionBackendConfigError> for WorkerConfigError {
    fn from(value: ProductionBackendConfigError) -> Self {
        Self::InvalidBackendConfig(value)
    }
}

/// Provider abstraction for environment variable access.
pub trait EnvProvider {
    /// Return the current value for `key`, if it is set.
    fn get(&self, key: &'static str) -> Option<String>;
}

/// Environment provider backed by the current process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnv;

impl EnvProvider for ProcessEnv {
    fn get(&self, key: &'static str) -> Option<String> {
        match std::env::var(key) {
            Ok(val) => Some(val),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                tracing::error!(
                    env_var = key,
                    "environment variable contains invalid UTF-8; treating as absent"
                );
                None
            }
        }
    }
}

#[derive(Clone, Default)]
struct RawWorkerConfig {
    execution_mode: Option<String>,
    backend: Option<String>,
    source: Option<String>,
    path: Option<String>,
    rules_file: Option<String>,
    decode_depth: Option<String>,
    scan_binary: Option<String>,
    skip_archives: Option<String>,
    anchor_mode: Option<String>,
    max_items: Option<String>,
    max_bytes: Option<String>,
    commit_queue_capacity: Option<String>,
    etcd_endpoints_csv: Option<String>,
    etcd_namespace: Option<String>,
    done_ledger_postgres_dsn: Option<String>,
    findings_postgres_dsn: Option<String>,
    tenant: Option<String>,
    run: Option<String>,
    worker: Option<String>,
    policy_hash: Option<String>,
    tenant_secret_key: Option<String>,
}

impl fmt::Debug for RawWorkerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawWorkerConfig")
            .field("execution_mode", &self.execution_mode)
            .field("backend", &self.backend)
            .field("source", &self.source)
            .field("path", &self.path)
            .field("rules_file", &self.rules_file)
            .field("decode_depth", &self.decode_depth)
            .field("scan_binary", &self.scan_binary)
            .field("skip_archives", &self.skip_archives)
            .field("anchor_mode", &self.anchor_mode)
            .field("max_items", &self.max_items)
            .field("max_bytes", &self.max_bytes)
            .field("commit_queue_capacity", &self.commit_queue_capacity)
            .field("etcd_endpoints_csv", &self.etcd_endpoints_csv)
            .field("etcd_namespace", &self.etcd_namespace)
            .field("done_ledger_postgres_dsn", &"[redacted]")
            .field("findings_postgres_dsn", &"[redacted]")
            .field("tenant", &self.tenant)
            .field("run", &self.run)
            .field("worker", &self.worker)
            .field("policy_hash", &self.policy_hash)
            .field("tenant_secret_key", &"[redacted]")
            .finish()
    }
}

impl RawWorkerConfig {
    fn from_env<E: EnvProvider + ?Sized>(env: &E) -> Self {
        Self {
            execution_mode: env.get(ENV_WORKER_MODE),
            backend: env.get(ENV_WORKER_BACKEND),
            source: env.get(ENV_WORKER_SOURCE),
            path: env.get(ENV_WORKER_PATH),
            rules_file: env.get(ENV_WORKER_RULES_FILE),
            decode_depth: env.get(ENV_WORKER_DECODE_DEPTH),
            scan_binary: env.get(ENV_WORKER_SCAN_BINARY),
            skip_archives: env.get(ENV_FS_SKIP_ARCHIVES),
            anchor_mode: env.get(ENV_WORKER_ANCHOR_MODE),
            max_items: env.get(ENV_MAX_ITEMS),
            max_bytes: env.get(ENV_MAX_BYTES),
            commit_queue_capacity: env.get(ENV_COMMIT_QUEUE_CAPACITY),
            etcd_endpoints_csv: env.get(ENV_ETCD_ENDPOINTS),
            etcd_namespace: env.get(ENV_ETCD_NAMESPACE),
            done_ledger_postgres_dsn: env.get(ENV_DONE_LEDGER_POSTGRES_DSN),
            findings_postgres_dsn: env.get(ENV_FINDINGS_POSTGRES_DSN),
            tenant: env.get(ENV_TENANT_ID),
            run: env.get(ENV_RUN_ID),
            worker: env.get(ENV_WORKER_ID),
            policy_hash: env.get(ENV_POLICY_HASH),
            tenant_secret_key: env.get(ENV_TENANT_SECRET_KEY),
        }
    }

    fn apply_cli_args<I, S>(&mut self, args: I) -> Result<(), WorkerConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut positionals = Vec::new();
        let mut flag_set_source = false;
        let mut flag_set_path = false;
        for raw_arg in args.into_iter().map(Into::into) {
            if let Some(flag) = raw_arg.strip_prefix("--") {
                let (name, value) = flag.split_once('=').ok_or_else(|| {
                    WorkerConfigError::Usage(format!("invalid flag '{raw_arg}'\n{}", usage()))
                })?;
                match name {
                    "source" => flag_set_source = true,
                    "path" => flag_set_path = true,
                    _ => {}
                }
                self.apply_cli_override(name, value)?;
            } else {
                positionals.push(raw_arg);
            }
        }

        // Positional args override environment variables (expected), but
        // conflict with explicit --source / --path flags (ambiguous intent).
        match positionals.len() {
            0 => Ok(()),
            1 => {
                // A single positional that matches a known source token
                // ("fs" or "git") is interpreted as the source selector,
                // not the path. This matches the documented CLI shape:
                //   gossip-worker [flags...] [source] [path]
                let token = positionals[0].trim().to_ascii_lowercase();
                if token == "fs" || token == "git" {
                    if flag_set_source {
                        return Err(WorkerConfigError::Usage(format!(
                            "source specified both as --source flag and as positional argument\n{}",
                            usage()
                        )));
                    }
                    self.source = Some(positionals[0].clone());
                } else {
                    if flag_set_path {
                        return Err(WorkerConfigError::Usage(format!(
                            "path specified both as --path flag and as positional argument\n{}",
                            usage()
                        )));
                    }
                    self.path = Some(positionals[0].clone());
                }
                Ok(())
            }
            2 => {
                if flag_set_source {
                    return Err(WorkerConfigError::Usage(format!(
                        "source specified both as --source flag and as positional argument\n{}",
                        usage()
                    )));
                }
                if flag_set_path {
                    return Err(WorkerConfigError::Usage(format!(
                        "path specified both as --path flag and as positional argument\n{}",
                        usage()
                    )));
                }
                self.source = Some(positionals[0].clone());
                self.path = Some(positionals[1].clone());
                Ok(())
            }
            _ => Err(WorkerConfigError::Usage(format!(
                "too many positional arguments\n{}",
                usage()
            ))),
        }
    }

    fn apply_cli_override(&mut self, name: &str, value: &str) -> Result<(), WorkerConfigError> {
        if value.trim().is_empty() {
            return Err(WorkerConfigError::Usage(format!(
                "flag '--{name}' requires a non-empty value\n{}",
                usage()
            )));
        }
        match name {
            "mode" => self.execution_mode = Some(value.to_owned()),
            "backend" => self.backend = Some(value.to_owned()),
            "source" => self.source = Some(value.to_owned()),
            "path" => self.path = Some(value.to_owned()),
            "rules-file" => self.rules_file = Some(value.to_owned()),
            "decode-depth" => self.decode_depth = Some(value.to_owned()),
            "scan-binary" => self.scan_binary = Some(value.to_owned()),
            "skip-archives" => self.skip_archives = Some(value.to_owned()),
            "anchor-mode" => self.anchor_mode = Some(value.to_owned()),
            "max-items" => self.max_items = Some(value.to_owned()),
            "max-bytes" => self.max_bytes = Some(value.to_owned()),
            "commit-queue-capacity" => self.commit_queue_capacity = Some(value.to_owned()),
            "etcd-endpoints" => self.etcd_endpoints_csv = Some(value.to_owned()),
            "etcd-namespace" => self.etcd_namespace = Some(value.to_owned()),
            "done-ledger-postgres-dsn" => self.done_ledger_postgres_dsn = Some(value.to_owned()),
            "findings-postgres-dsn" => self.findings_postgres_dsn = Some(value.to_owned()),
            "tenant-id" => self.tenant = Some(value.to_owned()),
            "run-id" => self.run = Some(value.to_owned()),
            "worker-id" => self.worker = Some(value.to_owned()),
            "policy-hash" => self.policy_hash = Some(value.to_owned()),
            "tenant-secret-key" => self.tenant_secret_key = Some(value.to_owned()),
            _ => {
                return Err(WorkerConfigError::Usage(format!(
                    "unknown flag '--{name}'\n{}",
                    usage()
                )));
            }
        }
        Ok(())
    }

    fn resolve(self) -> Result<ResolvedWorkerConfig, WorkerConfigError> {
        let execution_mode = parse_optional(self.execution_mode.as_deref(), "mode", parse_mode)?
            .unwrap_or(ExecutionMode::Connector);
        let backend = parse_optional(
            self.backend.as_deref(),
            "backend",
            parse_from_str::<BackendSelection>,
        )?;
        let source = parse_optional(
            self.source.as_deref(),
            "source",
            parse_from_str::<WorkerSource>,
        )?
        .unwrap_or(WorkerSource::Fs);
        let path = parse_optional(self.path.as_deref(), "path", parse_path)?
            .unwrap_or_else(|| PathBuf::from("."));
        let rules_file = parse_optional(self.rules_file.as_deref(), "rules_file", parse_path)?;
        let decode_depth =
            parse_optional(self.decode_depth.as_deref(), "decode_depth", parse_usize)?;
        let scan_binary = parse_optional(self.scan_binary.as_deref(), "scan_binary", parse_bool)?
            .unwrap_or(false);
        // skip_archives is only meaningful for filesystem scans. Defer
        // parsing so an invalid value in the environment does not reject
        // git launches where the option is irrelevant.
        let skip_archives = if source == WorkerSource::Fs {
            parse_optional(self.skip_archives.as_deref(), "skip_archives", parse_bool)?
                .unwrap_or(false)
        } else {
            false
        };
        let anchor_mode = parse_optional(
            self.anchor_mode.as_deref(),
            "anchor_mode",
            parse_anchor_mode,
        )?
        .unwrap_or(AnchorMode::Manual);
        let defaults = DistributedRuntimeConfig::default();
        let budgets = ScanBudgets {
            max_items: parse_optional(
                self.max_items.as_deref(),
                "max_items",
                parse_positive_usize,
            )?
            .unwrap_or(defaults.budgets.max_items),
            max_bytes: parse_optional(self.max_bytes.as_deref(), "max_bytes", parse_positive_u64)?
                .unwrap_or(defaults.budgets.max_bytes),
        };

        if budgets.max_items > MAX_ITEMS_CEILING {
            return Err(WorkerConfigError::invalid_value(
                "max_items",
                budgets.max_items.to_string(),
                format!("exceeds maximum of {MAX_ITEMS_CEILING}"),
            ));
        }
        if budgets.max_bytes > MAX_BYTES_CEILING {
            return Err(WorkerConfigError::invalid_value(
                "max_bytes",
                budgets.max_bytes.to_string(),
                format!("exceeds maximum of {MAX_BYTES_CEILING}"),
            ));
        }

        // Helper: build a local config for the given execution mode.
        let make_local = |mode| {
            LocalWorkerConfig::new(
                mode,
                build_local_source_settings(
                    source,
                    path.clone(),
                    rules_file.clone(),
                    decode_depth,
                    scan_binary,
                    skip_archives,
                    anchor_mode,
                ),
                budgets,
            )
            .map(ResolvedWorkerConfig::Local)
        };

        match execution_mode {
            ExecutionMode::Direct => {
                if matches!(backend, Some(BackendSelection::Production)) {
                    return Err(WorkerConfigError::UnsupportedCombination {
                        message: "backend=production requires connector mode; direct mode cannot use real distributed backends".to_owned(),
                    });
                }
                make_local(ExecutionMode::Direct)
            }
            ExecutionMode::Connector => {
                let backend = backend.ok_or(WorkerConfigError::MissingRequiredValue {
                    field: "backend",
                    flag: "--backend",
                    env: ENV_WORKER_BACKEND,
                })?;
                match backend {
                    BackendSelection::Local => make_local(ExecutionMode::Connector),
                    BackendSelection::Production => {
                        if source != WorkerSource::Fs {
                            return Err(WorkerConfigError::UnsupportedCombination {
                                message: "backend=production currently supports only source=fs"
                                    .to_owned(),
                            });
                        }

                        let etcd_endpoints = parse_required(
                            self.etcd_endpoints_csv.as_deref(),
                            parse_nonempty_string,
                            "etcd_endpoints",
                            "--etcd-endpoints",
                            ENV_ETCD_ENDPOINTS,
                        )?;
                        let etcd_namespace = parse_required(
                            self.etcd_namespace.as_deref(),
                            parse_nonempty_string,
                            "etcd_namespace",
                            "--etcd-namespace",
                            ENV_ETCD_NAMESPACE,
                        )?;
                        let done_ledger_postgres_dsn = parse_required(
                            self.done_ledger_postgres_dsn.as_deref(),
                            parse_nonempty_string_redacted,
                            "done_ledger_postgres_dsn",
                            "--done-ledger-postgres-dsn",
                            ENV_DONE_LEDGER_POSTGRES_DSN,
                        )?;
                        let findings_postgres_dsn = parse_required(
                            self.findings_postgres_dsn.as_deref(),
                            parse_nonempty_string_redacted,
                            "findings_postgres_dsn",
                            "--findings-postgres-dsn",
                            ENV_FINDINGS_POSTGRES_DSN,
                        )?;
                        let tenant = parse_required(
                            self.tenant.as_deref(),
                            parse_tenant_id,
                            "tenant_id",
                            "--tenant-id",
                            ENV_TENANT_ID,
                        )?;
                        let run = parse_required(
                            self.run.as_deref(),
                            parse_run_id,
                            "run_id",
                            "--run-id",
                            ENV_RUN_ID,
                        )?;
                        let worker = parse_required(
                            self.worker.as_deref(),
                            parse_worker_id,
                            "worker_id",
                            "--worker-id",
                            ENV_WORKER_ID,
                        )?;
                        let policy_hash = parse_required(
                            self.policy_hash.as_deref(),
                            parse_policy_hash,
                            "policy_hash",
                            "--policy-hash",
                            ENV_POLICY_HASH,
                        )?;
                        let tenant_secret_key = parse_required(
                            self.tenant_secret_key.as_deref(),
                            parse_tenant_secret_key,
                            "tenant_secret_key",
                            "--tenant-secret-key",
                            ENV_TENANT_SECRET_KEY,
                        )?;

                        let etcd = EtcdCoordinatorConfig::from_endpoints_csv(
                            &etcd_endpoints,
                            etcd_namespace,
                        )?;
                        let backends = ProductionBackendConfig::new(
                            etcd,
                            done_ledger_postgres_dsn,
                            findings_postgres_dsn,
                        )?;
                        match path.try_exists() {
                            Ok(false) => {
                                return Err(WorkerConfigError::invalid_value(
                                    "path",
                                    path.display().to_string(),
                                    "path does not exist on this host",
                                ));
                            }
                            Err(io_err) => {
                                return Err(WorkerConfigError::invalid_value(
                                    "path",
                                    path.display().to_string(),
                                    format!("cannot verify path existence: {io_err}"),
                                ));
                            }
                            Ok(true) => {}
                        }
                        let source = FsSourceSettings::new(path)
                            .with_rules_file(rules_file)
                            .with_decode_depth(decode_depth)
                            .with_scan_binary(scan_binary)
                            .with_skip_archives(skip_archives)
                            .with_anchor_mode(anchor_mode);
                        let commit_queue_capacity = parse_optional(
                            self.commit_queue_capacity.as_deref(),
                            "commit_queue_capacity",
                            parse_nonzero_usize,
                        )?
                        .unwrap_or(defaults.commit_queue_capacity);
                        if commit_queue_capacity.get() > MAX_COMMIT_QUEUE_CEILING {
                            return Err(WorkerConfigError::invalid_value(
                                "commit_queue_capacity",
                                commit_queue_capacity.to_string(),
                                format!("exceeds maximum of {MAX_COMMIT_QUEUE_CEILING}"),
                            ));
                        }
                        let runtime =
                            DistributedWorkerRuntimeSettings::new(budgets, commit_queue_capacity);
                        let identity = WorkerIdentityConfig::new(
                            tenant,
                            run,
                            worker,
                            policy_hash,
                            tenant_secret_key,
                        )?;
                        Ok(ResolvedWorkerConfig::Distributed(Box::new(
                            DistributedWorkerConfig::new(backends, identity, source, runtime)?,
                        )))
                    }
                }
            }
        }
    }
}

/// Resolve the current process environment plus CLI args into one typed launch configuration.
pub fn resolve_worker_config_from_env_and_args<I, S>(
    args: I,
) -> Result<ResolvedWorkerConfig, WorkerConfigError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let env = ProcessEnv;
    resolve_worker_config_from(args, &env)
}

/// Resolve one provided environment source plus CLI args into a typed launch configuration.
pub fn resolve_worker_config_from<I, S, E>(
    args: I,
    env: &E,
) -> Result<ResolvedWorkerConfig, WorkerConfigError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    E: EnvProvider + ?Sized,
{
    let mut raw = RawWorkerConfig::from_env(env);
    raw.apply_cli_args(args)?;
    raw.resolve()
}

fn usage() -> &'static str {
    "usage: gossip-worker [--mode=direct|connector] [--backend=local|production] \\
     [--tenant-id=HEX32] [--run-id=U64] [--worker-id=U64] [--policy-hash=HEX32] \\
     [--tenant-secret-key=HEX32] [--etcd-endpoints=CSV] [--etcd-namespace=PREFIX] \\
     [--done-ledger-postgres-dsn=DSN] [--findings-postgres-dsn=DSN] \\
     [--rules-file=PATH] [--decode-depth=N] [--scan-binary=true|false] \\
     [--skip-archives=true|false] [--anchor-mode=manual|derived] \\
     [--max-items=N] [--max-bytes=N] [--commit-queue-capacity=N] \\
     [fs|git] [path]\n\
     defaults: --mode=connector fs .\n\
     note: connector mode requires explicit backend selection; backend=production currently supports only fs"
}

fn validate_budgets(budgets: &ScanBudgets) -> Result<(), WorkerConfigError> {
    if budgets.max_items == 0 {
        return Err(WorkerConfigError::invalid_value(
            "max_items",
            "0",
            "must be > 0",
        ));
    }
    if budgets.max_items > MAX_ITEMS_CEILING {
        return Err(WorkerConfigError::invalid_value(
            "max_items",
            budgets.max_items.to_string(),
            format!("exceeds maximum of {MAX_ITEMS_CEILING}"),
        ));
    }
    if budgets.max_bytes == 0 {
        return Err(WorkerConfigError::invalid_value(
            "max_bytes",
            "0",
            "must be > 0",
        ));
    }
    if budgets.max_bytes > MAX_BYTES_CEILING {
        return Err(WorkerConfigError::invalid_value(
            "max_bytes",
            budgets.max_bytes.to_string(),
            format!("exceeds maximum of {MAX_BYTES_CEILING}"),
        ));
    }
    Ok(())
}

fn build_local_source_settings(
    source: WorkerSource,
    path: PathBuf,
    rules_file: Option<PathBuf>,
    decode_depth: Option<usize>,
    scan_binary: bool,
    skip_archives: bool,
    anchor_mode: AnchorMode,
) -> WorkerSourceSettings {
    match source {
        WorkerSource::Fs => WorkerSourceSettings::Fs(
            FsSourceSettings::new(path)
                .with_rules_file(rules_file)
                .with_decode_depth(decode_depth)
                .with_scan_binary(scan_binary)
                .with_skip_archives(skip_archives)
                .with_anchor_mode(anchor_mode),
        ),
        WorkerSource::Git => WorkerSourceSettings::Git(
            GitSourceSettings::new(path)
                .with_rules_file(rules_file)
                .with_decode_depth(decode_depth)
                .with_scan_binary(scan_binary)
                .with_anchor_mode(anchor_mode),
        ),
    }
}

fn parse_required<T>(
    value: Option<&str>,
    parser: fn(&'static str, &str) -> Result<T, WorkerConfigError>,
    field: &'static str,
    flag: &'static str,
    env: &'static str,
) -> Result<T, WorkerConfigError> {
    match value {
        Some(raw) => parser(field, raw),
        None => Err(WorkerConfigError::MissingRequiredValue { field, flag, env }),
    }
}

fn parse_optional<T>(
    value: Option<&str>,
    field: &'static str,
    parser: fn(&'static str, &str) -> Result<T, WorkerConfigError>,
) -> Result<Option<T>, WorkerConfigError> {
    value.map(|raw| parser(field, raw)).transpose()
}

fn parse_mode(field: &'static str, raw: &str) -> Result<ExecutionMode, WorkerConfigError> {
    raw.parse::<ExecutionMode>()
        .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))
}

/// Parse a `FromStr` type whose `Err` is `WorkerConfigError`, remapping the
/// field name so the error identifies the correct config key.
fn parse_from_str<T: std::str::FromStr<Err = WorkerConfigError>>(
    field: &'static str,
    raw: &str,
) -> Result<T, WorkerConfigError> {
    raw.parse::<T>().map_err(|error| match error {
        WorkerConfigError::InvalidValue { reason, .. } => {
            WorkerConfigError::invalid_value(field, raw, reason)
        }
        other => other,
    })
}

fn parse_path(field: &'static str, raw: &str) -> Result<PathBuf, WorkerConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "must not be empty",
        ));
    }
    Ok(PathBuf::from(trimmed))
}

fn parse_nonempty_string(field: &'static str, raw: &str) -> Result<String, WorkerConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "must not be empty",
        ));
    }
    Ok(trimmed.to_owned())
}

/// Same as [`parse_nonempty_string`] but uses redacted error values to avoid
/// leaking credentials (e.g. DSN passwords) in error messages.
fn parse_nonempty_string_redacted(
    field: &'static str,
    raw: &str,
) -> Result<String, WorkerConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WorkerConfigError::invalid_redacted_value(
            field,
            "must not be empty",
        ));
    }
    Ok(trimmed.to_owned())
}

fn parse_bool(field: &'static str, raw: &str) -> Result<bool, WorkerConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "expected a boolean (true/false, yes/no, on/off, 1/0)",
        )),
    }
}

fn parse_anchor_mode(field: &'static str, raw: &str) -> Result<AnchorMode, WorkerConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "manual" => Ok(AnchorMode::Manual),
        "derived" => Ok(AnchorMode::Derived),
        _ => Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "expected 'manual' or 'derived'",
        )),
    }
}

fn parse_usize(field: &'static str, raw: &str) -> Result<usize, WorkerConfigError> {
    raw.trim()
        .parse::<usize>()
        .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))
}

fn parse_positive_usize(field: &'static str, raw: &str) -> Result<usize, WorkerConfigError> {
    let value = parse_usize(field, raw)?;
    if value == 0 {
        return Err(WorkerConfigError::invalid_value(field, raw, "must be > 0"));
    }
    Ok(value)
}

fn parse_positive_u64(field: &'static str, raw: &str) -> Result<u64, WorkerConfigError> {
    let value = raw
        .trim()
        .parse::<u64>()
        .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))?;
    if value == 0 {
        return Err(WorkerConfigError::invalid_value(field, raw, "must be > 0"));
    }
    Ok(value)
}

fn parse_nonzero_usize(field: &'static str, raw: &str) -> Result<NonZeroUsize, WorkerConfigError> {
    let value = parse_positive_usize(field, raw)?;
    Ok(NonZeroUsize::new(value).expect("parse_positive_usize guarantees > 0"))
}

fn parse_tenant_id(field: &'static str, raw: &str) -> Result<TenantId, WorkerConfigError> {
    Ok(TenantId::from_bytes(parse_hex_32(field, raw)?))
}

fn parse_policy_hash(field: &'static str, raw: &str) -> Result<PolicyHash, WorkerConfigError> {
    Ok(PolicyHash::from_bytes(parse_hex_32(field, raw)?))
}

fn parse_tenant_secret_key(
    field: &'static str,
    raw: &str,
) -> Result<TenantSecretKey, WorkerConfigError> {
    Ok(TenantSecretKey::from_bytes(parse_hex_32_redacted(
        field, raw,
    )?))
}

fn parse_run_id(field: &'static str, raw: &str) -> Result<RunId, WorkerConfigError> {
    let value = raw
        .trim()
        .parse::<u64>()
        .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))?;
    if value == 0 {
        return Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "must be > 0 (0 is the unassigned sentinel)",
        ));
    }
    Ok(RunId::from_raw(value))
}

fn parse_worker_id(field: &'static str, raw: &str) -> Result<WorkerId, WorkerConfigError> {
    let value = raw
        .trim()
        .parse::<u64>()
        .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))?;
    if value == 0 {
        return Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "must be > 0 (0 is the unassigned sentinel)",
        ));
    }
    Ok(WorkerId::from_raw(value))
}

fn parse_hex_32(field: &'static str, raw: &str) -> Result<[u8; 32], WorkerConfigError> {
    parse_hex_32_inner(field, raw, false)
}

fn parse_hex_32_redacted(field: &'static str, raw: &str) -> Result<[u8; 32], WorkerConfigError> {
    parse_hex_32_inner(field, raw, true)
}

fn parse_hex_32_inner(
    field: &'static str,
    raw: &str,
    redact: bool,
) -> Result<[u8; 32], WorkerConfigError> {
    let make_err = |reason: &str| {
        if redact {
            WorkerConfigError::invalid_redacted_value(field, reason)
        } else {
            WorkerConfigError::invalid_value(field, raw, reason)
        }
    };

    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 64 {
        return Err(make_err("expected exactly 64 hex characters"));
    }

    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for index in 0..32 {
        let hi = decode_hex_nibble(bytes[index * 2])
            .ok_or_else(|| make_err("contains a non-hex character"))?;
        let lo = decode_hex_nibble(bytes[index * 2 + 1])
            .ok_or_else(|| make_err("contains a non-hex character"))?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Recorder that discards coordination events while still satisfying the runtime interface.
#[derive(Default)]
pub(crate) struct NoopCoordinationEventRecorder;

impl CoordinationEventRecorder for NoopCoordinationEventRecorder {
    fn record_core_event(&self, _shard_id: &str, _event: OwnedCoreEvent) -> AnyhowResult<()> {
        Ok(())
    }

    fn record_git_event(&self, _shard_id: &str, _event: StoredGitEvent) -> AnyhowResult<()> {
        Ok(())
    }

    fn record_commit_progress(
        &self,
        _shard_id: &str,
        _event: CommitProgressRecord,
    ) -> AnyhowResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    #[derive(Default)]
    struct TestEnv {
        vars: BTreeMap<String, String>,
    }

    impl TestEnv {
        fn with(mut self, key: &'static str, value: &str) -> Self {
            self.vars.insert(key.to_owned(), value.to_owned());
            self
        }
    }

    impl EnvProvider for TestEnv {
        fn get(&self, key: &'static str) -> Option<String> {
            self.vars.get(key).cloned()
        }
    }

    fn production_env() -> TestEnv {
        TestEnv::default()
            .with(ENV_WORKER_BACKEND, "production")
            .with(
                ENV_ETCD_ENDPOINTS,
                "http://127.0.0.1:2379,http://127.0.0.1:22379",
            )
            .with(ENV_ETCD_NAMESPACE, "/gossip/v1")
            .with(
                ENV_DONE_LEDGER_POSTGRES_DSN,
                "postgresql://scanner:super-secret@db.example.internal:5432/done",
            )
            .with(
                ENV_FINDINGS_POSTGRES_DSN,
                "host=db.example.internal user=scanner password=ultra-secret dbname=findings",
            )
            .with(
                ENV_TENANT_ID,
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .with(ENV_RUN_ID, "42")
            .with(ENV_WORKER_ID, "7")
            .with(
                ENV_POLICY_HASH,
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .with(
                ENV_TENANT_SECRET_KEY,
                "3333333333333333333333333333333333333333333333333333333333333333",
            )
            .with(ENV_WORKER_PATH, "/tmp")
            .with(ENV_WORKER_SCAN_BINARY, "true")
            .with(ENV_FS_SKIP_ARCHIVES, "false")
            .with(ENV_WORKER_ANCHOR_MODE, "derived")
            .with(ENV_MAX_ITEMS, "1024")
            .with(ENV_MAX_BYTES, "2097152")
            .with(ENV_COMMIT_QUEUE_CAPACITY, "128")
    }

    #[test]
    fn production_config_resolves_from_env_only() {
        let env = production_env();
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("production env should resolve");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.backend(), BackendSelection::Production);
                assert_eq!(cfg.tenant(), TenantId::from_bytes([0x11; 32]));
                assert_eq!(cfg.run(), RunId::from_raw(42));
                assert_eq!(cfg.worker(), WorkerId::from_raw(7));
                assert_eq!(cfg.policy_hash(), PolicyHash::from_bytes([0x22; 32]));
                assert_eq!(
                    cfg.tenant_secret_key(),
                    TenantSecretKey::from_bytes([0x33; 32]),
                );
                assert_eq!(cfg.runtime().budgets().max_items, 1024);
                assert_eq!(cfg.runtime().budgets().max_bytes, 2_097_152);
                assert_eq!(cfg.runtime().commit_queue_capacity().get(), 128);
                assert_eq!(cfg.source().path(), Path::new("/tmp"));
                assert!(cfg.source().scan_binary());
                assert_eq!(cfg.source().anchor_mode(), AnchorMode::Derived);
                assert_eq!(
                    cfg.production_backends().etcd().namespace_prefix(),
                    "/gossip/v1"
                );
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn cli_overrides_env_for_run_id_and_path() {
        let env = production_env();
        let resolved = resolve_worker_config_from(["--run-id=99", "fs", "/tmp"], &env)
            .expect("CLI overrides should resolve");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.run(), RunId::from_raw(99));
                assert_eq!(cfg.source().path(), Path::new("/tmp"));
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn cli_override_replaces_invalid_env_value_for_same_field() {
        let env = production_env().with(ENV_RUN_ID, "not-a-number");
        let resolved =
            resolve_worker_config_from(["--run-id=99"], &env).expect("CLI override should win");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.run(), RunId::from_raw(99));
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn invalid_env_for_non_overridden_field_still_fails() {
        let env = production_env().with(ENV_MAX_ITEMS, "not-a-number");
        let err = resolve_worker_config_from(["--run-id=99"], &env)
            .expect_err("invalid env for a non-overridden field must still produce an error");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_items",
                ..
            }
        ));
    }

    #[test]
    fn connector_mode_requires_explicit_backend_selection() {
        let err = resolve_worker_config_from(["fs", "/tmp/project"], &TestEnv::default())
            .expect_err("connector mode without backend must fail closed");

        assert!(matches!(
            err,
            WorkerConfigError::MissingRequiredValue {
                field: "backend",
                flag: "--backend",
                env: ENV_WORKER_BACKEND,
            }
        ));
    }

    #[test]
    fn direct_mode_defaults_to_local_without_backend() {
        let resolved = resolve_worker_config_from(
            ["--mode=direct", "fs", "/tmp/project"],
            &TestEnv::default(),
        )
        .expect("direct mode should resolve without backend selection");

        match resolved {
            ResolvedWorkerConfig::Local(cfg) => {
                assert_eq!(cfg.execution_mode(), ExecutionMode::Direct);
                match cfg.source() {
                    WorkerSourceSettings::Fs(settings) => {
                        assert_eq!(settings.path(), Path::new("/tmp/project"));
                    }
                    other => panic!("expected fs local settings, got {other:?}"),
                }
            }
            other => panic!("expected local config, got {other:?}"),
        }
    }

    #[test]
    fn production_requires_explicit_tenant_id() {
        let env = {
            let mut vars = production_env().vars;
            vars.remove(ENV_TENANT_ID);
            TestEnv { vars }
        };

        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("missing tenant id must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::MissingRequiredValue {
                field: "tenant_id",
                flag: "--tenant-id",
                env: ENV_TENANT_ID,
            }
        ));
    }

    #[test]
    fn production_rejects_git_source() {
        let env = production_env().with(ENV_WORKER_SOURCE, "git");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("production backend must reject git");

        assert!(matches!(
            err,
            WorkerConfigError::UnsupportedCombination { ref message }
                if message.contains("source=fs")
        ));
    }

    #[test]
    fn production_rejects_all_zero_tenant_secret_key() {
        let env = production_env().with(
            ENV_TENANT_SECRET_KEY,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("all-zero secret key must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "tenant_secret_key",
                ref value,
                ..
            } if value == "[redacted]"
        ));
        let message = err.to_string();
        assert!(message.contains("[redacted]"));
        assert!(
            !message.contains("0000000000000000000000000000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn invalid_backend_token_is_rejected() {
        let err = resolve_worker_config_from(
            ["--backend=banana", "fs", "/tmp/project"],
            &TestEnv::default(),
        )
        .expect_err("unknown backend token must fail");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "backend",
                ref value,
                ref reason,
            } if value == "banana" && reason.contains("expected 'local' or 'production'")
        ));
    }

    #[test]
    fn production_config_debug_redacts_dsns_and_tenant_secret_key() {
        let env = production_env();
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("production env should resolve");

        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("ultra-secret"));
        assert!(
            !debug.contains("3333333333333333333333333333333333333333333333333333333333333333")
        );
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn distributed_worker_identity_builds_valid_runtime_identity() {
        let env = production_env();
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("production env should resolve");

        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        let identity = cfg.worker_identity_noop();
        assert_eq!(identity.tenant, cfg.tenant());
        assert_eq!(identity.run, cfg.run());
        assert_eq!(identity.worker, cfg.worker());
        assert_eq!(identity.policy_hash, cfg.policy_hash());
        assert_eq!(identity.tenant_secret_key, cfg.tenant_secret_key());
        assert_eq!(identity.scan_template.path, PathBuf::from("/tmp"));
        assert_eq!(
            identity.scan_template.execution_mode,
            ExecutionMode::Connector
        );
        assert_eq!(identity.scan_template.budgets, cfg.runtime().budgets());
    }

    #[test]
    fn parse_hex_32_accepts_plain_hex() {
        let parsed = parse_hex_32(
            "tenant_id",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("valid hex should parse");

        assert_eq!(parsed, [0xaa; 32]);
    }

    #[test]
    fn parse_hex_32_accepts_0x_prefix() {
        let parsed = parse_hex_32(
            "tenant_id",
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("0x-prefixed valid hex should parse");

        assert_eq!(parsed, [0xbb; 32]);
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() {
        let err = parse_hex_32("tenant_id", "abcd").expect_err("short hex should be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "tenant_id",
                ref reason,
                ..
            } if reason.contains("exactly 64 hex characters")
        ));
    }

    #[test]
    fn parse_hex_32_rejects_non_hex_characters() {
        let err = parse_hex_32(
            "tenant_id",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        )
        .expect_err("non-hex data should be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "tenant_id",
                ref reason,
                ..
            } if reason.contains("non-hex")
        ));
    }

    #[test]
    fn raw_worker_config_debug_redacts_sensitive_fields() {
        let raw = RawWorkerConfig {
            done_ledger_postgres_dsn: Some(
                "postgresql://scanner:super-secret@db:5432/done".to_owned(),
            ),
            findings_postgres_dsn: Some(
                "host=db user=scanner password=ultra-secret dbname=findings".to_owned(),
            ),
            tenant_secret_key: Some(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_owned(),
            ),
            ..RawWorkerConfig::default()
        };

        let debug = format!("{raw:?}");
        assert!(
            !debug.contains("super-secret"),
            "Debug output must not leak the done-ledger DSN password"
        );
        assert!(
            !debug.contains("ultra-secret"),
            "Debug output must not leak the findings DSN password"
        );
        assert!(
            !debug.contains("abcdef1234567890"),
            "Debug output must not leak the tenant secret key"
        );
        assert!(
            debug.contains("[redacted]"),
            "Debug output should indicate that sensitive fields were redacted"
        );
    }

    #[test]
    fn parse_hex_32_redacted_hides_secret_input() {
        let err = parse_hex_32_redacted("tenant_secret_key", "abcd")
            .expect_err("short secret hex should be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "tenant_secret_key",
                ref value,
                ..
            } if value == "[redacted]"
        ));
    }

    #[test]
    fn direct_mode_rejects_production_backend() {
        let err = resolve_worker_config_from(
            [
                "--mode=direct",
                "--backend=production",
                "fs",
                "/tmp/project",
            ],
            &TestEnv::default(),
        )
        .expect_err("direct mode must reject production backend");

        assert!(matches!(
            err,
            WorkerConfigError::UnsupportedCombination { ref message }
                if message.contains("direct mode")
        ));
    }

    #[test]
    fn production_rejects_zero_max_items() {
        let env = production_env().with(ENV_MAX_ITEMS, "0");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("max_items=0 must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_items",
                ..
            }
        ));
    }

    #[test]
    fn production_rejects_zero_max_bytes() {
        let env = production_env().with(ENV_MAX_BYTES, "0");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("max_bytes=0 must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_bytes",
                ..
            }
        ));
    }

    #[test]
    fn parse_bool_accepts_all_truthy_tokens() {
        for token in ["true", "1", "yes", "on", "TRUE", " True ", " ON "] {
            assert!(
                parse_bool("test_field", token).unwrap(),
                "expected true for {token:?}"
            );
        }
    }

    #[test]
    fn parse_bool_accepts_all_falsy_tokens() {
        for token in ["false", "0", "no", "off", "FALSE", " No ", " OFF "] {
            assert!(
                !parse_bool("test_field", token).unwrap(),
                "expected false for {token:?}"
            );
        }
    }

    #[test]
    fn parse_bool_rejects_invalid_tokens() {
        for token in ["2", "maybe", ""] {
            parse_bool("test_field", token).expect_err(&format!("should reject {token:?}"));
        }
    }

    #[test]
    fn parse_anchor_mode_accepts_both_variants() {
        assert_eq!(
            parse_anchor_mode("anchor", "manual").unwrap(),
            AnchorMode::Manual
        );
        assert_eq!(
            parse_anchor_mode("anchor", "DERIVED").unwrap(),
            AnchorMode::Derived
        );
    }

    #[test]
    fn parse_anchor_mode_rejects_unknown() {
        parse_anchor_mode("anchor", "auto").expect_err("unknown anchor mode must fail");
    }

    #[test]
    fn parse_source_accepts_both_variants() {
        assert_eq!(
            parse_from_str::<WorkerSource>("source", "fs").unwrap(),
            WorkerSource::Fs
        );
        assert_eq!(
            parse_from_str::<WorkerSource>("source", "GIT").unwrap(),
            WorkerSource::Git
        );
    }

    #[test]
    fn parse_source_rejects_unknown() {
        parse_from_str::<WorkerSource>("source", "svn").expect_err("unknown source must fail");
    }

    #[test]
    fn flag_without_equals_produces_usage_error() {
        let err = resolve_worker_config_from(
            ["--backend", "production", "fs", "/tmp"],
            &TestEnv::default(),
        )
        .expect_err("space-separated flag must produce usage error");

        assert!(matches!(
            err,
            WorkerConfigError::Usage(ref msg) if msg.contains("invalid flag")
        ));
    }

    #[test]
    fn empty_flag_value_produces_usage_error() {
        let err = resolve_worker_config_from(
            ["--scan-binary=", "--backend=local", "fs", "/tmp"],
            &TestEnv::default(),
        )
        .expect_err("empty flag value must produce usage error");

        assert!(matches!(
            err,
            WorkerConfigError::Usage(ref msg)
                if msg.contains("non-empty value")
        ));
    }

    #[test]
    fn cli_flag_preserves_value_containing_equals() {
        let env = production_env();
        let resolved = resolve_worker_config_from(
            ["--done-ledger-postgres-dsn=host=db.example.com password=s3cret dbname=done"],
            &env,
        )
        .expect("DSN with embedded equals should resolve");

        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        assert_eq!(
            cfg.production_backends().done_ledger_postgres_dsn(),
            "host=db.example.com password=s3cret dbname=done"
        );
    }

    #[test]
    fn backend_selection_display_roundtrips() {
        for expected in [BackendSelection::Local, BackendSelection::Production] {
            let text = expected.to_string();
            let parsed: BackendSelection = text.parse().unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn distributed_runtime_defaults_mirror_upstream() {
        let defaults = DistributedWorkerRuntimeSettings::default();
        let upstream = DistributedRuntimeConfig::default();
        assert_eq!(defaults.budgets(), upstream.budgets);
        assert_eq!(
            defaults.commit_queue_capacity(),
            upstream.commit_queue_capacity
        );
    }

    #[test]
    fn positional_path_conflicts_with_flag_path() {
        let err = resolve_worker_config_from(
            ["--path=/srv/prod", "/tmp/test"],
            &TestEnv::default().with(ENV_WORKER_BACKEND, "local"),
        )
        .expect_err("positional path must conflict with --path flag");

        assert!(matches!(
            err,
            WorkerConfigError::Usage(ref msg)
                if msg.contains("path specified both")
        ));
    }

    #[test]
    fn positional_source_conflicts_with_flag_source() {
        let err = resolve_worker_config_from(
            ["--source=git", "fs", "/tmp/test"],
            &TestEnv::default().with(ENV_WORKER_BACKEND, "local"),
        )
        .expect_err("positional source must conflict with --source flag");

        assert!(matches!(
            err,
            WorkerConfigError::Usage(ref msg)
                if msg.contains("source specified both")
        ));
    }

    #[test]
    fn local_config_rejects_zero_budgets() {
        let err = LocalWorkerConfig::new(
            ExecutionMode::Direct,
            WorkerSourceSettings::Fs(FsSourceSettings::new("/tmp")),
            ScanBudgets {
                max_items: 0,
                max_bytes: 1024,
            },
        )
        .expect_err("zero max_items must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_items",
                ..
            }
        ));
    }

    #[test]
    fn max_items_exceeding_ceiling_is_rejected() {
        let env = production_env().with(ENV_MAX_ITEMS, "20000000");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("max_items above ceiling must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_items",
                ref reason,
                ..
            } if reason.contains("exceeds maximum")
        ));
    }

    #[test]
    fn max_bytes_exceeding_ceiling_is_rejected() {
        let above_ceiling = (MAX_BYTES_CEILING + 1).to_string();
        let env = production_env().with(ENV_MAX_BYTES, &above_ceiling);
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("max_bytes above ceiling must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_bytes",
                ref reason,
                ..
            } if reason.contains("exceeds maximum")
        ));
    }

    #[test]
    fn commit_queue_capacity_exceeding_ceiling_is_rejected() {
        let above_ceiling = (MAX_COMMIT_QUEUE_CEILING + 1).to_string();
        let env = production_env().with(ENV_COMMIT_QUEUE_CAPACITY, &above_ceiling);
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("commit_queue_capacity above ceiling must be rejected");

        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "commit_queue_capacity",
                ref reason,
                ..
            } if reason.contains("exceeds maximum")
        ));
    }

    #[test]
    fn max_items_at_ceiling_is_accepted() {
        let at_ceiling = MAX_ITEMS_CEILING.to_string();
        let env = production_env().with(ENV_MAX_ITEMS, &at_ceiling);
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("max_items at exactly the ceiling must be accepted");

        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        assert_eq!(cfg.runtime().budgets().max_items, MAX_ITEMS_CEILING);
    }

    #[test]
    fn max_bytes_at_ceiling_is_accepted() {
        let at_ceiling = MAX_BYTES_CEILING.to_string();
        let env = production_env().with(ENV_MAX_BYTES, &at_ceiling);
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("max_bytes at exactly the ceiling must be accepted");

        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        assert_eq!(cfg.runtime().budgets().max_bytes, MAX_BYTES_CEILING);
    }

    #[test]
    fn commit_queue_capacity_at_ceiling_is_accepted() {
        let at_ceiling = MAX_COMMIT_QUEUE_CEILING.to_string();
        let env = production_env().with(ENV_COMMIT_QUEUE_CAPACITY, &at_ceiling);
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("commit_queue_capacity at exactly the ceiling must be accepted");

        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        assert_eq!(
            cfg.runtime().commit_queue_capacity().get(),
            MAX_COMMIT_QUEUE_CEILING
        );
    }

    #[test]
    fn dsn_error_messages_are_redacted() {
        let env = production_env().with(ENV_DONE_LEDGER_POSTGRES_DSN, "   ");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("whitespace-only DSN must be rejected");

        let message = err.to_string();
        assert!(
            message.contains("[redacted]"),
            "error message must use [redacted] instead of the raw DSN value"
        );
        assert!(
            !message.contains("postgresql://"),
            "error message must not contain actual DSN content"
        );
    }

    #[test]
    fn zero_run_id_is_rejected() {
        let env = production_env().with(ENV_RUN_ID, "0");
        let result = resolve_worker_config_from(Vec::<String>::new(), &env);
        assert!(
            result.is_err(),
            "run_id=0 is the ZERO sentinel and must be rejected, but got: {result:?}"
        );
    }

    #[test]
    fn zero_worker_id_is_rejected() {
        let env = production_env().with(ENV_WORKER_ID, "0");
        let result = resolve_worker_config_from(Vec::<String>::new(), &env);
        assert!(
            result.is_err(),
            "worker_id=0 is the ZERO sentinel and must be rejected, but got: {result:?}"
        );
    }

    #[test]
    fn production_rejects_nonexistent_path() {
        let bogus = "/this/path/does/not/exist/gossip_f7_test";
        let env = production_env().with(ENV_WORKER_PATH, bogus);
        let result = resolve_worker_config_from(Vec::<String>::new(), &env);
        assert!(
            result.is_err(),
            "non-existent path must be rejected in production mode, but got: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                WorkerConfigError::InvalidValue {
                    field: "path",
                    ref reason,
                    ..
                } if reason.contains("does not exist")
            ),
            "expected InvalidValue for non-existent path, got: {err}"
        );
    }

    #[test]
    fn unknown_cli_flag_returns_usage_error() {
        let env = TestEnv::default();
        let result = resolve_worker_config_from(["--bogus=42"], &env);
        assert!(
            matches!(result, Err(WorkerConfigError::Usage(_))),
            "unknown flag must produce a Usage error, got: {result:?}"
        );
    }

    #[test]
    fn too_many_positional_args_returns_usage_error() {
        let env = TestEnv::default();
        let result = resolve_worker_config_from(["fs", "/path", "extra"], &env);
        assert!(
            matches!(result, Err(WorkerConfigError::Usage(_))),
            "three positional args must produce a Usage error, got: {result:?}"
        );
    }

    #[test]
    fn worker_identity_config_rejects_zero_run_id() {
        let result = WorkerIdentityConfig::new(
            TenantId::from_bytes([0x11; 32]),
            RunId::from_raw(0),
            WorkerId::from_raw(1),
            PolicyHash::from_bytes([0x22; 32]),
            TenantSecretKey::from_bytes([0x33; 32]),
        );
        assert!(
            result.is_err(),
            "WorkerIdentityConfig::new must reject RunId(0), got: {result:?}"
        );
    }

    #[test]
    fn worker_identity_config_rejects_zero_worker_id() {
        let result = WorkerIdentityConfig::new(
            TenantId::from_bytes([0x11; 32]),
            RunId::from_raw(1),
            WorkerId::from_raw(0),
            PolicyHash::from_bytes([0x22; 32]),
            TenantSecretKey::from_bytes([0x33; 32]),
        );
        assert!(
            result.is_err(),
            "WorkerIdentityConfig::new must reject WorkerId(0), got: {result:?}"
        );
    }

    #[test]
    fn distributed_config_rejects_commit_queue_capacity_above_ceiling() {
        let backends = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "host=127.0.0.1 dbname=done",
            "host=127.0.0.1 dbname=findings",
        )
        .expect("backend config should be valid");
        let identity = WorkerIdentityConfig::new(
            TenantId::from_bytes([0x11; 32]),
            RunId::from_raw(1),
            WorkerId::from_raw(1),
            PolicyHash::from_bytes([0x22; 32]),
            TenantSecretKey::from_bytes([0x33; 32]),
        )
        .expect("identity should be valid");
        let over_ceiling = NonZeroUsize::new(MAX_COMMIT_QUEUE_CEILING + 1).unwrap();
        let runtime = DistributedWorkerRuntimeSettings::new(ScanBudgets::default(), over_ceiling);
        let result = DistributedWorkerConfig::new(
            backends,
            identity,
            FsSourceSettings::new("/tmp"),
            runtime,
        );
        assert!(
            result.is_err(),
            "commit_queue_capacity above ceiling must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn single_positional_git_selects_source_not_path() {
        let env = TestEnv::default()
            .with(ENV_WORKER_MODE, "direct")
            .with(ENV_WORKER_PATH, "/some/path");
        let result = resolve_worker_config_from(["git"], &env);
        match result {
            Ok(ResolvedWorkerConfig::Local(cfg)) => {
                assert!(
                    matches!(cfg.source(), WorkerSourceSettings::Git(_)),
                    "single positional 'git' must select git source, got: {:?}",
                    cfg.source()
                );
            }
            other => panic!("expected local git config, got: {other:?}"),
        }
    }

    #[test]
    fn invalid_skip_archives_does_not_reject_git_launches() {
        let env = TestEnv::default()
            .with(ENV_WORKER_MODE, "direct")
            .with(ENV_FS_SKIP_ARCHIVES, "maybe");
        let result = resolve_worker_config_from(["git", "/some/path"], &env);
        assert!(
            result.is_ok(),
            "invalid skip_archives must not reject git launches: {result:?}"
        );
    }
}
