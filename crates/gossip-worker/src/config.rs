//! Typed configuration surface for worker launches.
//!
//! This module resolves environment variables plus CLI overrides into one of
//! two explicit launch paths:
//!
//! - local scans (`ExecutionMode::Direct`)
//! - real distributed scans (`ExecutionMode::Connector`)
//!
//! Connector mode defaults to the real production backends and never silently
//! falls back to a local or fake backend. Distributed launches support both
//! filesystem shards and Git repo-frontier shards.

use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use gossip_contracts::identity::{PolicyHash, RunId, TenantId, TenantSecretKey, WorkerId};
use gossip_coordination_etcd::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
use gossip_scanner_runtime::coordination_sink::CoordinationEventRecorder;
use gossip_scanner_runtime::distributed::{
    DistributedRuntimeConfig, GitWorkerIdentity, WorkerIdentity,
};
use gossip_scanner_runtime::{AnchorMode, ExecutionMode, FsScanConfig, GitScanConfig, ScanBudgets};

use crate::production::{ProductionStartupSettings, StartupSchemaMode};
use crate::recorder::ProductionCoordinationEventRecorder;

/// Environment variable selecting the worker runtime family.
pub const ENV_WORKER_MODE: &str = "GOSSIP_WORKER_MODE";
/// Environment variable selecting the worker backend.
pub const ENV_WORKER_BACKEND: &str = "GOSSIP_WORKER_BACKEND";
/// Environment variable selecting the source family.
pub const ENV_WORKER_SOURCE: &str = "GOSSIP_WORKER_SOURCE";
/// Environment variable supplying the filesystem path or git repository path.
pub const ENV_WORKER_PATH: &str = "GOSSIP_WORKER_PATH";
/// Environment variable supplying the Git mirror-root directory for connector mode.
pub const ENV_MIRROR_ROOT: &str = "GOSSIP_MIRROR_ROOT";
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
/// Environment variable selecting startup schema validation policy.
pub const ENV_STARTUP_SCHEMA_MODE: &str = "GOSSIP_STARTUP_SCHEMA_MODE";
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

/// Backend selection parsed from the worker config surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendSelection {
    /// Existing local/non-production worker path used by direct scans.
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
    ///
    /// # Panics
    ///
    /// Debug builds panic if `path` is empty.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        debug_assert!(!path.as_os_str().is_empty(), "scan path must not be empty");
        Self {
            path,
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
    ///
    /// # Panics
    ///
    /// Debug builds panic if `repo` is empty.
    #[must_use]
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        let repo: PathBuf = repo.into();
        debug_assert!(
            !repo.as_os_str().is_empty(),
            "repository path must not be empty"
        );
        Self {
            repo,
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

/// Git source configuration for distributed worker mode.
///
/// The wrapped [`GitSourceSettings`] carries the scan template used to derive
/// shard-local Git scan configs. `mirror_root` names the worker-local
/// directory where connector-mode Git launches keep deterministic mirrors
/// between lease cycles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitDistributedSourceSettings {
    git: GitSourceSettings,
    mirror_root: PathBuf,
}

impl GitDistributedSourceSettings {
    /// Bundle distributed Git scan settings with the required mirror root.
    #[must_use]
    pub fn new(git: GitSourceSettings, mirror_root: impl Into<PathBuf>) -> Self {
        Self {
            git,
            mirror_root: mirror_root.into(),
        }
    }

    /// Borrow the underlying Git scan settings.
    #[inline]
    #[must_use]
    pub fn git(&self) -> &GitSourceSettings {
        &self.git
    }

    /// Borrow the worker-local mirror root.
    #[inline]
    #[must_use]
    pub fn mirror_root(&self) -> &Path {
        &self.mirror_root
    }

    /// Convert the wrapped Git settings into a runtime scan template.
    #[inline]
    #[must_use]
    pub fn to_scan_config(
        &self,
        execution_mode: ExecutionMode,
        budgets: ScanBudgets,
    ) -> GitScanConfig {
        self.git.to_scan_config(execution_mode, budgets)
    }
}

/// Typed source settings for distributed worker launches.
///
/// Filesystem and Git connector paths share the same real backend bundle but
/// differ in their runtime requirements. Git launches require an explicit
/// mirror-root so the worker can initialize local mirror management before it
/// starts claiming repo-frontier shards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistributedSourceSettings {
    /// Filesystem connector mode.
    Fs(FsSourceSettings),
    /// Git repo-frontier connector mode.
    Git(GitDistributedSourceSettings),
}

/// Typed local direct worker launch configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWorkerConfig {
    source: WorkerSourceSettings,
    budgets: ScanBudgets,
}

impl LocalWorkerConfig {
    /// Construct one local direct worker launch configuration.
    ///
    /// Local configs never carry connector semantics. The execution mode is
    /// structurally fixed to [`ExecutionMode::Direct`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkerConfigError`] when `max_items` or `max_bytes` is zero,
    /// or when either value exceeds the configured validation ceiling
    /// (`max_items` > 10,000,000 or `max_bytes` > 64 GiB).
    pub fn new(
        source: WorkerSourceSettings,
        budgets: ScanBudgets,
    ) -> Result<Self, WorkerConfigError> {
        validate_budgets(&budgets)?;
        Ok(Self { source, budgets })
    }

    #[inline]
    #[must_use]
    pub fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Direct
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProductionBackendConfigError {
    /// The done-ledger PostgreSQL DSN was empty after trimming whitespace.
    #[error("done-ledger PostgreSQL DSN must not be empty")]
    EmptyDoneLedgerPostgresDsn,
    /// The findings PostgreSQL DSN was empty after trimming whitespace.
    #[error("findings PostgreSQL DSN must not be empty")]
    EmptyFindingsPostgresDsn,
}

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
    ///
    /// Prefer the resolution pipeline ([`resolve_worker_config_from`]) for
    /// end-to-end validated configuration. This constructor bypasses the
    /// end-to-end validation of the resolution pipeline. Callers are
    /// responsible for supplying individually valid budget and capacity values.
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
///
/// Filesystem and Git connector launches share the same backend bundle and
/// runtime tuning, but Git carries one extra invariant: `mirror_root` must
/// point to an existing local directory where worker-local mirrors can be
/// managed safely.
#[derive(Clone, Debug)]
pub struct DistributedWorkerConfig {
    backends: ProductionBackendConfig,
    startup: ProductionStartupSettings,
    identity: WorkerIdentityConfig,
    source: DistributedSourceSettings,
    runtime: DistributedWorkerRuntimeSettings,
}

impl DistributedWorkerConfig {
    /// Construct one validated distributed worker configuration bundle.
    ///
    /// Enforces non-zero budget invariants and resource-exhaustion ceilings as
    /// defense-in-depth. The secret-key and zero-ID invariants are enforced by
    /// [`WorkerIdentityConfig::new`].
    ///
    /// # Errors
    ///
    /// Returns [`WorkerConfigError`] when the configured scan budgets or
    /// commit queue capacity are invalid, or when a Git distributed source
    /// points at a mirror root that is missing from the local host.
    pub fn new(
        backends: ProductionBackendConfig,
        startup: ProductionStartupSettings,
        identity: WorkerIdentityConfig,
        source: DistributedSourceSettings,
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
        if let DistributedSourceSettings::Git(source) = &source {
            validate_path_exists("mirror_root", source.mirror_root())?;
        }
        Ok(Self {
            backends,
            startup,
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
    pub fn startup(&self) -> ProductionStartupSettings {
        self.startup
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
    pub fn source(&self) -> &DistributedSourceSettings {
        &self.source
    }

    #[inline]
    #[must_use]
    pub fn runtime(&self) -> DistributedWorkerRuntimeSettings {
        self.runtime
    }

    /// Build the runtime launch bundle with the production telemetry recorder.
    #[must_use]
    pub fn worker_launch(&self) -> DistributedWorkerLaunch {
        self.worker_launch_with_recorder(Arc::new(ProductionCoordinationEventRecorder::default()))
    }

    /// Build the runtime launch bundle using a caller-supplied recorder.
    #[must_use]
    pub fn worker_launch_with_recorder(
        &self,
        recorder: Arc<dyn CoordinationEventRecorder>,
    ) -> DistributedWorkerLaunch {
        match &self.source {
            DistributedSourceSettings::Fs(source) => {
                DistributedWorkerLaunch::Fs(WorkerIdentity::new(
                    self.identity.tenant(),
                    self.identity.run(),
                    self.identity.worker(),
                    self.identity.policy_hash(),
                    self.identity.tenant_secret_key(),
                    source.to_scan_config(ExecutionMode::Connector, self.runtime.budgets()),
                    recorder,
                ))
            }
            DistributedSourceSettings::Git(source) => DistributedWorkerLaunch::Git {
                identity: GitWorkerIdentity::new(
                    self.identity.tenant(),
                    self.identity.run(),
                    self.identity.worker(),
                    self.identity.policy_hash(),
                    self.identity.tenant_secret_key(),
                    source.to_scan_config(ExecutionMode::Connector, self.runtime.budgets()),
                    recorder,
                ),
                mirror_root: source.mirror_root().to_path_buf(),
            },
        }
    }

    /// Convert the parsed runtime settings into the runtime struct expected by the worker loop.
    #[inline]
    #[must_use]
    pub fn runtime_config(&self) -> DistributedRuntimeConfig {
        self.runtime.to_runtime_config()
    }
}

/// Source-specific runtime launch bundle derived from [`DistributedWorkerConfig`].
#[derive(Clone)]
pub enum DistributedWorkerLaunch {
    /// Filesystem distributed worker identity.
    Fs(WorkerIdentity),
    /// Git distributed worker identity plus the required mirror root.
    Git {
        identity: GitWorkerIdentity,
        mirror_root: PathBuf,
    },
}

/// Fully resolved worker launch configuration.
#[derive(Clone, Debug)]
pub enum ResolvedWorkerConfig {
    /// Local direct scan path.
    Local(LocalWorkerConfig),
    /// Real etcd + PostgreSQL distributed worker path.
    Distributed(Box<DistributedWorkerConfig>),
}

/// Error returned when parsing or validating worker configuration.
#[derive(Debug, thiserror::Error)]
pub enum WorkerConfigError {
    /// Invalid CLI usage or unknown flags.
    #[error("{0}")]
    Usage(String),
    /// A required field was missing.
    #[error("missing required value for {field} (set {flag}=... or {env}=...)")]
    MissingRequiredValue {
        field: &'static str,
        flag: &'static str,
        env: &'static str,
    },
    /// A field value was present but invalid.
    #[error("invalid value for {field}: {value} ({reason})")]
    InvalidValue {
        field: &'static str,
        value: String,
        reason: String,
    },
    /// The etcd configuration was syntactically invalid.
    #[error("invalid etcd worker configuration: {0}")]
    InvalidEtcdConfig(#[source] EtcdCoordinatorConfigError),
    /// The production backend configuration was invalid.
    #[error("invalid production backend configuration: {0}")]
    InvalidBackendConfig(#[source] ProductionBackendConfigError),
    /// The provided combination of mode, backend, and source is unsupported.
    #[error("{message}")]
    UnsupportedCombination { message: String },
    /// An environment variable is set but contains invalid UTF-8.
    #[error("environment variable {key} is set but contains invalid UTF-8")]
    InvalidEncoding { key: &'static str },
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
    ///
    /// # Errors
    ///
    /// Returns [`WorkerConfigError::InvalidEncoding`] when the variable is set
    /// but contains bytes that are not valid UTF-8.
    fn get(&self, key: &'static str) -> Result<Option<String>, WorkerConfigError>;
}

/// Environment provider backed by the current process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnv;

impl EnvProvider for ProcessEnv {
    fn get(&self, key: &'static str) -> Result<Option<String>, WorkerConfigError> {
        match std::env::var(key) {
            Ok(val) => Ok(Some(val)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(WorkerConfigError::InvalidEncoding { key })
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
    mirror_root: Option<String>,
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
    startup_schema_mode: Option<String>,
    tenant: Option<String>,
    run: Option<String>,
    worker: Option<String>,
    policy_hash: Option<String>,
    tenant_secret_key: Option<String>,
    /// Tracks whether the tenant secret key was supplied via a CLI flag.
    cli_tenant_secret_key: bool,
    /// Tracks whether the done-ledger DSN was supplied via a CLI flag.
    cli_done_ledger_dsn: bool,
    /// Tracks whether the findings DSN was supplied via a CLI flag.
    cli_findings_dsn: bool,
    /// Tracks whether the etcd endpoints were supplied via a CLI flag.
    cli_etcd_endpoints: bool,
}

impl fmt::Debug for RawWorkerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawWorkerConfig")
            .field("execution_mode", &self.execution_mode)
            .field("backend", &self.backend)
            .field("source", &self.source)
            .field("path", &self.path)
            .field("mirror_root", &self.mirror_root)
            .field("rules_file", &self.rules_file)
            .field("decode_depth", &self.decode_depth)
            .field("scan_binary", &self.scan_binary)
            .field("skip_archives", &self.skip_archives)
            .field("anchor_mode", &self.anchor_mode)
            .field("max_items", &self.max_items)
            .field("max_bytes", &self.max_bytes)
            .field("commit_queue_capacity", &self.commit_queue_capacity)
            .field("etcd_endpoints_csv", &"[redacted]")
            .field("etcd_namespace", &self.etcd_namespace)
            .field("done_ledger_postgres_dsn", &"[redacted]")
            .field("findings_postgres_dsn", &"[redacted]")
            .field("startup_schema_mode", &self.startup_schema_mode)
            .field("tenant", &self.tenant)
            .field("run", &self.run)
            .field("worker", &self.worker)
            .field("policy_hash", &self.policy_hash)
            .field("tenant_secret_key", &"[redacted]")
            .field("cli_tenant_secret_key", &self.cli_tenant_secret_key)
            .field("cli_done_ledger_dsn", &self.cli_done_ledger_dsn)
            .field("cli_findings_dsn", &self.cli_findings_dsn)
            .field("cli_etcd_endpoints", &self.cli_etcd_endpoints)
            .finish()
    }
}

impl RawWorkerConfig {
    fn from_env<E: EnvProvider + ?Sized>(env: &E) -> Result<Self, WorkerConfigError> {
        Ok(Self {
            execution_mode: env.get(ENV_WORKER_MODE)?,
            backend: env.get(ENV_WORKER_BACKEND)?,
            source: env.get(ENV_WORKER_SOURCE)?,
            path: env.get(ENV_WORKER_PATH)?,
            mirror_root: env.get(ENV_MIRROR_ROOT)?,
            rules_file: env.get(ENV_WORKER_RULES_FILE)?,
            decode_depth: env.get(ENV_WORKER_DECODE_DEPTH)?,
            scan_binary: env.get(ENV_WORKER_SCAN_BINARY)?,
            skip_archives: env.get(ENV_FS_SKIP_ARCHIVES)?,
            anchor_mode: env.get(ENV_WORKER_ANCHOR_MODE)?,
            max_items: env.get(ENV_MAX_ITEMS)?,
            max_bytes: env.get(ENV_MAX_BYTES)?,
            commit_queue_capacity: env.get(ENV_COMMIT_QUEUE_CAPACITY)?,
            etcd_endpoints_csv: env.get(ENV_ETCD_ENDPOINTS)?,
            etcd_namespace: env.get(ENV_ETCD_NAMESPACE)?,
            done_ledger_postgres_dsn: env.get(ENV_DONE_LEDGER_POSTGRES_DSN)?,
            findings_postgres_dsn: env.get(ENV_FINDINGS_POSTGRES_DSN)?,
            startup_schema_mode: env.get(ENV_STARTUP_SCHEMA_MODE)?,
            tenant: env.get(ENV_TENANT_ID)?,
            run: env.get(ENV_RUN_ID)?,
            worker: env.get(ENV_WORKER_ID)?,
            policy_hash: env.get(ENV_POLICY_HASH)?,
            tenant_secret_key: env.get(ENV_TENANT_SECRET_KEY)?,
            cli_tenant_secret_key: false,
            cli_done_ledger_dsn: false,
            cli_findings_dsn: false,
            cli_etcd_endpoints: false,
        })
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
            "mirror-root" => self.mirror_root = Some(value.to_owned()),
            "rules-file" => self.rules_file = Some(value.to_owned()),
            "decode-depth" => self.decode_depth = Some(value.to_owned()),
            "scan-binary" => self.scan_binary = Some(value.to_owned()),
            "skip-archives" => self.skip_archives = Some(value.to_owned()),
            "anchor-mode" => self.anchor_mode = Some(value.to_owned()),
            "max-items" => self.max_items = Some(value.to_owned()),
            "max-bytes" => self.max_bytes = Some(value.to_owned()),
            "commit-queue-capacity" => self.commit_queue_capacity = Some(value.to_owned()),
            "etcd-endpoints" => {
                self.etcd_endpoints_csv = Some(value.to_owned());
                self.cli_etcd_endpoints = true;
            }
            "etcd-namespace" => self.etcd_namespace = Some(value.to_owned()),
            "done-ledger-postgres-dsn" => {
                self.done_ledger_postgres_dsn = Some(value.to_owned());
                self.cli_done_ledger_dsn = true;
            }
            "findings-postgres-dsn" => {
                self.findings_postgres_dsn = Some(value.to_owned());
                self.cli_findings_dsn = true;
            }
            "startup-schema-mode" => self.startup_schema_mode = Some(value.to_owned()),
            "tenant-id" => self.tenant = Some(value.to_owned()),
            "run-id" => self.run = Some(value.to_owned()),
            "worker-id" => self.worker = Some(value.to_owned()),
            "policy-hash" => self.policy_hash = Some(value.to_owned()),
            "tenant-secret-key" => {
                self.tenant_secret_key = Some(value.to_owned());
                self.cli_tenant_secret_key = true;
            }
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
        )?
        .or_else(|| default_backend_for_mode(execution_mode));
        let source = parse_optional(
            self.source.as_deref(),
            "source",
            parse_from_str::<WorkerSource>,
        )?
        .unwrap_or(WorkerSource::Fs);
        let path = parse_optional(self.path.as_deref(), "path", parse_path)?.unwrap_or_else(|| {
            let default = PathBuf::from(".");
            tracing::warn!(
                path = %default.display(),
                "no scan path configured; defaulting to current directory"
            );
            default
        });
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

        // Warn when secrets are passed via CLI flags (visible in process table).
        if self.cli_tenant_secret_key {
            tracing::warn!(
                flag = "--tenant-secret-key",
                preferred_env = ENV_TENANT_SECRET_KEY,
                "secret provided via CLI flag; prefer env var to avoid process-table exposure"
            );
        }
        if self.cli_done_ledger_dsn {
            tracing::warn!(
                flag = "--done-ledger-postgres-dsn",
                preferred_env = ENV_DONE_LEDGER_POSTGRES_DSN,
                "credential provided via CLI flag; prefer env var to avoid process-table exposure"
            );
        }
        if self.cli_findings_dsn {
            tracing::warn!(
                flag = "--findings-postgres-dsn",
                preferred_env = ENV_FINDINGS_POSTGRES_DSN,
                "credential provided via CLI flag; prefer env var to avoid process-table exposure"
            );
        }
        if self.cli_etcd_endpoints {
            tracing::warn!(
                flag = "--etcd-endpoints",
                preferred_env = ENV_ETCD_ENDPOINTS,
                "endpoint provided via CLI flag; prefer env var to avoid process-table exposure"
            );
        }

        // Helper: build a direct local config.
        let make_local = || {
            validate_path_exists("path", &path)?;
            LocalWorkerConfig::new(
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
                make_local()
            }
            ExecutionMode::Connector => {
                let backend = backend.ok_or(WorkerConfigError::MissingRequiredValue {
                    field: "backend",
                    flag: "--backend",
                    env: ENV_WORKER_BACKEND,
                })?;
                match backend {
                    BackendSelection::Local => Err(WorkerConfigError::UnsupportedCombination {
                        message: "connector mode runs the distributed worker loop against the real production backends; switch to --mode=direct for local scans".to_owned(),
                    }),
                    BackendSelection::Production => {
                        let etcd_endpoints = parse_required(
                            self.etcd_endpoints_csv.as_deref(),
                            parse_nonempty_string_redacted,
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
                        let startup_schema_mode = parse_optional(
                            self.startup_schema_mode.as_deref(),
                            "startup_schema_mode",
                            parse_startup_schema_mode,
                        )?
                        .unwrap_or_default();
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
                        validate_path_exists("path", &path)?;
                        let source = match source {
                            WorkerSource::Fs => DistributedSourceSettings::Fs(
                                FsSourceSettings::new(path)
                                    .with_rules_file(rules_file)
                                    .with_decode_depth(decode_depth)
                                    .with_scan_binary(scan_binary)
                                    .with_skip_archives(skip_archives)
                                    .with_anchor_mode(anchor_mode),
                            ),
                            WorkerSource::Git => {
                                let mirror_root = parse_required(
                                    self.mirror_root.as_deref(),
                                    parse_nonempty_string,
                                    "mirror_root",
                                    "--mirror-root",
                                    ENV_MIRROR_ROOT,
                                )?;
                                let mirror_root = PathBuf::from(mirror_root);
                                validate_path_exists("mirror_root", &mirror_root)?;
                                DistributedSourceSettings::Git(GitDistributedSourceSettings::new(
                                    GitSourceSettings::new(path)
                                        .with_rules_file(rules_file)
                                        .with_decode_depth(decode_depth)
                                        .with_scan_binary(scan_binary)
                                        .with_anchor_mode(anchor_mode),
                                    mirror_root,
                                ))
                            }
                        };
                        let commit_queue_capacity = parse_optional(
                            self.commit_queue_capacity.as_deref(),
                            "commit_queue_capacity",
                            parse_nonzero_usize,
                        )?
                        .unwrap_or(defaults.commit_queue_capacity);
                        let runtime =
                            DistributedWorkerRuntimeSettings::new(budgets, commit_queue_capacity);
                        let startup = ProductionStartupSettings::new(startup_schema_mode);
                        let identity = WorkerIdentityConfig::new(
                            tenant,
                            run,
                            worker,
                            policy_hash,
                            tenant_secret_key,
                        )?;
                        Ok(ResolvedWorkerConfig::Distributed(Box::new(
                            DistributedWorkerConfig::new(
                                backends,
                                startup,
                                identity,
                                source,
                                runtime,
                            )?,
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
    let mut raw = RawWorkerConfig::from_env(env)?;
    raw.apply_cli_args(args)?;
    raw.resolve()
}

fn usage() -> &'static str {
    "usage: gossip-worker [--mode=direct|connector] [--backend=local|production] \\
     [--tenant-id=HEX32] [--run-id=U64] [--worker-id=U64] [--policy-hash=HEX32] \\
     [--tenant-secret-key=HEX32] [--etcd-endpoints=CSV] [--etcd-namespace=PREFIX] \\
     [--done-ledger-postgres-dsn=DSN] [--findings-postgres-dsn=DSN] \\
     [--mirror-root=PATH] \\
     [--startup-schema-mode=validate|dev-auto-migrate] \\
     [--rules-file=PATH] [--decode-depth=N] [--scan-binary=true|false] \\
     [--skip-archives=true|false] [--anchor-mode=manual|derived] \\
     [--max-items=N] [--max-bytes=N] [--commit-queue-capacity=N] \\
     [fs|git] [path]\n\
     defaults: --mode=connector fs .\n\
     note: connector mode defaults to backend=production; use --mode=direct for local scans"
}

fn default_backend_for_mode(execution_mode: ExecutionMode) -> Option<BackendSelection> {
    match execution_mode {
        ExecutionMode::Direct => None,
        ExecutionMode::Connector => Some(BackendSelection::Production),
    }
}

/// Fail-fast check that a scan path exists on the local host. Called during
/// config resolution so the worker surfaces a clear error at startup rather
/// than deep inside the scan loop.
fn validate_path_exists(field: &'static str, path: &Path) -> Result<(), WorkerConfigError> {
    match path.try_exists() {
        Ok(false) => Err(WorkerConfigError::invalid_value(
            field,
            path.display().to_string(),
            "path does not exist",
        )),
        Err(io_err) => Err(WorkerConfigError::invalid_value(
            field,
            path.display().to_string(),
            format!("cannot verify path existence: {io_err}"),
        )),
        Ok(true) => Ok(()),
    }
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

fn parse_startup_schema_mode(
    field: &'static str,
    raw: &str,
) -> Result<StartupSchemaMode, WorkerConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "validate" => Ok(StartupSchemaMode::Validate),
        "dev-auto-migrate" | "dev_auto_migrate" => Ok(StartupSchemaMode::DevAutoMigrate),
        _ => Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "expected 'validate' or 'dev-auto-migrate'",
        )),
    }
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
    Ok(TenantId::from_bytes(parse_hex_32_redacted(field, raw)?))
}

fn parse_policy_hash(field: &'static str, raw: &str) -> Result<PolicyHash, WorkerConfigError> {
    Ok(PolicyHash::from_bytes(parse_hex_32_redacted(field, raw)?))
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

#[cfg(test)]
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
        fn get(&self, key: &'static str) -> Result<Option<String>, WorkerConfigError> {
            Ok(self.vars.get(key).cloned())
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
                assert_eq!(cfg.startup(), ProductionStartupSettings::validate_only());
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn production_config_reads_startup_schema_mode_from_env() {
        let env = production_env().with(ENV_STARTUP_SCHEMA_MODE, "dev-auto-migrate");
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("production env should resolve");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.startup(), ProductionStartupSettings::dev_auto_migrate());
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
    fn cli_overrides_env_for_startup_schema_mode() {
        let env = production_env().with(ENV_STARTUP_SCHEMA_MODE, "validate");
        let resolved = resolve_worker_config_from(["--startup-schema-mode=dev-auto-migrate"], &env)
            .expect("CLI startup-schema-mode override should resolve");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.startup(), ProductionStartupSettings::dev_auto_migrate());
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
    fn connector_mode_defaults_backend_to_production() {
        let env = {
            let mut vars = production_env().vars;
            vars.remove(ENV_WORKER_BACKEND);
            TestEnv { vars }
        };
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("connector mode should default backend to production");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.backend(), BackendSelection::Production);
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn default_worker_path_fails_closed_when_backend_config_is_absent() {
        let err = resolve_worker_config_from(["fs", "/tmp/project"], &TestEnv::default())
            .expect_err("default worker launch without backend config must fail closed");

        assert!(matches!(
            err,
            WorkerConfigError::MissingRequiredValue {
                field: "etcd_endpoints",
                flag: "--etcd-endpoints",
                env: ENV_ETCD_ENDPOINTS,
            }
        ));
    }

    #[test]
    fn direct_mode_defaults_to_local_without_backend() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_str = dir.path().to_str().expect("utf-8 path");
        let resolved =
            resolve_worker_config_from(["--mode=direct", "fs", dir_str], &TestEnv::default())
                .expect("direct mode should resolve without backend selection");

        match resolved {
            ResolvedWorkerConfig::Local(cfg) => {
                assert_eq!(cfg.execution_mode(), ExecutionMode::Direct);
                match cfg.source() {
                    WorkerSourceSettings::Fs(settings) => {
                        assert_eq!(settings.path(), dir.path());
                    }
                    other => panic!("expected fs local settings, got {other:?}"),
                }
            }
            other => panic!("expected local config, got {other:?}"),
        }
    }

    #[test]
    fn production_requires_explicit_tenant_id() {
        assert_production_rejects_missing_field(
            ENV_TENANT_ID,
            "tenant_id",
            "--tenant-id",
            ENV_TENANT_ID,
        );
    }

    #[test]
    fn connector_mode_rejects_git_source_for_local_git_scans() {
        let env = production_env().with(ENV_WORKER_SOURCE, "git");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("connector mode must reject git");

        assert!(matches!(
            err,
            WorkerConfigError::UnsupportedCombination { ref message }
                if message.contains("source=fs")
                    && message.contains("--mode=direct")
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
        let identity = cfg.worker_identity();
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
    fn distributed_worker_identity_uses_production_recorder() {
        let env = production_env();
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("production env should resolve");
        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        let identity = cfg.worker_identity();
        let debug = format!("{:?}", identity.recorder);
        assert!(
            debug.contains("ProductionCoordinationEventRecorder"),
            "default worker_identity() must wire the production recorder: {debug}"
        );
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
    fn parse_tenant_id_redacts_invalid_input() {
        let raw_input = "not-valid-hex-at-all";
        let err = parse_tenant_id("tenant_id", raw_input)
            .expect_err("invalid tenant_id hex should be rejected");

        let display = err.to_string();
        assert!(
            display.contains("[redacted]"),
            "tenant_id parse error must redact the raw input, got: {display}"
        );
        assert!(
            !display.contains(raw_input),
            "tenant_id parse error must not contain the raw input, got: {display}"
        );
    }

    #[test]
    fn parse_policy_hash_redacts_invalid_input() {
        let raw_input = "short-policy-hash";
        let err = parse_policy_hash("policy_hash", raw_input)
            .expect_err("invalid policy_hash hex should be rejected");

        let display = err.to_string();
        assert!(
            display.contains("[redacted]"),
            "policy_hash parse error must redact the raw input, got: {display}"
        );
        assert!(
            !display.contains(raw_input),
            "policy_hash parse error must not contain the raw input, got: {display}"
        );
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
    fn parse_startup_schema_mode_accepts_supported_variants() {
        assert_eq!(
            parse_startup_schema_mode("startup_schema_mode", "validate").unwrap(),
            StartupSchemaMode::Validate
        );
        assert_eq!(
            parse_startup_schema_mode("startup_schema_mode", "DEV-AUTO-MIGRATE").unwrap(),
            StartupSchemaMode::DevAutoMigrate
        );
        assert_eq!(
            parse_startup_schema_mode("startup_schema_mode", "dev_auto_migrate").unwrap(),
            StartupSchemaMode::DevAutoMigrate
        );
    }

    #[test]
    fn parse_startup_schema_mode_rejects_unknown() {
        let err = parse_startup_schema_mode("startup_schema_mode", "auto")
            .expect_err("unknown startup schema mode must fail");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "startup_schema_mode",
                ..
            }
        ));
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
    fn local_worker_config_execution_mode_is_always_direct() {
        let cfg = LocalWorkerConfig::new(
            WorkerSourceSettings::Fs(FsSourceSettings::new(PathBuf::from("/tmp"))),
            ScanBudgets::default(),
        )
        .expect("default local config should be valid");
        assert_eq!(cfg.execution_mode(), ExecutionMode::Direct);
    }

    #[test]
    fn local_config_rejects_zero_budgets() {
        let err = LocalWorkerConfig::new(
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
    fn direct_mode_rejects_nonexistent_path() {
        let err = resolve_worker_config_from(
            ["--mode=direct", "fs", "/nonexistent/review-test"],
            &TestEnv::default(),
        )
        .expect_err("nonexistent path must be rejected in direct mode");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue { field: "path", .. }
        ));
    }

    #[test]
    fn local_backend_rejects_nonexistent_path() {
        let err = resolve_worker_config_from(
            [
                "--mode=direct",
                "--backend=local",
                "fs",
                "/nonexistent/review-test",
            ],
            &TestEnv::default(),
        )
        .expect_err("nonexistent path must be rejected with direct local backend");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue { field: "path", .. }
        ));
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

    // --- Connector rejection rules ---

    #[test]
    fn connector_mode_rejects_local_backend_for_filesystem_scans() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_str = dir.path().to_str().expect("utf-8 path");
        let err =
            resolve_worker_config_from(["--backend=local", "fs", dir_str], &TestEnv::default())
                .expect_err("connector mode must reject local backend selection");

        assert!(matches!(
            err,
            WorkerConfigError::UnsupportedCombination { ref message }
                if message.contains("distributed worker loop against the real production backends")
                    && message.contains("--mode=direct")
        ));
    }

    // --- InvalidEtcdConfig error variant coverage ---

    #[test]
    fn production_rejects_endpoints_csv_containing_only_delimiters() {
        // ",," passes parse_nonempty_string (non-empty after trim), but
        // EtcdCoordinatorConfig::from_endpoints_csv filters all empty
        // segments, yielding NoEndpoints.
        let env = production_env().with(ENV_ETCD_ENDPOINTS, ",,");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("all-delimiter endpoints must be rejected");
        assert!(
            matches!(err, WorkerConfigError::InvalidEtcdConfig(_)),
            "expected InvalidEtcdConfig, got {err:?}"
        );
    }

    #[test]
    fn production_rejects_invalid_etcd_namespace_prefix() {
        // A namespace without a leading slash fails etcd config validation.
        let env = production_env().with(ENV_ETCD_NAMESPACE, "no-leading-slash");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("namespace without leading '/' must be rejected");
        assert!(
            matches!(err, WorkerConfigError::InvalidEtcdConfig(_)),
            "expected InvalidEtcdConfig, got {err:?}"
        );
    }

    // --- Parser unit tests ---

    #[test]
    fn zero_run_id_is_rejected_with_descriptive_reason() {
        let env = production_env().with(ENV_RUN_ID, "0");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("run_id=0 must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "run_id",
                ref reason,
                ..
            } if reason.contains("must be > 0")
        ));
    }

    #[test]
    fn u64_max_run_id_is_accepted() {
        let env = production_env().with(ENV_RUN_ID, "18446744073709551615");
        let result = resolve_worker_config_from(Vec::<String>::new(), &env);
        assert!(result.is_ok(), "u64::MAX should be valid run_id");
    }

    #[test]
    fn overflowing_run_id_is_rejected() {
        let env = production_env().with(ENV_RUN_ID, "18446744073709551616");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("overflow must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "run_id",
                ..
            }
        ));
    }

    #[test]
    fn whitespace_padded_run_id_is_accepted() {
        let env = production_env().with(ENV_RUN_ID, "  42  ");
        let result = resolve_worker_config_from(Vec::<String>::new(), &env);
        assert!(result.is_ok(), "whitespace-padded run_id should be trimmed");
    }

    #[test]
    fn zero_worker_id_is_rejected_with_descriptive_reason() {
        let env = production_env().with(ENV_WORKER_ID, "0");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("worker_id=0 must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "worker_id",
                ref reason,
                ..
            } if reason.contains("must be > 0")
        ));
    }

    #[test]
    fn u64_max_worker_id_is_accepted() {
        let env = production_env().with(ENV_WORKER_ID, "18446744073709551615");
        let result = resolve_worker_config_from(Vec::<String>::new(), &env);
        assert!(result.is_ok(), "u64::MAX should be valid worker_id");
    }

    #[test]
    fn overflowing_worker_id_is_rejected() {
        let env = production_env().with(ENV_WORKER_ID, "18446744073709551616");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("overflow must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "worker_id",
                ..
            }
        ));
    }

    #[test]
    fn whitespace_only_path_is_rejected() {
        let err = resolve_worker_config_from(["--mode=direct", "fs", "   "], &TestEnv::default())
            .expect_err("whitespace-only path must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue { field: "path", .. }
        ));
    }

    #[test]
    fn non_numeric_max_items_is_rejected() {
        let env = production_env().with(ENV_MAX_ITEMS, "abc");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("non-numeric max_items must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_items",
                ..
            }
        ));
    }

    #[test]
    fn non_numeric_max_bytes_is_rejected() {
        let env = production_env().with(ENV_MAX_BYTES, "xyz");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("non-numeric max_bytes must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_bytes",
                ..
            }
        ));
    }

    #[test]
    fn negative_run_id_is_rejected() {
        let env = production_env().with(ENV_RUN_ID, "-1");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("negative run_id must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "run_id",
                ..
            }
        ));
    }

    // --- Missing required field tests ---

    /// Removes `remove_env` from a full production env and asserts that
    /// resolution fails with `MissingRequiredValue` carrying the expected
    /// field name, CLI flag, and env var.
    fn assert_production_rejects_missing_field(
        remove_env: &'static str,
        expected_field: &'static str,
        expected_flag: &'static str,
        expected_env: &'static str,
    ) {
        let env = {
            let mut vars = production_env().vars;
            vars.remove(remove_env);
            TestEnv { vars }
        };
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err(&format!("missing {expected_field} must be rejected"));
        assert!(
            matches!(
                err,
                WorkerConfigError::MissingRequiredValue { field, flag, env }
                    if field == expected_field && flag == expected_flag && env == expected_env
            ),
            "expected MissingRequiredValue for {expected_field}, got: {err:?}"
        );
    }

    #[test]
    fn production_missing_required_fields_are_rejected() {
        let cases: &[(&str, &str, &str, &str)] = &[
            (
                ENV_ETCD_ENDPOINTS,
                "etcd_endpoints",
                "--etcd-endpoints",
                ENV_ETCD_ENDPOINTS,
            ),
            (
                ENV_ETCD_NAMESPACE,
                "etcd_namespace",
                "--etcd-namespace",
                ENV_ETCD_NAMESPACE,
            ),
            (
                ENV_DONE_LEDGER_POSTGRES_DSN,
                "done_ledger_postgres_dsn",
                "--done-ledger-postgres-dsn",
                ENV_DONE_LEDGER_POSTGRES_DSN,
            ),
            (
                ENV_FINDINGS_POSTGRES_DSN,
                "findings_postgres_dsn",
                "--findings-postgres-dsn",
                ENV_FINDINGS_POSTGRES_DSN,
            ),
            (ENV_RUN_ID, "run_id", "--run-id", ENV_RUN_ID),
            (ENV_WORKER_ID, "worker_id", "--worker-id", ENV_WORKER_ID),
            (
                ENV_POLICY_HASH,
                "policy_hash",
                "--policy-hash",
                ENV_POLICY_HASH,
            ),
            (
                ENV_TENANT_SECRET_KEY,
                "tenant_secret_key",
                "--tenant-secret-key",
                ENV_TENANT_SECRET_KEY,
            ),
        ];

        for &(remove_env, field, flag, env) in cases {
            assert_production_rejects_missing_field(remove_env, field, flag, env);
        }
    }

    // --- Direct construction validation tests ---

    #[test]
    fn local_config_rejects_zero_max_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = LocalWorkerConfig::new(
            WorkerSourceSettings::Fs(FsSourceSettings::new(dir.path())),
            ScanBudgets {
                max_items: 100,
                max_bytes: 0,
            },
        )
        .expect_err("zero max_bytes must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_bytes",
                ..
            }
        ));
    }

    #[test]
    fn local_config_rejects_max_items_above_ceiling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = LocalWorkerConfig::new(
            WorkerSourceSettings::Fs(FsSourceSettings::new(dir.path())),
            ScanBudgets {
                max_items: MAX_ITEMS_CEILING + 1,
                max_bytes: 1024,
            },
        )
        .expect_err("above-ceiling max_items must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_items",
                ..
            }
        ));
    }

    #[test]
    fn local_config_rejects_max_bytes_above_ceiling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = LocalWorkerConfig::new(
            WorkerSourceSettings::Fs(FsSourceSettings::new(dir.path())),
            ScanBudgets {
                max_items: 100,
                max_bytes: MAX_BYTES_CEILING + 1,
            },
        )
        .expect_err("above-ceiling max_bytes must be rejected");
        assert!(matches!(
            err,
            WorkerConfigError::InvalidValue {
                field: "max_bytes",
                ..
            }
        ));
    }

    // --- Display formatting tests ---

    #[test]
    fn missing_required_value_display_includes_field_flag_and_env() {
        let err = WorkerConfigError::MissingRequiredValue {
            field: "tenant_id",
            flag: "--tenant-id",
            env: "GOSSIP_TENANT_ID",
        };
        let msg = err.to_string();
        assert!(msg.contains("tenant_id"), "display must include field name");
        assert!(msg.contains("--tenant-id"), "display must include flag");
        assert!(
            msg.contains("GOSSIP_TENANT_ID"),
            "display must include env var"
        );
    }

    #[test]
    fn invalid_value_display_includes_field_value_and_reason() {
        let err = WorkerConfigError::invalid_value(
            "backend",
            "banana",
            "expected 'local' or 'production'",
        );
        let msg = err.to_string();
        assert!(msg.contains("backend"), "display must include field name");
        assert!(
            msg.contains("banana"),
            "display must include rejected value"
        );
        assert!(msg.contains("expected"), "display must include reason");
    }

    #[test]
    fn usage_error_display_includes_message() {
        let err = WorkerConfigError::Usage("unknown flag --foo".into());
        let msg = err.to_string();
        assert!(msg.contains("--foo"), "display must include usage message");
    }

    #[test]
    fn unsupported_combination_display_includes_message() {
        let err = WorkerConfigError::UnsupportedCombination {
            message: "git source not supported".into(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("git source"),
            "display must include combination detail"
        );
    }

    #[test]
    fn invalid_etcd_config_display_includes_source_message() {
        let err = WorkerConfigError::InvalidEtcdConfig(EtcdCoordinatorConfigError::NoEndpoints);
        let msg = err.to_string();
        assert!(
            msg.contains("etcd"),
            "display must reference etcd configuration"
        );
        assert!(
            msg.contains("endpoint"),
            "display must propagate the inner error message"
        );
    }

    #[test]
    fn invalid_backend_config_display_includes_source_message() {
        let err = WorkerConfigError::InvalidBackendConfig(
            ProductionBackendConfigError::EmptyDoneLedgerPostgresDsn,
        );
        let msg = err.to_string();
        assert!(
            msg.contains("production backend"),
            "display must reference backend configuration"
        );
        assert!(
            msg.contains("done-ledger"),
            "display must propagate the inner error message"
        );
    }

    // --- Git source rejection via CLI positional arg ---

    #[test]
    fn connector_mode_rejects_git_source_via_cli_positional() {
        let env = production_env();
        let err = resolve_worker_config_from(["git", "/tmp"], &env)
            .expect_err("connector mode must reject git via positional arg");
        assert!(matches!(
            err,
            WorkerConfigError::UnsupportedCombination { ref message }
                if message.contains("source=fs")
                    && message.contains("--mode=direct")
        ));
    }

    // --- Direct WorkerIdentityConfig construction validation ---

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
            ProductionStartupSettings::validate_only(),
            identity,
            FsSourceSettings::new("/tmp"),
            runtime,
        );
        assert!(
            result.is_err(),
            "commit_queue_capacity above ceiling must be rejected, got: {result:?}"
        );
    }

    // --- Positional argument edge cases ---

    #[test]
    fn single_positional_git_selects_source_not_path() {
        let env = TestEnv::default()
            .with(ENV_WORKER_MODE, "direct")
            .with(ENV_WORKER_PATH, "/tmp");
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
        let result = resolve_worker_config_from(["git", "/tmp"], &env);
        assert!(
            result.is_ok(),
            "invalid skip_archives must not reject git launches: {result:?}"
        );
    }

    // ---- CLI secret-exposure warning tests ----

    #[test]
    fn cli_tenant_secret_key_warns_about_process_table_exposure() {
        use crate::recorder::test_support::capture_logs;
        use tracing::Level;

        let env = production_env();
        let logs = capture_logs(Level::WARN, || {
            let _ = resolve_worker_config_from(
                [
                    "--tenant-secret-key=3333333333333333333333333333333333333333333333333333333333333333",
                ],
                &env,
            );
        });
        assert!(
            logs.contains("process-table exposure"),
            "must warn when secret key supplied via CLI flag, got: {logs}"
        );
    }

    #[test]
    fn cli_done_ledger_dsn_warns_about_process_table_exposure() {
        use crate::recorder::test_support::capture_logs;
        use tracing::Level;

        let env = production_env();
        let logs = capture_logs(Level::WARN, || {
            let _ = resolve_worker_config_from(
                ["--done-ledger-postgres-dsn=postgresql://u:p@h/d"],
                &env,
            );
        });
        assert!(
            logs.contains("process-table exposure"),
            "must warn when done-ledger DSN supplied via CLI flag, got: {logs}"
        );
    }

    #[test]
    fn cli_findings_dsn_warns_about_process_table_exposure() {
        use crate::recorder::test_support::capture_logs;
        use tracing::Level;

        let env = production_env();
        let logs = capture_logs(Level::WARN, || {
            let _ = resolve_worker_config_from(["--findings-postgres-dsn=host=h dbname=d"], &env);
        });
        assert!(
            logs.contains("process-table exposure"),
            "must warn when findings DSN supplied via CLI flag, got: {logs}"
        );
    }

    #[test]
    fn cli_etcd_endpoints_warns_about_process_table_exposure() {
        use crate::recorder::test_support::capture_logs;
        use tracing::Level;

        let env = production_env();
        let logs = capture_logs(Level::WARN, || {
            let _ = resolve_worker_config_from(["--etcd-endpoints=http://127.0.0.1:2379"], &env);
        });
        assert!(
            logs.contains("process-table exposure"),
            "must warn when etcd endpoints supplied via CLI flag, got: {logs}"
        );
    }
}
