//! Typed configuration surface for worker launches.
//!
//! This module resolves environment variables plus CLI overrides into one of
//! two explicit launch paths:
//!
//! - explicit local scans (`ExecutionMode::Direct`)
//! - the default real distributed production path (`ExecutionMode::Connector`)
//!
//! Connector mode never silently falls back to a local or fake backend. The
//! real backend path is the default launch path, while local scans remain
//! available only through explicit direct-mode CLI usage. Filesystem connector
//! mode is the only distributed source supported in MVP-A.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use gossip_contracts::identity::{PolicyHash, RunId, TenantId, TenantSecretKey, WorkerId};
use gossip_coordination_etcd::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
use gossip_scanner_runtime::coordination_sink::CoordinationEventRecorder;
use gossip_scanner_runtime::distributed::{DistributedRuntimeConfig, WorkerIdentity};
use gossip_scanner_runtime::{
    AnchorMode, ExecutionMode, FsScanConfig, GitScanConfig, ScanBudgets,
};

use crate::production::{
    ProductionBackendConfig, ProductionBackendConfigError, ProductionStartupSettings,
    StartupSchemaMode,
};
use crate::recorder::ProductionCoordinationEventRecorder;

/// Environment variable selecting the worker runtime family.
pub const ENV_WORKER_MODE: &str = "GOSSIP_WORKER_MODE";
/// Environment variable selecting the worker backend.
pub const ENV_WORKER_BACKEND: &str = "GOSSIP_WORKER_BACKEND";
/// Environment variable selecting the source family.
pub const ENV_WORKER_SOURCE: &str = "GOSSIP_WORKER_SOURCE";
/// Environment variable supplying the filesystem path or git repository path.
pub const ENV_WORKER_PATH: &str = "GOSSIP_WORKER_PATH";
/// Environment variable supplying an optional rules file.
pub const ENV_WORKER_RULES_FILE: &str = "GOSSIP_WORKER_RULES_FILE";
/// Environment variable supplying an optional decode depth.
pub const ENV_WORKER_DECODE_DEPTH: &str = "GOSSIP_WORKER_DECODE_DEPTH";
/// Environment variable enabling or disabling binary scanning.
pub const ENV_WORKER_SCAN_BINARY: &str = "GOSSIP_WORKER_SCAN_BINARY";
/// Environment variable selecting the anchor extraction mode.
pub const ENV_WORKER_ANCHOR_MODE: &str = "GOSSIP_WORKER_ANCHOR_MODE";
/// Environment variable enabling or disabling archive expansion for
/// filesystem scans.
pub const ENV_FS_SKIP_ARCHIVES: &str = "GOSSIP_FS_SKIP_ARCHIVES";
/// Environment variable selecting the maximum items processed between
/// distributed checkpoints.
pub const ENV_MAX_ITEMS: &str = "GOSSIP_MAX_ITEMS";
/// Environment variable selecting the maximum bytes processed between
/// distributed checkpoints.
pub const ENV_MAX_BYTES: &str = "GOSSIP_MAX_BYTES";
/// Environment variable selecting the bounded commit queue capacity.
pub const ENV_COMMIT_QUEUE_CAPACITY: &str = "GOSSIP_COMMIT_QUEUE_CAPACITY";
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
/// Environment variable supplying the tenant secret key as a 32-byte hex
/// string.
pub const ENV_TENANT_SECRET_KEY: &str = "GOSSIP_TENANT_SECRET_KEY";
/// Environment variable selecting startup schema validation policy.
pub const ENV_STARTUP_SCHEMA_MODE: &str = "GOSSIP_STARTUP_SCHEMA_MODE";

/// Backend selection tokens accepted by the worker CLI and environment.
///
/// `Production` is the default backend for connector mode in MVP-A.
/// `Local` remains accepted only so explicit direct-mode invocations can state
/// their intent and validation can fail with a precise message instead of an
/// ambiguous parse error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendSelection {
    /// Existing local/non-production worker path for direct scans only.
    Local,
    /// Real etcd + PostgreSQL production path.
    Production,
}

impl FromStr for BackendSelection {
    type Err = WorkerConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "local" | "local-cli" | "cli-local" => Ok(Self::Local),
            "production" | "real" => Ok(Self::Production),
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
    /// Ordered-content filesystem scan.
    Fs,
    /// Local Git repository scan.
    Git,
}

impl WorkerSource {
    #[inline]
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Git => "git",
        }
    }
}

/// Filesystem-specific source settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsSourceSettings {
    path: PathBuf,
    decode_depth: Option<usize>,
    skip_archives: bool,
    scan_binary: bool,
    rules_file: Option<PathBuf>,
    anchor_mode: AnchorMode,
}

impl FsSourceSettings {
    /// Construct one filesystem source settings bundle.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            decode_depth: None,
            skip_archives: false,
            scan_binary: false,
            rules_file: None,
            anchor_mode: AnchorMode::Manual,
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
        self.decode_depth
    }

    #[inline]
    #[must_use]
    pub fn skip_archives(&self) -> bool {
        self.skip_archives
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
    pub fn with_skip_archives(mut self, skip_archives: bool) -> Self {
        self.skip_archives = skip_archives;
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

    /// Convert the typed source settings into a runtime scan template.
    #[must_use]
    pub fn to_scan_config(&self, execution_mode: ExecutionMode, budgets: ScanBudgets) -> FsScanConfig {
        FsScanConfig::new(self.path.clone())
            .with_decode_depth(self.decode_depth)
            .with_skip_archives(self.skip_archives)
            .with_scan_binary(self.scan_binary)
            .with_rules_file(self.rules_file.clone())
            .with_anchor_mode(self.anchor_mode)
            .with_execution_mode(execution_mode)
            .with_budgets(budgets)
    }
}

/// Git-specific source settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitSourceSettings {
    repo: PathBuf,
    decode_depth: Option<usize>,
    scan_binary: bool,
    rules_file: Option<PathBuf>,
    anchor_mode: AnchorMode,
}

impl GitSourceSettings {
    /// Construct one git source settings bundle.
    #[must_use]
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self {
            repo: repo.into(),
            decode_depth: None,
            scan_binary: false,
            rules_file: None,
            anchor_mode: AnchorMode::Manual,
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

    /// Convert the typed source settings into a runtime scan config.
    #[must_use]
    pub fn to_scan_config(&self, execution_mode: ExecutionMode, budgets: ScanBudgets) -> GitScanConfig {
        GitScanConfig::new(self.repo.clone())
            .with_decode_depth(self.decode_depth)
            .with_scan_binary(self.scan_binary)
            .with_rules_file(self.rules_file.clone())
            .with_anchor_mode(self.anchor_mode)
            .with_execution_mode(execution_mode)
            .with_budgets(budgets)
    }
}

/// Typed source settings for local worker launches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerSourceSettings {
    /// Filesystem settings.
    Fs(FsSourceSettings),
    /// Git settings.
    Git(GitSourceSettings),
}

impl WorkerSourceSettings {
    #[inline]
    #[must_use]
    pub fn source(&self) -> WorkerSource {
        match self {
            Self::Fs(_) => WorkerSource::Fs,
            Self::Git(_) => WorkerSource::Git,
        }
    }
}

/// Typed local worker launch configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalWorkerConfig {
    source: WorkerSourceSettings,
    budgets: ScanBudgets,
}

impl LocalWorkerConfig {
    /// Construct one local worker launch configuration.
    ///
    /// Local worker launches are always direct-mode scans. Connector-mode
    /// execution is reserved for the real distributed production path.
    #[must_use]
    pub fn new(source: WorkerSourceSettings, budgets: ScanBudgets) -> Self {
        Self { source, budgets }
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

/// Typed real-backend distributed worker launch configuration.
///
/// This configuration contains all explicit identity and source settings
/// required to run one worker against the default etcd + PostgreSQL production
/// path without any code changes or hidden fallback to doubles.
#[derive(Clone, Debug)]
pub struct DistributedWorkerConfig {
    backend: BackendSelection,
    backends: ProductionBackendConfig,
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
    policy_hash: PolicyHash,
    tenant_secret_key: TenantSecretKey,
    startup: ProductionStartupSettings,
    source: FsSourceSettings,
    runtime: DistributedWorkerRuntimeSettings,
}

impl DistributedWorkerConfig {
    /// Construct one validated distributed worker configuration bundle.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: BackendSelection,
        backends: ProductionBackendConfig,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        policy_hash: PolicyHash,
        tenant_secret_key: TenantSecretKey,
        startup: ProductionStartupSettings,
        source: FsSourceSettings,
        runtime: DistributedWorkerRuntimeSettings,
    ) -> Result<Self, WorkerConfigError> {
        if backend != BackendSelection::Production {
            return Err(WorkerConfigError::UnsupportedCombination {
                message: "distributed worker configuration requires backend=production".to_owned(),
            });
        }
        if !tenant_secret_key.is_valid() {
            return Err(WorkerConfigError::invalid_redacted_value(
                "tenant_secret_key",
                "must not be all zeros",
            ));
        }

        Ok(Self {
            backend,
            backends,
            tenant,
            run,
            worker,
            policy_hash,
            tenant_secret_key,
            startup,
            source,
            runtime,
        })
    }

    #[inline]
    #[must_use]
    pub fn backend(&self) -> BackendSelection {
        self.backend
    }

    #[inline]
    #[must_use]
    pub fn production_backends(&self) -> &ProductionBackendConfig {
        &self.backends
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

    #[inline]
    #[must_use]
    pub fn startup(&self) -> ProductionStartupSettings {
        self.startup
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

    /// Build the runtime `WorkerIdentity` using the default production recorder.
    #[must_use]
    pub fn worker_identity(&self) -> WorkerIdentity {
        self.worker_identity_with_recorder(Arc::new(ProductionCoordinationEventRecorder::default()))
    }

    /// Build the runtime `WorkerIdentity` using a caller-supplied recorder.
    #[must_use]
    pub fn worker_identity_with_recorder(
        &self,
        recorder: Arc<dyn CoordinationEventRecorder>,
    ) -> WorkerIdentity {
        WorkerIdentity::new(
            self.tenant,
            self.run,
            self.worker,
            self.policy_hash,
            self.tenant_secret_key,
            self.source
                .to_scan_config(ExecutionMode::Connector, self.runtime.budgets()),
            recorder,
        )
    }

    /// Convert the parsed runtime settings into the runtime struct expected by
    /// the distributed worker loop.
    #[inline]
    #[must_use]
    pub fn runtime_config(&self) -> DistributedRuntimeConfig {
        self.runtime.to_runtime_config()
    }
}

/// Fully resolved worker launch configuration.
#[derive(Clone, Debug)]
pub enum ResolvedWorkerConfig {
    /// Local direct scan path.
    Local(LocalWorkerConfig),
    /// Real etcd + PostgreSQL distributed worker path.
    Distributed(DistributedWorkerConfig),
}

/// Error returned when parsing or validating worker configuration.
#[derive(Debug)]
pub enum WorkerConfigError {
    /// Invalid CLI usage or unknown flags.
    Usage(String),
    /// A required production field was missing.
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
    /// The provided combination of mode/backend/source is unsupported.
    UnsupportedCombination { message: String },
}

impl WorkerConfigError {
    fn invalid_value(field: &'static str, value: impl Into<String>, reason: impl Into<String>) -> Self {
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

trait EnvProvider {
    fn get(&self, key: &'static str) -> Option<String>;
}

struct ProcessEnv;

impl EnvProvider for ProcessEnv {
    fn get(&self, key: &'static str) -> Option<String> {
        std::env::var(key).ok()
    }
}

#[derive(Clone, Debug, Default)]
struct RawWorkerConfig {
    execution_mode: Option<ExecutionMode>,
    backend: Option<BackendSelection>,
    source: Option<WorkerSource>,
    path: Option<PathBuf>,
    rules_file: Option<PathBuf>,
    decode_depth: Option<usize>,
    scan_binary: Option<bool>,
    skip_archives: Option<bool>,
    anchor_mode: Option<AnchorMode>,
    max_items: Option<usize>,
    max_bytes: Option<u64>,
    commit_queue_capacity: Option<NonZeroUsize>,
    etcd_endpoints_csv: Option<String>,
    etcd_namespace: Option<String>,
    done_ledger_postgres_dsn: Option<String>,
    findings_postgres_dsn: Option<String>,
    tenant: Option<TenantId>,
    run: Option<RunId>,
    worker: Option<WorkerId>,
    policy_hash: Option<PolicyHash>,
    tenant_secret_key: Option<TenantSecretKey>,
    startup_schema_mode: Option<StartupSchemaMode>,
}

impl RawWorkerConfig {
    fn from_env<E: EnvProvider>(env: &E) -> Result<Self, WorkerConfigError> {
        let mut raw = Self::default();
        raw.execution_mode = parse_optional_mode(env.get(ENV_WORKER_MODE), "mode")?;
        raw.backend = parse_optional_backend(env.get(ENV_WORKER_BACKEND), "backend")?;
        raw.source = parse_optional_source(env.get(ENV_WORKER_SOURCE), "source")?;
        raw.path = parse_optional_path(env.get(ENV_WORKER_PATH), "path")?;
        raw.rules_file = parse_optional_path(env.get(ENV_WORKER_RULES_FILE), "rules_file")?;
        raw.decode_depth = parse_optional_usize(env.get(ENV_WORKER_DECODE_DEPTH), "decode_depth")?;
        raw.scan_binary = parse_optional_bool(env.get(ENV_WORKER_SCAN_BINARY), "scan_binary")?;
        raw.skip_archives = parse_optional_bool(env.get(ENV_FS_SKIP_ARCHIVES), "skip_archives")?;
        raw.anchor_mode = parse_optional_anchor_mode(env.get(ENV_WORKER_ANCHOR_MODE), "anchor_mode")?;
        raw.max_items = parse_optional_positive_usize(env.get(ENV_MAX_ITEMS), "max_items")?;
        raw.max_bytes = parse_optional_positive_u64(env.get(ENV_MAX_BYTES), "max_bytes")?;
        raw.commit_queue_capacity =
            parse_optional_nonzero_usize(env.get(ENV_COMMIT_QUEUE_CAPACITY), "commit_queue_capacity")?;
        raw.etcd_endpoints_csv = parse_optional_nonempty_string(env.get(ENV_ETCD_ENDPOINTS), "etcd_endpoints")?;
        raw.etcd_namespace = parse_optional_nonempty_string(env.get(ENV_ETCD_NAMESPACE), "etcd_namespace")?;
        raw.done_ledger_postgres_dsn = parse_optional_nonempty_string(
            env.get(ENV_DONE_LEDGER_POSTGRES_DSN),
            "done_ledger_postgres_dsn",
        )?;
        raw.findings_postgres_dsn = parse_optional_nonempty_string(
            env.get(ENV_FINDINGS_POSTGRES_DSN),
            "findings_postgres_dsn",
        )?;
        raw.tenant = parse_optional_tenant_id(env.get(ENV_TENANT_ID), "tenant_id")?;
        raw.run = parse_optional_run_id(env.get(ENV_RUN_ID), "run_id")?;
        raw.worker = parse_optional_worker_id(env.get(ENV_WORKER_ID), "worker_id")?;
        raw.policy_hash = parse_optional_policy_hash(env.get(ENV_POLICY_HASH), "policy_hash")?;
        raw.tenant_secret_key =
            parse_optional_tenant_secret_key(env.get(ENV_TENANT_SECRET_KEY), "tenant_secret_key")?;
        raw.startup_schema_mode = parse_optional_startup_schema_mode(
            env.get(ENV_STARTUP_SCHEMA_MODE),
            "startup_schema_mode",
        )?;
        Ok(raw)
    }

    fn apply_cli_args<I, S>(&mut self, args: I) -> Result<(), WorkerConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut positionals = Vec::new();
        for raw_arg in args.into_iter().map(Into::into) {
            if let Some(flag) = raw_arg.strip_prefix("--") {
                let (name, value) = flag.split_once('=').ok_or_else(|| {
                    WorkerConfigError::Usage(format!(
                        "invalid flag '{raw_arg}'\n{}",
                        usage(),
                    ))
                })?;
                self.apply_cli_override(name, value)?;
            } else {
                positionals.push(raw_arg);
            }
        }

        match positionals.len() {
            0 => Ok(()),
            1 => {
                self.path = Some(parse_path("path", &positionals[0])?);
                Ok(())
            }
            2 => {
                self.source = Some(parse_source("source", &positionals[0])?);
                self.path = Some(parse_path("path", &positionals[1])?);
                Ok(())
            }
            _ => Err(WorkerConfigError::Usage(format!(
                "too many positional arguments\n{}",
                usage(),
            ))),
        }
    }

    fn apply_cli_override(&mut self, name: &str, value: &str) -> Result<(), WorkerConfigError> {
        match name {
            "mode" => self.execution_mode = Some(parse_mode("mode", value)?),
            "backend" => self.backend = Some(parse_backend("backend", value)?),
            "source" => self.source = Some(parse_source("source", value)?),
            "path" => self.path = Some(parse_path("path", value)?),
            "rules-file" => self.rules_file = Some(parse_path("rules_file", value)?),
            "decode-depth" => self.decode_depth = Some(parse_usize("decode_depth", value)?),
            "scan-binary" => self.scan_binary = Some(parse_bool("scan_binary", value)?),
            "skip-archives" => self.skip_archives = Some(parse_bool("skip_archives", value)?),
            "anchor-mode" => self.anchor_mode = Some(parse_anchor_mode("anchor_mode", value)?),
            "max-items" => self.max_items = Some(parse_positive_usize("max_items", value)?),
            "max-bytes" => self.max_bytes = Some(parse_positive_u64("max_bytes", value)?),
            "commit-queue-capacity" => {
                self.commit_queue_capacity = Some(parse_nonzero_usize("commit_queue_capacity", value)?)
            }
            "etcd-endpoints" => {
                self.etcd_endpoints_csv = Some(parse_nonempty_string("etcd_endpoints", value)?)
            }
            "etcd-namespace" => {
                self.etcd_namespace = Some(parse_nonempty_string("etcd_namespace", value)?)
            }
            "done-ledger-postgres-dsn" => {
                self.done_ledger_postgres_dsn =
                    Some(parse_nonempty_string("done_ledger_postgres_dsn", value)?)
            }
            "findings-postgres-dsn" => {
                self.findings_postgres_dsn = Some(parse_nonempty_string("findings_postgres_dsn", value)?)
            }
            "tenant-id" => self.tenant = Some(parse_tenant_id("tenant_id", value)?),
            "run-id" => self.run = Some(parse_run_id("run_id", value)?),
            "worker-id" => self.worker = Some(parse_worker_id("worker_id", value)?),
            "policy-hash" => self.policy_hash = Some(parse_policy_hash("policy_hash", value)?),
            "tenant-secret-key" => {
                self.tenant_secret_key = Some(parse_tenant_secret_key("tenant_secret_key", value)?)
            }
            "startup-schema-mode" => {
                self.startup_schema_mode = Some(parse_startup_schema_mode("startup_schema_mode", value)?)
            }
            _ => {
                return Err(WorkerConfigError::Usage(format!(
                    "unknown flag '--{name}'\n{}",
                    usage(),
                )));
            }
        }
        Ok(())
    }

    fn resolve(self) -> Result<ResolvedWorkerConfig, WorkerConfigError> {
        let execution_mode = self.execution_mode.unwrap_or(ExecutionMode::Connector);
        let backend = self
            .backend
            .or_else(|| default_backend_for_mode(execution_mode));
        let budgets = ScanBudgets {
            max_items: self.max_items.unwrap_or(ScanBudgets::default().max_items),
            max_bytes: self.max_bytes.unwrap_or(ScanBudgets::default().max_bytes),
        };
        let source = self.source.unwrap_or(WorkerSource::Fs);
        let path = self.path.unwrap_or_else(|| PathBuf::from("."));
        let rules_file = self.rules_file;
        let decode_depth = self.decode_depth;
        let scan_binary = self.scan_binary.unwrap_or(false);
        let skip_archives = self.skip_archives.unwrap_or(false);
        let anchor_mode = self.anchor_mode.unwrap_or(AnchorMode::Manual);

        match execution_mode {
            ExecutionMode::Direct => {
                if matches!(backend, Some(BackendSelection::Production)) {
                    return Err(WorkerConfigError::UnsupportedCombination {
                        message:
                            "backend=production requires connector mode; direct mode cannot use real distributed backends"
                                .to_owned(),
                    });
                }
                Ok(ResolvedWorkerConfig::Local(LocalWorkerConfig::new(
                    build_local_source_settings(
                        source,
                        path,
                        rules_file,
                        decode_depth,
                        scan_binary,
                        skip_archives,
                        anchor_mode,
                    ),
                    budgets,
                )))
            }
            ExecutionMode::Connector => {
                if source != WorkerSource::Fs {
                    return Err(WorkerConfigError::UnsupportedCombination {
                        message:
                            "connector mode currently supports only source=fs in MVP-A; git connector mode is not available until Epic 3 (use --mode=direct for local git scans)"
                                .to_owned(),
                    });
                }

                let backend = backend.unwrap_or(BackendSelection::Production);
                if backend != BackendSelection::Production {
                    return Err(WorkerConfigError::UnsupportedCombination {
                        message:
                            "connector mode runs the distributed worker loop against the real production backends; switch to --mode=direct for local scans"
                                .to_owned(),
                    });
                }

                let etcd_endpoints = required_string(
                    self.etcd_endpoints_csv,
                    "etcd_endpoints",
                    "--etcd-endpoints",
                    ENV_ETCD_ENDPOINTS,
                )?;
                let etcd_namespace = required_string(
                    self.etcd_namespace,
                    "etcd_namespace",
                    "--etcd-namespace",
                    ENV_ETCD_NAMESPACE,
                )?;
                let done_ledger_postgres_dsn = required_string(
                    self.done_ledger_postgres_dsn,
                    "done_ledger_postgres_dsn",
                    "--done-ledger-postgres-dsn",
                    ENV_DONE_LEDGER_POSTGRES_DSN,
                )?;
                let findings_postgres_dsn = required_string(
                    self.findings_postgres_dsn,
                    "findings_postgres_dsn",
                    "--findings-postgres-dsn",
                    ENV_FINDINGS_POSTGRES_DSN,
                )?;

                let etcd =
                    EtcdCoordinatorConfig::from_endpoints_csv(&etcd_endpoints, etcd_namespace)?;
                let backends = ProductionBackendConfig::new(
                    etcd,
                    done_ledger_postgres_dsn,
                    findings_postgres_dsn,
                )?;
                let startup = ProductionStartupSettings::new(
                    self.startup_schema_mode.unwrap_or(StartupSchemaMode::Validate),
                );
                let source = FsSourceSettings::new(path)
                    .with_rules_file(rules_file)
                    .with_decode_depth(decode_depth)
                    .with_scan_binary(scan_binary)
                    .with_skip_archives(skip_archives)
                    .with_anchor_mode(anchor_mode);
                let runtime = DistributedWorkerRuntimeSettings::new(
                    budgets,
                    self.commit_queue_capacity
                        .unwrap_or(DistributedRuntimeConfig::default().commit_queue_capacity),
                );
                let cfg = DistributedWorkerConfig::new(
                    BackendSelection::Production,
                    backends,
                    required_typed(
                        self.tenant,
                        "tenant_id",
                        "--tenant-id",
                        ENV_TENANT_ID,
                    )?,
                    required_typed(self.run, "run_id", "--run-id", ENV_RUN_ID)?,
                    required_typed(
                        self.worker,
                        "worker_id",
                        "--worker-id",
                        ENV_WORKER_ID,
                    )?,
                    required_typed(
                        self.policy_hash,
                        "policy_hash",
                        "--policy-hash",
                        ENV_POLICY_HASH,
                    )?,
                    required_typed(
                        self.tenant_secret_key,
                        "tenant_secret_key",
                        "--tenant-secret-key",
                        ENV_TENANT_SECRET_KEY,
                    )?,
                    startup,
                    source,
                    runtime,
                )?;
                Ok(ResolvedWorkerConfig::Distributed(cfg))
            }
        }
    }
}

fn default_backend_for_mode(execution_mode: ExecutionMode) -> Option<BackendSelection> {
    match execution_mode {
        ExecutionMode::Direct => None,
        ExecutionMode::Connector => Some(BackendSelection::Production),
    }
}

fn parse_optional_startup_schema_mode(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<StartupSchemaMode>, WorkerConfigError> {
    value
        .map(|value| parse_startup_schema_mode(field, &value))
        .transpose()
}

fn parse_startup_schema_mode(
    field: &'static str,
    value: &str,
) -> Result<StartupSchemaMode, WorkerConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "validate" => Ok(StartupSchemaMode::Validate),
        "dev-auto-migrate" | "auto-migrate" => Ok(StartupSchemaMode::DevAutoMigrate),
        _ => Err(WorkerConfigError::invalid_value(
            field,
            value,
            "expected 'validate' or 'dev-auto-migrate'",
        )),
    }
}

/// Resolve the current process environment plus CLI args into one typed launch
/// configuration.
pub fn resolve_worker_config_from_env_and_args<I, S>(args: I) -> Result<ResolvedWorkerConfig, WorkerConfigError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let env = ProcessEnv;
    resolve_worker_config_from(args, &env)
}

fn resolve_worker_config_from<I, S, E>(args: I, env: &E) -> Result<ResolvedWorkerConfig, WorkerConfigError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    E: EnvProvider,
{
    let mut raw = RawWorkerConfig::from_env(env)?;
    raw.apply_cli_args(args)?;
    raw.resolve()
}

fn usage() -> &'static str {
    "usage: gossip-worker [--mode=direct|connector] [--backend=local|production] \
     [--tenant-id=HEX32] [--run-id=U64] [--worker-id=U64] [--policy-hash=HEX32] \
     [--tenant-secret-key=HEX32] [--startup-schema-mode=validate|dev-auto-migrate] \
     [--etcd-endpoints=CSV] [--etcd-namespace=PREFIX] \
     [--done-ledger-postgres-dsn=DSN] [--findings-postgres-dsn=DSN] \
     [--rules-file=PATH] [--decode-depth=N] [--scan-binary=true|false] \
     [--skip-archives=true|false] [--anchor-mode=manual|derived] \
     [--max-items=N] [--max-bytes=N] [--commit-queue-capacity=N] \
     [fs|git] [path]\n\
     defaults: --mode=connector --backend=production --startup-schema-mode=validate fs .\n\
     note: connector mode is the default production path and currently supports only fs; use --mode=direct for explicit local fs/git scans"
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

fn required_string(
    value: Option<String>,
    field: &'static str,
    flag: &'static str,
    env: &'static str,
) -> Result<String, WorkerConfigError> {
    value.ok_or(WorkerConfigError::MissingRequiredValue { field, flag, env })
}

fn required_typed<T: Copy>(
    value: Option<T>,
    field: &'static str,
    flag: &'static str,
    env: &'static str,
) -> Result<T, WorkerConfigError> {
    value.ok_or(WorkerConfigError::MissingRequiredValue { field, flag, env })
}

fn parse_optional_mode(value: Option<String>, field: &'static str) -> Result<Option<ExecutionMode>, WorkerConfigError> {
    value.map(|raw| parse_mode(field, &raw)).transpose()
}

fn parse_mode(field: &'static str, raw: &str) -> Result<ExecutionMode, WorkerConfigError> {
    raw.parse::<ExecutionMode>()
        .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))
}

fn parse_optional_backend(value: Option<String>, field: &'static str) -> Result<Option<BackendSelection>, WorkerConfigError> {
    value.map(|raw| parse_backend(field, &raw)).transpose()
}

fn parse_backend(field: &'static str, raw: &str) -> Result<BackendSelection, WorkerConfigError> {
    raw.parse::<BackendSelection>().map_err(|error| match error {
        WorkerConfigError::InvalidValue { reason, .. } => {
            WorkerConfigError::invalid_value(field, raw, reason)
        }
        other => other,
    })
}

fn parse_optional_source(value: Option<String>, field: &'static str) -> Result<Option<WorkerSource>, WorkerConfigError> {
    value.map(|raw| parse_source(field, &raw)).transpose()
}

fn parse_source(field: &'static str, raw: &str) -> Result<WorkerSource, WorkerConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "fs" => Ok(WorkerSource::Fs),
        "git" => Ok(WorkerSource::Git),
        _ => Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "expected 'fs' or 'git'",
        )),
    }
}

fn parse_optional_path(value: Option<String>, field: &'static str) -> Result<Option<PathBuf>, WorkerConfigError> {
    value.map(|raw| parse_path(field, &raw)).transpose()
}

fn parse_path(field: &'static str, raw: &str) -> Result<PathBuf, WorkerConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WorkerConfigError::invalid_value(field, raw, "must not be empty"));
    }
    Ok(PathBuf::from(trimmed))
}

fn parse_optional_nonempty_string(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, WorkerConfigError> {
    value.map(|raw| parse_nonempty_string(field, &raw)).transpose()
}

fn parse_nonempty_string(field: &'static str, raw: &str) -> Result<String, WorkerConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WorkerConfigError::invalid_value(field, raw, "must not be empty"));
    }
    Ok(trimmed.to_owned())
}

fn parse_optional_bool(value: Option<String>, field: &'static str) -> Result<Option<bool>, WorkerConfigError> {
    value.map(|raw| parse_bool(field, &raw)).transpose()
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

fn parse_optional_anchor_mode(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<AnchorMode>, WorkerConfigError> {
    value.map(|raw| parse_anchor_mode(field, &raw)).transpose()
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

fn parse_optional_usize(value: Option<String>, field: &'static str) -> Result<Option<usize>, WorkerConfigError> {
    value.map(|raw| parse_usize(field, &raw)).transpose()
}

fn parse_usize(field: &'static str, raw: &str) -> Result<usize, WorkerConfigError> {
    raw.trim()
        .parse::<usize>()
        .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))
}

fn parse_optional_positive_usize(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<usize>, WorkerConfigError> {
    value.map(|raw| parse_positive_usize(field, &raw)).transpose()
}

fn parse_positive_usize(field: &'static str, raw: &str) -> Result<usize, WorkerConfigError> {
    let value = parse_usize(field, raw)?;
    if value == 0 {
        return Err(WorkerConfigError::invalid_value(field, raw, "must be > 0"));
    }
    Ok(value)
}

fn parse_optional_positive_u64(value: Option<String>, field: &'static str) -> Result<Option<u64>, WorkerConfigError> {
    value.map(|raw| parse_positive_u64(field, &raw)).transpose()
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

fn parse_optional_nonzero_usize(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<NonZeroUsize>, WorkerConfigError> {
    value.map(|raw| parse_nonzero_usize(field, &raw)).transpose()
}

fn parse_nonzero_usize(field: &'static str, raw: &str) -> Result<NonZeroUsize, WorkerConfigError> {
    let value = parse_positive_usize(field, raw)?;
    NonZeroUsize::new(value).ok_or_else(|| WorkerConfigError::invalid_value(field, raw, "must be > 0"))
}

fn parse_optional_tenant_id(value: Option<String>, field: &'static str) -> Result<Option<TenantId>, WorkerConfigError> {
    value.map(|raw| parse_tenant_id(field, &raw)).transpose()
}

fn parse_tenant_id(field: &'static str, raw: &str) -> Result<TenantId, WorkerConfigError> {
    Ok(TenantId::from_bytes(parse_hex_32(field, raw)?))
}

fn parse_optional_policy_hash(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<PolicyHash>, WorkerConfigError> {
    value.map(|raw| parse_policy_hash(field, &raw)).transpose()
}

fn parse_policy_hash(field: &'static str, raw: &str) -> Result<PolicyHash, WorkerConfigError> {
    Ok(PolicyHash::from_bytes(parse_hex_32(field, raw)?))
}

fn parse_optional_tenant_secret_key(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<TenantSecretKey>, WorkerConfigError> {
    value.map(|raw| parse_tenant_secret_key(field, &raw)).transpose()
}

fn parse_tenant_secret_key(
    field: &'static str,
    raw: &str,
) -> Result<TenantSecretKey, WorkerConfigError> {
    let secret = TenantSecretKey::from_bytes(parse_hex_32_redacted(field, raw)?);
    if !secret.is_valid() {
        return Err(WorkerConfigError::invalid_redacted_value(
            field,
            "must not be all zeros",
        ));
    }
    Ok(secret)
}

fn parse_optional_run_id(value: Option<String>, field: &'static str) -> Result<Option<RunId>, WorkerConfigError> {
    value.map(|raw| parse_run_id(field, &raw)).transpose()
}

fn parse_run_id(field: &'static str, raw: &str) -> Result<RunId, WorkerConfigError> {
    Ok(RunId::from_raw(
        raw.trim()
            .parse::<u64>()
            .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))?,
    ))
}

fn parse_optional_worker_id(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<WorkerId>, WorkerConfigError> {
    value.map(|raw| parse_worker_id(field, &raw)).transpose()
}

fn parse_worker_id(field: &'static str, raw: &str) -> Result<WorkerId, WorkerConfigError> {
    Ok(WorkerId::from_raw(
        raw.trim()
            .parse::<u64>()
            .map_err(|error| WorkerConfigError::invalid_value(field, raw, error.to_string()))?,
    ))
}

fn parse_hex_32(field: &'static str, raw: &str) -> Result<[u8; 32], WorkerConfigError> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 64 {
        return Err(WorkerConfigError::invalid_value(
            field,
            raw,
            "expected exactly 64 hex characters",
        ));
    }

    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for index in 0..32 {
        let hi = decode_hex_nibble(bytes[index * 2]).ok_or_else(|| {
            WorkerConfigError::invalid_value(field, raw, "contains a non-hex character")
        })?;
        let lo = decode_hex_nibble(bytes[index * 2 + 1]).ok_or_else(|| {
            WorkerConfigError::invalid_value(field, raw, "contains a non-hex character")
        })?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_hex_32_redacted(field: &'static str, raw: &str) -> Result<[u8; 32], WorkerConfigError> {
    let trimmed = raw.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 64 {
        return Err(WorkerConfigError::invalid_redacted_value(
            field,
            "expected exactly 64 hex characters",
        ));
    }

    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for index in 0..32 {
        let hi = decode_hex_nibble(bytes[index * 2]).ok_or_else(|| {
            WorkerConfigError::invalid_redacted_value(field, "contains a non-hex character")
        })?;
        let lo = decode_hex_nibble(bytes[index * 2 + 1]).ok_or_else(|| {
            WorkerConfigError::invalid_redacted_value(field, "contains a non-hex character")
        })?;
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

    use gossip_scanner_runtime::OwnedCoreEvent;
    use tracing::Level;

    use crate::recorder::test_support::capture_logs;

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
            .with(ENV_ETCD_ENDPOINTS, "http://127.0.0.1:2379,http://127.0.0.1:22379")
            .with(ENV_ETCD_NAMESPACE, "/gossip/v1")
            .with(ENV_DONE_LEDGER_POSTGRES_DSN, "postgresql://scanner:super-secret@db.example.internal:5432/done")
            .with(ENV_FINDINGS_POSTGRES_DSN, "host=db.example.internal user=scanner password=ultra-secret dbname=findings")
            .with(ENV_TENANT_ID, "1111111111111111111111111111111111111111111111111111111111111111")
            .with(ENV_RUN_ID, "42")
            .with(ENV_WORKER_ID, "7")
            .with(ENV_POLICY_HASH, "2222222222222222222222222222222222222222222222222222222222222222")
            .with(ENV_TENANT_SECRET_KEY, "3333333333333333333333333333333333333333333333333333333333333333")
            .with(ENV_WORKER_PATH, "/srv/scans/root")
            .with(ENV_WORKER_SCAN_BINARY, "true")
            .with(ENV_FS_SKIP_ARCHIVES, "false")
            .with(ENV_WORKER_ANCHOR_MODE, "derived")
            .with(ENV_MAX_ITEMS, "1024")
            .with(ENV_MAX_BYTES, "2097152")
            .with(ENV_COMMIT_QUEUE_CAPACITY, "128")
    }

    fn secret_canary() -> String {
        ["TEST_", "WORKER_", "RECORDER_", "CANARY_", "a91c"].concat()
    }

    #[test]
    fn worker_identity_uses_production_recorder_by_default() {
        let cfg = DistributedWorkerConfig::new(
            BackendSelection::Production,
            ProductionBackendConfig::new(
                EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/v1")
                    .expect("hard-coded etcd config should be valid"),
                "postgresql://scanner:super-secret@db.example.internal:5432/done",
                "host=db.example.internal user=scanner password=ultra-secret dbname=findings",
            )
            .expect("backend config should be valid"),
            TenantId::from_bytes([0x11; 32]),
            RunId::from_raw(42),
            WorkerId::from_raw(7),
            PolicyHash::from_bytes([0x22; 32]),
            TenantSecretKey::from_bytes([0x33; 32]),
            ProductionStartupSettings::validate_only(),
            FsSourceSettings::new(PathBuf::from("/srv/scans/root")).with_scan_binary(true),
            DistributedWorkerRuntimeSettings::default(),
        )
        .expect("distributed worker config should be valid");

        let identity = cfg.worker_identity();
        let canary = secret_canary();
        let logs = capture_logs(Level::TRACE, || {
            identity
                .recorder
                .record_core_event(
                    &format!("worker-shard-{canary}"),
                    OwnedCoreEvent::Diagnostic {
                        level: "warn",
                        message: canary.clone(),
                    },
                )
                .expect("production recorder should be best-effort");
        });

        assert!(logs.contains("coordination_core_diagnostic"));
        assert!(logs.contains("hash="));
        assert!(!logs.contains(&canary));
    }

    #[test]
    fn production_config_resolves_from_env_only() {
        let env = production_env();
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("production env should resolve");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.backend(), BackendSelection::Production);
                assert_eq!(cfg.run(), RunId::from_raw(42));
                assert_eq!(cfg.worker(), WorkerId::from_raw(7));
                assert_eq!(cfg.runtime().budgets().max_items, 1024);
                assert_eq!(cfg.runtime().budgets().max_bytes, 2_097_152);
                assert_eq!(cfg.runtime().commit_queue_capacity().get(), 128);
                assert_eq!(cfg.source().path(), Path::new("/srv/scans/root"));
                assert!(cfg.source().scan_binary());
                assert_eq!(cfg.source().anchor_mode(), AnchorMode::Derived);
                assert_eq!(cfg.startup().schema_mode(), StartupSchemaMode::Validate);
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn connector_mode_defaults_backend_to_production() {
        let env = production_env();
        let resolved =
            resolve_worker_config_from(["--mode=connector", "fs", "/srv/scans/root"], &env)
                .expect("connector mode should default to the production backend");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.backend(), BackendSelection::Production);
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn cli_overrides_env_for_run_id_and_path() {
        let env = production_env();
        let resolved = resolve_worker_config_from(
            ["--run-id=99", "fs", "/tmp/cli-root"],
            &env,
        )
        .expect("CLI overrides should resolve");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.run(), RunId::from_raw(99));
                assert_eq!(cfg.source().path(), Path::new("/tmp/cli-root"));
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn startup_schema_mode_cli_overrides_env() {
        let env = production_env().with(ENV_STARTUP_SCHEMA_MODE, "validate");
        let resolved = resolve_worker_config_from(
            ["--startup-schema-mode=dev-auto-migrate", "fs", "/tmp/cli-root"],
            &env,
        )
        .expect("CLI startup schema mode override should resolve");

        match resolved {
            ResolvedWorkerConfig::Distributed(cfg) => {
                assert_eq!(cfg.startup().schema_mode(), StartupSchemaMode::DevAutoMigrate);
            }
            other => panic!("expected distributed config, got {other:?}"),
        }
    }

    #[test]
    fn malformed_etcd_namespace_is_rejected_at_config_resolution() {
        let env = production_env().with(ENV_ETCD_NAMESPACE, "gossip-without-leading-slash");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("malformed etcd namespace must be rejected before startup");

        assert!(matches!(err, WorkerConfigError::InvalidEtcdConfig(_)));
    }

    #[test]
    fn default_worker_path_fails_closed_when_backend_config_is_absent() {
        let err = resolve_worker_config_from(["fs", "/tmp/project"], &TestEnv::default())
            .expect_err("default production path without real backend config must fail closed");

        assert!(
            matches!(
                err,
                WorkerConfigError::MissingRequiredValue {
                    field: "etcd_endpoints",
                    ..
                }
            ),
            "expected missing production backend config error, got {err:?}"
        );
    }

    #[test]
    fn direct_mode_defaults_to_local_without_backend() {
        let resolved = resolve_worker_config_from(["--mode=direct", "fs", "/tmp/project"], &TestEnv::default())
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
    fn production_config_debug_redacts_dsns_and_tenant_secret_key() {
        let env = production_env();
        let resolved = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect("production env should resolve");

        let ResolvedWorkerConfig::Distributed(cfg) = resolved else {
            panic!("expected distributed config");
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("super-secret"),
            "debug output must not leak done-ledger credentials"
        );
        assert!(
            !debug.contains("ultra-secret"),
            "debug output must not leak findings credentials"
        );
        assert!(
            !debug.contains("3333333333333333333333333333333333333333333333333333333333333333"),
            "debug output must not leak the tenant secret key"
        );
        assert!(
            debug.contains("[redacted]"),
            "debug output should show that secrets were redacted"
        );
    }

    #[test]
    fn production_requires_explicit_tenant_id() {
        let env = production_env();
        let mut stripped = env.vars.clone();
        stripped.remove(ENV_TENANT_ID);
        let env = TestEnv { vars: stripped };

        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("missing tenant id must be rejected");

        assert!(
            matches!(
                err,
                WorkerConfigError::MissingRequiredValue { field: "tenant_id", .. }
            ),
            "expected typed missing tenant_id error, got {err:?}"
        );
    }

    #[test]
    fn connector_mode_rejects_local_backend_for_filesystem_scans() {
        let err = resolve_worker_config_from(
            ["--backend=local", "fs", "/tmp/project"],
            &TestEnv::default(),
        )
        .expect_err("connector mode must not downgrade to a local scan path");

        assert!(
            err.to_string().contains("distributed worker loop"),
            "error should explain that connector mode is now the distributed path: {err}"
        );
        assert!(
            err.to_string().contains("--mode=direct"),
            "error should direct local users toward direct mode: {err}"
        );
    }

    #[test]
    fn connector_mode_rejects_git_source_until_epic3() {
        let env = production_env().with(ENV_WORKER_SOURCE, "git");
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("connector mode must reject git until Epic 3");

        assert!(
            err.to_string().contains("Epic 3"),
            "error should explain the current MVP-A git restriction: {err}"
        );
        assert!(
            err.to_string().contains("--mode=direct"),
            "error should point local git scans toward direct mode: {err}"
        );
    }

    #[test]
    fn production_rejects_all_zero_tenant_secret_key() {
        let env = production_env().with(
            ENV_TENANT_SECRET_KEY,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let err = resolve_worker_config_from(Vec::<String>::new(), &env)
            .expect_err("all-zero secret key must be rejected");

        assert!(
            err.to_string().contains("tenant_secret_key"),
            "error should point at the secret key field: {err}"
        );
        assert!(
            !err.to_string().contains("0000000000000000000000000000000000000000000000000000000000000000"),
            "error output must not echo secret material"
        );
    }

    #[test]
    fn invalid_backend_token_is_rejected() {
        let err = resolve_worker_config_from(["--backend=banana", "fs", "/tmp/project"], &TestEnv::default())
            .expect_err("unknown backend token must fail");
        assert!(err.to_string().contains("expected 'local' or 'production'"));
    }
}
