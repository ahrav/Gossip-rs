//! Unified scanner runtime entrypoints backed by `ScanDriver`.
//!
//! Both CLI and distributed execution paths route through the same
//! assignment-to-driver seam:
//!
//! ```text
//! config -> Assignment -> ScanSourceFactory -> ScanDriver::run
//! ```
//!
//! Parity invariant: `Direct` and `Connector` modes currently execute the same
//! runtime path. The mode flag remains for CLI compatibility and telemetry.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use gossip_connectors::{FilesystemScanSourceFactory, GitScanSourceFactory};
use gossip_contracts::{
    connector::{ConnectorInputError, Cursor},
    coordination::ShardSpec,
    identity::PolicyHash,
};
use gossip_scan_driver::{
    Assignment, AssignmentSource, CancellationToken, CommitSink, ConnectorKind, CursorUpdate,
    GitDebugLevel, GitExecutionConfig, NoOpCommitSink, ScanExecutionConfig, ScanReport,
    ScanSourceFactory,
};
use scanner_engine::{AnchorPolicy, Gate, TransformConfig, TransformId, TransformMode};
use scanner_git::{GitEventOutput, GitScanMode, MergeDiffMode};
use scanner_scheduler::events::{EventOutput, NullEventOutput};

pub mod cli;
pub mod commit_sink;
pub mod coordination_sink;
pub mod distributed;
pub mod event_sink;
pub mod parity;

/// How the runtime acquires source items.
///
/// In unified execution mode this flag is retained for CLI compatibility and
/// telemetry only; both variants route through the same scan-driver path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    #[default]
    Direct,
    Connector,
}

impl std::str::FromStr for ExecutionMode {
    type Err = ParseExecutionModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct),
            "connector" => Ok(Self::Connector),
            _ => Err(ParseExecutionModeError {
                raw: value.to_owned(),
            }),
        }
    }
}

/// Error returned when parsing [`ExecutionMode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseExecutionModeError {
    raw: String,
}

impl fmt::Display for ParseExecutionModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid execution mode '{}' (expected 'direct' or 'connector')",
            self.raw
        )
    }
}

impl std::error::Error for ParseExecutionModeError {}

/// Anchor extraction mode for rule planning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnchorMode {
    #[default]
    Manual,
    Derived,
}

/// CLI-selectable event output format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventFormat {
    #[default]
    Jsonl,
    Text,
    Json,
    Sarif,
}

/// Controls which transform decoders are enabled in the runtime engine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TransformFilter {
    #[default]
    All,
    None,
    Only(Vec<TransformId>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RuntimeEngineConfig {
    anchor_mode: AnchorMode,
    decode_depth: Option<usize>,
    rules_file: Option<PathBuf>,
    transform_filter: TransformFilter,
}

/// Runtime budgets for source scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanBudgets {
    /// Maximum items processed between checkpoints.
    pub max_items: usize,
    /// Runtime-level byte budget knob (must be non-zero).
    pub max_bytes: u64,
}

impl Default for ScanBudgets {
    fn default() -> Self {
        Self {
            max_items: 256,
            max_bytes: 1_000_000,
        }
    }
}

impl ScanBudgets {
    fn to_execution_config_with_workers(
        self,
        workers: usize,
    ) -> Result<ScanExecutionConfig, ScanRuntimeError> {
        if self.max_items == 0 {
            return Err(ScanRuntimeError::ConnectorInput(
                ConnectorInputError::ZeroBudget { field: "max_items" },
            ));
        }
        if self.max_bytes == 0 {
            return Err(ScanRuntimeError::ConnectorInput(
                ConnectorInputError::ZeroBudget { field: "max_bytes" },
            ));
        }
        Ok(ScanExecutionConfig {
            workers: workers.max(1),
            checkpoint_every_items: self.max_items as u64,
            ..ScanExecutionConfig::default()
        })
    }

    pub(crate) fn to_execution_config(self) -> Result<ScanExecutionConfig, ScanRuntimeError> {
        self.to_execution_config_with_workers(available_workers())
    }
}

/// Filesystem scan config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsScanConfig {
    /// Filesystem root or file path to scan.
    pub path: PathBuf,
    /// Number of worker threads to use.
    pub workers: usize,
    /// Optional transform decode depth override.
    pub decode_depth: Option<usize>,
    /// When true, archive expansion is disabled.
    pub skip_archives: bool,
    /// When true, binary files are scanned.
    pub scan_binary: bool,
    /// When true, findings are persisted via the commit sink bridge.
    pub persist_findings: bool,
    /// Anchor extraction policy for rule matching.
    pub anchor_mode: AnchorMode,
    /// Optional external rules file path.
    pub rules_file: Option<PathBuf>,
    /// Transform decoder filter.
    pub transform_filter: TransformFilter,
    /// Retained for compatibility; both variants currently share one path.
    pub execution_mode: ExecutionMode,
    /// Scan execution budget controls.
    pub budgets: ScanBudgets,
}

impl FsScanConfig {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            workers: available_workers(),
            decode_depth: None,
            skip_archives: false,
            scan_binary: false,
            persist_findings: false,
            anchor_mode: AnchorMode::Manual,
            rules_file: None,
            transform_filter: TransformFilter::All,
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
        }
    }

    #[must_use]
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
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
    pub fn with_persist_findings(mut self, persist_findings: bool) -> Self {
        self.persist_findings = persist_findings;
        self
    }

    #[must_use]
    pub fn with_anchor_mode(mut self, anchor_mode: AnchorMode) -> Self {
        self.anchor_mode = anchor_mode;
        self
    }

    #[must_use]
    pub fn with_rules_file(mut self, rules_file: Option<PathBuf>) -> Self {
        self.rules_file = rules_file;
        self
    }

    #[must_use]
    pub fn with_transform_filter(mut self, transform_filter: TransformFilter) -> Self {
        self.transform_filter = transform_filter;
        self
    }

    #[must_use]
    pub fn with_execution_mode(mut self, execution_mode: ExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    #[must_use]
    pub fn with_budgets(mut self, budgets: ScanBudgets) -> Self {
        self.budgets = budgets;
        self
    }
}

/// Git scan config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitScanConfig {
    /// Repository root path to scan.
    pub repo: PathBuf,
    /// Number of pack-exec worker threads.
    pub workers: usize,
    /// Optional transform decode depth override.
    pub decode_depth: Option<usize>,
    /// When true, binary blobs are scanned.
    pub scan_binary: bool,
    /// Git debug output level.
    pub debug_level: GitDebugLevel,
    /// When true, enrich commit metadata with identity dictionary IDs.
    pub enrich_identities: bool,
    /// Anchor extraction policy for rule matching.
    pub anchor_mode: AnchorMode,
    /// Optional external rules file path.
    pub rules_file: Option<PathBuf>,
    /// Transform decoder filter.
    pub transform_filter: TransformFilter,
    /// Stable repository identifier used in persistence keys.
    pub repo_id: u64,
    /// Git scan mode (diff-history vs ODB-blob fast path).
    pub scan_mode: GitScanMode,
    /// Merge-diff strategy for merge commits.
    pub merge_mode: MergeDiffMode,
    /// Optional tree delta cache size override in MiB.
    pub tree_delta_cache_mb: Option<u32>,
    /// Optional engine chunk size override in MiB.
    pub engine_chunk_mb: Option<u32>,
    /// Retained for compatibility; both variants currently share one path.
    pub execution_mode: ExecutionMode,
    /// Scan execution budget controls.
    pub budgets: ScanBudgets,
}

impl GitScanConfig {
    #[must_use]
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self {
            repo: repo.into(),
            workers: available_workers(),
            decode_depth: None,
            scan_binary: false,
            debug_level: GitDebugLevel::Off,
            enrich_identities: false,
            anchor_mode: AnchorMode::Manual,
            rules_file: None,
            transform_filter: TransformFilter::All,
            repo_id: 1,
            scan_mode: GitScanMode::OdbBlobFast,
            merge_mode: MergeDiffMode::AllParents,
            tree_delta_cache_mb: None,
            engine_chunk_mb: None,
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
        }
    }

    #[must_use]
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
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
    pub fn with_debug_level(mut self, debug_level: GitDebugLevel) -> Self {
        self.debug_level = debug_level;
        self
    }

    #[must_use]
    pub fn with_enrich_identities(mut self, enrich_identities: bool) -> Self {
        self.enrich_identities = enrich_identities;
        self
    }

    #[must_use]
    pub fn with_anchor_mode(mut self, anchor_mode: AnchorMode) -> Self {
        self.anchor_mode = anchor_mode;
        self
    }

    #[must_use]
    pub fn with_rules_file(mut self, rules_file: Option<PathBuf>) -> Self {
        self.rules_file = rules_file;
        self
    }

    #[must_use]
    pub fn with_transform_filter(mut self, transform_filter: TransformFilter) -> Self {
        self.transform_filter = transform_filter;
        self
    }

    #[must_use]
    pub fn with_repo_id(mut self, repo_id: u64) -> Self {
        self.repo_id = repo_id;
        self
    }

    #[must_use]
    pub fn with_scan_mode(mut self, scan_mode: GitScanMode) -> Self {
        self.scan_mode = scan_mode;
        self
    }

    #[must_use]
    pub fn with_merge_mode(mut self, merge_mode: MergeDiffMode) -> Self {
        self.merge_mode = merge_mode;
        self
    }

    #[must_use]
    pub fn with_tree_delta_cache_mb(mut self, tree_delta_cache_mb: Option<u32>) -> Self {
        self.tree_delta_cache_mb = tree_delta_cache_mb;
        self
    }

    #[must_use]
    pub fn with_engine_chunk_mb(mut self, engine_chunk_mb: Option<u32>) -> Self {
        self.engine_chunk_mb = engine_chunk_mb;
        self
    }

    #[must_use]
    pub fn with_execution_mode(mut self, execution_mode: ExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    #[must_use]
    pub fn with_budgets(mut self, budgets: ScanBudgets) -> Self {
        self.budgets = budgets;
        self
    }
}

/// Runtime wiring errors for unified scan execution.
#[derive(Debug)]
pub enum ScanRuntimeError {
    InvalidPath {
        source: &'static str,
        path: PathBuf,
        message: String,
    },
    UnsupportedConnectorKind(ConnectorKind),
    GitCommandFailed {
        repo: PathBuf,
        status_code: Option<i32>,
        stderr: String,
    },
    Io {
        op: &'static str,
        path: Option<PathBuf>,
        error: std::io::Error,
    },
    RulesConfig {
        path: Option<PathBuf>,
        message: String,
    },
    ConnectorInput(ConnectorInputError),
    Driver(anyhow::Error),
}

impl fmt::Display for ScanRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath {
                source,
                path,
                message,
            } => {
                write!(f, "{source} path '{}' invalid: {message}", path.display())
            }
            Self::UnsupportedConnectorKind(kind) => {
                write!(f, "connector kind '{kind:?}' is not supported by runtime")
            }
            Self::GitCommandFailed {
                repo,
                status_code,
                stderr,
            } => write!(
                f,
                "git command failed for '{}' (status={status_code:?}): {stderr}",
                repo.display()
            ),
            Self::Io { op, path, error } => match path {
                Some(path) => write!(f, "{op} failed for '{}': {error}", path.display()),
                None => write!(f, "{op} failed: {error}"),
            },
            Self::RulesConfig { path, message } => match path {
                Some(path) => write!(f, "rules config error for '{}': {message}", path.display()),
                None => write!(f, "rules config error: {message}"),
            },
            Self::ConnectorInput(error) => write!(f, "{error}"),
            Self::Driver(error) => write!(f, "scan driver failed: {error}"),
        }
    }
}

impl std::error::Error for ScanRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::ConnectorInput(error) => Some(error),
            Self::Driver(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<ConnectorInputError> for ScanRuntimeError {
    fn from(value: ConnectorInputError) -> Self {
        Self::ConnectorInput(value)
    }
}

/// Execution outcome for one assignment run.
#[derive(Clone, Debug)]
pub struct AssignmentOutcome {
    /// Scan-driver report for the assignment.
    pub report: ScanReport,
    /// Driver-provided checkpoint hint to hand back to coordinators.
    pub checkpoint_hint: Option<CursorUpdate>,
    /// Optional driver-generated debug diagnostics (for CLI stderr output).
    pub debug_output: Option<String>,
}

/// Top-level filesystem scan dispatcher.
///
/// Both execution modes currently call the same unified scan path.
pub fn scan_fs(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_fs_direct(config),
        ExecutionMode::Connector => scan_fs_connector(config),
    }
}

/// Top-level git scan dispatcher.
///
/// Both execution modes currently call the same unified scan path.
pub fn scan_git(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_git_direct(config),
        ExecutionMode::Connector => scan_git_connector(config),
    }
}

/// Filesystem scan routed through the unified assignment/driver seam.
pub fn scan_fs_direct(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let out = NullEventOutput;
    let commit = NoOpCommitSink;
    let cancel = CancellationToken::new();
    scan_fs_with_runtime(config, &out, &commit, &cancel).map(|outcome| outcome.report)
}

/// Connector-mode filesystem scan.
///
/// Unified model note: this currently executes identically to
/// [`scan_fs_direct`], preserving one execution path.
pub fn scan_fs_connector(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    scan_fs_direct(config)
}

/// Git scan routed through the unified assignment/driver seam.
pub fn scan_git_direct(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let out = NullEventOutput;
    let commit = NoOpCommitSink;
    let cancel = CancellationToken::new();
    scan_git_with_runtime(config, &out, None, &commit, &cancel).map(|outcome| outcome.report)
}

/// Connector-mode git scan.
///
/// Unified model note: this currently executes identically to
/// [`scan_git_direct`], preserving one execution path.
pub fn scan_git_connector(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    scan_git_direct(config)
}

pub(crate) fn scan_fs_with_runtime(
    config: &FsScanConfig,
    out: &dyn EventOutput,
    commit: &dyn CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    let canonical_path = validate_fs_path(&config.path)?;
    let assignment = build_assignment(
        ConnectorKind::Filesystem,
        canonical_path.display().to_string(),
        AssignmentSource::Filesystem {
            root: canonical_path,
        },
    );
    let mut runtime = config
        .budgets
        .to_execution_config_with_workers(config.workers)?;
    runtime.filesystem.skip_archives = config.skip_archives;
    runtime.filesystem.skip_binary = !config.scan_binary;
    runtime.filesystem.emit_findings_to_commit_sink = config.persist_findings;
    let engine = RuntimeEngineConfig {
        anchor_mode: config.anchor_mode,
        decode_depth: config.decode_depth,
        rules_file: config.rules_file.clone(),
        transform_filter: config.transform_filter.clone(),
    };
    execute_assignment_with_config(&assignment, runtime, &engine, out, None, commit, cancel)
}

pub(crate) fn scan_git_with_runtime(
    config: &GitScanConfig,
    out: &dyn EventOutput,
    git_out: Option<&dyn GitEventOutput>,
    commit: &dyn CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    let canonical_repo = validate_git_repo_path(&config.repo)?;
    let assignment = build_assignment(
        ConnectorKind::Git,
        canonical_repo.display().to_string(),
        AssignmentSource::Git {
            repo_root: canonical_repo,
        },
    );
    let mut runtime = config
        .budgets
        .to_execution_config_with_workers(config.workers)?;
    // Keep git execution tuning centralized in the shared ScanExecutionConfig
    // so both CLI and distributed worker paths hit identical driver behavior.
    runtime.git = GitExecutionConfig {
        repo_id: config.repo_id,
        scan_mode: config.scan_mode,
        merge_diff_mode: config.merge_mode,
        pack_exec_workers: Some(config.workers),
        scan_binary: config.scan_binary,
        enrich_identities: config.enrich_identities,
        debug_level: config.debug_level,
        tree_delta_cache_mb: config.tree_delta_cache_mb,
        engine_chunk_mb: config.engine_chunk_mb,
    };
    let engine = RuntimeEngineConfig {
        anchor_mode: config.anchor_mode,
        decode_depth: config.decode_depth,
        rules_file: config.rules_file.clone(),
        transform_filter: config.transform_filter.clone(),
    };
    execute_assignment_with_config(&assignment, runtime, &engine, out, git_out, commit, cancel)
}

pub(crate) fn execute_assignment_with_config(
    assignment: &Assignment,
    config: ScanExecutionConfig,
    engine_config: &RuntimeEngineConfig,
    out: &dyn EventOutput,
    git_out: Option<&dyn GitEventOutput>,
    commit: &dyn CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    // Keep runtime entry points and distributed workers on one driver seam.
    let mut driver = driver_for_assignment(assignment)?;
    let report = driver
        .run(
            runtime_engine(engine_config)?,
            &config,
            out,
            git_out,
            commit,
            cancel,
        )
        .map_err(ScanRuntimeError::Driver)?;

    Ok(AssignmentOutcome {
        report,
        checkpoint_hint: driver.checkpoint_hint(),
        debug_output: driver.debug_output(),
    })
}

fn driver_for_assignment(
    assignment: &Assignment,
) -> Result<Box<dyn gossip_scan_driver::ScanDriver>, ScanRuntimeError> {
    let factory: &dyn ScanSourceFactory = match assignment.connector_kind {
        ConnectorKind::Filesystem => &FilesystemScanSourceFactory,
        ConnectorKind::Git => &GitScanSourceFactory,
        ConnectorKind::InMemory => {
            return Err(ScanRuntimeError::UnsupportedConnectorKind(
                assignment.connector_kind,
            ));
        }
    };

    factory
        .driver_for_assignment(assignment)
        .map_err(ScanRuntimeError::Driver)
}

pub(crate) fn build_assignment(
    connector_kind: ConnectorKind,
    connector_instance_id: String,
    source: AssignmentSource,
) -> Assignment {
    Assignment {
        job_id: format!("runtime-{connector_instance_id}"),
        connector_kind,
        connector_instance_id,
        policy_hash: PolicyHash::from_bytes([0x52; 32]),
        shard_spec: ShardSpec::with_range([], []),
        cursor: Cursor::initial(),
        source,
    }
}

fn runtime_engine(
    config: &RuntimeEngineConfig,
) -> Result<Arc<scanner_engine::Engine>, ScanRuntimeError> {
    if config == &RuntimeEngineConfig::default() {
        static ENGINE: OnceLock<Arc<scanner_engine::Engine>> = OnceLock::new();
        let engine = ENGINE.get_or_init(|| {
            Arc::new(
                build_runtime_engine(&RuntimeEngineConfig::default())
                    .expect("default runtime engine must build"),
            )
        });
        Ok(Arc::clone(engine))
    } else {
        Ok(Arc::new(build_runtime_engine(config)?))
    }
}

fn build_runtime_engine(
    config: &RuntimeEngineConfig,
) -> Result<scanner_engine::Engine, ScanRuntimeError> {
    let rules = load_runtime_rules(config.rules_file.as_deref())?;
    let mut tuning = default_runtime_tuning();
    if let Some(depth) = config.decode_depth {
        tuning.max_transform_depth = depth;
    }
    let transforms = apply_transform_filter(default_runtime_transforms(), &config.transform_filter);
    let policy = match config.anchor_mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    Ok(scanner_engine::Engine::new_with_anchor_policy(
        rules, transforms, tuning, policy,
    ))
}

/// Load scan rules using the reference scanner's 3-tier resolution:
///
/// 1. Explicit `--rules=<path>` override
/// 2. `default_rules.yaml` adjacent to the binary executable
/// 3. Compile-time embedded fallback (223 rules from `default_rules.yaml`)
///
/// Emits provenance info to stderr so operators can verify which rules are
/// active.
fn load_runtime_rules(
    rules_file: Option<&Path>,
) -> Result<Vec<scanner_engine::RuleSpec>, ScanRuntimeError> {
    // 1. Explicit override.
    if let Some(path) = rules_file {
        let content = scanner_engine::read_rules_text(path).map_err(|error| {
            ScanRuntimeError::RulesConfig {
                path: Some(path.to_path_buf()),
                message: error.to_string(),
            }
        })?;
        let rules = scanner_engine::load_rules_from_content(&content).map_err(|error| {
            ScanRuntimeError::RulesConfig {
                path: Some(path.to_path_buf()),
                message: error.to_string(),
            }
        })?;
        let hash = scanner_engine::rules_content_hash64(content.as_bytes());
        eprintln!(
            "info: using rules from {} ({} rules, rule_hash: {hash:016x})",
            path.display(),
            rules.len(),
        );
        return Ok(rules);
    }

    // 2. Default candidate adjacent to binary.
    if let Some(default_path) = scanner_engine::default_rules_path() {
        if default_path.exists() && !default_path.is_file() {
            eprintln!(
                "warn: {} exists but is not a regular file; falling back to built-in rules",
                default_path.display()
            );
        } else if default_path.is_file() {
            let content = scanner_engine::read_rules_text(&default_path).map_err(|error| {
                ScanRuntimeError::RulesConfig {
                    path: Some(default_path.clone()),
                    message: error.to_string(),
                }
            })?;
            let rules = scanner_engine::load_rules_from_content(&content).map_err(|error| {
                ScanRuntimeError::RulesConfig {
                    path: Some(default_path.clone()),
                    message: error.to_string(),
                }
            })?;
            let hash = scanner_engine::rules_content_hash64(content.as_bytes());
            eprintln!(
                "info: using {} ({} rules, source: default_rules.yaml, rule_hash: {hash:016x})",
                default_path.display(),
                rules.len(),
            );
            return Ok(rules);
        }
    }

    // 3. Compile-time embedded fallback.
    let rules = scanner_engine::builtin_rules();
    let hash = scanner_engine::builtin_rules_hash64();
    eprintln!("info: no default_rules.yaml next to binary; using compiled-in rules");
    eprintln!(
        "info: using compiled-in rule set ({} rules, source: built-in, rule_hash: {hash:016x})",
        rules.len(),
    );
    Ok(rules)
}

fn default_runtime_transforms() -> Vec<TransformConfig> {
    vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 32,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ]
}

fn default_runtime_tuning() -> scanner_engine::Tuning {
    scanner_engine::Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 16,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 2048,
        max_utf16_decoded_bytes_per_window: 64 * 1024,
        max_transform_depth: 3,
        max_total_decode_output_bytes: 512 * 1024,
        max_work_items: 256,
        max_findings_per_chunk: 8192,
        scan_utf16_variants: true,
    }
}

fn apply_transform_filter(
    transforms: Vec<TransformConfig>,
    filter: &TransformFilter,
) -> Vec<TransformConfig> {
    match filter {
        TransformFilter::All => transforms,
        TransformFilter::None => Vec::new(),
        TransformFilter::Only(ids) => transforms
            .into_iter()
            .filter(|transform| ids.contains(&transform.id))
            .collect(),
    }
}

fn validate_fs_path(path: &Path) -> Result<PathBuf, ScanRuntimeError> {
    if !path.exists() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "filesystem",
            path: path.to_path_buf(),
            message: "path does not exist".to_owned(),
        });
    }
    if !path.is_dir() && !path.is_file() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "filesystem",
            path: path.to_path_buf(),
            message: "path must be a directory or regular file".to_owned(),
        });
    }
    fs::canonicalize(path).map_err(|error| ScanRuntimeError::Io {
        op: "canonicalize",
        path: Some(path.to_path_buf()),
        error,
    })
}

fn validate_git_repo_path(path: &Path) -> Result<PathBuf, ScanRuntimeError> {
    if !path.exists() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "git",
            path: path.to_path_buf(),
            message: "repository path does not exist".to_owned(),
        });
    }
    if !path.is_dir() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "git",
            path: path.to_path_buf(),
            message: "repository path must be a directory".to_owned(),
        });
    }

    // Use --show-toplevel to resolve the actual repository root rather than
    // --is-inside-work-tree, which succeeds for arbitrary subdirectories.
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| ScanRuntimeError::Io {
            op: "git rev-parse",
            path: Some(path.to_path_buf()),
            error,
        })?;
    if !output.status.success() {
        return Err(ScanRuntimeError::GitCommandFailed {
            repo: path.to_path_buf(),
            status_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let toplevel = PathBuf::from(std::str::from_utf8(&output.stdout).unwrap_or("").trim_end());
    let canonical_input = fs::canonicalize(path).map_err(|error| ScanRuntimeError::Io {
        op: "canonicalize",
        path: Some(path.to_path_buf()),
        error,
    })?;
    let canonical_toplevel = fs::canonicalize(&toplevel).map_err(|error| ScanRuntimeError::Io {
        op: "canonicalize",
        path: Some(toplevel.clone()),
        error,
    })?;

    if canonical_input != canonical_toplevel {
        return Err(ScanRuntimeError::InvalidPath {
            source: "git",
            path: path.to_path_buf(),
            message: format!(
                "path is inside a git repository but is not the repository root (root is '{}')",
                canonical_toplevel.display()
            ),
        });
    }

    Ok(canonical_input)
}

pub(crate) fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
