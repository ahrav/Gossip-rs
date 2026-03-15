//! Family-oriented scanner runtime: config parsing, path validation, and
//! placeholder execution boundaries for the connector family architecture.
//!
//! The runtime surface is expressed in terms of source families:
//!
//! - ordered content
//! - Git repository execution
//!
//! The public config surface remains available so callers can keep building
//! scan requests while the family-specific runtime loops are wired in.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub use gossip_contracts::connector::git::GitDebugLevel;
use gossip_contracts::connector::{ConnectorInputError, Cursor};
use scanner_engine::TransformId;
use scanner_git::{GitEventOutput, GitScanMode, MergeDiffMode};
use scanner_scheduler::events::{EventOutput, NullEventOutput};

pub mod cli;
pub mod commit_sink;
pub mod coordination_sink;
pub mod distributed;
pub mod event_sink;
pub mod git_repo;
pub mod ordered_content;
pub mod parity;

/// How the runtime acquires source items.
///
/// Both modes currently route through the same family boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Scan source items directly from local state.
    #[default]
    Direct,
    /// Scan through the connector/runtime family path.
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
    /// Use manually specified anchors from rule definitions.
    #[default]
    Manual,
    /// Derive anchors automatically from rule patterns.
    Derived,
}

/// CLI-selectable event output format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventFormat {
    /// Newline-delimited JSON (one object per line).
    #[default]
    Jsonl,
    /// Human-readable plain text.
    Text,
    /// Streaming JSON array.
    Json,
    /// SARIF 2.1.0 document.
    Sarif,
}

/// Controls which transform decoders are enabled in the runtime engine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TransformFilter {
    /// Enable all built-in transform decoders.
    #[default]
    All,
    /// Disable all transform decoders.
    None,
    /// Enable only the specified transform decoders.
    Only(Vec<TransformId>),
}

/// Cooperative cancellation token for runtime entry points.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a new token in the non-cancelled state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cooperative cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns true when cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Runtime budgets for source scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanBudgets {
    /// Maximum items processed between checkpoints.
    pub max_items: usize,
    /// Runtime-level byte budget knob.
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
    pub(crate) fn validate(self) -> Result<(), ScanRuntimeError> {
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
        Ok(())
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
    /// Execution mode selector.
    pub execution_mode: ExecutionMode,
    /// Scan execution budget controls.
    pub budgets: ScanBudgets,
}

impl FsScanConfig {
    /// Creates a filesystem scan config for `path` with default settings.
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

    /// Sets the number of worker threads. Clamped to a minimum of 1.
    #[must_use]
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    /// Sets the maximum transform decode depth.
    #[must_use]
    pub fn with_decode_depth(mut self, decode_depth: Option<usize>) -> Self {
        self.decode_depth = decode_depth;
        self
    }

    /// Enables or disables archive expansion during scanning.
    #[must_use]
    pub fn with_skip_archives(mut self, skip_archives: bool) -> Self {
        self.skip_archives = skip_archives;
        self
    }

    /// Enables or disables scanning of binary files.
    #[must_use]
    pub fn with_scan_binary(mut self, scan_binary: bool) -> Self {
        self.scan_binary = scan_binary;
        self
    }

    /// Enables or disables finding persistence via the commit sink bridge.
    #[must_use]
    pub fn with_persist_findings(mut self, persist_findings: bool) -> Self {
        self.persist_findings = persist_findings;
        self
    }

    /// Sets the anchor extraction policy for rule matching.
    #[must_use]
    pub fn with_anchor_mode(mut self, anchor_mode: AnchorMode) -> Self {
        self.anchor_mode = anchor_mode;
        self
    }

    /// Sets an external rules file path.
    #[must_use]
    pub fn with_rules_file(mut self, rules_file: Option<PathBuf>) -> Self {
        self.rules_file = rules_file;
        self
    }

    /// Sets the transform decoder filter.
    #[must_use]
    pub fn with_transform_filter(mut self, transform_filter: TransformFilter) -> Self {
        self.transform_filter = transform_filter;
        self
    }

    /// Sets the execution mode.
    #[must_use]
    pub fn with_execution_mode(mut self, execution_mode: ExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    /// Sets the scan execution budgets.
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
    /// Git scan mode.
    pub scan_mode: GitScanMode,
    /// Merge-diff strategy for merge commits.
    pub merge_mode: MergeDiffMode,
    /// Optional tree delta cache size override in MiB.
    pub tree_delta_cache_mb: Option<u32>,
    /// Optional engine chunk size override in MiB.
    pub engine_chunk_mb: Option<u32>,
    /// Execution mode selector.
    pub execution_mode: ExecutionMode,
    /// Scan execution budget controls.
    pub budgets: ScanBudgets,
}

impl GitScanConfig {
    /// Creates a git scan config for `repo` with default settings.
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

    /// Sets the number of pack-exec worker threads. Clamped to a minimum of 1.
    #[must_use]
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    /// Sets the maximum transform decode depth.
    #[must_use]
    pub fn with_decode_depth(mut self, decode_depth: Option<usize>) -> Self {
        self.decode_depth = decode_depth;
        self
    }

    /// Enables or disables scanning of binary blobs.
    #[must_use]
    pub fn with_scan_binary(mut self, scan_binary: bool) -> Self {
        self.scan_binary = scan_binary;
        self
    }

    /// Sets the git debug output level.
    #[must_use]
    pub fn with_debug_level(mut self, debug_level: GitDebugLevel) -> Self {
        self.debug_level = debug_level;
        self
    }

    /// Enables or disables commit metadata enrichment.
    #[must_use]
    pub fn with_enrich_identities(mut self, enrich_identities: bool) -> Self {
        self.enrich_identities = enrich_identities;
        self
    }

    /// Sets the anchor extraction policy for rule matching.
    #[must_use]
    pub fn with_anchor_mode(mut self, anchor_mode: AnchorMode) -> Self {
        self.anchor_mode = anchor_mode;
        self
    }

    /// Sets an external rules file path.
    #[must_use]
    pub fn with_rules_file(mut self, rules_file: Option<PathBuf>) -> Self {
        self.rules_file = rules_file;
        self
    }

    /// Sets the transform decoder filter.
    #[must_use]
    pub fn with_transform_filter(mut self, transform_filter: TransformFilter) -> Self {
        self.transform_filter = transform_filter;
        self
    }

    /// Sets the stable repository identifier used in persistence keys.
    #[must_use]
    pub fn with_repo_id(mut self, repo_id: u64) -> Self {
        self.repo_id = repo_id;
        self
    }

    /// Sets the git scan strategy.
    #[must_use]
    pub fn with_scan_mode(mut self, scan_mode: GitScanMode) -> Self {
        self.scan_mode = scan_mode;
        self
    }

    /// Sets the merge-diff strategy for merge commits.
    #[must_use]
    pub fn with_merge_mode(mut self, merge_mode: MergeDiffMode) -> Self {
        self.merge_mode = merge_mode;
        self
    }

    /// Sets the tree delta cache size in MiB.
    #[must_use]
    pub fn with_tree_delta_cache_mb(mut self, tree_delta_cache_mb: Option<u32>) -> Self {
        self.tree_delta_cache_mb = tree_delta_cache_mb;
        self
    }

    /// Sets the engine chunk size in MiB.
    #[must_use]
    pub fn with_engine_chunk_mb(mut self, engine_chunk_mb: Option<u32>) -> Self {
        self.engine_chunk_mb = engine_chunk_mb;
        self
    }

    /// Sets the execution mode.
    #[must_use]
    pub fn with_execution_mode(mut self, execution_mode: ExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    /// Sets the scan execution budgets.
    #[must_use]
    pub fn with_budgets(mut self, budgets: ScanBudgets) -> Self {
        self.budgets = budgets;
        self
    }
}

/// Aggregate counters returned by one runtime execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Total items (files / blobs) processed.
    pub items_scanned: u64,
    /// Total payload bytes scanned.
    pub bytes_scanned: u64,
    /// Total chunk windows scanned across all items.
    pub chunks_scanned: u64,
    /// Findings emitted to the event stream.
    pub findings_emitted: u64,
    /// Non-fatal errors encountered during scanning.
    pub errors: u64,
    /// Items skipped because they were classified as binary by content probe.
    pub binary_skipped: u64,
    /// Items skipped pre-open because extension matched the binary skip table.
    pub ext_skipped: u64,
    /// Items skipped pre-open because filename matched the lock-file table.
    pub lock_skipped: u64,
    /// Items scanned via extracted text from known binary container formats.
    pub binary_extracted: u64,
    /// Findings dropped by engine caps during scan.
    pub dropped_findings: u64,
    /// Persistence batch emission failures observed by the runtime.
    pub persist_emit_failures: u64,
    /// Whether persistence loss counters indicate an incomplete run.
    pub persist_incomplete: bool,
    /// Aggregate scan-loop time in nanoseconds.
    pub scan_ns: u64,
    /// Aggregate persistence emission time in nanoseconds.
    pub persist_ns: u64,
}

/// Incremental progress checkpoint produced by the runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanCheckpoint {
    /// Cursor pointing just past the last fully committed item.
    pub cursor: Cursor,
    /// Running count of items committed up to this cursor position.
    pub committed_items: u64,
}

/// Runtime wiring errors for scan execution.
#[derive(Debug)]
pub enum ScanRuntimeError {
    /// A scan target path failed validation.
    InvalidPath {
        /// Which subsystem originated the path.
        source: &'static str,
        /// The path that failed validation.
        path: PathBuf,
        /// Human-readable reason for the failure.
        message: String,
    },
    /// A `git` subprocess exited with a non-zero status.
    GitCommandFailed {
        /// Repository path the command was invoked against.
        repo: PathBuf,
        /// Process exit code, if available.
        status_code: Option<i32>,
        /// Captured stderr output from the git process.
        stderr: String,
    },
    /// An I/O operation failed during runtime setup.
    Io {
        /// Short description of the operation.
        op: &'static str,
        /// Associated file path, when applicable.
        path: Option<PathBuf>,
        /// Underlying I/O error.
        error: std::io::Error,
    },
    /// The external rules configuration file could not be loaded or parsed.
    RulesConfig {
        /// Path to the rules file, if one was specified.
        path: Option<PathBuf>,
        /// Human-readable parse or load error.
        message: String,
    },
    /// A connector input parameter was invalid.
    ConnectorInput(ConnectorInputError),
    /// The family runtime returned an execution error.
    Driver(anyhow::Error),
}

impl fmt::Display for ScanRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath {
                source,
                path,
                message,
            } => write!(f, "{source} path '{}' invalid: {message}", path.display()),
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
            Self::Driver(error) => write!(f, "runtime execution failed: {error}"),
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

/// Execution outcome for one runtime invocation.
#[derive(Clone, Debug)]
pub struct AssignmentOutcome {
    /// Aggregate counters for the invocation.
    pub report: ScanReport,
    /// Optional checkpoint hint for distributed coordinators.
    pub checkpoint_hint: Option<ScanCheckpoint>,
    /// Optional debug diagnostics for stderr output.
    pub debug_output: Option<String>,
}

/// Top-level filesystem scan dispatcher.
pub fn scan_fs(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_fs_direct(config),
        ExecutionMode::Connector => scan_fs_connector(config),
    }
}

/// Top-level git scan dispatcher.
pub fn scan_git(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_git_direct(config),
        ExecutionMode::Connector => scan_git_connector(config),
    }
}

/// Filesystem scan routed through the ordered-content runtime boundary.
pub fn scan_fs_direct(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let out = NullEventOutput;
    let commit = commit_sink::CliNoOpCommitSink;
    let cancel = CancellationToken::new();
    scan_fs_with_runtime(config, &out, &commit, &cancel).map(|outcome| outcome.report)
}

/// Connector-mode filesystem scan.
pub fn scan_fs_connector(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    scan_fs_direct(config)
}

/// Git scan routed through the Git-family runtime boundary.
pub fn scan_git_direct(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let out = scanner_git::NullEventSink;
    let cancel = CancellationToken::new();
    scan_git_with_runtime(config, &out, &cancel).map(|outcome| outcome.report)
}

/// Connector-mode git scan.
pub fn scan_git_connector(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    scan_git_direct(config)
}

/// Internal filesystem entrypoint that accepts caller-provided sinks.
pub(crate) fn scan_fs_with_runtime(
    config: &FsScanConfig,
    _out: &dyn EventOutput,
    _commit: &dyn commit_sink::CommitSink,
    _cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    let canonical_path = validate_fs_path(&config.path)?;
    config.budgets.validate()?;
    ordered_content::filesystem_placeholder(config, canonical_path).map(|report| {
        AssignmentOutcome {
            report,
            checkpoint_hint: None,
            debug_output: None,
        }
    })
}

/// Internal git entrypoint that accepts caller-provided sinks.
pub(crate) fn scan_git_with_runtime(
    config: &GitScanConfig,
    _out: &dyn GitEventOutput,
    _cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    let canonical_repo = validate_git_repo_path(&config.repo)?;
    config.budgets.validate()?;
    git_repo::local_repo_placeholder(config, canonical_repo).map(|report| AssignmentOutcome {
        report,
        checkpoint_hint: None,
        debug_output: None,
    })
}

/// Query available hardware parallelism, falling back to 1 on failure.
pub(crate) fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn validate_fs_path(path: &Path) -> Result<PathBuf, ScanRuntimeError> {
    if !path.exists() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "filesystem",
            path: path.to_path_buf(),
            message: "path does not exist".to_owned(),
        });
    }
    if !path.is_file() && !path.is_dir() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "filesystem",
            path: path.to_path_buf(),
            message: "path must be a regular file or directory".to_owned(),
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
            message: "path does not exist".to_owned(),
        });
    }
    if !path.is_dir() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "git",
            path: path.to_path_buf(),
            message: "path must be a directory".to_owned(),
        });
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .map_err(|error| ScanRuntimeError::Io {
            op: "spawn git rev-parse",
            path: Some(path.to_path_buf()),
            error,
        })?;

    if !output.status.success() {
        return Err(ScanRuntimeError::GitCommandFailed {
            repo: path.to_path_buf(),
            status_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    let toplevel = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let canonical_input = fs::canonicalize(path).map_err(|error| ScanRuntimeError::Io {
        op: "canonicalize",
        path: Some(path.to_path_buf()),
        error,
    })?;
    let canonical_toplevel = fs::canonicalize(&toplevel).map_err(|error| ScanRuntimeError::Io {
        op: "canonicalize",
        path: Some(PathBuf::from(&toplevel)),
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

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
