//! Unified scanner runtime entrypoints backed by `ScanDriver`.
//!
//! Both CLI and distributed execution paths route through the same
//! assignment-to-driver seam:
//!
//! ```text
//! config -> Assignment -> ScanSourceFactory -> ScanDriver::run
//! ```

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
    NoOpCommitSink, ScanExecutionConfig, ScanReport, ScanSourceFactory,
};
use regex::bytes::Regex;
use scanner_scheduler::events::{EventOutput, NullEventOutput};

pub mod cli;
pub mod commit_sink;
pub mod coordination_sink;
pub mod distributed;
pub mod event_sink;

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

/// Runtime budgets for source scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanBudgets {
    pub max_items: usize,
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
    fn to_execution_config(self) -> Result<ScanExecutionConfig, ScanRuntimeError> {
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
            workers: available_workers(),
            checkpoint_every_items: self.max_items as u64,
        })
    }
}

/// Filesystem scan config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsScanConfig {
    pub path: PathBuf,
    pub execution_mode: ExecutionMode,
    pub budgets: ScanBudgets,
}

impl FsScanConfig {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
        }
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
    pub repo: PathBuf,
    pub execution_mode: ExecutionMode,
    pub budgets: ScanBudgets,
}

impl GitScanConfig {
    #[must_use]
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self {
            repo: repo.into(),
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
        }
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
    pub report: ScanReport,
    pub checkpoint_hint: Option<CursorUpdate>,
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

/// Filesystem scan routed through the unified assignment/driver seam.
pub fn scan_fs_direct(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let canonical_path = validate_fs_path(&config.path)?;
    let assignment = build_assignment(
        ConnectorKind::Filesystem,
        canonical_path.display().to_string(),
        AssignmentSource::Filesystem {
            root: canonical_path,
        },
    );

    let out = NullEventOutput;
    let commit = NoOpCommitSink;
    let cancel = CancellationToken::new();
    execute_assignment(&assignment, config.budgets, &out, &commit, &cancel)
        .map(|outcome| outcome.report)
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
    let canonical_repo = validate_git_repo_path(&config.repo)?;
    let assignment = build_assignment(
        ConnectorKind::Git,
        canonical_repo.display().to_string(),
        AssignmentSource::Git {
            repo_root: canonical_repo,
        },
    );

    let out = NullEventOutput;
    let commit = NoOpCommitSink;
    let cancel = CancellationToken::new();
    execute_assignment(&assignment, config.budgets, &out, &commit, &cancel)
        .map(|outcome| outcome.report)
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
    execute_assignment(&assignment, config.budgets, out, commit, cancel)
}

pub(crate) fn scan_git_with_runtime(
    config: &GitScanConfig,
    out: &dyn EventOutput,
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
    execute_assignment(&assignment, config.budgets, out, commit, cancel)
}

pub(crate) fn execute_assignment(
    assignment: &Assignment,
    budgets: ScanBudgets,
    out: &dyn EventOutput,
    commit: &dyn CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    let mut driver = driver_for_assignment(assignment)?;
    let cfg = budgets.to_execution_config()?;
    let report = driver
        .run(runtime_engine(), &cfg, out, commit, cancel)
        .map_err(ScanRuntimeError::Driver)?;

    Ok(AssignmentOutcome {
        report,
        checkpoint_hint: driver.checkpoint_hint(),
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

pub(crate) fn runtime_engine() -> Arc<scanner_engine::Engine> {
    static ENGINE: OnceLock<Arc<scanner_engine::Engine>> = OnceLock::new();
    Arc::clone(ENGINE.get_or_init(|| Arc::new(build_runtime_engine())))
}

fn build_runtime_engine() -> scanner_engine::Engine {
    const ANCHORS: &[&[u8]] = &[b"SECRET", b"password", b"token"];
    let rule = scanner_engine::RuleSpec {
        name: "runtime-secret",
        anchors: ANCHORS,
        radius: 64,
        validator: scanner_engine::ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new(r"(?i)(secret|password|token)[A-Za-z0-9=_:+-]{4,}")
            .expect("runtime regex must compile"),
    };
    let tuning = scanner_engine::Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 64,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 256,
        max_utf16_decoded_bytes_per_window: 4096,
        max_transform_depth: 2,
        max_total_decode_output_bytes: 1024 * 1024,
        max_work_items: 64,
        max_findings_per_chunk: 4096,
        scan_utf16_variants: true,
    };
    let transforms: Vec<scanner_engine::TransformConfig> = Vec::new();
    scanner_engine::Engine::new(vec![rule], transforms, tuning)
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

    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--is-inside-work-tree"])
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

    fs::canonicalize(path).map_err(|error| ScanRuntimeError::Io {
        op: "canonicalize",
        path: Some(path.to_path_buf()),
        error,
    })
}

fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
