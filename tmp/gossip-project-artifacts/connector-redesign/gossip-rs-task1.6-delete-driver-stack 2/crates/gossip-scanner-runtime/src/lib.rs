//! Family-oriented scanner runtime: config parsing, path validation, and
//! placeholder execution boundaries for the new connector architecture.
//!
//! The previous driver-based surface is intentionally no longer referenced from
//! this crate. Runtime wiring is now expressed in terms of source families:
//!
//! - ordered content (`OrderedContentSource`)
//! - Git repo discovery / mirror / execution
//!
//! Task 1.5 only cuts over the compile surface. The concrete worker loops land
//! in later tasks/epics.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gossip_contracts::connector::ConnectorInputError;
use scanner_engine::TransformId;
use scanner_git::{GitScanMode, MergeDiffMode};

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
/// Retained for CLI and telemetry compatibility during the migration away from
/// the legacy source model.
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnchorMode {
    #[default]
    Manual,
    Derived,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventFormat {
    #[default]
    Jsonl,
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TransformFilter {
    #[default]
    All,
    None,
    Only(Vec<TransformId>),
}

/// Git-specific debug verbosity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum GitDebugLevel {
    #[default]
    Off,
    Stats,
    Perf,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsScanConfig {
    pub path: PathBuf,
    pub workers: usize,
    pub decode_depth: Option<usize>,
    pub skip_archives: bool,
    pub scan_binary: bool,
    pub persist_findings: bool,
    pub anchor_mode: AnchorMode,
    pub rules_file: Option<PathBuf>,
    pub transform_filter: TransformFilter,
    pub execution_mode: ExecutionMode,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitScanConfig {
    pub repo: PathBuf,
    pub workers: usize,
    pub decode_depth: Option<usize>,
    pub scan_binary: bool,
    pub debug_level: GitDebugLevel,
    pub enrich_identities: bool,
    pub anchor_mode: AnchorMode,
    pub rules_file: Option<PathBuf>,
    pub transform_filter: TransformFilter,
    pub repo_id: u64,
    pub scan_mode: GitScanMode,
    pub merge_mode: MergeDiffMode,
    pub tree_delta_cache_mb: Option<u32>,
    pub engine_chunk_mb: Option<u32>,
    pub execution_mode: ExecutionMode,
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub items_scanned: u64,
    pub chunks_scanned: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
    pub errors: u64,
    pub binary_skipped: u64,
    pub ext_skipped: u64,
    pub lock_skipped: u64,
    pub binary_extracted: u64,
    pub dropped_findings: u64,
    pub persist_emit_failures: u64,
    pub persist_incomplete: bool,
    pub scan_ns: u64,
    pub persist_ns: u64,
}

#[derive(Debug)]
pub enum ScanRuntimeError {
    InvalidPath {
        source: &'static str,
        path: PathBuf,
        message: String,
    },
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
    FamilyRuntimeNotImplemented {
        family: &'static str,
        source: &'static str,
    },
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
            Self::FamilyRuntimeNotImplemented { family, source } => {
                write!(
                    f,
                    "{family} runtime path for source '{source}' is not implemented yet"
                )
            }
        }
    }
}

impl std::error::Error for ScanRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::ConnectorInput(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ConnectorInputError> for ScanRuntimeError {
    fn from(value: ConnectorInputError) -> Self {
        Self::ConnectorInput(value)
    }
}

pub fn scan_fs(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_fs_direct(config),
        ExecutionMode::Connector => scan_fs_connector(config),
    }
}

pub fn scan_git(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_git_direct(config),
        ExecutionMode::Connector => scan_git_connector(config),
    }
}

pub fn scan_fs_direct(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let canonical_path = validate_fs_path(&config.path)?;
    config.budgets.validate()?;
    ordered_content::filesystem_placeholder(config, canonical_path)
}

pub fn scan_fs_connector(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let canonical_path = validate_fs_path(&config.path)?;
    config.budgets.validate()?;
    ordered_content::filesystem_placeholder(config, canonical_path)
}

pub fn scan_git_direct(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let canonical_repo = validate_git_repo_path(&config.repo)?;
    config.budgets.validate()?;
    git_repo::local_repo_placeholder(config, canonical_repo)
}

pub fn scan_git_connector(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let canonical_repo = validate_git_repo_path(&config.repo)?;
    config.budgets.validate()?;
    git_repo::local_repo_placeholder(config, canonical_repo)
}

#[must_use]
pub fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
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
                "path must point at repository toplevel '{}'",
                canonical_toplevel.display()
            ),
        });
    }

    Ok(canonical_toplevel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_execution_mode_valid_values() {
        assert_eq!("direct".parse::<ExecutionMode>().unwrap(), ExecutionMode::Direct);
        assert_eq!("CONNECTOR".parse::<ExecutionMode>().unwrap(), ExecutionMode::Connector);
    }

    #[test]
    fn scan_budgets_reject_zero_values() {
        let err = ScanBudgets { max_items: 0, max_bytes: 1 }.validate().unwrap_err();
        assert!(matches!(err, ScanRuntimeError::ConnectorInput(_)));
    }

    #[test]
    fn validate_fs_path_rejects_missing_path() {
        let err = scan_fs_direct(&FsScanConfig::new("/definitely/missing/path")).unwrap_err();
        assert!(matches!(err, ScanRuntimeError::InvalidPath { source: "filesystem", .. }));
    }

    #[test]
    fn placeholder_fs_runtime_is_exposed_after_validation() {
        let dir = tempdir().unwrap();
        let err = scan_fs_direct(&FsScanConfig::new(dir.path())).unwrap_err();
        assert!(matches!(err, ScanRuntimeError::FamilyRuntimeNotImplemented { family: "ordered-content", .. }));
    }
}
