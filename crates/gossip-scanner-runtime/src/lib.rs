//! Scanner runtime orchestration APIs shared by CLI and worker binaries.
//!
//! This crate owns source-level scan orchestration (`fs` and `git`) while
//! keeping process-exit behavior in binaries. Public functions return typed
//! errors and deterministic summary outputs.

use std::{
    ffi::OsString,
    fmt, fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::UNIX_EPOCH,
};

#[cfg(unix)]
use std::{
    ffi::OsStr,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

use gossip_connectors::FilesystemConnector;
use gossip_contracts::{
    connector::{
        Budgets, ConnectorInputError, Cursor, EnumerateError, EnumerationConnector, ItemKey,
        ItemRef, ScanItem, VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ItemIdentityKey, ObjectVersionId},
};
use gossip_engine::{
    PageScanContext, PageScanOutput, PageScanRequest, ScanDedupState, ScannerCore, ScannerCoreError,
};

const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");
const GIT_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"gitlocal");

/// Execution-mode selection shared across scanner runtime entrypoints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Runtime-direct mode.
    #[default]
    Direct,
    /// Connector mode (explicit until later phases).
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

/// Error returned when parsing [`ExecutionMode`] from CLI-style strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseExecutionModeError {
    raw: String,
}

impl ParseExecutionModeError {
    /// Original user-provided value.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }
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

/// Page-budget controls for source enumeration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanBudgets {
    /// Maximum items per page.
    pub max_items: usize,
    /// Maximum bytes per read/enumerate call.
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
    fn to_contract_budgets(self) -> Result<Budgets, ScanRuntimeError> {
        Budgets::try_new(self.max_items, self.max_bytes, None).map_err(ScanRuntimeError::from)
    }
}

/// Filesystem scan configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsScanConfig {
    /// Root directory or single file path to scan.
    pub path: PathBuf,
    /// Runtime execution mode.
    pub execution_mode: ExecutionMode,
    /// Enumeration/read budgets.
    pub budgets: ScanBudgets,
}

impl FsScanConfig {
    /// Build filesystem scan config with direct mode defaults.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
        }
    }

    /// Override execution mode.
    #[must_use]
    pub fn with_execution_mode(mut self, execution_mode: ExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    /// Override budgets.
    #[must_use]
    pub fn with_budgets(mut self, budgets: ScanBudgets) -> Self {
        self.budgets = budgets;
        self
    }
}

/// Git scan configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitScanConfig {
    /// Repository working-tree path.
    pub repo: PathBuf,
    /// Runtime execution mode.
    pub execution_mode: ExecutionMode,
    /// Enumeration/read budgets.
    pub budgets: ScanBudgets,
}

impl GitScanConfig {
    /// Build git scan config with direct mode defaults.
    #[must_use]
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self {
            repo: repo.into(),
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
        }
    }

    /// Override execution mode.
    #[must_use]
    pub fn with_execution_mode(mut self, execution_mode: ExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    /// Override budgets.
    #[must_use]
    pub fn with_budgets(mut self, budgets: ScanBudgets) -> Self {
        self.budgets = budgets;
        self
    }
}

/// Aggregated scan outcome for runtime entrypoints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Number of non-empty pages evaluated by scanner core.
    pub pages_scanned: u64,
    /// Number of scan items evaluated.
    pub items_scanned: u64,
    /// Number of findings emitted by scanner core.
    pub findings_emitted: u64,
    /// Number of diagnostics emitted by scanner core.
    pub diagnostics_emitted: u64,
}

impl ScanOutcome {
    fn record_page(&mut self, page: &PageScanOutput) {
        self.pages_scanned = self.pages_scanned.saturating_add(1);
        self.items_scanned = self
            .items_scanned
            .saturating_add(page.summary().item_count() as u64);
        self.findings_emitted = self
            .findings_emitted
            .saturating_add(page.findings().len() as u64);
        self.diagnostics_emitted = self
            .diagnostics_emitted
            .saturating_add(page.diagnostics().len() as u64);
    }
}

/// Runtime-level scan orchestration errors.
#[derive(Debug)]
pub enum ScanRuntimeError {
    /// Connector-mode paths are intentionally gated until later phases.
    UnsupportedExecutionMode {
        source: &'static str,
        mode: ExecutionMode,
    },
    /// Invalid or missing source path/repo.
    InvalidPath {
        source: &'static str,
        path: PathBuf,
        message: String,
    },
    /// Contract-level input error (keys/cursors/budgets).
    ConnectorInput(ConnectorInputError),
    /// Connector enumeration failure.
    Enumerate(EnumerateError),
    /// Scanner-core page processing failure.
    Scanner(ScannerCoreError),
    /// Local I/O failure.
    Io {
        op: &'static str,
        path: Option<PathBuf>,
        error: io::Error,
    },
    /// `git` command failed (non-zero exit status).
    GitCommandFailed {
        repo: PathBuf,
        status_code: Option<i32>,
        stderr: String,
    },
    /// Connector page returned non-empty items but did not advance cursor.
    CursorStalled { page_num: u64 },
}

impl fmt::Display for ScanRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedExecutionMode { source, mode } => {
                write!(f, "{source} execution mode '{mode:?}' is not enabled yet")
            }
            Self::InvalidPath {
                source,
                path,
                message,
            } => {
                write!(f, "invalid {source} path '{}': {message}", path.display())
            }
            Self::ConnectorInput(error) => write!(f, "connector input error: {error}"),
            Self::Enumerate(error) => write!(f, "enumeration error: {error}"),
            Self::Scanner(error) => write!(f, "scanner core error: {error}"),
            Self::Io { op, path, error } => {
                if let Some(path) = path {
                    write!(f, "{op} failed for '{}': {error}", path.display())
                } else {
                    write!(f, "{op} failed: {error}")
                }
            }
            Self::GitCommandFailed {
                repo,
                status_code,
                stderr,
            } => {
                write!(
                    f,
                    "git ls-files failed in '{}' (status={status_code:?}): {}",
                    repo.display(),
                    stderr.trim()
                )
            }
            Self::CursorStalled { page_num } => write!(
                f,
                "connector cursor did not advance on non-empty page {page_num}"
            ),
        }
    }
}

impl std::error::Error for ScanRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConnectorInput(error) => Some(error),
            Self::Enumerate(error) => Some(error),
            Self::Scanner(error) => Some(error),
            Self::Io { error, .. } => Some(error),
            Self::UnsupportedExecutionMode { .. }
            | Self::InvalidPath { .. }
            | Self::GitCommandFailed { .. }
            | Self::CursorStalled { .. } => None,
        }
    }
}

impl From<ConnectorInputError> for ScanRuntimeError {
    fn from(value: ConnectorInputError) -> Self {
        Self::ConnectorInput(value)
    }
}

impl From<EnumerateError> for ScanRuntimeError {
    fn from(value: EnumerateError) -> Self {
        Self::Enumerate(value)
    }
}

impl From<ScannerCoreError> for ScanRuntimeError {
    fn from(value: ScannerCoreError) -> Self {
        Self::Scanner(value)
    }
}

/// Dispatch filesystem scans according to [`FsScanConfig::execution_mode`].
pub fn scan_fs(config: &FsScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_fs_direct(config),
        ExecutionMode::Connector => scan_fs_connector(config),
    }
}

/// Dispatch git scans according to [`GitScanConfig::execution_mode`].
pub fn scan_git(config: &GitScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_git_direct(config),
        ExecutionMode::Connector => scan_git_connector(config),
    }
}

/// Direct-mode filesystem scan entrypoint.
pub fn scan_fs_direct(config: &FsScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    validate_fs_path(&config.path)?;

    let scanner = ScannerCore::default();
    let shard = ShardSpec::with_range([], []);

    if config.path.is_dir() {
        let budgets = config.budgets.to_contract_budgets()?;
        let mut connector = FilesystemConnector::new(&config.path);
        scan_from_connector_pages(&mut connector, &scanner, &shard, budgets)
    } else {
        let single_item = build_local_file_scan_item(&config.path, FILESYSTEM_CONNECTOR_TAG)?;
        scan_materialized_items_pages(&[single_item], &scanner, &shard, config.budgets.max_items)
    }
}

/// Direct-mode git scan entrypoint.
pub fn scan_git_direct(config: &GitScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    validate_git_repo_path(&config.repo)?;

    let tracked_paths = list_git_tracked_paths(&config.repo)?;
    let mut items = Vec::with_capacity(tracked_paths.len());
    for rel_path in tracked_paths {
        let abs_path = config.repo.join(&rel_path);
        if !abs_path.is_file() {
            continue;
        }
        let key_bytes = path_bytes(&rel_path);
        if key_bytes.is_empty() {
            continue;
        }
        let metadata = fs::metadata(&abs_path).map_err(|error| ScanRuntimeError::Io {
            op: "metadata",
            path: Some(abs_path.clone()),
            error,
        })?;
        let item = build_scan_item(
            &key_bytes,
            GIT_CONNECTOR_TAG,
            &key_bytes,
            metadata.len(),
            metadata.modified().ok(),
        )?;
        items.push(item);
    }

    items.sort_unstable_by(|left, right| left.item_key().cmp(right.item_key()));

    let scanner = ScannerCore::default();
    let shard = ShardSpec::with_range([], []);
    scan_materialized_items_pages(&items, &scanner, &shard, config.budgets.max_items)
}

/// Connector-mode filesystem entrypoint stub (explicitly gated until later phases).
pub fn scan_fs_connector(config: &FsScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    let _ = config;
    Err(ScanRuntimeError::UnsupportedExecutionMode {
        source: "filesystem",
        mode: ExecutionMode::Connector,
    })
}

/// Connector-mode git entrypoint stub (explicitly gated until later phases).
pub fn scan_git_connector(config: &GitScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    let _ = config;
    Err(ScanRuntimeError::UnsupportedExecutionMode {
        source: "git",
        mode: ExecutionMode::Connector,
    })
}

fn validate_fs_path(path: &Path) -> Result<(), ScanRuntimeError> {
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
    Ok(())
}

fn validate_git_repo_path(path: &Path) -> Result<(), ScanRuntimeError> {
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
    Ok(())
}

fn list_git_tracked_paths(repo: &Path) -> Result<Vec<PathBuf>, ScanRuntimeError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("ls-files")
        .arg("-z")
        .output()
        .map_err(|error| ScanRuntimeError::Io {
            op: "git ls-files",
            path: Some(repo.to_path_buf()),
            error,
        })?;

    if !output.status.success() {
        return Err(ScanRuntimeError::GitCommandFailed {
            repo: repo.to_path_buf(),
            status_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let mut paths = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        paths.push(path_buf_from_bytes(entry));
    }
    Ok(paths)
}

fn scan_from_connector_pages<C>(
    connector: &mut C,
    scanner: &ScannerCore,
    shard: &ShardSpec,
    budgets: Budgets,
) -> Result<ScanOutcome, ScanRuntimeError>
where
    C: EnumerationConnector,
{
    let mut cursor = Cursor::initial();
    let mut dedupe = ScanDedupState::default();
    let mut outcome = ScanOutcome::default();
    let mut page_num = 1u64;

    loop {
        let page = connector
            .enumerate_page(shard, &cursor, budgets)
            .map_err(ScanRuntimeError::from)?;
        if page.items().is_empty() {
            break;
        }

        let next_cursor = page.next_cursor().clone();
        if next_cursor == cursor {
            return Err(ScanRuntimeError::CursorStalled { page_num });
        }

        let context = PageScanContext::new(
            shard.key_range_start(),
            shard.key_range_end(),
            &cursor,
            page.next_cursor(),
            page_num,
        );
        let request = PageScanRequest::metadata_only(context, page.items());
        let output = scanner.scan_page_with_dedupe(request, &mut dedupe)?;
        outcome.record_page(&output);

        cursor = next_cursor;
        page_num = page_num.saturating_add(1);
    }

    Ok(outcome)
}

fn scan_materialized_items_pages(
    items: &[ScanItem],
    scanner: &ScannerCore,
    shard: &ShardSpec,
    max_items_per_page: usize,
) -> Result<ScanOutcome, ScanRuntimeError> {
    let budgets = ScanBudgets {
        max_items: max_items_per_page,
        max_bytes: 1,
    };
    let _ = budgets.to_contract_budgets()?;

    let mut cursor = Cursor::initial();
    let mut dedupe = ScanDedupState::default();
    let mut outcome = ScanOutcome::default();

    for (index, chunk) in items.chunks(max_items_per_page).enumerate() {
        if chunk.is_empty() {
            continue;
        }
        let page_num = index as u64 + 1;
        let last_key = chunk.last().expect("non-empty chunk").item_key().clone();
        let next_cursor = Cursor::with_last_key(last_key);

        let context = PageScanContext::new(
            shard.key_range_start(),
            shard.key_range_end(),
            &cursor,
            &next_cursor,
            page_num,
        );
        let request = PageScanRequest::metadata_only(context, chunk);
        let output = scanner.scan_page_with_dedupe(request, &mut dedupe)?;
        outcome.record_page(&output);
        cursor = next_cursor;
    }

    Ok(outcome)
}

fn build_local_file_scan_item(
    path: &Path,
    connector_tag: ConnectorTag,
) -> Result<ScanItem, ScanRuntimeError> {
    let metadata = fs::metadata(path).map_err(|error| ScanRuntimeError::Io {
        op: "metadata",
        path: Some(path.to_path_buf()),
        error,
    })?;
    let key_bytes = path_bytes(path);
    build_scan_item(
        &key_bytes,
        connector_tag,
        &key_bytes,
        metadata.len(),
        metadata.modified().ok(),
    )
}

fn build_scan_item(
    key_bytes: &[u8],
    connector_tag: ConnectorTag,
    version_material_prefix: &[u8],
    size_hint: u64,
    modified: Option<std::time::SystemTime>,
) -> Result<ScanItem, ScanRuntimeError> {
    let item_key = ItemKey::try_from_slice(key_bytes)?;
    let item_ref = ItemRef::try_from_slice(key_bytes)?;
    let stable_item_id = ItemIdentityKey::new(connector_tag, key_bytes).stable_id();

    let mut version_material = Vec::with_capacity(version_material_prefix.len() + 32);
    version_material.extend_from_slice(version_material_prefix);
    version_material.extend_from_slice(&size_hint.to_le_bytes());
    let modified_nanos = modified
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    version_material.extend_from_slice(&modified_nanos.to_le_bytes());

    let version = VersionId::Weak(ObjectVersionId::from_version_bytes(&version_material));
    Ok(ScanItem::new(item_key, item_ref, stable_item_id, version).with_size_hint(size_hint))
}

#[cfg(unix)]
fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

#[cfg(not(unix))]
fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    path_to_raw_bytes(path.as_os_str()).to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

#[cfg(unix)]
fn path_to_raw_bytes(path: &OsStr) -> &[u8] {
    path.as_bytes()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn scan_fs_direct_scans_directory() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("a.txt");
        let mut file = fs::File::create(&file_path).expect("create file");
        writeln!(file, "hello world").expect("write file");

        let outcome = scan_fs_direct(&FsScanConfig::new(dir.path())).expect("fs direct scan");
        assert!(outcome.pages_scanned >= 1);
        assert!(outcome.items_scanned >= 1);
        assert!(outcome.findings_emitted >= 1);
    }

    #[test]
    fn scan_fs_connector_is_explicitly_gated() {
        let dir = tempdir().expect("tempdir");
        let error =
            scan_fs(&FsScanConfig::new(dir.path()).with_execution_mode(ExecutionMode::Connector))
                .expect_err("connector mode should be gated");
        assert!(matches!(
            error,
            ScanRuntimeError::UnsupportedExecutionMode {
                source: "filesystem",
                mode: ExecutionMode::Connector,
            }
        ));
    }

    #[test]
    fn scan_git_direct_errors_for_non_repo() {
        let dir = tempdir().expect("tempdir");
        let error = scan_git_direct(&GitScanConfig::new(dir.path())).expect_err("non-repo");
        assert!(matches!(
            error,
            ScanRuntimeError::GitCommandFailed { .. } | ScanRuntimeError::Io { .. }
        ));
    }

    #[test]
    fn parse_execution_mode_is_case_insensitive() {
        assert_eq!(
            "direct".parse::<ExecutionMode>().unwrap(),
            ExecutionMode::Direct
        );
        assert_eq!(
            "CONNECTOR".parse::<ExecutionMode>().unwrap(),
            ExecutionMode::Connector
        );
        assert!("unknown".parse::<ExecutionMode>().is_err());
    }
}
