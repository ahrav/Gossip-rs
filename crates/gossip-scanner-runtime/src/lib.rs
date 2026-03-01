//! Scanner runtime orchestration for filesystem and git sources.
//!
//! This crate sits between source connectors (filesystem, git) and the
//! [`ScannerCore`] engine. It owns the page-based scan loop: enumerate items
//! from a source, chunk them into pages, feed each page through the engine,
//! and aggregate results into a [`ScanOutcome`].
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐     ┌──────────────────┐     ┌─────────────┐
//! │ CLI / bin  │────▶│  scanner-runtime │────▶│ ScannerCore │
//! └────────────┘     │                  │     └─────────────┘
//!                    │  scan_fs()       │           ▲
//!                    │  scan_git()      │           │
//!                    │                  │     ┌─────┴───────┐
//!                    │  page loop +     │     │ PageScan    │
//!                    │  dedup state     │     │ Request/Out │
//!                    └──────────────────┘     └─────────────┘
//! ```
//!
//! # Execution modes
//!
//! Each scan function accepts an [`ExecutionMode`]:
//!
//! - **Direct** — the runtime reads source metadata itself (filesystem
//!   `stat`, `git ls-files`) and synthesises [`ScanItem`]s in-process.
//! - **Connector** — the runtime delegates enumeration to a connector that
//!   implements [`EnumerationConnector`]. Currently gated; selecting it
//!   returns [`ScanRuntimeError::UnsupportedExecutionMode`].
//!
//! # Pagination model
//!
//! Sources may contain millions of items. The runtime pages through them
//! with bounded memory using [`ScanBudgets`]:
//!
//! - **Connector path** — `scan_from_connector_pages` calls
//!   `enumerate_page` in a cursor-advancing loop until an empty page
//!   signals completion.
//! - **Materialized path** — `scan_materialized_items_pages` chunks a
//!   pre-collected `&[ScanItem]` into fixed-size slices, synthesising
//!   cursors from each chunk's last key.
//!
//! Both paths thread a shared [`ScanDedupState`] across pages so the engine
//! can suppress duplicate findings across page boundaries.
//!
//! # Error handling
//!
//! All public functions return `Result<ScanOutcome, ScanRuntimeError>`.
//! Process-exit policy (exit codes, stderr formatting) lives in the binary
//! crates, not here.

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

/// Connector identity tag for local-filesystem sources.
///
/// Embedded in every [`ScanItem`] so the engine can attribute findings back
/// to the originating connector type.
const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");

/// Connector identity tag for local-git sources.
const GIT_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"gitlocal");

/// How the runtime acquires source items for scanning.
///
/// See the [module-level docs](self) for the architectural distinction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionMode {
    /// The runtime reads the source directly (filesystem `stat` / `git ls-files`)
    /// and constructs [`ScanItem`]s in-process. This is the only mode
    /// currently enabled.
    #[default]
    Direct,
    /// The runtime delegates enumeration to an [`EnumerationConnector`].
    /// Selecting this mode currently returns
    /// [`ScanRuntimeError::UnsupportedExecutionMode`]; it will be enabled
    /// once the full connector pipeline is wired.
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

/// Per-page resource limits passed to connectors and used when chunking
/// materialized item slices.
///
/// These caps prevent any single enumeration call from consuming unbounded
/// memory. The defaults (256 items, 1 MB) are sized for interactive CLI
/// usage; worker binaries may raise them for throughput.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanBudgets {
    /// Maximum items a single page may contain.
    pub max_items: usize,
    /// Maximum bytes a connector may transfer in one enumerate/read call.
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
    /// Convert to the contract-level [`Budgets`] type, validating that both
    /// limits are non-zero.
    fn to_contract_budgets(self) -> Result<Budgets, ScanRuntimeError> {
        Budgets::try_new(self.max_items, self.max_bytes, None).map_err(ScanRuntimeError::from)
    }
}

/// Configuration for a filesystem scan.
///
/// Supports both directory trees (enumerated via [`FilesystemConnector`]) and
/// single files (wrapped into a one-item page). Use the builder methods
/// ([`with_execution_mode`](Self::with_execution_mode),
/// [`with_budgets`](Self::with_budgets)) to override defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsScanConfig {
    /// Root directory or single file path to scan.
    pub path: PathBuf,
    /// How items are acquired (see [`ExecutionMode`]).
    pub execution_mode: ExecutionMode,
    /// Per-page resource limits.
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

/// Configuration for a git-tracked-file scan.
///
/// The runtime shells out to `git ls-files -z` to discover tracked paths,
/// then stats each file to build [`ScanItem`]s. Use the builder methods
/// ([`with_execution_mode`](Self::with_execution_mode),
/// [`with_budgets`](Self::with_budgets)) to override defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitScanConfig {
    /// Repository working-tree path (must contain a `.git` directory
    /// reachable by the `git` binary).
    pub repo: PathBuf,
    /// How items are acquired (see [`ExecutionMode`]).
    pub execution_mode: ExecutionMode,
    /// Per-page resource limits.
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

/// Aggregated counters produced by a completed scan.
///
/// All counters use saturating arithmetic, so overflow is impossible.
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
    /// Fold a single page's output into the running totals.
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

/// Top-level filesystem scan dispatcher.
///
/// Routes to [`scan_fs_direct`] or [`scan_fs_connector`] based on
/// [`FsScanConfig::execution_mode`].
pub fn scan_fs(config: &FsScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_fs_direct(config),
        ExecutionMode::Connector => scan_fs_connector(config),
    }
}

/// Top-level git scan dispatcher.
///
/// Routes to [`scan_git_direct`] or [`scan_git_connector`] based on
/// [`GitScanConfig::execution_mode`].
pub fn scan_git(config: &GitScanConfig) -> Result<ScanOutcome, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_git_direct(config),
        ExecutionMode::Connector => scan_git_connector(config),
    }
}

/// Direct-mode filesystem scan.
///
/// Two branches depending on the target path:
///
/// - **Directory** — wraps the path in a [`FilesystemConnector`] and drives
///   it through the paginated connector loop (`scan_from_connector_pages`).
/// - **Single file** — stats the file, builds one [`ScanItem`], and runs it
///   through the materialized-items path as a single-item page.
///
/// Uses an unbounded shard range (`[]..[]`) so every item is in scope.
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

/// Direct-mode git scan.
///
/// Pipeline:
/// 1. Shell out to `git ls-files -z` to collect tracked relative paths.
/// 2. For each path that resolves to a regular file, stat it and build a
///    [`ScanItem`] keyed by the relative path bytes.
/// 3. Sort items by key so the scanner core sees them in deterministic order.
/// 4. Page the sorted items through `scan_materialized_items_pages`.
///
/// Paths that no longer exist on disk (e.g. staged deletions) or that
/// produce empty key bytes are silently skipped.
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

    // Deterministic key order so page boundaries and dedup are reproducible.
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

/// Collect git-tracked file paths via `git -C <repo> ls-files -z`.
///
/// The `-z` flag produces NUL-delimited output, which is essential for
/// correct handling of filenames containing newlines or other special
/// characters. Returned paths are relative to `repo`.
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

/// Drive a connector through its full pagination sequence.
///
/// Repeatedly calls [`EnumerationConnector::enumerate_page`] until an empty
/// page is returned. Each non-empty page is fed to
/// [`ScannerCore::scan_page_with_dedupe`] so dedup state spans the entire
/// source.
///
/// # Stall detection
///
/// If a non-empty page returns the same cursor it was called with, the loop
/// would spin forever. This is caught and surfaced as
/// [`ScanRuntimeError::CursorStalled`].
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

/// Page a pre-collected item slice through the scanner engine.
///
/// Used when items have already been materialised in memory (e.g. from
/// `git ls-files` output or a single-file scan). The slice is split into
/// chunks of `max_items_per_page`, and synthetic cursors are derived from
/// each chunk's last [`ItemKey`] so the engine sees a well-formed page
/// sequence.
///
/// The `max_bytes` budget is set to 1 (the contract minimum) because no
/// actual byte transfer occurs — items are already in memory.
fn scan_materialized_items_pages(
    items: &[ScanItem],
    scanner: &ScannerCore,
    shard: &ShardSpec,
    max_items_per_page: usize,
) -> Result<ScanOutcome, ScanRuntimeError> {
    let budgets = ScanBudgets {
        max_items: max_items_per_page,
        // No byte transfer — items are already materialised.
        max_bytes: 1,
    };
    let _ = budgets.to_contract_budgets()?;

    let mut cursor = Cursor::initial();
    let mut dedupe = ScanDedupState::default();
    let mut outcome = ScanOutcome::default();

    for (index, chunk) in items.chunks(max_items_per_page).enumerate() {
        let page_num = (index as u64).saturating_add(1);
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

/// Build a [`ScanItem`] for a single local file by stat-ing it.
///
/// The file's path bytes serve as both the item key and the version
/// material prefix.
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

/// Construct a [`ScanItem`] from raw key bytes and filesystem metadata.
///
/// # Version fingerprint
///
/// Because local files lack a strong server-assigned version (ETag, S3
/// version-id, etc.), we synthesise a *weak* version by hashing:
///
/// ```text
/// version_material = prefix ‖ size_le64 ‖ mtime_nanos_le128
/// ```
///
/// This means the dedup layer treats a file as "changed" when its size or
/// modification time changes — a reasonable proxy for local sources.
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

// ---------------------------------------------------------------------------
// Platform-aware path ↔ byte conversions.
//
// On Unix, paths are arbitrary byte sequences and can be round-tripped
// losslessly via `OsStr::as_bytes` / `OsString::from_vec`.
//
// On non-Unix (primarily Windows), we fall back to lossy UTF-8 conversion.
// This is acceptable because git itself normalises paths to UTF-8 on
// Windows, so data loss is unlikely in practice.
// ---------------------------------------------------------------------------

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

    use rstest::rstest;
    use tempfile::tempdir;

    use super::*;

    // ── ExecutionMode parsing ──────────────────────────────────────

    #[rstest]
    #[case::lowercase_direct("direct", ExecutionMode::Direct)]
    #[case::uppercase_direct("DIRECT", ExecutionMode::Direct)]
    #[case::lowercase_connector("connector", ExecutionMode::Connector)]
    #[case::uppercase_connector("CONNECTOR", ExecutionMode::Connector)]
    #[case::mixed_case("DiReCt", ExecutionMode::Direct)]
    #[case::padded("  direct  ", ExecutionMode::Direct)]
    fn parse_execution_mode_valid(#[case] input: &str, #[case] expected: ExecutionMode) {
        assert_eq!(input.parse::<ExecutionMode>().unwrap(), expected);
    }

    #[rstest]
    #[case::unknown("unknown")]
    #[case::empty("")]
    #[case::numeric("42")]
    fn parse_execution_mode_invalid(#[case] input: &str) {
        let err = input.parse::<ExecutionMode>().unwrap_err();
        assert_eq!(err.raw(), input);
    }

    // ── Filesystem scan integration ────────────────────────────────

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
    fn scan_fs_direct_scans_single_file() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("secret.txt");
        fs::write(&file_path, "password=hunter2").expect("write");

        let outcome = scan_fs_direct(&FsScanConfig::new(&file_path)).expect("single file scan");
        assert_eq!(outcome.pages_scanned, 1);
        assert_eq!(outcome.items_scanned, 1);
    }

    #[test]
    fn scan_fs_direct_rejects_nonexistent_path() {
        let err =
            scan_fs_direct(&FsScanConfig::new("/no/such/path")).expect_err("nonexistent path");
        assert!(matches!(
            err,
            ScanRuntimeError::InvalidPath {
                source: "filesystem",
                ..
            }
        ));
    }

    // ── Connector-mode gating ──────────────────────────────────────

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
    fn scan_git_connector_is_explicitly_gated() {
        let dir = tempdir().expect("tempdir");
        let error =
            scan_git(&GitScanConfig::new(dir.path()).with_execution_mode(ExecutionMode::Connector))
                .expect_err("connector mode should be gated");
        assert!(matches!(
            error,
            ScanRuntimeError::UnsupportedExecutionMode {
                source: "git",
                mode: ExecutionMode::Connector,
            }
        ));
    }

    // ── Git scan error paths ───────────────────────────────────────

    #[test]
    fn scan_git_direct_errors_for_non_repo() {
        let dir = tempdir().expect("tempdir");
        let error = scan_git_direct(&GitScanConfig::new(dir.path())).expect_err("non-repo");
        assert!(matches!(
            error,
            ScanRuntimeError::GitCommandFailed { .. } | ScanRuntimeError::Io { .. }
        ));
    }
}
