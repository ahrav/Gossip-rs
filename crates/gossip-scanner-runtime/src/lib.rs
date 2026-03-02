//! Scanner runtime orchestration for filesystem and git sources.
//!
//! This crate sits between source connectors (filesystem, git) and the
//! [`ScannerCore`] engine. It owns the page-based scan loop: enumerate items
//! from a source, chunk them into pages, feed each page through the engine,
//! and aggregate results into a [`ScanAggregateStats`].
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
//!   implements [`EnumerationConnector`]. Filesystem connector mode runs
//!   through the same scan-loop/page-hook seam used by worker execution.
//!
//! # Pagination model
//!
//! Sources may contain millions of items. The runtime pages through them
//! with bounded memory using [`ScanBudgets`]:
//!
//! - **Direct directory path** — `scan_from_connector_pages` calls
//!   `enumerate_page` in a cursor-advancing loop until an empty page
//!   signals completion.
//! - **Connector mode path (filesystem, git)** — uses
//!   `run_scan_loop_with_page_processor` for worker-parity cursor progression
//!   and page processing.
//! - **Materialized path** — `scan_materialized_items_pages` chunks a
//!   pre-collected `&[ScanItem]` into fixed-size slices, synthesising
//!   cursors from each chunk's last key.
//!
//! Both paths thread a shared [`ScanDedupState`] across pages so the engine
//! can suppress duplicate findings across page boundaries.
//!
//! # Error handling
//!
//! All public functions return `Result<ScanAggregateStats, ScanRuntimeError>`.
//! Process-exit policy (exit codes, stderr formatting) lives in the binary
//! crates, not here.

use std::{
    ffi::OsString,
    fmt, fs, io,
    path::{Component, Path, PathBuf},
    process::Command,
    time::UNIX_EPOCH,
};

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use gossip_connectors::{FilesystemConnector, GitConnector};
use gossip_contracts::{
    connector::{
        Budgets, ConnectorInputError, Cursor, EnumerateError, EnumerationConnector, ItemKey,
        ItemRef, ScanItem, VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ItemIdentityKey, ObjectVersionId},
};
use gossip_coordination::{
    AcquireError, CreateRunError, CursorSemantics, CursorUpdate, InMemoryCoordinator,
    InitialShardInput, LogicalTime, OpId, RegisterShardsError, RunConfig, RunConfigError, RunId,
    RunManagement, ShardId, ShardKey, TenantId, WorkerId, WorkerSession,
};
use gossip_engine::{
    PageScanContext, PageScanOutput, PageScanRequest, ScanAggregateStats, ScanDedupState,
    ScannerCore, ScannerCoreError,
};
use gossip_scan_pipeline::{
    DEFAULT_MAX_TRANSIENT_RETRIES, LeaseLossCause, PageProcessingContext, PageProcessingError,
    ScanLoopError, ScanLoopOutcome, run_scan_loop_with_page_processor,
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
    /// and constructs [`ScanItem`]s in-process.
    #[default]
    Direct,
    /// The runtime delegates enumeration to an [`EnumerationConnector`].
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
    /// Upper bound on tracked files accepted from `git ls-files`.
    /// `None` disables the limit. Defaults to 1,000,000.
    pub max_tracked_files: Option<usize>,
}

impl GitScanConfig {
    /// Build git scan config with direct mode defaults.
    #[must_use]
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self {
            repo: repo.into(),
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
            max_tracked_files: Some(1_000_000),
        }
    }

    /// Override the maximum number of tracked files accepted.
    /// Pass `None` to disable the limit.
    #[must_use]
    pub fn with_max_tracked_files(mut self, limit: Option<usize>) -> Self {
        self.max_tracked_files = limit;
        self
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
    /// Invalid run configuration for connector-mode scan-loop setup.
    RunConfig(RunConfigError),
    /// Creating ephemeral scan-loop run state failed.
    CreateRun(CreateRunError),
    /// Registering the single connector-mode shard failed.
    RegisterShards(RegisterShardsError),
    /// Acquiring a worker session for connector-mode execution failed.
    Acquire(AcquireError),
    /// Connector-mode scan loop terminated with a non-terminal error.
    ScanLoop(Box<ScanLoopError>),
    /// Connector-mode scan loop parked the shard instead of completing.
    ScanLoopParked {
        reason: gossip_coordination::ParkReason,
        retry_after_ms: Option<u64>,
    },
    /// Connector-mode scan loop lost lease before terminal completion.
    ScanLoopLeaseLost {
        pages_completed: u64,
        cause: LeaseLossCause,
    },
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
    /// Git repository tracks more files than the configured limit.
    TooManyTrackedFiles { count: usize, limit: usize },
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
            Self::RunConfig(error) => write!(f, "connector-mode run config failed: {error}"),
            Self::CreateRun(error) => write!(f, "connector-mode run creation failed: {error}"),
            Self::RegisterShards(error) => {
                write!(f, "connector-mode shard registration failed: {error}")
            }
            Self::Acquire(error) => write!(f, "connector-mode session acquire failed: {error}"),
            Self::ScanLoop(error) => {
                write!(f, "connector-mode scan loop failed: {}", error.as_ref())
            }
            Self::ScanLoopParked {
                reason,
                retry_after_ms,
            } => {
                write!(f, "connector-mode scan loop parked shard ({reason}")?;
                if let Some(retry_after_ms) = retry_after_ms {
                    write!(f, ", retry_after_ms={retry_after_ms}")?;
                }
                write!(f, ")")
            }
            Self::ScanLoopLeaseLost {
                pages_completed,
                cause,
            } => write!(
                f,
                "connector-mode scan loop lost lease after {pages_completed} completed pages: {cause}"
            ),
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
            Self::TooManyTrackedFiles { count, limit } => write!(
                f,
                "git repository tracks {count} files, exceeding limit of {limit}"
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
            Self::RunConfig(error) => Some(error),
            Self::CreateRun(error) => Some(error),
            Self::RegisterShards(error) => Some(error),
            Self::Acquire(error) => Some(error),
            Self::ScanLoop(error) => Some(error.as_ref()),
            Self::Io { error, .. } => Some(error),
            Self::UnsupportedExecutionMode { .. }
            | Self::InvalidPath { .. }
            | Self::GitCommandFailed { .. }
            | Self::ScanLoopParked { .. }
            | Self::CursorStalled { .. }
            | Self::TooManyTrackedFiles { .. } => None,
            Self::ScanLoopLeaseLost { cause, .. } => match cause {
                LeaseLossCause::RenewFailed(e) => Some(e),
                LeaseLossCause::DeadlineElapsed { .. } => None,
            },
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

impl From<RunConfigError> for ScanRuntimeError {
    fn from(value: RunConfigError) -> Self {
        Self::RunConfig(value)
    }
}

impl From<CreateRunError> for ScanRuntimeError {
    fn from(value: CreateRunError) -> Self {
        Self::CreateRun(value)
    }
}

impl From<RegisterShardsError> for ScanRuntimeError {
    fn from(value: RegisterShardsError) -> Self {
        Self::RegisterShards(value)
    }
}

impl From<AcquireError> for ScanRuntimeError {
    fn from(value: AcquireError) -> Self {
        Self::Acquire(value)
    }
}

impl From<ScanLoopError> for ScanRuntimeError {
    fn from(value: ScanLoopError) -> Self {
        Self::ScanLoop(Box::new(value))
    }
}

/// Top-level filesystem scan dispatcher.
///
/// Routes to [`scan_fs_direct`] or [`scan_fs_connector`] based on
/// [`FsScanConfig::execution_mode`].
pub fn scan_fs(config: &FsScanConfig) -> Result<ScanAggregateStats, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_fs_direct(config),
        ExecutionMode::Connector => scan_fs_connector(config),
    }
}

/// Top-level git scan dispatcher.
///
/// Routes to [`scan_git_direct`] or [`scan_git_connector`] based on
/// [`GitScanConfig::execution_mode`].
pub fn scan_git(config: &GitScanConfig) -> Result<ScanAggregateStats, ScanRuntimeError> {
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
pub fn scan_fs_direct(config: &FsScanConfig) -> Result<ScanAggregateStats, ScanRuntimeError> {
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
pub fn scan_git_direct(config: &GitScanConfig) -> Result<ScanAggregateStats, ScanRuntimeError> {
    let canonical_repo = validate_git_repo_path(&config.repo)?;

    let tracked_paths = list_git_tracked_paths(&config.repo)?;

    if let Some(max) = config.max_tracked_files
        && tracked_paths.len() > max
    {
        return Err(ScanRuntimeError::TooManyTrackedFiles {
            count: tracked_paths.len(),
            limit: max,
        });
    }

    let mut items = Vec::with_capacity(tracked_paths.len());
    for rel_path in tracked_paths {
        // Reject paths containing `..` to prevent directory traversal.
        if rel_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            continue;
        }

        let abs_path = canonical_repo.join(&rel_path);

        // Verify the resolved path is still within the repo boundary.
        let canonical_abs = match fs::canonicalize(&abs_path) {
            Ok(p) => p,
            Err(_) => continue, // file may have been deleted since ls-files
        };
        if !canonical_abs.starts_with(&canonical_repo) {
            continue;
        }

        // Use symlink_metadata to avoid following symlinks.
        let metadata = match fs::symlink_metadata(&abs_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }

        #[cfg(unix)]
        let key_bytes = path_bytes_ref(&rel_path);
        #[cfg(not(unix))]
        let key_bytes = path_bytes(&rel_path);
        if key_bytes.is_empty() {
            continue;
        }
        let item = build_scan_item(
            key_bytes,
            GIT_CONNECTOR_TAG,
            key_bytes,
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

/// Connector-mode filesystem scan.
///
/// Directory scans use the same connector scan-loop + page-processor seam as
/// worker execution (`run_scan_loop_with_page_processor`).
///
/// Single-file scans keep the direct-mode single-item path because
/// [`FilesystemConnector`] is directory-rooted by design.
///
/// **Known divergence**: directory scans use a bounded `ShardSpec` (from
/// `connector_mode_shard_spec`) while single-file scans use an unbounded
/// `ShardSpec::with_range([], [])`. This means `PageScanContext::key_range_*`
/// differs between the two input shapes within the same execution mode. The
/// scanner core currently does not use key ranges for filtering, so this has
/// no behavioral impact today.
pub fn scan_fs_connector(config: &FsScanConfig) -> Result<ScanAggregateStats, ScanRuntimeError> {
    validate_fs_path(&config.path)?;

    let scanner = ScannerCore::default();

    if config.path.is_dir() {
        let shard = connector_mode_shard_spec();
        let budgets = config.budgets.to_contract_budgets()?;
        let mut connector = FilesystemConnector::new(&config.path);
        scan_from_connector_pages_with_pipeline(&mut connector, &scanner, &shard, budgets)
    } else {
        let shard = ShardSpec::with_range([], []);
        let single_item = build_local_file_scan_item(&config.path, FILESYSTEM_CONNECTOR_TAG)?;
        scan_materialized_items_pages(&[single_item], &scanner, &shard, config.budgets.max_items)
    }
}

/// Connector-mode git scan.
///
/// Uses the same worker-compatible scan-loop + page-processor seam as
/// [`scan_fs_connector`] to preserve runtime and worker parity.
pub fn scan_git_connector(config: &GitScanConfig) -> Result<ScanAggregateStats, ScanRuntimeError> {
    validate_git_repo_path(&config.repo)?;

    let scanner = ScannerCore::default();
    let shard = connector_mode_shard_spec();
    let budgets = config.budgets.to_contract_budgets()?;
    let mut connector = GitConnector::new(&config.repo);
    scan_from_connector_pages_with_pipeline(&mut connector, &scanner, &shard, budgets)
}

const CONNECTOR_MODE_LEASE_DURATION_TICKS: u64 = 60_000;
const CONNECTOR_MODE_TENANT: TenantId = TenantId::from_bytes([0x52; 32]);
const CONNECTOR_MODE_RUN: RunId = RunId::from_raw(1);
const CONNECTOR_MODE_SHARD: ShardId = ShardId::from_raw(1);
const CONNECTOR_MODE_WORKER: WorkerId = WorkerId::from_raw(1);

/// Build a bounded shard range for standalone connector-mode scans.
///
/// Coordination manifest validation rejects unbounded shard ranges, so we use
/// `[0x00, 0xff..ff)` as a practical "full keyspace" envelope for local scans.
fn connector_mode_shard_spec() -> ShardSpec {
    ShardSpec::with_range([0], vec![0xff; gossip_coordination::MAX_KEY_SIZE])
}

/// Seed one in-memory run/shard and acquire a session for scan-loop execution.
///
/// This preserves worker-level loop semantics (checkpoint/complete transitions)
/// for standalone runtime execution without requiring external coordination
/// infrastructure.
fn create_runtime_worker_session<'a>(
    coordinator: &'a mut InMemoryCoordinator,
    shard: &ShardSpec,
) -> Result<WorkerSession<'a, InMemoryCoordinator>, ScanRuntimeError> {
    let run_config = RunConfig::try_new(
        CursorSemantics::Completed,
        CONNECTOR_MODE_LEASE_DURATION_TICKS,
        None,
    )?;
    coordinator.create_run(
        LogicalTime::from_raw(1),
        CONNECTOR_MODE_TENANT,
        CONNECTOR_MODE_RUN,
        run_config,
    )?;

    let shard_inputs = [InitialShardInput::new(
        CONNECTOR_MODE_SHARD,
        shard.as_ref(),
        CursorUpdate::initial(),
    )];
    let _ = coordinator.register_shards(
        LogicalTime::from_raw(2),
        CONNECTOR_MODE_TENANT,
        CONNECTOR_MODE_RUN,
        &shard_inputs,
        OpId::from_raw(1),
    )?;

    WorkerSession::new(
        coordinator,
        LogicalTime::from_raw(3),
        CONNECTOR_MODE_TENANT,
        ShardKey::new(CONNECTOR_MODE_RUN, CONNECTOR_MODE_SHARD),
        CONNECTOR_MODE_WORKER,
    )
    .map_err(ScanRuntimeError::from)
}

/// Run a connector through the worker-style scan loop with scanner-core page processing.
fn scan_from_connector_pages_with_pipeline<C>(
    connector: &mut C,
    scanner: &ScannerCore,
    shard: &ShardSpec,
    budgets: Budgets,
) -> Result<ScanAggregateStats, ScanRuntimeError>
where
    C: EnumerationConnector,
{
    let mut coordinator = InMemoryCoordinator::new(CONNECTOR_MODE_LEASE_DURATION_TICKS);
    let session = create_runtime_worker_session(&mut coordinator, shard)?;

    // Shard op log starts empty: register_shards writes to the run-level op
    // log, not the shard's, so the first shard-level op can use raw ID 1.
    let mut next_op_raw = 1u64;
    let mut next_now_raw = 4u64;
    let mut dedupe = ScanDedupState::default();
    let mut outcome = ScanAggregateStats::default();

    let mut page_output = PageScanOutput::default();

    let scan_loop_outcome = run_scan_loop_with_page_processor(
        session,
        connector,
        budgets,
        DEFAULT_MAX_TRANSIENT_RETRIES,
        || {
            let out = OpId::from_raw(next_op_raw);
            next_op_raw = next_op_raw.saturating_add(1);
            out
        },
        || {
            let out = LogicalTime::from_raw(next_now_raw);
            next_now_raw = next_now_raw.saturating_add(1);
            out
        },
        |context| {
            process_page_with_engine(
                scanner,
                &mut dedupe,
                &mut outcome,
                &mut page_output,
                context,
            )
        },
    );

    match scan_loop_outcome {
        ScanLoopOutcome::Completed => Ok(outcome),
        ScanLoopOutcome::Parked {
            reason,
            retry_after_ms,
        } => Err(ScanRuntimeError::ScanLoopParked {
            reason,
            retry_after_ms,
        }),
        ScanLoopOutcome::LeaseLost {
            pages_completed,
            cause,
        } => Err(ScanRuntimeError::ScanLoopLeaseLost {
            pages_completed,
            cause,
        }),
        ScanLoopOutcome::Error(error) => Err(ScanRuntimeError::ScanLoop(Box::new(error))),
    }
}

/// Worker-compatible page-processing adapter: map page context to scanner request.
fn process_page_with_engine(
    scanner: &ScannerCore,
    dedupe: &mut ScanDedupState,
    outcome: &mut ScanAggregateStats,
    page_output: &mut PageScanOutput,
    context: PageProcessingContext<'_>,
) -> Result<(), PageProcessingError> {
    let request = PageScanRequest::metadata_only(
        PageScanContext::new(
            context.spec().key_range_start(),
            context.spec().key_range_end(),
            context.cursor(),
            context.next_cursor(),
            context.page_num(),
        ),
        context.items(),
    );

    scanner
        .scan_page_into(request, dedupe, page_output)
        .map_err(|error| {
            PageProcessingError::new(format!(
                "scanner core failed on page {}: {error}",
                context.page_num()
            ))
        })?;
    outcome.record_page(page_output);
    Ok(())
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

/// Validate that `path` exists, is a directory, and return its canonical form.
///
/// Canonicalization resolves symlinks and `..` components in the repo root
/// itself, producing a stable prefix for path-containment checks in the
/// scan loop.
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
    fs::canonicalize(path).map_err(|error| ScanRuntimeError::Io {
        op: "canonicalize",
        path: Some(path.to_path_buf()),
        error,
    })
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
        .arg("--")
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
) -> Result<ScanAggregateStats, ScanRuntimeError>
where
    C: EnumerationConnector,
{
    let mut cursor = Cursor::initial();
    let mut dedupe = ScanDedupState::default();
    let mut outcome = ScanAggregateStats::default();
    let mut page_output = PageScanOutput::default();
    let mut page_num = 1u64;

    loop {
        let page = connector
            .enumerate_page(shard, &cursor, budgets)
            .map_err(ScanRuntimeError::from)?;
        if page.items().is_empty() {
            break;
        }

        if *page.next_cursor() == cursor {
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
        scanner.scan_page_into(request, &mut dedupe, &mut page_output)?;
        outcome.record_page(&page_output);

        cursor = page.into_next_cursor();
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
fn scan_materialized_items_pages(
    items: &[ScanItem],
    scanner: &ScannerCore,
    shard: &ShardSpec,
    max_items_per_page: usize,
) -> Result<ScanAggregateStats, ScanRuntimeError> {
    if max_items_per_page == 0 {
        return Err(ScanRuntimeError::ConnectorInput(
            ConnectorInputError::ZeroBudget {
                field: "max_items_per_page",
            },
        ));
    }

    let mut cursor = Cursor::initial();
    let mut dedupe = ScanDedupState::with_capacity(items.len());
    let mut outcome = ScanAggregateStats::default();
    let mut page_output = PageScanOutput::default();

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
        scanner.scan_page_into(request, &mut dedupe, &mut page_output)?;
        outcome.record_page(&page_output);
        cursor = next_cursor;
    }

    Ok(outcome)
}

/// Build a [`ScanItem`] for a single local file by stat-ing it.
///
/// Uses `symlink_metadata` to avoid following symlinks — a symlink
/// targeting a sensitive file outside the scan root would otherwise
/// leak its metadata (size, mtime).
fn build_local_file_scan_item(
    path: &Path,
    connector_tag: ConnectorTag,
) -> Result<ScanItem, ScanRuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ScanRuntimeError::Io {
        op: "metadata",
        path: Some(path.to_path_buf()),
        error,
    })?;
    if metadata.is_symlink() {
        return Err(ScanRuntimeError::InvalidPath {
            source: "filesystem",
            path: path.to_path_buf(),
            message: "path is a symlink".to_owned(),
        });
    }
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

    let modified_nanos = modified
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    // 8 bytes for size_hint (u64 LE) + 16 bytes for modified_nanos (u128 LE).
    const METADATA_LEN: usize = 8 + 16;
    // Stack buffer covers paths up to 128 bytes (covers 99%+ of real paths).
    const INLINE_CAP: usize = 128 + METADATA_LEN;
    let total_len = version_material_prefix.len() + METADATA_LEN;

    let version = if total_len <= INLINE_CAP {
        let mut buf = [0u8; INLINE_CAP];
        buf[..version_material_prefix.len()].copy_from_slice(version_material_prefix);
        let off = version_material_prefix.len();
        buf[off..off + 8].copy_from_slice(&size_hint.to_le_bytes());
        buf[off + 8..off + METADATA_LEN].copy_from_slice(&modified_nanos.to_le_bytes());
        VersionId::Weak(ObjectVersionId::from_version_bytes(&buf[..total_len]))
    } else {
        let mut vm = Vec::with_capacity(total_len);
        vm.extend_from_slice(version_material_prefix);
        vm.extend_from_slice(&size_hint.to_le_bytes());
        vm.extend_from_slice(&modified_nanos.to_le_bytes());
        VersionId::Weak(ObjectVersionId::from_version_bytes(&vm))
    };
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
    path.as_os_str().as_bytes().to_vec()
}

/// Zero-copy path-to-bytes reference for Unix (avoids `Vec<u8>` allocation).
///
/// Use where the `Path` outlives the call and ownership transfer is not needed.
#[cfg(unix)]
fn path_bytes_ref(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
