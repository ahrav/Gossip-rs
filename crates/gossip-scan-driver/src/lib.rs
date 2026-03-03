//! Unified scan-driver boundary for source-specific execution backends.
//!
//! This crate defines the one-path execution seam used by both CLI and
//! distributed scanner runtimes:
//!
//! ```text
//! Assignment -> ScanSourceFactory -> ScanDriver::run()
//!                         \-> shared scanner scheduler + scanner engine
//! ```
//!
//! The goal is to keep the contracts crate lightweight while still exposing
//! a shared integration boundary for filesystem, git, and future sources.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use gossip_contracts::connector::{Cursor, ItemKey, VersionId};
use gossip_contracts::coordination::ShardSpec;
use gossip_contracts::identity::PolicyHash;
use scanner_git::{GitEventOutput, GitScanMode, MergeDiffMode};
use scanner_scheduler::events::EventOutput;

/// Cooperative cancellation token for long-running scans.
///
/// Drivers are expected to check this token at source-specific scheduling
/// boundaries (for example between batch submissions).
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

/// Connector/source family for an assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorKind {
    Filesystem,
    Git,
    InMemory,
}

/// Source-specific assignment payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignmentSource {
    Filesystem { root: PathBuf },
    Git { repo_root: PathBuf },
    InMemory { dataset_id: String },
}

/// Work assignment translated by a [`ScanSourceFactory`] into a driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub job_id: String,
    pub connector_kind: ConnectorKind,
    pub connector_instance_id: String,
    pub policy_hash: PolicyHash,
    pub shard_spec: ShardSpec,
    pub cursor: Cursor,
    pub source: AssignmentSource,
}

/// Runtime knobs shared across driver implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemExecutionConfig {
    /// When true, archive expansion is disabled.
    pub skip_archives: bool,
    /// When true, binary-looking files are skipped.
    pub skip_binary: bool,
    /// When true, findings are forwarded through the commit sink bridge.
    pub emit_findings_to_commit_sink: bool,
}

impl Default for FilesystemExecutionConfig {
    fn default() -> Self {
        Self {
            skip_archives: false,
            skip_binary: true,
            emit_findings_to_commit_sink: true,
        }
    }
}

/// Runtime knobs shared across driver implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanExecutionConfig {
    pub workers: usize,
    pub checkpoint_every_items: u64,
    pub filesystem: FilesystemExecutionConfig,
    pub git: GitExecutionConfig,
}

impl Default for ScanExecutionConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            checkpoint_every_items: 1_000,
            filesystem: FilesystemExecutionConfig::default(),
            git: GitExecutionConfig::default(),
        }
    }
}

/// Git-specific debug output level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitDebugLevel {
    #[default]
    Off,
    Stats,
    Perf,
}

/// Runtime knobs shared across git driver implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GitExecutionConfig {
    /// Stable repository identifier used to namespace persisted keys.
    pub repo_id: u64,
    /// Git scan mode (diff-history vs ODB-blob fast-path).
    pub scan_mode: GitScanMode,
    /// Merge-diff strategy for merge commits.
    pub merge_diff_mode: MergeDiffMode,
    /// Optional explicit pack-exec worker override.
    ///
    /// When `None`, git driver falls back to [`ScanExecutionConfig::workers`].
    pub pack_exec_workers: Option<usize>,
    /// When true, skip binary-class filtering and scan all blobs.
    pub scan_binary: bool,
    /// When true, emit identity-dictionary and enriched commit metadata.
    pub enrich_identities: bool,
    /// Optional diagnostic output level.
    pub debug_level: GitDebugLevel,
    /// Optional tree delta cache size override in MiB.
    pub tree_delta_cache_mb: Option<u32>,
    /// Optional engine chunk size override in MiB.
    pub engine_chunk_mb: Option<u32>,
}

impl Default for GitExecutionConfig {
    fn default() -> Self {
        Self {
            repo_id: 1,
            scan_mode: GitScanMode::OdbBlobFast,
            merge_diff_mode: MergeDiffMode::AllParents,
            pack_exec_workers: None,
            scan_binary: false,
            enrich_identities: false,
            debug_level: GitDebugLevel::Off,
            tree_delta_cache_mb: None,
            engine_chunk_mb: None,
        }
    }
}

/// Generic run report from a driver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub items_scanned: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
}

/// Source-provided checkpoint hint in assignment keyspace order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorUpdate {
    pub cursor: Cursor,
    pub committed_items: u64,
}

/// Coarse source capability flags.
///
/// These flags tell the orchestration layer what a driver supports so it can
/// adapt scheduling and lifecycle decisions accordingly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceCapabilities {
    /// Whether the driver produces meaningful [`CursorUpdate`] values from
    /// [`ScanDriver::checkpoint_hint`].
    pub supports_checkpoint_hints: bool,
    /// Whether the driver checks the [`CancellationToken`] during execution
    /// (not just before starting) and can stop mid-scan cooperatively.
    ///
    /// Set this to `true` only if the driver's `run` method polls
    /// `cancel.is_cancelled()` at regular intervals during scanning.
    /// A pre-check before starting does not count as cooperative cancel.
    pub supports_cooperative_cancel: bool,
}

/// Metadata associated with one committed item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemMeta {
    pub version: Option<VersionId>,
    pub size_hint: Option<u64>,
}

/// Finding record used by commit sinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingRecord {
    pub rule_id: u32,
    pub start: u64,
    pub end: u64,
    pub norm_hash: [u8; 32],
    pub confidence_score: i8,
}

/// Batch of findings for one item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FindingsBatch {
    pub findings: Vec<FindingRecord>,
}

/// Per-item commit lifecycle sink.
pub trait CommitSink: Send + Sync {
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()>;
    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()>;
    fn finish_item(&self, item_key: &ItemKey) -> Result<()>;
}

/// No-op sink used by CLI mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOpCommitSink;

impl CommitSink for NoOpCommitSink {
    fn begin_item(&self, _item_key: &ItemKey, _meta: &ItemMeta) -> Result<()> {
        Ok(())
    }

    fn upsert_findings(&self, _item_key: &ItemKey, _batch: &FindingsBatch) -> Result<()> {
        Ok(())
    }

    fn finish_item(&self, _item_key: &ItemKey) -> Result<()> {
        Ok(())
    }
}

/// Source-specific execution backend.
pub trait ScanDriver: Send {
    fn run(
        &mut self,
        engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn EventOutput,
        git_out: Option<&dyn GitEventOutput>,
        commit: &dyn CommitSink,
        cancel: &CancellationToken,
    ) -> Result<ScanReport>;

    fn checkpoint_hint(&self) -> Option<CursorUpdate> {
        None
    }

    fn debug_output(&self) -> Option<String> {
        None
    }
}

/// Factory that maps assignments to source-specific drivers.
pub trait ScanSourceFactory: Send {
    fn driver_for_assignment(&self, assignment: &Assignment) -> Result<Box<dyn ScanDriver>>;

    fn capabilities(&self) -> SourceCapabilities;
}
