//! Unified scan-driver boundary for source-specific execution backends.
//!
//! This crate is the integration seam between scan orchestration (CLI,
//! distributed runtime, coordination layer) and source-specific backends
//! (filesystem, git, in-memory). It defines the shared vocabulary — types,
//! traits, and config — without containing any implementation logic. Concrete
//! driver implementations live in downstream crates, primarily
//! `gossip-connectors`; runtime crates consume these interfaces and bridge them
//! to coordination.
//!
//! # Execution flow
//!
//! ```text
//! Assignment ─► ScanSourceFactory::driver_for_assignment()
//!                        │
//!                        ▼
//!               Box<dyn ScanDriver>
//!                        │
//!          ┌─────────────┼───────────────────┐
//!          │             run()                │
//!          │ Engine + Config + GitEventOutput │
//!          │  + CommitSink + CancellationToken│
//!          │             │                    │
//!          │             ▼                    │
//!          │        ScanReport                │
//!          └─────────────────────────────────-┘
//! ```
//!
//! # Why a separate crate?
//!
//! `gossip-contracts` defines coordination-layer data (shards, cursors,
//! identities). Scan-driver concerns — engines, event sinks, finding batches,
//! cancellation — are orthogonal. Splitting them keeps `gossip-contracts` a
//! lightweight leaf crate and avoids pulling scanner dependencies into the
//! coordination graph.
//!
//! # Consumers
//!
//! | Crate | Role |
//! |-------|------|
//! | `gossip-connectors` | Implements [`ScanDriver`] for FS, Git, and in-memory sources |
//! | `gossip-scanner-runtime` | Builds [`Assignment`]s, calls [`ScanSourceFactory`], and bridges [`ScanReport`] to the coordination layer via `distributed.rs` |

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use gossip_contracts::connector::{Cursor, ItemKey, VersionId};
use gossip_contracts::coordination::ShardSpec;
use gossip_contracts::identity::{PolicyHash, StableItemId};
use scanner_git::{GitEventOutput, GitScanMode, MergeDiffMode};

/// Cooperative cancellation token for long-running scans.
///
/// Shared via [`Arc`] so the caller can signal cancellation from any thread
/// while the driver is running. Drivers are expected to poll [`is_cancelled`]
/// at source-specific scheduling boundaries (e.g., between batch submissions
/// or after each item). A driver that honours mid-scan cancellation should
/// declare [`SourceCapabilities::supports_cooperative_cancel`] `= true`.
///
/// Uses `Release`/`Acquire` ordering to ensure that any state written before
/// [`cancel`] is visible to the driver after it observes cancellation.
///
/// [`is_cancelled`]: CancellationToken::is_cancelled
/// [`cancel`]: CancellationToken::cancel
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

/// Discriminant for the source backend that will execute an [`Assignment`].
///
/// Each variant has a corresponding [`AssignmentSource`] payload and a
/// [`ScanSourceFactory`] implementation that knows how to construct the
/// matching driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorKind {
    /// Local or mounted filesystem walk.
    Filesystem,
    /// Git repository scan (commit-graph traversal or ODB blob fast-path).
    Git,
    /// Pre-loaded in-memory dataset for tests and evaluation harnesses.
    InMemory,
}

/// Source-specific payload carried by an [`Assignment`].
///
/// Must be consistent with [`Assignment::connector_kind`] — a factory will
/// reject the assignment if the variant does not match the expected kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignmentSource {
    /// Root directory to walk for filesystem scans.
    Filesystem { root: PathBuf },
    /// Repository root (the directory containing `.git/`) for git scans.
    Git { repo_root: PathBuf },
    /// Logical dataset identifier for in-memory test harnesses.
    InMemory { dataset_id: String },
}

/// Work unit dispatched to a [`ScanSourceFactory`] to produce a driver.
///
/// In distributed mode, assignments are constructed by the coordination layer
/// from shard claims. In CLI / direct mode, the runtime synthesises a
/// single-shard assignment with a placeholder job ID and initial cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Unique identifier for the parent scan job (used for logging and
    /// tracing, not for deduplication).
    pub job_id: String,
    /// Backend that should execute this assignment.
    pub connector_kind: ConnectorKind,
    /// Stable identifier for the specific connector instance.
    ///
    /// Filesystem and in-memory factories feed these UTF-8 bytes back into
    /// `ConnectorInstanceIdHash::try_from_instance_id_bytes` when reconstructing
    /// stable item identity from assignments. Even for backends that do not yet
    /// consume the value directly (for example the current git scan-driver
    /// path), this string should stay stable across retries and continue to
    /// represent the same logical source instance.
    pub connector_instance_id: String,
    /// Hash of the detection policy active when this assignment was created.
    /// Drivers do not interpret it — it flows through to the engine.
    pub policy_hash: PolicyHash,
    /// Key-range shard that scopes this assignment within the connector's
    /// total keyspace.
    pub shard_spec: ShardSpec,
    /// Resumption cursor from the last successful checkpoint, or
    /// [`Cursor::initial()`] for a fresh scan.
    pub cursor: Cursor,
    /// Source-specific payload (filesystem root, repo path, etc.).
    pub source: AssignmentSource,
}

/// Filesystem-specific runtime knobs.
///
/// Embedded in [`ScanExecutionConfig::filesystem`] and forwarded to the
/// `parallel_scan_dir` scheduler by the filesystem driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemExecutionConfig {
    /// Disable archive (zip/tar/gz) expansion during the walk.
    pub skip_archives: bool,
    /// Skip files classified as binary by content-type sniffing (default: `true`).
    pub skip_binary: bool,
    /// Forward engine findings through the [`CommitSink`] bridge so the
    /// coordination layer can persist per-item identity chains. Only
    /// meaningful in distributed mode — CLI mode uses [`NoOpCommitSink`].
    pub emit_findings_to_commit_sink: bool,
}

impl Default for FilesystemExecutionConfig {
    fn default() -> Self {
        Self {
            skip_archives: false,
            skip_binary: true,
            emit_findings_to_commit_sink: false,
        }
    }
}

/// Top-level runtime configuration passed to every [`ScanDriver::run`] call.
///
/// Contains cross-cutting knobs (worker count, checkpoint interval) plus
/// embedded source-specific sections. Drivers read the section that matches
/// their backend and ignore the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanExecutionConfig {
    /// Number of scanner worker threads. Interpreted as a hint — some
    /// drivers cap or override it (see [`GitExecutionConfig::pack_exec_workers`]).
    pub workers: usize,
    /// Emit a progress / checkpoint event after this many items. The
    /// coordination layer uses these events to track incremental progress
    /// and build resumption cursors.
    pub checkpoint_every_items: u64,
    /// Filesystem-specific overrides.
    pub filesystem: FilesystemExecutionConfig,
    /// Git-specific overrides.
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

/// Diagnostic verbosity for git scan debug output.
///
/// Returned via [`ScanDriver::debug_output`] and printed to stderr by the
/// CLI after the scan completes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitDebugLevel {
    /// No diagnostic output (default).
    #[default]
    Off,
    /// High-level aggregate statistics (ref counts, blob totals).
    Stats,
    /// Detailed per-phase timing and pack-exec performance counters.
    Perf,
}

/// Git-specific runtime knobs.
///
/// Embedded in [`ScanExecutionConfig::git`] and forwarded to the
/// `run_git_scan` entry point by the git driver.
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

/// Aggregate counters returned by [`ScanDriver::run`] after a scan completes.
///
/// Used for coordination-layer bookkeeping (shard progress, error budgets)
/// and CLI summary output. Wall-clock elapsed time is intentionally omitted
/// — callers derive that from their own timers because drivers may spend
/// time outside the scan loop (engine init, path validation, ref resolution)
/// that the coordination layer should not account for. The [`scan_ns`] and
/// [`persist_ns`] fields capture internal phase durations only.
///
/// [`scan_ns`]: ScanReport::scan_ns
/// [`persist_ns`]: ScanReport::persist_ns
///
/// Counter overflow semantics depend on the backend: the in-memory driver
/// uses saturating arithmetic, while the filesystem and git drivers inherit
/// the aggregation strategy of their upstream metrics (currently wrapping).
/// In practice, overflow is not expected for single-scan values.
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
    /// Non-fatal errors encountered during scanning (I/O errors, read
    /// failures, etc.). Does **not** include items that were intentionally
    /// skipped by classification filters (binary, extension, lock-file).
    pub errors: u64,
    /// Items skipped because they were classified as binary by content probe.
    pub binary_skipped: u64,
    /// Items skipped pre-open because extension matched binary skip table.
    pub ext_skipped: u64,
    /// Items skipped pre-open because filename matched lock-file table.
    pub lock_skipped: u64,
    /// Items scanned via extracted text from known binary container formats.
    pub binary_extracted: u64,
    /// Findings dropped by engine caps during scan.
    pub dropped_findings: u64,
    /// Persistence batch emission failures observed by the driver.
    pub persist_emit_failures: u64,
    /// Whether persistence loss counters indicate an incomplete run.
    pub persist_incomplete: bool,
    /// Aggregate scan-loop time in nanoseconds.
    pub scan_ns: u64,
    /// Aggregate persistence emission time in nanoseconds.
    pub persist_ns: u64,
}

/// Incremental progress checkpoint produced by [`ScanDriver::checkpoint_hint`].
///
/// The coordination layer uses this to build resumption cursors so a
/// restarted scan can skip already-committed items. Not all drivers support
/// checkpointing — see [`SourceCapabilities::supports_checkpoint_hints`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorUpdate {
    /// Cursor pointing just past the last fully committed item.
    pub cursor: Cursor,
    /// Running count of items committed up to this cursor position.
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

/// Per-item metadata passed to [`CommitSink::begin_item`].
///
/// Carries connector-provided identity and optional context that the sink may
/// use when persisting identity chains (for example a version ID from a
/// versioned object store).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemMeta {
    /// Connector-assigned stable identity for the scanned item. This must be
    /// computed by the source and trusted by downstream persistence code; the
    /// runtime must not re-derive it from ad hoc tags or raw item keys.
    pub stable_item_id: StableItemId,
    /// Connector-assigned version for the item snapshot being scanned,
    /// if the source supports versioned objects. `None` for unversioned
    /// sources (plain filesystem).
    pub version: Option<VersionId>,
    /// Approximate byte length of the item payload, if known before
    /// scanning. Used for progress estimation, not for correctness.
    pub size_hint: Option<u64>,
}

/// Compact finding record forwarded through the [`CommitSink`] bridge.
///
/// Carries the minimal set of fields the coordination layer needs to
/// derive the full identity chain (`norm_hash → secret_hash → finding_id
/// → occurrence_id`). Richer per-finding details (matched text, transform
/// path) travel through the [`scanner_scheduler::events::EventOutput`] stream
/// instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingRecord {
    /// Numeric identifier of the detection rule that matched.
    pub rule_id: u32,
    /// Byte offset of the match start within the item payload.
    pub start: u64,
    /// Byte offset one past the match end (exclusive).
    pub end: u64,
    /// BLAKE3 digest of the normalised secret bytes. Two findings with
    /// the same `norm_hash` matched the same logical secret regardless of
    /// surrounding context or transform chain.
    pub norm_hash: [u8; 32],
    /// Additive confidence score from gate signals. Conventionally 0–10 but
    /// the `i8` type is not range-restricted — consumers must tolerate
    /// values outside that range. Does **not** participate in dedup — two
    /// findings at the same span with different scores still deduplicate
    /// normally.
    pub confidence_score: i8,
}

/// All findings for a single item, passed to [`CommitSink::upsert_findings`].
///
/// An empty batch is valid — it signals that the item was scanned
/// successfully but produced no matches.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FindingsBatch {
    pub findings: Vec<FindingRecord>,
}

/// Per-item commit lifecycle sink for persisting scan results.
///
/// Drivers call the three methods in strict order for each item:
///
/// 1. [`begin_item`] — register the item and its metadata.
/// 2. [`upsert_findings`] — zero or more calls with finding batches.
/// 3. [`finish_item`] — mark the item as fully scanned.
///
/// In distributed mode the sink derives identity chains and records
/// progress for the coordination layer. In CLI mode, [`NoOpCommitSink`]
/// discards all calls. The git driver currently ignores the sink
/// entirely — git findings flow only through the
/// [`scanner_scheduler::events::EventOutput`] stream.
///
/// [`begin_item`]: CommitSink::begin_item
/// [`upsert_findings`]: CommitSink::upsert_findings
/// [`finish_item`]: CommitSink::finish_item
pub trait CommitSink: Send + Sync {
    /// Open a new item transaction. Must be called before any findings
    /// are upserted for this key.
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()>;

    /// Record one batch of findings for an in-progress item. May be
    /// called multiple times if findings arrive incrementally.
    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()>;

    /// Close the item transaction. After this call, no further findings
    /// may be upserted for this key within the current scan.
    fn finish_item(&self, item_key: &ItemKey) -> Result<()>;
}

/// No-op [`CommitSink`] that discards all calls.
///
/// Used in CLI and direct-mode scans where per-item persistence is not
/// needed. Also used as the commit sink for git scans, which route
/// finding persistence through the git scanner's own event stream instead
/// of the per-item lifecycle.
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
///
/// Implementors own the scan loop for one source type. The runtime provides
/// a shared [`Engine`](scanner_engine::Engine), configuration, output sinks,
/// and a cancellation token; the driver orchestrates source-specific I/O
/// (directory walk, git pack traversal, etc.) and returns aggregate counters
/// in a [`ScanReport`].
///
/// # Implementors
///
/// - `FsScanDriver` — filesystem walk via `parallel_scan_dir`
/// - `GitScanDriver` — git repository via `run_git_scan`
/// - `InMemoryScanDriver` — pre-loaded dataset for tests
pub trait ScanDriver: Send {
    /// Execute the scan and return aggregate counters.
    ///
    /// # Parameters
    ///
    /// - `engine` — compiled detection rules shared across workers.
    /// - `cfg` — runtime knobs (workers, checkpoint interval, source config).
    /// - `out` — event sink for both core and git-specific events.
    /// - `commit` — per-item lifecycle sink for persistence (see [`CommitSink`]).
    /// - `cancel` — cooperative cancellation token; drivers that support it
    ///   poll [`CancellationToken::is_cancelled`] at regular intervals.
    ///
    /// # Errors
    ///
    /// Returns `Err` for fatal failures (repository not found, engine init
    /// failure). Non-fatal per-item errors (I/O, read failures) are counted
    /// in [`ScanReport::errors`] and do not abort the scan.
    fn run(
        &mut self,
        engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn GitEventOutput,
        commit: &dyn CommitSink,
        cancel: &CancellationToken,
    ) -> Result<ScanReport>;

    /// Return the latest incremental progress checkpoint, if available.
    ///
    /// The coordination layer polls this after the scan completes (or is
    /// cancelled) to persist a resumption cursor. Returns `None` when the
    /// driver does not support checkpointing or has not yet committed any
    /// items.
    fn checkpoint_hint(&self) -> Option<CursorUpdate> {
        None
    }

    /// Optional human-readable debug diagnostics generated during the scan.
    ///
    /// Used by the git driver to surface ref-resolution stats and pack-exec
    /// timing. The CLI prints this to stderr after the scan completes.
    fn debug_output(&self) -> Option<String> {
        None
    }
}

/// Factory that maps [`Assignment`]s to source-specific [`ScanDriver`]s.
///
/// The runtime selects a factory based on [`Assignment::connector_kind`],
/// then calls [`driver_for_assignment`] to obtain a boxed driver ready
/// to execute.
///
/// [`driver_for_assignment`]: ScanSourceFactory::driver_for_assignment
pub trait ScanSourceFactory: Send {
    /// Construct a driver for the given assignment.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the assignment's connector kind or source payload
    /// does not match this factory (kind mismatch), or if the source cannot
    /// be opened (e.g., path does not exist).
    fn driver_for_assignment(&self, assignment: &Assignment) -> Result<Box<dyn ScanDriver>>;

    /// Declare what optional lifecycle features this factory's drivers
    /// support. The orchestration layer reads these flags to decide whether
    /// to poll for checkpoints or attempt cooperative cancellation.
    fn capabilities(&self) -> SourceCapabilities;
}
