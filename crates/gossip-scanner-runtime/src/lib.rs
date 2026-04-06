//! Unified scanner runtime: configuration, path validation, engine
//! construction, scan dispatch, and receipt-driven durability plumbing for
//! filesystem and Git source families.
//!
//! # Architecture
//!
//! The runtime sits between CLI / worker entry points and the lower-level
//! `scanner_engine`, `scanner_scheduler`, and `scanner_git` crates. Its job is
//! to:
//!
//! 1. **Validate** user-supplied paths and budget parameters.
//! 2. **Build** a detection engine from rules, transforms, and tuning knobs.
//! 3. **Dispatch** local scans through the appropriate source-family module:
//!    - [`ordered_content`] for filesystem trees and single files.
//!    - [`git_repo`] for local Git repositories.
//! 4. **Drive** distributed durability through the shared receipt vocabulary
//!    and stages: [`commit_model`], [`result_translation`],
//!    [`result_committer`], [`commit_pipeline`], and
//!    [`checkpoint_aggregator`].
//! 5. **Bridge** scan-internal events into caller-owned sinks via bounded
//!    channels and scoped forwarding threads.
//!
//! # Source families
//!
//! | Family | Module | Config type | Dispatcher |
//! |--------|--------|-------------|------------|
//! | Ordered content (fs) | [`ordered_content`] | [`FsScanConfig`] | [`scan_fs`] |
//! | Git repository | [`git_repo`] | [`GitScanConfig`] | [`scan_git`] |
//! | Git repository executor | [`git_executor`] | `GitSelection + GitExecutionLimits` | [`git_executor::ScannerGitExecutor`] |
//!
//! # Execution modes
//!
//! [`ExecutionMode::Direct`] dispatches scans via the scheduler-driven local
//! scan path. [`ExecutionMode::Connector`] selects the family boundary
//! instead: filesystem sources perform ordered page acquisition and validation
//! through `OrderedContentRuntime`, while Git sources use the direct path.
//!
//! # Durability model
//!
//! Local CLI entry points can use no-op commit sinks, but distributed
//! completion is locked to durable per-unit receipts. Scan completion and
//! driver-local checkpoint hints are never authoritative progress signals;
//! [`distributed`] advances shard completion only after
//! [`result_committer::ResultCommitter`] returns receipts that
//! [`checkpoint_aggregator::PrefixCheckpointAggregator`] can fold into the
//! committed prefix.
//!
//! # Event forwarding
//!
//! Scan loops emit events through trait-object sinks (`EventOutput`,
//! `GitEventOutput`). Because the scheduler and git crates own those
//! callbacks on scanner-internal threads, the runtime interposes a
//! bounded `sync_channel` and a scoped forwarding thread so that
//! caller-owned sinks are never called from scan-internal threads.
//! Owned event types (`OwnedCoreEvent`, `OwnedGitEvent`) carry the
//! channel payloads without borrowing into the scan's lifetime.

use std::fmt;
use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};

pub use git_executor::ScannerGitExecutor;
use gossip_connectors::FilesystemConnector;
pub use gossip_contracts::connector::git::GitDebugLevel;
use gossip_contracts::connector::git::GitRefSelection;
use gossip_contracts::identity::{ConnectorInstanceIdHash, ItemIdentityKey, StableItemId};
use gossip_contracts::{
    connector::{Budgets, ConnectorInputError, Cursor, FILESYSTEM_CONNECTOR_TAG},
    coordination::{CursorSemantics, RestoredShardState, ShardSpec},
};
use scanner_engine::TransformId;
use scanner_engine::{AnchorPolicy, Gate, TransformConfig, TransformMode, Tuning};
use scanner_git::{
    CommitIdentityIds, CommitMetaEvent, GitEvent, GitEventOutput, GitScanMode,
    IdentityDictionaryEvent, MergeDiffMode, OidBytes,
};
use scanner_scheduler::events::{
    CoreEvent, DiagnosticEvent, EventOutput, FindingEvent, NullEventOutput, ProgressEvent,
    RedactedNormHash, SummaryEvent,
};
use scanner_scheduler::source_kind::SourceKind;
use scanner_scheduler::store::{
    FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, StoreProducer,
};

// Receipt-driven committed-prefix checkpoint aggregation.
pub mod checkpoint_aggregator;
// CLI entrypoint wiring, argument parsing, and runtime dispatch.
pub mod cli;
// Shared runtime commit vocabulary for family-neutral durability stages.
pub mod commit_model;
// Bounded execution -> commit pipeline for the receipt-driven durability model.
pub mod commit_pipeline;
// Commit-sink compatibility shims for non-durable runtime entry points.
pub mod commit_sink;
// Coordination-backed event sink for distributed scans.
pub mod coordination_sink;
// In-memory Bloom filter for done-ledger prefiltering.
pub(crate) mod done_ledger_bloom;
// Distributed worker runtime and receipt-backed commit plumbing.
pub mod distributed;
// Event sink implementations for CLI and runtime output.
pub mod event_sink;
// Static single-target Git repository discovery source.
pub mod git_discovery;
// Contract-level adapter for mirror-backed Git repository execution.
pub mod git_executor;
// Runtime-backed persistence adapters for scanner-git durability seams.
pub mod git_persistence;
// Worker-local Git mirror lifecycle and deterministic cache-path helpers.
pub mod git_mirror;
// Git-repository runtime boundary for local scans.
pub mod git_repo;
// Ordered-content (filesystem) runtime boundary.
pub mod ordered_content;
// Cross-scanner parity helpers.
pub mod parity;
// Authoritative findings -> done-ledger durable commit stage.
pub mod result_committer;
// Deterministic translation from scan results into persistence-layer rows.
pub mod result_translation;

/// Returns the current wall-clock time as epoch milliseconds (minimum 1).
///
/// The minimum of 1 avoids zero-valued timestamps, which some coordination
/// backends treat as sentinel values. Logs a warning if the system clock
/// returns a pre-epoch or overflow value.
pub(crate) fn epoch_millis_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
    {
        Some(ms) => ms.max(1),
        None => {
            tracing::warn!("system clock pre-epoch or overflow; using fallback timestamp 1");
            1
        }
    }
}

/// How the runtime acquires source items.
///
/// `Direct` dispatches via the local scan implementation. `Connector`
/// selects the source-family boundary: filesystem scans run one ordered
/// connector page acquisition/validation step, while Git connector mode
/// uses the direct path.
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
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid execution mode '{}' (expected 'direct' or 'connector')", raw)]
pub struct ParseExecutionModeError {
    raw: String,
}

/// Anchor extraction mode for rule planning.
///
/// Anchors are short literal strings extracted from rule patterns to drive a
/// fast Vectorscan pre-filter before full regex evaluation. The mode
/// determines whether anchors come from explicit rule annotations or are
/// inferred automatically.
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
///
/// Cloneable handle backed by a shared `AtomicBool`. Runtime scan functions
/// check `is_cancelled()` before starting work and return a default
/// [`ScanReport`] without doing any I/O when the token is set.
///
/// Memory ordering: `cancel()` uses `Release` and `is_cancelled()` uses
/// `Acquire` so that any state written before cancellation is visible to the
/// thread that observes it.
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
    ///
    /// All clones of this token will observe `is_cancelled() == true` after
    /// this call returns.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns the underlying cancellation flag used by scanner-git.
    ///
    /// Scanner-git accepts `&AtomicBool` so it can stay independent from the
    /// runtime crate. Callers that bridge into that pipeline only observe the
    /// cancellation signal itself, so scanner-git uses `Relaxed` loads at read
    /// sites while this token continues to publish cancellation with
    /// `Release`/`Acquire` semantics for runtime-owned state.
    ///
    /// Note: because scanner-git reads with `Relaxed` ordering, there is no
    /// happens-before edge from `cancel()` to the read. On weakly-ordered
    /// architectures, the signal may not be visible for a brief window after
    /// `cancel()` returns. The amortized check interval dominates this delay
    /// in practice.
    #[must_use]
    pub(crate) fn as_atomic(&self) -> &AtomicBool {
        self.cancelled.as_ref()
    }

    /// Returns true when cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Runtime budgets for source scans.
///
/// Both fields must be non-zero. Validation enforces this constraint in
/// three places: before distributed scan dispatch, during connector-mode
/// page acquisition (where `scan_fs_connector` converts these values into
/// connector [`Budgets`] via `Budgets::try_new`), and before ordered-content miss execution. The
/// ordered-content executor consumes these values as real item-count and
/// byte limits; direct local scan paths (`scan_fs_with_runtime`,
/// `scan_git_with_runtime`) still do not use them.
///
/// Defaults target a work-to-overhead ratio where the scan engine is
/// active for tens of milliseconds per page — long enough to amortize
/// coordination round-trips (typically 10–20 ms) and connector I/O
/// setup. At 1–2 GB/s engine throughput, 64 MiB yields ~32–64 ms of
/// scan work per page.  Memory pressure stays bounded because only one
/// 256 KiB scan buffer is live at a time; the byte budget controls how
/// many bytes are *read from the source*, not how much RAM is resident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanBudgets {
    /// Maximum items processed between checkpoints.
    pub max_items: usize,
    /// Total bytes the executor may read from the source per page pass.
    pub max_bytes: u64,
}

impl Default for ScanBudgets {
    fn default() -> Self {
        Self {
            max_items: 4_096,
            max_bytes: 64 * 1024 * 1024, // 64 MiB
        }
    }
}

impl ScanBudgets {
    /// Reject zero-valued runtime budgets before execution starts.
    ///
    /// Ordered-content miss execution treats both fields as hard admission
    /// limits, so a zero value would make progress impossible while looking
    /// like a valid configuration. Returns
    /// [`ScanRuntimeError::ConnectorInput`] naming the offending field.
    pub fn validate(self) -> Result<(), ScanRuntimeError> {
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

/// Configuration for a filesystem (ordered-content) scan.
///
/// Builder methods follow a `with_*` convention and clamp worker counts to a
/// minimum of 1.
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

/// Configuration for a Git repository scan.
///
/// Builder methods follow a `with_*` convention and clamp worker counts to a
/// minimum of 1. Size overrides (`tree_delta_cache_mb`, `engine_chunk_mb`) are
/// specified in MiB and converted to byte counts at dispatch time with
/// overflow checking.
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
    /// Ref-selection policy that determines which refs form the scan start set.
    ///
    /// Translated into a `scanner_git::StartSetConfig` at dispatch time.
    /// Explicit-commit selections are lowered to `ExplicitRefs` containing a
    /// synthetic ref before reaching this field — `GitRefSelection` is always
    /// ref-backed.
    pub ref_selection: GitRefSelection,
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
            ref_selection: GitRefSelection::DefaultBranchOnly,
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

    /// Sets the lowered ref-selection policy for the Git start set.
    ///
    /// The selection controls which refs the scanner walks. For explicit-commit
    /// scans, callers should pass the `ExplicitRefs` variant containing the
    /// synthetic ref name produced by
    /// [`materialize_synthetic_commit_ref`](scanner_git::materialize_synthetic_commit_ref).
    #[must_use]
    pub fn with_ref_selection(mut self, ref_selection: GitRefSelection) -> Self {
        self.ref_selection = ref_selection;
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
///
/// Fields are intentionally flat so callers can log or serialize
/// the report without traversing nested structures. All counter fields
/// are monotonically accumulated during the scan; none are reset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Total items (files / blobs) processed.
    pub items_scanned: u64,
    /// Items deferred by the skip-ahead admission check because they
    /// exceeded the remaining runtime byte budget.
    pub items_deferred: u64,
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

impl std::ops::AddAssign for ScanReport {
    #[allow(clippy::suspicious_op_assign_impl)] // |= for persist_incomplete is intentional (any-incomplete flag)
    fn add_assign(&mut self, rhs: Self) {
        self.items_scanned = self.items_scanned.saturating_add(rhs.items_scanned);
        self.items_deferred = self.items_deferred.saturating_add(rhs.items_deferred);
        self.bytes_scanned = self.bytes_scanned.saturating_add(rhs.bytes_scanned);
        self.chunks_scanned = self.chunks_scanned.saturating_add(rhs.chunks_scanned);
        self.findings_emitted = self.findings_emitted.saturating_add(rhs.findings_emitted);
        self.errors = self.errors.saturating_add(rhs.errors);
        self.binary_skipped = self.binary_skipped.saturating_add(rhs.binary_skipped);
        self.ext_skipped = self.ext_skipped.saturating_add(rhs.ext_skipped);
        self.lock_skipped = self.lock_skipped.saturating_add(rhs.lock_skipped);
        self.binary_extracted = self.binary_extracted.saturating_add(rhs.binary_extracted);
        self.dropped_findings = self.dropped_findings.saturating_add(rhs.dropped_findings);
        self.persist_emit_failures = self
            .persist_emit_failures
            .saturating_add(rhs.persist_emit_failures);
        self.persist_incomplete |= rhs.persist_incomplete;
        self.scan_ns = self.scan_ns.saturating_add(rhs.scan_ns);
        self.persist_ns = self.persist_ns.saturating_add(rhs.persist_ns);
    }
}

/// Incremental progress checkpoint produced by the runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanCheckpoint {
    /// Cursor pointing just past the last fully committed item.
    pub cursor: Cursor,
    /// Running count of units committed up to this cursor position.
    pub committed_units: u64,
}

/// Runtime wiring errors for scan execution.
///
/// Covers the full lifecycle from path validation through engine construction
/// and scan dispatch. Each variant carries enough context for a human-readable
/// error message without requiring access to the original inputs.
#[derive(Debug, thiserror::Error)]
pub enum ScanRuntimeError {
    /// A scan target path failed validation.
    #[error("{origin} path '{}' invalid: {message}", path.display())]
    InvalidPath {
        /// Which subsystem originated the path.
        origin: &'static str,
        /// The path that failed validation.
        path: PathBuf,
        /// Human-readable reason for the failure.
        message: String,
    },
    /// A `git` subprocess exited with a non-zero status.
    #[error("git command failed for '{}' (status={status_code:?}): {stderr}", repo.display())]
    GitCommandFailed {
        /// Repository path the command was invoked against.
        repo: PathBuf,
        /// Process exit code, if available.
        status_code: Option<i32>,
        /// Captured stderr output from the git process.
        stderr: String,
    },
    /// An I/O operation failed during runtime setup.
    #[error("{}", fmt_io_error(.op, .path.as_ref(), .error))]
    Io {
        /// Short description of the operation.
        op: &'static str,
        /// Associated file path, when applicable.
        path: Option<PathBuf>,
        /// Underlying I/O error.
        #[source]
        error: std::io::Error,
    },
    /// The external rules configuration file could not be loaded or parsed.
    #[error("{}", fmt_rules_config_error(.path.as_ref(), .message))]
    RulesConfig {
        /// Path to the rules file, if one was specified.
        path: Option<PathBuf>,
        /// Human-readable parse or load error.
        message: String,
    },
    /// A connector input parameter was invalid.
    #[error("{0}")]
    ConnectorInput(#[source] ConnectorInputError),
    /// Commit OID map reached capacity, preventing consistent findings
    /// translation. The shard should be parked to prevent re-claim loops.
    #[error(
        "git repo-frontier shard '{shard_id}': commit OID map saturated at {entry_limit} entries; {detail}"
    )]
    CommitOidMapSaturated {
        /// Redacted shard identifier for log correlation.
        shard_id: String,
        /// Maximum number of entries the OID map supports.
        entry_limit: usize,
        /// Human-readable context about how saturation was detected.
        detail: String,
    },
    /// The family runtime returned an execution error.
    #[error("runtime execution failed: {0}")]
    Driver(#[source] anyhow::Error),
}

fn fmt_io_error(op: &str, path: Option<&PathBuf>, error: &std::io::Error) -> String {
    match path {
        Some(path) => format!("{op} failed for '{}': {error}", path.display()),
        None => format!("{op} failed: {error}"),
    }
}

fn fmt_rules_config_error(path: Option<&PathBuf>, message: &str) -> String {
    match path {
        Some(path) => format!("rules config error for '{}': {message}", path.display()),
        None => format!("rules config error: {message}"),
    }
}

impl From<ConnectorInputError> for ScanRuntimeError {
    fn from(value: ConnectorInputError) -> Self {
        Self::ConnectorInput(value)
    }
}

/// Execution outcome for one runtime assignment.
///
/// Local entry points consume this for summary reporting, while the
/// distributed worker uses it to hand scan-side information back into
/// coordinator flow control. The authoritative distributed progress signal is
/// the receipt-driven committed prefix, not any driver-local checkpoint hint.
#[derive(Clone, Debug)]
pub struct AssignmentOutcome {
    /// Aggregate counters for the invocation.
    pub report: ScanReport,
    /// Optional driver-local checkpoint hint retained for runtime-local
    /// bookkeeping, never as the authoritative distributed progress signal.
    pub checkpoint_hint: Option<ScanCheckpoint>,
    /// Optional debug diagnostics for stderr output.
    pub debug_output: Option<String>,
}

/// Top-level filesystem scan dispatcher.
///
/// Routes to `scan_fs_direct` or `scan_fs_connector` based on
/// [`FsScanConfig::execution_mode`]. Direct mode runs the local scan;
/// connector mode exercises the ordered-content page-fill boundary.
pub fn scan_fs(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_fs_direct(config),
        ExecutionMode::Connector => scan_fs_connector(config),
    }
}

/// Top-level Git scan dispatcher.
///
/// Routes to `scan_git_direct` or `scan_git_connector` based on
/// [`GitScanConfig::execution_mode`]. Both currently resolve to the same
/// implementation.
pub fn scan_git(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    match config.execution_mode {
        ExecutionMode::Direct => scan_git_direct(config),
        ExecutionMode::Connector => scan_git_connector(config),
    }
}

/// Filesystem scan using null sinks (no event or commit output).
///
/// Suitable for headless / batch scans where only the aggregate report matters.
pub fn scan_fs_direct(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let out = NullEventOutput;
    let commit = commit_sink::CliNoOpCommitSink;
    let cancel = CancellationToken::new();
    scan_fs_with_runtime(config, &out, &commit, &cancel).map(|outcome| outcome.report)
}

/// Connector-mode filesystem scan (single-page validation boundary).
///
/// Validates the target path, constructs a [`FilesystemConnector`], and
/// executes one ordered page acquisition through
/// [`ordered_content::OrderedContentRuntime`]. Content reads, rule execution,
/// and durability are handled by the direct filesystem runtime path.
pub fn scan_fs_connector(config: &FsScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let canonical_path = validate_fs_path(&config.path)?;
    let budgets = Budgets::try_new(config.budgets.max_items, config.budgets.max_bytes, None)?;
    let state = RestoredShardState::new(
        ShardSpec::unbounded(),
        Cursor::initial(),
        CursorSemantics::Completed,
    );
    let runtime_input = ordered_content::OrderedContentRuntimeInput::new(state, budgets);
    let mut source = FilesystemConnector::new(canonical_path);

    match ordered_content::OrderedContentRuntime::execute_source(&mut source, &runtime_input)? {
        ordered_content::OrderedContentExecutionOutcome::ExhaustedEmpty => {
            Ok(ScanReport::default())
        }
        ordered_content::OrderedContentExecutionOutcome::Page(page) => {
            if page.page().state().next_cursor().is_some() {
                let items = page.report().items_scanned;
                tracing::warn!(
                    items_scanned = items,
                    "connector page indicates more items available; \
                     scan result is partial"
                );
            }
            Ok(page.report())
        }
        ordered_content::OrderedContentExecutionOutcome::Stopped(stop) => {
            Err(ScanRuntimeError::Driver(anyhow::anyhow!("{stop}")))
        }
    }
}

/// Git scan using a null event sink (no event output).
///
/// Suitable for headless / batch scans where only the aggregate report matters.
pub fn scan_git_direct(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    let out = scanner_git::NullEventSink;
    let cancel = CancellationToken::new();
    scan_git_with_runtime(config, &out, &cancel).map(|outcome| outcome.report)
}

/// Connector-mode Git scan. Currently delegates to [`scan_git_direct`].
pub fn scan_git_connector(config: &GitScanConfig) -> Result<ScanReport, ScanRuntimeError> {
    scan_git_direct(config)
}

/// Internal filesystem entrypoint that accepts caller-provided sinks.
///
/// Validates the path (must exist and be a file or directory), then delegates
/// to [`ordered_content::scan_local_filesystem`]. Budget validation is not
/// performed here — budgets are consumed by the distributed runtime path only.
pub(crate) fn scan_fs_with_runtime(
    config: &FsScanConfig,
    out: &dyn EventOutput,
    commit: &dyn commit_sink::CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    let canonical_path = validate_fs_path(&config.path)?;
    ordered_content::scan_local_filesystem(config, canonical_path, out, commit, cancel)
}

/// Internal Git entrypoint that accepts a caller-provided event sink.
///
/// Validates the path (must be a directory at the repository root), then
/// delegates to [`git_repo::scan_local_repo`]. Budget validation is not
/// performed here — budgets are consumed by the distributed runtime path only.
pub(crate) fn scan_git_with_runtime(
    config: &GitScanConfig,
    out: &dyn GitEventOutput,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    let canonical_repo = validate_git_repo_path(&config.repo)?;
    git_repo::scan_local_repo(config, canonical_repo, out, cancel)
}

/// Query available hardware parallelism, falling back to 1 on failure.
///
/// Used as the default worker count for [`FsScanConfig`] and [`GitScanConfig`].
pub(crate) fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "failed to query available parallelism, defaulting to 1");
            1
        })
}

/// Bounded channel capacity for scan event forwarding.
///
/// Large enough to buffer a burst of findings without blocking the scan thread,
/// small enough to bound memory when the consumer is slow.
pub(crate) const EVENT_CHANNEL_CAP: usize = 8_192;

/// Bounded channel capacity for commit (persistence) message forwarding.
pub(crate) const COMMIT_CHANNEL_CAP: usize = 1_024;

/// Build a shared detection engine from runtime configuration.
///
/// Loads rules (from file or built-in), filters transforms, applies tuning
/// overrides, and constructs the engine inside `catch_unwind` to convert
/// panics in rule compilation into recoverable [`ScanRuntimeError::RulesConfig`]
/// errors.
pub(crate) fn build_runtime_engine(
    rules_file: Option<&Path>,
    transform_filter: &TransformFilter,
    decode_depth: Option<usize>,
    anchor_mode: AnchorMode,
) -> Result<Arc<scanner_engine::Engine>, ScanRuntimeError> {
    let rules_path = rules_file.map(Path::to_path_buf);
    let rules = load_runtime_rules(rules_file)?;
    let transforms = filtered_runtime_transforms(transform_filter);
    let mut tuning = default_runtime_tuning();
    if let Some(depth) = decode_depth {
        tuning.max_transform_depth = depth;
    }

    let engine = std::panic::catch_unwind(AssertUnwindSafe(|| {
        scanner_engine::Engine::new_with_anchor_policy(
            rules,
            transforms,
            tuning,
            anchor_policy(anchor_mode),
        )
    }))
    .map_err(|payload| ScanRuntimeError::RulesConfig {
        path: rules_path,
        message: panic_payload_message(payload),
    })?;

    Ok(Arc::new(engine))
}

fn load_runtime_rules(
    rules_file: Option<&Path>,
) -> Result<Vec<scanner_engine::RuleSpec>, ScanRuntimeError> {
    match rules_file {
        Some(path) => {
            let content = scanner_engine::read_rules_text(path).map_err(|error| {
                ScanRuntimeError::RulesConfig {
                    path: Some(path.to_path_buf()),
                    message: error.to_string(),
                }
            })?;
            scanner_engine::load_rules_from_content(&content).map_err(|error| {
                ScanRuntimeError::RulesConfig {
                    path: Some(path.to_path_buf()),
                    message: error.to_string(),
                }
            })
        }
        None => Ok(scanner_engine::builtin_rules()),
    }
}

fn filtered_runtime_transforms(filter: &TransformFilter) -> Vec<TransformConfig> {
    let mut transforms = default_runtime_transforms();
    match filter {
        TransformFilter::All => transforms,
        TransformFilter::None => Vec::new(),
        TransformFilter::Only(ids) => {
            transforms.retain(|transform| ids.contains(&transform.id));
            transforms
        }
    }
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

fn default_runtime_tuning() -> Tuning {
    Tuning {
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

fn anchor_policy(mode: AnchorMode) -> AnchorPolicy {
    match mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    }
}

/// Extract a human-readable message from a panic payload.
///
/// Handles `&str` and `String` payloads; falls back to a generic message
/// for other payload types.
fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "engine construction panicked".to_owned()
    }
}

/// Owned event payload sent through the bounded forwarding channel.
///
/// The `Core` variant carries scheduler events (findings, progress, summary,
/// diagnostics). The `Git` variant carries git-specific events (commit
/// metadata, identity dictionary entries). Owning the data decouples the
/// event's lifetime from the scan thread that produced it.
#[derive(Debug)]
pub(crate) enum OwnedDriverEvent {
    Core(OwnedCoreEvent),
    Git(OwnedGitEvent),
}

/// [`EventOutput`] adapter that serializes core events into an owned
/// representation and sends them through a bounded `SyncSender`.
///
/// Send failures are silently dropped — a closed channel means the forwarder
/// thread has exited, and there is no useful recovery action.
#[derive(Clone, Debug)]
pub(crate) struct ChannelEventOutput {
    tx: SyncSender<OwnedDriverEvent>,
}

impl ChannelEventOutput {
    pub(crate) fn new(tx: SyncSender<OwnedDriverEvent>) -> Self {
        Self { tx }
    }
}

impl EventOutput for ChannelEventOutput {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let _ = self
            .tx
            .send(OwnedDriverEvent::Core(OwnedCoreEvent::from_core(event)));
    }

    fn flush(&self) {}
}

impl GitEventOutput for ChannelEventOutput {
    fn emit_git(&self, event: GitEvent<'_>) {
        let _ = self
            .tx
            .send(OwnedDriverEvent::Git(OwnedGitEvent::from_git(event)));
    }
}

/// Drain the event channel and replay each event into `out`.
///
/// Runs on a scoped forwarder thread spawned by the git scan path. Exits
/// when the channel is closed (all senders dropped), then flushes the output
/// sink. Both core and git event variants are replayed so a single channel
/// can carry the full event stream.
pub(crate) fn forward_git_events(out: &dyn GitEventOutput, rx: Receiver<OwnedDriverEvent>) {
    while let Ok(event) = rx.recv() {
        match event {
            OwnedDriverEvent::Core(core) => core.emit_into(out),
            OwnedDriverEvent::Git(git) => git.emit_into(out),
        }
    }
    out.flush();
}

/// Drain the event channel and replay core events into `out`, discarding
/// any git-specific events. Used by the filesystem scan path.
pub(crate) fn forward_core_events(out: &dyn EventOutput, rx: Receiver<OwnedDriverEvent>) {
    while let Ok(event) = rx.recv() {
        if let OwnedDriverEvent::Core(core) = event {
            core.emit_into(out);
        }
    }
    out.flush();
}

/// Derives deterministic [`StableItemId`] values for filesystem objects
/// under a single canonicalized scan root.
///
/// Identity is a three-part hash: the fixed filesystem connector tag, a
/// connector-instance hash derived from the canonical root path, and the
/// normalized forward-slash-separated item key. Two scan roots that
/// resolve to the same canonical path always produce the same instance
/// hash (and therefore the same stable IDs), while distinct roots
/// produce distinct namespaces even for identical relative paths.
///
/// # Platform note
///
/// Identity stability assumes `fs::canonicalize` returns byte-identical
/// results for the same logical directory across invocations. On macOS
/// APFS, directory names containing non-ASCII characters may be stored in
/// NFC or NFD Unicode normalization forms; `fs::canonicalize` preserves
/// whichever form the filesystem reports. Two scans of the same directory
/// created under different normalization forms would produce distinct
/// connector-instance hashes. This edge case (non-ASCII directory names
/// on APFS) does not warrant a `unicode-normalization` dependency.
#[derive(Clone, Debug)]
struct FilesystemIdentityScope {
    canonical_root: PathBuf,
    connector_instance: ConnectorInstanceIdHash,
}

impl FilesystemIdentityScope {
    /// Build one filesystem identity scope for a canonicalized scan root.
    ///
    /// Equivalent input spellings belong to the same connector-instance
    /// namespace because the runtime canonicalizes before constructing this
    /// scope.
    fn from_canonical_root(canonical_root: PathBuf) -> Self {
        debug_assert!(
            canonical_root.is_absolute()
                && !canonical_root.components().any(|c| matches!(
                    c,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )),
            "FilesystemIdentityScope requires a fully canonicalized path \
             (no `.`, no `..`), got: {canonical_root:?}"
        );
        let connector_instance = ConnectorInstanceIdHash::from_instance_id_bytes(
            canonical_root.as_os_str().as_encoded_bytes(),
        );
        Self {
            canonical_root,
            connector_instance,
        }
    }

    /// Normalize a scheduler-produced object path and derive its stable
    /// identity.
    ///
    /// Returns the normalized forward-slash path bytes alongside the
    /// [`StableItemId`]. Fails if the path cannot be made relative to
    /// the canonical root or if the resulting key exceeds `ItemKey`
    /// length limits.
    fn stable_item_id_for_scheduler_path(
        &self,
        object_path: &[u8],
    ) -> Result<(Vec<u8>, StableItemId), FsStoreError> {
        let normalized_path =
            normalize_scheduler_path(&self.canonical_root, object_path).map_err(|error| {
                FsStoreError::backend(format!("path normalization failed: {error}"))
            })?;
        let item_key = gossip_contracts::connector::ItemKey::try_from_slice(&normalized_path)
            .map_err(|error| {
                FsStoreError::backend(format!("normalized item key invalid: {error}"))
            })?;
        let stable_item_id = ItemIdentityKey::new(
            FILESYSTEM_CONNECTOR_TAG,
            self.connector_instance,
            item_key.as_bytes(),
        )
        .stable_id();
        Ok((normalized_path, stable_item_id))
    }
}

/// [`StoreProducer`] adapter that derives stable item identities via
/// [`FilesystemIdentityScope`] and forwards finding batches through a
/// bounded commit channel.
#[derive(Clone, Debug)]
pub(crate) struct ChannelStoreProducer {
    tx: SyncSender<CommitMessage>,
    identity: FilesystemIdentityScope,
}

impl ChannelStoreProducer {
    pub(crate) fn from_canonical_root(
        tx: SyncSender<CommitMessage>,
        canonical_root: PathBuf,
    ) -> Self {
        Self {
            tx,
            identity: FilesystemIdentityScope::from_canonical_root(canonical_root),
        }
    }
}

impl StoreProducer for ChannelStoreProducer {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        let (normalized_path, stable_item_id) = self
            .identity
            .stable_item_id_for_scheduler_path(batch.object_path)?;

        self.tx
            .send(CommitMessage::Batch(OwnedCommitBatch {
                object_path: normalized_path,
                stable_item_id,
                findings: batch.findings.to_vec(),
                discovery_sequence: batch.discovery_sequence,
            }))
            .map_err(|_| FsStoreError::backend("commit forwarding channel closed"))
    }

    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError> {
        self.tx
            .send(CommitMessage::RunLoss(loss))
            .map_err(|_| FsStoreError::backend("commit forwarding channel closed"))
    }

    fn end_run(&self, had_coverage_limits: bool) -> Result<(), FsStoreError> {
        self.tx
            .send(CommitMessage::EndRun(had_coverage_limits))
            .map_err(|_| FsStoreError::backend("commit forwarding channel closed"))
    }
}

/// Messages sent through the commit forwarding channel.
#[derive(Debug)]
pub(crate) enum CommitMessage {
    /// A batch of findings for one scanned item.
    Batch(OwnedCommitBatch),
    /// Run-level loss record. Not forwarded to the commit sink because
    /// `ScanReport` already captures `dropped_findings` and
    /// `persist_emit_failures` from the executor metrics. Present in the
    /// channel because `ChannelStoreProducer` implements `StoreProducer`,
    /// which requires `record_fs_run_loss`.
    RunLoss(FsRunLoss),
    /// End-of-run signal. Not forwarded to the commit sink because
    /// run completion is handled by the caller after the scan function
    /// returns. Present for the same `StoreProducer` trait obligation.
    EndRun(bool),
}

/// Owned finding batch ready for commit-sink forwarding.
#[derive(Debug)]
pub(crate) struct OwnedCommitBatch {
    object_path: Vec<u8>,
    stable_item_id: StableItemId,
    findings: Vec<FsFindingRecord>,
    /// Discovery-order sequence from the sorted file walk. Used by the
    /// commit forwarder to reorder batches so `begin_item` calls respect
    /// the original path-sorted discovery order, ensuring checkpoint
    /// sequence numbers are monotonically consistent with `ItemKey`.
    discovery_sequence: u32,
}

/// Reorder buffer that ensures commit batches are forwarded in
/// discovery order (file-path-sorted) rather than executor processing
/// order (LIFO-reversed).
///
/// The work-stealing executor's LIFO local deque reverses file
/// processing order relative to the sorted discovery order. Without
/// reordering, `ReceiptCommitSink::begin_item` assigns monotonically
/// increasing sequence numbers in *processing* order, causing
/// `PrefixCheckpointAggregator::build_contiguous_prefix` to observe
/// decreasing `ItemKey` values and return `BoundaryRegression`.
///
/// With `workers=1` (enforced for receipt-driven execution), files are
/// processed sequentially: all batches for one file arrive on the
/// channel before any batches for the next file. The buffer exploits
/// this by tracking discovery-sequence transitions: when the incoming
/// `discovery_sequence` changes, the previous sequence is known to be
/// complete and can be flushed if it is the next expected sequence.
///
/// Internally the buffer uses a `VecDeque` indexed by
/// `(discovery_sequence - next_flush)`, giving O(1) insert and O(1)
/// drain per slot with cache-linear iteration. Discovery sequences are
/// dense `u32`s starting from 0, so direct indexing avoids the O(log n)
/// overhead and pointer chasing of a tree-based map.
///
/// When files arrive in near-discovery order, memory stays bounded by
/// the number of in-flight files (`max_in_flight_objects`). When
/// skipped files create gaps, `drain_ready` stalls and all produced
/// batches accumulate until `finish()` drains them at channel close.
///
/// Files that produce zero batches (skipped by extension, binary
/// classification, size limit, or I/O error) create gaps in the
/// discovery-sequence space. `drain_ready` stalls at the first gap
/// because the missing sequence is never marked complete. The
/// `finish()` safety net handles this correctly: it flushes all
/// residual batches in index order (ascending discovery sequence).
/// Under real workloads with skipped files the buffer therefore
/// degrades to sort-at-end rather than streaming, which is acceptable
/// since it runs on a dedicated consumer thread.
struct DiscoveryOrderBuffer {
    /// Batches indexed by `(discovery_sequence - next_flush)`. `None`
    /// slots represent gaps from skipped files that produced zero
    /// batches.
    pending: std::collections::VecDeque<Option<Vec<OwnedCommitBatch>>>,
    /// The discovery sequence currently being received (all batches
    /// arriving on the channel belong to this sequence until it changes).
    current_ds: Option<u32>,
    /// Next discovery sequence to flush (starts at 0, increments after
    /// each successful flush).
    next_flush: u32,
}

impl DiscoveryOrderBuffer {
    fn new() -> Self {
        Self {
            pending: std::collections::VecDeque::new(),
            current_ds: None,
            next_flush: 0,
        }
    }

    /// Accept a batch. When the discovery sequence changes, the previous
    /// sequence is implicitly complete (single-writer guarantee) and
    /// becomes eligible for flushing via [`Self::drain_ready`].
    fn push(&mut self, batch: OwnedCommitBatch) {
        let ds = batch.discovery_sequence;
        if ds < self.next_flush {
            tracing::error!(
                discovery_sequence = ds,
                next_flush = self.next_flush,
                path = %String::from_utf8_lossy(&batch.object_path),
                "batch arrived for already-flushed discovery sequence; \
                 dropping to prevent duplicate forwarding"
            );
            return;
        }
        self.current_ds = Some(ds);
        let idx = (ds - self.next_flush) as usize;
        if idx >= self.pending.len() {
            self.pending.resize_with(idx + 1, || None);
        }
        self.pending[idx].get_or_insert_with(Vec::new).push(batch);
    }

    /// Drain all contiguous complete discovery sequences starting at
    /// `next_flush`, preserving arrival order within each sequence.
    /// A pending sequence is complete when it differs from `current_ds`
    /// (the single-writer guarantee means no more batches will arrive).
    fn drain_ready(&mut self, out: &mut Vec<OwnedCommitBatch>) {
        while Some(self.next_flush) != self.current_ds {
            match self.pending.front() {
                Some(Some(_)) => {
                    // Front slot is populated — flush it.
                    if let Some(Some(batches)) = self.pending.pop_front() {
                        out.extend(batches);
                    }
                }
                Some(None) => {
                    // Gap: skipped file produced zero batches.
                    tracing::debug!(
                        gap_at = self.next_flush,
                        buffered_sequences = self.pending.iter().filter(|s| s.is_some()).count(),
                        "drain stalled at sequence gap (skipped file); \
                         remaining batches deferred to finish()"
                    );
                    break;
                }
                None => break,
            }
            self.next_flush += 1;
        }
    }

    /// Flush all remaining batches in discovery order. Called when the
    /// channel is closed — all sequences are complete at this point.
    /// Iterates the `VecDeque` front-to-back, which is ascending
    /// discovery-sequence order by construction.
    fn finish(self) -> Vec<OwnedCommitBatch> {
        let has_leading_gap = self.pending.front().is_some_and(|slot| slot.is_none());
        if has_leading_gap {
            tracing::debug!(
                expected_next = self.next_flush,
                residual_sequences = self.pending.iter().filter(|s| s.is_some()).count(),
                "discovery order buffer: gaps detected in sequence space"
            );
        }
        let mut out = Vec::new();
        for batches in self.pending.into_iter().flatten() {
            out.extend(batches);
        }
        out
    }
}

/// Drain commit messages from the channel and forward finding batches to
/// the commit sink.
///
/// `RunLoss` and `EndRun` messages are acknowledged but not forwarded:
/// run-level loss counters are already captured in [`ScanReport`] via the
/// executor metrics, and run completion is signaled by the scan function's
/// return. These variants exist in the channel only because
/// [`ChannelStoreProducer`] must satisfy the [`StoreProducer`] trait.
///
/// Captures only the *first* error and continues draining the channel so
/// the sender side does not block. Returns the first error (if any) after
/// the channel is fully drained.
pub(crate) fn forward_commits(
    commit: &dyn commit_sink::CommitSink,
    rx: Receiver<CommitMessage>,
) -> anyhow::Result<()> {
    let mut first_error: Option<anyhow::Error> = None;
    let mut error_count: u64 = 0;
    let mut buffer = DiscoveryOrderBuffer::new();
    let mut ready = Vec::new();

    /// Record an error, keeping only the first. Subsequent errors are
    /// logged individually so operators have a trail for every failure.
    fn record_err(
        result: anyhow::Result<()>,
        first_error: &mut Option<anyhow::Error>,
        error_count: &mut u64,
    ) {
        if let Err(error) = result {
            *error_count += 1;
            if first_error.is_none() {
                *first_error = Some(error);
            } else {
                tracing::warn!(
                    error_number = *error_count,
                    %error,
                    "additional commit forwarding error (only first is propagated)"
                );
            }
        }
    }

    while let Ok(message) = rx.recv() {
        match message {
            CommitMessage::Batch(batch) => {
                buffer.push(batch);
                buffer.drain_ready(&mut ready);
                for b in ready.drain(..) {
                    record_err(
                        forward_commit_batch(commit, b),
                        &mut first_error,
                        &mut error_count,
                    );
                }
            }
            CommitMessage::RunLoss(loss) => {
                tracing::debug!(
                    dropped_findings = loss.dropped_findings,
                    persistence_emit_failures = loss.persistence_emit_failures,
                    "received run-loss record",
                );
            }
            CommitMessage::EndRun(had_coverage_limits) => {
                tracing::debug!(had_coverage_limits, "received end-run signal");
            }
        }
    }

    // Channel closed: flush remaining buffered batches in discovery order.
    for batch in buffer.finish() {
        record_err(
            forward_commit_batch(commit, batch),
            &mut first_error,
            &mut error_count,
        );
    }

    if error_count > 1 {
        tracing::warn!(
            total_errors = error_count,
            "commit forwarding encountered multiple errors; only the first is propagated",
        );
    }

    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

/// Replay one finding batch through the commit sink's begin/upsert/finish
/// lifecycle. Skips the `upsert_findings` call when the batch is empty.
fn forward_commit_batch(
    commit: &dyn commit_sink::CommitSink,
    batch: OwnedCommitBatch,
) -> anyhow::Result<()> {
    let item_key = gossip_contracts::connector::ItemKey::try_from_slice(&batch.object_path)
        .map_err(|error| anyhow::anyhow!("invalid item key from scheduler batch: {error}"))?;
    let meta = commit_sink::ItemMeta {
        stable_item_id: batch.stable_item_id,
        version: None,
        size_hint: None,
    };
    commit.begin_item(&item_key, &meta)?;

    if !batch.findings.is_empty() {
        let findings = batch
            .findings
            .iter()
            .map(|finding| commit_sink::FindingRecord {
                rule_id: finding.rule_id,
                start: finding.blob_offset_start,
                end: finding.blob_offset_end,
                norm_hash: finding.norm_hash,
                confidence_score: finding.confidence_score,
            })
            .collect();
        commit.upsert_findings(&item_key, &commit_sink::FindingsBatch { findings })?;
    }

    commit.finish_item(&item_key)?;
    Ok(())
}

/// Convert an absolute object path emitted by the scheduler into a
/// root-relative, forward-slash-separated byte key suitable for persistence.
///
/// # Special case: single-file scan
///
/// When the scan root *is* the file itself, `strip_prefix` produces an empty
/// relative path. In that case the function returns the file name component
/// of the root as the item key.
///
/// # Platform
///
/// This function relies on `OsStr::from_encoded_bytes_unchecked`, which is
/// sound on Unix (arbitrary bytes are valid OS strings) but requires WTF-8
/// on Windows. The scanner runtime is Unix-only; a compile-time assertion
/// below rejects Windows targets.
///
/// # Internal unsafe
///
/// Uses `OsStr::from_encoded_bytes_unchecked` because `raw_bytes` originates
/// from the scheduler, which always provides valid OS-string-encoded paths.
fn normalize_scheduler_path(root: &Path, raw_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    #[cfg(windows)]
    compile_error!("normalize_scheduler_path relies on Unix byte-string semantics for OsStr");

    // SAFETY: raw_bytes originate from FsFindingBatch::object_path, which the
    // scanner-scheduler populates from std::fs directory traversal. On Unix,
    // any &[u8] is a valid OsStr encoding.
    let os_str = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(raw_bytes) };
    let path = Path::new(os_str);
    let rel = path.strip_prefix(root).map_err(|_| {
        anyhow::anyhow!(
            "batch path '{}' is not under scan root '{}'",
            path.display(),
            root.display()
        )
    })?;

    if rel.as_os_str().is_empty() {
        let file_name = root
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("single-file scan root has no file name"))?;
        let encoded = file_name.as_encoded_bytes().to_vec();
        if encoded.is_empty() {
            anyhow::bail!("single-file scan root encoded to an empty key");
        }
        return Ok(encoded);
    }

    let mut out = Vec::new();
    for component in rel.components() {
        let segment = match component {
            std::path::Component::Normal(segment) => segment,
            _ => anyhow::bail!("path contains non-normal component: {}", rel.display()),
        };
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(segment.as_encoded_bytes());
    }
    if out.is_empty() {
        anyhow::bail!("relative path encoded to empty key: {}", rel.display());
    }
    Ok(out)
}

/// Owned representation of [`CoreEvent`] for cross-thread forwarding and
/// coordination-level persistence.
///
/// Mirrors the borrowed `CoreEvent<'_>` variants but owns all heap data
/// (paths, rule names, messages). Created by `from_core` and replayed by
/// `emit_into`.
#[derive(Clone)]
pub enum OwnedCoreEvent {
    Finding {
        source: SourceKind,
        object_path: Vec<u8>,
        start: u64,
        end: u64,
        rule_id: u32,
        /// Heap-allocated because `FindingEvent.rule_name` is `&'a str`
        /// (lifetime-bound to the engine), not `&'static str`. Changing the
        /// engine's `rule_name()` return type would require a cross-crate
        /// signature change across `scanner_engine` and `scanner_scheduler`.
        rule_name: String,
        /// BLAKE3 digest of the normalized secret content.
        norm_hash: [u8; 32],
        commit_id: Option<u32>,
        change_kind: Option<String>,
        confidence_score: i8,
    },
    Progress {
        source: SourceKind,
        stage: &'static str,
        objects_scanned: u64,
        bytes_scanned: u64,
        findings_emitted: u64,
    },
    Summary {
        source: SourceKind,
        status: &'static str,
        elapsed_ms: u64,
        bytes_scanned: u64,
        findings_emitted: u64,
        errors: u64,
        throughput_mib_s: f64,
    },
    Diagnostic {
        level: &'static str,
        message: String,
    },
}

impl fmt::Debug for OwnedCoreEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finding {
                source,
                object_path,
                start,
                end,
                rule_id,
                rule_name,
                norm_hash: _norm_hash,
                commit_id,
                change_kind,
                confidence_score,
            } => f
                .debug_struct("Finding")
                .field("source", source)
                .field("object_path", object_path)
                .field("start", start)
                .field("end", end)
                .field("rule_id", rule_id)
                .field("rule_name", rule_name)
                // Secret-derived digests are redacted to keep debug output safe.
                .field("norm_hash", &RedactedNormHash)
                .field("commit_id", commit_id)
                .field("change_kind", change_kind)
                .field("confidence_score", confidence_score)
                .finish(),
            Self::Progress {
                source,
                stage,
                objects_scanned,
                bytes_scanned,
                findings_emitted,
            } => f
                .debug_struct("Progress")
                .field("source", source)
                .field("stage", stage)
                .field("objects_scanned", objects_scanned)
                .field("bytes_scanned", bytes_scanned)
                .field("findings_emitted", findings_emitted)
                .finish(),
            Self::Summary {
                source,
                status,
                elapsed_ms,
                bytes_scanned,
                findings_emitted,
                errors,
                throughput_mib_s,
            } => f
                .debug_struct("Summary")
                .field("source", source)
                .field("status", status)
                .field("elapsed_ms", elapsed_ms)
                .field("bytes_scanned", bytes_scanned)
                .field("findings_emitted", findings_emitted)
                .field("errors", errors)
                .field("throughput_mib_s", throughput_mib_s)
                .finish(),
            Self::Diagnostic { level, message } => f
                .debug_struct("Diagnostic")
                .field("level", level)
                .field("message", message)
                .finish(),
        }
    }
}

impl OwnedCoreEvent {
    /// Convert a borrowed scheduler event into an owned event suitable for
    /// cross-thread forwarding and coordination sinks.
    pub(crate) fn from_core(event: CoreEvent<'_>) -> Self {
        match event {
            CoreEvent::Finding(finding) => Self::Finding {
                source: finding.source,
                object_path: finding.object_path.to_vec(),
                start: finding.start,
                end: finding.end,
                rule_id: finding.rule_id,
                rule_name: finding.rule_name.to_owned(),
                norm_hash: finding.norm_hash,
                commit_id: finding.commit_id,
                change_kind: finding.change_kind.map(ToOwned::to_owned),
                confidence_score: finding.confidence_score,
            },
            CoreEvent::Progress(progress) => Self::Progress {
                source: progress.source,
                stage: progress.stage,
                objects_scanned: progress.objects_scanned,
                bytes_scanned: progress.bytes_scanned,
                findings_emitted: progress.findings_emitted,
            },
            CoreEvent::Summary(summary) => Self::Summary {
                source: summary.source,
                status: summary.status,
                elapsed_ms: summary.elapsed_ms,
                bytes_scanned: summary.bytes_scanned,
                findings_emitted: summary.findings_emitted,
                errors: summary.errors,
                throughput_mib_s: summary.throughput_mib_s,
            },
            CoreEvent::Diagnostic(diagnostic) => Self::Diagnostic {
                level: diagnostic.level,
                message: diagnostic.message.to_owned(),
            },
        }
    }

    /// Replay this owned event into a borrowed [`EventOutput`] sink.
    ///
    /// Reconstructs the original borrowed `CoreEvent<'_>` from owned fields
    /// and emits it. This is the second half of the channel-based forwarding
    /// pattern: `from_core` on the producer side, `emit_into` on the consumer.
    pub(crate) fn emit_into(&self, out: &dyn EventOutput) {
        match self {
            Self::Finding {
                source,
                object_path,
                start,
                end,
                rule_id,
                rule_name,
                norm_hash,
                commit_id,
                change_kind,
                confidence_score,
            } => out.emit_core(CoreEvent::Finding(FindingEvent {
                source: *source,
                object_path,
                start: *start,
                end: *end,
                rule_id: *rule_id,
                rule_name,
                norm_hash: *norm_hash,
                commit_id: *commit_id,
                change_kind: change_kind.as_deref(),
                confidence_score: *confidence_score,
            })),
            Self::Progress {
                source,
                stage,
                objects_scanned,
                bytes_scanned,
                findings_emitted,
            } => out.emit_core(CoreEvent::Progress(ProgressEvent {
                source: *source,
                stage,
                objects_scanned: *objects_scanned,
                bytes_scanned: *bytes_scanned,
                findings_emitted: *findings_emitted,
            })),
            Self::Summary {
                source,
                status,
                elapsed_ms,
                bytes_scanned,
                findings_emitted,
                errors,
                throughput_mib_s,
            } => out.emit_core(CoreEvent::Summary(SummaryEvent {
                source: *source,
                status,
                elapsed_ms: *elapsed_ms,
                bytes_scanned: *bytes_scanned,
                findings_emitted: *findings_emitted,
                errors: *errors,
                throughput_mib_s: *throughput_mib_s,
            })),
            Self::Diagnostic { level, message } => {
                out.emit_core(CoreEvent::Diagnostic(DiagnosticEvent { level, message }))
            }
        }
    }
}

impl PartialEq for OwnedCoreEvent {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Finding {
                    source: s1,
                    object_path: p1,
                    start: st1,
                    end: e1,
                    rule_id: r1,
                    rule_name: rn1,
                    norm_hash: nh1,
                    commit_id: c1,
                    change_kind: ck1,
                    confidence_score: cs1,
                },
                Self::Finding {
                    source: s2,
                    object_path: p2,
                    start: st2,
                    end: e2,
                    rule_id: r2,
                    rule_name: rn2,
                    norm_hash: nh2,
                    commit_id: c2,
                    change_kind: ck2,
                    confidence_score: cs2,
                },
            ) => {
                s1 == s2
                    && p1 == p2
                    && st1 == st2
                    && e1 == e2
                    && r1 == r2
                    && rn1 == rn2
                    && nh1 == nh2
                    && c1 == c2
                    && ck1 == ck2
                    && cs1 == cs2
            }
            (
                Self::Progress {
                    source: s1,
                    stage: st1,
                    objects_scanned: os1,
                    bytes_scanned: bs1,
                    findings_emitted: fe1,
                },
                Self::Progress {
                    source: s2,
                    stage: st2,
                    objects_scanned: os2,
                    bytes_scanned: bs2,
                    findings_emitted: fe2,
                },
            ) => s1 == s2 && st1 == st2 && os1 == os2 && bs1 == bs2 && fe1 == fe2,
            (
                Self::Summary {
                    source: s1,
                    status: st1,
                    elapsed_ms: em1,
                    bytes_scanned: bs1,
                    findings_emitted: fe1,
                    errors: er1,
                    throughput_mib_s: t1,
                },
                Self::Summary {
                    source: s2,
                    status: st2,
                    elapsed_ms: em2,
                    bytes_scanned: bs2,
                    findings_emitted: fe2,
                    errors: er2,
                    throughput_mib_s: t2,
                },
            ) => {
                s1 == s2
                    && st1 == st2
                    && em1 == em2
                    && bs1 == bs2
                    && fe1 == fe2
                    && er1 == er2
                    && t1.to_bits() == t2.to_bits()
            }
            (
                Self::Diagnostic {
                    level: l1,
                    message: m1,
                },
                Self::Diagnostic {
                    level: l2,
                    message: m2,
                },
            ) => l1 == l2 && m1 == m2,
            _ => false,
        }
    }
}

/// Owned representation of [`GitEvent`] for cross-thread forwarding.
///
/// Mirrors the borrowed `GitEvent<'_>` variants. Identity dictionary values
/// (arbitrary byte strings) are cloned into owned `Vec<u8>`.
#[derive(Debug)]
pub(crate) enum OwnedGitEvent {
    CommitMeta {
        commit_id: u32,
        commit_oid: OidBytes,
        timestamp: u64,
        identity: Option<CommitIdentityIds>,
    },
    IdentityDictionary {
        id: u32,
        value: Vec<u8>,
    },
}

impl OwnedGitEvent {
    fn from_git(event: GitEvent<'_>) -> Self {
        match event {
            GitEvent::CommitMeta(meta) => Self::CommitMeta {
                commit_id: meta.commit_id,
                commit_oid: meta.commit_oid,
                timestamp: meta.timestamp,
                identity: meta.identity,
            },
            GitEvent::IdentityDictionary(entry) => Self::IdentityDictionary {
                id: entry.id,
                value: entry.value.to_vec(),
            },
        }
    }

    /// Replay this owned git event into a borrowed [`GitEventOutput`] sink.
    fn emit_into(&self, out: &dyn GitEventOutput) {
        match self {
            Self::CommitMeta {
                commit_id,
                commit_oid,
                timestamp,
                identity,
            } => out.emit_git(GitEvent::CommitMeta(CommitMetaEvent {
                commit_id: *commit_id,
                commit_oid: *commit_oid,
                timestamp: *timestamp,
                identity: *identity,
            })),
            Self::IdentityDictionary { id, value } => {
                out.emit_git(GitEvent::IdentityDictionary(IdentityDictionaryEvent {
                    id: *id,
                    value,
                }))
            }
        }
    }
}

/// Join a scoped thread handle, converting a panic into an `anyhow::Error`
/// that names the thread for diagnostics.
pub(crate) fn join_scoped<T>(
    handle: std::thread::ScopedJoinHandle<'_, T>,
    thread_name: &str,
) -> anyhow::Result<T> {
    handle.join().map_err(|payload| {
        anyhow::anyhow!("{thread_name} panicked: {}", panic_payload_message(payload))
    })
}

/// Validate a filesystem scan target path.
///
/// Returns the canonicalized path on success. Rejects paths that do not exist
/// or are neither a regular file nor a directory (e.g. symlinks to special
/// files, device nodes).
///
/// `fs::metadata` runs first to check existence and classify the path kind.
/// `NotFound` maps to `InvalidPath` (bad user input); other I/O failures
/// (e.g. `PermissionDenied`) map to `Io` to preserve the underlying error
/// chain. `fs::canonicalize` follows only when the kind is acceptable,
/// avoiding a redundant second stat on the already-resolved path.
fn validate_fs_path(path: &Path) -> Result<PathBuf, ScanRuntimeError> {
    let meta = fs::metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => ScanRuntimeError::InvalidPath {
            origin: "filesystem",
            path: path.to_path_buf(),
            message: "path does not exist".to_owned(),
        },
        _ => ScanRuntimeError::Io {
            op: "metadata",
            path: Some(path.to_path_buf()),
            error,
        },
    })?;
    if !meta.is_file() && !meta.is_dir() {
        return Err(ScanRuntimeError::InvalidPath {
            origin: "filesystem",
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

/// Validate a Git scan target path.
///
/// Checks that `path` exists, is a directory, is a valid Git repository
/// (via `git rev-parse --show-toplevel`), and that the canonicalized path
/// matches the repository root. Subdirectories of a repository are rejected
/// to prevent accidental partial scans.
fn validate_git_repo_path(path: &Path) -> Result<PathBuf, ScanRuntimeError> {
    if !path.exists() {
        return Err(ScanRuntimeError::InvalidPath {
            origin: "git",
            path: path.to_path_buf(),
            message: "path does not exist".to_owned(),
        });
    }
    if !path.is_dir() {
        return Err(ScanRuntimeError::InvalidPath {
            origin: "git",
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
            origin: "git",
            path: path.to_path_buf(),
            message: format!(
                "path is inside a git repository but is not the repository root (root is '{}')",
                canonical_toplevel.display()
            ),
        });
    }

    Ok(canonical_input)
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_fixtures;

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

#[cfg(test)]
mod runtime_durability_tests;
