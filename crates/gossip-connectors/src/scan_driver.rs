//! Scan-driver adapters that bridge connector assignments to scheduler runners.
//!
//! These wrappers intentionally live in a gossip-side crate so scanner crates
//! remain independent leaf crates.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::{Receiver, Sender, unbounded};
use gossip_contracts::connector::ItemKey;
use gossip_contracts::identity::{ConnectorInstanceIdHash, StableItemId};
use gossip_scan_driver::{
    Assignment, AssignmentSource, CommitSink, ConnectorKind, CursorUpdate, FindingRecord,
    FindingsBatch, GitDebugLevel, ItemMeta, ScanDriver, ScanExecutionConfig, ScanReport,
    ScanSourceFactory, SourceCapabilities,
};
use scanner_git::{
    CommitIdentityIds, CommitMetaEvent, EventSink as GitEventSink, GitEvent, GitEventOutput,
    GitScanConfig, GitScanResult, IdentityDictionaryEvent, NativeRefResolver, NeverSeenStore,
    OidBytes, RefWatermarkStore, RepoOpenError, StartSetConfig, run_git_scan,
};
use scanner_scheduler::events::{
    CoreEvent, DiagnosticEvent, EventOutput, FindingEvent, ProgressEvent, SummaryEvent,
};
use scanner_scheduler::parallel_scan::{ParallelScanConfig, parallel_scan_dir};
use scanner_scheduler::source_kind::SourceKind;
use scanner_scheduler::store::{
    FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, StoreProducer,
};

use crate::common::derive_stable_item_id;
use crate::filesystem::FILESYSTEM_CONNECTOR_TAG;
use crate::in_memory::{IN_MEMORY_CONNECTOR_TAG, MemItem};

/// Factory for filesystem assignments.
#[derive(Clone, Copy, Debug, Default)]
pub struct FilesystemScanSourceFactory;

/// Build a filesystem driver from an assignment and preserve its shard bounds.
///
/// The bounds are stored on the driver even though `parallel_scan_dir` cannot
/// consume them yet, so assignment metadata is not lost as execution paths
/// evolve toward connector-backed filesystem enumeration.
fn filesystem_driver_from_assignment(assignment: &Assignment) -> Result<FsScanDriver> {
    if assignment.connector_kind != ConnectorKind::Filesystem {
        bail!(
            "assignment kind mismatch: expected filesystem, got {:?}",
            assignment.connector_kind
        );
    }

    let AssignmentSource::Filesystem { root } = &assignment.source else {
        bail!("filesystem assignment missing filesystem source payload");
    };
    let connector_instance = ConnectorInstanceIdHash::try_from_instance_id_bytes(
        assignment.connector_instance_id.as_bytes(),
    )
    .map_err(|error| anyhow!("invalid filesystem connector_instance_id: {error}"))?;

    Ok(FsScanDriver {
        root: root.clone(),
        connector_instance,
        checkpoint_hint: None,
        shard_start: assignment.shard_spec.key_range_start().into(),
        shard_end: assignment.shard_spec.key_range_end().into(),
    })
}

impl ScanSourceFactory for FilesystemScanSourceFactory {
    fn driver_for_assignment(&self, assignment: &Assignment) -> Result<Box<dyn ScanDriver>> {
        Ok(Box::new(filesystem_driver_from_assignment(assignment)?))
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            supports_checkpoint_hints: true,
            // parallel_scan_dir does not accept a cancellation token and has no
            // mid-scan cancellation mechanism. The driver only checks the token
            // before starting (pre-check), not during the scan.
            supports_cooperative_cancel: false,
        }
    }
}

/// Factory for git assignments.
#[derive(Clone, Copy, Debug, Default)]
pub struct GitScanSourceFactory;

impl ScanSourceFactory for GitScanSourceFactory {
    fn driver_for_assignment(&self, assignment: &Assignment) -> Result<Box<dyn ScanDriver>> {
        if assignment.connector_kind != ConnectorKind::Git {
            bail!(
                "assignment kind mismatch: expected git, got {:?}",
                assignment.connector_kind
            );
        }

        let AssignmentSource::Git { repo_root } = &assignment.source else {
            bail!("git assignment missing git source payload");
        };

        Ok(Box::new(GitScanDriver {
            repo_root: repo_root.clone(),
            debug_output: None,
        }))
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            supports_checkpoint_hints: false,
            supports_cooperative_cancel: false,
        }
    }
}

/// Factory for in-memory dataset assignments used in tests/harnesses.
#[derive(Clone, Debug)]
pub struct InMemoryScanSourceFactory {
    dataset_id: String,
    items: Arc<[MemItem]>,
}

impl InMemoryScanSourceFactory {
    /// Create a new factory for the given dataset.
    ///
    /// Items are sorted by key so the driver produces deterministic scan order
    /// regardless of the caller's insertion order.
    #[must_use]
    pub fn new(dataset_id: impl Into<String>, mut items: Vec<MemItem>) -> Self {
        items.sort_by(|left, right| left.key.cmp(&right.key));
        Self {
            dataset_id: dataset_id.into(),
            items: items.into(),
        }
    }
}

impl ScanSourceFactory for InMemoryScanSourceFactory {
    fn driver_for_assignment(&self, assignment: &Assignment) -> Result<Box<dyn ScanDriver>> {
        if assignment.connector_kind != ConnectorKind::InMemory {
            bail!(
                "assignment kind mismatch: expected in-memory, got {:?}",
                assignment.connector_kind
            );
        }

        let AssignmentSource::InMemory { dataset_id } = &assignment.source else {
            bail!("in-memory assignment missing in-memory source payload");
        };
        if dataset_id != &self.dataset_id {
            bail!(
                "assignment dataset_id mismatch: expected '{}', got '{}'",
                self.dataset_id,
                dataset_id
            );
        }
        let connector_instance = ConnectorInstanceIdHash::try_from_instance_id_bytes(
            assignment.connector_instance_id.as_bytes(),
        )
        .map_err(|error| anyhow!("invalid in-memory connector_instance_id: {error}"))?;

        Ok(Box::new(InMemoryScanDriver {
            items: Arc::clone(&self.items),
            connector_instance,
            checkpoint_hint: None,
        }))
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            supports_checkpoint_hints: true,
            supports_cooperative_cancel: true,
        }
    }
}

/// Filesystem scan driver backed by [`parallel_scan_dir`].
///
/// Spawns scoped threads for event and commit forwarding so the scheduler's
/// channel-based sinks are bridged to the [`EventOutput`] / [`CommitSink`]
/// interfaces expected by the coordination layer.
#[derive(Debug)]
struct FsScanDriver {
    root: PathBuf,
    connector_instance: ConnectorInstanceIdHash,
    checkpoint_hint: Option<CursorUpdate>,
    /// Inclusive assignment lower bound (`[]` means unbounded).
    shard_start: Box<[u8]>,
    /// Exclusive assignment upper bound (`[]` means unbounded).
    shard_end: Box<[u8]>,
}

impl FsScanDriver {
    /// Return shard bounds as `Option` slices (empty vec → `None`).
    ///
    /// Not yet consumed by `parallel_scan_dir` — will be wired into
    /// `FilesystemConnector::with_shard_bounds` once the scan path is
    /// connector-backed.
    #[allow(dead_code)]
    fn shard_bounds(&self) -> (Option<&[u8]>, Option<&[u8]>) {
        (
            (!self.shard_start.is_empty()).then_some(&self.shard_start),
            (!self.shard_end.is_empty()).then_some(&self.shard_end),
        )
    }
}

impl ScanDriver for FsScanDriver {
    fn run(
        &mut self,
        engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn EventOutput,
        _git_out: Option<&dyn GitEventOutput>,
        commit: &dyn CommitSink,
        cancel: &gossip_scan_driver::CancellationToken,
    ) -> Result<ScanReport> {
        std::thread::scope(|scope| -> Result<ScanReport> {
            // TODO: pass shard_start/shard_end to FilesystemConnector via
            // `with_shard_bounds` once parallel_scan_dir is replaced by a
            // connector-backed enumeration path. Bounds are stored on the
            // driver (populated from the assignment's ShardSpec) but cannot
            // be applied yet because parallel_scan_dir has no key-range API.

            let (event_tx, event_rx) = unbounded();
            let event_forwarder = scope.spawn(move || forward_events(out, None, event_rx));

            let (commit_tx, commit_rx) = unbounded();
            let commit_forwarder = scope.spawn(move || forward_commits(commit, commit_rx));

            let mut scan_cfg = ParallelScanConfig {
                workers: cfg.workers.max(1),
                event_sink: Arc::new(ChannelEventOutput::new(event_tx.clone())),
                skip_binary: cfg.filesystem.skip_binary,
                ..ParallelScanConfig::default()
            };
            if cfg.filesystem.skip_archives {
                scan_cfg.archive.enabled = false;
            }
            if cfg.filesystem.emit_findings_to_commit_sink {
                scan_cfg.store_producer = Some(Arc::new(ChannelStoreProducer::new(
                    commit_tx.clone(),
                    self.root.clone(),
                    self.connector_instance,
                )));
            }

            let scan_start = std::time::Instant::now();
            let report = if cancel.is_cancelled() {
                scanner_scheduler::scheduler::local_fs_owner::LocalReport::default()
            } else {
                parallel_scan_dir(&self.root, engine, scan_cfg).with_context(|| {
                    format!("filesystem scan failed for {}", self.root.display())
                })?
            };
            let scan_elapsed = scan_start.elapsed();

            // Filesystem scans currently restart from the beginning on resume
            // because `parallel_scan_dir` does not track per-item cursor state.
            // A `CursorUpdate` with `Cursor::initial()` would be semantically
            // wrong (it means "no progress"), so we leave the checkpoint as None.
            // TODO: track last scanned file path to enable resumable FS scans.

            drop(event_tx);
            drop(commit_tx);

            join_scoped(event_forwarder, "event forwarder thread")?;
            join_scoped(commit_forwarder, "commit forwarder thread")??;

            Ok(ScanReport {
                items_scanned: report.stats.files_enqueued,
                bytes_scanned: report.metrics.bytes_scanned,
                chunks_scanned: report.metrics.chunks_scanned,
                findings_emitted: report.metrics.findings_emitted,
                errors: report.metrics.io_errors,
                binary_skipped: report.metrics.binary_skipped,
                ext_skipped: report.metrics.ext_skipped,
                lock_skipped: report.metrics.lock_skipped,
                binary_extracted: report.metrics.binary_extracted,
                dropped_findings: report.stats.dropped_findings,
                persist_emit_failures: report.stats.persistence_emit_failures,
                persist_incomplete: report.stats.persistence_incomplete,
                scan_ns: u64::try_from(scan_elapsed.as_nanos()).unwrap_or(u64::MAX),
                persist_ns: report.metrics.persist_ns,
            })
        })
    }

    fn checkpoint_hint(&self) -> Option<CursorUpdate> {
        self.checkpoint_hint.clone()
    }
}

/// Git scan driver backed by [`run_git_scan`].
///
/// Resolves refs via [`NativeRefResolver`] and treats every ref
/// as unseen ([`EmptyWatermarkStore`]), performing a full scan on each run.
#[derive(Debug)]
struct GitScanDriver {
    repo_root: PathBuf,
    debug_output: Option<String>,
}

impl ScanDriver for GitScanDriver {
    /// Run the git scan driver.
    ///
    /// **Note:** The `commit` sink is intentionally unused. Git scans operate
    /// on a commit-graph model (ref watermarks, seen-blob deduplication) that
    /// does not map to the per-item begin/finish lifecycle of the commit sink.
    /// Persistence for git findings is handled separately via the git scanner's
    /// `PersistenceStore` (currently passed as `None` until git persistence is
    /// integrated with the coordination backend).
    fn run(
        &mut self,
        engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn EventOutput,
        git_out: Option<&dyn GitEventOutput>,
        _commit: &dyn CommitSink,
        cancel: &gossip_scan_driver::CancellationToken,
    ) -> Result<ScanReport> {
        self.debug_output = None;
        if cancel.is_cancelled() {
            return Ok(ScanReport::default());
        }

        std::thread::scope(|scope| -> Result<ScanReport> {
            let (event_tx, event_rx) = unbounded();
            let event_forwarder = scope.spawn(move || forward_events(out, git_out, event_rx));

            let git_sink: Arc<dyn GitEventSink> =
                Arc::new(ChannelGitEventOutput::new(event_tx.clone()));

            let git_cfg = build_git_scan_config(cfg)?;

            let resolver = NativeRefResolver::new(StartSetConfig::DefaultBranchOnly);
            let watermarks = EmptyWatermarkStore;
            let seen = NeverSeenStore;
            let scan_start = std::time::Instant::now();
            let result = run_git_scan(
                &self.repo_root,
                engine,
                &resolver,
                &seen,
                &watermarks,
                None,
                &git_cfg,
                git_sink,
            )
            .with_context(|| format!("git scan failed for {}", self.repo_root.display()))?;
            let scan_elapsed = scan_start.elapsed();

            self.debug_output = format_git_debug_output(&result.0, cfg.git.debug_level);
            drop(event_tx);
            join_scoped(event_forwarder, "event forwarder thread")?;

            Ok(git_report_to_scan_report(result, scan_elapsed))
        })
    }

    fn debug_output(&self) -> Option<String> {
        self.debug_output.clone()
    }
}

/// In-memory scan driver for tests and harnesses.
///
/// Iterates pre-loaded items sequentially, driving the commit-sink lifecycle
/// (begin/finish) and emitting checkpoint hints at configured intervals.
/// Does not invoke the scanner engine.
#[derive(Debug)]
struct InMemoryScanDriver {
    items: Arc<[MemItem]>,
    connector_instance: ConnectorInstanceIdHash,
    checkpoint_hint: Option<CursorUpdate>,
}

impl ScanDriver for InMemoryScanDriver {
    /// Run the in-memory scan driver.
    ///
    /// **Note:** The `engine` parameter is intentionally unused. This driver
    /// is a test/harness adapter that exercises the commit-sink lifecycle
    /// (begin_item / finish_item) and checkpoint machinery without running
    /// the scanner engine. Tests that need engine integration should use
    /// the filesystem or git drivers.
    fn run(
        &mut self,
        _engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn EventOutput,
        _git_out: Option<&dyn GitEventOutput>,
        commit: &dyn CommitSink,
        cancel: &gossip_scan_driver::CancellationToken,
    ) -> Result<ScanReport> {
        let mut report = ScanReport::default();
        let checkpoint_every = cfg.checkpoint_every_items.max(1);

        for item in self.items.iter() {
            if cancel.is_cancelled() {
                break;
            }

            let meta = ItemMeta {
                stable_item_id: derive_stable_item_id(
                    IN_MEMORY_CONNECTOR_TAG,
                    self.connector_instance,
                    &item.key,
                ),
                version: None,
                size_hint: Some(item.bytes.len() as u64),
            };
            commit.begin_item(&item.key, &meta)?;
            commit.finish_item(&item.key)?;

            report.items_scanned = report.items_scanned.saturating_add(1);
            report.bytes_scanned = report.bytes_scanned.saturating_add(item.bytes.len() as u64);

            if report.items_scanned % checkpoint_every == 0 {
                self.checkpoint_hint = Some(CursorUpdate {
                    cursor: gossip_contracts::connector::Cursor::with_last_key(item.key.clone()),
                    committed_items: report.items_scanned,
                });
                // SourceKind::Fs is used because no InMemory variant exists in
                // the scanner-scheduler crate. The `stage: "in-memory"` field
                // disambiguates these events from actual filesystem progress.
                out.emit_core(CoreEvent::Progress(ProgressEvent {
                    source: SourceKind::Fs,
                    stage: "in-memory",
                    objects_scanned: report.items_scanned,
                    bytes_scanned: report.bytes_scanned,
                    findings_emitted: report.findings_emitted,
                }));
            }
        }

        Ok(report)
    }

    fn checkpoint_hint(&self) -> Option<CursorUpdate> {
        self.checkpoint_hint.clone()
    }
}

/// [`EventOutput`] adapter that serializes events into a channel as
/// owned event values for cross-thread forwarding.
#[derive(Clone, Debug)]
struct ChannelEventOutput {
    tx: Sender<OwnedDriverEvent>,
}

impl ChannelEventOutput {
    fn new(tx: Sender<OwnedDriverEvent>) -> Self {
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

/// Git-aware event output that forwards both core and git events through
/// a channel for cross-thread emission into runtime sinks.
#[derive(Clone, Debug)]
struct ChannelGitEventOutput {
    inner: ChannelEventOutput,
}

impl ChannelGitEventOutput {
    fn new(tx: Sender<OwnedDriverEvent>) -> Self {
        Self {
            inner: ChannelEventOutput::new(tx),
        }
    }
}

impl EventOutput for ChannelGitEventOutput {
    fn emit_core(&self, event: CoreEvent<'_>) {
        self.inner.emit_core(event);
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

impl GitEventOutput for ChannelGitEventOutput {
    fn emit_git(&self, event: GitEvent<'_>) {
        let _ = self
            .inner
            .tx
            .send(OwnedDriverEvent::Git(OwnedGitEvent::from_git(event)));
    }
}

/// [`StoreProducer`] adapter that normalizes scheduler paths to the connector's
/// relative key encoding and forwards batches through a channel.
#[derive(Clone, Debug)]
struct ChannelStoreProducer {
    tx: Sender<CommitMessage>,
    /// Scan root used to strip the absolute prefix from scheduler paths,
    /// yielding `/`-separated relative keys matching the connector keyspace.
    root: PathBuf,
    connector_instance: ConnectorInstanceIdHash,
}

impl ChannelStoreProducer {
    fn new(
        tx: Sender<CommitMessage>,
        root: PathBuf,
        connector_instance: ConnectorInstanceIdHash,
    ) -> Self {
        Self {
            tx,
            root,
            connector_instance,
        }
    }
}

impl StoreProducer for ChannelStoreProducer {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        // Normalize the scheduler's absolute OS path to the connector's
        // relative key encoding before forwarding through the channel.
        let normalized_path = normalize_scheduler_path(&self.root, batch.object_path)
            .map_err(|e| FsStoreError::backend(format!("path normalization failed: {e}")))?;
        let item_key = ItemKey::try_from_slice(&normalized_path)
            .map_err(|e| FsStoreError::backend(format!("normalized item key invalid: {e}")))?;
        let stable_item_id =
            derive_stable_item_id(FILESYSTEM_CONNECTOR_TAG, self.connector_instance, &item_key);
        self.tx
            .send(CommitMessage::Batch(OwnedCommitBatch {
                object_path: normalized_path,
                stable_item_id,
                findings: batch.findings.to_vec(),
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

/// Messages forwarded from the scheduler's [`StoreProducer`] to the
/// coordination layer's [`CommitSink`] via a crossbeam channel.
#[derive(Debug)]
enum CommitMessage {
    Batch(OwnedCommitBatch),
    RunLoss(FsRunLoss),
    EndRun(bool),
}

#[derive(Debug)]
struct OwnedCommitBatch {
    object_path: Vec<u8>,
    stable_item_id: StableItemId,
    findings: Vec<FsFindingRecord>,
}

/// Drain owned events from `rx` and re-emit them into `out` as borrowed
/// event values, flushing when the channel closes.
fn forward_events(
    out: &dyn EventOutput,
    git_out: Option<&dyn GitEventOutput>,
    rx: Receiver<OwnedDriverEvent>,
) {
    while let Ok(event) = rx.recv() {
        match event {
            OwnedDriverEvent::Core(core) => core.emit_into(out),
            OwnedDriverEvent::Git(git) => {
                if let Some(sink) = git_out {
                    git.emit_into(sink);
                }
            }
        }
    }
    out.flush();
    if let Some(sink) = git_out {
        sink.flush();
    }
}

/// Forward commit messages from the channel to the commit sink.
///
/// On error, the first failure is captured but the loop continues draining
/// the channel. This is intentional: breaking out of the loop on first error
/// would leave messages in the channel, preventing sender threads from
/// completing and causing the scoped thread join to deadlock. The first error
/// is returned after the channel is fully drained.
fn forward_commits(commit: &dyn CommitSink, rx: Receiver<CommitMessage>) -> Result<()> {
    let mut first_error: Option<anyhow::Error> = None;

    while let Ok(message) = rx.recv() {
        let result = match message {
            CommitMessage::Batch(batch) => forward_commit_batch(commit, batch),
            CommitMessage::RunLoss(_loss) => Ok(()),
            CommitMessage::EndRun(_had_coverage_limits) => Ok(()),
        };

        if first_error.is_none()
            && let Err(error) = result
        {
            first_error = Some(error);
        }
    }

    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

/// Normalize an absolute OS path (from the scheduler) into the connector's
/// relative `/`-separated key encoding.
///
/// The scheduler stores absolute OS-encoded paths in `FsFindingBatch.object_path`
/// (via `task.path.as_os_str().as_encoded_bytes()`), but the filesystem connector
/// encodes `ItemKey` values as root-relative `/`-separated byte strings (via
/// `strip_prefix(root)` + `encode_rel_path` in `filesystem.rs`). This function
/// bridges the two representations so commit-sink keys align with connector cursors.
fn normalize_scheduler_path(root: &Path, raw_bytes: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: The scheduler produced these bytes via
    // `path.as_os_str().as_encoded_bytes()`, so they are valid platform-encoded
    // bytes that round-trip correctly through `from_encoded_bytes_unchecked`.
    let os_str = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(raw_bytes) };
    let path = Path::new(os_str);
    let rel = path.strip_prefix(root).with_context(|| {
        format!(
            "batch path '{}' is not under scan root '{}'",
            path.display(),
            root.display()
        )
    })?;

    // Re-encode as `/`-separated relative bytes, matching the connector's
    // `encode_rel_path` contract (only Normal components, joined with `/`).
    let mut out = Vec::new();
    for component in rel.components() {
        let segment = match component {
            std::path::Component::Normal(s) => s,
            _ => bail!("path contains non-normal component: {}", rel.display()),
        };
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(segment.as_encoded_bytes());
    }
    if out.is_empty() {
        bail!("relative path encoded to empty key: {}", rel.display());
    }
    Ok(out)
}

/// Map a scheduler batch to the [`CommitSink`] lifecycle:
/// `begin_item` → `upsert_findings` (if any) → `finish_item`.
fn forward_commit_batch(commit: &dyn CommitSink, batch: OwnedCommitBatch) -> Result<()> {
    let item_key = ItemKey::try_from_slice(&batch.object_path)
        .map_err(|error| anyhow!("invalid item key from scheduler batch: {error}"))?;
    let meta = ItemMeta {
        stable_item_id: batch.stable_item_id,
        version: None,
        size_hint: None,
    };
    commit.begin_item(&item_key, &meta)?;

    if !batch.findings.is_empty() {
        let mut findings = Vec::with_capacity(batch.findings.len());
        for finding in &batch.findings {
            findings.push(FindingRecord {
                rule_id: finding.rule_id,
                start: finding.span_start,
                end: finding.span_end,
                norm_hash: finding.norm_hash,
                confidence_score: finding.confidence_score,
            });
        }
        commit.upsert_findings(&item_key, &FindingsBatch { findings })?;
    }

    commit.finish_item(&item_key)?;
    Ok(())
}

/// Convert a git scanner result into the generic [`ScanReport`] used by
/// the coordination layer.
fn git_report_to_scan_report(
    result: GitScanResult,
    scan_elapsed: std::time::Duration,
) -> ScanReport {
    let report = result.0;
    let metrics = report.common_metrics;
    // Prefer the stage-level timer when available; fall back to the
    // wall-clock duration around `run_git_scan`. The fallback may include
    // internal setup (repo open, MIDX parse) not captured by the stage
    // timer, so the two sources are not directly comparable if
    // `stage_nanos.scan` starts being populated mid-process.
    let scan_ns = if report.stage_nanos.scan > 0 {
        report.stage_nanos.scan
    } else {
        u64::try_from(scan_elapsed.as_nanos()).unwrap_or(u64::MAX)
    };
    ScanReport {
        items_scanned: metrics.objects_scanned,
        bytes_scanned: metrics.bytes_scanned,
        chunks_scanned: metrics.chunks_scanned,
        findings_emitted: metrics.findings_emitted,
        errors: metrics.errors,
        binary_skipped: metrics.binary_skipped,
        ext_skipped: metrics.ext_skipped,
        lock_skipped: metrics.lock_skipped,
        binary_extracted: metrics.binary_extracted,
        dropped_findings: 0,
        persist_emit_failures: 0,
        persist_incomplete: false,
        scan_ns,
        persist_ns: 0,
    }
}

/// Owned mirror of driver events for channel forwarding.
#[derive(Debug)]
enum OwnedDriverEvent {
    Core(OwnedCoreEvent),
    Git(OwnedGitEvent),
}

/// Convert runtime-level execution knobs into the low-level git runner config.
///
/// Runtime options use MiB units for CLI ergonomics; this function performs
/// checked MiB->byte conversion and applies sane worker fallbacks.
fn build_git_scan_config(cfg: &ScanExecutionConfig) -> Result<GitScanConfig> {
    const MIB: u32 = 1024 * 1024;

    fn mebibytes_to_u32_bytes(value_mb: u32, label: &str) -> Result<u32> {
        if value_mb == 0 {
            bail!("{label} must be >= 1 MiB");
        }
        value_mb
            .checked_mul(MIB)
            .ok_or_else(|| anyhow!("{label} exceeds supported size"))
    }

    fn mebibytes_to_usize_bytes(value_mb: u32, label: &str) -> Result<usize> {
        usize::try_from(mebibytes_to_u32_bytes(value_mb, label)?)
            .map_err(|_| anyhow!("{label} exceeds platform usize"))
    }

    let mut git_cfg = GitScanConfig {
        repo_id: cfg.git.repo_id,
        scan_mode: cfg.git.scan_mode,
        merge_diff_mode: cfg.git.merge_diff_mode,
        pack_exec_workers: cfg
            .git
            .pack_exec_workers
            .unwrap_or_else(|| cfg.workers.max(1))
            .max(1),
        enrich_identities: cfg.git.enrich_identities,
        ..GitScanConfig::default()
    };
    git_cfg.engine_adapter.scan_binary = cfg.git.scan_binary;

    if let Some(value_mb) = cfg.git.tree_delta_cache_mb {
        git_cfg.tree_diff.max_tree_delta_cache_bytes =
            mebibytes_to_u32_bytes(value_mb, "x-tree-delta-cache-mb")?;
    }
    if let Some(value_mb) = cfg.git.engine_chunk_mb {
        git_cfg.engine_adapter.chunk_bytes =
            mebibytes_to_usize_bytes(value_mb, "x-engine-chunk-mb")?;
    }

    Ok(git_cfg)
}

/// Build stderr-oriented debug output for `--debug` / `--debug=perf`.
fn format_git_debug_output(
    report: &scanner_git::GitScanReport,
    level: GitDebugLevel,
) -> Option<String> {
    if matches!(level, GitDebugLevel::Off) {
        return None;
    }

    fn push_line<T: std::fmt::Display>(out: &mut String, key: &str, value: T) {
        out.push_str(key);
        out.push('=');
        out.push_str(&value.to_string());
        out.push('\n');
    }

    let mut out = String::new();
    push_line(
        &mut out,
        "git_debug.level",
        match level {
            GitDebugLevel::Off => "off",
            GitDebugLevel::Stats => "stats",
            GitDebugLevel::Perf => "perf",
        },
    );
    push_line(
        &mut out,
        "git.objects_scanned",
        report.common_metrics.objects_scanned,
    );
    push_line(
        &mut out,
        "git.bytes_scanned",
        report.common_metrics.bytes_scanned,
    );
    push_line(
        &mut out,
        "git.findings_emitted",
        report.common_metrics.findings_emitted,
    );
    let has_stage_nanos = report.stage_nanos.tree_diff > 0
        || report.stage_nanos.commit_plan > 0
        || report.stage_nanos.blob_intro > 0
        || report.stage_nanos.spill > 0
        || report.stage_nanos.pack_collect > 0
        || report.stage_nanos.mapping > 0
        || report.stage_nanos.pack_plan > 0
        || report.stage_nanos.pack_exec > 0
        || report.stage_nanos.loose_scan > 0
        || report.stage_nanos.scan > 0;
    if has_stage_nanos {
        push_line(
            &mut out,
            "stage.tree_diff.nanos",
            report.stage_nanos.tree_diff,
        );
        push_line(
            &mut out,
            "stage.commit_plan.nanos",
            report.stage_nanos.commit_plan,
        );
        push_line(
            &mut out,
            "stage.blob_intro.nanos",
            report.stage_nanos.blob_intro,
        );
        push_line(&mut out, "stage.spill.nanos", report.stage_nanos.spill);
        push_line(
            &mut out,
            "stage.pack_collect.nanos",
            report.stage_nanos.pack_collect,
        );
        push_line(&mut out, "stage.mapping.nanos", report.stage_nanos.mapping);
        push_line(
            &mut out,
            "stage.pack_plan.nanos",
            report.stage_nanos.pack_plan,
        );
        push_line(
            &mut out,
            "stage.pack_exec.nanos",
            report.stage_nanos.pack_exec,
        );
        push_line(
            &mut out,
            "stage.loose_scan.nanos",
            report.stage_nanos.loose_scan,
        );
        push_line(&mut out, "stage.scan.nanos", report.stage_nanos.scan);
    }

    if matches!(level, GitDebugLevel::Perf) {
        out.push_str(&report.format_metrics());
        for (index, pack_report) in report.pack_exec_reports.iter().enumerate() {
            push_line(
                &mut out,
                &format!("pack_exec.{index}.cache_lookup_nanos"),
                pack_report.stats.cache_lookup_nanos,
            );
            push_line(
                &mut out,
                &format!("pack_exec.{index}.fallback_resolve_nanos"),
                pack_report.stats.fallback_resolve_nanos,
            );
            push_line(
                &mut out,
                &format!("pack_exec.{index}.sink_emit_nanos"),
                pack_report.stats.sink_emit_nanos,
            );
        }
    }

    Some(out)
}

/// Owned mirror of [`CoreEvent`] for sending across thread boundaries.
///
/// `CoreEvent` borrows strings/slices from the scanner, so it cannot outlive
/// the emitting thread. This enum clones the borrowed fields into owned
/// storage so events can be forwarded through a channel to a consumer thread.
#[derive(Debug)]
enum OwnedCoreEvent {
    Finding {
        source: SourceKind,
        object_path: Vec<u8>,
        start: u64,
        end: u64,
        rule_id: u32,
        rule_name: String,
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

impl OwnedCoreEvent {
    fn from_core(event: CoreEvent<'_>) -> Self {
        match event {
            CoreEvent::Finding(finding) => Self::Finding {
                source: finding.source,
                object_path: finding.object_path.to_vec(),
                start: finding.start,
                end: finding.end,
                rule_id: finding.rule_id,
                rule_name: finding.rule_name.to_owned(),
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

    fn emit_into(&self, out: &dyn EventOutput) {
        match self {
            Self::Finding {
                source,
                object_path,
                start,
                end,
                rule_id,
                rule_name,
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

/// Owned mirror of [`GitEvent`] for sending across thread boundaries.
#[derive(Debug)]
enum OwnedGitEvent {
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

/// Join a scoped thread handle, converting panics into an `anyhow` error
/// tagged with the thread's name for diagnostics.
fn join_scoped<T>(handle: std::thread::ScopedJoinHandle<'_, T>, thread_name: &str) -> Result<T> {
    handle.join().map_err(|_| anyhow!("{thread_name} panicked"))
}

/// Watermark store that always returns `None`.
///
/// Forces the runner to treat all refs as unwatermarked and scan
/// full history every run.
struct EmptyWatermarkStore;

impl RefWatermarkStore for EmptyWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossip_scan_driver::{CommitSink, FindingsBatch, ItemMeta};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Spy commit sink that records the keys passed to each lifecycle call.
    #[derive(Default)]
    struct SpyCommitSink {
        begin_keys: Mutex<Vec<Vec<u8>>>,
        begin_stable_item_ids: Mutex<Vec<StableItemId>>,
    }

    impl CommitSink for SpyCommitSink {
        fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
            self.begin_keys
                .lock()
                .unwrap()
                .push(item_key.as_bytes().to_vec());
            self.begin_stable_item_ids
                .lock()
                .unwrap()
                .push(meta.stable_item_id);
            Ok(())
        }

        fn upsert_findings(&self, _item_key: &ItemKey, _batch: &FindingsBatch) -> Result<()> {
            Ok(())
        }

        fn finish_item(&self, _item_key: &ItemKey) -> Result<()> {
            Ok(())
        }
    }

    fn filesystem_assignment(shard_start: &[u8], shard_end: &[u8]) -> Assignment {
        Assignment {
            job_id: "job-1".to_owned(),
            connector_kind: ConnectorKind::Filesystem,
            connector_instance_id: "fs-1".to_owned(),
            policy_hash: gossip_contracts::identity::PolicyHash::from_bytes([0x11; 32]),
            shard_spec: gossip_contracts::coordination::ShardSpec::with_range(
                shard_start,
                shard_end,
            ),
            cursor: gossip_contracts::connector::Cursor::initial(),
            source: AssignmentSource::Filesystem {
                root: PathBuf::from("/tmp/scan-root"),
            },
        }
    }

    #[test]
    fn normalize_scheduler_path_strips_root_prefix() {
        let root = Path::new("/tmp/scan-root");
        let normalized = normalize_scheduler_path(root, b"/tmp/scan-root/src/main.rs").unwrap();
        assert_eq!(normalized, b"src/main.rs");
    }

    #[test]
    fn normalize_scheduler_path_handles_nested_dirs() {
        let root = Path::new("/data/scans");
        let normalized =
            normalize_scheduler_path(root, b"/data/scans/deep/nested/file.txt").unwrap();
        assert_eq!(normalized, b"deep/nested/file.txt");
    }

    #[test]
    fn normalize_scheduler_path_rejects_non_child() {
        let root = Path::new("/tmp/scan-root");
        let result = normalize_scheduler_path(root, b"/other/path/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn commit_batch_keys_use_relative_paths() {
        // After normalization by ChannelStoreProducer, forward_commit_batch
        // receives relative paths. Verify the full ItemKey creation works.
        let batch = OwnedCommitBatch {
            object_path: b"src/main.rs".to_vec(),
            stable_item_id: StableItemId::from_bytes([0xAB; 32]),
            findings: vec![],
        };

        let spy = SpyCommitSink::default();
        forward_commit_batch(&spy, batch).unwrap();

        let keys = spy.begin_keys.lock().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0], b"src/main.rs",
            "batch key must be a relative path in connector keyspace"
        );
        let stable_ids = spy.begin_stable_item_ids.lock().unwrap();
        assert_eq!(
            stable_ids.as_slice(),
            &[StableItemId::from_bytes([0xAB; 32])]
        );
    }

    #[test]
    fn filesystem_driver_extracts_shard_bounds_from_assignment() {
        let assignment = filesystem_assignment(b"m", b"z");

        let driver = filesystem_driver_from_assignment(&assignment).expect("filesystem driver");
        assert_eq!(&*driver.shard_start, b"m");
        assert_eq!(&*driver.shard_end, b"z");
    }

    #[test]
    fn filesystem_driver_preserves_unbounded_shard_bounds() {
        let assignment = filesystem_assignment(b"", b"");

        let driver = filesystem_driver_from_assignment(&assignment).expect("filesystem driver");
        assert!(
            driver.shard_start.is_empty(),
            "empty shard start should stay unbounded"
        );
        assert!(
            driver.shard_end.is_empty(),
            "empty shard end should stay unbounded"
        );
    }

    #[test]
    #[ignore] // Enable when connector-backed filesystem enumeration lands
    fn filesystem_driver_applies_shard_bounds_during_scan() {
        // Verify that assignment shard bounds flow through FsScanDriver
        // into the connector's key-range filter during actual scanning.
        //
        // Expected: create assignment with bounds [b"m", b"z"), run scan
        // on a test directory, verify only files within range are scanned.
    }

    #[test]
    fn build_git_scan_config_maps_runtime_git_knobs() {
        let cfg = ScanExecutionConfig {
            workers: 3,
            git: gossip_scan_driver::GitExecutionConfig {
                repo_id: 42,
                scan_mode: scanner_git::GitScanMode::DiffHistory,
                merge_diff_mode: scanner_git::MergeDiffMode::FirstParentOnly,
                pack_exec_workers: Some(5),
                scan_binary: true,
                enrich_identities: true,
                debug_level: GitDebugLevel::Perf,
                tree_delta_cache_mb: Some(256),
                engine_chunk_mb: Some(4),
            },
            ..ScanExecutionConfig::default()
        };

        let git_cfg = build_git_scan_config(&cfg).expect("build git config");
        assert_eq!(git_cfg.repo_id, 42);
        assert_eq!(git_cfg.scan_mode, scanner_git::GitScanMode::DiffHistory);
        assert_eq!(
            git_cfg.merge_diff_mode,
            scanner_git::MergeDiffMode::FirstParentOnly
        );
        assert_eq!(git_cfg.pack_exec_workers, 5);
        assert!(git_cfg.engine_adapter.scan_binary);
        assert!(git_cfg.enrich_identities);
        assert_eq!(
            git_cfg.tree_diff.max_tree_delta_cache_bytes,
            256 * 1024 * 1024
        );
        assert_eq!(git_cfg.engine_adapter.chunk_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn build_git_scan_config_uses_shared_worker_fallback() {
        let cfg = ScanExecutionConfig {
            workers: 7,
            git: gossip_scan_driver::GitExecutionConfig {
                pack_exec_workers: None,
                ..gossip_scan_driver::GitExecutionConfig::default()
            },
            ..ScanExecutionConfig::default()
        };
        let git_cfg = build_git_scan_config(&cfg).expect("build git config");
        assert_eq!(git_cfg.pack_exec_workers, 7);
    }
}
