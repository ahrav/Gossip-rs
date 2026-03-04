//! Scan-driver adapters that bridge connector assignments to scheduler runners.
//!
//! These wrappers intentionally live in a gossip-side crate so scanner crates
//! remain independent leaf crates.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::{Receiver, Sender, unbounded};
use gossip_contracts::connector::ItemKey;
use gossip_scan_driver::{
    Assignment, AssignmentSource, CommitSink, ConnectorKind, CursorUpdate, FindingRecord,
    FindingsBatch, GitDebugLevel, ItemMeta, ScanDriver, ScanExecutionConfig, ScanReport,
    ScanSourceFactory, SourceCapabilities,
};
use scanner_git::{
    CommitIdentityIds, CommitMetaEvent, EventSink as GitEventSink, GitEvent, GitEventOutput,
    GitRepoPaths, GitScanConfig, GitScanResult, IdentityDictionaryEvent, NeverSeenStore, OidBytes,
    RefWatermarkStore, RepoOpenError, StartSetConfig, StartSetResolver, run_git_scan,
};
use scanner_scheduler::events::{
    CoreEvent, DiagnosticEvent, EventOutput, FindingEvent, ProgressEvent, SummaryEvent,
};
use scanner_scheduler::parallel_scan::{ParallelScanConfig, parallel_scan_dir};
use scanner_scheduler::source_kind::SourceKind;
use scanner_scheduler::store::{
    FsFindingBatch, FsRunLoss, FsStoreError, OwnedFsFindingBatch, StoreProducer,
};

use crate::in_memory::MemItem;

/// Factory for filesystem assignments.
#[derive(Clone, Copy, Debug, Default)]
pub struct FilesystemScanSourceFactory;

impl ScanSourceFactory for FilesystemScanSourceFactory {
    fn driver_for_assignment(&self, assignment: &Assignment) -> Result<Box<dyn ScanDriver>> {
        if assignment.connector_kind != ConnectorKind::Filesystem {
            bail!(
                "assignment kind mismatch: expected filesystem, got {:?}",
                assignment.connector_kind
            );
        }

        let AssignmentSource::Filesystem { root } = &assignment.source else {
            bail!("filesystem assignment missing filesystem source payload");
        };

        Ok(Box::new(FsScanDriver {
            root: root.clone(),
            checkpoint_hint: None,
        }))
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

        Ok(Box::new(InMemoryScanDriver {
            items: Arc::clone(&self.items),
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
    checkpoint_hint: Option<CursorUpdate>,
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
                )));
            }

            let report = if cancel.is_cancelled() {
                scanner_scheduler::scheduler::local_fs_owner::LocalReport::default()
            } else {
                parallel_scan_dir(&self.root, engine, scan_cfg).with_context(|| {
                    format!("filesystem scan failed for {}", self.root.display())
                })?
            };

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
            })
        })
    }

    fn checkpoint_hint(&self) -> Option<CursorUpdate> {
        self.checkpoint_hint.clone()
    }
}

/// Git scan driver backed by [`run_git_scan`].
///
/// Resolves refs via the `git` CLI ([`GitCliResolver`]) and treats every ref
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

            let resolver =
                GitCliResolver::new(self.repo_root.clone(), StartSetConfig::DefaultBranchOnly);
            let watermarks = EmptyWatermarkStore;
            let seen = NeverSeenStore;
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

            self.debug_output = format_git_debug_output(&result.0, cfg.git.debug_level);
            drop(event_tx);
            join_scoped(event_forwarder, "event forwarder thread")?;

            Ok(git_report_to_scan_report(result))
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
}

impl ChannelStoreProducer {
    fn new(tx: Sender<CommitMessage>, root: PathBuf) -> Self {
        Self { tx, root }
    }
}

impl StoreProducer for ChannelStoreProducer {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        // Normalize the scheduler's absolute OS path to the connector's
        // relative key encoding before forwarding through the channel.
        let normalized_path = normalize_scheduler_path(&self.root, batch.object_path)
            .map_err(|e| FsStoreError::backend(format!("path normalization failed: {e}")))?;
        self.tx
            .send(CommitMessage::Batch(OwnedFsFindingBatch {
                object_path: normalized_path,
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
    Batch(OwnedFsFindingBatch),
    RunLoss(FsRunLoss),
    EndRun(bool),
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

/// Map a scheduler [`OwnedFsFindingBatch`] to the [`CommitSink`] lifecycle:
/// `begin_item` → `upsert_findings` (if any) → `finish_item`.
fn forward_commit_batch(commit: &dyn CommitSink, batch: OwnedFsFindingBatch) -> Result<()> {
    let item_key = ItemKey::try_from_slice(&batch.object_path)
        .map_err(|error| anyhow!("invalid item key from scheduler batch: {error}"))?;
    let meta = ItemMeta::default();
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
fn git_report_to_scan_report(result: GitScanResult) -> ScanReport {
    let metrics = result.0.common_metrics;
    ScanReport {
        items_scanned: metrics.objects_scanned,
        bytes_scanned: metrics.bytes_scanned,
        chunks_scanned: metrics.chunks_scanned,
        findings_emitted: metrics.findings_emitted,
        // Git scan errors are tracked per-pack-exec and not aggregated into
        // a single counter in `GitScanCommonMetrics`. Leave at zero for now;
        // a follow-up can surface pack-exec error totals here.
        errors: 0,
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

/// Resolves the start set by invoking `git` in the target repository.
///
/// Supported configs: `DefaultBranchOnly` and `ExplicitRefs`. All other
/// start-set modes return an error to keep the CLI lightweight.
///
/// Requires `git` on PATH; command failures surface as `RepoOpenError::Io`.
struct GitCliResolver {
    repo: PathBuf,
    start_set: StartSetConfig,
}

impl GitCliResolver {
    fn new(repo: PathBuf, start_set: StartSetConfig) -> Self {
        Self { repo, start_set }
    }
}

impl StartSetResolver for GitCliResolver {
    fn resolve(&self, _paths: &GitRepoPaths) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        match &self.start_set {
            StartSetConfig::DefaultBranchOnly => resolve_default_branch(&self.repo),
            StartSetConfig::ExplicitRefs { refs } => resolve_explicit_refs(&self.repo, refs),
            _ => Err(RepoOpenError::io(io::Error::other(
                "start set config not supported by git_scan CLI",
            ))),
        }
    }
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

/// Run `git` in `repo` and return trimmed UTF-8 stdout.
///
/// Output is lossy UTF-8 with leading and trailing whitespace removed.
/// Both stdout and stderr are captured; only stdout is used.
fn run_git(repo: &PathBuf, args: &[&str]) -> io::Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("git command failed: {:?}", args)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Resolve the default-branch tip, falling back to detached `HEAD`.
///
/// Uses `symbolic-ref --quiet HEAD` to find the default branch; if that
/// fails, falls back to `HEAD`. Returns an empty start set for unborn
/// branches (newly initialized repos with no commits).
fn resolve_default_branch(repo: &PathBuf) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let head_ref = run_git(repo, &["symbolic-ref", "--quiet", "HEAD"]).ok();
    if let Some(ref_name) = head_ref {
        // `rev-parse` fails when the branch is unborn (no commits yet).
        // Return an empty start set so the scanner sees zero objects.
        let Ok(tip_hex) = run_git(repo, &["rev-parse", &ref_name]) else {
            return Ok(Vec::new());
        };
        let oid = oid_from_hex(&tip_hex)?;
        return Ok(vec![(ref_name.into_bytes(), oid)]);
    }

    // Detached HEAD fallback — also returns empty for unborn repos where
    // `symbolic-ref` itself failed (uncommon, but possible on bare init).
    let Ok(tip_hex) = run_git(repo, &["rev-parse", "HEAD"]) else {
        return Ok(Vec::new());
    };
    let oid = oid_from_hex(&tip_hex)?;
    Ok(vec![(b"HEAD".to_vec(), oid)])
}

/// Resolve the tip OIDs for explicitly provided ref names.
///
/// Each ref is passed to `git rev-parse`; missing refs surface as errors.
fn resolve_explicit_refs(
    repo: &PathBuf,
    refs: &[Vec<u8>],
) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let mut out = Vec::with_capacity(refs.len());
    for r in refs {
        let name = String::from_utf8_lossy(r);
        let tip_hex = run_git(repo, &["rev-parse", name.as_ref()]).map_err(RepoOpenError::io)?;
        let oid = oid_from_hex(&tip_hex)?;
        out.push((r.clone(), oid));
    }
    Ok(out)
}

/// Decode a hex-encoded OID into raw bytes.
///
/// The input must have an even number of hex digits.
fn oid_from_hex(hex: &str) -> Result<OidBytes, RepoOpenError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(RepoOpenError::io(io::Error::other(
            "invalid OID hex length",
        )));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| RepoOpenError::io(io::Error::other("invalid OID hex")))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| RepoOpenError::io(io::Error::other("invalid OID hex")))?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(OidBytes::from_slice(&out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossip_scan_driver::{CommitSink, FindingsBatch, ItemMeta};
    use std::path::Path;
    use std::sync::Mutex;

    /// Spy commit sink that records the keys passed to each lifecycle call.
    #[derive(Default)]
    struct SpyCommitSink {
        begin_keys: Mutex<Vec<Vec<u8>>>,
    }

    impl CommitSink for SpyCommitSink {
        fn begin_item(&self, item_key: &ItemKey, _meta: &ItemMeta) -> Result<()> {
            self.begin_keys
                .lock()
                .unwrap()
                .push(item_key.as_bytes().to_vec());
            Ok(())
        }

        fn upsert_findings(&self, _item_key: &ItemKey, _batch: &FindingsBatch) -> Result<()> {
            Ok(())
        }

        fn finish_item(&self, _item_key: &ItemKey) -> Result<()> {
            Ok(())
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
        let batch = OwnedFsFindingBatch {
            object_path: b"src/main.rs".to_vec(),
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

    #[test]
    fn resolve_default_branch_returns_empty_for_unborn_branch() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let repo = tmp.path().to_path_buf();
        // `git init` creates a repo with an unborn default branch (no commits).
        let status = std::process::Command::new("git")
            .args(["init", "--initial-branch=main"])
            .arg(tmp.path())
            .output()
            .expect("git init");
        assert!(status.status.success(), "git init must succeed");

        // symbolic-ref succeeds on the unborn branch, but rev-parse fails.
        // The function must return an empty start set, not propagate the error.
        let result = resolve_default_branch(&repo);
        assert!(result.is_ok(), "unborn branch must not error: {result:?}");
        assert!(
            result.unwrap().is_empty(),
            "unborn branch must produce an empty start set"
        );
    }

    #[test]
    fn oid_from_hex_accepts_sha1() {
        let oid = oid_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(oid.len(), 20);
    }

    #[test]
    fn oid_from_hex_rejects_bad_length() {
        assert!(oid_from_hex("abc").is_err());
    }
}
