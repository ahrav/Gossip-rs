//! Scan-driver adapters that bridge connector assignments to scheduler runners.
//!
//! These wrappers intentionally live in a gossip-side crate so scanner crates
//! remain independent leaf crates.

use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::{Receiver, Sender, unbounded};
use gossip_contracts::connector::ItemKey;
use gossip_scan_driver::{
    Assignment, AssignmentSource, CommitSink, ConnectorKind, CursorUpdate, FindingRecord,
    FindingsBatch, ItemMeta, ScanDriver, ScanExecutionConfig, ScanReport, ScanSourceFactory,
    SourceCapabilities,
};
use scanner_git::{
    EventSink as GitEventSink, GitEvent, GitEventOutput, GitRepoPaths, GitScanConfig,
    GitScanResult, NeverSeenStore, OidBytes, RefWatermarkStore, RepoOpenError, StartSetId,
    StartSetResolver, run_git_scan,
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
            supports_cooperative_cancel: true,
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
        commit: &dyn CommitSink,
        cancel: &gossip_scan_driver::CancellationToken,
    ) -> Result<ScanReport> {
        std::thread::scope(|scope| -> Result<ScanReport> {
            let (event_tx, event_rx) = unbounded();
            let event_forwarder = scope.spawn(move || forward_events(out, event_rx));

            let (commit_tx, commit_rx) = unbounded();
            let commit_forwarder = scope.spawn(move || forward_commits(commit, commit_rx));

            let scan_cfg = ParallelScanConfig {
                workers: cfg.workers.max(1),
                event_sink: Arc::new(ChannelEventOutput::new(event_tx.clone())),
                store_producer: Some(Arc::new(ChannelStoreProducer::new(commit_tx.clone()))),
                ..ParallelScanConfig::default()
            };

            let report = if cancel.is_cancelled() {
                scanner_scheduler::scheduler::local_fs_owner::LocalReport::default()
            } else {
                parallel_scan_dir(&self.root, engine, scan_cfg).with_context(|| {
                    format!("filesystem scan failed for {}", self.root.display())
                })?
            };

            if report.stats.files_enqueued > 0 {
                self.checkpoint_hint = Some(CursorUpdate {
                    cursor: gossip_contracts::connector::Cursor::initial(),
                    committed_items: report.stats.files_enqueued,
                });
            }

            drop(event_tx);
            drop(commit_tx);

            join_scoped(event_forwarder, "event forwarder thread")?;
            join_scoped(commit_forwarder, "commit forwarder thread")??;

            Ok(ScanReport {
                items_scanned: report.stats.files_enqueued,
                bytes_scanned: report.metrics.bytes_scanned,
                findings_emitted: report.metrics.findings_emitted,
            })
        })
    }

    fn checkpoint_hint(&self) -> Option<CursorUpdate> {
        self.checkpoint_hint.clone()
    }
}

#[derive(Debug)]
struct GitScanDriver {
    repo_root: PathBuf,
}

impl ScanDriver for GitScanDriver {
    fn run(
        &mut self,
        engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn EventOutput,
        _commit: &dyn CommitSink,
        cancel: &gossip_scan_driver::CancellationToken,
    ) -> Result<ScanReport> {
        if cancel.is_cancelled() {
            return Ok(ScanReport::default());
        }

        std::thread::scope(|scope| -> Result<ScanReport> {
            let (event_tx, event_rx) = unbounded();
            let event_forwarder = scope.spawn(move || forward_events(out, event_rx));

            let git_sink: Arc<dyn GitEventSink> =
                Arc::new(ChannelGitEventOutput::new(event_tx.clone()));

            let git_cfg = GitScanConfig {
                pack_exec_workers: cfg.workers.max(1),
                ..GitScanConfig::default()
            };

            let resolver = CliRefResolver::new(self.repo_root.clone());
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

            drop(event_tx);
            join_scoped(event_forwarder, "event forwarder thread")?;

            Ok(git_report_to_scan_report(result))
        })
    }
}

#[derive(Debug)]
struct InMemoryScanDriver {
    items: Arc<[MemItem]>,
    checkpoint_hint: Option<CursorUpdate>,
}

impl ScanDriver for InMemoryScanDriver {
    fn run(
        &mut self,
        _engine: Arc<scanner_engine::Engine>,
        cfg: &ScanExecutionConfig,
        out: &dyn EventOutput,
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

#[derive(Clone, Debug)]
struct ChannelEventOutput {
    tx: Sender<OwnedCoreEvent>,
}

impl ChannelEventOutput {
    fn new(tx: Sender<OwnedCoreEvent>) -> Self {
        Self { tx }
    }
}

impl EventOutput for ChannelEventOutput {
    fn emit_core(&self, event: CoreEvent<'_>) {
        let _ = self.tx.send(OwnedCoreEvent::from_core(event));
    }

    fn flush(&self) {}
}

#[derive(Clone, Debug)]
struct ChannelGitEventOutput {
    inner: ChannelEventOutput,
}

impl ChannelGitEventOutput {
    fn new(tx: Sender<OwnedCoreEvent>) -> Self {
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
    fn emit_git(&self, _event: GitEvent<'_>) {}
}

#[derive(Clone, Debug)]
struct ChannelStoreProducer {
    tx: Sender<CommitMessage>,
}

impl ChannelStoreProducer {
    fn new(tx: Sender<CommitMessage>) -> Self {
        Self { tx }
    }
}

impl StoreProducer for ChannelStoreProducer {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        self.tx
            .send(CommitMessage::Batch(OwnedFsFindingBatch {
                object_path: batch.object_path.to_vec(),
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

#[derive(Debug)]
enum CommitMessage {
    Batch(OwnedFsFindingBatch),
    RunLoss(FsRunLoss),
    EndRun(bool),
}

fn forward_events(out: &dyn EventOutput, rx: Receiver<OwnedCoreEvent>) {
    while let Ok(event) = rx.recv() {
        event.emit_into(out);
    }
    out.flush();
}

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

fn git_report_to_scan_report(result: GitScanResult) -> ScanReport {
    let metrics = result.0.common_metrics;
    ScanReport {
        items_scanned: metrics.objects_scanned,
        bytes_scanned: metrics.bytes_scanned,
        findings_emitted: metrics.findings_emitted,
    }
}

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

fn join_scoped<T>(handle: std::thread::ScopedJoinHandle<'_, T>, thread_name: &str) -> Result<T> {
    handle.join().map_err(|_| anyhow!("{thread_name} panicked"))
}

#[derive(Clone, Debug)]
struct CliRefResolver {
    repo_root: PathBuf,
}

impl CliRefResolver {
    fn new(repo_root: PathBuf) -> Self {
        Self { repo_root }
    }
}

impl StartSetResolver for CliRefResolver {
    fn resolve(&self, _paths: &GitRepoPaths) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args([
                "for-each-ref",
                "--format=%(refname)%00%(objectname)",
                "refs/heads",
                "refs/remotes",
                "refs/tags",
            ])
            .output()
            .map_err(RepoOpenError::io)?;

        if !output.status.success() {
            return Err(RepoOpenError::io(io::Error::other(format!(
                "git for-each-ref failed for {}: {}",
                self.repo_root.display(),
                String::from_utf8_lossy(&output.stderr)
            ))));
        }

        let text = String::from_utf8(output.stdout).map_err(|error| {
            RepoOpenError::io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("git for-each-ref emitted invalid UTF-8: {error}"),
            ))
        })?;

        let mut refs = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let Some((name, oid_hex)) = line.split_once('\0') else {
                continue;
            };
            let oid = decode_oid_hex(oid_hex).map_err(RepoOpenError::io)?;
            refs.push((name.as_bytes().to_vec(), oid));
        }
        Ok(refs)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct EmptyWatermarkStore;

impl RefWatermarkStore for EmptyWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

fn decode_oid_hex(hex: &str) -> io::Result<OidBytes> {
    let trimmed = hex.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("OID hex has odd length: {}", trimmed.len()),
        ));
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let mut chars = trimmed.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let hi = from_hex_nibble(pair[0])?;
        let lo = from_hex_nibble(pair[1])?;
        bytes.push((hi << 4) | lo);
    }

    OidBytes::try_from_slice(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("OID must be 20 or 32 bytes, got {}", bytes.len()),
        )
    })
}

fn from_hex_nibble(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hex nibble: {}", byte as char),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_oid_hex_accepts_sha1() {
        let oid = decode_oid_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(oid.len(), 20);
    }

    #[test]
    fn decode_oid_hex_rejects_bad_length() {
        let err = decode_oid_hex("abc").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
