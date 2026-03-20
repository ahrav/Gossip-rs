//! Ordered-content (filesystem) runtime boundary.
//!
//! This module implements the filesystem scan path: given a validated
//! directory or file path and an [`FsScanConfig`], it builds a detection
//! engine, spawns scoped event and commit forwarder threads, and delegates
//! to [`parallel_scan_dir`] for multi-threaded file enumeration and scanning.
//!
//! # Threading model
//!
//! `scan_local_filesystem` uses [`std::thread::scope`] to spawn two forwarder
//! threads:
//!
//! 1. **Event forwarder** — drains core events (findings, progress, summary,
//!    diagnostics) from the scan workers into the caller's [`EventOutput`] sink.
//! 2. **Commit forwarder** — drains persistence batches into the caller's
//!    [`CommitSink`](crate::commit_sink::CommitSink) (a no-op sink for CLI
//!    scans; distributed mode routes the same lifecycle into the
//!    receipt-driven commit pipeline).
//!
//! Both channels are bounded (`EVENT_CHANNEL_CAP` and `COMMIT_CHANNEL_CAP`)
//! and are explicitly dropped after the scan completes so the forwarder
//! threads observe a clean EOF.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

use anyhow::anyhow;
use gossip_contracts::connector::ordered::OrderedContentSource;
use scanner_scheduler::events::EventOutput;
use scanner_scheduler::scheduler::parallel_scan::{ParallelScanConfig, parallel_scan_dir};

use crate::{
    AssignmentOutcome, COMMIT_CHANNEL_CAP, CancellationToken, ChannelEventOutput,
    ChannelStoreProducer, EVENT_CHANNEL_CAP, FsScanConfig, ScanReport, ScanRuntimeError,
    build_runtime_engine, forward_commits, forward_core_events, join_scoped,
};

/// Marker type for the ordered-content (filesystem) source family.
///
/// Provides the trait-dispatched entry point for connector-provided content
/// sources. This path is a placeholder; the primary scan path for local
/// filesystems is the crate-internal `scan_local_filesystem` function.
#[derive(Debug, Default)]
pub struct OrderedContentRuntime;

impl OrderedContentRuntime {
    /// Execute one ordered-content source (not yet implemented).
    ///
    /// Ordered-content sources provide items through a streaming iterator API.
    /// This path always returns an error until connector-level content
    /// enumeration is wired in.
    pub fn execute_source<S: OrderedContentSource>(
        _source: &mut S,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::Driver(anyhow!(
            "ordered-content runtime path for source '{}' is not implemented yet",
            std::any::type_name::<S>()
        )))
    }
}

/// Run a parallel filesystem scan against a local directory or single file.
///
/// This is the primary scan path for filesystem sources. It builds a
/// detection engine, configures the parallel scanner, and bridges scan
/// events and persistence batches into the caller's sinks.
///
/// # Persistence
///
/// When `config.persist_findings` is true, a [`ChannelStoreProducer`] is
/// wired into the parallel scanner. Finding batches flow through the commit
/// channel to the `commit` sink, which is a no-op for CLI scans; distributed
/// mode routes the same lifecycle into the receipt-driven commit pipeline via
/// its commit-sink adapter.
///
/// # Errors
///
/// Returns [`ScanRuntimeError::Driver`] if `parallel_scan_dir` fails, or
/// propagates engine-construction errors from [`build_runtime_engine`].
pub(crate) fn scan_local_filesystem(
    config: &FsScanConfig,
    canonical_path: PathBuf,
    out: &dyn EventOutput,
    commit: &dyn crate::commit_sink::CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    if cancel.is_cancelled() {
        return Ok(AssignmentOutcome {
            report: ScanReport::default(),
            checkpoint_hint: None,
            debug_output: None,
        });
    }

    let engine = build_runtime_engine(
        config.rules_file.as_deref(),
        &config.transform_filter,
        config.decode_depth,
        config.anchor_mode,
    )?;

    scan_local_filesystem_with_engine(config, canonical_path, engine, out, commit, cancel)
}

/// Run a parallel filesystem scan against a local directory or single file
/// using a caller-provided detection engine.
///
/// Distributed execution uses this to share one engine instance between the
/// scan workers and the receipt commit sink's rule-fingerprint lookup.
///
/// Returns early with a default (zero-count) report if cancellation has
/// already been requested. Otherwise spawns two scoped forwarder threads
/// (event and commit), runs the parallel scanner, and joins both forwarders
/// before returning.
pub(crate) fn scan_local_filesystem_with_engine(
    config: &FsScanConfig,
    canonical_path: PathBuf,
    engine: Arc<scanner_engine::Engine>,
    out: &dyn EventOutput,
    commit: &dyn crate::commit_sink::CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    if cancel.is_cancelled() {
        return Ok(AssignmentOutcome {
            report: ScanReport::default(),
            checkpoint_hint: None,
            debug_output: None,
        });
    }

    let report = std::thread::scope(|scope| -> Result<ScanReport, ScanRuntimeError> {
        let (event_tx, event_rx) = sync_channel(EVENT_CHANNEL_CAP);
        let event_forwarder = scope.spawn(move || forward_core_events(out, event_rx));

        let (commit_tx, commit_rx) = sync_channel(COMMIT_CHANNEL_CAP);
        let commit_forwarder = scope.spawn(move || forward_commits(commit, commit_rx));

        let mut scan_cfg = ParallelScanConfig {
            workers: config.workers.max(1),
            event_sink: Arc::new(ChannelEventOutput::new(event_tx.clone())),
            skip_binary: !config.scan_binary,
            ..ParallelScanConfig::default()
        };
        if config.skip_archives {
            scan_cfg.archive.enabled = false;
        }
        if config.persist_findings {
            scan_cfg.store_producer = Some(Arc::new(ChannelStoreProducer::new(
                commit_tx.clone(),
                canonical_path.clone(),
            )));
        }

        let scan_start = std::time::Instant::now();
        let report = parallel_scan_dir(&canonical_path, engine, scan_cfg).map_err(|error| {
            ScanRuntimeError::Driver(anyhow!(
                "filesystem scan failed for '{}': {error}",
                canonical_path.display()
            ))
        })?;
        let scan_elapsed = scan_start.elapsed();

        // Close senders before joining so forwarder threads see EOF.
        drop(event_tx);
        drop(commit_tx);

        join_scoped(event_forwarder, "filesystem event forwarder thread")
            .map_err(ScanRuntimeError::Driver)?;
        join_scoped(commit_forwarder, "filesystem commit forwarder thread")
            .map_err(ScanRuntimeError::Driver)?
            .map_err(ScanRuntimeError::Driver)?;

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
    })?;

    Ok(AssignmentOutcome {
        report,
        checkpoint_hint: None,
        debug_output: None,
    })
}
